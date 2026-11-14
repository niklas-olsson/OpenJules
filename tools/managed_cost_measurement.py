"""Bounded, opt-in observers for the managed-cost fixture, never runtime policy.

Only the fixture installs these hooks through its temporary MonkeyPatch context.
Spans are inclusive and may overlap. Thread CPU excludes work on other threads;
neither span durations nor CPU observations may be summed into process totals.
HTTP counters are supplied by fixture code at actual body reads/writes. No HTTP
interception, buffering, impairment, archive reread or production retry is added.
"""

from __future__ import annotations

from contextlib import contextmanager
from contextvars import ContextVar
from functools import wraps
import inspect
import json
import math
import os
from pathlib import Path
import re
import resource
import subprocess
import threading
import time


PHASES = frozenset({
    "source.prepare", "source.export", "source.cold", "source.reuse",
    "runtime.ensure", "runtime.create", "runtime.execute", "runtime.retire",
    "runtime.capture", "runtime.cancel", "child.launch", "child.final_capture",
    "dispatch.capture_delivery", "publication.run", "publication.journal_save",
    "publication.compose", "publication.initial", "publication.replay",
    "publication.reconciliation", "forge.upload_objects", "forge.request",
    "authority.request", "syscall.fsync", "case.total", "case.root",
    "case.children", "case.two_workers", "case.capture", "case.source",
    "case.publication", "case.control", "case.installed_idle", "setup",
    "cleanup", "idle.window", "control", "control.cancel", "control.denial", "overhead",
    "installed_prepare", "installed_offline_bootstrap", "installed_readiness",
    "installed_target_one_convergence", "installed_idle_0", "installed_idle_1",
    "installed_retirement", "installed_owned_cleanup",
})
COUNTERS = frozenset({
    "subprocess.started.git", "subprocess.started.python",
    "subprocess.started.docker", "subprocess.started.node", "subprocess.started.other",
    "fsync.calls", "http.requests", "http.request_bytes", "http.response_bytes",
    "model.requests", "model.response_bytes", "docker.created", "docker.started",
    "docker.stopped", "docker.removed",
})
FACTS = frozenset({
    "fixture", "correctness", "artifacts", "control", "process", "environment",
    "source", "model", "publication", "storage", "setup", "sample", "overhead",
    "owned_worker_ids", "owned_container_ids",
    "installed_owned_worker_id", "failed_sample_cleanup",
})
EXCEPTIONS = frozenset({
    "AssertionError", "ValueError", "TypeError", "OSError", "RuntimeError",
    "TimeoutError", "CancelledError", "KeyboardInterrupt", "SystemExit",
    "AuthorityUnavailable", "AuthorityRejected", "RuntimeUnavailable",
    "CleanupBlocked", "ForgeError", "PublicationError", "SnapshotUnavailable",
    "CompositionError", "ChildRejected", "BrokerDenied", "LifecycleConflict",
})
MAX_SPANS = 32768
MAX_CAPTURES = 256
MAX_FACT_BYTES = 65536
MAX_COUNTER = 2**63 - 1
SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _json_value(value, depth=0):
    """Reject arbitrary objects before serialization, including custom methods."""
    if depth > 8:
        raise ValueError("measurement fact exceeds depth bound")
    kind = type(value)
    if value is None or kind in {bool, int}:
        if kind is int and not -MAX_COUNTER <= value <= MAX_COUNTER:
            raise ValueError("measurement fact integer exceeds bound")
        return
    if kind is float and math.isfinite(value):
        return
    if kind is str and len(value) <= 4096:
        return
    if kind in {list, dict} and len(value) <= 1024:
        if kind is dict:
            if any(type(key) is not str or len(key) > 128 for key in value):
                raise ValueError("measurement fact has invalid keys")
            values = value.values()
        else:
            values = value
        for item in values:
            _json_value(item, depth + 1)
        return
    raise ValueError("measurement fact is not bounded JSON")


def _cpu():
    own = resource.getrusage(resource.RUSAGE_SELF)
    children = resource.getrusage(resource.RUSAGE_CHILDREN)
    return {
        "self_user_seconds": own.ru_utime,
        "self_system_seconds": own.ru_stime,
        "reaped_children_user_seconds": children.ru_utime,
        "reaped_children_system_seconds": children.ru_stime,
    }


def _executable(arguments, options):
    if options.get("shell"):
        return "other"
    command = options.get("executable")
    if command is None:
        command = arguments[0] if arguments else options.get("args")
        if isinstance(command, (list, tuple)):
            command = command[0] if command else None
    if isinstance(command, Path):
        command = os.fspath(command)
    if isinstance(command, bytes):
        command = os.fsdecode(command)
    if not isinstance(command, str):
        return "other"
    name = os.path.basename(command)
    if name in {"git", "docker", "node"}:
        return name
    if re.fullmatch(r"python(?:[0-9]+(?:\.[0-9]+)?)?", name):
        return "python"
    return "other"


class Recorder:
    """One fresh fixture process's observations and explicit synthetic facts.

    Disabled controls retain explicit fixture counters/facts and process-wide
    counters, but install no production hooks or spans. The caller owns factual
    content: fact() must receive only approved, nonsecret fixture projections.
    Automatic observations never retain arguments, paths, headers, bodies,
    exception messages, credentials or arbitrary executable names.
    """

    def __init__(self, workdir, enabled=True, impairment_ms=0, bytes_per_second=1250000):
        if type(enabled) is not bool or impairment_ms not in {0, 20, 100}:
            raise ValueError("invalid measurement mode")
        if type(impairment_ms) is not int or type(bytes_per_second) is not int or bytes_per_second != 1250000:
            raise ValueError("invalid fixture impairment declaration")
        self.workdir = Path(workdir)
        self.enabled = enabled
        self.impairment_ms = impairment_ms
        self.bytes_per_second = bytes_per_second
        self._lock = threading.RLock()
        self._parent = ContextVar("managed_cost_parent", default=None)
        self._spans, self._captures, self._facts, self._problems = [], [], {}, set()
        self._counters = {name: 0 for name in sorted(COUNTERS)}
        self._active = 0
        self._installed = False
        self._start = time.perf_counter_ns()
        self._cpu_start = _cpu()

    def _problem(self, code):
        with self._lock:
            self._problems.add(code)

    @contextmanager
    def phase(self, name):
        if name not in PHASES:
            raise ValueError("unapproved measurement phase")
        if not self.enabled:
            yield
            return
        start, cpu = time.perf_counter_ns(), time.thread_time_ns()
        with self._lock:
            if len(self._spans) >= MAX_SPANS:
                self._problems.add("span_limit")
                row = None
            else:
                row = {
                    "id": len(self._spans), "parent_id": self._parent.get(),
                    "phase": name, "start_ns": start - self._start,
                    "wall_ns": None, "thread_cpu_ns": None,
                    "outcome": "running", "exception_type": None,
                }
                self._spans.append(row)
                self._active += 1
        if row is None:
            yield
            return
        token = self._parent.set(row["id"])
        outcome, exception = "completed", None
        try:
            yield
        except BaseException as error:
            outcome = "raised"
            kind = type(error).__name__
            exception = kind if kind in EXCEPTIONS else "OtherException"
            raise
        finally:
            end, stop_cpu = time.perf_counter_ns(), time.thread_time_ns()
            self._parent.reset(token)
            with self._lock:
                row.update(wall_ns=end - start, thread_cpu_ns=stop_cpu - cpu,
                           outcome=outcome, exception_type=exception)
                self._active -= 1

    def add(self, name, value=1):
        if name not in COUNTERS or type(value) is not int or not 0 <= value <= MAX_COUNTER:
            raise ValueError("invalid measurement counter")
        with self._lock:
            total = self._counters[name] + value
            if total > MAX_COUNTER:
                self._problems.add("counter_limit")
                return
            self._counters[name] = total

    def observe_body(self, direction, count):
        if direction not in {"request", "response"}:
            raise ValueError("invalid measured body direction")
        self.add("http." + direction + "_bytes", count)

    def fact(self, name, value):
        if name not in FACTS:
            raise ValueError("unapproved measurement fact")
        _json_value(value)
        raw = json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
        if len(raw) > MAX_FACT_BYTES:
            raise ValueError("measurement fact exceeds byte bound")
        copied = json.loads(raw)
        with self._lock:
            if name in self._facts:
                previous = json.dumps(self._facts[name], sort_keys=True, separators=(",", ":"), allow_nan=False).encode()
                if previous != raw:
                    raise ValueError("measurement fact changed")
            self._facts[name] = copied

    def _capture(self, receipt, kind):
        """Project existing producer metadata only; never open the archive."""
        try:
            if not getattr(receipt, "artifacts_captured", False):
                return
            raw = receipt.manifest
            if type(raw) is not str or len(raw) > 65536:
                raise ValueError
            manifest = json.loads(raw)
            size, digest = manifest.get("archive_bytes"), manifest.get("archive_sha256")
            if (type(size) is not int or not 0 <= size <= 16 * 1024 * 1024
                    or type(digest) is not str or not SHA256.fullmatch(digest)
                    or digest != receipt.capture_sha256):
                raise ValueError
            with self._lock:
                if len(self._captures) >= MAX_CAPTURES:
                    self._problems.add("capture_limit")
                else:
                    self._captures.append({"kind": kind, "archive_bytes": size, "archive_sha256": digest})
        except Exception:
            self._problem("capture_projection_unavailable")

    def _wrap(self, original, label):
        if inspect.iscoroutinefunction(original):
            @wraps(original)
            async def async_call(*args, **kwargs):
                with self.phase(label):
                    return await original(*args, **kwargs)
            return async_call

        @wraps(original)
        def call(*args, **kwargs):
            with self.phase(label):
                result = original(*args, **kwargs)
            if label == "runtime.capture":
                self._capture(result, "root")
            elif label == "child.final_capture":
                receipt = args[3] if len(args) > 3 else kwargs.get("receipt")
                self._capture(receipt, "child")
            return result
        return call

    def install(self, monkeypatch):
        """Install a closed set of temporary hooks; the caller undoes them."""
        if self._installed:
            raise ValueError("measurement hooks already installed")
        self._installed = True
        # Both paired modes prepare the same imports before the case timer.
        # Otherwise disabled controls pay lazy imports inside the workload while
        # instrumented samples have already paid them during hook installation.
        from src.worker.source_snapshot import SourceSnapshots
        from src.worker.docker_runtime import ManagedDockerRuntime
        from src.worker.child_runtime import ChildRuntime
        from src.worker.managed_dispatch import ManagedDispatcher
        from src.worker import managed_publication
        from src.git_manager import managed_composition
        from src.forge.managed_github import ManagedGitHubPublisher
        from src.polyphony.managed_client import ManagedAuthorityClient

        if not self.enabled:
            return

        hooks = (
            (SourceSnapshots, "prepare", "source.prepare"),
            (SourceSnapshots, "_export", "source.export"),
            (ManagedDockerRuntime, "ensure", "runtime.ensure"),
            (ManagedDockerRuntime, "_create", "runtime.create"),
            (ManagedDockerRuntime, "execute_attempt", "runtime.execute"),
            (ManagedDockerRuntime, "_retire_locked", "runtime.retire"),
            (ManagedDockerRuntime, "_capture", "runtime.capture"),
            (ManagedDockerRuntime, "cancel_attempt", "runtime.cancel"),
            (ChildRuntime, "launch", "child.launch"),
            (ChildRuntime, "final_capture", "child.final_capture"),
            (ManagedDispatcher, "_publish_capture", "dispatch.capture_delivery"),
            (managed_publication.PublicationService, "run", "publication.run"),
            (managed_publication.PublicationJournal, "save", "publication.journal_save"),
            (ManagedGitHubPublisher, "upload_objects", "forge.upload_objects"),
            (ManagedGitHubPublisher, "_request", "forge.request"),
            (ManagedAuthorityClient, "request", "authority.request"),
        )
        for owner, attribute, label in hooks:
            monkeypatch.setattr(owner, attribute, self._wrap(getattr(owner, attribute), label))
        composed = self._wrap(managed_composition.compose, "publication.compose")
        monkeypatch.setattr(managed_composition, "compose", composed)
        monkeypatch.setattr(managed_publication, "compose", composed)

        original_fsync = os.fsync
        @wraps(original_fsync)
        def fsync(descriptor):
            self.add("fsync.calls")
            with self.phase("syscall.fsync"):
                return original_fsync(descriptor)
        monkeypatch.setattr(os, "fsync", fsync)

        original_init = subprocess.Popen.__init__
        @wraps(original_init)
        def start(process, *args, **kwargs):
            result = original_init(process, *args, **kwargs)
            self.add("subprocess.started." + _executable(args, kwargs))
            return result
        monkeypatch.setattr(subprocess.Popen, "__init__", start)

    def report(self):
        cpu = _cpu()
        with self._lock:
            result = {
                "schema_version": 1, "enabled": self.enabled,
                "complete": not self._problems and self._active == 0,
                "problems": sorted(self._problems | ({"active_spans"} if self._active else set())),
                "observation_ns": time.perf_counter_ns() - self._start,
                "process_cpu": {key: cpu[key] - self._cpu_start[key] for key in cpu},
                "spans": [dict(row) for row in self._spans],
                "captures": [dict(row) for row in self._captures],
                "counters": dict(self._counters),
                "facts": json.loads(json.dumps(self._facts)),
                "fixture_impairment_declaration": {
                    "added_request_delay_ms": self.impairment_ms,
                    "body_bytes_per_second": self.bytes_per_second,
                    "applied_by_recorder": False,
                },
                "limits": [
                    "inclusive overlapping spans, not additive phase totals",
                    "thread CPU excludes other threads and subprocesses; asynchronous spans can include other tasks on that thread",
                    "process CPU covers the whole recorder interval; reaped-child CPU excludes still-running children",
                    "subprocess counts cover this process's successful Popen calls only; children started elsewhere are excluded",
                    "fsync counts are explicit Python os.fsync calls, not SQLite/native or Docker-daemon writes",
                    "HTTP counters are fixture-observed body bytes, not headers, wire bytes, tokens or charges",
                    "capture metadata is producer-reported, not independently rehashed by this observer",
                    "explicit facts and control counters are retained in disabled overhead controls",
                ],
            }
        return result
