"""Bounded installed idle observations for the managed cost investigation.

Reuses the pinned ZPM installer, process-counter observer and lifecycle witness.
Only the test harness gains a target-zero witness. No producer/controller source
is patched. The generated private bundle and its credentials are never exported.
"""

from __future__ import annotations

from contextlib import contextmanager
import hashlib
import importlib
import json
import os
from pathlib import Path
import re
import secrets
import sqlite3
import stat
import subprocess
import sys
import time
from unittest.mock import patch
from urllib.parse import parse_qsl, unquote, urlsplit


ZPM_REVISION = "e8cb65ea7c1717cc5b49c1a6199960a51ac99b9f"
POLYPHONY_REVISION = "6480e36355bf0d5de4e25a560d40e665fd76038c"
WINDOWS = 3
WITNESS_SECONDS = 60
MAX_LOG_BYTES = 131072
MAX_LOG_LINE = 4096
MAX_LOG_LINES = 1024
SNAPSHOT_ARRAYS = frozenset({"task", "attempt", "resource", "problem", "advice", "candidate",
                             "evidence", "work", "response", "destination"})


def require(value, code):
    if not value:
        raise AssertionError(code)


def _git(path, *arguments):
    return subprocess.check_output(
        ["git", "-C", str(path), *arguments], stderr=subprocess.DEVNULL,
        timeout=15, text=True,
    ).strip()


def zero_binding(plan):
    """Require an empty, validated original binding without contacting services."""
    require(type(plan) is dict and type(plan.get("reserved")) is int
            and plan["reserved"] == 0 and len(plan.get("repositories", [])) == 1,
            "idle_zero_plan_invalid")
    row = plan["repositories"][0]
    require(all(type(row.get(name)) is int and row[name] == 0 for name in (
        "desired_workers", "effective_target", "permitted_target", "healthy", "reserved"))
        and row.get("workers") == [] and row.get("enabled") is True
        and row.get("paused") is False and row.get("validation", {}).get("ready") is True,
        "idle_zero_binding_changed")
    result = {"deployment_id": plan.get("deployment_id"),
              "repository": row.get("repository"), "profile": row.get("profile"),
              "binding_revision": row.get("revision")}
    require(all(type(result[name]) is str and 0 < len(result[name]) <= 512
                and not any(ch.isspace() for ch in result[name])
                for name in ("deployment_id", "repository", "profile"))
            and type(result["binding_revision"]) is int and result["binding_revision"] >= 1,
            "idle_zero_identity_invalid")
    return result


def require_empty_snapshot(value, scope):
    """Missing authority fields are unavailable, never an empty task list."""
    require(type(value) is dict and set(value) == SNAPSHOT_ARRAYS | {
        "schema_version", "deployment_id", "repository", "cursor"}, "idle_snapshot_schema")
    require(type(value["schema_version"]) is int and value["schema_version"] == 1
            and type(value["cursor"]) is int and value["cursor"] == 0
            and value["deployment_id"] == scope["deployment_id"]
            and value["repository"] == scope["repository"]
            and all(type(value[name]) is list and value[name] == [] for name in SNAPSHOT_ARRAYS),
            "idle_canonical_work_or_scope_changed")


def retained_cleanup_receipt(result, scope, worker, recorder):
    """Retain a closed diagnostic before requiring the producer's exact refusal.

    A never-dispatched worker deliberately lacks the executed-attempt proof
    required by native physical cleanup. Observing this refusal is not removal.
    """
    output = result.stdout.encode("utf-8")
    value = None
    if len(output) <= 4096:
        try:
            value = json.loads(output)
        except (ValueError, UnicodeError):
            pass
    expected = {"schema_version": 1, **scope, "worker_id": worker,
                "state": "retained", "reason": "executed_capture_required",
                "container_removed": False, "volume_removed": False,
                "archives_retained": True}
    observation = {"returncode": result.returncode, "stdout_bytes": len(output),
                   "state": "unrecognized", "reason": "unrecognized",
                   "identity_matches": False}
    if type(value) is dict:
        for name, allowed in (("state", {"retained", "cleaned"}),
                              ("reason", {"executed_capture_required", ""})):
            observed = value.get(name)
            if type(observed) is str and observed in allowed:
                observation[name] = observed
        observation["identity_matches"] = all(
            type(value.get(name)) is type(expected[name]) and value.get(name) == expected[name]
            for name in ("schema_version", "deployment_id", "repository", "worker_id"))
        for name in ("container_removed", "volume_removed", "archives_retained"):
            observation[name] = value.get(name) if type(value.get(name)) is bool else None
    recorder.fact("installed_cleanup_observation", observation)
    require(type(result.returncode) is int and result.returncode == 1
            and type(value) is dict and set(value) == set(expected)
            and all(type(value[name]) is type(expected[name]) and value[name] == expected[name]
                    for name in expected), "idle_retained_cleanup_receipt_invalid")
    return value


def retained_resource_size(client, container_id, volume_name, volume_identity):
    """Observe the same stopped native resources and their actual volume charge."""
    from src.worker.docker_runtime import ManagedDockerRuntime

    container = client.containers.get(container_id)
    container.reload()
    state = container.attrs.get("State", {})
    mounts = [mount for mount in container.attrs.get("Mounts", [])
              if mount.get("Destination") == "/workspace"]
    require(container.id == container_id and state.get("Running") is False
            and state.get("Restarting", False) is False and state.get("Paused", False) is False
            and state.get("Status") in {"created", "exited", "dead"}
            and len(mounts) == 1 and mounts[0].get("Type") == "volume"
            and mounts[0].get("Name") == volume_name, "idle_retained_container_changed")
    volume = client.volumes.get(volume_name)
    volume.reload()
    require(ManagedDockerRuntime._volume_identity(volume) == volume_identity,
            "idle_retained_volume_changed")
    sizes = [entry.get("UsageData", {}).get("Size") for entry in client.df().get("Volumes", [])
             if entry.get("Name") == volume_name]
    require(len(sizes) == 1 and type(sizes[0]) is int and sizes[0] >= 0,
            "idle_retained_storage_unavailable")
    return sizes[0]


def retained_worker_rows(state, identity, scope):
    """Read the original journal after failed convergence without initialization."""
    try:
        descriptor = os.open(state, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW)
    except OSError:
        raise AssertionError("idle_original_journal_changed") from None
    try:
        def unchanged():
            opened, named = os.fstat(descriptor), state.lstat()
            require(stat.S_ISREG(opened.st_mode) and stat.S_ISREG(named.st_mode)
                    and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino) == identity,
                    "idle_original_journal_changed")

        unchanged()
        with sqlite3.connect(state.as_uri() + "?mode=ro", uri=True, timeout=1) as db:
            unchanged()
            db.row_factory = sqlite3.Row
            actual = db.execute("SELECT value FROM metadata WHERE key='deployment_id'").fetchone()
            require(actual is not None and actual[0] == scope["deployment_id"], "idle_original_scope_changed")
            rows = [dict(row) for row in db.execute("SELECT * FROM workers")]
            unchanged()
    finally:
        os.close(descriptor)
    require(len(rows) <= 1 and all(row["repository"] == scope["repository"] for row in rows),
            "idle_original_reservations_changed")
    for row in rows:
        row["snapshot"] = json.loads(row["snapshot"])
    return rows


@contextmanager
def original_store(store_type, state, identity, scope):
    """Open existing control state without permitting a fresh initialization."""
    retained_worker_rows(state, identity, scope)
    with store_type(state, scope["deployment_id"], create=False) as store:
        retained_worker_rows(state, identity, scope)
        yield store


def _zero_event(line, binding):
    """Recognize only one existing scoped lifecycle capability response."""
    try:
        text = line.decode("utf-8", errors="strict")
    except UnicodeError:
        raise AssertionError("idle_log_encoding") from None
    match = re.fullmatch(
        r'INFO:\s+127\.0\.0\.1:([0-9]{1,5}) - "([A-Z]+) ([^ "\r\n]+) HTTP/1\.[01]" ([0-9]{3}) ([^\r\n]+)',
        text,
    )
    if match is None:
        require("/api/workers" not in text, "idle_log_ambiguous_lifecycle")
        return None
    port, method, target, status, reason = match.groups()
    try:
        url = urlsplit(target)
        path = unquote(url.path, encoding="utf-8", errors="strict")
        if not path.startswith("/api/workers"):
            return None
        pairs = parse_qsl(url.query, keep_blank_values=True, strict_parsing=True,
                          encoding="utf-8", errors="strict", max_num_fields=4)
    except (ValueError, UnicodeError):
        raise AssertionError("idle_log_target_invalid") from None
    expected = {name: binding[name] for name in ("deployment_id", "repository", "profile")}
    require(not url.scheme and not url.netloc and not url.fragment
            and 1 <= int(port) <= 65535 and method == "GET" and status == "200"
            and reason == "OK" and path == "/api/workers/capabilities"
            and len(pairs) == len(dict(pairs)) and dict(pairs) == expected,
            "idle_zero_unexpected_lifecycle")
    return "capabilities"


def witness_zero(path, binding, manager, start, clock, sleep):
    """Three passive C/C/C starts contain a complete middle zero-target cycle.

    This specializes ZPM's bounded C/O/C/O/C witness for a proven empty binding.
    Log offsets and reader times remain observations, not server tick timestamps.
    """
    deadline = start + WITNESS_SECONDS * 1_000_000_000
    previous = start

    def now():
        nonlocal previous
        value = clock()
        require(type(value) is int and previous <= value < deadline,
                "idle_witness_deadline")
        previous = value
        return value

    now()
    path = Path(path)
    descriptor = os.open(path, os.O_RDONLY | os.O_CLOEXEC | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        original = os.fstat(descriptor)
        require(stat.S_ISREG(original.st_mode), "idle_log_not_regular")
        offset = os.lseek(descriptor, 0, os.SEEK_END)
        position = offset
        discard_partial = False
        if offset:
            os.lseek(descriptor, offset - 1, os.SEEK_SET)
            discard_partial = os.read(descriptor, 1) != b"\n"
            os.lseek(descriptor, offset, os.SEEK_SET)
        events, buffer = [], b""
        examined = discarded = 0
        line_start = offset

        def unchanged():
            opened, named = os.fstat(descriptor), path.lstat()
            require(stat.S_ISREG(named.st_mode)
                    and (opened.st_dev, opened.st_ino) == (named.st_dev, named.st_ino)
                    == (original.st_dev, original.st_ino)
                    and position <= opened.st_size <= offset + MAX_LOG_BYTES,
                    "idle_log_identity_or_size_changed")

        while True:
            now()
            require(manager.poll() is None, "idle_manager_exited")
            unchanged()
            chunk = os.read(descriptor, min(4096, MAX_LOG_BYTES - (position - offset) + 1))
            position += len(chunk)
            require(position - offset <= MAX_LOG_BYTES, "idle_log_bytes_exhausted")
            buffer += chunk
            while b"\n" in buffer:
                line, buffer = buffer.split(b"\n", 1)
                end = line_start + len(line) + 1
                examined += 1
                require(len(line) + 1 <= MAX_LOG_LINE and examined <= MAX_LOG_LINES,
                        "idle_log_records_exhausted")
                observed = now()
                if discard_partial:
                    discarded = end - offset
                    discard_partial = False
                elif _zero_event(line, binding) is not None:
                    events.append({"event": "capabilities", "log_start_offset": line_start,
                                   "log_end_offset": end,
                                   "reader_observed_after_start_ns": observed - start})
                    if len(events) == 3:
                        unchanged()
                        now()
                        return {"binding": dict(binding), "events": events,
                                "log_start_offset": offset, "log_read_end_offset": position,
                                "log_bytes_read": position - offset,
                                "complete_lines_examined": examined,
                                "discarded_partial_prefix_bytes": discarded,
                                "observation_limit_seconds": WITNESS_SECONDS,
                                "timing_scope": "reader observations of complete access records; not server tick timestamps"}
                line_start = end
            require(len(buffer) < MAX_LOG_LINE, "idle_log_line_exhausted")
            if not chunk:
                observed = now()
                sleep(min(0.1, (deadline - observed) / 1_000_000_000))
    finally:
        os.close(descriptor)


@contextmanager
def _harness_imports(zpm):
    """Load exact approved test helpers, not an ambient checkout or installed copy."""
    names = ("check_stack", "check_model_stack", "operational_measurement")
    require(not any(name in sys.modules for name in (*names, "zpm")),
            "installed_harness_module_collision")
    old = list(sys.path)
    sys.path[:0] = [str(zpm / "tests/contracts"), str(zpm)]
    try:
        modules = [importlib.import_module(name) for name in names]
        require(all(Path(module.__file__).resolve().is_relative_to(zpm) for module in modules),
                "installed_harness_source_changed")
        yield modules
    finally:
        sys.path[:] = old


def run_case(case, workdir, recorder, images, monkeypatch):
    """One installed bundle, six windows and explicitly retained idle custody."""
    zpm = Path(case["zpm_checkout"]).resolve(strict=True)
    polyphony = Path(case["polyphony_checkout"]).resolve(strict=True)
    openjules = Path(__file__).resolve().parents[1]
    sources = {"zpm": zpm, "polyphony": polyphony, "openjules": openjules}
    revisions = {name: _git(path, "rev-parse", "HEAD") for name, path in sources.items()}
    require(revisions["zpm"] == ZPM_REVISION and revisions["polyphony"] == POLYPHONY_REVISION,
            "installed_source_pin_changed")
    require(all(not _git(path, "status", "--porcelain", "--untracked-files=all")
                for path in sources.values()), "installed_sources_not_clean")
    reference_path = Path(case["dependency_plan"]).resolve(strict=True)
    require(reference_path.is_file() and reference_path.stat().st_size <= 16384,
            "installed_dependency_reference_invalid")
    reference = json.loads(reference_path.read_text(encoding="utf-8"))
    image = images["agent"][1]
    require(re.fullmatch(r"sha256:[0-9a-f]{64}", image), "installed_image_invalid")
    root = Path(workdir) / "installed-idle"
    root.mkdir(mode=0o700)
    fixture = root / "source"
    fixture.mkdir(mode=0o755)
    (fixture / "answer.py").write_text("def answer():\n    return 0\n", encoding="utf-8")
    for args in (["init", "-q"], ["add", "answer.py"],
                 ["-c", "user.name=Managed Cost Fixture", "-c", "user.email=fixture@example.invalid",
                  "commit", "-qm", "controlled idle input"]):
        _git(fixture, *args)
    base = _git(fixture, "rev-parse", "HEAD")
    with _harness_imports(zpm) as (support, model_support, measurement):
        from zpm.controller import Controller
        from zpm.deployment import MODEL_TOKEN_ENV, _command, _environment, prepare, verify
        from zpm.models import released, snapshot as worker_snapshot
        from zpm.store import Store

        processes = support.Processes(root)
        scope = {"deployment_id": "cost-idle-" + secrets.token_hex(8),
                 "repository": "github:github.com/managed-cost-fixture/idle"}
        profile = "cost-idle-model-v1"
        bundle = root / "installation"
        windows, worker, installation = [], None, None
        container_id = volume_name = volume_identity = None
        retention_confirmed = acquisition_started = False
        with model_support.ModelFixture() as model:
            manager_environment = support.clean_environment({model_support.TOKEN_SOURCE: model.token})
            authority_port, runtime_port = support.port(), support.port()
            while authority_port == runtime_port:
                runtime_port = support.port()
            config = {
                "schema_version": 1, "deployment_id": scope["deployment_id"],
                "binding": {"schema_version": 1, "repository": scope["repository"],
                            "profile": profile, "desired_workers": 0},
                "max_workers": 1,
                "sources": {name: {"checkout": str(path), "revision": revisions[name]}
                            for name, path in sources.items()},
                "source": {"checkout": str(fixture), "revision": base}, "image": image,
                "command": ["python3", "-I", "-S", "/opt/openjules/managed_runner.py",
                            "--socket", "/run/openjules-model/model.sock", "--max-turns", "4",
                            "--verify-json", json.dumps(["python3", "-I", "-c", "pass"])],
                "ports": {"polyphony": authority_port, "openjules": runtime_port},
                "runtime": {"max_seconds": 240},
                "policy": {"checks": ["controlled-test"], "reviewers": ["operator"],
                           "max_attempts": 1, "budget_seconds": 300, "attempt_seconds": 180,
                           "capabilities": ["python"]},
                "model_policy": {"endpoint": model.endpoint, "model": model_support.MODEL_NAME,
                                 "token_ref": "env:" + model_support.TOKEN_SOURCE,
                                 "max_calls": 4, "max_output_tokens": 1024,
                                 "max_total_output_tokens": 4096, "request_timeout_seconds": 10},
                "dependency_plan": reference,
            }
            with recorder.phase("installed_prepare"):
                prepare(config, bundle)
                verify(bundle)
            data = json.loads((bundle / "manifest.json").read_text())["configuration"]
            commands = {name: _command(bundle, name, data) for name in sources}
            manager = [sys.executable, str(bundle / "manage.py")]
            state = bundle / "state/zpm.sqlite3"
            state_info = state.lstat()
            state_identity = (state_info.st_dev, state_info.st_ino)
            runtime_config = json.loads((bundle / "config/openjules.json").read_text())
            require(runtime_config["poll_interval_seconds"] == 1
                    and runtime_config["models"][0]["policy"]["token_ref"] == "env:" + MODEL_TOKEN_ENV,
                    "installed_runtime_configuration_changed")
            tokens = json.loads((bundle / "secrets/environment.json").read_text())
            authority = support.Client(f"http://127.0.0.1:{authority_port}", tokens["POLYPHONY_RUNTIME_TOKEN"])
            runtime = support.Client(f"http://127.0.0.1:{runtime_port}", tokens["OPENJULES_WORKER_TOKEN"])

            def plan():
                with original_store(Store, state, state_identity, scope) as store:
                    return Controller(store).plan()

            def target(count):
                with original_store(Store, state, state_identity, scope) as store:
                    store.change(scope["repository"], "target", count)
                return support.wait_for_capacity(plan, processes, count)

            def model_counts():
                with model.lock:
                    counts = {"requests": len(model.requests), "errors": len(model.errors)}
                require(counts == {"requests": 0, "errors": 0}, "idle_performed_inference")
                return counts

            def canonical_empty():
                value = authority.request("GET", "/managed/snapshot", query=scope)
                require_empty_snapshot(value, scope)
                return True

            def register_original_worker():
                nonlocal worker, container_id, volume_name, volume_identity
                from tools.managed_costs import register_container
                from src.worker.docker_runtime import ManagedDockerRuntime
                rows = retained_worker_rows(state, state_identity, scope)
                require(len(rows) == 1, "idle_original_worker_unresolved")
                original = rows[0]["snapshot"].get("worker_id")
                require(type(original) is str and original and worker in (None, original),
                        "idle_original_worker_identity_changed")
                worker = original
                containers = images["agent"][0].containers.list(
                    all=True, filters={"label": "openjules.worker=" + worker})
                require(len(containers) == 1 and container_id in (None, containers[0].id),
                        "idle_container_identity_ambiguous")
                container_id = containers[0].id
                containers[0].reload()
                mounts = [mount for mount in containers[0].attrs.get("Mounts", [])
                          if mount.get("Destination") == "/workspace"]
                require(len(mounts) == 1 and mounts[0].get("Type") == "volume"
                        and type(mounts[0].get("Name")) is str and mounts[0]["Name"]
                        and volume_name in (None, mounts[0]["Name"]), "idle_volume_identity_ambiguous")
                volume_name = mounts[0]["Name"]
                volume = images["agent"][0].volumes.get(volume_name)
                volume.reload()
                current_identity = ManagedDockerRuntime._volume_identity(volume)
                require(volume_identity is None or volume_identity == current_identity,
                        "idle_original_volume_changed")
                volume_identity = current_identity
                register_container(workdir, images["agent"][0], container_id)
                recorder.fact("installed_owned_worker_id", worker)

            def retire_and_observe_retention():
                """Respect the native no-attempt retention gate without inventing work."""
                nonlocal retention_confirmed
                from tools.managed_costs import mark_container_terminal, write_private

                require(worker is not None and installation is not None
                        and installation.poll() is None, "idle_cleanup_owner_unavailable")
                with recorder.phase("installed_retirement"):
                    target(0)
                    retired = runtime.request("GET", "/api/workers/" + worker, query=scope)
                    require(retired["worker_id"] == worker and released(worker_snapshot(retired)),
                            "idle_worker_not_retired")
                    owned_container = images["agent"][0].containers.get(container_id)
                    owned_container.reload()
                    require(owned_container.attrs["State"]["Running"] is False,
                            "idle_native_termination_unconfirmed")
                    mark_container_terminal(workdir, container_id, state="stopped")
                processes.stop("installation")
                require(installation.poll() == 130, "installed_manager_shutdown_unconfirmed")
                # The existing native cleanup interface retains its own proof gates.
                with patch.dict(os.environ, manager_environment, clear=True):
                    env = {name: _environment(bundle, name, data) for name in ("polyphony", "openjules")}
                processes.start("cleanup-authority", commands["polyphony"], polyphony, env["polyphony"])
                support.eventually(canonical_empty, processes, "retained idle authority", 30)
                with recorder.phase("installed_owned_cleanup"):
                    result = subprocess.run(commands["openjules"] + ["--cleanup-worker", worker,
                                            "--deployment-id", scope["deployment_id"],
                                            "--repository", scope["repository"]],
                                            cwd=openjules, env=env["openjules"], capture_output=True,
                                            text=True, timeout=60)
                cleanup = retained_cleanup_receipt(result, scope, worker, recorder)
                retained_bytes = retained_resource_size(images["agent"][0], container_id,
                                                        volume_name, volume_identity)
                reserved = plan()["reserved"]
                require(type(reserved) is int and reserved == 0, "idle_capacity_not_retired")
                canonical_empty()
                model_counts()
                verify(bundle)
                retention = {"schema_version": 1, "state": "retained_stopped", "scope": scope,
                             "worker_id": worker, "container_id": container_id,
                             "volume_name": volume_name,
                             "volume_identity_sha256": hashlib.sha256(json.dumps(
                                 volume_identity, sort_keys=True, separators=(",", ":")).encode()).hexdigest(),
                             "reason": "executed_capture_required", "observed_stopped": True,
                             "capacity_reserved": reserved, "model_fixture_calls": 0, "tasks_enrolled": 0,
                             "volume_storage_bytes": retained_bytes}
                write_private(Path(workdir) / "installed-retention.json", retention)
                retention_confirmed = True
                case["_guard"]["uncertain"] = False
                write_private(Path(workdir) / "installed-acquisition.json", {
                    "schema_version": 1, "state": "retained_stopped", "scope": scope,
                    "worker_ceiling": 1, "memory_reservation_bytes": 0,
                })
                return cleanup, retention, worker_snapshot(retired)

            try:
                # The sealed plan was acquired separately before benchmark admission.
                with recorder.phase("installed_offline_bootstrap"):
                    processes.run_once("bootstrap", manager + ["bootstrap"], bundle,
                                       support.clean_environment(), 300)
                installation = processes.start("installation", manager + ["start"], bundle, manager_environment)

                def ready():
                    result = subprocess.run(manager + ["doctor"], cwd=bundle,
                                            env=support.clean_environment(), capture_output=True,
                                            text=True, timeout=50)
                    require(result.returncode in (0, 3), "installed_doctor_failed")
                    return json.loads(result.stdout).get("ready") is True

                with recorder.phase("installed_readiness"):
                    support.eventually(ready, processes, "idle installation readiness", 60)
                canonical_empty()
                model_counts()
                sample_args = (installation, commands | {"manager": manager + ["start"]},
                               {name: sources[name] for name in sources} | {"manager": bundle.resolve()})
                log = root / "installation.log"
                for target_count in (0, 1):
                    if target_count:
                        # The parent samples a possible partial acquisition even
                        # before this process receives a ready worker identity.
                        from tools.managed_costs import write_private
                        write_private(Path(workdir) / "installed-acquisition.json", {
                            "schema_version": 1, "state": "may_acquire", "scope": scope,
                            "worker_ceiling": 1, "memory_reservation_bytes": 512 * 1024 * 1024,
                        })
                        acquisition_started = True
                        case["_guard"]["uncertain"] = True
                        with recorder.phase("installed_target_one_convergence"):
                            target(1)
                        register_original_worker()
                        require(measurement.idle_worker_binding(plan())["worker_id"] == worker,
                                "idle_ready_worker_changed")
                    for number in range(WINDOWS):
                        before_plan = plan()
                        binding = measurement.idle_worker_binding(before_plan) if target_count else zero_binding(before_plan)
                        counts_before = model_counts()
                        with recorder.phase("installed_idle_" + str(target_count)):
                            if target_count:
                                sample = measurement.idle_process_sample(*sample_args, log_path=log, binding=binding)
                            else:
                                with patch.object(measurement, "_idle_reconciliation_witness", witness_zero):
                                    sample = measurement.idle_process_sample(*sample_args, log_path=log, binding=binding)
                        after_plan, counts_after = plan(), model_counts()
                        if target_count:
                            measurement.confirm_idle_reconciliation(sample, binding, after_plan,
                                                                   counts_before, counts_after)
                        else:
                            require(binding == zero_binding(after_plan), "idle_zero_changed_during_sample")
                            sample["fixture_counts"] = {"before": counts_before, "after": counts_after}
                            sample["reconciliation_witness"]["ready_binding_unchanged"] = True
                            sample["completed_reconcile_tick_proven"] = True
                        sample.update(target=target_count, window=number + 1)
                        windows.append(sample)
                recorder.fact("installed_windows", windows)
                canonical_empty()
                cleanup, retention, retired = retire_and_observe_retention()
                facts = {"component_revisions": revisions, "image_id": image, "windows": windows,
                         "controller_interval_seconds": 5.0, "runtime_poll_interval_seconds": 1,
                         "model_fixture_calls": 0, "tasks_enrolled": 0, "final_reserved": plan()["reserved"],
                         "worker_id": worker, "cleanup_receipt": cleanup,
                         "known_retained_custody": retention, "retired_worker": retired,
                         "proof": "actual installed services and Docker; passive installed-controller-cycle witnesses",
                         "counter_scope": "ZPM observer self CPU and endpoint RSS, separate from outer sampled process-tree/container memory",
                         "helper_sha256": {name: hashlib.sha256((zpm / "tests/contracts" / name).read_bytes()).hexdigest()
                                           for name in ("operational_measurement.py", "check_stack.py", "check_model_stack.py")}}
                require(all(token not in json.dumps(facts) for token in (*tokens.values(), model.token)),
                        "installed_report_credential_leak")
                return facts
            finally:
                if not retention_confirmed and acquisition_started:
                    # Attempt only the original producer's recovery. A failed or
                    # interrupted cleanup stays unresolved; do not force-remove it.
                    try:
                        if worker is None or container_id is None:
                            # First close new admission through the retained
                            # controller. Convergence failure is not no-effect.
                            target(0)
                            register_original_worker()
                        retire_and_observe_retention()
                        recorder.fact("failed_sample_cleanup", "confirmed_retained")
                    except BaseException:
                        recorder.fact("failed_sample_cleanup", "unresolved")
                processes.close()
