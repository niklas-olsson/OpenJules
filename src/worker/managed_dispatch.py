"""Trusted host dispatcher connecting capacity to canonical task authority.

The SQLite file contains delivery intents and receipts, not task ownership,
budgets, reviews or acceptance. Polyphony is the authority for those facts.
Every worker incarnation runs at most one root and is then retired in Docker.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import hashlib
import json
import logging
import math
from pathlib import Path
import sqlite3
import threading
import time
from uuid import uuid4

from src.worker.destination import connect_journal
from src.worker.managed_configuration import validate_dispatcher_configuration

from src.polyphony.managed_client import (
    AuthorityRejected,
    AuthorityUnavailable,
    ManagedAuthorityClient,
)
from src.worker.lifecycle import (
    LifecycleConflict,
    RuntimeUnavailable,
    WorkerLifecycle,
    WorkerScope,
    WorkerSpec,
)

logger = logging.getLogger(__name__)


def _json(value) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


class DispatchJournal:
    def __init__(self, directory: str | Path, *, journal_binding=None):
        self.journal_binding = journal_binding
        self.directory = Path(directory).resolve()
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.database = self.directory / "dispatch.sqlite3"
        self.locks = self.directory / "dispatch-locks"
        self.locks.mkdir(exist_ok=True, mode=0o700)
        with self.connection(initializing=True) as db:
            db.execute("PRAGMA journal_mode=WAL")
            db.execute(
                "CREATE TABLE IF NOT EXISTS deliveries ("
                "worker_id TEXT PRIMARY KEY,spec TEXT NOT NULL,task_id TEXT NOT NULL,"
                "request_key TEXT NOT NULL,phase TEXT NOT NULL,binding TEXT,"
                "artifacts TEXT NOT NULL DEFAULT '{}',reason TEXT NOT NULL DEFAULT '')"
            )
            if self.journal_binding is not None:
                self.journal_binding.seal(db)

    @contextmanager
    def connection(self, *, initializing=False):
        db = connect_journal(self.database, binding=self.journal_binding, initializing=initializing, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def lock(self, name: str):
        # Names are generated worker UUIDs or the fixed service lock. They are
        # never arbitrary paths from repository code or an HTTP request.
        if name != "service" and (
            len(name) != 32 or any(c not in "0123456789abcdef" for c in name)
        ):
            raise ValueError("invalid dispatcher lock identity")
        with (self.locks / f"{name}.lock").open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def get(self, worker_id: str):
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM deliveries WHERE worker_id=?", (worker_id,)
            ).fetchone()
        return dict(row) if row else None

    def reserve(self, worker: dict, task_id: str):
        spec = WorkerSpec(
            **{key: worker[key] for key in WorkerSpec.__dataclass_fields__}
        )
        with self.connection() as db:
            db.execute(
                "INSERT OR IGNORE INTO deliveries (worker_id,spec,task_id,request_key,phase) "
                "VALUES (?,?,?,?, 'claiming')",
                (worker["worker_id"], _json(asdict(spec)), task_id, uuid4().hex),
            )
        return self.get(worker["worker_id"])

    def update(self, worker_id: str, **changes):
        if not changes or not set(changes) <= {
            "phase",
            "binding",
            "artifacts",
            "reason",
        }:
            raise ValueError("invalid journal update")
        with self.connection() as db:
            db.execute(
                "UPDATE deliveries SET "
                + ",".join(f"{key}=?" for key in changes)
                + " WHERE worker_id=?",
                (*changes.values(), worker_id),
            )

    def rejected_claim(self, worker_id: str):
        with self.connection() as db:
            db.execute(
                "DELETE FROM deliveries WHERE worker_id=? AND phase='claiming' AND binding IS NULL",
                (worker_id,),
            )


class ManagedDispatcher:
    def __init__(
        self,
        lifecycle: WorkerLifecycle,
        runtime,
        authority: ManagedAuthorityClient,
        profiles,
        state_directory: str | Path,
        *,
        poll_interval_seconds: float = 1,
        max_parallel: int = 16,
        model_broker=None,
        child_supervisor=None,
        journal_binding=None,
    ):
        validate_dispatcher_configuration(poll_interval_seconds, max_parallel)
        self.lifecycle = lifecycle
        self.runtime = runtime
        self.authority = authority
        self.profiles = {(p.deployment_id, p.repository, p.name): p for p in profiles}
        self.journal = DispatchJournal(state_directory, journal_binding=journal_binding)
        self.poll_interval_seconds = poll_interval_seconds
        self.max_parallel = max_parallel
        self.model_broker = model_broker
        self.child_supervisor = child_supervisor
        self.running = threading.Event()
        self.stop_requested = threading.Event()

    def profile(self, spec: WorkerSpec):
        return self.profiles[(spec.deployment_id, spec.repository, spec.profile)]

    def model_permission(self, model_binding):
        """Authorize inference against the original admitted canonical binding."""
        spec = model_binding.spec
        row = self.journal.get(model_binding.worker_id)
        if (
            self.stop_requested.is_set()
            or row is None
            or row["phase"] != "dispatching"
            or row["spec"] != _json(asdict(spec))
            or not row["binding"]
            or (
                self.child_supervisor is not None
                and self.child_supervisor.retiring(model_binding.worker_id)
            )
        ):
            return 0
        original = json.loads(row["binding"])
        profile = self.profile(spec)
        attempt_id = self._verify_binding(
            original, spec, model_binding.worker_id, profile, model_binding.attempt_id
        )
        permission = self.authority.call(
            "permission", spec.scope, attempt_id=attempt_id
        )
        self._verify_binding(
            permission, spec, model_binding.worker_id, profile, attempt_id
        )
        current = self.journal.get(model_binding.worker_id)
        remaining = permission.get("remaining_seconds")
        if (
            self.stop_requested.is_set()
            or current is None
            or current["phase"] != "dispatching"
            or current["spec"] != row["spec"]
            or current["binding"] != row["binding"]
            or permission["binding"] != original["binding"]
            or permission["requirements"] != original["requirements"]
            or not permission["launch_allowed"]
            or type(remaining) not in {int, float}
            or not math.isfinite(remaining)
            or remaining <= 0
            or (
                self.child_supervisor is not None
                and self.child_supervisor.retiring(model_binding.worker_id)
            )
        ):
            return 0
        return min(profile.max_seconds, remaining)

    def child_root_active(self, context):
        row = self.journal.get(context.worker_id)
        if (
            self.stop_requested.is_set()
            or row is None
            or row["phase"] != "dispatching"
            or row["spec"] != _json(asdict(context.spec))
            or not row["binding"]
        ):
            return False
        binding = json.loads(row["binding"])["binding"]
        return (
            binding["attempt_id"] == context.attempt_id
            and binding["worker_id"] == context.worker_id
        )

    def _uses_model(self, spec):
        return (
            self.model_broker is not None
            and (spec.deployment_id, spec.repository, spec.profile)
            in self.model_broker.policies
        )

    def _revoke_model(self, worker_id, spec, attempt_id):
        if self._uses_model(spec):
            from src.worker.model_broker import BrokerDenied

            try:
                self.model_broker.revoke_attempt(worker_id, attempt_id)
            except BrokerDenied:
                # A cancellation before model binding has no inference grant.
                pass

    @staticmethod
    def _spec(worker: dict) -> WorkerSpec:
        return WorkerSpec(
            **{key: worker[key] for key in WorkerSpec.__dataclass_fields__}
        )

    def _choose_task(self, snapshot: dict, profile):
        tasks, attempts = snapshot.get("task"), snapshot.get("attempt")
        if not isinstance(tasks, list) or not isinstance(attempts, list):
            raise AuthorityUnavailable("Canonical snapshot is incomplete")
        capability = self.authority.capabilities(
            WorkerScope(profile.deployment_id, profile.repository),
            profile.name,
            profile.base_commit,
        )
        allocation = capability.get("attempt_seconds")
        supported = capability.get("capabilities")
        if (
            isinstance(allocation, bool)
            or not isinstance(allocation, (int, float))
            or not math.isfinite(allocation)
            or allocation <= 0
            or not isinstance(supported, list)
            or any(not isinstance(item, str) for item in supported)
        ):
            raise AuthorityUnavailable("Canonical allocation capability is incomplete")
        unresolved = {
            a["task"] for a in attempts if a.get("termination_confirmed") is not True
        }
        eligible = [
            t
            for t in tasks
            if t.get("status") in {"todo", "in_progress"}
            and t.get("id") not in unresolved
            and not t.get("dependency_problem")
            and t.get("attempts", 0) < t.get("max_attempts", 0)
            and t.get("allocated_seconds", 0) + allocation <= t.get("budget_seconds", 0)
            and set(t.get("required", [])) <= set(supported)
        ]
        # Selection is advisory. Only the atomic canonical claim can grant work.
        eligible.sort(
            key=lambda task: (
                -task.get("priority", 0),
                task.get("created", 0),
                task["id"],
            )
        )
        return eligible[0] if eligible else None

    @staticmethod
    def _verify_binding(
        response: dict, spec: WorkerSpec, worker_id: str, profile, attempt_id=None
    ):
        binding, attempt = response.get("binding"), response.get("attempt")
        if (
            not isinstance(binding, dict)
            or not isinstance(attempt, dict)
            or binding.get("deployment_id") != spec.deployment_id
            or binding.get("repository") != spec.repository
            or binding.get("profile") != spec.profile
            or binding.get("worker_id") != worker_id
            or binding.get("base") != profile.base_commit
            or not isinstance(binding.get("attempt_id"), str)
            or binding["attempt_id"] != attempt.get("id")
            or (attempt_id is not None and binding["attempt_id"] != attempt_id)
            or not isinstance(response.get("requirements"), str)
            or type(response.get("launch_allowed")) is not bool
            or not isinstance(binding.get("launch_key"), str)
            or not binding["launch_key"]
        ):
            raise AuthorityUnavailable("Canonical execution binding does not match")
        return binding["attempt_id"]

    def tick_worker(self, worker: dict):
        worker_id = worker["worker_id"]
        with self.journal.lock(worker_id) as acquired:
            if not acquired:
                return
            row = self.journal.get(worker_id)
            if row and row["phase"] == "completed":
                return
            spec = self._spec(worker)
            profile = self.profile(spec)
            if row is None:
                if (
                    self.stop_requested.is_set()
                    or worker["state"] != "ready"
                    or not worker["admission_open"]
                ):
                    return
                task = self._choose_task(self.authority.snapshot(spec.scope), profile)
                if task is None:
                    return  # No inference or model polling while idle.
                row = self.journal.reserve(worker, task["id"])
            if row["spec"] != _json(asdict(spec)):
                raise LifecycleConflict("Dispatcher incarnation binding changed")
            if row["phase"] == "claiming":
                try:
                    response = self.authority.call(
                        "claim",
                        spec.scope,
                        profile=spec.profile,
                        worker_id=worker_id,
                        task_id=row["task_id"],
                        request_key=row["request_key"],
                        base=profile.base_commit,
                    )
                except AuthorityRejected as exc:
                    if exc.status == 409 and exc.claim_not_allocated:
                        # An explicit rejected atomic claim created no attempt.
                        # A timeout/5xx never clears the original delivery key.
                        self.journal.rejected_claim(worker_id)
                    raise
                self._verify_binding(response, spec, worker_id, profile)
                self.journal.update(worker_id, phase="bound", binding=_json(response))
                row = self.journal.get(worker_id)
            bound = json.loads(row["binding"])
            attempt_id = self._verify_binding(bound, spec, worker_id, profile)
            before = time.monotonic()
            permission = self.authority.call(
                "permission", spec.scope, attempt_id=attempt_id
            )
            self._verify_binding(permission, spec, worker_id, profile, attempt_id)
            if (
                permission["binding"] != bound["binding"]
                or permission["requirements"] != bound["requirements"]
            ):
                raise AuthorityUnavailable(
                    "Canonical immutable execution binding changed"
                )
            remaining = permission.get("remaining_seconds")
            if (
                isinstance(remaining, bool)
                or not isinstance(remaining, (int, float))
                or not math.isfinite(remaining)
            ):
                raise AuthorityUnavailable("Canonical execution deadline is invalid")
            cutoff = before + min(profile.max_seconds, remaining)
            allowed = (
                permission["launch_allowed"]
                and cutoff > time.monotonic()
                and not self.stop_requested.is_set()
            )

            active = self.lifecycle.observe_worker(spec.scope, worker_id)[
                "active_executions"
            ]
            if row["phase"] in {"bound", "admitted"} and allowed:
                if attempt_id not in active:
                    try:
                        self.lifecycle.begin_execution(
                            spec.scope, worker_id, attempt_id
                        )
                    except LifecycleConflict:
                        current = self.lifecycle.observe_worker(spec.scope, worker_id)
                        if current["admission_open"]:
                            return  # An observer may briefly own the runtime lock.
                        allowed = False
                if allowed:
                    # Persist before any call that can start repository code.
                    self.journal.update(worker_id, phase="dispatching")
                    row = self.journal.get(worker_id)

            remaining = cutoff - time.monotonic()
            allowed = allowed and remaining > 0 and not self.stop_requested.is_set()
            children = (
                self.child_supervisor
                if self.child_supervisor is not None
                and self.child_supervisor.enabled(spec)
                else None
            )
            if children is not None:
                children.bind_root(worker_id, spec, bound, cutoff)
                if allowed and row["phase"] != "cancelling":
                    children.reconcile(worker_id)
                if children.retiring(worker_id):
                    allowed = False
            if allowed and row["phase"] != "cancelling" and self._uses_model(spec):
                from src.worker.model_broker import BrokerDenied

                try:
                    self.model_broker.bind_attempt(
                        worker_id,
                        spec,
                        attempt_id,
                        remaining,
                        deadline_monotonic=cutoff,
                    )
                except BrokerDenied:
                    allowed = False
            if not allowed or row["phase"] == "cancelling":
                self.journal.update(worker_id, phase="cancelling")
                self._revoke_model(worker_id, spec, attempt_id)
                receipt = self.runtime.cancel_attempt(
                    worker_id, spec, attempt_id, bound["requirements"]
                )
            else:
                # Runtime intent/tombstones make this the same execution after
                # a lost reply. A smaller remaining limit cannot extend it.
                receipt = self.runtime.execute_attempt(
                    worker_id,
                    spec,
                    attempt_id,
                    bound["requirements"],
                    remaining,
                    deadline_monotonic=cutoff,
                )

            if receipt.termination_confirmed and receipt.launch_fenced:
                self._revoke_model(worker_id, spec, attempt_id)

            if not (
                receipt.termination_confirmed
                and receipt.artifacts_captured
                and receipt.launch_fenced
            ):
                self.journal.update(
                    worker_id, reason="Execution or capture remains unresolved"
                )
                self.authority.call(
                    "observe",
                    spec.scope,
                    attempt_id=attempt_id,
                    state="unknown",
                    termination_confirmed=False,
                    launch_fenced=False,
                    artifacts={},
                )
                return
            self._publish_capture(worker_id, spec, attempt_id, row, receipt)

    def _publish_capture(self, worker_id, spec, attempt_id, row, receipt):
        public = (
            None if self.child_supervisor is None
            else getattr(self.child_supervisor, "public_supervisor", None)
        )
        if public is not None and public.enabled(spec):
            receipt = public.effective_receipt(worker_id, receipt, prepare=True)
        if self.child_supervisor is not None and self.child_supervisor.enabled(spec):
            # A canonical root terminal cannot precede any allocated child,
            # including a grant whose reply was lost before local binding.
            self.child_supervisor.finalize(worker_id, receipt)
        artifacts = json.loads(row["artifacts"])
        # The runtime supplies durable bytes, not arbitrary guest paths. Patch
        # and logs remain untrusted evidence; no test result is self-accepted.
        contents = {
            "patch": receipt.patch,
            "log": receipt.log,
            "manifest": (
                receipt.manifest
                if isinstance(receipt.manifest, str)
                else _json(receipt.manifest)
            ),
        }
        for kind, content in contents.items():
            if not isinstance(content, str):
                raise LifecycleConflict("Runtime capture must contain immutable text")
            expected_hash = hashlib.sha256(content.encode()).hexdigest()
            if kind in artifacts and artifacts[kind] != expected_hash:
                raise LifecycleConflict("Previously delivered capture changed")
            if kind not in artifacts:
                result = self.authority.call(
                    "capture",
                    spec.scope,
                    attempt_id=attempt_id,
                    kind=kind,
                    content=content,
                )
                if (
                    result.get("attempt_id") != attempt_id
                    or result.get("kind") != kind
                    or result.get("artifact_id") != expected_hash
                ):
                    raise AuthorityUnavailable(
                        "Canonical capture receipt does not match"
                    )
                artifacts[kind] = result["artifact_id"]
                self.journal.update(worker_id, artifacts=_json(artifacts))
        self.authority.call(
            "observe",
            spec.scope,
            attempt_id=attempt_id,
            state="timed_out" if receipt.state == "timed_out" else "exited",
            termination_confirmed=True,
            launch_fenced=True,
            artifacts=artifacts,
        )
        if receipt.exit_code == 0 and contents["patch"]:
            # Candidate is a review request, never authority to merge or release.
            try:
                self.authority.call(
                    "candidate",
                    spec.scope,
                    attempt_id=attempt_id,
                    artifact_id=artifacts["patch"],
                )
            except AuthorityRejected as exc:
                if exc.status != 409:
                    raise
                # A revision can make preserved work unsuitable as the current
                # candidate. Its completed execution must still be releasable.
                logger.info("Captured work requires a new canonical review decision")
        current = self.lifecycle.observe_worker(spec.scope, worker_id)
        if attempt_id in current["active_executions"]:
            self.lifecycle.record_execution_end(
                spec.scope,
                worker_id,
                attempt_id,
                termination_confirmed=True,
                artifacts_captured=True,
            )
        self.journal.update(
            worker_id,
            phase="completed",
            reason="Durable capture delivered to canonical authority",
        )
        self.lifecycle.observe_worker(spec.scope, worker_id)

    def _cleanup_proof(self, worker_id, spec, receipt):
        from .docker_runtime import CleanupBlocked, require_cleanup

        public = (
            None if self.child_supervisor is None
            else getattr(self.child_supervisor, "public_supervisor", None)
        )
        if public is not None and public.enabled(spec):
            try:
                receipt = public.effective_receipt(worker_id, receipt, prepare=False)
            except RuntimeUnavailable:
                raise CleanupBlocked("public_capture_unresolved") from None
        worker = self.lifecycle._current(spec.scope, worker_id)
        require_cleanup(
            worker["state"] in {"stopped", "failed"}
            and worker["termination_confirmed"] is True
            and worker["artifacts_captured"] is True
            and not worker["active_executions"],
            "execution_references_unresolved",
        )
        row = self.journal.get(worker_id)
        require_cleanup(
            row is not None
            and row["phase"] == "completed"
            and row["spec"] == _json(asdict(spec))
            and row["binding"],
            "canonical_delivery_incomplete",
        )
        bound = json.loads(row["binding"])
        profile = self.profile(spec)
        attempt_id = json.loads(receipt.manifest)["attempt_id"]
        self._verify_binding(bound, spec, worker_id, profile, attempt_id)
        contents = {
            "patch": receipt.patch,
            "log": receipt.log,
            "manifest": receipt.manifest,
        }
        require_cleanup(
            all(isinstance(v, str) for v in contents.values()), "capture_invalid"
        )
        artifacts = {
            kind: hashlib.sha256(value.encode()).hexdigest()
            for kind, value in contents.items()
        }
        require_cleanup(
            json.loads(row["artifacts"]) == artifacts, "root_capture_incomplete"
        )
        expected = {
            "state": "timed_out" if receipt.state == "timed_out" else "exited",
            "termination_confirmed": True,
            "launch_fenced": True,
            "artifacts": artifacts,
        }
        try:
            response = self.authority.call(
                "permission", spec.scope, attempt_id=attempt_id
            )
            self._verify_binding(response, spec, worker_id, profile, attempt_id)
        except AuthorityUnavailable:
            raise CleanupBlocked("canonical_capture_unresolved") from None
        terminal = response["attempt"]
        require_cleanup(
            response["binding"] == bound["binding"]
            and response["requirements"] == bound["requirements"]
            and response.get("launch_allowed") is False
            and terminal.get("runtime_binding") == bound["binding"]
            and terminal.get("termination_confirmed") is True
            and terminal.get("launch_fenced") is True
            and terminal.get("state") == expected["state"]
            and terminal.get("captured_artifacts") == artifacts
            and terminal.get("runtime_receipt") == expected,
            "canonical_root_incomplete",
        )
        lineage = []
        if self.child_supervisor is not None and self.child_supervisor.enabled(spec):
            from .child_types import verify_grant

            children = self.child_supervisor
            child_worker = children.journal.worker(worker_id)
            root = children.journal.context(worker_id)
            require_cleanup(
                child_worker["closed"]
                and child_worker["close_delivered"]
                and root.spec == spec
                and root.worker_id == worker_id
                and root.attempt_id == attempt_id
                and child_worker["spec"] == _json(asdict(spec))
                and child_worker["policy_digest"] == children.policy(spec).fingerprint
                and terminal.get("child_admission_closed") is True,
                "child_admission_unresolved",
            )
            known = children.journal.children(worker_id)
            known_ids = {child["child_id"] for child in known}
            require_cleanup(
                all(
                    intent["status"] == "rejected"
                    or (intent["status"] == "bound" and intent["child_id"] in known_ids)
                    for intent in children.journal.intents(worker_id)
                ),
                "child_grant_unresolved",
            )
            for child in known:
                require_cleanup(
                    child["phase"] == "completed" and child["capture"],
                    "child_capture_incomplete",
                )
                saved = json.loads(child["capture"])["contents"]
                require_cleanup(
                    set(saved) == {"patch", "log", "manifest"}
                    and all(isinstance(v, str) for v in saved.values()),
                    "child_capture_incomplete",
                )
                hashes = {
                    kind: hashlib.sha256(value.encode()).hexdigest()
                    for kind, value in saved.items()
                }
                saved_grant = json.loads(child["grant_json"])
                verify_grant(saved_grant, root, children.policy(spec))
                grant = saved_grant["binding"]
                manifest = json.loads(saved["manifest"])
                if public is not None and public.enabled(spec):
                    try:
                        public.validate_child_capture(root, child["child_id"], manifest)
                    except (RuntimeUnavailable, LifecycleConflict):
                        raise CleanupBlocked("public_capture_unresolved") from None
                require_cleanup(
                    json.loads(child["artifacts"]) == hashes
                    and manifest.get("child_id") == child["child_id"]
                    and manifest.get("root_attempt_id") == attempt_id
                    and manifest.get("worker_id") == worker_id
                    and manifest.get("grant_digest") == grant.get("grant_digest")
                    and isinstance(grant.get("grant_digest"), str)
                    and manifest.get("archive_sha256") == receipt.capture_sha256
                    and manifest.get("root_manifest_sha256") == artifacts["manifest"]
                    and manifest.get("termination_confirmed") is True
                    and manifest.get("launch_fenced") is True,
                    "child_capture_changed",
                )
                lineage.append(
                    {
                        "child_id": child["child_id"],
                        "grant_digest": grant["grant_digest"],
                        "artifacts": hashes,
                    }
                )
        lineage.sort(key=lambda value: value["child_id"])
        require_cleanup(
            terminal.get("child_lineage", []) == lineage,
            "canonical_child_lineage_mismatch",
        )
        with self.lifecycle._transaction() as db:
            execution_ids = {
                row[0]
                for row in db.execute(
                    "SELECT execution_id FROM worker_executions WHERE worker_id=?",
                    (worker_id,),
                )
            }
        require_cleanup(
            execution_ids <= {attempt_id} | {child["child_id"] for child in lineage},
            "execution_lineage_mismatch",
        )
        return {
            "binding": bound["binding"],
            "runtime_receipt": expected,
            "child_lineage": lineage,
        }

    def cleanup_worker(self, scope, worker_id):
        """Explicit host operation for a stopped service, never a dispatch tick."""
        from .docker_runtime import CleanupBlocked, ManagedDockerRuntime

        result = {
            "schema_version": 1,
            "deployment_id": scope.deployment_id,
            "repository": scope.repository,
            "worker_id": worker_id,
        }
        try:
            worker = self.lifecycle._current(
                scope, worker_id
            )  # Scope before lock paths.
            spec = self._spec(worker)
            with self.journal.lock("service") as service:
                if not service:
                    raise CleanupBlocked("managed_service_running")
                with self.journal.lock(worker_id) as dispatch:
                    if not dispatch:
                        raise CleanupBlocked("dispatch_operation_busy")
                    with self.lifecycle._runtime_lock(worker_id) as lifecycle:
                        if not lifecycle:
                            raise CleanupBlocked("lifecycle_operation_busy")
                        return result | self.runtime.cleanup_worker(
                            worker_id,
                            spec,
                            lambda receipt: self._cleanup_proof(
                                worker_id, spec, receipt
                            ),
                        )
        except CleanupBlocked as exc:
            return result | ManagedDockerRuntime._cleanup_result(reason=str(exc))
        except Exception:
            return result | ManagedDockerRuntime._cleanup_result(
                reason="cleanup_binding_unresolved"
            )

    def _tick_safely(self, worker):
        try:
            self.tick_worker(worker)
        except (AuthorityUnavailable, LifecycleConflict):
            # Do not echo remote exception text or repository output into logs.
            logger.info(
                "Managed worker is waiting for authority or runtime reconciliation"
            )
        except Exception:
            logger.error(
                "Managed worker dispatch failed; its durable intent is retained"
            )

    def run(self):
        with self.journal.lock("service") as acquired:
            if not acquired:
                raise LifecycleConflict("Another managed dispatcher owns this state")
            threads = {}
            scopes = sorted(
                {(p.deployment_id, p.repository) for p in self.profiles.values()}
            )
            self.running.set()
            try:
                while not self.stop_requested.is_set():
                    threads = {
                        key: thread
                        for key, thread in threads.items()
                        if thread.is_alive()
                    }
                    for deployment_id, repository in scopes:
                        try:
                            workers = self.lifecycle.discover_workers(
                                WorkerScope(deployment_id, repository)
                            )
                        except Exception:
                            logger.info("Worker discovery is awaiting recovery")
                            continue
                        for worker in workers:
                            worker_id = worker["worker_id"]
                            if (
                                worker["deployment_id"],
                                worker["repository"],
                                worker["profile"],
                            ) not in self.profiles:
                                continue
                            try:
                                # Control delivery must continue while root
                                # executions occupy every dispatcher slot. A
                                # successful HTTP response can acknowledge an
                                # intent that could not yet acquire its lock.
                                worker = self.lifecycle.reconcile_control(
                                    WorkerScope(deployment_id, repository), worker_id
                                )
                            except Exception:
                                logger.info(
                                    "Managed control intent awaits runtime reconciliation"
                                )
                                continue
                            if (
                                worker_id in threads
                                or len(threads) >= self.max_parallel
                            ):
                                continue
                            row = self.journal.get(worker_id)
                            if row and row["phase"] == "completed":
                                continue
                            if row is None and worker["state"] == "unknown":
                                # Observation does not mutate containers. The
                                # trusted daemon may separately finalize a
                                # verified dead idle incarnation and its capture.
                                try:
                                    self.runtime.recover_idle(
                                        worker_id, self._spec(worker)
                                    )
                                    self.lifecycle.observe_worker(
                                        self._spec(worker).scope, worker_id
                                    )
                                except Exception:
                                    logger.info(
                                        "Idle worker recovery remains unresolved"
                                    )
                                continue
                            if row is None and worker["state"] != "ready":
                                continue
                            thread = threading.Thread(
                                target=self._tick_safely, args=(worker,), daemon=True
                            )
                            threads[worker_id] = thread
                            thread.start()
                    self.stop_requested.wait(self.poll_interval_seconds)
            finally:
                self.running.clear()
                # The immutable container's independent watchdog survives API
                # loss. Incomplete deliveries are reconciled after restart.
                deadline = time.monotonic() + 5
                for thread in threads.values():
                    thread.join(max(0, deadline - time.monotonic()))

    def stop(self):
        self.stop_requested.set()
