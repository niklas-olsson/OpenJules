"""A canonical claim reply cannot reopen drained local admission.

These tests use production runtime, lifecycle and dispatcher code with real Git
and SQLite. Docker and canonical authority are explicit fixtures, not actual
confinement, HTTP or independent canonical-service evidence.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import io
import json
from pathlib import Path
import sqlite3
import tarfile
import threading

import pytest

from src.polyphony.managed_client import AuthorityUnavailable
from src.worker.docker_runtime import ManagedDockerRuntime
from src.worker.lifecycle import WorkerLifecycle
from src.worker.managed_dispatch import ManagedDispatcher
from tests.unit.test_managed_dispatch import Authority
from tests.unit.test_managed_docker_runtime import (
    FakeDocker,
    setup_runtime,  # noqa: F401
)


class HeldClaimAuthorityFixture(Authority):
    """Allocate once, then hold or lose that original canonical-fixture reply."""

    def __init__(self, lose_reply):
        super().__init__()
        self.lose_reply = lose_reply
        self.allocated = threading.Event()
        self.release = threading.Event()
        self.original = None
        self.allocations = 0
        self.method_calls = []
        self.permissions = []

    def call(self, operation, scope, **data):
        scoped = (scope.deployment_id, scope.repository)
        self.method_calls.append((operation, scoped, deepcopy(data)))
        if operation == "claim":
            request = (scoped, deepcopy(data))
            if self.original is None:
                reply = deepcopy(super().call(operation, scope, **data))
                self.original = (request, reply)
                self.allocations += 1
                self.allocated.set()
                assert self.release.wait(5), "held fixture claim was not released"
                if self.lose_reply:
                    raise AuthorityUnavailable("fixture reply lost after allocation")
                return deepcopy(reply)
            assert request == self.original[0], "original claim payload/key changed"
            self.claims.append(deepcopy(data))
            return deepcopy(self.original[1])
        result = super().call(operation, scope, **data)
        if operation == "permission":
            self.permissions.append(deepcopy(result))
        return result


def rows(path, table):
    # These fixed fixture tables are read from committed SQLite/WAL state.
    with closing(
        sqlite3.connect(Path(path).resolve().as_uri() + "?mode=ro", uri=True)
    ) as db:
        db.row_factory = sqlite3.Row
        return [
            dict(row) for row in db.execute(f"SELECT * FROM {table} ORDER BY rowid")
        ]


def retained_state(runtime, lifecycle, dispatcher, authority, client):
    return {
        "runtime": {
            table: rows(runtime.database, table)
            for table in ("profiles", "workers", "attempts", "child_profiles")
        },
        "lifecycle": {
            table: rows(lifecycle.database, table)
            for table in ("managed_workers", "worker_operations", "worker_executions")
        },
        "deliveries": rows(dispatcher.journal.database, "deliveries"),
        "canonical": deepcopy(
            {
                "original": authority.original,
                "allocations": authority.allocations,
                "method_calls": authority.method_calls,
                "permissions": authority.permissions,
                "claims": authority.claims,
                "artifacts": authority.artifacts,
                "terminals": authority.terminals,
                "candidates": authority.candidates,
            }
        ),
        "docker_fixture": {
            "created": client.created,
            "executed": client.executed,
            "container_ids": sorted(item.id for item in client.all_containers.values()),
            "volume_names": sorted(client.all_volumes),
            "starts": client.container.starts,
            "stops": client.container.stops,
            "exec_options": deepcopy(client.exec_options),
            "puts": [
                (path, hashlib.sha256(content).hexdigest())
                for path, content in client.container.puts
            ],
        },
    }


def reopen(runtime, lifecycle, dispatcher, profile, authority, client):
    dispatcher.stop()
    recovered = ManagedDockerRuntime(
        runtime.root, [profile], runtime.readiness, client
    )
    lifecycle = WorkerLifecycle(lifecycle.database, recovered)
    dispatcher = ManagedDispatcher(
        lifecycle, recovered, authority, [profile], dispatcher.journal.directory
    )
    return recovered, lifecycle, dispatcher


@pytest.mark.parametrize("lose_reply", [False, True], ids=["delivered", "lost-reply"])
def test_claim_reply_after_drain_reconciles_without_execution_or_new_allocation(
    tmp_path, setup_runtime, lose_reply
):
    runtime, client, profile, spec = setup_runtime
    assert isinstance(client, FakeDocker)
    # archive({}) in the imported fixture selects its default nonempty output.
    # A never-executed root must instead capture this explicit empty archive.
    empty = io.BytesIO()
    with tarfile.open(fileobj=empty, mode="w"):
        pass
    client.archive = empty.getvalue()
    lifecycle = WorkerLifecycle(tmp_path / "lifecycle.sqlite3", runtime)
    authority = HeldClaimAuthorityFixture(lose_reply)
    dispatcher = ManagedDispatcher(
        lifecycle, runtime, authority, [profile], tmp_path / "dispatch"
    )
    worker = lifecycle.ensure_worker(spec)
    worker_id = worker["worker_id"]
    assert worker["state"] == "ready" and worker["admission_open"] is True
    assert client.created == client.container.starts == 1
    assert client.executed == 0 and client.exec_options is None
    assert dispatcher.model_broker is None and dispatcher.child_supervisor is None
    failures = []

    def deliver():
        try:
            dispatcher.tick_worker(worker)
        except BaseException as exc:
            failures.append(exc)

    thread = threading.Thread(target=deliver, daemon=True)
    thread.start()
    try:
        try:
            assert authority.allocated.wait(5), "fixture claim was not allocated"
            pending = dispatcher.journal.get(worker_id)
            assert pending["phase"] == "claiming" and pending["binding"] is None
            original_key = pending["request_key"]
            assert authority.claims[0]["request_key"] == original_key
            assert authority.allocations == 1
            assert runtime._attempt(worker_id) is None

            # Normal lifecycle control runs while the canonical response is held.
            # No execution admission or runtime lock is held by that response.
            drain_key = "drain-while-original-claim-reply-is-held"
            drained = lifecycle.drain_worker(spec.scope, worker_id, drain_key)
            assert drained["state"] == "draining"
            assert drained["admission_open"] is False
            assert drained["active_executions"] == []
            assert rows(lifecycle.database, "worker_executions") == []
            drain = next(
                row
                for row in rows(lifecycle.database, "worker_operations")
                if row["request_key"] == drain_key
            )
            assert drain == {
                "deployment_id": spec.deployment_id,
                "repository": spec.repository,
                "request_key": drain_key,
                "action": "drain",
                "worker_id": worker_id,
                "payload": json.dumps(
                    {"action": "drain", "worker_id": worker_id},
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                "completed": 1,
            }
            assert runtime._row(worker_id, spec)["retired"] == 1
            assert runtime._attempt(worker_id) is None
            assert dispatcher.journal.get(worker_id) == pending
            assert client.container.attrs["State"]["Running"] is True
            assert client.container.stops == client.executed == 0
        finally:
            # Always release/join the owned delivery thread, including failures.
            authority.release.set()
            thread.join(15)
        assert not thread.is_alive(), "fixture delivery thread did not finish"

        if lose_reply:
            assert len(failures) == 1 and isinstance(failures[0], AuthorityUnavailable)
            assert str(failures[0]) == "fixture reply lost after allocation"
            assert dispatcher.journal.get(worker_id) == pending
            assert runtime._attempt(worker_id) is None
            assert authority.allocations == len(authority.claims) == 1
            runtime, lifecycle, dispatcher = reopen(
                runtime, lifecycle, dispatcher, profile, authority, client
            )
            assert dispatcher.journal.get(worker_id) == pending
            dispatcher.tick_worker(lifecycle.observe_worker(spec.scope, worker_id))
        else:
            assert failures == []

        delivery = dispatcher.journal.get(worker_id)
        assert delivery["phase"] == "completed"
        assert delivery["request_key"] == original_key
        bound = json.loads(delivery["binding"])
        assert bound == authority.original[1]
        attempt_id = bound["binding"]["attempt_id"]
        assert authority.allocations == 1
        assert len(authority.claims) == (2 if lose_reply else 1)
        assert all(request == authority.claims[0] for request in authority.claims)
        assert len(authority.permissions) == 1
        assert authority.permissions[0]["launch_allowed"] is True
        assert authority.permissions[0]["remaining_seconds"] == 30
        assert authority.permissions[0]["binding"] == bound["binding"]

        # This is a real runtime cancellation tombstone, not the generic
        # dispatch fixture's successful execution receipt.
        attempt = dict(runtime._attempt(worker_id))
        assert attempt["worker_id"] == worker_id and attempt["attempt_id"] == attempt_id
        assert attempt["input_sha256"] == hashlib.sha256(
            bound["requirements"].encode()
        ).hexdigest()
        assert attempt["exec_dispatched"] == 0 and attempt["exec_id"] is None
        assert attempt["cancelled"] == 1 and attempt["exit_code"] is None
        assert attempt["seconds"] == 0
        receipt = runtime.inspect_attempt(worker_id, spec, attempt_id)
        assert receipt.state == "cancelled" and receipt.exit_code is None
        assert receipt.patch == receipt.log == ""
        assert (
            receipt.termination_confirmed
            and receipt.launch_fenced
            and receipt.artifacts_captured
        )
        archive = Path(receipt.capture_path).read_bytes()
        assert archive == client.archive
        assert hashlib.sha256(archive).hexdigest() == receipt.capture_sha256
        with tarfile.open(fileobj=io.BytesIO(archive)) as captured:
            assert captured.getnames() == []
        manifest = json.loads(receipt.manifest)
        assert manifest["worker_id"] == worker_id
        assert manifest["attempt_id"] == attempt_id
        assert manifest["profile"] == spec.profile
        assert manifest["profile_fingerprint"] == profile.fingerprint
        assert manifest["base_commit"] == profile.base_commit
        assert manifest["container_id"] == client.container.id
        assert manifest["archive_sha256"] == receipt.capture_sha256
        assert manifest["archive_bytes"] == len(archive)
        assert manifest["deadline_monotonic"] == attempt["deadline"]
        assert manifest["patch_present"] is manifest["log_present"] is False
        assert manifest["termination_confirmed"] is manifest["launch_fenced"] is True
        contents = {"patch": "", "log": "", "manifest": receipt.manifest}
        artifacts = {
            kind: hashlib.sha256(content.encode()).hexdigest()
            for kind, content in contents.items()
        }
        assert authority.artifacts == contents
        assert json.loads(delivery["artifacts"]) == artifacts
        assert authority.terminals == [
            {
                "attempt_id": attempt_id,
                # Canonical observation normalizes runtime cancellation to exited.
                "state": "exited",
                "termination_confirmed": True,
                "launch_fenced": True,
                "artifacts": artifacts,
            }
        ]
        assert sum(call[0] == "capture" for call in authority.method_calls) == 3
        assert authority.candidates == []
        assert not any(call[0] == "candidate" for call in authority.method_calls)
        observed = lifecycle.observe_worker(spec.scope, worker_id)
        assert observed["admission_open"] is False
        assert observed["active_executions"] == []
        assert observed["termination_confirmed"] and observed["artifacts_captured"]
        assert rows(lifecycle.database, "worker_executions") == []
        assert client.created == client.container.starts == client.container.stops == 1
        assert client.executed == 0 and client.exec_options is None
        assert len(client.all_containers) == len(client.all_volumes) == 1

        retained = retained_state(runtime, lifecycle, dispatcher, authority, client)
        assert len(retained["runtime"]["workers"]) == 1
        assert len(retained["runtime"]["attempts"]) == 1
        assert len(retained["lifecycle"]["managed_workers"]) == 1
        assert len(retained["lifecycle"]["worker_operations"]) == 2
        assert len(retained["deliveries"]) == 1
        runtime, lifecycle, dispatcher = reopen(
            runtime, lifecycle, dispatcher, profile, authority, client
        )
        dispatcher.tick_worker(lifecycle.observe_worker(spec.scope, worker_id))
        # There was no local execution allocation. Replay the original
        # cancellation, never invent positive seconds for execute_attempt.
        assert runtime.cancel_attempt(
            worker_id, spec, attempt_id, bound["requirements"]
        ) == receipt
        repeated = lifecycle.drain_worker(spec.scope, worker_id, drain_key)
        assert repeated["admission_open"] is False
        assert repeated["active_executions"] == []
        assert lifecycle.ensure_worker(spec)["worker_id"] == worker_id
        assert Path(receipt.capture_path).read_bytes() == archive
        assert (
            retained_state(runtime, lifecycle, dispatcher, authority, client)
            == retained
        )
        assert dispatcher.model_broker is None and dispatcher.child_supervisor is None
    finally:
        dispatcher.stop()
