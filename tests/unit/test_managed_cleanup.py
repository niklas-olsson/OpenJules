"""Cleanup recovery contracts; fake Docker/authority are not runtime proof."""

from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import threading
from types import SimpleNamespace

import docker
from docker.errors import NotFound
import pytest
import requests
from urllib3.util.retry import Retry

from src.polyphony.managed_client import AuthorityUnavailable
from src.worker.docker_runtime import ManagedDockerRuntime, _CLEANUP_TRANSPORT
from src.worker.lifecycle import WorkerLifecycle, WorkerScope
from src.worker.managed_dispatch import ManagedDispatcher
from tests.unit.test_managed_dispatch import Authority
from tests.unit.test_managed_docker_runtime import setup_runtime  # noqa: F401


class CompletedAuthority(Authority):
    def __init__(self):
        super().__init__()
        self.terminal = None
        self.unavailable = False
        self.lineage = []
        self.transform = lambda response: response

    def call(self, operation, scope, **data):
        if operation == "permission" and self.unavailable:
            raise AuthorityUnavailable("private backend response")
        result = super().call(operation, scope, **data)
        if operation == "observe" and data["termination_confirmed"]:
            self.terminal = {
                key: data[key]
                for key in (
                    "state",
                    "termination_confirmed",
                    "launch_fenced",
                    "artifacts",
                )
            }
        if operation == "permission" and self.terminal:
            result["launch_allowed"] = False
            result["attempt"].update(
                runtime_binding=self.binding,
                state=self.terminal["state"],
                termination_confirmed=True,
                launch_fenced=True,
                captured_artifacts=self.terminal["artifacts"],
                runtime_receipt=self.terminal,
                child_lineage=self.lineage,
                child_admission_closed=True,
            )
            result = self.transform(result)
        return result


@pytest.fixture
def stack(setup_runtime, monkeypatch, tmp_path):
    runtime, client, profile, spec = setup_runtime
    # Explicit fixture qualification, not a claim about fake transport.
    monkeypatch.setattr(runtime, "_cleanup_transport", lambda: _CLEANUP_TRANSPORT)
    client.removals = []
    client.remove_failure = None
    original_volume, original_container = client.create_volume, client.create

    def get_volume(name):
        if name not in client.all_volumes:
            raise NotFound("absent")
        return client.all_volumes[name]

    def create_volume(name, labels):
        volume = original_volume(name, labels)
        volume.attrs.update(
            Name=name,
            CreatedAt="2026-11-11T00:00:00Z",
            Driver="local",
            Scope="local",
            Options=None,
        )

        def remove(*, force):
            assert force is False
            client.removals.append("volume")
            if client.remove_failure == "volume_before":
                raise TimeoutError("private volume failure")
            del client.all_volumes[name]
            if client.remove_failure == "volume_after":
                raise TimeoutError("lost volume removal reply")

        volume.remove = remove
        return volume

    def create_container(image, **kwargs):
        container = original_container(image, **kwargs)
        volume_name = next(
            name
            for name, mount in kwargs["volumes"].items()
            if mount["bind"] == "/workspace"
        )
        container.attrs["Mounts"] = [
            {"Type": "volume", "Name": volume_name, "Destination": "/workspace"}
        ]

        def remove(*, force, v):
            assert force is False and v is False
            client.removals.append("container")
            if client.remove_failure == "container_before":
                raise TimeoutError("private container failure")
            del client.all_containers[kwargs["name"]]
            client.container = None
            if client.remove_failure == "container_after":
                raise TimeoutError("lost container removal reply")

        container.remove = remove
        return container

    client.volumes.get, client.volumes.create = get_volume, create_volume
    client.containers.create = create_container
    authority = CompletedAuthority()
    lifecycle = WorkerLifecycle(tmp_path / "workers.sqlite", runtime)
    dispatcher = ManagedDispatcher(
        lifecycle, runtime, authority, [profile], tmp_path / "dispatcher"
    )
    worker = lifecycle.ensure_worker(spec)
    dispatcher.tick_worker(worker)
    worker = lifecycle.observe_worker(spec.scope, worker["worker_id"])
    assert worker["state"] == "stopped" and not worker["active_executions"]
    assert dispatcher.journal.get(worker["worker_id"])["phase"] == "completed"
    return SimpleNamespace(
        runtime=runtime,
        client=client,
        profile=profile,
        spec=spec,
        authority=authority,
        lifecycle=lifecycle,
        dispatcher=dispatcher,
        worker=worker,
        worker_id=worker["worker_id"],
    )


def clean(s):
    return s.dispatcher.cleanup_worker(s.spec.scope, s.worker_id)


def test_completed_capture_cleanup_reopens_and_never_recreates(stack, monkeypatch):
    s = stack
    before = dict(s.runtime._row(s.worker_id, s.spec))
    receipt = s.runtime.inspect_attempt(
        s.worker_id, s.spec, s.authority.binding["attempt_id"]
    )
    archive = Path(receipt.capture_path).read_bytes()
    assert clean(s)["state"] == "cleaned"
    assert s.client.removals == ["container", "volume"]
    assert not s.client.all_containers and not s.client.all_volumes
    assert Path(receipt.capture_path).read_bytes() == archive
    assert s.runtime._row(s.worker_id, s.spec)["receipt"] == before["receipt"]
    reopened = ManagedDockerRuntime(
        s.runtime.root, [s.profile], s.runtime.readiness, s.client
    )
    s.lifecycle.runtime = reopened
    s.dispatcher.runtime = reopened
    assert reopened.ensure(s.worker_id, s.spec).state == "stopped"
    assert (
        reopened.stop(s.worker_id, s.spec, "docker:" + before["container_id"]).state
        == "stopped"
    )
    assert (
        reopened.execute_attempt(
            s.worker_id, s.spec, s.authority.binding["attempt_id"], "Change result", 1
        )
        == receipt
    )
    s.authority.unavailable = True
    monkeypatch.setattr(
        s.client.containers,
        "get",
        lambda _: pytest.fail("completed cleanup touched Docker"),
    )
    monkeypatch.setattr(
        s.client.volumes,
        "get",
        lambda _: pytest.fail("completed cleanup touched volume"),
    )
    assert clean(s)["state"] == "cleaned"
    assert s.client.created == 1 and s.client.executed == 1


def reopen_with_historical_transport(s, monkeypatch, columns):
    historical = "docker-7.2.0:stock-unix:retry-0:redirect-0"
    with s.runtime._db() as db:
        for column in columns:
            db.execute(
                f"UPDATE workers SET {column}=? WHERE worker_id=?",
                (historical, s.worker_id),
            )
    before = dict(s.runtime._row(s.worker_id, s.spec))
    reopened = ManagedDockerRuntime(
        s.runtime.root, [s.profile], s.runtime.readiness, s.client
    )
    # A currently qualified fixture transport cannot repair historical proof.
    monkeypatch.setattr(reopened, "_cleanup_transport", lambda: _CLEANUP_TRANSPORT)
    assert dict(reopened._row(s.worker_id, s.spec)) == before
    return reopened, before


@pytest.mark.parametrize("column", ["volume_transport", "container_transport"])
def test_historical_transport_proof_is_not_upgraded_after_reopen(
    stack, monkeypatch, column
):
    s = stack
    reopened, before = reopen_with_historical_transport(s, monkeypatch, [column])
    archive = Path(json.loads(before["receipt"])["capture_path"])
    captured = archive.read_bytes()
    containers, volumes = set(s.client.all_containers), set(s.client.all_volumes)
    result = reopened.cleanup_worker(
        s.worker_id, s.spec, lambda _: pytest.fail("historical proof reached authority")
    )
    assert result["state"] == "retained"
    assert result["reason"] == "resource_creation_unqualified"
    assert result["container_removed"] is False
    assert result["volume_removed"] is False
    assert s.client.removals == []
    assert set(s.client.all_containers) == containers
    assert set(s.client.all_volumes) == volumes
    assert s.client.created == s.client.executed == 1
    assert dict(reopened._row(s.worker_id, s.spec)) == before
    assert archive.read_bytes() == captured


@pytest.mark.parametrize("failure", ["container_before", "volume_before"])
def test_historical_transport_proof_blocks_pending_cleanup_after_reopen(
    stack, monkeypatch, failure
):
    s = stack
    s.client.remove_failure = failure
    pending = clean(s)
    assert pending["state"] == "retained"
    assert pending["reason"] == "cleanup_unresolved"
    assert pending["container_removed"] is (failure == "volume_before")
    s.client.remove_failure = None
    reopened, before = reopen_with_historical_transport(
        s, monkeypatch, ["volume_transport", "container_transport"]
    )
    progress = json.loads(before["cleanup"])
    assert progress["completed"] is False
    assert progress["container_removed"] is (failure == "volume_before")
    assert progress["volume_removed"] is False
    archive = Path(json.loads(before["receipt"])["capture_path"])
    captured = archive.read_bytes()
    removals = list(s.client.removals)
    containers, volumes = set(s.client.all_containers), set(s.client.all_volumes)
    result = reopened.cleanup_worker(
        s.worker_id, s.spec, lambda _: pytest.fail("old intent reached authority")
    )
    assert result["state"] == "retained"
    assert result["reason"] == "resource_creation_unqualified"
    assert result["container_removed"] is progress["container_removed"]
    assert result["volume_removed"] is False
    assert s.client.removals == removals
    assert set(s.client.all_containers) == containers
    assert set(s.client.all_volumes) == volumes
    assert s.client.created == s.client.executed == 1
    assert dict(reopened._row(s.worker_id, s.spec)) == before
    assert archive.read_bytes() == captured


def test_completed_historical_cleanup_receipt_reopens_without_side_effects(
    stack, monkeypatch
):
    s = stack
    completed = clean(s)
    assert completed["state"] == "cleaned"
    reopened, before = reopen_with_historical_transport(
        s, monkeypatch, ["volume_transport", "container_transport"]
    )
    archive = Path(json.loads(before["receipt"])["capture_path"])
    captured = archive.read_bytes()
    monkeypatch.setattr(
        reopened,
        "_cleanup_transport",
        lambda: pytest.fail("completed historical receipt checked transport"),
    )
    monkeypatch.setattr(
        s.client.containers,
        "get",
        lambda _: pytest.fail("completed historical receipt touched Docker"),
    )
    monkeypatch.setattr(
        s.client.volumes,
        "get",
        lambda _: pytest.fail("completed historical receipt touched volume"),
    )
    result = reopened.cleanup_worker(
        s.worker_id, s.spec, lambda _: pytest.fail("cached receipt reached authority")
    )
    assert result == {
        key: completed[key]
        for key in (
            "state",
            "reason",
            "container_removed",
            "volume_removed",
            "archives_retained",
        )
    }
    assert s.client.removals == ["container", "volume"]
    assert not s.client.all_containers and not s.client.all_volumes
    assert s.client.created == s.client.executed == 1
    assert dict(reopened._row(s.worker_id, s.spec)) == before
    assert archive.read_bytes() == captured


@pytest.mark.parametrize(
    "column,value",
    [
        ("creation_version", 0),
        ("volume_creates", 2),
        ("volume_create_acks", 0),
        ("container_creates", 2),
        ("container_create_acks", 0),
        ("volume_transport", "custom"),
        ("container_transport", "custom"),
    ],
)
def test_creation_ambiguity_never_permits_cleanup(stack, column, value):
    s = stack
    with s.runtime._db() as db:
        db.execute(
            f"UPDATE workers SET {column}=? WHERE worker_id=?", (value, s.worker_id)
        )
    result = clean(s)
    assert result["state"] == "retained"
    assert result["reason"] == "resource_creation_unqualified"
    assert s.client.removals == []


def test_legacy_database_migration_does_not_infer_creation_proof(stack, tmp_path):
    s = stack
    directory = tmp_path / "legacy"
    directory.mkdir()
    old = dict(s.runtime._row(s.worker_id, s.spec))
    columns = (
        "worker_id",
        "spec",
        "profile_fingerprint",
        "container_id",
        "create_dispatched",
        "start_dispatched",
        "start_confirmed",
        "retired",
        "receipt",
    )
    with sqlite3.connect(directory / "journal.sqlite3") as db:
        db.execute(
            "CREATE TABLE workers(worker_id TEXT PRIMARY KEY,spec TEXT,profile_fingerprint TEXT,"
            "container_id TEXT,create_dispatched INTEGER,start_dispatched INTEGER,"
            "start_confirmed INTEGER,retired INTEGER,receipt TEXT)"
        )
        db.execute(
            "INSERT INTO workers VALUES(?,?,?,?,?,?,?,?,?)",
            tuple(old[name] for name in columns),
        )
    runtime = ManagedDockerRuntime(
        directory, [s.profile], s.runtime.readiness, s.client
    )
    row = runtime._row(s.worker_id, s.spec)
    assert (
        row["creation_version"]
        == row["volume_creates"]
        == row["container_creates"]
        == 0
    )
    result = runtime.cleanup_worker(
        s.worker_id, s.spec, lambda _: pytest.fail("legacy proof inferred")
    )
    assert result["reason"] == "resource_creation_unqualified"
    assert s.client.removals == []


@pytest.mark.parametrize(
    "failure", ["container_before", "container_after", "volume_before", "volume_after"]
)
def test_remove_failure_or_lost_reply_replays_exact_intent(stack, failure):
    s = stack
    original = s.runtime._row(s.worker_id, s.spec)["receipt"]
    s.client.remove_failure = failure
    first = clean(s)
    assert first["state"] == "retained" and "private" not in json.dumps(first)
    if failure.startswith("container"):
        assert s.client.removals == ["container"]
    else:
        assert s.client.removals == ["container", "volume"]
    s.client.remove_failure = None
    assert clean(s)["state"] == "cleaned"
    assert s.runtime._row(s.worker_id, s.spec)["receipt"] == original
    assert Path(json.loads(original)["capture_path"]).is_file()


def test_partial_replay_retains_replaced_same_name_volume(stack):
    s = stack
    s.client.remove_failure = "volume_before"
    assert clean(s)["container_removed"] is True
    s.client.volume.attrs["CreatedAt"] = "2026-11-12T00:00:00Z"
    s.client.remove_failure = None
    before = list(s.client.removals)
    result = clean(s)
    assert result["reason"] == "volume_identity_mismatch"
    assert s.client.removals == before and s.client.all_volumes


@pytest.mark.parametrize(
    "change",
    [
        "archive",
        "symlink",
        "running",
        "container_label",
        "volume_label",
        "volume_missing",
        "container_missing",
        "unavailable",
        "dispatch",
        "root_hash",
        "root_terminal",
        "binding",
        "lineage",
    ],
)
def test_unsafe_or_incomplete_evidence_retains_resources(stack, change):
    s = stack
    archive = Path(
        json.loads(s.runtime._row(s.worker_id, s.spec)["receipt"])["capture_path"]
    )
    if change == "archive":
        archive.write_bytes(b"changed")
    elif change == "symlink":
        original = archive.with_suffix(".saved")
        archive.rename(original)
        archive.symlink_to(original)
    elif change == "running":
        s.client.container.attrs["State"].update(Running=True, Status="running")
    elif change == "container_label":
        s.client.container.attrs["Config"]["Labels"] = {"openjules.worker": "foreign"}
    elif change == "volume_label":
        s.client.volume.attrs["Labels"] = {"openjules.worker": "foreign"}
    elif change == "volume_missing":
        s.client.all_volumes.clear()
    elif change == "container_missing":
        s.client.all_containers.clear()
        s.client.container = None
    elif change == "unavailable":
        s.authority.unavailable = True
    elif change == "dispatch":
        s.dispatcher.journal.update(s.worker_id, phase="claiming")
    elif change == "root_hash":
        s.authority.transform = lambda r: r | {
            "attempt": r["attempt"] | {"captured_artifacts": {}}
        }
    elif change == "root_terminal":
        s.authority.transform = lambda r: r | {
            "attempt": r["attempt"] | {"termination_confirmed": False}
        }
    elif change == "binding":
        s.authority.transform = lambda r: r | {
            "binding": r["binding"] | {"worker_id": "foreign"}
        }
    elif change == "lineage":
        s.authority.lineage = [{"child_id": "unknown"}]
    assert clean(s)["state"] == "retained"
    assert s.client.removals == []


@pytest.mark.parametrize("which", ["service", "dispatch", "lifecycle", "runtime"])
def test_cleanup_never_steals_existing_locks(stack, which):
    s = stack
    lock = {
        "service": lambda: s.dispatcher.journal.lock("service"),
        "dispatch": lambda: s.dispatcher.journal.lock(s.worker_id),
        "lifecycle": lambda: s.lifecycle._runtime_lock(s.worker_id),
        "runtime": lambda: s.runtime._lock(s.worker_id),
    }[which]
    with lock() as acquired:
        assert acquired
        assert clean(s)["state"] == "retained"
    assert s.client.removals == []


def test_wrong_scope_cannot_touch_owned_resources(stack):
    s = stack
    result = s.dispatcher.cleanup_worker(
        WorkerScope("foreign", s.spec.repository), s.worker_id
    )
    assert result["state"] == "retained" and s.client.removals == []


def test_fifo_capture_is_rejected_without_blocking_or_deleting_work(stack):
    s = stack
    archive = Path(
        json.loads(s.runtime._row(s.worker_id, s.spec)["receipt"])["capture_path"]
    )
    saved = archive.with_suffix(".saved")
    archive.rename(saved)
    original = saved.read_bytes()
    os.mkfifo(archive, 0o600)
    results = []
    thread = threading.Thread(target=lambda: results.append(clean(s)), daemon=True)
    thread.start()
    try:
        thread.join(2)
        assert not thread.is_alive(), "cleanup blocked while opening a FIFO capture"
        assert results[0]["state"] == "retained"
        assert results[0]["reason"] == "capture_invalid"
        assert not s.client.removals and saved.read_bytes() == original
    finally:
        if thread.is_alive():
            # Only this test's FIFO: release a regressed reader so a failing
            # assertion cannot leave it holding the runtime locks indefinitely.
            writer = os.open(archive, os.O_WRONLY | os.O_NONBLOCK)
            os.close(writer)
            thread.join(2)


def test_stock_unix_transport_disables_hidden_post_retries_and_redirects(
    setup_runtime, monkeypatch
):
    runtime, _, _, _ = setup_runtime
    client = docker.DockerClient(
        base_url="unix:///var/run/docker.sock", version="1.45", timeout=5
    )
    runtime._client = client
    try:
        assert runtime._cleanup_transport() is None  # Redirects enabled by default.
        client.api.max_redirects = 0
        assert runtime._cleanup_transport() == _CLEANUP_TRANSPORT
        adapter = client.api.get_adapter(client.api.base_url)
        requests_sent = []

        def redirect(request, **kwargs):
            requests_sent.append(request)
            response = requests.Response()
            response.status_code, response.request = 307, request
            response.url = request.url
            response.headers["Location"] = request.url
            response._content = b""
            return response

        monkeypatch.setattr(adapter, "send", redirect)
        with pytest.raises(requests.TooManyRedirects):
            client.api.create_volume(name="fixture")
        assert len(requests_sent) == 1 and requests_sent[0].method == "POST"
        adapter.max_retries = Retry(total=1, allowed_methods=None)
        assert runtime._cleanup_transport() is None
    finally:
        client.close()


@pytest.mark.parametrize("path", ["/volumes/create", "/containers/create"])
def test_endpoint_adapter_mount_never_qualifies_for_cleanup(setup_runtime, path):
    runtime, _, _, _ = setup_runtime
    client = docker.DockerClient(
        base_url="unix:///var/run/docker.sock", version="1.45", timeout=5
    )
    runtime._client = client
    try:
        client.api.max_redirects = 0
        assert runtime._cleanup_transport() == _CLEANUP_TRANSPORT
        original = client.api.get_adapter(client.api.base_url)
        endpoint = client.api._url(path)
        replacement = requests.adapters.HTTPAdapter(
            max_retries=Retry(total=1, allowed_methods=None)
        )
        client.api.mount(endpoint, replacement)
        assert client.api.get_adapter(client.api.base_url) is original
        assert client.api.get_adapter(endpoint) is replacement
        assert runtime._cleanup_transport() is None
    finally:
        client.close()


def test_authenticator_response_hooks_never_qualify_for_cleanup(setup_runtime):
    runtime, _, _, _ = setup_runtime
    client = docker.DockerClient(
        base_url="unix:///var/run/docker.sock", version="1.45", timeout=5
    )
    runtime._client = client
    try:
        client.api.max_redirects = 0
        assert runtime._cleanup_transport() == _CLEANUP_TRANSPORT
        authentication = requests.auth.HTTPDigestAuth(
            "fixture-user", "fixture-password"
        )
        client.api.auth = authentication
        prepared = client.api.prepare_request(
            requests.Request("POST", client.api._url("/containers/create"), json={})
        )
        assert client.api.hooks == {"response": []}
        assert authentication.handle_401 in prepared.hooks["response"]
        assert runtime._cleanup_transport() is None
    finally:
        client.close()


@pytest.mark.parametrize("stage", ["intent", "container", "completion"])
def test_process_death_before_progress_commit_reconciles_without_recapture(
    stack, monkeypatch, stage
):
    s = stack
    original_update = s.runtime._update

    class SupervisorDied(BaseException):
        pass

    def crash(worker_id, **values):
        if "cleanup" in values:
            progress = json.loads(values["cleanup"])
            at = (
                "completion"
                if progress["completed"]
                else ("container" if progress["container_removed"] else "intent")
            )
            if at == stage:
                raise SupervisorDied()
        return original_update(worker_id, **values)

    monkeypatch.setattr(s.runtime, "_update", crash)
    with pytest.raises(SupervisorDied):
        clean(s)
    if stage == "intent":
        assert not s.client.removals
    monkeypatch.setattr(s.runtime, "_update", original_update)
    assert clean(s)["state"] == "cleaned"
    assert s.client.removals == ["container", "volume"]


@pytest.mark.parametrize("kind", ["volume", "container"])
def test_lost_create_reply_and_retry_never_acquire_cleanup_eligibility(
    setup_runtime, monkeypatch, kind
):
    runtime, client, _, spec = setup_runtime
    monkeypatch.setattr(runtime, "_cleanup_transport", lambda: _CLEANUP_TRANSPORT)
    collection = client.volumes if kind == "volume" else client.containers
    original = collection.create

    def lost(*args, **kwargs):
        original(*args, **kwargs)
        raise TimeoutError("lost creation reply")

    monkeypatch.setattr(collection, "create", lost)
    runtime.ensure("fixture", spec)
    row = runtime._row("fixture", spec)
    assert row[kind + "_creates"] == 1 and row[kind + "_create_acks"] == 0
    monkeypatch.setattr(collection, "create", original)
    runtime.ensure("fixture", spec)
    receipt = runtime.execute_attempt("fixture", spec, "attempt", "instructions", 10)
    assert receipt.artifacts_captured
    result = runtime.cleanup_worker(
        "fixture", spec, lambda _: pytest.fail("uncertain creation admitted")
    )
    assert result["reason"] == "resource_creation_unqualified"
    assert client.all_containers and client.all_volumes


@pytest.fixture
def child_stack(stack, tmp_path):
    from src.worker.child_journal import ChildJournal
    from src.worker.child_types import ChildPolicy, RootContext, text_hash
    from tests.unit.test_child_authority_contract import grant, request

    s = stack
    policy = ChildPolicy(2, 20, 3, ("python",))
    root = RootContext(
        s.worker_id,
        s.spec,
        s.authority.binding["attempt_id"],
        "task-1",
        "fixture-runtime",
        "b" * 64,
        1,
        s.profile.base_commit,
        2000000000,
        1000,
        "fixture-boot",
    )
    journal = ChildJournal(tmp_path / "children")
    journal.prepare(s.worker_id, s.spec, policy)
    journal.bind(root)
    journal.reserve(s.worker_id, "child-request", request(), policy)
    approved = grant(root)
    child_id = approved["binding"]["child_id"]
    journal.grant(s.worker_id, "child-request", approved, 10, "fixture-boot", policy)
    receipt = s.runtime.inspect_attempt(s.worker_id, s.spec, root.attempt_id)
    manifest = json.dumps(
        {
            "child_id": child_id,
            "root_attempt_id": root.attempt_id,
            "worker_id": s.worker_id,
            "grant_digest": approved["binding"]["grant_digest"],
            "archive_sha256": receipt.capture_sha256,
            "root_manifest_sha256": text_hash(receipt.manifest),
            "termination_confirmed": True,
            "launch_fenced": True,
        }
    )
    contents = {"patch": "child patch", "log": "child log", "manifest": manifest}
    artifacts = {kind: text_hash(content) for kind, content in contents.items()}
    journal.freeze_capture(
        s.worker_id, child_id, contents, "exited", expected_report=None
    )
    journal.update(
        s.worker_id, child_id, phase="completed", artifacts=json.dumps(artifacts)
    )
    journal.close_admission(s.worker_id, "fixture complete", retire=True)
    journal.close_delivered(s.worker_id)
    s.authority.lineage = [
        {
            "child_id": child_id,
            "grant_digest": approved["binding"]["grant_digest"],
            "artifacts": artifacts,
        }
    ]
    s.dispatcher.child_supervisor = SimpleNamespace(
        enabled=lambda _: True, journal=journal, policy=lambda _: policy
    )
    s.child_id, s.child_journal = child_id, journal
    try:
        yield s
    finally:
        journal.close()


def test_complete_child_journal_and_exact_canonical_lineage_permit_cleanup(child_stack):
    assert clean(child_stack)["state"] == "cleaned"
    assert child_stack.child_journal.child(child_stack.worker_id, child_stack.child_id)[
        "capture"
    ]


@pytest.mark.parametrize(
    "fault",
    ["pending_grant", "not_closed", "not_delivered", "capture", "hashes", "lineage"],
)
def test_incomplete_child_capture_never_permits_cleanup(child_stack, fault):
    s = child_stack
    with s.child_journal.connection() as db:
        if fault == "pending_grant":
            db.execute("UPDATE intents SET status='pending',child_id=NULL")
        elif fault == "not_closed":
            db.execute("UPDATE workers SET closed=0")
        elif fault == "not_delivered":
            db.execute("UPDATE workers SET close_delivered=0")
        elif fault == "capture":
            db.execute("UPDATE children SET phase='captured'")
        elif fault == "hashes":
            db.execute("UPDATE children SET artifacts='{}'")
        else:
            s.authority.lineage = []
    assert clean(s)["state"] == "retained" and s.client.removals == []


def test_cleanup_cli_does_not_start_service_or_restore_endpoints(
    stack, monkeypatch, capsys
):
    import sys
    from src.worker import execution_context, managed_service

    # The CLI normally owns its process. Scope its permanent context latch to
    # this invocation when running in pytest's shared interpreter.
    monkeypatch.setattr(execution_context, "_managed_process", False)
    monkeypatch.setattr(execution_context, "_selector_observed", False)

    s = stack
    app = SimpleNamespace(
        state=SimpleNamespace(
            managed_dispatcher=s.dispatcher, model_broker=None, child_supervisor=None
        )
    )
    monkeypatch.setattr(managed_service, "load_configuration", lambda _: ({}, {}))

    def build(*args, cleanup_only):
        assert cleanup_only is True
        return app

    monkeypatch.setattr(managed_service, "build_app", build)
    s.client.close = lambda: None
    monkeypatch.setattr(
        sys,
        "argv",
        [
            "managed_service",
            "--config",
            "/fixture/config",
            "--cleanup-worker",
            s.worker_id,
            "--deployment-id",
            s.spec.deployment_id,
            "--repository",
            s.spec.repository,
        ],
    )
    with pytest.raises(SystemExit) as result:
        managed_service.main()
    assert result.value.code == 0
    assert json.loads(capsys.readouterr().out)["state"] == "cleaned"
    assert s.client.created == s.client.executed == 1
    with pytest.raises(execution_context.LegacyExecutionRefused):
        execution_context.require_legacy_execution()


def test_cleanup_app_construction_opens_journals_without_transport_or_execution(
    tmp_path, monkeypatch
):
    from src.worker import managed_service
    from src.worker.model_broker import ModelBroker
    from tests.unit.test_managed_model_integration import service_config

    config, credentials = service_config(tmp_path)
    config["children"] = [
        {
            key: config["models"][0][key]
            for key in ("deployment_id", "repository", "profile")
        }
        | {
            "policy": {
                "max_children": 2,
                "max_child_seconds": 20,
                "max_child_turns": 3,
                "capabilities": ["python"],
            }
        }
    ]
    monkeypatch.setattr(
        ModelBroker,
        "check_ready",
        lambda *_: pytest.fail("cleanup opened a transport probe"),
    )
    monkeypatch.setattr(
        ManagedDockerRuntime,
        "restore_model_endpoints",
        lambda *_: pytest.fail("cleanup restored endpoints"),
    )
    monkeypatch.setattr(
        ManagedDispatcher, "run", lambda *_: pytest.fail("cleanup started dispatcher")
    )
    app = managed_service.build_app(config, credentials, cleanup_only=True)
    try:
        assert app.state.managed_dispatcher.runtime._client is None
        assert not app.state.model_broker.endpoints
        assert not app.state.child_supervisor.endpoints.controls
        assert not app.state.managed_dispatcher.running.is_set()
    finally:
        app.state.child_supervisor.close()
        app.state.model_broker.close()
