"""The added installed-idle witness must prove a real complete scoped cycle."""

from copy import deepcopy
import json
import sqlite3
from types import SimpleNamespace
from urllib.parse import urlencode

import pytest

from tools.managed_cost_installed import (
    SNAPSHOT_ARRAYS, _zero_event, original_store, require_empty_snapshot, retained_worker_rows,
    retained_cleanup_receipt, retained_resource_size, witness_zero, zero_binding,
)


def plan():
    return {"schema_version": 1, "deployment_id": "cost-idle-fixture", "reserved": 0,
            "repositories": [{"repository": "github:github.com/managed-cost-fixture/idle",
                              "profile": "cost-idle-model-v1", "revision": 1,
                              "desired_workers": 0, "effective_target": 0,
                              "permitted_target": 0, "healthy": 0, "reserved": 0,
                              "workers": [], "enabled": True, "paused": False,
                              "validation": {"ready": True}}]}


def line(binding, *, path="/api/workers/capabilities", query=None, method="GET", status="200 OK"):
    if query is None:
        query = urlencode({name: binding[name] for name in ("deployment_id", "repository", "profile")})
    return f'INFO:     127.0.0.1:40000 - "{method} {path}?{query} HTTP/1.1" {status}\n'.encode()


def test_zero_binding_requires_ready_empty_original_target():
    original = plan()
    binding = zero_binding(original)
    assert binding["binding_revision"] == 1
    assert binding["deployment_id"] == original["deployment_id"]
    for key, value in (("desired_workers", 1), ("healthy", False), ("reserved", True),
                       ("workers", [{"worker_id": "foreign"}]), ("enabled", False),
                       ("paused", True), ("validation", {"ready": False})):
        changed = deepcopy(original)
        changed["repositories"][0][key] = value
        with pytest.raises(AssertionError):
            zero_binding(changed)
    changed = deepcopy(original)
    changed["reserved"] = False
    with pytest.raises(AssertionError):
        zero_binding(changed)


def test_zero_log_rejects_foreign_duplicate_mutating_and_failed_calls():
    binding = zero_binding(plan())
    assert _zero_event(line(binding).rstrip(b"\n"), binding) == "capabilities"
    assert _zero_event(b"INFO: service ready", binding) is None
    for candidate in (
        line(binding, path="/api/workers/foreign"),
        line(binding, method="POST"),
        line(binding, status="403 Forbidden"),
        line(binding, query=urlencode({**binding, "profile": "foreign"})),
        line(binding, query=urlencode({name: binding[name] for name in ("deployment_id", "repository", "profile")}) + "&profile=cost-idle-model-v1"),
        b"unrecognized /api/workers/capabilities output\n",
        b"\xff\n",
    ):
        with pytest.raises(AssertionError):
            _zero_event(candidate.rstrip(b"\n"), binding)


class Clock:
    def __init__(self):
        self.value = 0

    def __call__(self):
        self.value += 1_000_000
        return self.value


def test_zero_witness_counts_only_fresh_complete_scoped_records(tmp_path):
    binding = zero_binding(plan())
    path = tmp_path / "installation.log"
    old = line(binding) * 3 + b"partial old record"
    path.write_bytes(old)
    clock = Clock()
    writes = 0

    def sleep(_):
        nonlocal writes
        writes += 1
        with path.open("ab") as stream:
            stream.write(b" continuation\n" + line(binding) * 3)

    result = witness_zero(path, binding, SimpleNamespace(poll=lambda: None), 0, clock, sleep)
    assert writes == 1
    assert len(result["events"]) == 3
    assert result["log_start_offset"] == len(old)
    assert result["discarded_partial_prefix_bytes"] == len(b" continuation\n")
    assert all(event["log_start_offset"] >= len(old) + len(b" continuation\n") for event in result["events"])
    assert result["binding"] == binding


def test_zero_witness_rejects_unexpected_worker_and_log_replacement(tmp_path):
    binding = zero_binding(plan())
    for replace in (False, True):
        path = tmp_path / ("replacement.log" if replace else "foreign.log")
        path.write_bytes(b"")

        def sleep(_):
            if replace:
                path.rename(path.with_suffix(".old"))
                path.write_bytes(line(binding) * 3)
            else:
                with path.open("ab") as stream:
                    stream.write(line(binding, path="/api/workers/foreign"))

        with pytest.raises(AssertionError):
            witness_zero(path, binding, SimpleNamespace(poll=lambda: None), 0, Clock(), sleep)


def test_zero_witness_deadline_and_manager_loss_are_not_empty_success(tmp_path):
    path = tmp_path / "installation.log"
    path.write_bytes(b"")
    binding = zero_binding(plan())
    with pytest.raises(AssertionError, match="idle_witness_deadline"):
        witness_zero(path, binding, SimpleNamespace(poll=lambda: None), 0,
                     lambda: 60_000_000_000, lambda _: None)
    with pytest.raises(AssertionError, match="idle_manager_exited"):
        witness_zero(path, binding, SimpleNamespace(poll=lambda: 1), 0,
                     Clock(), lambda _: None)


def empty_snapshot():
    scope = {"deployment_id": "cost-idle-fixture",
             "repository": "github:github.com/managed-cost-fixture/idle"}
    value = {"schema_version": 1, **scope, "cursor": 0,
             **{name: [] for name in SNAPSHOT_ARRAYS}}
    return value, scope


def test_idle_empty_snapshot_requires_exact_authority_schema():
    original, scope = empty_snapshot()
    require_empty_snapshot(original, scope)
    for key in original:
        changed = deepcopy(original)
        del changed[key]
        with pytest.raises(AssertionError, match="idle_snapshot_schema"):
            require_empty_snapshot(changed, scope)
    for candidate in ([], None, {**original, "admission": []}):
        with pytest.raises(AssertionError, match="idle_snapshot_schema"):
            require_empty_snapshot(candidate, scope)
    assert original == empty_snapshot()[0]


@pytest.mark.parametrize("name", sorted(SNAPSHOT_ARRAYS))
def test_idle_empty_snapshot_rejects_work_or_unavailable_arrays(name):
    original, scope = empty_snapshot()
    for value in ([{"id": "original-work"}], None, {}, ()):
        changed = {**original, name: value}
        with pytest.raises(AssertionError, match="idle_canonical_work_or_scope_changed"):
            require_empty_snapshot(changed, scope)


@pytest.mark.parametrize("field,value", [
    ("schema_version", True), ("schema_version", 2), ("schema_version", "1"),
    ("cursor", False), ("cursor", 1), ("cursor", "0"),
    ("deployment_id", "other-installation"),
    ("repository", "github:github.com/managed-cost-fixture/other"),
])
def test_idle_empty_snapshot_rejects_changed_scope_and_nonzero_cursor(field, value):
    original, scope = empty_snapshot()
    with pytest.raises(AssertionError, match="idle_canonical_work_or_scope_changed"):
        require_empty_snapshot({**original, field: value}, scope)


def journal(path, scope, workers=()):
    """Small real retained journal, sufficient for the read-only recovery query."""
    with sqlite3.connect(path) as db:
        db.executescript("""
            CREATE TABLE metadata (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE workers (
                launch_id TEXT PRIMARY KEY, repository TEXT NOT NULL,
                snapshot TEXT NOT NULL
            );
        """)
        db.execute("INSERT INTO metadata VALUES (?, ?)",
                   ("deployment_id", scope["deployment_id"]))
        for index, worker in enumerate(workers):
            db.execute("INSERT INTO workers VALUES (?, ?, ?)",
                       ("original-launch-" + str(index), scope["repository"],
                        json.dumps({"worker_id": worker, "state": "provisioning"})))
    info = path.lstat()
    return info.st_dev, info.st_ino


def test_retained_journal_recovers_original_reservation_without_writing(tmp_path):
    _, scope = empty_snapshot()
    state = tmp_path / "state.sqlite3"
    identity = journal(state, scope, ["original-worker"])
    before = state.read_bytes(), state.stat().st_mtime_ns, set(tmp_path.iterdir())
    rows = retained_worker_rows(state, identity, scope)
    assert rows == [{"launch_id": "original-launch-0", "repository": scope["repository"],
                     "snapshot": {"worker_id": "original-worker", "state": "provisioning"}}]
    assert (state.read_bytes(), state.stat().st_mtime_ns, set(tmp_path.iterdir())) == before


def test_retained_journal_can_observe_original_empty_journal(tmp_path):
    _, scope = empty_snapshot()
    state = tmp_path / "state.sqlite3"
    identity = journal(state, scope)
    assert retained_worker_rows(state, identity, scope) == []


@pytest.mark.parametrize("change", ["deployment", "repository", "multiple", "missing_scope"])
def test_retained_journal_refuses_changed_scope_or_reservations(tmp_path, change):
    _, scope = empty_snapshot()
    state = tmp_path / "state.sqlite3"
    identity = journal(state, scope, ["original-worker"])
    with sqlite3.connect(state) as db:
        if change == "deployment":
            db.execute("UPDATE metadata SET value = 'other-installation'")
        elif change == "repository":
            db.execute("UPDATE workers SET repository = 'other-repository'")
        elif change == "multiple":
            db.execute("INSERT INTO workers SELECT 'second-launch', repository, snapshot FROM workers")
        else:
            db.execute("DELETE FROM metadata")
    before = state.read_bytes()
    with pytest.raises(AssertionError, match="idle_original_(scope|reservations)_changed"):
        retained_worker_rows(state, identity, scope)
    assert state.read_bytes() == before


@pytest.mark.parametrize("change", ["replacement", "symlink", "missing"])
def test_retained_journal_refuses_changed_file_without_initializing(tmp_path, change):
    _, scope = empty_snapshot()
    state = tmp_path / "state.sqlite3"
    original = tmp_path / "original.sqlite3"
    identity = journal(state, scope, ["original-worker"])
    state.rename(original)
    if change == "replacement":
        journal(state, scope, ["foreign-worker"])
    elif change == "symlink":
        state.symlink_to(original)
    before = set(tmp_path.iterdir()), original.read_bytes()
    with pytest.raises((AssertionError, FileNotFoundError)):
        retained_worker_rows(state, identity, scope)
    assert (set(tmp_path.iterdir()), original.read_bytes()) == before


def test_retained_journal_refuses_replacement_between_identity_check_and_open(tmp_path, monkeypatch):
    _, scope = empty_snapshot()
    state = tmp_path / "state.sqlite3"
    identity = journal(state, scope, ["original-worker"])
    replacement = tmp_path / "replacement.sqlite3"
    journal(replacement, scope, ["foreign-worker"])
    connect = sqlite3.connect

    def swapped_connect(*args, **kwargs):
        state.rename(tmp_path / "original.sqlite3")
        replacement.rename(state)
        return connect(*args, **kwargs)

    monkeypatch.setattr(sqlite3, "connect", swapped_connect)
    with pytest.raises(AssertionError, match="idle_original_journal_changed"):
        retained_worker_rows(state, identity, scope)


def test_original_store_never_initializes_missing_control_state(tmp_path):
    _, scope = empty_snapshot()
    state = tmp_path / "state.sqlite3"
    identity = journal(state, scope)
    state.rename(tmp_path / "original.sqlite3")
    calls = []

    def forbidden_constructor(*args, **kwargs):
        calls.append((args, kwargs))
        raise AssertionError("constructor must not reach missing original state")

    with pytest.raises(AssertionError, match="idle_original_journal_changed"):
        with original_store(forbidden_constructor, state, identity, scope):
            pytest.fail("changed state must never be yielded")
    assert calls == [] and not state.exists()


def test_original_store_refuses_replacement_during_constructor_before_yield(tmp_path):
    _, scope = empty_snapshot()
    state = tmp_path / "state.sqlite3"
    identity = journal(state, scope, ["original-worker"])
    replacement = tmp_path / "replacement.sqlite3"
    journal(replacement, scope, ["foreign-worker"])
    calls = []

    class ReplacingStore:
        def __init__(self, path, deployment_id, *, create):
            assert path == state and deployment_id == scope["deployment_id"]
            calls.append(("constructed", create))
            state.rename(tmp_path / "original.sqlite3")
            replacement.rename(state)

        def __enter__(self):
            calls.append("entered")
            return self

        def __exit__(self, kind, value, traceback):
            calls.append(("closed", kind))

    with pytest.raises(AssertionError, match="idle_original_journal_changed"):
        with original_store(ReplacingStore, state, identity, scope):
            pytest.fail("replacement must never receive a controller mutation")
    assert calls == [("constructed", False), "entered", ("closed", AssertionError)]


def cleanup_result():
    _, scope = empty_snapshot()
    receipt = {"schema_version": 1, **scope, "worker_id": "original-worker",
               "state": "retained", "reason": "executed_capture_required",
               "container_removed": False, "volume_removed": False,
               "archives_retained": True}
    return scope, receipt


def test_idle_native_retention_is_observed_without_claiming_removal(tmp_path):
    from tools.managed_cost_measurement import Recorder

    scope, receipt = cleanup_result()
    recorder = Recorder(tmp_path)
    result = SimpleNamespace(returncode=1, stdout=json.dumps(receipt))
    assert retained_cleanup_receipt(result, scope, "original-worker", recorder) == receipt
    observed = recorder.report()["facts"]["installed_cleanup_observation"]
    assert observed["state"] == "retained" and observed["identity_matches"] is True
    assert observed["container_removed"] is False and observed["volume_removed"] is False
    assert recorder.report()["complete"] is True


@pytest.mark.parametrize("change", [
    {"schema_version": True}, {"worker_id": "foreign-worker"}, {"state": "cleaned"},
    {"reason": "SECRET_PRIVATE_PATH"}, {"container_removed": 0},
    {"volume_removed": True}, {"extra": "SECRET_PRIVATE_PATH"},
])
def test_changed_native_cleanup_receipt_remains_unqualified_and_private(tmp_path, change):
    from tools.managed_cost_measurement import Recorder

    scope, receipt = cleanup_result()
    recorder = Recorder(tmp_path)
    result = SimpleNamespace(returncode=1, stdout=json.dumps(receipt | change))
    with pytest.raises(AssertionError, match="idle_retained_cleanup_receipt_invalid"):
        retained_cleanup_receipt(result, scope, "original-worker", recorder)
    assert "SECRET_PRIVATE_PATH" not in json.dumps(recorder.report())


@pytest.mark.parametrize("returncode,stdout", [(0, None), (True, None), (1, "not-json"),
                                              (1, "x" * 4097)])
def test_idle_retention_needs_exact_native_exit_and_bounded_receipt(tmp_path, returncode, stdout):
    from tools.managed_cost_measurement import Recorder

    scope, receipt = cleanup_result()
    result = SimpleNamespace(returncode=returncode,
                             stdout=json.dumps(receipt) if stdout is None else stdout)
    with pytest.raises(AssertionError, match="idle_retained_cleanup_receipt_invalid"):
        retained_cleanup_receipt(result, scope, "original-worker", Recorder(tmp_path))


def retained_resources():
    from src.worker.docker_runtime import ManagedDockerRuntime

    container = SimpleNamespace(id="original-container", reload=lambda: None,
                                attrs={"State": {"Running": False, "Status": "exited"},
                                       "Mounts": [{"Destination": "/workspace", "Type": "volume",
                                                   "Name": "original-volume"}]})
    volume = SimpleNamespace(reload=lambda: None,
                             attrs={"Name": "original-volume", "CreatedAt": "fixture-time",
                                    "Driver": "local", "Scope": "local",
                                    "Labels": {"openjules.worker": "original-worker"}, "Options": None})
    sizes = {"Volumes": [{"Name": "original-volume", "UsageData": {"Size": 8192}}]}
    calls = []
    def get_container(identity):
        calls.append(("container", identity))
        assert identity == "original-container"
        return container
    def get_volume(identity):
        calls.append(("volume", identity))
        assert identity == "original-volume"
        return volume
    client = SimpleNamespace(containers=SimpleNamespace(get=get_container),
                             volumes=SimpleNamespace(get=get_volume), df=lambda: sizes)
    identity = deepcopy(ManagedDockerRuntime._volume_identity(volume))
    return client, container, volume, sizes, identity, calls


def test_retained_volume_is_observed_and_charged_not_removed():
    client, container, volume, sizes, identity, calls = retained_resources()
    assert retained_resource_size(client, "original-container", "original-volume", identity) == 8192
    assert calls == [("container", "original-container"), ("volume", "original-volume")]


@pytest.mark.parametrize("change", ["running", "foreign_container", "foreign_mount", "changed_volume",
                                   "missing_size", "boolean_size", "duplicate_size"])
def test_retention_requires_original_stopped_resources_and_actual_storage(change):
    client, container, volume, sizes, identity, calls = retained_resources()
    if change == "running":
        container.attrs["State"]["Running"] = True
    elif change == "foreign_container":
        container.id = "foreign-container"
    elif change == "foreign_mount":
        container.attrs["Mounts"][0]["Name"] = "foreign-volume"
    elif change == "changed_volume":
        volume.attrs["CreatedAt"] = "recreated"
    elif change == "missing_size":
        sizes["Volumes"].clear()
    elif change == "boolean_size":
        sizes["Volumes"][0]["UsageData"]["Size"] = False
    elif change == "duplicate_size":
        sizes["Volumes"].append(deepcopy(sizes["Volumes"][0]))
    with pytest.raises(AssertionError):
        retained_resource_size(client, "original-container", "original-volume", identity)
