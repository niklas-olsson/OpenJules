"""Real local identity journals; runtime/provider behavior is explicitly absent."""

from copy import deepcopy
from dataclasses import asdict, replace
import json
import os
from pathlib import Path
import sqlite3
import sys

import pytest

from src.worker import destination as module
from src.worker.destination import (
    DestinationConflict, DestinationState, DestinationUnavailable,
    connect_journal, initialize_destination, journal_members, parse_binding,
)
from src.worker.docker_runtime import DockerProfile, ManagedDockerRuntime
from src.worker.lifecycle import WorkerLifecycle, WorkerScope, WorkerSpec
from src.worker.managed_dispatch import DispatchJournal
from src.worker.model_broker import ModelBroker, ModelPolicy
from src.worker.child_journal import ChildJournal
from src.worker.child_types import ChildPolicy
from tests.unit.test_worker_lifecycle import ContractRuntime


SCOPE = WorkerScope("destination-test", "github:github.com/example/project")
SPEC = WorkerSpec(SCOPE.deployment_id, SCOPE.repository, "slot", 1, "original-key", "fixture")


def configuration(tmp_path, *, optional=False):
    root = tmp_path / "state"
    config = {
        "schema_version": 1,
        "state_directory": str(root),
        "lifecycle_database": str(root / "workers.sqlite3"),
        "credentials_file": str(tmp_path / "explicit-worker-credentials.json"),
        "authority": {"endpoint": "https://authority.example.invalid", "token_ref": "env:DESTINATION_AUTH_TOKEN"},
        "execution_destination": {"destination_id": "host-a"},
        "profiles": [{
            "name": "fixture", "deployment_id": SCOPE.deployment_id,
            "repository": SCOPE.repository, "source_path": str(tmp_path / "source"),
            "image": "sha256:" + "1" * 64, "command": ["python3", "-I", "-c", "pass"],
            "base_commit": "2" * 40,
        }],
    }
    if optional:
        common = asdict(SCOPE) | {"profile": "fixture"}
        config["models"] = [common | {"policy": {
            "endpoint": "https://provider.example.invalid/chat/completions",
            "model": "fixture-model", "token_ref": "env:PRIVATE_MODEL_TOKEN",
        }}]
        config["children"] = [common | {"policy": {
            "max_children": 2, "max_child_seconds": 20, "max_child_turns": 2,
            "capabilities": ["python"],
        }}]
    return config


def initialized(tmp_path, *, optional=False):
    config = configuration(tmp_path, optional=optional)
    initialize_destination(config)
    state = DestinationState.load(config)
    return config, state


def prepare_application(config, state):
    """Run actual effect-free schema constructors; never contact Docker/model/KP."""
    key = (SCOPE.deployment_id, SCOPE.repository, "fixture")
    model = None
    children = None
    try:
        if config.get("models"):
            model = ModelBroker(
                state.root / "models", {key: ModelPolicy(**config["models"][0]["policy"])},
                lambda _: 0, journal_binding=state.member("models"),
            )
        policies = {key: ChildPolicy(**config["children"][0]["policy"])} if config.get("children") else {}
        ManagedDockerRuntime(
            state.root / "runtime", [DockerProfile(**config["profiles"][0])], lambda *_: None,
            model_broker=model, child_policies=policies, journal_binding=state.member("runtime"),
        )
        WorkerLifecycle(config["lifecycle_database"], destination=state)
        DispatchJournal(state.root / "dispatcher", journal_binding=state.member("dispatcher"))
        if policies:
            children = ChildJournal(state.root / "children", journal_binding=state.member("children"))
        state.activate()
    finally:
        if children is not None:
            children.close()
        if model is not None:
            model.close()


def test_host_initialization_and_inspection_are_private_idempotent_and_effect_free(tmp_path, monkeypatch):
    def forbidden(*args, **kwargs):
        raise AssertionError("identity bootstrap must not contact runtime, model or authority")

    monkeypatch.setattr("docker.DockerClient", forbidden)
    monkeypatch.setattr("docker.from_env", forbidden)
    monkeypatch.setattr("src.polyphony.managed_client.ManagedAuthorityClient.__init__", forbidden)
    monkeypatch.setattr(ModelBroker, "check_ready", forbidden)
    config, state = initialized(tmp_path, optional=True)
    inspected = state.inspection()
    before = {path: Path(path).read_bytes() for path in journal_members(config).values()}
    assert initialize_destination(config) == inspected == DestinationState.load(config).inspection()
    assert before == {path: Path(path).read_bytes() for path in before}
    assert set(state.value["members"]) == {"lifecycle", "runtime", "dispatcher", "models", "children"}
    assert inspected["identity_binding"] == 1
    assert inspected["portable_manifest"] is False and inspected["local_admission"] is False
    safe = json.dumps(inspected)
    for private in (str(tmp_path), "PRIVATE_MODEL_TOKEN", "provider.example.invalid", "fingerprints"):
        assert private not in safe
    for path in [state.path, *(Path(p) for p in before)]:
        assert path.stat().st_mode & 0o077 == 0
    for member in before:
        with sqlite3.connect(member) as connection:
            assert connection.execute("SELECT name FROM sqlite_master WHERE type='table'").fetchall() == [
                (module.IDENTITY_TABLE,),
            ]


def test_private_policy_binding_covers_exact_docker_model_and_child_fingerprints(tmp_path):
    config, state = initialized(tmp_path, optional=True)
    retained = state.policies[(SCOPE.deployment_id, SCOPE.repository, "fixture")]["fingerprints"]
    assert retained == {
        "version": 1,
        "docker": DockerProfile(**config["profiles"][0]).fingerprint,
        "model": ModelPolicy(**config["models"][0]["policy"]).fingerprint,
        "children": ChildPolicy(**config["children"][0]["policy"]).fingerprint,
    }


def test_no_effect_until_all_enabled_application_journals_are_sealed(tmp_path, monkeypatch):
    config, state = initialized(tmp_path, optional=True)
    fixture = ContractRuntime()
    lifecycle = WorkerLifecycle(config["lifecycle_database"], fixture, destination=state)
    binding = state.binding(SCOPE, SPEC.profile)
    with pytest.raises(DestinationUnavailable, match="not initialized"):
        lifecycle.ensure_worker(SPEC, binding)
    with pytest.raises(DestinationUnavailable, match="not been initialized"):
        state.activate()
    assert fixture.launches == 0 and not state.inspection()["journals_initialized"]
    prepare_application(config, state)
    assert state.inspection()["journals_initialized"]
    assert lifecycle.ensure_worker(SPEC, binding)["state"] == "ready"
    assert fixture.launches == 1


@pytest.mark.parametrize("member,table", [
    ("lifecycle", "managed_workers"), ("lifecycle", "worker_operations"),
    ("lifecycle", "worker_executions"), ("runtime", "profiles"),
    ("runtime", "workers"), ("runtime", "attempts"), ("runtime", "child_profiles"),
    ("dispatcher", "deliveries"), ("models", "policies"), ("models", "workers"),
    ("models", "calls"), ("children", "workers"), ("children", "intents"), ("children", "children"),
])
def test_lost_application_table_blocks_entire_set_before_constructor_repair(tmp_path, member, table):
    config, state = initialized(tmp_path, optional=True)
    prepare_application(config, state)
    path = state.value["members"][member]
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE " + table)
    with pytest.raises(DestinationUnavailable):
        DestinationState.load(config)
    # A different member's normal connection also fences the partial set.
    with pytest.raises(DestinationUnavailable):
        connect_journal(config["lifecycle_database"], binding=state.member("lifecycle"))
    with pytest.raises(DestinationUnavailable):
        prepare_application(config, state)
    with sqlite3.connect(path) as connection:
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name=?", (table,)).fetchall()


@pytest.mark.parametrize("bit,table", [(1, "cold_rounds"), (2, "public_slots")])
def test_lost_enabled_optional_child_schema_fences_other_member_preflight(tmp_path, bit, table):
    from src.worker.managed_public_journal import install_optional_schema

    config, state = initialized(tmp_path, optional=True)
    prepare_application(config, state)
    path = state.value["members"]["children"]
    with sqlite3.connect(path) as connection:
        connection.execute("BEGIN IMMEDIATE")
        install_optional_schema(connection, bit, require_existing=False)
    state.verify()
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE " + table)
    with pytest.raises(DestinationUnavailable, match="optional child schema"):
        DestinationState.load(config)
    with pytest.raises(DestinationUnavailable, match="optional child schema"):
        connect_journal(config["lifecycle_database"], binding=state.member("lifecycle"))


@pytest.mark.parametrize("changed", ["conditional_index", "same_columns_without_unique", "missing_column"])
def test_schema_seal_preserves_replay_constraints_and_owned_indexes(tmp_path, changed):
    config, state = initialized(tmp_path)
    prepare_application(config, state)
    with sqlite3.connect(config["lifecycle_database"]) as connection:
        if changed == "conditional_index":
            connection.execute("DROP INDEX managed_worker_runtime_id")
        elif changed == "same_columns_without_unique":
            connection.execute("DROP TABLE worker_executions")
            connection.execute("CREATE TABLE worker_executions (worker_id TEXT NOT NULL,execution_id TEXT NOT NULL,parent_id TEXT,termination_confirmed INTEGER NOT NULL DEFAULT 0,artifacts_captured INTEGER NOT NULL DEFAULT 0)")
        else:
            connection.execute("ALTER TABLE managed_workers DROP COLUMN reason")
    with pytest.raises(DestinationUnavailable, match="schema"):
        DestinationState.load(config)
    with pytest.raises(DestinationUnavailable):
        WorkerLifecycle(config["lifecycle_database"], ContractRuntime(), destination=state)


@pytest.mark.parametrize("member", ["lifecycle", "runtime", "dispatcher", "models", "children"])
def test_missing_identity_table_cannot_downgrade_via_format_sentinel(tmp_path, member):
    config, state = initialized(tmp_path, optional=True)
    prepare_application(config, state)
    path = state.value["members"][member]
    with sqlite3.connect(path) as connection:
        connection.execute("DROP TABLE " + module.IDENTITY_TABLE)
    with pytest.raises(DestinationUnavailable):
        connect_journal(path)
    with pytest.raises(DestinationUnavailable):
        connect_journal(path, binding=state.member(member))
    if member == "lifecycle":
        with pytest.raises(DestinationUnavailable):
            WorkerLifecycle(path, ContractRuntime())


@pytest.mark.parametrize("retained", ["models/inference.sqlite3", "children/children.sqlite3", "runtime/captures/original.bin"])
def test_fresh_initialization_refuses_omitted_optional_or_partial_state(tmp_path, retained):
    config = configuration(tmp_path)
    target = Path(config["state_directory"]) / retained
    target.parent.mkdir(mode=0o700, parents=True)
    Path(config["state_directory"]).chmod(0o700)
    target.write_bytes(b"retained original state")
    with pytest.raises(DestinationConflict, match="existing journals"):
        initialize_destination(config)
    assert target.read_bytes() == b"retained original state"
    assert not (Path(config["state_directory"]) / "destination.json").exists()


def test_service_wires_all_members_and_activates_before_model_readiness(tmp_path, monkeypatch):
    from src.worker import managed_service

    config, state = initialized(tmp_path, optional=True)
    config["authority"] = {"endpoint": "https://authority.example.invalid", "token_ref": "env:DESTINATION_AUTH_TOKEN"}
    monkeypatch.setenv("DESTINATION_AUTH_TOKEN", "authority-fixture-token-" * 2)
    observations = []

    def ready(broker):
        # No socket/provider fixture here. The guard must already allow a normal
        # connection, and all five members must already be sealed.
        with broker.connection():
            pass
        observations.append(DestinationState.load(config).inspection()["journals_initialized"])

    monkeypatch.setattr(ModelBroker, "check_ready", ready)
    app = managed_service.build_app(config, {"lifecycle-fixture-token-" * 2: [SCOPE]})
    try:
        assert observations == [True]
        dispatcher = app.state.managed_dispatcher
        owners = [
            app.state.worker_lifecycle, dispatcher.runtime, dispatcher.journal,
            app.state.model_broker, app.state.child_supervisor.journal,
        ]
        assert {owner.journal_binding.member for owner in owners} == set(state.value["members"])
        assert DestinationState.load(config).inspection()["journals_initialized"]
    finally:
        app.state.child_supervisor.close()
        app.state.model_broker.close()


def test_service_rejects_partial_state_before_authority_or_component_construction(tmp_path, monkeypatch):
    from src.worker import managed_service

    config, state = initialized(tmp_path, optional=True)
    prepare_application(config, state)
    Path(state.value["members"]["models"]).unlink()

    def forbidden(*args, **kwargs):
        raise AssertionError("state must be validated before authority construction")

    monkeypatch.setattr("src.polyphony.managed_client.ManagedAuthorityClient", forbidden)
    with pytest.raises(DestinationUnavailable):
        managed_service.build_app(config, {"lifecycle-fixture-token-" * 2: [SCOPE]})
    assert not Path(state.value["members"]["models"]).exists()


def test_public_initialization_rejects_wrong_root_command_before_binding(tmp_path):
    from tests.unit.test_managed_public_policy import public_config

    config = public_config(tmp_path)
    config["execution_destination"] = {"destination_id": "public-host"}
    config["profiles"][0]["command"] = ["python3", "-I", "-c", "pass"]
    with pytest.raises(ValueError, match="public_root_command"):
        initialize_destination(config)
    assert not (Path(config["state_directory"]) / "destination.json").exists()


def test_local_cli_initialization_and_inspection_do_not_build_service(tmp_path, monkeypatch, capsys):
    from src.worker import managed_service

    config = configuration(tmp_path)
    credentials = tmp_path / "credentials.json"
    credentials.write_text(json.dumps({"lifecycle-fixture-token-" * 2: [asdict(SCOPE)]}))
    credentials.chmod(0o600)
    config["credentials_file"] = str(credentials)
    config["authority"] = {"endpoint": "https://authority.example.invalid", "token_ref": "env:UNRESOLVED_AUTH_TOKEN"}
    path = tmp_path / "service.json"
    path.write_text(json.dumps(config))

    def forbidden(*args, **kwargs):
        raise AssertionError("identity-only command must not construct the service")

    monkeypatch.setattr(managed_service, "build_app", forbidden)
    # This identity-only fixture must not latch managed context for later tests.
    # The process-wide refusal itself is exercised in the command-boundary suite.
    monkeypatch.setattr(managed_service, "select_managed_context", lambda: None)
    monkeypatch.setattr(managed_service, "enter_managed_context", lambda: None)
    monkeypatch.setattr(sys, "argv", ["managed-service", "--config", str(path), "--inspect-destination"])
    with pytest.raises(SystemExit) as error:
        managed_service.main()
    assert error.value.code == 2
    assert not Path(config["state_directory"]).exists()
    capsys.readouterr()
    monkeypatch.setattr(sys, "argv", ["managed-service", "--config", str(path), "--initialize-destination"])
    managed_service.main()
    original = json.loads(capsys.readouterr().out)
    monkeypatch.setattr(sys, "argv", ["managed-service", "--config", str(path), "--inspect-destination"])
    managed_service.main()
    assert json.loads(capsys.readouterr().out) == original
    assert original["journals_initialized"] is False


def test_actual_runtime_requires_original_policy_material_for_recovery(tmp_path):
    from src.worker.lifecycle import LifecycleConflict

    config, state = initialized(tmp_path)
    prepare_application(config, state)
    config["profiles"][0]["cpu_quota"] = 50000
    retained = DestinationState.load(config)
    assert retained.binding(SCOPE, SPEC.profile) == state.binding(SCOPE, SPEC.profile)
    with pytest.raises(LifecycleConflict, match="approved profile changed"):
        ManagedDockerRuntime(
            state.root / "runtime", [DockerProfile(**config["profiles"][0])], lambda *_: None,
            journal_binding=retained.member("runtime"),
        )


def test_changed_policy_cannot_seed_application_tables_after_identity_bootstrap(tmp_path):
    config, state = initialized(tmp_path)
    config["profiles"][0]["cpu_quota"] = 50000
    with pytest.raises(DestinationConflict, match="initialization policy changed"):
        DestinationState.load(config)
    with pytest.raises(DestinationConflict, match="initialization policy changed"):
        initialize_destination(config)
    with sqlite3.connect(state.value["members"]["runtime"]) as connection:
        assert not connection.execute("SELECT 1 FROM sqlite_master WHERE name='profiles'").fetchall()


@pytest.mark.parametrize("member", ["lifecycle", "runtime", "dispatcher", "models", "children"])
def test_missing_ready_member_refuses_load_reinitialize_and_existing_connection(tmp_path, member):
    config, state = initialized(tmp_path, optional=True)
    path = Path(state.value["members"][member])
    path.unlink()
    for operation in (
        lambda: DestinationState.load(config), lambda: initialize_destination(config),
        lambda: connect_journal(path, binding=state.member(member)),
    ):
        with pytest.raises(DestinationUnavailable):
            operation()
        assert not path.exists()


@pytest.mark.parametrize("member", ["lifecycle", "runtime", "dispatcher", "models", "children"])
def test_replaced_or_legacy_member_is_not_adopted(tmp_path, member):
    config, state = initialized(tmp_path, optional=True)
    other_config, other = initialized(tmp_path / "other", optional=True)
    path = Path(state.value["members"][member])
    path.write_bytes(Path(other.value["members"][member]).read_bytes())
    with pytest.raises(DestinationUnavailable):
        DestinationState.load(config)
    with pytest.raises(DestinationUnavailable):
        connect_journal(path, binding=state.member(member))
    path.write_bytes(b"")
    with pytest.raises(DestinationUnavailable):
        initialize_destination(config)
    assert path.read_bytes() == b""


def test_legacy_journal_and_bound_configuration_cannot_silently_migrate(tmp_path):
    config = configuration(tmp_path)
    legacy = WorkerLifecycle(config["lifecycle_database"], ContractRuntime())
    original = legacy.ensure_worker(SPEC)
    Path(config["state_directory"]).chmod(0o700)
    with pytest.raises(DestinationConflict, match="existing journals"):
        initialize_destination(config)
    assert legacy.ensure_worker(SPEC)["worker_id"] == original["worker_id"]
    assert not (Path(config["state_directory"]) / "destination.json").exists()


def test_bound_state_cannot_downgrade_through_any_legacy_journal_owner(tmp_path):
    config, state = initialized(tmp_path, optional=True)
    legacy = deepcopy(config)
    del legacy["execution_destination"]
    with pytest.raises(DestinationUnavailable, match="downgrade"):
        DestinationState.load(legacy)
    key = (SCOPE.deployment_id, SCOPE.repository, "fixture")
    constructors = (
        lambda: WorkerLifecycle(config["lifecycle_database"]),
        lambda: ManagedDockerRuntime(state.root / "runtime", [DockerProfile(**config["profiles"][0])], lambda *_: None),
        lambda: DispatchJournal(state.root / "dispatcher"),
        lambda: ModelBroker(state.root / "models", {key: ModelPolicy(**config["models"][0]["policy"])}, lambda _: 0),
        lambda: ChildJournal(state.root / "children"),
    )
    for construct in constructors:
        with pytest.raises(DestinationUnavailable, match="original destination context"):
            construct()


def test_refused_legacy_child_constructor_releases_ownership(tmp_path):
    config, state = initialized(tmp_path, optional=True)
    prepare_application(config, state)
    with pytest.raises(DestinationUnavailable) as retained_error:
        ChildJournal(state.root / "children")
    # Keep the failed constructor traceback alive while valid recovery acquires
    # the same service lock; collection of the failed object is not the fence.
    assert retained_error.value
    recovered = ChildJournal(state.root / "children", journal_binding=state.member("children"))
    recovered.close()


@pytest.mark.parametrize("changed", ["version", "required_feature", "extra_field", "member_version", "member_extra_column"])
def test_unknown_state_formats_fence_startup_and_already_open_service(tmp_path, changed):
    config, state = initialized(tmp_path)
    binding = state.member("lifecycle")
    if changed.startswith("member_"):
        with sqlite3.connect(config["lifecycle_database"]) as connection:
            if changed == "member_version":
                connection.execute("UPDATE " + module.IDENTITY_TABLE + " SET format_version=2")
            else:
                connection.execute("ALTER TABLE " + module.IDENTITY_TABLE + " ADD COLUMN future TEXT")
    else:
        value = deepcopy(state.value)
        if changed == "version":
            value["schema_version"] = 2
        elif changed == "required_feature":
            value["required_features"].append("future_admission_v1")
        else:
            value["unknown"] = True
        state.path.write_text(json.dumps(value))
    with pytest.raises(DestinationUnavailable):
        DestinationState.load(config)
    with pytest.raises(DestinationUnavailable):
        connect_journal(config["lifecycle_database"], binding=binding)


def test_interrupted_initialization_reuses_original_intent_without_adopting_partial_sqlite(tmp_path, monkeypatch):
    config = configuration(tmp_path)
    link = os.link
    calls = 0

    def crash(source, target, **kwargs):
        nonlocal calls
        calls += 1
        if calls == 2:
            raise RuntimeError("injected crash before publishing complete member")
        return link(source, target, **kwargs)

    monkeypatch.setattr(os, "link", crash)
    with pytest.raises(RuntimeError, match="injected crash"):
        initialize_destination(config)
    original = json.loads((Path(config["state_directory"]) / "destination.json").read_text())
    with pytest.raises(DestinationUnavailable):
        DestinationState.load(config)
    monkeypatch.setattr(os, "link", link)
    result = initialize_destination(config)
    assert result["journal_incarnation"] == original["journal_incarnation"]
    assert result["profiles"][0]["destination_binding"]["policy_binding_id"] == original["policies"][0]["id"]


def test_wrong_journal_recovery_cannot_look_empty_or_duplicate_original_key(tmp_path):
    config_a, state_a = initialized(tmp_path / "a")
    config_b, state_b = initialized(tmp_path / "b")
    prepare_application(config_a, state_a)
    prepare_application(config_b, state_b)
    runtime_a, runtime_b = ContractRuntime(), ContractRuntime()
    runtime_a.lose_launch_response = True
    a = WorkerLifecycle(config_a["lifecycle_database"], runtime_a, destination=state_a)
    b = WorkerLifecycle(config_b["lifecycle_database"], runtime_b, destination=state_b)
    binding = state_a.binding(SCOPE, "fixture")
    lost = a.ensure_worker(SPEC, binding)
    assert lost["state"] == "unknown" and runtime_a.launches == 1
    with pytest.raises(DestinationConflict):
        b.ensure_worker(SPEC, binding)
    assert runtime_b.launches == 0
    reopened = WorkerLifecycle(config_a["lifecycle_database"], runtime_a, destination=DestinationState.load(config_a))
    recovered = reopened.ensure_worker(SPEC, binding)
    assert recovered["worker_id"] == lost["worker_id"] and recovered["state"] == "ready"
    assert recovered["destination_binding"] == binding and runtime_a.launches == 1
    with reopened._transaction() as connection:
        row = connection.execute("SELECT payload FROM worker_operations").fetchone()
        assert json.loads(row["payload"]) == {"spec": asdict(SPEC), "destination_binding": binding}
    dispatch = DispatchJournal(state_a.root / "dispatcher", journal_binding=state_a.member("dispatcher"))
    # The internal canonical worker schema remains v1 despite bound HTTP projection.
    assert json.loads(dispatch.reserve(recovered, "task-fixture")["spec"])["schema_version"] == 1


def test_policy_change_preserves_api_identity_with_original_fixture_driver(tmp_path):
    config, state = initialized(tmp_path)
    prepare_application(config, state)
    runtime = ContractRuntime()
    lifecycle = WorkerLifecycle(config["lifecycle_database"], runtime, destination=state)
    binding = state.binding(SCOPE, "fixture")
    original = lifecycle.ensure_worker(SPEC, binding)
    changed = deepcopy(config)
    changed["profiles"][0]["cpu_quota"] = 50000
    retained = DestinationState.load(changed)
    assert retained.binding(SCOPE, "fixture") == binding
    assert retained.inspection()["profiles"][0]["current_policy_matches"] is False
    lifecycle = WorkerLifecycle(config["lifecycle_database"], runtime, destination=retained)
    lifecycle.validate_worker_binding(SCOPE, original["worker_id"], binding)
    assert lifecycle.ensure_worker(SPEC, binding)["worker_id"] == original["worker_id"]
    with pytest.raises(DestinationUnavailable, match="not approved"):
        lifecycle.ensure_worker(replace(SPEC, slot_id="next", launch_key="new-key"), binding)
    result = lifecycle.stop_worker(SCOPE, original["worker_id"], "stop-original")
    assert result["state"] == "stopped" and result["termination_confirmed"] and result["artifacts_captured"]
    assert runtime.launches == 1 and runtime.stops == 1


@pytest.mark.parametrize("field,value", [
    ("destination_id", ""), ("destination_id", "host/name"), ("destination_id", "a" * 129),
    ("journal_incarnation", "A" * 32), ("journal_incarnation", "0" * 31),
    ("policy_binding_id", 1), ("policy_binding_version", True), ("policy_binding_version", "1"),
])
def test_binding_formats_are_exact(tmp_path, field, value):
    _, state = initialized(tmp_path)
    with pytest.raises(ValueError):
        parse_binding(state.binding(SCOPE, "fixture") | {field: value})
