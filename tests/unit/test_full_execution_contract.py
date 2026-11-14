"""Full destination approval, original-key recovery and serialized admission.

Explicit local runtime/image fixtures qualify this boundary. Real installed
source/image and container evidence is a separate native integration case.
"""

from concurrent.futures import ThreadPoolExecutor
from copy import deepcopy
from dataclasses import asdict, replace
import json
from pathlib import Path
import sqlite3
import subprocess
import sys
import time
from threading import Event
from types import SimpleNamespace
from unittest.mock import Mock

import httpx
import pytest

from src.api.worker_lifecycle import create_worker_app
from src.worker.destination import DestinationState, DestinationConflict, DestinationUnavailable, FULL_FEATURES, initialize_destination
from src.worker.execution_contract import canonical_bytes, digest, normalize_configuration, primary_configuration, project, MAX_INTEGER
from src.worker.lifecycle import LifecycleConflict, WorkerLifecycle
from src.worker.managed_configuration import ConfigurationInvalid, parse_configuration_bytes, prepare_configuration
from tests.unit.test_execution_destination import configuration, prepare_application, SCOPE, SPEC
from tests.unit.test_worker_lifecycle import ContractRuntime

IMAGE = {"config_digest": "sha256:" + "1" * 64, "os": "linux", "architecture": "amd64", "variant": None}


def full_configuration(path, *, optional=False):
    config = configuration(path, optional=optional)
    config["schema_version"] = 2
    config["profiles"][0]["root_timeout_ms"] = 300000
    if optional:
        config["models"][0]["policy"]["request_timeout_ms"] = 30000
        child = config["children"][0]["policy"]
        child["max_child_ms"] = child.pop("max_child_seconds") * 1000
    config["execution_contract"] = {
        "version": 1, "mode": "full", "initial_worker_ceiling": 2,
        "public_profiles": [asdict(SCOPE) | {"profile": SPEC.profile,
                            "model_service_policy_id": "fixture-model-policy" if optional else None}],
    }
    return config


class FullRuntime(ContractRuntime):
    def __init__(self):
        super().__init__()
        self.execution_image = Mock(return_value=dict(IMAGE))


def full_destination(tmp_path, *, optional=False, activate=True, runtime=None):
    config = full_configuration(tmp_path, optional=optional)
    initialize_destination(config)
    state = DestinationState.load(config)
    candidate = state.preview_contract(SCOPE, SPEC.profile, IMAGE)
    state.approve_contract(json.dumps(candidate).encode())
    if activate:
        prepare_application(normalize_configuration(config), state)
    runtime = runtime or FullRuntime()
    lifecycle = WorkerLifecycle(config["lifecycle_database"], runtime, destination=state)
    binding = state.binding(SCOPE, SPEC.profile)
    original = {"contract_version": 1, "execution_manifest_sha256": candidate["execution_manifest_sha256"], "admission_revision": 1}
    return config, state, lifecycle, runtime, binding, original


def opened(tmp_path):
    result = full_destination(tmp_path)
    result[2].admission_status("open")
    result[5]["admission_revision"] = 2
    return result


def test_restricted_encoding_has_literal_unicode_and_integer_vectors():
    assert canonical_bytes({"z": "\U0001f600", "a": "\b\f\n\r\t\"\\"}) == b'{"a":"\\b\\f\\n\\r\\t\\\"\\\\","z":"\xf0\x9f\x98\x80"}'
    assert canonical_bytes({"n": MAX_INTEGER}) == b'{"n":9007199254740991}'
    assert canonical_bytes({"x": "e\u0301"}) != canonical_bytes({"x": "\u00e9"})
    assert canonical_bytes({"x": ["b", "a"]}) != canonical_bytes({"x": ["a", "b"]})
    for value in (1.0, float("nan"), -1, MAX_INTEGER + 1, "\ud800", {"\u00e9": 1}):
        with pytest.raises(ValueError):
            canonical_bytes({"x": value})


@pytest.mark.parametrize("optional", [False, True])
def test_full_primary_configuration_is_native_and_public_projection_is_complete(tmp_path, optional):
    config = full_configuration(tmp_path, optional=optional)
    prepared = prepare_configuration(config)
    key = (SCOPE.deployment_id, SCOPE.repository, SPEC.profile)
    manifest = project(config, prepared, key, IMAGE)
    assert manifest["resources"]["root_timeout_ms"] == 300000
    assert manifest["image"] == IMAGE
    assert manifest["children"] is not None if optional else manifest["children"] is None
    public = canonical_bytes(manifest).decode()
    for private in (str(tmp_path), "PRIVATE_MODEL_TOKEN", "DESTINATION_AUTH_TOKEN", "provider.example.invalid", "fingerprints"):
        assert private not in public
    assert prepared.fingerprints() == prepare_configuration(normalize_configuration(config)).fingerprints()
    assert primary_configuration(config)["root_durations"][0][-1] == 300000


@pytest.mark.parametrize("change", [
    lambda c: c["profiles"][0].update(root_timeout_ms=True),
    lambda c: c["profiles"][0].update(root_timeout_ms=1001),
    lambda c: c["profiles"][0].update(max_seconds=300),
    lambda c: c["profiles"][0].pop("root_timeout_ms"),
    lambda c: c["profiles"][0].update(repository="https://github.com/example/project"),
    lambda c: c["profiles"][0].update(repository="github:github.com/Example/project"),
    lambda c: c["profiles"][0].update(environment_refs={"OPENAI_API_KEY": "env:SECRET"}),
    lambda c: c["execution_contract"].update(initial_worker_ceiling=True),
    lambda c: c["execution_contract"].update(version=True),
    lambda c: c["execution_contract"]["public_profiles"][0].update(model_service_policy_id="unexpected"),
    lambda c: c.update(unrecognized="value"),
])
def test_invalid_schema_two_fails_in_pure_phase(tmp_path, change):
    config = full_configuration(tmp_path)
    change(config)
    with pytest.raises(ConfigurationInvalid):
        prepare_configuration(config)
    assert not Path(config["state_directory"]).exists()


def test_schema_two_duplicate_fields_do_not_preserve_legacy_tolerance(tmp_path):
    raw = json.dumps(full_configuration(tmp_path)).replace('"schema_version": 2', '"schema_version": 1, "schema_version": 2').encode()
    with pytest.raises(ConfigurationInvalid):
        parse_configuration_bytes(raw)


def test_approval_initialization_and_counter_state_do_not_call_runtime_or_read_credentials(tmp_path, monkeypatch):
    config = full_configuration(tmp_path)
    initialize_destination(config)
    state = DestinationState.load(config)
    assert state.value["required_features"] == FULL_FEATURES
    with pytest.raises(DestinationUnavailable):
        state.require_approvals()
    runtime = FullRuntime()
    lifecycle = WorkerLifecycle(config["lifecycle_database"], runtime, destination=state)
    assert lifecycle.admission_status() == {"version": 1, "revision": 1, "new_effects_open": False, "worker_ceiling": 2, "unreleased_workers": 0}
    candidate = state.preview_contract(SCOPE, SPEC.profile, IMAGE)
    changed = deepcopy(candidate)
    changed["manifest"]["execution"]["root_uid"] = True
    changed["execution_manifest_sha256"] = digest(canonical_bytes(changed["manifest"]))
    with pytest.raises(DestinationConflict):
        state.approve_contract(json.dumps(changed).encode())
    state.approve_contract(json.dumps(candidate).encode())
    with pytest.raises(DestinationConflict):
        state.preview_contract(SCOPE, SPEC.profile, IMAGE | {"architecture": "arm64"})
    lifecycle.admission_status("open")
    before = lifecycle.admission_status()
    state.approve_contract(json.dumps(candidate).encode())
    assert lifecycle.admission_status() == before
    assert not Path(config["credentials_file"]).exists()
    runtime.execution_image.assert_not_called()


@pytest.mark.parametrize("field", ["revision", "closure_epoch"])
def test_admission_idempotence_and_exhaustion_never_wrap(tmp_path, field):
    config, state, lifecycle, runtime, binding, original = full_destination(tmp_path)
    assert lifecycle.admission_status("close")["revision"] == 1
    assert lifecycle.admission_status("ceiling", 2)["revision"] == 1
    assert lifecycle.admission_status("ceiling", 3)["revision"] == 2
    with sqlite3.connect(config["lifecycle_database"]) as db:
        db.execute(f"UPDATE destination_admission SET {field}=?", (MAX_INTEGER,))
    with pytest.raises(DestinationConflict):
        lifecycle.admission_status("open")
    assert lifecycle.admission_status()["new_effects_open"] is False


def test_missing_admission_or_approval_never_reinitializes(tmp_path):
    config, state, lifecycle, *_ = full_destination(tmp_path)
    with sqlite3.connect(config["lifecycle_database"]) as db:
        db.execute("DELETE FROM destination_admission")
    with pytest.raises(DestinationUnavailable):
        initialize_destination(config)
    with sqlite3.connect(config["lifecycle_database"]) as db:
        assert db.execute("SELECT COUNT(*) FROM destination_admission").fetchone()[0] == 0


def test_closed_refusal_keeps_one_terminal_original_receipt_across_restart_reopen_and_runtime_loss(tmp_path):
    config, state, lifecycle, runtime, binding, original = full_destination(tmp_path)
    refused = lifecycle.ensure_worker(SPEC, binding, original)
    assert refused["state"] == "stopped" and refused["reason"] == "never_admitted"
    assert refused["termination_confirmed"] and refused["artifacts_captured"]
    assert refused["active_executions"] == [] and not refused["admission_open"]
    assert refused["disposition"] == {"version": 1, "kind": "never_admitted", "reason": "closed", "observed_admission_revision": 1}
    runtime.execution_image.reset_mock()
    runtime.available = False
    runtime.execution_image.side_effect = AssertionError("known refused work must not requalify")
    lifecycle = WorkerLifecycle(config["lifecycle_database"], runtime, destination=DestinationState.load(config))
    lifecycle.admission_status("open")
    assert lifecycle.ensure_worker(SPEC, binding, original) == refused
    assert lifecycle.discover_bound_workers(SCOPE, SPEC.profile, binding, launch_key=SPEC.launch_key, execution_qualification=original) == [refused]
    assert lifecycle.stop_worker(SCOPE, refused["worker_id"], "stop-original") == refused
    assert runtime.launches == runtime.stops == 0
    runtime.execution_image.assert_not_called()
    with pytest.raises(LifecycleConflict):
        lifecycle.ensure_worker(SPEC, binding, original | {"admission_revision": 2})


@pytest.mark.parametrize("corruption", ["completed_execution", "outer_reason", "draining"])
def test_never_admitted_refuses_contradictory_retained_history(tmp_path, corruption):
    config, state, lifecycle, runtime, binding, original = full_destination(tmp_path)
    refused = lifecycle.ensure_worker(SPEC, binding, original)
    wid = refused["worker_id"]
    with sqlite3.connect(config["lifecycle_database"]) as db:
        if corruption == "completed_execution":
            db.execute("INSERT INTO worker_executions VALUES (?,?,NULL,1,1)", (wid, "historical-root"))
        elif corruption == "outer_reason":
            db.execute("UPDATE managed_workers SET reason='captured' WHERE worker_id=?", (wid,))
        else:
            db.execute("UPDATE managed_workers SET draining=0 WHERE worker_id=?", (wid,))
    runtime.execution_image.reset_mock()
    for operation in (
        lambda: lifecycle.observe_worker(SCOPE, wid),
        lambda: lifecycle.ensure_worker(SPEC, binding, original),
        lambda: lifecycle.discover_bound_workers(SCOPE, SPEC.profile, binding,
            launch_key=SPEC.launch_key, execution_qualification=original),
    ):
        with pytest.raises(DestinationUnavailable):
            operation()
    assert runtime.launches == runtime.stops == 0
    runtime.execution_image.assert_not_called()


def test_parallel_ceiling_counts_unknown_reservations_and_refuses_without_runtime_effects(tmp_path):
    config, state, lifecycle, runtime, binding, original = opened(tmp_path)
    specs = [replace(SPEC, slot_id=f"slot-{i}", launch_key=f"launch-{i}") for i in range(8)]
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda spec: lifecycle.ensure_worker(spec, binding, original), specs))
    assert len([r for r in results if r["disposition"] is None]) == runtime.launches == 2
    assert {r["disposition"]["reason"] for r in results if r["disposition"]} == {"ceiling"}
    assert lifecycle.admission_status()["unreleased_workers"] == 2


def test_prior_admission_without_external_call_cannot_become_never_admitted(tmp_path):
    config, state, lifecycle, runtime, binding, original = opened(tmp_path)
    runtime.crash_before_launch = True
    with pytest.raises(SystemExit):
        lifecycle.ensure_worker(SPEC, binding, original)
    lifecycle.admission_status("close")
    lifecycle.admission_status("open")
    retained = lifecycle.discover_bound_workers(SCOPE, SPEC.profile, binding, launch_key=SPEC.launch_key, execution_qualification=original)[0]
    assert retained["disposition"] is None and retained["state"] == "unknown"
    assert not retained["termination_confirmed"] and not retained["artifacts_captured"]
    assert lifecycle.admission_status()["unreleased_workers"] == 1
    runtime.crash_before_launch = False
    recovered = lifecycle.ensure_worker(SPEC, binding, original)
    assert recovered["worker_id"] == retained["worker_id"] and recovered["disposition"] is None
    assert runtime.launches == 1


def test_original_execution_epoch_survives_close_reopen_but_ceiling_change_does_not_revoke(tmp_path):
    config, state, lifecycle, runtime, binding, original = opened(tmp_path)
    worker = lifecycle.ensure_worker(SPEC, binding, original)
    wid = worker["worker_id"]
    lifecycle.reserve_execution_intent(SCOPE, wid, "root-intent")
    lifecycle.admission_status("ceiling", 0)
    lifecycle.begin_execution(SCOPE, wid, "root", intent_key="root-intent")
    lifecycle.reserve_execution_intent(SCOPE, wid, "child-admitted")
    lifecycle.begin_execution(SCOPE, wid, "child", parent_id="root", intent_key="child-admitted")
    lifecycle.reserve_execution_intent(SCOPE, wid, "child-pending")
    lifecycle.admission_status("close")
    lifecycle.admission_status("open")
    assert lifecycle.execution_intent_allowed(SCOPE, wid, "child-admitted")
    assert not lifecycle.execution_intent_allowed(SCOPE, wid, "child-pending")
    with pytest.raises(LifecycleConflict):
        lifecycle.begin_execution(SCOPE, wid, "late-child", parent_id="root", intent_key="child-pending")
    assert lifecycle.observe_worker(SCOPE, wid)["active_executions"] == ["child", "root"]
    lifecycle.admission_status("close")
    lifecycle.record_execution_end(SCOPE, wid, "child", termination_confirmed=True, artifacts_captured=True)
    lifecycle.record_execution_end(SCOPE, wid, "root", termination_confirmed=True, artifacts_captured=True)
    assert lifecycle.stop_worker(SCOPE, wid, "original-stop")["termination_confirmed"]


def test_admission_close_during_runtime_preflight_fences_new_worker(tmp_path):
    config, state, lifecycle, runtime, binding, original = opened(tmp_path)
    entered, released = Event(), Event()
    def image(*_):
        entered.set()
        assert released.wait(5)
        return dict(IMAGE)
    runtime.execution_image.side_effect = image
    with ThreadPoolExecutor(max_workers=1) as pool:
        pending = pool.submit(lifecycle.ensure_worker, SPEC, binding, original)
        assert entered.wait(5)
        lifecycle.admission_status("close")
        released.set()
        receipt = pending.result()
    assert receipt["disposition"]["reason"] == "stale_admission_revision"
    assert runtime.launches == 0


@pytest.mark.asyncio
async def test_full_http_modes_preserve_exact_envelopes_and_original_controls(tmp_path):
    config, state, lifecycle, runtime, binding, original = full_destination(tmp_path)
    token = "fixture-scope-token-" * 3
    app = create_worker_app(lifecycle, {token: {SCOPE}})
    query = asdict(SCOPE) | binding | {"schema_version": "2"}
    body = asdict(SPEC) | {"schema_version": 2, "destination_binding": binding} | original
    async with httpx.AsyncClient(transport=httpx.ASGITransport(app), base_url="http://fixture",
                                  headers={"Authorization": "Bearer " + token}) as client:
        endpoint = await client.get("/api/v2/workers/execution-contract", params=query | {"profile": SPEC.profile, "contract_version": "1"})
        assert endpoint.status_code == 200, endpoint.text
        assert set(endpoint.json()) == {"schema_version", "contract_version", "deployment_id", "repository", "profile", "destination_binding", "manifest", "execution_manifest_sha256", "admission"}
        keyed = query | {"profile": SPEC.profile, "launch_key": SPEC.launch_key} | original
        empty = await client.get("/api/v2/workers", params=keyed)
        assert empty.json() == {"schema_version": 2, "destination_binding": binding, "workers": []} | original
        created = await client.post("/api/v2/workers/ensure", json=body)
        assert created.status_code == 200, created.text
        receipt = created.json()
        assert receipt["disposition"]["kind"] == "never_admitted"
        identity = await client.get("/api/v2/workers", params=query | {"profile": SPEC.profile})
        assert identity.status_code == 409
        mixed = await client.get("/api/v2/workers", params=query | {"profile": SPEC.profile, "contract_version": "1"})
        assert mixed.json() == {"schema_version": 2, "contract_version": 1, "destination_binding": binding, "workers": [receipt]}
        assert (await client.get("/api/v2/workers", params=keyed)).json()["workers"] == [receipt]
        control = asdict(SCOPE) | {"schema_version": 2, "destination_binding": binding, "request_key": "stop-key"}
        assert (await client.post("/api/v2/workers/" + receipt["worker_id"] + "/stop", json=control)).json() == receipt
        for changed in ({"contract_version": True}, {"admission_revision": True}, {"admission_revision": 0}):
            assert (await client.post("/api/v2/workers/ensure", json=body | changed)).status_code == 422
        for revision in ("00", "01", "+1", "1.0", "1" * 5000):
            assert (await client.get("/api/v2/workers", params=keyed | {"admission_revision": revision})).status_code == 422
        unauth = await client.get("/api/v2/workers/execution-contract", params=query | {"profile": SPEC.profile, "contract_version": "1"}, headers={"Authorization": "Bearer wrong"})
        assert unauth.status_code == 401


@pytest.mark.parametrize("close_after_admission", [False, True])
def test_actual_dispatcher_retains_original_root_epoch_across_closure(tmp_path, close_after_admission):
    from src.worker.managed_dispatch import ManagedDispatcher
    from tests.unit.test_managed_dispatch import Runtime, Authority
    runtime, authority = Runtime(), Authority()
    runtime.execution_image = Mock(return_value=dict(IMAGE))
    config, state, lifecycle, _, binding, original = full_destination(tmp_path, runtime=runtime)
    lifecycle.admission_status("open")
    original["admission_revision"] = 2
    worker = lifecycle.ensure_worker(SPEC, binding, original)
    profile = prepare_configuration(config).profiles[0]
    dispatcher = ManagedDispatcher(lifecycle, runtime, authority, [profile], state.root / "dispatcher",
                                   journal_binding=state.member("dispatcher"))
    if close_after_admission:
        begin = lifecycle.begin_execution
        def close_after(*args, **kwargs):
            begin(*args, **kwargs)
            lifecycle.admission_status("close")
        lifecycle.begin_execution = close_after
    else:
        call = authority.call
        def close_after_claim(operation, *args, **kwargs):
            result = call(operation, *args, **kwargs)
            if operation == "claim":
                lifecycle.admission_status("close")
                lifecycle.admission_status("open")
            return result
        authority.call = close_after_claim
    dispatcher.tick_worker(worker)
    assert len(authority.claims) == 1
    assert runtime.launches == int(close_after_admission)
    assert bool(runtime.cancelled) is not close_after_admission
    assert dispatcher.journal.get(worker["worker_id"])["phase"] == "completed"
    dispatcher.tick_worker(lifecycle.observe_worker(SCOPE, worker["worker_id"]))
    assert len(authority.claims) == 1


@pytest.mark.parametrize("close_after_admission", [False, True])
def test_actual_child_supervisor_keeps_stale_grant_charged_without_closing_root(tmp_path, close_after_admission):
    from src.worker.child_supervisor import ChildSupervisor
    from tests.unit.test_child_authority_contract import context
    from tests.unit.test_child_supervisor import FixtureAuthority, FixtureDriver, spawn
    config, state, lifecycle, runtime, binding, original = full_destination(tmp_path, optional=True)
    lifecycle.admission_status("open")
    original["admission_revision"] = 2
    worker = lifecycle.ensure_worker(SPEC, binding, original)
    root = replace(context(), spec=SPEC, worker_id=worker["worker_id"],
                   base=config["profiles"][0]["base_commit"], monotonic_deadline=time.monotonic() + 60,
                   boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip())
    lifecycle.reserve_execution_intent(SCOPE, root.worker_id, "root")
    lifecycle.begin_execution(SCOPE, root.worker_id, root.attempt_id, intent_key="root")
    policy = prepare_configuration(config).child_policies[(SCOPE.deployment_id, SCOPE.repository, SPEC.profile)]
    supervisor = ChildSupervisor(state.root / "children", {(SCOPE.deployment_id, SCOPE.repository, SPEC.profile): policy},
                                 None, lifecycle, runtime, None, lambda _: 50, lambda _: True,
                                 journal_binding=state.member("children"))
    supervisor.authority = FixtureAuthority(root)
    supervisor.driver = FixtureDriver(supervisor)
    supervisor.endpoints = SimpleNamespace(prepare_child=lambda *_: None, revoke=lambda *_: None, close=lambda callback: callback())
    supervisor.journal.prepare(root.worker_id, SPEC, policy)
    supervisor.journal.bind(root)
    try:
        if close_after_admission:
            begin = lifecycle.begin_execution
            def close_after(*args, **kwargs):
                begin(*args, **kwargs)
                lifecycle.admission_status("close")
            lifecycle.begin_execution = close_after
        else:
            call = supervisor.authority.call
            def close_after_grant(operation, *args, **kwargs):
                result = call(operation, *args, **kwargs)
                if operation == "grant":
                    lifecycle.admission_status("close")
                    lifecycle.admission_status("open")
                return result
            supervisor.authority.call = close_after_grant
        result = spawn(supervisor, root)
        assert len(supervisor.authority.grants) == 1
        assert len(supervisor.driver.launches) == int(close_after_admission)
        assert supervisor.authority.closed is False
        assert supervisor.journal.worker(root.worker_id)["closed"] == 0
        child = supervisor.journal.child(root.worker_id, result["child_id"])
        assert child["phase"] == ("running" if close_after_admission else "granted")
        if not close_after_admission:
            repeated = spawn(supervisor, root)
            assert repeated["child_id"] == result["child_id"]
            assert len(supervisor.authority.grants) == 1 and supervisor.driver.launches == []
    finally:
        supervisor.close()


def test_host_cli_initialization_and_administration_need_no_worker_credential_file(tmp_path):
    config = full_configuration(tmp_path)
    path = tmp_path / "host-config.json"
    path.write_text(json.dumps(config))
    command = [sys.executable, "-B", "-m", "src.worker.managed_service", "--config", str(path)]
    def run(*args):
        return subprocess.run(command + list(args), capture_output=True, timeout=20)
    first = run("--initialize-destination")
    assert first.returncode == 0, first.stderr
    assert json.loads(first.stdout)["journals_initialized"] is False
    assert not Path(config["credentials_file"]).exists()
    inspected = run("--inspect-admission")
    assert inspected.returncode == 0, inspected.stderr
    assert json.loads(inspected.stdout)["new_effects_open"] is False
    opened_result = run("--open-admission")
    assert json.loads(opened_result.stdout)["revision"] == 2
    assert json.loads(run("--set-worker-ceiling", "0").stdout)["worker_ceiling"] == 0
    assert run("--open-admission", "--profile", SPEC.profile).returncode == 2
    assert run("--preview-execution-contract", "--deployment-id", SCOPE.deployment_id).returncode == 2
    assert run("--set-worker-ceiling", "-1").returncode == 2
    assert run("--open-admission", "--close-admission").returncode == 2
