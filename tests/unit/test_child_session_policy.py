"""Managed configuration boundary for the opt-in cold-session policy.

Invalid policy is refused by the actual loader before credentials or any model
journal. Valid policy still reaches a real model journal/ownership lock and an
explicit runtime stop fixture, not Docker or canonical/provider readiness.
"""

from copy import deepcopy
from dataclasses import asdict
import json
from types import SimpleNamespace

import pytest

import src.worker.docker_runtime as runtime_module
import src.worker.managed_service as service_module
import src.worker.model_broker as broker_module
from src.worker.model_broker import ModelBroker
from src.worker.managed_configuration import ConfigurationInvalid, parse_configuration_bytes
from tests.unit.test_managed_model_integration import service_config, SCOPE_KEY


class RuntimeBoundaryReached(Exception):
    pass


@pytest.fixture
def construction_boundary(monkeypatch):
    brokers = []
    runtime_policies = []

    class ParsingBroker(ModelBroker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            brokers.append(self)

        def check_ready(self):
            pass  # Transport qualification belongs to the real socket tests.

    def stop_before_runtime(*_args, **kwargs):
        runtime_policies.append(kwargs["child_policies"])
        raise RuntimeBoundaryReached()

    monkeypatch.setattr(broker_module, "ModelBroker", ParsingBroker)
    monkeypatch.setattr(
        runtime_module, "ManagedDockerRuntime", stop_before_runtime
    )
    try:
        yield SimpleNamespace(
            brokers=brokers, runtime_policies=runtime_policies
        )
    finally:
        for broker in brokers:
            broker.close()


def configuration(tmp_path):
    config, credentials = service_config(tmp_path)
    credential_path = tmp_path / "worker-credentials.json"
    credential_path.write_text(
        json.dumps({
            token: [asdict(scope) for scope in scopes]
            for token, scopes in credentials.items()
        }),
        encoding="utf-8",
    )
    credential_path.chmod(0o600)
    config["credentials_file"] = str(credential_path)
    config["children"] = [{
        "deployment_id": SCOPE_KEY[0],
        "repository": SCOPE_KEY[1],
        "profile": SCOPE_KEY[2],
        "policy": {
            "max_children": 2,
            "max_child_seconds": 20,
            "max_child_turns": 3,
            "capabilities": ["python"],
            "outcome_protocol": "initial-v1",
            "session_protocol": "cold-clarification-v1",
        },
    }]
    return config


def load_file(tmp_path, config, *, invalid=None):
    path = tmp_path / "openjules.json"
    path.write_text(json.dumps(config, indent=2), encoding="utf-8")
    original_bytes = path.read_bytes()
    if invalid is None:
        loaded, credentials = service_module.load_configuration(path)
    else:
        with pytest.raises(ConfigurationInvalid, match="^" + invalid + "$"):
            service_module.load_configuration(path)
        # Also exercise a direct builder call; no credential lookup is needed
        # because the same complete pure phase must refuse before effects.
        loaded, credentials = parse_configuration_bytes(original_bytes), {}
    assert path.read_bytes() == original_bytes
    return path, original_bytes, loaded, credentials


def assert_brokers_released(boundary):
    assert all(broker.closed for broker in boundary.brokers)
    assert all(broker._service_lock.closed for broker in boundary.brokers)


@pytest.mark.parametrize(
    "protocol",
    [
        None, True, False, 0, 1, "", "initial-v1", "cold-clarification-v2",
        [], {}, ["cold-clarification-v1"],
    ],
)
def test_explicit_invalid_protocol_refuses_before_credentials_or_model_state(
    tmp_path, construction_boundary, protocol
):
    config = configuration(tmp_path)
    config["children"][0]["policy"]["session_protocol"] = protocol
    path, original_bytes, loaded, credentials = load_file(tmp_path, config, invalid="child_session_unsupported")
    original_loaded = deepcopy(loaded)
    with pytest.raises(ValueError, match="child_session_unsupported"):
        service_module.build_app(loaded, credentials)
    assert loaded == original_loaded
    assert path.read_bytes() == original_bytes
    assert construction_boundary.runtime_policies == []
    assert construction_boundary.brokers == []
    assert_brokers_released(construction_boundary)

    # A corrected configuration can acquire its first real model journal/lock.
    config["children"][0]["policy"]["session_protocol"] = "cold-clarification-v1"
    _, _, corrected, credentials = load_file(tmp_path, config)
    with pytest.raises(RuntimeBoundaryReached):
        service_module.build_app(corrected, credentials)
    assert len(construction_boundary.brokers) == 1
    assert len(construction_boundary.runtime_policies) == 1
    assert_brokers_released(construction_boundary)


@pytest.mark.parametrize("mode", ["ordinary", "initial", "cold"])
def test_config_preserves_omission_and_passes_only_approved_policy(
    tmp_path, construction_boundary, mode
):
    config = configuration(tmp_path)
    child_policy = config["children"][0]["policy"]
    if mode != "cold":
        child_policy.pop("session_protocol")
    if mode == "ordinary":
        child_policy.pop("outcome_protocol")
    path, original_bytes, loaded, credentials = load_file(tmp_path, config)
    original_loaded = deepcopy(loaded)
    with pytest.raises(RuntimeBoundaryReached):
        service_module.build_app(loaded, credentials)
    assert loaded == original_loaded
    assert path.read_bytes() == original_bytes
    assert ("session_protocol" in loaded["children"][0]["policy"]) is (
        mode == "cold"
    )
    assert len(construction_boundary.runtime_policies) == 1
    approved = construction_boundary.runtime_policies[0]
    assert set(approved) == {SCOPE_KEY}
    policy = approved[SCOPE_KEY]
    assert policy.session_protocol == (
        "cold-clarification-v1" if mode == "cold" else None
    )
    assert policy.outcome_protocol == (
        None if mode == "ordinary" else "initial-v1"
    )
    assert policy.command == (
        "python3", "-I", "-S", "/opt/openjules/managed_runner.py"
    )
    assert policy.canonical_policy == {
        "max_children": 2,
        "max_child_seconds": 20,
        "max_child_turns": 3,
        "child_capabilities": ["python"],
    }
    assert len(construction_boundary.brokers) == 1
    assert_brokers_released(construction_boundary)


@pytest.mark.parametrize(
    ("missing", "message"),
    [
        ("outcome", "policy_invalid"),
        ("lifetime_slot", "policy_invalid"),
        ("trusted_command", "policy_invalid"),
        ("model", "child_model_required"),
    ],
)
def test_session_requires_the_existing_approvals_at_service_construction(
    tmp_path, construction_boundary, missing, message
):
    config = configuration(tmp_path)
    policy = config["children"][0]["policy"]
    if missing == "outcome":
        policy.pop("outcome_protocol")
    elif missing == "lifetime_slot":
        policy["max_children"] = 1
    elif missing == "trusted_command":
        policy["command"] = ["sh", "-c", "true"]
    else:
        config["models"] = []
    path, original_bytes, loaded, credentials = load_file(tmp_path, config, invalid=message)
    with pytest.raises(ValueError, match=message):
        service_module.build_app(loaded, credentials)
    assert path.read_bytes() == original_bytes
    assert construction_boundary.runtime_policies == []
    assert construction_boundary.brokers == []
    assert_brokers_released(construction_boundary)
