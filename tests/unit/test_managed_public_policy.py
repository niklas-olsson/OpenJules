"""Actual public configuration parsing and original service construction bounds.

The loader, descriptors, model journal and ownership lock are real. The existing
explicit runtime constructor stop fixture prevents Docker/authority/provider work.
"""

from copy import deepcopy
import json

import pytest

from src.worker import managed_service as service
from tests.unit.test_child_session_policy import (
    RuntimeBoundaryReached, assert_brokers_released, configuration,
    construction_boundary, load_file,
)
from tests.unit.test_managed_model_integration import SCOPE_KEY
from tests.unit.test_managed_public_types import public_document, root_command


def public_config(tmp_path):
    value = configuration(tmp_path)
    policy = value["children"][0]["policy"]
    policy.pop("session_protocol")
    policy["public_discussion"] = public_document(tmp_path)
    value["profiles"][0]["command"] = root_command()
    return value


def test_explicit_public_configuration_passes_exact_policy_and_unchanged_canonical_projection(
    tmp_path, construction_boundary,
):
    config = public_config(tmp_path)
    path, raw, loaded, credentials = load_file(tmp_path, config)
    original = deepcopy(loaded)
    with pytest.raises(RuntimeBoundaryReached):
        service.build_app(loaded, credentials)
    assert loaded == original and path.read_bytes() == raw
    assert len(construction_boundary.runtime_policies) == 1
    approved = construction_boundary.runtime_policies[0][SCOPE_KEY]
    assert approved.public_discussion == config["children"][0]["policy"]["public_discussion"]
    assert approved.session_protocol is None and approved.outcome_protocol == "initial-v1"
    assert approved.canonical_policy == {
        "max_children": 2, "max_child_seconds": 20, "max_child_turns": 3,
        "child_capabilities": ["python"],
    }
    loaded["children"][0]["policy"]["public_discussion"]["instructions"].clear()
    assert approved.public_discussion == config["children"][0]["policy"]["public_discussion"]
    assert len(construction_boundary.brokers) == 1
    assert_brokers_released(construction_boundary)


@pytest.mark.parametrize("value", [None, False, 0, "", [], ["managed-public-pull-v1"]])
def test_present_nonobject_public_approval_is_refused_and_corrected_same_state_can_open(
    tmp_path, construction_boundary, value,
):
    config = public_config(tmp_path)
    original_block = deepcopy(config["children"][0]["policy"]["public_discussion"])
    config["children"][0]["policy"]["public_discussion"] = value
    path, raw, loaded, credentials = load_file(tmp_path, config)
    with pytest.raises(ValueError, match="unsupported explicit public discussion policy"):
        service.build_app(loaded, credentials)
    assert construction_boundary.runtime_policies == [] and path.read_bytes() == raw
    assert len(construction_boundary.brokers) == 1
    assert_brokers_released(construction_boundary)
    config["children"][0]["policy"]["public_discussion"] = original_block
    _, _, corrected, credentials = load_file(tmp_path, config)
    with pytest.raises(RuntimeBoundaryReached):
        service.build_app(corrected, credentials)
    assert len(construction_boundary.runtime_policies) == 1
    assert len(construction_boundary.brokers) == 2
    assert_brokers_released(construction_boundary)


@pytest.mark.parametrize(("missing", "message"), [
    ("initial", "requires initial-v1"),
    ("two_slots", "requires initial-v1"),
    ("child_runner", "requires the approved managed runner"),
    ("root_runner", "requires the approved root runner"),
    ("model", "children require a unique approved model-backed profile"),
    ("cold", "requires initial-v1"),
    ("scope_bytes", "host bindings are unavailable"),
])
def test_public_opt_in_requires_existing_approval_and_fixed_runtime_bindings(
    tmp_path, construction_boundary, missing, message,
):
    config = public_config(tmp_path)
    policy = config["children"][0]["policy"]
    if missing == "initial":
        policy.pop("outcome_protocol")
    elif missing == "two_slots":
        policy["max_children"] = 1
    elif missing == "child_runner":
        policy["command"] = ["sh", "-c", "true"]
    elif missing == "root_runner":
        config["profiles"][0]["command"] = ["python3", "-I", "-c", "pass"]
    elif missing == "model":
        config["models"] = []
    elif missing == "cold":
        policy["session_protocol"] = "cold-clarification-v1"
    else:
        policy["public_discussion"]["server"]["scope_key_sha256"] = "0" * 64
    path, raw, loaded, credentials = load_file(tmp_path, config)
    with pytest.raises(ValueError, match=message):
        service.build_app(loaded, credentials)
    assert construction_boundary.runtime_policies == []
    assert path.read_bytes() == raw and loaded == config
    assert len(construction_boundary.brokers) == (0 if missing == "model" else 1)
    assert_brokers_released(construction_boundary)


@pytest.mark.parametrize("duplicate", ["approval", "top_level"])
def test_raw_ambiguous_public_configuration_is_rejected_before_construction(
    tmp_path, construction_boundary, duplicate,
):
    config = public_config(tmp_path)
    path = tmp_path / "ambiguous.json"
    raw = json.dumps(config, separators=(",", ":"))
    if duplicate == "approval":
        marker = '"public_approved":true'
        assert raw.count(marker) == 1
        raw = raw.replace(marker, '"public_approved":false,"public_approved":true')
    else:
        assert raw.startswith("{")
        raw = '{"schema_version":2,' + raw[1:]
    path.write_text(raw, encoding="utf-8")
    with pytest.raises(ValueError, match="duplicate JSON fields"):
        service.load_configuration(path)
    assert path.read_text() == raw
    assert construction_boundary.runtime_policies == [] and construction_boundary.brokers == []
    # Exact corrected bytes retain the existing state and construction path.
    _, _, loaded, credentials = load_file(tmp_path, config)
    with pytest.raises(RuntimeBoundaryReached):
        service.build_app(loaded, credentials)
    assert len(construction_boundary.runtime_policies) == 1
    assert_brokers_released(construction_boundary)


@pytest.mark.parametrize("mode", ["ordinary", "initial", "cold"])
def test_omitted_public_block_keeps_existing_loader_and_profile_semantics(
    tmp_path, construction_boundary, mode,
):
    config = configuration(tmp_path)
    policy = config["children"][0]["policy"]
    if mode != "cold":
        policy.pop("session_protocol")
    if mode == "ordinary":
        policy.pop("outcome_protocol")
    assert "public_discussion" not in policy
    # The opt-in-only ambiguity rejection does not change the old loader.
    path = tmp_path / "ordinary.json"
    raw = '{"schema_version":2,' + json.dumps(config, separators=(",", ":"))[1:]
    path.write_text(raw, encoding="utf-8")
    loaded, credentials = service.load_configuration(path)
    assert loaded["schema_version"] == 1 and "public_discussion" not in loaded["children"][0]["policy"]
    with pytest.raises(RuntimeBoundaryReached):
        service.build_app(loaded, credentials)
    approved = construction_boundary.runtime_policies[0][SCOPE_KEY]
    assert approved.public_discussion is None
    assert approved.outcome_protocol == (None if mode == "ordinary" else "initial-v1")
    assert approved.session_protocol == ("cold-clarification-v1" if mode == "cold" else None)
    assert_brokers_released(construction_boundary)
