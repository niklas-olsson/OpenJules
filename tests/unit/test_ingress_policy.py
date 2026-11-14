import copy
import json
import os
import subprocess
import sys

import pytest

from src.api.ingress_policy import IngressError, bounded_task, load_policy, strict_json
from tests.unit.ingress_core_support import TASK, host_fixture, write_private


def test_policy_freezes_secrets_and_grants_without_exposing_values(tmp_path):
    policy, _, environment, _, _ = host_fixture(tmp_path)
    assert policy.authenticate_bearer(environment["OPENJULES_INGRESS_BEARER_OPERATOR"]).principal_id == "operator"
    assert policy.github_auth()[0].actor_ids == frozenset({456, 789})
    assert policy.require_grant("operator", "repo", "task.start").repository_id == 123
    assert environment["OPENJULES_INGRESS_BEARER_OPERATOR"] not in repr(policy)
    assert environment["OPENJULES_INGRESS_HMAC_WEBHOOK"] not in repr(policy.principals)
    with pytest.raises(TypeError):
        policy.bindings["replacement"] = policy.bindings["repo"]
    environment["OPENJULES_INGRESS_BEARER_OPERATOR"] = "rotated-value"
    with pytest.raises(IngressError, match="credentials_changed"):
        policy.authenticate_bearer(environment["OPENJULES_INGRESS_BEARER_OPERATOR"])


@pytest.mark.parametrize("raw", [b'{"a":1,"a":2}', b'{"nested":{"x":1,"x":2}}', b'{"x":NaN}', b'\xff', b'[' * 2000])
def test_strict_json_refuses_duplicate_invalid_and_excessive_structure(raw):
    with pytest.raises(IngressError):
        strict_json(raw)


def test_body_limit_and_exact_task_types():
    with pytest.raises(IngressError) as failure:
        strict_json(b" " * 11, 10)
    assert failure.value.status == 413
    for change in ({"issue_id": True}, {"issue_id": "7"}, {"issue_title": "x" * 1025}, {"issue_body": "x" * 262145}, {"installation_id": 99}):
        with pytest.raises(IngressError):
            bounded_task({**TASK, **change})


@pytest.mark.parametrize("mutate", [
    lambda doc: doc.update(schema_version=True),
    lambda doc: doc.update(unrecognized="not admitted"),
    lambda doc: doc["bindings"][0].update(repository_id=True),
    lambda doc: doc["bindings"][0].update(installation_id="1"),
    lambda doc: doc["bindings"][0].update(clone_url="https://token@github.com/fixture/repo.git"),
    lambda doc: doc["bindings"][0].update(forge="radicle"),
    lambda doc: doc["bindings"][0].update(cohort_profiles={"profile": {}}),
    lambda doc: doc["principals"][0]["grants"][0].update(operations=["review.start"]),
    lambda doc: doc["principals"][1].update(github_actor_ids=[True]),
    lambda doc: doc["principals"][0]["authentication"].update(secret_ref="literal:secret"),
])
def test_policy_rejects_ambiguous_or_unqualified_definition(tmp_path, mutate):
    with pytest.raises(IngressError):
        host_fixture(tmp_path, mutate=mutate)


def test_duplicate_bearer_values_refuse_principal_ambiguity(tmp_path):
    _, path, environment, doc, _ = host_fixture(tmp_path)
    other = copy.deepcopy(doc["principals"][0])
    other["principal_id"] = "other"
    other["authentication"]["secret_ref"] = "env:OPENJULES_INGRESS_BEARER_OTHER"
    doc["principals"].append(other)
    write_private(path, doc)
    environment["OPENJULES_INGRESS_BEARER_OTHER"] = environment["OPENJULES_INGRESS_BEARER_OPERATOR"]
    with pytest.raises(IngressError, match="ambiguous_authentication"):
        load_policy(path, environment)


def test_cross_kind_secret_reuse_cannot_widen_principal_authority(tmp_path):
    _, path, environment, _, _ = host_fixture(tmp_path)
    environment["OPENJULES_INGRESS_HMAC_WEBHOOK"] = environment["OPENJULES_INGRESS_BEARER_OPERATOR"]
    with pytest.raises(IngressError, match="ambiguous_authentication"):
        load_policy(path, environment)


@pytest.mark.parametrize("name,value", [
    ("GITHUB_TOKEN", "test-operator-value"),
    ("OPENAI_API_KEY", "test-hmac-value"),
    ("LLM_API_KEY", "test-operator-value"),
    ("OPENJULES_INGRESS_HMAC_WEBHOOK", "different-current-value"),
])
def test_ingress_values_cannot_alias_execution_values_or_references(tmp_path, name, value):
    policy, *_ = host_fixture(tmp_path)
    with pytest.raises(IngressError) as failure:
        policy.assert_execution_separation({name: value})
    assert failure.value.code == "ingress_execution_secret_alias"
    assert name not in str(failure.value)
    assert value not in str(failure.value)
    policy.assert_execution_separation({"GITHUB_TOKEN": "separate-selected-token", "OPENAI_API_KEY": None})


@pytest.mark.parametrize("reference", [
    "env:GITHUB_TOKEN", "env:OPENAI_API_KEY", "env:OPENJULES_INGRESS_HMAC_OPERATOR",
    "env:OPENJULES_INGRESS_BEARER_", "env:OPENJULES_INGRESS_BEARER_" + "a" * 65,
])
def test_only_the_kind_specific_ingress_secret_namespace_is_qualified(tmp_path, reference):
    with pytest.raises(IngressError, match="invalid_secret_reference"):
        host_fixture(tmp_path, mutate=lambda doc: doc["principals"][0]["authentication"].update(secret_ref=reference))


def test_any_ambient_equal_value_alias_is_rejected_and_irreversibly_revokes_epoch(tmp_path):
    policy, path, environment, _, _ = host_fixture(tmp_path)
    environment["PROVIDER_SPECIFIC_API_KEY"] = environment["OPENJULES_INGRESS_HMAC_WEBHOOK"]
    with pytest.raises(IngressError, match="ingress_execution_secret_alias"):
        load_policy(path, environment)
    with pytest.raises(IngressError, match="ingress_execution_secret_alias"):
        policy.ensure_current()
    del environment["PROVIDER_SPECIFIC_API_KEY"]
    with pytest.raises(IngressError, match="policy_epoch_revoked"):
        policy.ensure_current()
    load_policy(path, environment).ensure_current()


def test_malformed_live_policy_is_host_unavailability_and_latches(tmp_path):
    policy, path, _, document, _ = host_fixture(tmp_path)
    path.write_bytes(b'{"schema_version":1,"schema_version":1}')
    with pytest.raises(IngressError) as failure:
        policy.ensure_current()
    assert (failure.value.code, failure.value.status) == ("policy_unavailable", 503)
    write_private(path, document)
    with pytest.raises(IngressError, match="policy_epoch_revoked"):
        policy.ensure_current()


@pytest.mark.parametrize("grants", [[], [{"binding_id": "repo", "operations": []}]])
def test_empty_grants_authenticate_without_authorizing_any_action(tmp_path, grants):
    def mutate(document):
        document["principals"][0]["grants"] = grants
    policy, _, environment, _, _ = host_fixture(tmp_path, mutate=mutate)
    principal = policy.authenticate_bearer(environment["OPENJULES_INGRESS_BEARER_OPERATOR"])
    for operation in ("task.start", "receipt.read"):
        with pytest.raises(IngressError, match="scope_denied"):
            policy.require_grant(principal.principal_id, "repo", operation)


@pytest.mark.parametrize("branch", ["@", "HEAD", "part/.hidden", "part.lock/child", "main\x7f", "-main", "a..b"])
def test_invalid_git_branch_components_are_rejected_without_git_calls(tmp_path, branch):
    with pytest.raises(IngressError, match="invalid_branch"):
        host_fixture(tmp_path, mutate=lambda doc: doc["bindings"][0].update(default_branch=branch))


@pytest.mark.parametrize("mode,origin,accepted", [
    ("local_only", "http://127.0.0.1:8000", True),
    ("local_only", "http://[::1]:8000/", True),
    ("local_only", "http://localhost:8000", False),
    ("local_only", "http://127.0.0.1", False),
    ("local_only", "http://0.0.0.0:8000", False),
    ("remote", "https://example.invalid:443", True),
    ("remote", "http://example.invalid", False),
    ("remote", "https://user@example.invalid", False),
    ("remote", "https://example.invalid/path", False),
    ("remote", "https://example.invalid?redirect=true", False),
])
def test_origin_is_exact_and_explicit(tmp_path, mode, origin, accepted):
    def mutate(doc):
        doc["mode"] = mode
        doc["transport"]["external_origin"] = origin
    if accepted:
        policy, *_ = host_fixture(tmp_path, mutate=mutate)
        assert policy.origin == origin.rstrip("/")
        assert policy.authority == policy.origin.split("://", 1)[1]
    else:
        with pytest.raises(IngressError):
            host_fixture(tmp_path, mutate=mutate)


def test_private_policy_and_original_selected_definition(tmp_path):
    policy, path, environment, doc, _ = host_fixture(tmp_path)
    path.chmod(0o644)
    with pytest.raises(IngressError, match="private_file_unavailable"):
        load_policy(path, environment)
    path.chmod(0o600)
    doc["policy_id"] = "changed-policy"
    write_private(path, doc)
    with pytest.raises(IngressError, match="policy_changed"):
        policy.ensure_current()
    link = tmp_path / "policy-link.json"
    link.symlink_to(path)
    with pytest.raises(IngressError, match="private_file_unavailable"):
        load_policy(link, environment)


def test_managed_guard_precedes_policy_and_initialization_files(tmp_path):
    target = tmp_path / "not-created" / "receipt.sqlite"
    script = """
import sys
from src.worker.execution_context import select_managed_context, LegacyExecutionRefused
from src.storage.ingress_receipts import initialize_store
from src.api.ingress_policy import load_policy
select_managed_context()
for call in (lambda: initialize_store(sys.argv[1]), lambda: load_policy(sys.argv[1])):
    try: call()
    except LegacyExecutionRefused: pass
    else: raise AssertionError('managed guard missing')
"""
    result = subprocess.run([sys.executable, "-c", script, str(target)], capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    assert not target.parent.exists()
