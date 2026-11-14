"""Private synthetic host fixtures; no live providers or credentials."""

import json
import os

from src.api.ingress_policy import load_policy
from src.storage.ingress_receipts import enroll_policy, initialize_store


def write_private(path, value):
    path.write_text(json.dumps(value), encoding="utf-8")
    path.chmod(0o600)
    return path


def policy_document(store, journal_id):
    return {
        "schema_version": 1, "policy_id": "policy-1", "mode": "local_only",
        "transport": {"external_origin": "http://127.0.0.1:8000"},
        "receipt_store": {"path": str(store), "journal_id": journal_id},
        "bindings": [{
            "binding_id": "repo", "forge": "github", "repository": "fixture/repo",
            "repository_id": 123, "installation_id": None,
            "clone_url": "https://github.com/fixture/repo.git", "default_branch": "main",
            "cohort_profiles": {},
        }],
        "principals": [
            {"principal_id": "operator", "authentication": {"kind": "bearer", "secret_ref": "env:OPENJULES_INGRESS_BEARER_OPERATOR"},
             "grants": [{"binding_id": "repo", "operations": ["task.start", "receipt.read"]}]},
            {"principal_id": "webhook", "authentication": {"kind": "github_hmac_sha256", "secret_ref": "env:OPENJULES_INGRESS_HMAC_WEBHOOK"},
             "github_actor_ids": [456, 789], "grants": [{"binding_id": "repo", "operations": ["task.start"]}]},
        ],
    }


def activation_document(policy, **changes):
    result = {
        "schema_version": 1, "declaration_id": "activation-1",
        "journal_id": policy.journal_id, "policy_id": policy.policy_id,
        "policy_digest": policy.digest,
        "repositories": sorted({binding.canonical_repository for binding in policy.bindings.values()}),
        "operator": "fixture-maintainer", "assertion": "fresh_isolated_scope",
    }
    result.update(changes)
    return result


def host_fixture(tmp_path, *, enrolled=True, mutate=None):
    os.chmod(tmp_path, 0o700)
    store = tmp_path / "receipts.sqlite"
    journal = initialize_store(store)
    doc = policy_document(store, journal["journal_id"])
    if mutate:
        mutate(doc)
    path = write_private(tmp_path / "policy.json", doc)
    environment = {"OPENJULES_INGRESS_BEARER_OPERATOR": "test-operator-value", "OPENJULES_INGRESS_HMAC_WEBHOOK": "test-hmac-value"}
    policy = load_policy(path, environment)
    activation = write_private(tmp_path / "activation.json", activation_document(policy))
    if enrolled:
        enroll_policy(policy, activation)
    return policy, path, environment, doc, activation


TASK = {"issue_id": 7, "issue_title": "Synthetic task", "issue_body": "Private synthetic input"}


def reserve(store, key="key-1", **changes):
    args = {"principal_id": "operator", "binding_id": "repo", "source_kind": "operator_task",
            "source_id": None, "request_key": key, "task": dict(TASK)}
    args.update(changes)
    return store.reserve(**args)
