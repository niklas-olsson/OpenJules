"""Explicit synthetic review policy values. No deployment defaults."""

import hashlib

from src.api.ingress_policy import load_policy
from src.api.ingress_adapter import ReviewCredentialSnapshot
from src.api.review_ingress import webhook_review
from src.storage.ingress_receipts import enroll_policy
from src.worker.review_contract import RESULT_SCHEMA
from src.worker.review_result import COUNTERS, FACT_FIELDS
from tests.unit.ingress_core_support import host_fixture, write_private


def profile(root):
    return {
        "schema": "standalone-review-source-cas-v1",
        "source": {"repository_path": str(root / "source"), "state_root": str(root / "state")},
        "guest": {"docker_endpoint": "unix:///run/docker.sock", "docker_api_version": "1.45",
            "image": "sha256:" + "1" * 64, "uid": 1000, "gid": 1000,
            "test_command": "python -m unittest", "memory_bytes": 104857600,
            "cpu_quota_us": 50000, "pids_limit": 32},
        "model": {"url": "http://127.0.0.1:9000/v1/chat/completions", "model": "fixture-only",
            "temperature": 0.0, "credential_ref": None},
        "forge_auth": {"kind": "pat", "token_ref": "env:REVIEW_FIXTURE_TOKEN", "username": "fixture"},
        "commit_author": {"name": "Review fixture", "email": "fixture@example.invalid"},
        "limits": {"total_ms": 10000, "cleanup_reserve_ms": 1000, "model_call_ms": 1000,
            "exec_call_ms": 1000, "guest_api_ms": 1000, "git_call_ms": 1000, "forge_call_ms": 1000,
            "agent_turns": 4, "model_calls": 6, "model_request_bytes": 10000,
            "model_request_total_bytes": 60000, "model_response_bytes": 10000,
            "model_response_total_bytes": 60000, "model_output_tokens_per_call": 128,
            "model_output_tokens_total": 768, "exec_calls": 10, "exec_input_bytes": 10000,
            "exec_output_bytes": 10000, "exec_output_total_bytes": 100000,
            "guest_api_calls": 40, "guest_api_cleanup_calls": 6, "source_bytes": 100000,
            "source_objects": 100, "context_bytes": 10000, "archive_bytes": 100000,
            "patch_bytes": 10000, "log_bytes": 10000, "files": 100, "path_bytes": 512,
            "blob_bytes": 10000, "patch_records": 100, "object_bytes": 100000,
            "object_count": 100, "git_calls": 40, "git_output_bytes": 10000,
            "git_output_total_bytes": 400000, "forge_response_bytes": 10000,
            "forge_response_total_bytes": 50000, "receipt_result_bytes": 500000},
    }


def declaration(policy, **changes):
    binding = policy.bindings["repo"]
    value = {"schema_version": 1, "declaration_id": "review-activation-1",
        "journal_id": policy.journal_id, "repository_key": binding.canonical_repository,
        "operation": "review.start", "policy_id": policy.policy_id, "policy_digest": policy.digest,
        "profile_digest": binding.review_profile.digest, "operator": "fixture-maintainer",
        "assertion": "fresh_review_scope", "evidence": {
            "summary": "Isolated fixture scope and storage; capture bounds are not a live disk quota.",
            "records": []}}
    value.update(changes)
    return value


def host(root, *, enrolled=True, task=False, mutate=None):
    def change(document):
        document["bindings"][0]["standalone_review"] = profile(root)
        document["principals"][0]["grants"][0]["operations"] = ["receipt.read"] + (["task.start"] if task else [])
        document["principals"][1]["grants"][0]["operations"] = ["review.start"] + (["task.start"] if task else [])
        if mutate:
            mutate(document)
    policy, path, environment, document, activation = host_fixture(root, enrolled=False, mutate=change)
    environment["REVIEW_FIXTURE_TOKEN"] = "synthetic-review-token-for-tests"
    policy = load_policy(path, environment)
    review_activation = write_private(root / "review-activation.json", declaration(policy))
    if enrolled:
        enroll_policy(policy, activation if task else None, review_activation_paths=[review_activation])
    credentials = {"repo": ReviewCredentialSnapshot(policy.bindings["repo"], policy)}
    return policy, path, environment, document, activation, review_activation, credentials


def event():
    repository = {"id": 123, "full_name": "fixture/repo"}
    return {"action": "submitted", "repository": dict(repository), "sender": {"id": 456},
        "pull_request": {"number": 7, "state": "open", "merged": False, "body": "Original PR",
            "base": {"repo": dict(repository)},
            "head": {"repo": dict(repository), "ref": "topic", "sha": "2" * 40}},
        "review": {"id": 8001, "user": {"id": 456}, "state": "changes_requested",
            "commit_id": "2" * 40, "body": "/jules review Fix the original fixture."}}


def normalized(policy, value=None):
    binding, review, actor = webhook_review(policy, policy.principals["webhook"],
        event() if value is None else value, "pull_request_review")
    return binding, review, actor


def result(claim, *, status="running", failure=None):
    original, review, limits = claim.original, claim.original["review"], claim.profile.limits
    return {"schema": RESULT_SCHEMA, "operation_id": claim.operation_id, "owner_epoch": claim.owner_epoch,
        "profile_digest": claim.profile.digest, "activation_digest": claim.activation_digest,
        "request_digest": original["request_digest"],
        "identity": {"repository_id": original["binding"]["repository_id"], "pull_number": review["pull_number"],
            "review_id": review["review_id"], "head_ref": review["head_ref"], "head_sha": review["head_sha"]},
        "status": status, "first_failure": failure,
        "timing": {"started_ms": int(claim.started_at * 1000),
            "work_deadline_ms": int((claim.started_at + (limits["total_ms"] - limits["cleanup_reserve_ms"]) / 1000) * 1000),
            "total_deadline_ms": int((claim.started_at + limits["total_ms"] / 1000) * 1000)},
        "counters": dict.fromkeys(COUNTERS, 0), "effects": [], "facts": {key: {} for key in FACT_FIELDS}}


def claim_review(store, policy):
    binding, review, actor = normalized(policy)
    receipt = store.reserve_review("webhook", binding.binding_id, review, actor)
    ticket = store.fence(receipt["operation_id"], "webhook")
    invocation = store.begin_callback(ticket)
    original = store.claim_callback(invocation)
    return receipt, invocation, store.review_claim(invocation, original)
