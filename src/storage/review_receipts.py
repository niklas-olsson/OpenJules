"""Review extensions within the original standalone journal and callback owner.

There is no second connection, queue, task ledger, recovery owner or reset API.
Schema extension occurs only in explicit stopped-owner policy enrollment.
"""

from __future__ import annotations

import hashlib
import json
import math
import os
import secrets
import time

from src.api.ingress_policy import (
    IngressError, POLICY_LIMIT, canonical_json, digest_json, exact_object,
    identifier, positive_integer, read_private_json, strict_json,
)
from src.api.review_ingress import bounded_review
from src.api.review_policy import freeze, scan_review_secrets, text, thaw
from src.worker.review_contract import RESULT_SCHEMA, ReviewClaim, ReviewError

_EVENT_FIELDS = frozenset({
    "principal_id", "binding_id", "binding", "operation", "review",
    "source_kind", "source_id", "request_key", "actor_id",
})
_ADMISSION_FIELDS = frozenset({
    "review_profile", "review_profile_sha256", "review_activation_sha256", "review_clock",
})
_REVIEW_SCHEMA = """CREATE TABLE review_activations (
    repository_key TEXT NOT NULL, operation TEXT NOT NULL,
    declaration_id TEXT UNIQUE NOT NULL, declaration_sha256 TEXT NOT NULL,
    declaration_json TEXT NOT NULL, os_uid INTEGER NOT NULL, recorded_at INTEGER NOT NULL,
    PRIMARY KEY(repository_key, operation)
)"""


def is_review(row):
    return row["target_key"].endswith(":review.start")


def enabled_review_bindings(policy):
    return tuple(binding for binding in policy.bindings.values() if any(
        "review.start" in principal.grants.get(binding.binding_id, ())
        for principal in policy.principals.values()
    ))


def _table(connection):
    return connection.execute(
        "SELECT 1 FROM sqlite_master WHERE type='table' AND name='review_activations'"
    ).fetchone() is not None


def _sha(value):
    return type(value) is str and len(value) == 64 and all(c in "0123456789abcdef" for c in value)


def _activation(declaration, policy, binding, *, current):
    exact_object(declaration, {
        "schema_version", "declaration_id", "journal_id", "repository_key", "operation",
        "policy_id", "policy_digest", "profile_digest", "operator", "assertion", "evidence",
    })
    if (type(declaration["schema_version"]) is not int or declaration["schema_version"] != 1
            or declaration["journal_id"] != policy.journal_id
            or declaration["repository_key"] != binding.canonical_repository
            or declaration["operation"] != "review.start"
            or type(declaration["assertion"]) is not str
            or declaration["assertion"] not in {"fresh_review_scope", "resolved_review_scope"}
            or not _sha(declaration["policy_digest"]) or not _sha(declaration["profile_digest"])):
        raise IngressError("invalid_review_activation", 422)
    identifier(declaration["declaration_id"])
    identifier(declaration["policy_id"])
    operator = text(declaration["operator"], 256)
    if any(ord(c) < 32 or ord(c) == 127 for c in operator):
        raise IngressError("invalid_review_activation", 422)
    evidence = exact_object(declaration["evidence"], {"summary", "records"})
    text(evidence["summary"], 2048)
    records = evidence["records"]
    if type(records) is not list or len(records) > 32:
        raise IngressError("invalid_review_activation", 422)
    if declaration["assertion"] == "resolved_review_scope" and not records:
        raise IngressError("review_resolution_evidence_required", 409)
    references = set()
    for record in records:
        exact_object(record, {"reference", "sha256"})
        reference = text(record["reference"], 256)
        if (any(ord(c) < 33 or ord(c) == 127 for c in reference)
                or reference in references or not _sha(record["sha256"])):
            raise IngressError("invalid_review_activation", 422)
        references.add(reference)
    if current and (
        declaration["policy_id"] != policy.policy_id or declaration["policy_digest"] != policy.digest
        or declaration["profile_digest"] != binding.review_profile.digest
    ):
        raise IngressError("review_activation_identity_mismatch", 409)
    scan_review_secrets(declaration, tuple(p._secret for p in policy.principals.values()))
    return declaration


def enroll_review_scopes(connection, policy, paths):
    """Called only inside the existing stopped-owner enrollment transaction."""
    bindings = enabled_review_bindings(policy)
    selected = {}
    for binding in bindings:
        previous = selected.get(binding.canonical_repository)
        if previous is not None and previous.review_profile.digest != binding.review_profile.digest:
            raise IngressError("ambiguous_review_activation", 409)
        selected[binding.canonical_repository] = binding
    if type(paths) not in (tuple, list) or len(paths) > 128:
        raise IngressError("invalid_review_activation", 422)
    if not selected:
        if paths:
            raise IngressError("review_activation_not_selected", 409)
        return
    exists = _table(connection)
    rows = {} if not exists else {row["repository_key"]: row for row in connection.execute(
        "SELECT * FROM review_activations WHERE operation='review.start'"
    )}
    missing = set(selected) - set(rows)
    declarations = {}
    for path in paths:
        declaration = read_private_json(path)
        repository = declaration.get("repository_key") if type(declaration) is dict else None
        if type(repository) is not str or repository not in missing or repository in declarations:
            raise IngressError("review_activation_exists_or_unselected", 409)
        declarations[repository] = _activation(declaration, policy, selected[repository], current=True)
    if set(declarations) != missing:
        raise IngressError("review_scope_activation_required", 409)
    # Never infer review scope from an old task activation or an empty journal.
    if not exists:
        connection.execute(_REVIEW_SCHEMA)
    for repository, declaration in declarations.items():
        declaration_id = declaration["declaration_id"]
        if (connection.execute("SELECT 1 FROM activations WHERE declaration_id=?", (declaration_id,)).fetchone()
                or connection.execute("SELECT 1 FROM review_activations WHERE declaration_id=?", (declaration_id,)).fetchone()):
            raise IngressError("review_activation_identity_conflict", 409)
        connection.execute("INSERT INTO review_activations VALUES(?,?,?,?,?,?,?)", (
            repository, "review.start", declaration_id, digest_json(declaration),
            canonical_json(declaration), os.getuid(), int(time.time()),
        ))
    ensure_review_scopes(connection, policy)


def activation_digest(connection, policy, binding):
    if not _table(connection):
        raise IngressError("review_scope_unavailable", 503)
    row = connection.execute(
        "SELECT * FROM review_activations WHERE repository_key=? AND operation='review.start'",
        (binding.canonical_repository,),
    ).fetchone()
    if row is None:
        raise IngressError("review_scope_unavailable", 503)
    try:
        declaration = strict_json(row["declaration_json"].encode(), POLICY_LIMIT)
        _activation(declaration, policy, binding, current=False)
        if (digest_json(declaration) != row["declaration_sha256"]
                or declaration["declaration_id"] != row["declaration_id"]):
            raise ValueError
    except (IngressError, ValueError, TypeError, KeyError):
        raise IngressError("review_scope_unavailable", 503) from None
    return row["declaration_sha256"]


def ensure_review_scopes(connection, policy):
    for binding in enabled_review_bindings(policy):
        activation_digest(connection, policy, binding)


def event_input(normalized):
    if type(normalized) is not dict or set(normalized) != _EVENT_FIELDS | _ADMISSION_FIELDS:
        raise IngressError("original_review_input_unavailable", 503)
    return {key: normalized[key] for key in _EVENT_FIELDS}


def _visible(store, row, principal_id):
    from src.storage.ingress_receipts import _projection
    operation = "review.start" if is_review(row) else "task.start"
    if row["principal_id"] != principal_id:
        operation = "receipt.read"
    try:
        store.policy.require_grant(principal_id, row["binding_id"], operation)
    except IngressError:
        return None
    return _projection(row)


def reserve_review(store, principal_id, binding_id, review, actor_id, *, allow_new=True):
    from src.storage.ingress_receipts import _projection, _transaction
    with store._mutex:
        store._check_open()
        if type(allow_new) is not bool:
            raise IngressError("invalid_admission_capacity", 422)
        store.policy.ensure_current()
        binding = store.policy.require_grant(principal_id, binding_id, "review.start")
        principal = store.policy.principals[principal_id]
        review = bounded_review(review)
        positive_integer(actor_id)
        if (principal.kind != "github_hmac_sha256" or actor_id not in principal.actor_ids
                or actor_id != review["author_id"] or binding.review_profile is None):
            raise IngressError("scope_denied", 403)
        event = {
            "principal_id": principal_id, "binding_id": binding_id, "binding": binding.effect_input(),
            "operation": "review.start", "review": review,
            "source_kind": "github_pull_request_review", "source_id": review["review_id"],
            "request_key": None, "actor_id": actor_id,
        }
        scan_review_secrets(event, tuple(p._secret for p in store.policy.principals.values()))
        source_key = digest_json([
            "github", binding.repository_id, "review.start", "github_pull_request_review", review["review_id"],
        ])
        request_digest = digest_json(event)
        target_key = f"{binding.canonical_repository}:pull:{review['pull_number']}:review.start"
        with _transaction(store._owner) as connection:
            store._check_policy(connection)
            row = connection.execute("SELECT * FROM receipts WHERE source_key=?", (source_key,)).fetchone()
            if row is not None:
                if row["request_sha256"] != request_digest:
                    raise IngressError("source_identity_conflict", 409, receipt=_visible(store, row, principal_id))
                return _projection(row)
            fenced = connection.execute(
                "SELECT receipts.* FROM target_fences JOIN receipts USING(operation_id) WHERE target_fences.target_key=?",
                (target_key,),
            ).fetchone()
            if fenced is not None:
                raise IngressError("target_action_fenced", 409, receipt=_visible(store, fenced, principal_id))
            store._check_open(admission=True)
            if not allow_new:
                raise IngressError("ingress_callbacks_unavailable", 503)
            if store._epoch_validator is not None:
                store._epoch_validator()
            credential = store._review_credentials.get(binding_id)
            if credential is None:
                raise IngressError("review_credentials_unavailable", 503)
            credential.validate_epoch()
            normalized = event | {
                "review_profile": thaw(binding.review_profile.document),
                "review_profile_sha256": binding.review_profile.digest,
                "review_activation_sha256": activation_digest(connection, store.policy, binding),
                "review_clock": None,
            }
            scan_review_secrets(normalized, credential.literal_secrets)
            raw = canonical_json(normalized)
            if len(raw.encode()) > 1048576:
                raise IngressError("review_input_too_large", 413)
            operation_id = secrets.token_hex(16)
            connection.execute("""INSERT INTO receipts
                (operation_id,source_key,request_sha256,policy_id,policy_digest,principal_id,binding_id,
                 repository_key,target_key,normalized_input,created_at,state,code)
                VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                operation_id, source_key, request_digest, store.policy.policy_id, store.policy.digest,
                principal_id, binding_id, binding.canonical_repository, target_key, raw,
                int(time.time()), "reserved", "admitted",
            ))
            connection.execute("INSERT INTO target_fences VALUES(?,?)", (target_key, operation_id))
            return _projection(store._row(connection, operation_id))


def bind_fence_clock(store, connection, row):
    normalized = strict_json(row["normalized_input"].encode(), 1048576)
    if digest_json(event_input(normalized)) != row["request_sha256"] or normalized["review_clock"] is not None:
        raise IngressError("original_review_input_unavailable", 503)
    started = time.monotonic()
    if type(started) not in (int, float) or not math.isfinite(started) or started < 0:
        raise IngressError("review_clock_unavailable", 503)
    normalized["review_clock"] = {"owner_epoch": store._epoch, "started_at": started}
    connection.execute("UPDATE receipts SET normalized_input=? WHERE operation_id=?", (
        canonical_json(normalized), row["operation_id"],
    ))


def validate_original(store, connection, row, binding):
    normalized = strict_json(row["normalized_input"].encode(), 1048576)
    event = event_input(normalized)
    if (digest_json(event) != row["request_sha256"] or event["operation"] != "review.start"
            or event["binding"] != binding.effect_input()
            or event["principal_id"] != row["principal_id"] or event["binding_id"] != row["binding_id"]
            or event["source_kind"] != "github_pull_request_review" or event["request_key"] is not None):
        raise IngressError("original_review_input_unavailable", 503)
    review = bounded_review(event["review"])
    principal = store.policy.principals[row["principal_id"]]
    if (event["source_id"] != review["review_id"] or event["actor_id"] != review["author_id"]
            or event["actor_id"] not in principal.actor_ids
            or row["repository_key"] != binding.canonical_repository
            or row["target_key"] != f"{binding.canonical_repository}:pull:{review['pull_number']}:review.start"):
        raise IngressError("original_review_input_unavailable", 503)
    if (binding.review_profile is None or normalized["review_profile_sha256"] != binding.review_profile.digest
            or digest_json(normalized["review_profile"]) != binding.review_profile.digest
            or normalized["review_activation_sha256"] != activation_digest(connection, store.policy, binding)):
        raise IngressError("original_review_profile_changed", 503)
    clock = exact_object(normalized["review_clock"], {"owner_epoch", "started_at"})
    if (clock["owner_epoch"] != store._epoch or type(clock["started_at"]) not in (int, float)
            or not math.isfinite(clock["started_at"]) or clock["started_at"] < 0):
        raise IngressError("original_review_clock_unavailable", 503)
    credential = store._review_credentials.get(binding.binding_id)
    if credential is None:
        raise IngressError("review_credentials_unavailable", 503)
    credential.validate_epoch()
    scan_review_secrets(normalized, credential.literal_secrets)
    return normalized


def _owned(store, invocation):
    if (store._closed or os.getpid() != store._owner.pid or not store._owns_invocation(invocation)
            or store._claim_owners.get(invocation.operation_id) != invocation._invocation_id
            or store._tickets.get(invocation.operation_id) != invocation._ticket):
        raise ReviewError("custody_unavailable", unknown=True)


def _checked_result(row, value, previous=None):
    from src.worker.review_result import validate_review_result
    normalized = strict_json(row["normalized_input"].encode(), 1048576)
    event = event_input(normalized)
    maximum = normalized["review_profile"]["limits"]["receipt_result_bytes"]
    checked = validate_review_result(value, maximum, previous=previous)
    review, binding = event["review"], event["binding"]
    started = normalized["review_clock"]["started_at"]
    limits = normalized["review_profile"]["limits"]
    timing = {"started_ms": int(started * 1000),
        "work_deadline_ms": int((started + (limits["total_ms"] - limits["cleanup_reserve_ms"]) / 1000) * 1000),
        "total_deadline_ms": int((started + limits["total_ms"] / 1000) * 1000)}
    if (checked["schema"] != RESULT_SCHEMA or checked["operation_id"] != row["operation_id"]
            or checked["owner_epoch"] != row["owner_epoch"]
            or checked["request_digest"] != row["request_sha256"]
            or checked["profile_digest"] != normalized["review_profile_sha256"]
            or checked["activation_digest"] != normalized["review_activation_sha256"]
            or checked["timing"] != timing
            or checked["identity"] != {"repository_id": binding["repository_id"],
                "pull_number": review["pull_number"], "review_id": review["review_id"],
                "head_ref": review["head_ref"], "head_sha": review["head_sha"]}):
        raise ReviewError("record_unavailable", unknown=True)
    return checked


def project_review_result(row, observed):
    try:
        return _checked_result(row, observed)
    except (ReviewError, IngressError, TypeError, KeyError, ValueError, OverflowError):
        raise IngressError("receipt_state_invalid", 503) from None


def make_claim(store, invocation, original):
    from src.storage.ingress_receipts import _transaction
    with store._mutex:
        _owned(store, invocation)
        with _transaction(store._owner) as connection:
            row = store._row(connection, invocation.operation_id)
            binding = store.policy.require_grant(row["principal_id"], row["binding_id"], "review.start")
            normalized = validate_original(store, connection, row, binding)
            event = event_input(normalized)
            event.update(operation_id=row["operation_id"], request_digest=row["request_sha256"])
            if original != normalized | {"operation_id": row["operation_id"]}:
                raise ReviewError("record_unavailable", unknown=True)
            clock = normalized["review_clock"]

    def productive():
        with store._mutex:
            _owned(store, invocation)
            store._check_open(admission=True)
            with _transaction(store._owner) as connection:
                store._check_policy(connection, admission=True)
                row = store._row(connection, invocation.operation_id)
                selected = store.policy.require_grant(row["principal_id"], row["binding_id"], "review.start")
                validate_original(store, connection, row, selected)

    def retirement():
        # Original local custody survives productive revocation/store failure.
        # It never constructs a replacement owner or grants productive work.
        with store._mutex:
            _owned(store, invocation)

    def persist(value):
        with store._mutex:
            _owned(store, invocation)
            with _transaction(store._owner) as connection:
                row = store._row(connection, invocation.operation_id)
                previous = None if row["result_json"] is None else strict_json(row["result_json"].encode(),
                    binding.review_profile.limits["receipt_result_bytes"])
                checked = _checked_result(row, value, previous)
                maximum = binding.review_profile.limits["receipt_result_bytes"]
                scan_review_secrets(checked, store._review_credentials[binding.binding_id].literal_secrets,
                    maximum_bytes=maximum, maximum_nodes=maximum, maximum_members=maximum)
                connection.execute("UPDATE receipts SET result_json=? WHERE operation_id=?", (
                    canonical_json(checked), invocation.operation_id,
                ))

    return ReviewClaim(
        operation_id=invocation.operation_id, owner_epoch=store._epoch,
        started_at=clock["started_at"], original=freeze(event), profile=binding.review_profile,
        activation_digest=normalized["review_activation_sha256"],
        credentials=store._review_credentials[binding.binding_id], validate_productive=productive,
        validate_retirement=retirement, persist_result=persist,
    )


def finish_review(store, invocation, outcome):
    from src.storage.ingress_receipts import _projection, _transaction
    with store._mutex:
        _owned(store, invocation)
        with _transaction(store._owner) as connection:
            row = store._row(connection, invocation.operation_id)
            previous = None if row["result_json"] is None else json.loads(row["result_json"])
            checked = _checked_result(row, outcome, previous)
            maximum = store.policy.bindings[row["binding_id"]].review_profile.limits["receipt_result_bytes"]
            scan_review_secrets(checked, store._review_credentials[row["binding_id"]].literal_secrets,
                maximum_bytes=maximum, maximum_nodes=maximum, maximum_members=maximum)
            if checked["status"] == "running":
                raise ReviewError("record_unavailable", unknown=True)
            unknown = checked["status"] == "unknown"
            connection.execute("UPDATE receipts SET state=?,code=?,result_json=? WHERE operation_id=?", (
                "reconciliation_required" if unknown else "returned",
                "adapter_outcome_unknown" if unknown else "adapter_refused" if checked["status"] == "refused" else "handler_returned",
                canonical_json(checked), invocation.operation_id,
            ))
            projected = _projection(store._row(connection, invocation.operation_id))
        store._entered.discard(invocation.operation_id)
        return projected
