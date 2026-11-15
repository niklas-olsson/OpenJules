"""Pure normalization of an already authenticated review webhook body."""

import hashlib
import re

from src.api.ingress_policy import (
    IngressError, branch_name, exact_object, positive_integer,
)
from src.api.review_policy import text
from src.worker.review_source import ReviewSourceRejected, require_legacy_review_source

_COMMAND = re.compile(r"^/jules review(?=\s|$)")
_HEAD = re.compile(r"[0-9a-f]{40}\Z")
REVIEW_FIELDS = frozenset({
    "pull_number", "branch", "head_ref", "head_sha", "review_id", "author_id",
    "review_body", "instruction", "body_sha256", "pull_body", "pull_body_sha256",
})


def _refuse(code="review_source_unsupported", status=404):
    raise IngressError(code, status)


def _object(value):
    if type(value) is not dict:
        _refuse("invalid_review_source", 422)
    return value


def _digest(value):
    return hashlib.sha256(value.encode("utf-8")).hexdigest()


def bounded_review(value):
    """Validate the stored exact target, including all derived identities."""
    exact_object(value, REVIEW_FIELDS)
    for field in ("pull_number", "review_id", "author_id"):
        positive_integer(value[field])
    branch = branch_name(value["branch"])
    if value["head_ref"] != "refs/heads/" + branch:
        _refuse("invalid_review_ref", 422)
    if type(value["head_sha"]) is not str or not _HEAD.fullmatch(value["head_sha"]):
        _refuse("invalid_review_head", 422)
    body = text(value["review_body"], 262144)
    pull_body = text(value["pull_body"], 262144, empty=True)
    match = _COMMAND.match(body)
    if match is None or not body[match.end():].strip():
        _refuse("review_trigger_required", 403)
    instruction = body[match.end():].strip()
    if (value["instruction"] != instruction or value["body_sha256"] != _digest(body)
            or value["pull_body_sha256"] != _digest(pull_body)):
        _refuse("invalid_review_identity", 422)
    try:
        require_legacy_review_source(branch, pull_body, body)
    except ReviewSourceRejected:
        _refuse("review_target_unsupported")
    return dict(value)


def webhook_review(policy, principal, payload, event):
    """Unsigned routing headers cannot reinterpret a signed review source."""
    payload = _object(payload)
    if (event not in (None, "pull_request_review") or payload.get("action") != "submitted"
            or any(name in payload for name in ("issue", "comment", "review_comment", "pull_request_review_comment"))):
        _refuse()
    review = _object(payload.get("review"))
    pull = _object(payload.get("pull_request"))
    repository = _object(payload.get("repository"))
    base, head = _object(pull.get("base")), _object(pull.get("head"))
    base_repository, head_repository = _object(base.get("repo")), _object(head.get("repo"))
    repository_id = positive_integer(repository.get("id"))
    repository_name = text(repository.get("full_name"), 256)
    for original_repository in (base_repository, head_repository):
        if (positive_integer(original_repository.get("id")) != repository_id
                or text(original_repository.get("full_name"), 256) != repository_name):
            _refuse("foreign_review_head_unsupported")
    actor = positive_integer(_object(review.get("user")).get("id"))
    if (positive_integer(_object(payload.get("sender")).get("id")) != actor
            or actor not in principal.actor_ids):
        _refuse("review_actor_refused", 403)
    if (review.get("state") != "changes_requested" or pull.get("state") != "open"
            or ("merged" in pull and pull["merged"] is not False)
            or review.get("commit_id") != head.get("sha")):
        _refuse()
    body = text(review.get("body"), 262144)
    raw_pull_body = pull.get("body")
    pull_body = text("" if raw_pull_body is None else raw_pull_body, 262144, empty=True)
    branch = branch_name(head.get("ref"))
    match = _COMMAND.match(body)
    if match is None:
        _refuse("review_trigger_required", 403)
    original = bounded_review({
        "pull_number": positive_integer(pull.get("number")), "branch": branch,
        "head_ref": "refs/heads/" + branch, "head_sha": head.get("sha"),
        "review_id": positive_integer(review.get("id")), "author_id": actor,
        "review_body": body, "instruction": body[match.end():].strip(),
        "body_sha256": _digest(body), "pull_body": pull_body,
        "pull_body_sha256": _digest(pull_body),
    })
    candidates = []
    for binding in policy.bindings.values():
        if binding.repository_id != repository_id or binding.repository != repository_name:
            continue
        if binding.installation_id is not None:
            installation = _object(payload.get("installation"))
            if positive_integer(installation.get("id")) != binding.installation_id:
                continue
        try:
            policy.require_grant(principal.principal_id, binding.binding_id, "review.start")
        except IngressError as error:
            if error.status == 403:
                continue
            raise
        if binding.review_profile is not None:
            candidates.append(binding)
    if len(candidates) != 1:
        _refuse("review_binding_refused", 403)
    return candidates[0], original, actor
