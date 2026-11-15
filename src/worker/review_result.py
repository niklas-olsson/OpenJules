"""Closed, data-only facts for an original standalone review operation.

These observations confer no task, publication, cleanup or retry authority.
The fixed capacity calculation includes every permitted effect's late facts.
"""

from __future__ import annotations

import json
import re
from collections.abc import Mapping

from .review_contract import RESULT_SCHEMA, REVIEW_CODES, ReviewError


MAX_INTEGER = 2**63 - 1
MIN_CLEANUP_CALLS = 6
KINDS = frozenset({"forge_get", "forge_token", "git", "guest_api", "exec", "model"})
STATES = frozenset({"entered", "returned", "acknowledged", "refused", "outcome_unknown", "closed"})
COUNTERS = (
    "forge_get", "forge_token", "git", "guest_api", "guest_api_cleanup", "exec", "model",
    "model_request_bytes", "model_response_reserved", "model_response_bytes", "model_output_tokens",
    "forge_response_reserved", "forge_response_bytes", "git_response_reserved", "git_response_bytes",
    "exec_request_bytes", "exec_response_reserved", "exec_response_bytes",
    "guest_api_response_reserved", "guest_api_response_bytes",
)
_SHA40 = re.compile(r"[0-9a-f]{40}\Z")
_SHA64 = re.compile(r"[0-9a-f]{64}\Z")
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
PUBLICATION = frozenset({"acknowledged", "refused", "observed_no_update", "outcome_unknown"})


def _bad():
    raise ReviewError("record_unavailable", unknown=True)


def _integer(value):
    return type(value) is int and 0 <= value <= MAX_INTEGER


def _exit(value):
    return value is None or (type(value) is int and -(2**31) <= value < 2**31)


def _string(pattern):
    return lambda value: type(value) is str and pattern.fullmatch(value) is not None


def _nullable(check):
    return lambda value: value is None or check(value)


_bool = lambda value: type(value) is bool
_id = _string(_ID)
_sha40 = _string(_SHA40)
_sha64 = _string(_SHA64)
def valid_head_ref(value):
    if type(value) is not str or not value.startswith("refs/heads/"):
        return False
    try:
        if len(value.encode("utf-8")) > 512:
            return False
    except UnicodeError:
        return False
    suffix = value[len("refs/heads/"):]
    return bool(suffix) and not (
        suffix.endswith(("/", ".")) or ".." in suffix or "@{" in suffix
        or any(ord(c) < 33 or ord(c) == 127 or c in "~^:?*[\\" for c in suffix)
        or any(not p or p.startswith(".") or p.endswith(".lock") for p in suffix.split("/")))


_ref = valid_head_ref

FACT_FIELDS = {
    "source": {"base_sha": _sha40, "tree_sha": _sha40, "snapshot_sha256": _sha64,
               "source_bytes": _integer, "source_objects": _integer},
    "guest": {"incarnation": _id, "container_id": _nullable(_id), "volume_name": _id,
              "create_entered": _bool, "create_acknowledged": _bool,
              "start_entered": _bool, "start_acknowledged": _bool, "stopped": _bool,
              "local_closed": _bool, "retained": _bool},
    "capture": {"retained_id": _id, "container_id": _id,
                "archive_sha256": _sha64, "archive_bytes": _integer,
                "patch_sha256": _sha64, "patch_bytes": _integer,
                "log_sha256": _sha64, "log_bytes": _integer, "manifest_sha256": _sha64,
                "durable": _bool, "termination_confirmed": _bool},
    "candidate": {"parent_sha": _sha40, "tree_sha": _sha40,
                  "commit_sha": _nullable(_sha40), "no_change": _bool},
    "publication": {"status": lambda value: type(value) is str and value in PUBLICATION,
                    "original_ref": _ref, "expected_head": _sha40,
                    "candidate_sha": _nullable(_sha40), "invoked": _bool,
                    "local_closed": _bool, "late_acknowledged": _bool},
    "cleanup": {"container_removed": _bool, "volume_removed": _bool, "auth_removed": _bool,
                "local_processes_closed": _bool, "local_exchanges_closed": _bool,
                "resources_retained": _bool},
    "verification": {"command_sha256": _sha64, "exchange_id": _id,
                     "exit_code": _exit, "local_closed": _bool, "observed": _bool},
    "engine": {"planned": _bool, "turns": _integer, "model_complete": _bool},
    "model": {"local_closed": _bool, "provider_outcome_unknown": _bool},
}
DATA_FIELDS = {"exit_code": _exit, "local_closed": _bool, "sha256": _sha64,
               "payload_sha256": _sha64, "route_sha256": _sha64,
               "status": lambda value: type(value) is str and value in PUBLICATION}
_EFFECT_KEYS = frozenset({"id", "kind", "cleanup", "deadline_ms", "request_bytes",
                          "response_reserved", "response_bytes", "output_tokens", "code", "data"}) | STATES
_RESULT_KEYS = frozenset({"schema", "operation_id", "owner_epoch", "profile_digest", "activation_digest",
                          "request_digest", "identity", "status", "first_failure", "timing", "counters",
                          "effects", "facts"})


def encode_result(value) -> bytes:
    try:
        return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
                          allow_nan=False).encode("ascii")
    except (ValueError, TypeError, OverflowError, RecursionError):
        _bad()


def required_result_capacity(limits: Mapping) -> int:
    """Conservative maximum, not an operating allowance or a default profile.

    A closed effect is smaller than 2,048 ASCII bytes even with every flag,
    63-bit counter, code and optional data field populated. The fixed identity,
    timing, counters and all bounded fact groups fit within 16,384 bytes.
    """
    if not isinstance(limits, Mapping):
        _bad()
    if (type(limits.get("guest_api_cleanup_calls")) is not int
            or type(limits.get("guest_api_calls")) is not int
            or not MIN_CLEANUP_CALLS <= limits["guest_api_cleanup_calls"] <= limits["guest_api_calls"]):
        _bad()
    count = 5  # The selected four GETs and one possible App token POST.
    for name in ("git_calls", "guest_api_calls", "exec_calls", "model_calls"):
        value = limits.get(name)
        if not _integer(value) or value < 1:
            _bad()
        count += value
    capacity = 16_384 + count * 2_048
    if capacity > MAX_INTEGER:
        _bad()
    return capacity


def validate_fact(name, value):
    if type(name) is not str or name not in FACT_FIELDS or type(value) is not dict or set(value) - set(FACT_FIELDS[name]):
        _bad()
    for key, item in value.items():
        if not FACT_FIELDS[name][key](item):
            _bad()
    return dict(value)


def validate_result(value, *, max_bytes: int | None = None):
    """Return a detached JSON value after closed shape and implication checks."""
    if type(value) is not dict or set(value) != _RESULT_KEYS or value["schema"] != RESULT_SCHEMA:
        _bad()
    for key in ("operation_id", "owner_epoch"):
        if not _id(value[key]):
            _bad()
    for key in ("profile_digest", "activation_digest", "request_digest"):
        if not _sha64(value[key]):
            _bad()
    identity = value["identity"]
    if type(identity) is not dict or set(identity) != {"repository_id", "pull_number", "review_id", "head_ref", "head_sha"}:
        _bad()
    if any(not _integer(identity[k]) or identity[k] < 1 for k in ("repository_id", "pull_number", "review_id")):
        _bad()
    if not _ref(identity["head_ref"]) or not _sha40(identity["head_sha"]):
        _bad()
    if type(value["status"]) is not str or value["status"] not in {"running", "returned", "refused", "unknown"}:
        _bad()
    failure = value["first_failure"]
    if failure is not None:
        if type(failure) is not dict or set(failure) != {"code", "unknown"}:
            _bad()
        if type(failure["code"]) is not str or failure["code"] not in REVIEW_CODES or not _bool(failure["unknown"]):
            _bad()
    if value["status"] == "returned" and failure is not None:
        _bad()
    if value["status"] in {"refused", "unknown"} and failure is None:
        _bad()
    timing = value["timing"]
    if type(timing) is not dict or set(timing) != {"started_ms", "work_deadline_ms", "total_deadline_ms"}:
        _bad()
    if any(not _integer(v) for v in timing.values()) or not timing["started_ms"] < timing["work_deadline_ms"] < timing["total_deadline_ms"]:
        _bad()
    counters = value["counters"]
    if type(counters) is not dict or set(counters) != set(COUNTERS) or any(not _integer(v) for v in counters.values()):
        _bad()
    if type(value["effects"]) is not list:
        _bad()
    for index, effect in enumerate(value["effects"], 1):
        if type(effect) is not dict or set(effect) != _EFFECT_KEYS:
            _bad()
        if effect["id"] != index or type(effect["id"]) is not int or type(effect["kind"]) is not str or effect["kind"] not in KINDS:
            _bad()
        if any(not _bool(effect[k]) for k in (*STATES, "cleanup")):
            _bad()
        if effect["cleanup"] and effect["kind"] != "guest_api":
            _bad()
        if any(not _integer(effect[k]) for k in ("deadline_ms", "request_bytes", "response_reserved", "response_bytes", "output_tokens")):
            _bad()
        if effect["response_bytes"] > effect["response_reserved"] and not effect["outcome_unknown"]:
            _bad()
        if (effect["acknowledged"] or effect["returned"]) and not effect["entered"]:
            _bad()
        if effect["code"] is not None and (type(effect["code"]) is not str or effect["code"] not in REVIEW_CODES):
            _bad()
        if type(effect["data"]) is not dict or set(effect["data"]) - set(DATA_FIELDS):
            _bad()
        if any(not DATA_FIELDS[k](v) for k, v in effect["data"].items()):
            _bad()
    derived = dict.fromkeys(COUNTERS, 0)
    for effect in value["effects"]:
        kind = effect["kind"]
        derived[kind] += 1
        if effect["cleanup"]:
            derived["guest_api_cleanup"] += 1
        prefix = "forge" if kind.startswith("forge_") else kind
        derived[prefix + "_response_reserved"] += effect["response_reserved"]
        derived[prefix + "_response_bytes"] += effect["response_bytes"]
        if kind in {"model", "exec"}:
            derived[kind + "_request_bytes"] += effect["request_bytes"]
        if kind == "model":
            derived["model_output_tokens"] += effect["output_tokens"]
    if derived != counters:
        _bad()
    if any(effect["outcome_unknown"] for effect in value["effects"]) and value["status"] != "unknown":
        _bad()
    facts = value["facts"]
    if type(facts) is not dict or set(facts) != set(FACT_FIELDS):
        _bad()
    for name, fact in facts.items():
        validate_fact(name, fact)
    guest, capture, candidate, publication = (facts[k] for k in ("guest", "capture", "candidate", "publication"))
    if capture.get("durable") is True:
        if not {"retained_id", "archive_sha256", "archive_bytes", "patch_sha256", "patch_bytes", "log_sha256", "log_bytes", "manifest_sha256", "termination_confirmed"} <= set(capture):
            _bad()
        if capture.get("termination_confirmed") is not True or guest.get("stopped") is not True or guest.get("local_closed") is not True:
            _bad()
    if candidate.get("commit_sha") is not None:
        if candidate.get("parent_sha") != identity["head_sha"] or capture.get("durable") is not True:
            _bad()
    if publication.get("status") == "acknowledged":
        verification = facts["verification"]
        if (publication.get("invoked") is not True or publication.get("local_closed") is not True
                or publication.get("original_ref") != identity["head_ref"]
                or publication.get("expected_head") != identity["head_sha"]
                or not candidate.get("commit_sha") or publication.get("candidate_sha") != candidate["commit_sha"]
                or verification.get("observed") is not True or verification.get("exit_code") != 0
                or verification.get("local_closed") is not True):
            _bad()
    raw = encode_result(value)
    if max_bytes is not None and (not _integer(max_bytes) or len(raw) > max_bytes):
        _bad()
    return json.loads(raw)


def validate_review_result(value, maximum, previous=None):
    """Validate an original callback's bounded, monotone journal projection.

    This checks facts, never callback ownership or execution authorization.
    The receipt owner must separately bind the immutable identity to its row.
    """
    if not _integer(maximum) or maximum < 1:
        _bad()
    current = validate_result(value, max_bytes=maximum)
    if previous is None:
        return current
    old = validate_result(previous, max_bytes=maximum)
    for key in ("schema", "operation_id", "owner_epoch", "profile_digest",
                "activation_digest", "request_digest", "identity", "timing"):
        if current[key] != old[key]:
            _bad()
    if old["first_failure"] is not None and current["first_failure"] != old["first_failure"]:
        _bad()
    allowed_status = {"running": {"running", "returned", "refused", "unknown"},
                      "returned": {"returned", "refused", "unknown"},
                      "refused": {"refused", "unknown"}, "unknown": {"unknown"}}
    if current["status"] not in allowed_status[old["status"]]:
        _bad()
    if any(current["counters"][key] < old["counters"][key] for key in COUNTERS):
        _bad()
    if len(current["effects"]) < len(old["effects"]):
        _bad()
    if old["status"] == "returned" and len(current["effects"]) != len(old["effects"]):
        _bad()
    immutable_effect = _EFFECT_KEYS - STATES - {"response_bytes", "code", "data"}
    for before, after in zip(old["effects"], current["effects"]):
        if any(after[key] != before[key] for key in immutable_effect):
            _bad()
        if any(before[key] and not after[key] for key in STATES):
            _bad()
        if after["response_bytes"] < before["response_bytes"]:
            _bad()
        if before["code"] is not None and after["code"] != before["code"]:
            _bad()
        for key, item in before["data"].items():
            if key not in after["data"]:
                _bad()
            if item is not None and after["data"][key] != item:
                if not (key == "local_closed" and item is False and after["data"][key] is True):
                    _bad()
    released = all(current["facts"]["cleanup"].get(key) is True for key in (
        "container_removed", "volume_removed", "local_processes_closed", "local_exchanges_closed"))
    for name, before in old["facts"].items():
        after = current["facts"][name]
        for key, item in before.items():
            if key not in after:
                _bad()
            if item is None or after[key] == item:
                continue
            if type(item) is bool and item is False and after[key] is True:
                continue
            if name == "engine" and key == "turns" and after[key] >= item:
                continue
            if key in {"retained", "resources_retained"} and item is True and after[key] is False and released:
                continue
            _bad()
    return current
