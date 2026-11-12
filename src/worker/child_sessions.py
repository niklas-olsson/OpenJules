"""Private host correlation for two separately granted cold child rounds.

Canonical children and their initial-v1 outcomes are never rewritten. This
module adds no allocation authority; every execution uses an ordinary grant.
"""

from __future__ import annotations

import json
import math
import re

from src.agent.child_outcome import report_value

from .child_outcomes import work_outcome
from .child_types import (
    CHILD_ID,
    HASH,
    IDENTIFIER,
    canonical,
    digest,
    text_hash,
    verify_grant,
)
from .lifecycle import LifecycleConflict

SESSION_PROTOCOL = "cold-clarification-v1"
SESSION_SCHEMA_VERSION = 1
INSTRUCTION_PROTOCOL = "openjules-cold-clarification-v1"
SESSION_ID = re.compile(r"session_[0-9a-f]{64}")
TEXT_LIMIT = 16384
INSTRUCTION_LIMIT = 65536
RECORD_LIMIT = 262144
GRANT_RECORD_LIMIT = 1048576
SESSION_OPERATIONS = {
    "session_start": {"instructions", "seconds", "max_turns", "capabilities"},
    "session_followup": {
        "session_id", "predecessor_digest", "instructions", "seconds", "max_turns"
    },
    "session_status": {"session_id"},
}
SESSION_BINDING_FIELDS = {
    "schema_version", "protocol", "session_id", "deployment_id", "repository",
    "profile", "worker_id", "root_attempt_id", "parent_attempt_id", "task_id",
    "requirements_revision", "runtime_principal", "profile_digest",
    "child_policy_digest", "start_request_id", "initial_instructions",
    "capabilities", "max_rounds",
}
SESSION_COLUMNS = (
    "worker_id", "session_id", "start_request_id", "binding", "binding_digest",
    "closure", "close_reason",
)
ROUND_COLUMNS = (
    "worker_id", "session_id", "ordinal", "request_id", "request_json",
    "request_digest", "grant_payload", "instructions_digest", "predecessor",
    "predecessor_digest", "cutoff", "boot_id", "state", "reason", "child_id",
    "grant_digest", "model_closed", "fence_established",
)
SESSION_SQL = (
    "CREATE TABLE cold_sessions("
    "worker_id TEXT NOT NULL,session_id TEXT NOT NULL,start_request_id TEXT NOT NULL,"
    "binding TEXT NOT NULL,binding_digest TEXT NOT NULL,closure TEXT,close_reason TEXT,"
    "PRIMARY KEY(worker_id,session_id),UNIQUE(worker_id,start_request_id))"
)
ROUND_SQL = (
    "CREATE TABLE cold_rounds("
    "worker_id TEXT NOT NULL,session_id TEXT NOT NULL,ordinal INTEGER NOT NULL,"
    "request_id TEXT NOT NULL,request_json TEXT NOT NULL,request_digest TEXT NOT NULL,"
    "grant_payload TEXT NOT NULL,instructions_digest TEXT NOT NULL,"
    "predecessor TEXT,predecessor_digest TEXT,cutoff REAL NOT NULL,boot_id TEXT NOT NULL,"
    "state TEXT NOT NULL,reason TEXT,child_id TEXT,grant_digest TEXT,"
    "model_closed INTEGER NOT NULL DEFAULT 0,"
    "fence_established INTEGER NOT NULL DEFAULT 0,"
    "PRIMARY KEY(worker_id,session_id,ordinal),UNIQUE(worker_id,request_id),"
    "UNIQUE(worker_id,child_id))"
)


def _pairs(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate cold-session field")
        result[key] = value
    return result


def _invalid_constant(_value):
    raise ValueError("nonfinite cold-session number")


def object_value(value, limit=RECORD_LIMIT):
    try:
        if (
            not isinstance(value, str)
            or len(value.encode("utf-8")) > limit
        ):
            raise ValueError("record exceeds its bound")
        result = json.loads(
            value, object_pairs_hook=_pairs, parse_constant=_invalid_constant
        )
        if not isinstance(result, dict) or canonical(result) != value:
            raise ValueError("record is not a canonical object")
    except (TypeError, ValueError, OverflowError, RecursionError) as error:
        raise LifecycleConflict("cold-session record is invalid") from error
    return result


def text_value(value, limit=TEXT_LIMIT):
    if (
        not isinstance(value, str)
        or not value.strip()
        or "\0" in value
        or len(value.encode("utf-8")) > limit
    ):
        raise ValueError("invalid bounded session instruction")
    return value


def duration(value, maximum):
    # Range-check before conversion: a bounded JSON file can contain a huge int.
    if (
        type(value) not in {int, float}
        or not 0 < value <= maximum
        or not math.isfinite(float(value))
    ):
        raise ValueError("invalid bounded session duration")
    return value


def validate_request(payload, policy):
    if (
        not isinstance(payload, dict)
        or type(payload.get("schema_version")) is not int
        or payload["schema_version"] != 1
        or not isinstance(payload.get("request_id"), str)
        or not IDENTIFIER.fullmatch(payload["request_id"])
        or not isinstance(payload.get("operation"), str)
        or payload["operation"] not in SESSION_OPERATIONS
        or set(payload)
        != SESSION_OPERATIONS[payload["operation"]]
        | {"schema_version", "request_id", "operation"}
    ):
        raise ValueError("invalid cold-session request")
    operation = payload["operation"]
    if "session_id" in payload and (
        not isinstance(payload["session_id"], str)
        or not SESSION_ID.fullmatch(payload["session_id"])
    ):
        raise ValueError("invalid cold-session identity")
    if operation != "session_status":
        text_value(payload["instructions"])
        duration(payload["seconds"], policy.max_child_seconds)
        if (
            type(payload["max_turns"]) is not int
            or not 1 <= payload["max_turns"] <= policy.max_child_turns
        ):
            raise ValueError("invalid cold-session inference allowance")
    if operation == "session_start":
        policy.request({
            name: payload[name] for name in SESSION_OPERATIONS["session_start"]
        })
    if operation == "session_followup" and (
        not isinstance(payload["predecessor_digest"], str)
        or not HASH.fullmatch(payload["predecessor_digest"])
    ):
        raise ValueError("invalid predecessor identity")
    return payload


def session_binding(root, policy, payload):
    session_id = "session_" + digest([
        INSTRUCTION_PROTOCOL, root.spec.deployment_id, root.spec.repository,
        root.spec.profile, root.worker_id, root.attempt_id,
        root.requirements_revision, payload["request_id"],
    ])
    return {
        "schema_version": 1,
        "protocol": SESSION_PROTOCOL,
        "session_id": session_id,
        "deployment_id": root.spec.deployment_id,
        "repository": root.spec.repository,
        "profile": root.spec.profile,
        "worker_id": root.worker_id,
        "root_attempt_id": root.attempt_id,
        "parent_attempt_id": root.attempt_id,
        "task_id": root.task_id,
        "requirements_revision": root.requirements_revision,
        "runtime_principal": root.runtime_principal,
        "profile_digest": root.profile_digest,
        "child_policy_digest": policy.fingerprint,
        "start_request_id": payload["request_id"],
        "initial_instructions": payload["instructions"],
        "capabilities": list(policy.request({
            name: payload[name] for name in SESSION_OPERATIONS["session_start"]
        })["capabilities"]),
        "max_rounds": 2,
    }


def effective_instructions(binding, ordinal, instructions, predecessor):
    if type(ordinal) is not int or ordinal not in {1, 2}:
        raise ValueError("invalid logical round")
    value = canonical({
        "schema_version": 1,
        "protocol": INSTRUCTION_PROTOCOL,
        "session_id": binding["session_id"],
        "logical_round": ordinal,
        "initial_instructions": binding["initial_instructions"],
        "followup": None if ordinal == 1 else text_value(instructions),
        "predecessor": None if ordinal == 1 else predecessor,
    })
    if len(value.encode("utf-8")) > INSTRUCTION_LIMIT:
        raise ValueError("combined session instruction exceeds the child bound")
    return value


def predecessor_snapshot(child):
    if (
        not child["exec_dispatched"]
        or not isinstance(child["exec_id"], str)
        or not IDENTIFIER.fullmatch(child["exec_id"])
        or child["outcome_report"] is None
    ):
        raise LifecycleConflict("predecessor lacks its original execution/report")
    grant = object_value(child["grant_json"], GRANT_RECORD_LIMIT)
    report = object_value(child["outcome_report"])
    try:
        checked = report_value(
            report["request_key"], report["outcome"], report["summary"]
        )
    except (KeyError, TypeError, ValueError) as error:
        raise LifecycleConflict("predecessor report is invalid") from error
    if canonical(report) != canonical(checked) or report["outcome"] != "needs_clarification":
        raise LifecycleConflict("predecessor did not request clarification")
    return {
        "exec_id": child["exec_id"],
        "work_outcome": work_outcome(grant["binding"], report)
        | {"canonical_committed": False, "release_authorized": False},
    }


def session_tables_present(db):
    from .managed_public_journal import optional_schema

    return bool(optional_schema(db) & SESSION_SCHEMA_VERSION)


def install_session_schema(db, *, require_existing):
    from .managed_public_journal import install_optional_schema

    if require_existing and not session_tables_present(db):
        raise LifecycleConflict("existing session worker lacks its recovery schema")
    install_optional_schema(db, SESSION_SCHEMA_VERSION, require_existing=require_existing)


def validate_existing_session_schema(db):
    """Inspect the whole optional registry without enabling an omitted policy."""
    return session_tables_present(db)


def session_request_owner(db, worker_id, request_id):
    if not validate_existing_session_schema(db):
        return None
    row = db.execute(
        "SELECT session_id,ordinal FROM cold_rounds WHERE worker_id=? AND request_id=?",
        (worker_id, request_id),
    ).fetchone()
    return None if row is None else (row["session_id"], row["ordinal"])


def bind_session_grant(db, worker_id, request_id, response):
    owner = session_request_owner(db, worker_id, request_id)
    if owner is None:
        return
    row = db.execute(
        "SELECT * FROM cold_rounds WHERE worker_id=? AND request_id=?",
        (worker_id, request_id),
    ).fetchone()
    binding = response["binding"]
    payload = object_value(row["grant_payload"])
    if (
        row["state"] != "linked"
        or row["child_id"] not in {None, binding["child_id"]}
        or row["grant_digest"] not in {None, binding["grant_digest"]}
        or payload["instructions"] != response["instructions"]
        or row["instructions_digest"] != binding["instructions_digest"]
        or payload["seconds"] != binding["allocated_seconds"]
        or payload["max_turns"] != binding["max_turns"]
        or payload["capabilities"] != binding["capabilities"]
    ):
        raise LifecycleConflict("session grant changed its original round intent")
    db.execute(
        "UPDATE cold_rounds SET child_id=?,grant_digest=? "
        "WHERE worker_id=? AND request_id=?",
        (binding["child_id"], binding["grant_digest"], worker_id, request_id),
    )


def retain_terminal_observation(db, worker_id, child_id):
    """Share the exact transaction that first records an exec-return fact."""
    if not validate_existing_session_schema(db):
        return
    row = db.execute(
        "SELECT * FROM cold_rounds WHERE worker_id=? AND child_id=?",
        (worker_id, child_id),
    ).fetchone()
    child = db.execute(
        "SELECT * FROM children WHERE worker_id=? AND child_id=?",
        (worker_id, child_id),
    ).fetchone()
    if row is None:
        # Optional tables are global, but ordinary workers retain their exact
        # instruction behavior. Opted-in whole-map checks detect lost mappings
        # at admission/delivery/launch/finalization, before further work or release.
        return
    session = db.execute(
        "SELECT * FROM cold_sessions WHERE worker_id=? AND session_id=?",
        (worker_id, row["session_id"]),
    ).fetchone()
    _conflict(session is None, "cold execution lost its original session")
    if session["closure"] is not None:
        return
    closure, reason = None, None
    report = _report(child)
    if child["phase"] == "uncertain":
        closure, reason = "uncertain", "launch_uncertain"
    elif child["phase"] == "exec_returned":
        if report is not None and (
            row["ordinal"] == 2 or report["outcome"] != "needs_clarification"
        ):
            closure = report["outcome"]
            reason = "round_limit" if closure == "needs_clarification" else None
        elif type(child["exit_code"]) is not int:
            closure, reason = "uncertain", "runtime_failed"
        elif child["exit_code"] != 0:
            closure, reason = "failed", "runtime_failed"
        elif report is None:
            closure = "unreported"
    if closure is not None:
        db.execute(
            "UPDATE cold_sessions SET closure=?,close_reason=? "
            "WHERE worker_id=? AND session_id=? AND closure IS NULL",
            (closure, reason, worker_id, row["session_id"]),
        )


CLOSURES = {
    "completed", "declined", "needs_clarification", "failed", "unreported",
    "refused", "cancelled", "expired", "uncertain",
}
REASONS = {
    "awaiting_exec_return", "awaiting_model_fence", "awaiting_canonical",
    "child_not_allocated", "lifetime_limit", "round_limit", "admission_closed",
    "expired", "invalid_predecessor", "model_unresolved", "launch_uncertain",
    "runtime_failed", "capture_unresolved",
}


def _conflict(condition, message):
    if condition:
        raise LifecycleConflict(message)


def _report(child):
    value = child["outcome_report"]
    if value is None:
        return None
    saved = object_value(value)
    try:
        checked = report_value(
            saved["request_key"], saved["outcome"], saved["summary"]
        )
    except (KeyError, TypeError, ValueError, RecursionError) as error:
        raise LifecycleConflict("cold-session child report is invalid") from error
    _conflict(canonical(checked) != value, "cold-session child report changed")
    return saved


def _host_instruction(value):
    """Recognize our reserved instruction envelope without adopting it."""
    try:
        decoded = json.loads(value)
    except (TypeError, ValueError, RecursionError):
        return False
    return (
        isinstance(decoded, dict)
        and decoded.get("protocol") == INSTRUCTION_PROTOCOL
    )


class ColdSessionStore:
    """Correlation only. The ordinary child intents remain the allocation path."""

    def __init__(self, journal):
        self.journal = journal

    @staticmethod
    def _child(db, worker_id, child_id):
        if child_id is None:
            return None
        row = db.execute(
            "SELECT * FROM children WHERE worker_id=? AND child_id=?",
            (worker_id, child_id),
        ).fetchone()
        _conflict(row is None, "cold-session original child is missing")
        return dict(row)

    @staticmethod
    def _payload(binding, request, ordinal, predecessor, policy):
        return policy.request({
            "instructions": effective_instructions(
                binding, ordinal, request["instructions"], predecessor
            ),
            "seconds": request["seconds"],
            "max_turns": request["max_turns"],
            "capabilities": binding["capabilities"],
        })

    def _load_all(self, db, root, policy):
        try:
            return self._checked_all(db, root, policy)
        except (KeyError, TypeError, ValueError, OverflowError, RecursionError) as error:
            raise LifecycleConflict("cold-session retained state is invalid") from error

    def _checked_all(self, db, root, policy):
        _conflict(
            policy.session_protocol != SESSION_PROTOCOL,
            "cold sessions are not enabled for this worker",
        )
        install_session_schema(db, require_existing=True)
        worker = db.execute(
            "SELECT * FROM workers WHERE worker_id=?", (root.worker_id,)
        ).fetchone()
        _conflict(
            worker is None or worker["policy_digest"] != policy.fingerprint,
            "cold-session worker policy changed",
        )
        sessions = db.execute(
            "SELECT * FROM cold_sessions WHERE worker_id=? ORDER BY rowid",
            (root.worker_id,),
        ).fetchall()
        _conflict(
            len(sessions) > policy.max_children,
            "cold-session record count exceeds the original policy",
        )
        results, request_ids, child_ids = {}, set(), set()
        for saved in sessions:
            session = dict(saved)
            binding = object_value(session["binding"])
            _conflict(
                set(binding) != SESSION_BINDING_FIELDS
                or session["binding_digest"] != digest(binding)
                or session["session_id"] != binding.get("session_id")
                or session["start_request_id"] != binding.get("start_request_id")
                or session["closure"] not in CLOSURES | {None}
                or session["close_reason"] not in REASONS | {None}
                or (session["closure"] is None and session["close_reason"] is not None),
                "cold-session binding or closure is invalid",
            )
            raw_rounds = db.execute(
                "SELECT * FROM cold_rounds WHERE worker_id=? AND session_id=? "
                "ORDER BY ordinal", (root.worker_id, session["session_id"]),
            ).fetchall()
            _conflict(
                [row["ordinal"] for row in raw_rounds] not in ([1], [1, 2]),
                "cold-session original rounds are missing or changed",
            )
            rounds = []
            for raw in raw_rounds:
                row = dict(raw)
                ordinal = row["ordinal"]
                request = object_value(row["request_json"])
                try:
                    validate_request(request, policy)
                except (TypeError, ValueError, OverflowError, RecursionError) as error:
                    raise LifecycleConflict("cold-session original request is invalid") from error
                _conflict(
                    request["operation"] != (
                        "session_start" if ordinal == 1 else "session_followup"
                    )
                    or request["request_id"] != row["request_id"]
                    or digest(request) != row["request_digest"]
                    or row["request_id"] in request_ids
                    or type(row["cutoff"]) not in {int, float}
                    or not 0 < row["cutoff"] < 1e15
                    or not math.isfinite(row["cutoff"])
                    or row["boot_id"] != root.boot_id
                    or row["state"] not in {"linked", "queued", "refused"}
                    or row["reason"] not in REASONS | {None}
                    or row["model_closed"] not in {0, 1}
                    or row["fence_established"] not in {0, 1}
                    or (row["fence_established"] and not row["model_closed"]),
                    "cold-session round is inconsistent",
                )
                request_ids.add(row["request_id"])
                predecessor = (
                    None if row["predecessor"] is None
                    else object_value(row["predecessor"])
                )
                if ordinal == 1:
                    expected_binding = session_binding(root, policy, request)
                    _conflict(
                        canonical(expected_binding) != session["binding"]
                        or predecessor is not None
                        or row["predecessor_digest"] is not None
                        or row["state"] != "linked"
                        or row["reason"] is not None,
                        "cold-session first round changed",
                    )
                else:
                    first = rounds[0]
                    _conflict(
                        request["session_id"] != session["session_id"]
                        or predecessor is None
                        or row["predecessor_digest"] != digest(predecessor)
                        or request["predecessor_digest"] != row["predecessor_digest"]
                        or request["seconds"] > first["request"]["seconds"]
                        or request["max_turns"] > first["request"]["max_turns"]
                        or first["child"] is None
                        or canonical(predecessor_snapshot(first["child"]))
                        != row["predecessor"]
                        or not first["model_closed"]
                        or row["model_closed"]
                        or row["fence_established"]
                        or (row["state"] == "linked" and not first["fence_established"])
                        or (row["state"] == "queued" and first["fence_established"])
                        or (row["state"] == "refused" and row["reason"] is None)
                        or (row["state"] != "refused" and row["reason"] is not None),
                        "cold-session follow-up or predecessor changed",
                    )
                expected = self._payload(binding, request, ordinal, predecessor, policy)
                _conflict(
                    canonical(expected) != row["grant_payload"]
                    or row["instructions_digest"] != text_hash(expected["instructions"]),
                    "cold-session encoded instruction changed",
                )
                intent_row = db.execute(
                    "SELECT * FROM intents WHERE worker_id=? AND request_id=?",
                    (root.worker_id, row["request_id"]),
                ).fetchone()
                intent = None if intent_row is None else dict(intent_row)
                child = self._child(db, root.worker_id, row["child_id"])
                if row["state"] == "linked":
                    _conflict(
                        intent is None
                        or intent["payload"] != row["grant_payload"]
                        or intent["delivery_key"] != "openjules-child:" + digest([
                            root.worker_id, root.attempt_id, row["request_id"]
                        ])
                        or intent["child_id"] != row["child_id"]
                        or intent["status"] not in {"pending", "bound", "rejected"}
                        or (child is None and intent["status"] == "bound")
                        or (child is not None and intent["status"] != "bound"),
                        "cold-session ordinary delivery link changed",
                    )
                else:
                    _conflict(
                        intent is not None or child is not None
                        or row["grant_digest"] is not None,
                        "unpromoted cold-session round acquired a grant",
                    )
                if child is None:
                    _conflict(
                        row["grant_digest"] is not None,
                        "cold-session grant binding is partial",
                    )
                else:
                    grant = object_value(child["grant_json"], GRANT_RECORD_LIMIT)
                    try:
                        verify_grant(grant, root, policy, requested=expected)
                    except Exception as error:
                        raise LifecycleConflict("cold-session original grant changed") from error
                    _conflict(
                        row["child_id"] in child_ids
                        or row["child_id"] != grant["binding"]["child_id"]
                        or row["grant_digest"] != grant["binding"]["grant_digest"]
                        or row["instructions_digest"] != grant["binding"]["instructions_digest"],
                        "cold-session physical child binding changed",
                    )
                    child_ids.add(row["child_id"])
                    _report(child)
                rounds.append(row | {
                    "request": request, "payload": expected,
                    "predecessor_value": predecessor, "intent": intent, "child": child,
                })
            _conflict(
                len(rounds) == 1
                and (rounds[0]["model_closed"] or rounds[0]["fence_established"]),
                "cold-session model fence lacks its original follow-up",
            )
            results[session["session_id"]] = session | {
                "binding_value": binding, "rounds": rounds,
            }
        # Optional table loss and partial row loss cannot free a request already
        # encoded into an ordinary intent or an immutable canonical child grant.
        orphan = db.execute(
            "SELECT 1 FROM cold_rounds r LEFT JOIN cold_sessions s "
            "ON s.worker_id=r.worker_id AND s.session_id=r.session_id "
            "WHERE r.worker_id=? AND s.session_id IS NULL LIMIT 1",
            (root.worker_id,),
        ).fetchone()
        _conflict(orphan is not None, "cold-session round lost its original session")
        for intent in db.execute(
            "SELECT * FROM intents WHERE worker_id=?", (root.worker_id,)
        ):
            payload = object_value(intent["payload"])
            if _host_instruction(payload.get("instructions")):
                _conflict(
                    intent["request_id"] not in request_ids,
                    "cold-session delivery lost its original correlation",
                )
        for child in db.execute(
            "SELECT * FROM children WHERE worker_id=?", (root.worker_id,)
        ):
            grant = object_value(child["grant_json"], GRANT_RECORD_LIMIT)
            if _host_instruction(grant.get("instructions")):
                _conflict(
                    child["child_id"] not in child_ids,
                    "cold-session child lost its original correlation",
                )
        return results

    def all(self, root, policy):
        with self.journal.connection() as db:
            db.execute("BEGIN")
            return list(self._load_all(db, root, policy).values())

    def get(self, root, policy, session_id):
        with self.journal.connection() as db:
            db.execute("BEGIN")
            result = self._load_all(db, root, policy).get(session_id)
        _conflict(result is None, "cold session does not belong to this root")
        return result

    @staticmethod
    def _insert_round(db, root, session_id, ordinal, request, payload, predecessor, cutoff, state):
        db.execute(
            "INSERT INTO cold_rounds("
            "worker_id,session_id,ordinal,request_id,request_json,request_digest,"
            "grant_payload,instructions_digest,predecessor,predecessor_digest,"
            "cutoff,boot_id,state) VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)",
            (
                root.worker_id, session_id, ordinal, request["request_id"],
                canonical(request), digest(request), canonical(payload),
                text_hash(payload["instructions"]),
                None if predecessor is None else canonical(predecessor),
                None if predecessor is None else digest(predecessor),
                cutoff, root.boot_id, state,
            ),
        )

    def start(self, root, policy, request):
        validate_request(request, policy)
        binding = session_binding(root, policy, request)
        session_id = binding["session_id"]
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            sessions = self._load_all(db, root, policy)
            old = sessions.get(session_id)
            if old is not None:
                _conflict(
                    old["rounds"][0]["request_json"] != canonical(request),
                    "session start key changed its original request",
                )
                return session_id
            _conflict(
                len(sessions) >= policy.max_children,
                "cold-session lifetime record bound reached",
            )
            _conflict(
                session_request_owner(db, root.worker_id, request["request_id"]) is not None
                or db.execute(
                    "SELECT 1 FROM intents WHERE worker_id=? AND request_id=?",
                    (root.worker_id, request["request_id"]),
                ).fetchone() is not None,
                "session start key already belongs to another operation",
            )
            payload = self._payload(binding, request, 1, None, policy)
            db.execute(
                "INSERT INTO cold_sessions("
                "worker_id,session_id,start_request_id,binding,binding_digest) "
                "VALUES(?,?,?,?,?)",
                (
                    root.worker_id, session_id, request["request_id"],
                    canonical(binding), digest(binding),
                ),
            )
            self._insert_round(
                db, root, session_id, 1, request, payload, None,
                root.monotonic_deadline, "linked",
            )
            self.journal._reserve_in(
                db, root.worker_id, request["request_id"], payload, policy,
                session_owner=(session_id, 1),
            )
        return session_id

    def queue(self, root, policy, request, now):
        validate_request(request, policy)
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            sessions = self._load_all(db, root, policy)
            session = sessions.get(request["session_id"])
            _conflict(session is None, "cold session does not belong to this root")
            if len(session["rounds"]) == 2:
                _conflict(
                    session["rounds"][1]["request_json"] != canonical(request),
                    "cold follow-up already has a different original request",
                )
                return
            _conflict(
                session["closure"] is not None,
                "cold session is already logically closed",
            )
            worker = db.execute(
                "SELECT * FROM workers WHERE worker_id=?", (root.worker_id,)
            ).fetchone()
            _conflict(worker["closed"], "cold-session admission is closed")
            first = session["rounds"][0]
            child = first["child"]
            _conflict(
                child is None
                or child["phase"] not in {"running", "exec_returned"}
                or child["revoked"]
                or child["boot_id"] != root.boot_id
                or (child["phase"] == "exec_returned" and (
                    type(child["exit_code"]) is not int or child["exit_code"] != 0
                ))
                or type(child["armed_deadline"]) not in {int, float}
                or child["armed_deadline"] <= now,
                "predecessor lacks an eligible live original execution",
            )
            predecessor = predecessor_snapshot(child)
            _conflict(
                request["predecessor_digest"] != digest(predecessor)
                or request["seconds"] > first["request"]["seconds"]
                or request["max_turns"] > first["request"]["max_turns"],
                "follow-up changed its predecessor or original allowance",
            )
            _conflict(
                session_request_owner(db, root.worker_id, request["request_id"]) is not None
                or db.execute(
                    "SELECT 1 FROM intents WHERE worker_id=? AND request_id=?",
                    (root.worker_id, request["request_id"]),
                ).fetchone() is not None,
                "follow-up key already belongs to another operation",
            )
            payload = self._payload(
                session["binding_value"], request, 2, predecessor, policy
            )
            cutoff = min(
                root.monotonic_deadline, child["deadline"], child["armed_deadline"]
            )
            _conflict(cutoff <= now, "predecessor original interval expired")
            self._insert_round(
                db, root, session["session_id"], 2, request, payload,
                predecessor, cutoff, "queued",
            )
            db.execute(
                "UPDATE cold_rounds SET model_closed=1 "
                "WHERE worker_id=? AND session_id=? AND ordinal=1",
                (root.worker_id, session["session_id"]),
            )

    @staticmethod
    def _close(db, root, session_id, closure, reason):
        db.execute(
            "UPDATE cold_sessions SET closure=?,close_reason=? "
            "WHERE worker_id=? AND session_id=? AND closure IS NULL",
            (closure, reason, root.worker_id, session_id),
        )

    def observe(self, root, policy, now, boot_id):
        """Retain logical closure, without requesting or progressing any work."""
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            sessions = self._load_all(db, root, policy)
            worker = db.execute(
                "SELECT * FROM workers WHERE worker_id=?", (root.worker_id,)
            ).fetchone()
            for session_id, session in sessions.items():
                if session["closure"] is not None:
                    continue
                last = session["rounds"][-1]
                observed = (
                    session["rounds"][0] if last["state"] == "queued" else last
                )
                child = observed["child"]
                closure, reason = None, None
                if last["state"] == "refused":
                    closure, reason = "refused", last["reason"]
                elif last["intent"] is not None and last["intent"]["status"] == "rejected":
                    closure, reason = "refused", "child_not_allocated"
                elif child is not None:
                    report = _report(child)
                    if child["phase"] == "uncertain":
                        closure, reason = "uncertain", "launch_uncertain"
                    elif report is not None and (
                        observed["ordinal"] == 2 or report["outcome"] != "needs_clarification"
                    ):
                        closure = report["outcome"]
                        reason = "round_limit" if closure == "needs_clarification" else None
                    elif child["phase"] == "exec_returned":
                        if type(child["exit_code"]) is not int:
                            closure, reason = "uncertain", "runtime_failed"
                        elif child["exit_code"] != 0:
                            closure, reason = "failed", "runtime_failed"
                        elif report is None:
                            closure = "unreported"
                if closure is None and (
                    root.boot_id != boot_id or now >= root.monotonic_deadline
                    or (child is not None and (
                        child["boot_id"] != boot_id
                        or now >= min(
                            child["deadline"], child["armed_deadline"] or child["deadline"]
                        )
                    ))
                    or (last["ordinal"] == 2 and now >= last["cutoff"])
                ):
                    closure, reason = "expired", "expired"
                if closure is None and (worker["closed"] or (child is not None and child["revoked"])):
                    closure, reason = "cancelled", "admission_closed"
                if closure is not None:
                    self._close(db, root, session_id, closure, reason)

    def promote(self, root, policy, session_id, now):
        """Called only with the existing operation and inference gates owned."""
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._load_all(db, root, policy).get(session_id)
            _conflict(session is None, "cold session does not belong to this root")
            _conflict(len(session["rounds"]) != 2, "cold follow-up is not queued")
            first, second = session["rounds"]
            if second["state"] != "queued":
                return
            worker = db.execute(
                "SELECT * FROM workers WHERE worker_id=?", (root.worker_id,)
            ).fetchone()
            child = first["child"]
            _conflict(
                session["closure"] is not None or worker["closed"]
                or not first["model_closed"] or child is None
                or child["phase"] != "exec_returned"
                or type(child["exit_code"]) is not int or child["exit_code"] != 0
                or child["revoked"] or child["boot_id"] != root.boot_id
                or now >= min(
                    second["cutoff"], root.monotonic_deadline, child["deadline"],
                    child["armed_deadline"] or child["deadline"],
                ),
                "cold follow-up no longer has an eligible original predecessor",
            )
            db.execute(
                "UPDATE cold_rounds SET fence_established=1 "
                "WHERE worker_id=? AND session_id=? AND ordinal=1",
                (root.worker_id, session_id),
            )
            if not self.journal._capacity_available(db, root.worker_id, policy):
                db.execute(
                    "UPDATE cold_rounds SET state='refused',reason='lifetime_limit' "
                    "WHERE worker_id=? AND session_id=? AND ordinal=2",
                    (root.worker_id, session_id),
                )
                self._close(db, root, session_id, "refused", "lifetime_limit")
                return
            self.journal._reserve_in(
                db, root.worker_id, second["request_id"], second["payload"], policy,
                session_owner=(session_id, 2),
            )
            db.execute(
                "UPDATE cold_rounds SET state='linked' "
                "WHERE worker_id=? AND session_id=? AND ordinal=2",
                (root.worker_id, session_id),
            )

    def block_uncertain(self, root, policy, session_id):
        with self.journal.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            session = self._load_all(db, root, policy).get(session_id)
            _conflict(session is None, "cold session does not belong to this root")
            self._close(db, root, session_id, "uncertain", "model_unresolved")

    def for_child(self, root, policy, child_id):
        for session in self.all(root, policy):
            for row in session["rounds"]:
                if row["child_id"] == child_id:
                    return session, row
        return None

    def admission_closed(self, root, policy, child_id):
        found = self.for_child(root, policy, child_id)
        return found is not None and bool(found[1]["model_closed"])

    def launch_cutoff(self, root, policy, child_id, cutoff, now):
        found = self.for_child(root, policy, child_id)
        if found is None or found[1]["ordinal"] == 1:
            return cutoff
        session, row = found
        _conflict(
            session["closure"] is not None
            or row["state"] != "linked"
            or not session["rounds"][0]["fence_established"],
            "cold successor has no open fenced original intent",
        )
        armed = [
            child["armed_deadline"] for child in self.journal.children(root.worker_id)
            if child["exec_dispatched"] and child["armed_deadline"] is not None
        ]
        cutoff = min(cutoff, row["cutoff"], root.monotonic_deadline, *armed)
        _conflict(cutoff <= now, "cold successor original interval expired")
        return cutoff

    def delivery_expired(self, root, policy, request_id, now, boot_id):
        for session in self.all(root, policy):
            for row in session["rounds"]:
                if row["request_id"] == request_id and row["ordinal"] == 2:
                    armed = [
                        child["armed_deadline"]
                        for child in self.journal.children(root.worker_id)
                        if child["exec_dispatched"] and child["armed_deadline"] is not None
                    ]
                    return (
                        row["boot_id"] != boot_id
                        or now >= min(row["cutoff"], root.monotonic_deadline, *armed)
                    )
        return False

    def check_intent(self, root, policy, intent):
        # Full validation also detects row loss unrelated to this delivery.
        sessions = self.all(root, policy)
        for session in sessions:
            for row in session["rounds"]:
                if row["request_id"] == intent["request_id"]:
                    _conflict(
                        row["intent"] is None
                        or canonical(row["intent"]) != canonical(intent),
                        "cold delivery differs from its original linked intent",
                    )
                    return
        _conflict(
            _host_instruction(object_value(intent["payload"]).get("instructions")),
            "cold delivery lost its original correlation",
        )

    @staticmethod
    def _round_projection(row, policy):
        child = row["child"]
        result = {
            "logical_round": row["ordinal"],
            "request_id": row["request_id"],
            "child_id": row["child_id"],
            "grant_digest": row["grant_digest"],
            "instructions_digest": row["instructions_digest"],
            "exec_id": None,
            "runtime_state": None,
            "exit_code": None,
            "initial_outcome": None,
            "evidence": "pending",
            "artifacts": None,
        }
        if child is None:
            return result
        _conflict(
            child["exit_code"] is not None and type(child["exit_code"]) is not int,
            "cold-session runtime exit is invalid",
        )
        grant = object_value(child["grant_json"], GRANT_RECORD_LIMIT)
        outcome = work_outcome(grant["binding"], _report(child))
        result.update(
            exec_id=child["exec_id"], runtime_state=child["phase"],
            exit_code=child["exit_code"], evidence="provisional",
            initial_outcome=outcome | {
                "canonical_committed": False, "release_authorized": False,
            },
        )
        if child["phase"] != "completed":
            return result
        # The ordinary finalization path writes completed only after validating
        # the exact canonical terminal receipt. Revalidate retained local bytes.
        capture = object_value(
            child["capture"], policy.max_result_bytes * 18 + 131072
        )
        artifacts = object_value(child["artifacts"])
        _conflict(
            set(capture) != {"contents", "state"}
            or capture["state"] not in {"exited", "timed_out"}
            or not isinstance(capture["contents"], dict)
            or set(capture["contents"]) != {"patch", "log", "manifest"}
            or set(artifacts) != {"patch", "log", "manifest"},
            "cold-session final capture is incomplete",
        )
        for name, content in capture["contents"].items():
            _conflict(
                not isinstance(content, str)
                or not isinstance(artifacts[name], str)
                or not HASH.fullmatch(artifacts[name])
                or text_hash(content) != artifacts[name],
                "cold-session final artifact changed",
            )
        manifest = object_value(capture["contents"]["manifest"], GRANT_RECORD_LIMIT)
        _conflict(
            canonical(manifest.get("work_outcome")) != canonical(outcome),
            "cold-session final report changed its original outcome",
        )
        result.update(
            evidence="canonical_child_final", artifacts=artifacts,
            initial_outcome=outcome | {
                "artifacts": artifacts,
                "canonical_committed": True,
                "release_authorized": False,
            },
        )
        return result

    def project(self, root, policy, session_id):
        session = self.get(root, policy, session_id)
        worker = self.journal.worker(root.worker_id)
        rounds = session["rounds"]
        first, last = rounds[0], rounds[-1]
        closure, reason = session["closure"], session["close_reason"]
        predecessor = (
            None if first["child"] is None or _report(first["child"]) is None
            or _report(first["child"])["outcome"] != "needs_clarification"
            else digest(predecessor_snapshot(first["child"]))
        )
        if closure is not None:
            phase = "uncertain" if closure == "uncertain" else "closed"
        elif len(rounds) == 2:
            phase = "followup_queued" if last["state"] == "queued" else "round2"
            if last["state"] == "queued":
                reason = (
                    "awaiting_exec_return"
                    if first["child"]["phase"] != "exec_returned"
                    else "awaiting_model_fence"
                )
            elif last["child"] is None:
                reason = "awaiting_canonical"
        elif predecessor is not None:
            phase = "awaiting_followup"
            if first["child"]["phase"] != "exec_returned":
                reason = "awaiting_exec_return"
        else:
            phase = "round1"
            if first["child"] is None:
                reason = "awaiting_canonical"
        projected = [self._round_projection(row, policy) for row in rounds]
        resolved = all(
            row["state"] == "refused"
            or (row["state"] == "queued" and worker["closed"])
            or (row["intent"] is not None and row["intent"]["status"] == "rejected")
            or projection["evidence"] == "canonical_child_final"
            for row, projection in zip(rounds, projected)
        )
        return {
            "protocol": SESSION_PROTOCOL,
            "session_id": session_id,
            "root_attempt_id": root.attempt_id,
            "phase": phase,
            "reason": reason,
            "predecessor_digest": predecessor,
            "followup_request_id": None if len(rounds) == 1 else last["request_id"],
            "model_fence": (
                "established" if first["fence_established"]
                else "requested" if first["model_closed"] else "open"
            ),
            "logical_outcome": None if closure == "uncertain" else closure,
            "all_child_receipts_final": bool(resolved),
            "canonical_session": False,
            "release_authorized": False,
            "rounds": projected,
        }

    def validate_final(self, root, policy):
        for session in self.all(root, policy):
            result = self.project(root, policy, session["session_id"])
            _conflict(
                not result["all_child_receipts_final"],
                "cold-session original children lack final receipts",
            )
