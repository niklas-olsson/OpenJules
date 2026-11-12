"""Finite public request ownership in the existing child-service journal.

This is private correlation and retained communication state, not a task or
model-budget allocator. Canonical grants and the common ModelBroker remain the
only protected admission/accounting paths. All writes use the original SQLite
transaction and child-service owner lock.
"""

from __future__ import annotations

from contextlib import contextmanager
import json
import time

from .child_types import RootContext
from .discussion_types import (
    DiscussionError, validate_receipt, validate_status,
    verify_record,
)
from .lifecycle import LifecycleConflict
from .managed_public_types import (
    ACTOR_LIMIT, ACTOR_SLOT_LIMIT, AUTHOR, CHILD_ID, CODES, HEX64,
    HISTORY_LIMIT, MODEL_PREFIX, OWNER_LIMIT, PAGE_LIMIT, POLICY_LIMIT,
    PROTOCOL, PUBLIC_SECONDS, RECORD_LIMIT, REQUEST_ID, REQUEST_LIMIT,
    RESPONSE_LIMIT, ROOT_CAPTURE_LIMIT, CHILD_CAPTURE_LIMIT,
    SELECTED_BYTES, SELECTED_LIMIT, SLOT_LIMIT, SLOT_STATES,
    TRANSCRIPT_BYTES, TRANSCRIPT_LIMIT, ManagedPublicError, PublicPolicy,
    absolute_path, canonical, digest, fields, finite, integer, invitation_key, matches,
    model_key, object_value, publication_key, public_model_payload,
    signed_intent, validate_request,
)

PUBLIC_SCHEMA_BIT = 2
PUBLIC_ROW_LIMIT = 524288
PUBLIC_TABLES = {
    "public_workers": ("worker_id", "data", "digest"),
    "public_actors": ("worker_id", "actor_id", "data", "digest"),
    "public_requests": ("worker_id", "request_id", "data", "digest"),
    "public_slots": ("worker_id", "slot_id", "data", "digest"),
    "public_records": ("worker_id", "message_id", "data", "digest"),
    "public_processes": ("worker_id", "process_id", "data", "digest"),
}
PUBLIC_SQL = {
    name: (
        "CREATE TABLE " + name + "("
        + "worker_id TEXT " + ("PRIMARY KEY," if len(columns) == 3 else "NOT NULL,")
        + (columns[1] + " TEXT NOT NULL," if len(columns) == 4 else "")
        + "data TEXT NOT NULL,digest TEXT NOT NULL"
        + (",PRIMARY KEY(worker_id," + columns[1] + ")" if len(columns) == 4 else "")
        + ")"
    )
    for name, columns in PUBLIC_TABLES.items()
}
WORKER_FIELDS = {
    "schema_version", "protocol", "policy", "policy_digest", "root",
    "closed", "actors", "requests", "slots", "records", "processes",
    "history_charges", "page_charges", "post_reservations",
    "transcript_bytes", "frozen", "freeze_digest",
}
IDENTITY_FIELDS = {
    "schema_version", "protocol", "worker_id", "root_attempt_id", "task_id",
    "requirements_revision", "profile_digest", "child_policy_digest", "role",
    "child_id", "uid", "exec_id", "grant_digest", "instructions_digest",
}
ACTOR_FIELDS = {
    "actor_id", "identity", "identity_digest", "status", "binding",
    "binding_digest", "closed", "leave_slot", "config", "generations",
}
REQUEST_FIELDS = {
    "request_id", "actor_id", "payload", "payload_digest", "expires_at",
    "monotonic_cutoff", "boot_id", "state", "error", "result", "slot_id",
    "history_charges", "page_charges", "invitation",
}
SLOT_FIELDS = {
    "slot_id", "actor_id", "activation_request_id", "activation_actor_id",
    "persona_key", "instruction_key", "selected_message_ids", "reply_to",
    "expires_at", "monotonic_cutoff", "boot_id", "state", "reason",
    "context", "context_digest", "model_key", "model_call_digest",
    "response", "publication_intent", "receipt", "history_charges",
    "page_charges", "decision_request_id",
}
PROCESS_FIELDS = {
    "process_id", "actor_id", "generation", "stage", "intent", "intent_digest",
    "state", "identity", "cleanup",
}
TERMINAL = frozenset({"published", "declined", "left", "expired", "refused"})
SUCCESSFUL = {"published": "message", "declined": "decline", "left": "leave"}


def _conflict():
    raise LifecycleConflict("managed public retained state is inconsistent")


def optional_schema(db):
    """Validate the complete optional registry, including ordinary workers.

    Legacy0 and cold-only1 are unchanged. Public-only2 and both3 are explicit
    new combinations. A missing table is never interpreted as a fresh install.
    """
    from .child_sessions import SESSION_COLUMNS, ROUND_COLUMNS, SESSION_SQL, ROUND_SQL

    version = db.execute("PRAGMA user_version").fetchone()[0]
    if type(version) is not int or version not in {0, 1, 2, 3}:
        raise LifecycleConflict("optional child schema marker or definition is inconsistent")
    actual = {
        row[0] for row in db.execute(
            "SELECT name FROM sqlite_master WHERE type='table' "
            "AND (name GLOB 'cold_*' OR name GLOB 'public_*')"
        )
    }
    definitions = {}
    if version & 1:
        definitions.update({
            "cold_sessions": (SESSION_COLUMNS, SESSION_SQL),
            "cold_rounds": (ROUND_COLUMNS, ROUND_SQL),
        })
    if version & PUBLIC_SCHEMA_BIT:
        definitions.update({
            name: (columns, PUBLIC_SQL[name])
            for name, columns in PUBLIC_TABLES.items()
        })
    if actual != set(definitions):
        raise LifecycleConflict("optional child schema marker or definition is inconsistent")
    for name, (columns, sql) in definitions.items():
        found = tuple(row[1] for row in db.execute("PRAGMA table_info(" + name + ")"))
        saved = db.execute(
            "SELECT sql FROM sqlite_master WHERE type='table' AND name=?", (name,),
        ).fetchone()
        if found != columns or saved is None or saved[0] != sql:
            raise LifecycleConflict("optional child schema marker or definition is inconsistent")
    return version


def install_optional_schema(db, bit, *, require_existing):
    from .child_sessions import SESSION_SQL, ROUND_SQL

    if bit not in {1, PUBLIC_SCHEMA_BIT}:
        _conflict()
    version = optional_schema(db)
    if version & bit:
        return
    if require_existing or not db.in_transaction:
        _conflict()
    statements = (SESSION_SQL, ROUND_SQL) if bit == 1 else tuple(PUBLIC_SQL.values())
    for statement in statements:
        db.execute(statement)
    db.execute("PRAGMA user_version=" + str(version | bit))
    optional_schema(db)


def _decode(row, limit=PUBLIC_ROW_LIMIT):
    if row is None:
        _conflict()
    try:
        value = object_value(row["data"], limit, code="state_conflict", retained=True)
        if digest(value) != row["digest"]:
            _conflict()
        return value
    except ManagedPublicError:
        _conflict()


def _save(db, table, worker_id, key, value, *, insert=False):
    columns = PUBLIC_TABLES[table]
    encoded = canonical(value, limit=PUBLIC_ROW_LIMIT).decode("utf-8")
    checksum = digest(value)
    if len(columns) == 3:
        if insert:
            db.execute(
                "INSERT INTO public_workers(worker_id,data,digest) VALUES(?,?,?)",
                (worker_id, encoded, checksum),
            )
        else:
            cursor = db.execute(
                "UPDATE public_workers SET data=?,digest=? WHERE worker_id=?",
                (encoded, checksum, worker_id),
            )
            if cursor.rowcount != 1:
                _conflict()
    elif insert:
        db.execute(
            "INSERT INTO " + table + "(worker_id," + columns[1]
            + ",data,digest) VALUES(?,?,?,?)",
            (worker_id, key, encoded, checksum),
        )
    else:
        cursor = db.execute(
            "UPDATE " + table + " SET data=?,digest=? WHERE worker_id=? AND "
            + columns[1] + "=?", (encoded, checksum, worker_id, key),
        )
        if cursor.rowcount != 1:
            _conflict()


def prepare_public_worker(db, worker_id, policy, *, require_existing):
    """Called inside the same transaction that binds the child worker policy."""
    install_optional_schema(db, PUBLIC_SCHEMA_BIT, require_existing=require_existing)
    row = db.execute(
        "SELECT * FROM public_workers WHERE worker_id=?", (worker_id,),
    ).fetchone()
    if require_existing:
        value = _decode(row)
        if (
            value.get("policy_digest") != policy.fingerprint
            or canonical(value.get("policy")) != canonical(policy.public_discussion)
        ):
            _conflict()
        return
    if row is not None:
        _conflict()
    value = {
        "schema_version": 1, "protocol": PROTOCOL,
        "policy": PublicPolicy.parse(policy.public_discussion).document,
        "policy_digest": policy.fingerprint, "root": None, "closed": False,
        "actors": 0, "requests": 0, "slots": 0, "records": 0, "processes": 0,
        "history_charges": 0, "page_charges": 0, "post_reservations": 0,
        "transcript_bytes": 0, "frozen": None, "freeze_digest": None,
    }
    _save(db, "public_workers", worker_id, None, value, insert=True)


def public_request_owner(db, worker_id, request_id):
    if not optional_schema(db) & PUBLIC_SCHEMA_BIT:
        return None
    row = db.execute(
        "SELECT * FROM public_requests WHERE worker_id=? AND request_id=?",
        (worker_id, request_id),
    ).fetchone()
    if row is None:
        return None
    value = _decode(row)
    if value.get("request_id") != request_id:
        _conflict()
    return value.get("actor_id"), value.get("payload_digest")


def ordinary_request_key(db, worker_id, request_id):
    """The public namespace cannot be adopted by a coding/control operation."""
    version = optional_schema(db)
    if not version & PUBLIC_SCHEMA_BIT:
        return
    row = db.execute(
        "SELECT * FROM public_workers WHERE worker_id=?", (worker_id,),
    ).fetchone()
    if row is None:
        return
    header = _decode(row)
    worker = db.execute(
        "SELECT policy_digest FROM workers WHERE worker_id=?", (worker_id,),
    ).fetchone()
    if worker is None or header.get("policy_digest") != worker["policy_digest"]:
        _conflict()
    if isinstance(request_id, str) and request_id.startswith(("mpub1:", MODEL_PREFIX)):
        raise LifecycleConflict("request key belongs to the managed public operation namespace")


def _root_identity(value):
    # Permission samples may shorten the current monotonic deadline, but cannot
    # change this original canonical/task/profile relationship.
    return {name: item for name, item in value.items()
            if name not in {"monotonic_deadline", "boot_id"}}


def actor_id(identity):
    return "root" if identity["role"] == "root" else identity["child_id"]


def _deadline(expires_at, monotonic_cutoff, boot_id):
    finite(expires_at, 0, 1e15, code="state_conflict")
    finite(monotonic_cutoff, 0, 1e15, code="state_conflict")
    if not isinstance(boot_id, str) or not boot_id:
        _conflict()


def remaining(value, current_boot, now=None, wall=None):
    now = time.monotonic() if now is None else now
    wall = time.time() if wall is None else wall
    if value["boot_id"] != current_boot:
        return 0
    return max(0, min(value["expires_at"] - wall, value["monotonic_cutoff"] - now))


class PublicStore:
    def __init__(self, journal):
        self.journal = journal

    @staticmethod
    def _rows(db, table, worker_id):
        key = PUBLIC_TABLES[table][1]
        result = {}
        for row in db.execute(
            "SELECT * FROM " + table + " WHERE worker_id=? ORDER BY rowid",
            (worker_id,),
        ):
            value = _decode(row)
            if value.get(key) != row[key] or row[key] in result:
                _conflict()
            result[row[key]] = value
        return result

    @staticmethod
    def _identity(db, header, identity):
        fields(identity, IDENTITY_FIELDS, code="state_conflict")
        integer(identity["schema_version"], 1, 1, code="state_conflict")
        root = header["root"]
        if root is None or any(identity[name] != root[other] for name, other in (
            ("worker_id", "worker_id"), ("root_attempt_id", "attempt_id"),
            ("task_id", "task_id"), ("requirements_revision", "requirements_revision"),
            ("profile_digest", "profile_digest"),
        )):
            _conflict()
        if (
            identity["protocol"] != PROTOCOL
            or identity["child_policy_digest"] != header["policy_digest"]
            or identity["role"] not in {"root", "child"}
        ):
            _conflict()
        integer(identity["uid"], 1, 65535, code="state_conflict")
        matches(CHILD_ID, identity["exec_id"], code="state_conflict")
        matches(HEX64, identity["instructions_digest"], code="state_conflict")
        if identity["role"] == "root":
            if identity["child_id"] is not None or identity["grant_digest"] is not None:
                _conflict()
            return
        matches(CHILD_ID, identity["child_id"], code="state_conflict")
        matches(HEX64, identity["grant_digest"], code="state_conflict")
        row = db.execute(
            "SELECT * FROM children WHERE worker_id=? AND child_id=?",
            (root["worker_id"], identity["child_id"]),
        ).fetchone()
        if (
            row is None or not row["exec_dispatched"]
            or row["uid"] != identity["uid"] or row["exec_id"] != identity["exec_id"]
        ):
            _conflict()
        grant = object_value(row["grant_json"], 1048576, code="state_conflict", retained=True)
        binding = grant["binding"]
        if (
            binding["grant_digest"] != identity["grant_digest"]
            or binding["instructions_digest"] != identity["instructions_digest"]
            or binding["child_id"] != identity["child_id"]
            or binding["root_attempt_id"] != root["attempt_id"]
            or binding["parent_attempt_id"] != root["attempt_id"]
            or binding["task_id"] != root["task_id"]
            or binding["requirements_revision"] != root["requirements_revision"]
        ):
            _conflict()

    @staticmethod
    def _scope(header):
        public = header["policy"]
        swarm_id = public["server"]["scope_key_sha256"]
        return {
            "topic": public["topic"], "swarm_id": swarm_id,
            "session_id": digest([
                "polyphony-public-conversation-v1", swarm_id, public["topic"],
            ]),
        }

    @staticmethod
    def _slot_identity(header, actor, request):
        payload = request["payload"]
        return digest([
            PROTOCOL, header["root"]["worker_id"], header["root"]["attempt_id"],
            actor["actor_id"], request["request_id"], header["policy_digest"],
            payload["persona_key"], payload["instruction_key"],
            payload["selected_message_ids"], payload["reply_to"],
        ])

    def _checked(self, db, worker_id, policy=None):
        try:
            return self._checked_state(db, worker_id, policy)
        except (ManagedPublicError, DiscussionError, KeyError, TypeError,
                ValueError, OverflowError, RecursionError):
            _conflict()

    def _checked_state(self, db, worker_id, policy=None):
        if not optional_schema(db) & PUBLIC_SCHEMA_BIT:
            _conflict()
        header = _decode(db.execute(
            "SELECT * FROM public_workers WHERE worker_id=?", (worker_id,),
        ).fetchone())
        fields(header, WORKER_FIELDS, code="state_conflict")
        integer(header["schema_version"], 1, 1, code="state_conflict")
        approved = PublicPolicy.parse(header["policy"])
        worker = db.execute(
            "SELECT * FROM workers WHERE worker_id=?", (worker_id,),
        ).fetchone()
        if (
            worker is None or header["protocol"] != PROTOCOL
            or header["policy_digest"] != worker["policy_digest"]
            or (policy is not None and (
                policy.public_discussion is None
                or header["policy_digest"] != policy.fingerprint
                or approved.encoded != canonical(policy.public_discussion)
            ))
            or type(header["closed"]) is not bool
        ):
            _conflict()
        root = header["root"]
        if root is not None:
            current = object_value(
                worker["context"], 65536, code="state_conflict", retained=True,
            )
            RootContext.from_dict(root)
            if (
                root["worker_id"] != worker_id
                or _root_identity(root) != _root_identity(current)
                or (root["boot_id"] == current["boot_id"]
                    and current["monotonic_deadline"] > root["monotonic_deadline"])
            ):
                _conflict()
        bundle = {"header": header, "policy": approved}
        for short, table, maximum in (
            ("actors", "public_actors", ACTOR_LIMIT),
            ("requests", "public_requests", OWNER_LIMIT),
            ("slots", "public_slots", SLOT_LIMIT),
            ("records", "public_records", TRANSCRIPT_LIMIT),
            ("processes", "public_processes", ACTOR_LIMIT * 2 * 2),
        ):
            values = self._rows(db, table, worker_id)
            integer(header[short], 0, maximum, code="state_conflict")
            if header[short] != len(values) or (root is None and values):
                _conflict()
            bundle[short] = values
        actors, requests, slots = bundle["actors"], bundle["requests"], bundle["slots"]
        scope = self._scope(header)
        seen_authors, seen_streams = set(), set()
        for key, actor in actors.items():
            fields(actor, ACTOR_FIELDS, code="state_conflict")
            self._identity(db, header, actor["identity"])
            if (
                key != actor_id(actor["identity"])
                or digest(actor["identity"]) != actor["identity_digest"]
                or type(actor["closed"]) is not bool
                or (actor["status"] is None) != (actor["binding_digest"] is None)
                or (actor["status"] is None) != (actor["binding"] is None)
            ):
                _conflict()
            integer(actor["generations"], 0, 2, code="state_conflict")
            if actor["status"] is not None:
                validate_status(actor["status"], scope["topic"])
                if (
                    actor["status"]["swarm_id"] != scope["swarm_id"]
                    or actor["status"]["author"] in seen_authors
                    or actor["status"]["stream_id"] in seen_streams
                    or actor["binding"]["identity"] != actor["identity"]
                    or actor["binding"]["status"] != actor["status"]
                    or digest(actor["binding"]) != actor["binding_digest"]
                ):
                    _conflict()
                seen_authors.add(actor["status"]["author"])
                seen_streams.add(actor["status"]["stream_id"])
            if actor["leave_slot"] is not None:
                leaving = slots.get(actor["leave_slot"])
                if (
                    not actor["closed"] or leaving is None
                    or leaving["actor_id"] != key
                    or leaving["publication_intent"] is None
                    or leaving["publication_intent"]["kind"] != "leave"
                ):
                    _conflict()
            self._check_configuration(header, actor)
        history = pages = invitations = 0
        for key, request in requests.items():
            fields(request, REQUEST_FIELDS, code="state_conflict")
            matches(REQUEST_ID, key, code="state_conflict")
            actor = actors.get(request["actor_id"])
            if actor is None:
                _conflict()
            validate_request(request["payload"], actor["identity"]["role"])
            if (
                request["payload"]["request_id"] != key
                or digest(request["payload"]) != request["payload_digest"]
                or request["state"] not in {"accepted", "complete", "refused", "uncertain"}
                or request["error"] not in CODES | {None}
                or (request["state"] == "refused" and request["error"] is None)
            ):
                _conflict()
            _deadline(request["expires_at"], request["monotonic_cutoff"], request["boot_id"])
            if (
                request["boot_id"] != root["boot_id"]
                or request["monotonic_cutoff"] > root["monotonic_deadline"]
                or request["expires_at"] > root["deadline"]
            ):
                _conflict()
            for name in ("history_charges", "page_charges"):
                integer(request[name], 0, 1, code="state_conflict")
            if request["history_charges"] or request["page_charges"]:
                if request["payload"]["operation"] != "public_read":
                    _conflict()
            history += request["history_charges"]
            pages += request["page_charges"]
            if request["slot_id"] is not None:
                slot = slots.get(request["slot_id"])
                if slot is None:
                    _conflict()
                operation = request["payload"]["operation"]
                if operation in {"public_pull", "public_decline", "public_status"}:
                    if slot["slot_id"] != request["payload"]["slot_id"]:
                        _conflict()
                elif operation not in {"public_activate", "public_turn"}:
                    _conflict()
                if actor["identity"]["role"] == "child" and slot["actor_id"] != actor["actor_id"]:
                    _conflict()
            if request["invitation"] is not None:
                invitations += 1
                self._check_invitation(header, actor, request)
                receipt = request["invitation"]["receipt"]
                if receipt is not None and bundle["records"].get(receipt["message_id"]) != receipt["record"]:
                    _conflict()
            if request["result"] is not None:
                if request["payload"]["operation"] != "public_read" or actor["status"] is None:
                    _conflict()
                discussion_page = request["result"]
                from .discussion_types import validate_history
                validate_history(discussion_page, actor["status"], request["payload"]["after"])
                if (
                    request["payload"]["stream_id"] not in {None, actor["status"]["stream_id"]}
                    and discussion_page["gap"] is None
                ):
                    _conflict()
                for item in discussion_page["messages"]:
                    saved = bundle["records"].get(item["record"]["message_id"])
                    if saved != item["record"]:
                        _conflict()
        for key, slot in slots.items():
            fields(slot, SLOT_FIELDS, code="state_conflict")
            actor = actors.get(slot["actor_id"])
            activation = requests.get(slot["activation_request_id"])
            if actor is None or activation is None:
                _conflict()
            payload = activation["payload"]
            expected_actor = "root" if payload["operation"] == "public_turn" else payload.get("child_id")
            if (
                payload["operation"] not in {"public_activate", "public_turn"}
                or activation["actor_id"] != "root"
                or slot["activation_actor_id"] != "root"
                or activation["slot_id"] != key
                or expected_actor != slot["actor_id"]
                or key != self._slot_identity(header, actor, activation)
                or any(slot[name] != payload[name] for name in (
                    "persona_key", "instruction_key", "selected_message_ids", "reply_to",
                ))
                or slot["persona_key"] not in approved.document["personas"]
                or slot["instruction_key"] not in approved.document["instructions"]
                or slot["state"] not in SLOT_STATES
                or slot["reason"] not in CODES | {None, "refused_left"}
                or slot["model_key"] != model_key(
                    worker_id, root["attempt_id"], actor["actor_id"],
                    activation["request_id"], key,
                )
            ):
                _conflict()
            _deadline(slot["expires_at"], slot["monotonic_cutoff"], slot["boot_id"])
            if (
                slot["expires_at"] > activation["expires_at"]
                or slot["monotonic_cutoff"] > activation["monotonic_cutoff"]
                or slot["boot_id"] != activation["boot_id"]
            ):
                _conflict()
            own_slots = [item for item in slots.values() if item["actor_id"] == actor["actor_id"]]
            if len(own_slots) > ACTOR_SLOT_LIMIT:
                _conflict()
            if slot["decision_request_id"] is not None:
                decision = requests.get(slot["decision_request_id"])
                if (
                    decision is None or decision["slot_id"] != key
                    or decision["actor_id"] != actor["actor_id"]
                    or decision["payload"]["operation"] not in {
                        "public_pull", "public_decline", "public_turn",
                    }
                ):
                    _conflict()
            integer(slot["history_charges"], 0, 1, code="state_conflict")
            integer(slot["page_charges"], 0, 8, code="state_conflict")
            history += slot["history_charges"]
            pages += slot["page_charges"]
            if (slot["context"] is None) != (slot["context_digest"] is None):
                _conflict()
            if slot["context"] is not None:
                if (
                    actor["status"] is None or not isinstance(slot["context"], list)
                    or len(slot["context"]) > SELECTED_LIMIT
                    or sum(len(canonical(item)) for item in slot["context"]) > SELECTED_BYTES
                    or digest(slot["context"]) != slot["context_digest"]
                    or {item["message_id"] for item in slot["context"]}
                    != set(slot["selected_message_ids"])
                    or len(slot["context"]) != len(slot["selected_message_ids"])
                ):
                    _conflict()
                for record in slot["context"]:
                    verify_record(record, actor["status"])
                    if bundle["records"].get(record["message_id"]) != record:
                        _conflict()
            if slot["model_call_digest"] is not None:
                if digest(public_model_payload(approved, actor, slot)) != slot["model_call_digest"]:
                    _conflict()
            if slot["response"] is not None:
                from .discussion_types import validate_output
                from .managed_public_types import DECLINE_TEXT
                validate_output(slot["response"])
                decision = requests.get(slot["decision_request_id"])
                if decision is None:
                    _conflict()
                if decision["payload"]["operation"] == "public_decline":
                    if (
                        slot["model_call_digest"] is not None
                        or slot["response"] != {"kind": "decline", "content": DECLINE_TEXT}
                    ):
                        _conflict()
                elif slot["model_call_digest"] is None:
                    _conflict()
                intent = signed_intent(
                    actor["status"], publication_key(key), slot["response"]["kind"],
                    slot["response"]["content"], reply_to=slot["reply_to"],
                )
                if slot["publication_intent"] != intent:
                    _conflict()
            elif slot["publication_intent"] is not None:
                _conflict()
            if slot["state"] == "leave_pending" and not actor["closed"]:
                _conflict()
            if slot["state"] in SUCCESSFUL:
                if (
                    slot["receipt"] is None or slot["publication_intent"] is None
                    or slot["publication_intent"]["kind"] != SUCCESSFUL[slot["state"]]
                    or (slot["state"] == "left" and not actor["closed"])
                ):
                    _conflict()
                validate_receipt(slot["receipt"], actor["status"], slot["publication_intent"])
                record = slot["receipt"]["record"]
                if bundle["records"].get(record["message_id"]) != record:
                    _conflict()
            elif slot["receipt"] is not None:
                _conflict()
        for key, record in bundle["records"].items():
            verify_record(record, scope)
            if record["message_id"] != key:
                _conflict()
        for name, maximum in (
            ("history_charges", HISTORY_LIMIT), ("page_charges", PAGE_LIMIT),
            ("post_reservations", 7), ("transcript_bytes", TRANSCRIPT_BYTES),
        ):
            integer(header[name], 0, maximum, code="state_conflict")
        used = sum(len(canonical(record)) for record in bundle["records"].values())
        outstanding = self._outstanding_posts(bundle)
        if (
            invitations > 1 or header["post_reservations"] != len(slots) + invitations
            or header["post_reservations"] > 7
            or header["history_charges"] != history or history > HISTORY_LIMIT
            or header["page_charges"] != pages or pages > PAGE_LIMIT
            or header["transcript_bytes"] != used
            or used + outstanding * RECORD_LIMIT > TRANSCRIPT_BYTES
            or len(bundle["records"]) + outstanding > TRANSCRIPT_LIMIT
        ):
            _conflict()
        self._check_processes(bundle)
        if (header["frozen"] is None) != (header["freeze_digest"] is None):
            _conflict()
        if header["frozen"] is not None:
            if not header["closed"] or digest(header["frozen"]) != header["freeze_digest"]:
                _conflict()
            if header["frozen"] != self._snapshot(bundle):
                _conflict()
        return bundle

    def _check_configuration(self, header, actor):
        config = actor["config"]
        if config is None:
            if actor["binding"] is not None or actor["generations"]:
                _conflict()
            return
        fields(config, {
            "state", "path", "state_directory", "document", "sha256", "server_binding",
        }, code="state_conflict")
        base = (
            self.journal.root / "public"
            / digest([header["root"]["worker_id"], header["root"]["attempt_id"]])
            / actor["identity_digest"]
        )
        expected = {
            "schema_version": 1, "topic": header["policy"]["topic"],
            "scope_key_file": header["policy"]["server"]["scope_key_file"],
            "state_directory": str(base / "state"),
        }
        if "bootstrap" in header["policy"]["server"]:
            expected["bootstrap"] = header["policy"]["server"]["bootstrap"]
        if (
            config["state"] not in {"preparing", "ready"}
            or config["path"] != str(base / "profile.json")
            or config["state_directory"] != str(base / "state")
            or config["document"] != expected
            or digest(config["document"]) != config["sha256"]
        ):
            _conflict()
        server = fields(config["server_binding"], {
            "launch_path", "resolved_executable", "executable_device",
            "executable_inode", "executable_size", "executable_mtime_ns",
            "cwd", "cwd_device", "cwd_inode", "scope",
        }, code="state_conflict")
        approved = header["policy"]["server"]
        if server["launch_path"] != approved["python"] or server["cwd"] != approved["cwd"]:
            _conflict()
        absolute_path(server["resolved_executable"], code="state_conflict")
        for name in (
            "executable_device", "executable_inode", "executable_size",
            "executable_mtime_ns", "cwd_device", "cwd_inode",
        ):
            integer(server[name], 0, (1 << 127) - 1, code="state_conflict")
        scope = fields(server["scope"], {
            "path", "sha256", "device", "inode", "mode", "uid",
        }, code="state_conflict")
        if scope["path"] != approved["scope_key_file"] or scope["sha256"] != approved["scope_key_sha256"]:
            _conflict()
        for name in ("device", "inode", "uid"):
            integer(scope[name], 0, (1 << 127) - 1, code="state_conflict")
        integer(scope["mode"], 0, 0o777, code="state_conflict")
        if scope["mode"] not in {0o400, 0o600}:
            _conflict()
        if actor["binding"] is not None:
            binding = fields(actor["binding"], {
                "schema_version", "identity", "config_sha256",
                "server", "interpreter", "status",
            }, code="state_conflict")
            integer(binding["schema_version"], 1, 1, code="state_conflict")
            interpreter = fields(binding["interpreter"], {
                "schema_version", "launch_path", "resolved_executable", "prefix",
            }, code="state_conflict")
            integer(interpreter["schema_version"], 1, 1, code="state_conflict")
            absolute_path(interpreter["prefix"], code="state_conflict")
            if (
                config["state"] != "ready"
                or binding["config_sha256"] != config["sha256"]
                or binding["server"] != server
                or interpreter["launch_path"] != server["launch_path"]
                or interpreter["resolved_executable"] != server["resolved_executable"]
            ):
                _conflict()

    @staticmethod
    def _check_invitation(header, actor, request):
        value = request["invitation"]
        fields(value, {
            "invitation_key", "publication_request_key", "state", "reason",
            "intent", "receipt",
        }, code="state_conflict")
        key = request["payload"].get("invitation_key")
        if (
            request["payload"]["operation"] != "public_invite"
            or actor["actor_id"] != "root"
            or key != value["invitation_key"]
            or key not in header["policy"]["invitations"]
            or value["state"] not in {
                "publication_pending", "published", "expired", "refused", "uncertain",
            }
            or value["reason"] not in CODES | {None}
        ):
            _conflict()
        if actor["status"] is None:
            if value["publication_request_key"] is not None or value["intent"] is not None:
                _conflict()
        else:
            expected = invitation_key(actor["status"]["author"], key, request["request_id"])
            if value["publication_request_key"] != expected or value["intent"] is None:
                _conflict()
            if value["intent"] is not None:
                approved = header["policy"]["invitations"][key]
                if value["intent"] != signed_intent(
                    actor["status"], expected, "invite", approved["content"],
                    target=approved["target"],
                ):
                    _conflict()
        if value["state"] == "published":
            if value["receipt"] is None or value["intent"] is None:
                _conflict()
            validate_receipt(value["receipt"], actor["status"], value["intent"])
        elif value["receipt"] is not None:
            _conflict()

    @staticmethod
    def _check_processes(bundle):
        actors = bundle["actors"]
        generations = {key: set() for key in actors}
        for key, process in bundle["processes"].items():
            fields(process, PROCESS_FIELDS, code="state_conflict")
            actor = actors.get(process["actor_id"])
            if actor is None:
                _conflict()
            integer(process["generation"], 1, 2, code="state_conflict")
            if (
                process["stage"] not in {"probe", "server"}
                or process["state"] not in {"intent", "running", "stopped", "unknown"}
                or digest(process["intent"]) != process["intent_digest"]
                or key != digest([
                    process["actor_id"], process["generation"], process["stage"],
                ])
            ):
                _conflict()
            intent = fields(process["intent"], {
                "schema_version", "stage", "launch_path", "cwd", "config_sha256",
                "argv_sha256", "environment_sha256", "monotonic_cutoff", "boot_id",
            }, {"leave_recovery"}, code="state_conflict")
            integer(intent["schema_version"], 1, 1, code="state_conflict")
            finite(intent["monotonic_cutoff"], 0, 1e15, code="state_conflict")
            matches(HEX64, intent["argv_sha256"], code="state_conflict")
            matches(HEX64, intent["environment_sha256"], code="state_conflict")
            config = actor["config"]
            if (
                config is None or config["state"] != "ready"
                or intent["stage"] != process["stage"]
                or intent["launch_path"] != config["server_binding"]["launch_path"]
                or intent["cwd"] != config["server_binding"]["cwd"]
                or intent["config_sha256"] != config["sha256"]
                or not isinstance(intent["boot_id"], str) or not intent["boot_id"]
                or intent["boot_id"] != bundle["header"]["root"]["boot_id"]
                or intent["monotonic_cutoff"] > bundle["header"]["root"]["monotonic_deadline"]
            ):
                _conflict()
            if "leave_recovery" in intent:
                retained_recovery = fields(intent["leave_recovery"], {
                    "schema_version", "slot_id", "decision_request_id",
                    "request_payload_digest", "publication_intent_digest", "actor_binding_digest",
                }, code="state_conflict")
                integer(retained_recovery["schema_version"], 1, 1, code="state_conflict")
                recovery = PublicStore._leave_recovery(
                    bundle, actor["actor_id"], intent["leave_recovery"].get("slot_id")
                    if isinstance(intent["leave_recovery"], dict) else None,
                )
                decision = bundle["requests"][recovery["decision_request_id"]]
                slot = bundle["slots"][recovery["slot_id"]]
                if (
                    process["generation"] != 2 or intent["leave_recovery"] != recovery
                    or intent["monotonic_cutoff"] > min(
                        slot["monotonic_cutoff"], decision["monotonic_cutoff"],
                    )
                ):
                    _conflict()
            generations[process["actor_id"]].add(process["generation"])
            identity = process["identity"]
            if identity is not None:
                fields(identity, {"pid", "starttime", "pgid", "boot_id"}, code="state_conflict")
                integer(identity["pid"], 1, (1 << 31) - 1, code="state_conflict")
                integer(identity["starttime"], 1, (1 << 63) - 1, code="state_conflict")
                integer(identity["pgid"], 1, (1 << 31) - 1, code="state_conflict")
                if identity["pgid"] != identity["pid"] or identity["boot_id"] != intent["boot_id"]:
                    _conflict()
            if process["state"] == "intent" and identity is not None:
                _conflict()
            if process["state"] == "running" and identity is None:
                _conflict()
            if process["state"] == "stopped":
                cleanup = fields(process["cleanup"], {
                    "identity", "leader_terminated", "leader_reaped", "group_terminated",
                }, code="state_conflict")
                if (
                    identity is None or cleanup["identity"] != identity
                    or cleanup["leader_terminated"] is not True
                    or cleanup["group_terminated"] is not True
                    or type(cleanup["leader_reaped"]) is not bool
                ):
                    _conflict()
            elif process["cleanup"] is not None:
                _conflict()
        for key, actor in actors.items():
            if generations[key] != set(range(1, actor["generations"] + 1)):
                _conflict()
            for generation in generations[key]:
                current = {
                    item["stage"]: item for item in bundle["processes"].values()
                    if item["actor_id"] == key and item["generation"] == generation
                }
                if "probe" not in current or (
                    "server" in current and current["probe"]["state"] != "stopped"
                ):
                    _conflict()
                if "server" in current and (
                    current["server"]["intent"].get("leave_recovery")
                    != current["probe"]["intent"].get("leave_recovery")
                ):
                    _conflict()
                previous = [
                    item for item in bundle["processes"].values()
                    if item["actor_id"] == key and item["generation"] < generation
                ]
                if any(item["state"] != "stopped" for item in previous):
                    _conflict()

    @contextmanager
    def _transaction(self, root, policy, *, write=True):
        try:
            with self.journal.connection() as db:
                if write:
                    db.execute("BEGIN IMMEDIATE")
                bundle = self._checked(db, root.worker_id, policy)
                header = bundle["header"]
                if header["root"] is None:
                    if not write or header["frozen"] is not None:
                        _conflict()
                    current = self.journal.context(root.worker_id)
                    if current.to_dict() != root.to_dict():
                        _conflict()
                    header["root"] = root.to_dict()
                    _save(db, "public_workers", root.worker_id, None, header)
                elif _root_identity(header["root"]) != _root_identity(root.to_dict()):
                    _conflict()
                yield db, bundle
                if write:
                    self._checked(db, root.worker_id, policy)
        except (DiscussionError, KeyError, TypeError, ValueError, OverflowError, RecursionError):
            _conflict()

    def view(self, root, policy):
        with self._transaction(root, policy) as (_db, bundle):
            return bundle

    @staticmethod
    def project_actor(actor):
        return {
            "role": actor["identity"]["role"], "child_id": actor["identity"]["child_id"],
            "binding_digest": actor["binding_digest"], "status": actor["status"],
            "admission_closed": actor["closed"],
        }

    @classmethod
    def project_slot(cls, bundle, slot_id):
        slot = bundle["slots"][slot_id]
        return {
            "slot_id": slot_id, "actor": cls.project_actor(bundle["actors"][slot["actor_id"]]),
            **{name: slot[name] for name in (
                "activation_request_id", "persona_key", "instruction_key",
                "selected_message_ids", "reply_to", "expires_at", "state", "reason",
                "context_digest", "model_call_digest", "receipt",
            )},
            "publication_request_key": publication_key(slot_id),
        }


    @staticmethod
    def _save_header(db, bundle):
        header = bundle["header"]
        _save(db, "public_workers", header["root"]["worker_id"], None, header)

    def _actor(self, db, bundle, identity):
        self._identity(db, bundle["header"], identity)
        key = actor_id(identity)
        old = bundle["actors"].get(key)
        if old is not None:
            if old["identity"] != identity:
                raise ManagedPublicError("conflict")
            return old
        if (
            bundle["header"]["actors"] >= ACTOR_LIMIT
            or (identity["role"] == "child" and sum(
                item["identity"]["role"] == "child" for item in bundle["actors"].values()
            ) >= 2)
        ):
            raise ManagedPublicError("slot_limit")
        value = {
            "actor_id": key, "identity": identity, "identity_digest": digest(identity),
            "status": None, "binding": None, "binding_digest": None,
            "closed": False, "leave_slot": None, "config": None, "generations": 0,
        }
        _save(db, "public_actors", identity["worker_id"], key, value, insert=True)
        bundle["actors"][key] = value
        bundle["header"]["actors"] += 1
        return value

    def accept(self, root, policy, identity, payload, cutoff, *, now=None, wall=None):
        """Own the exact actor/operation/key before any external effect."""
        now = time.monotonic() if now is None else now
        wall = time.time() if wall is None else wall
        validate_request(payload, identity["role"])
        finite(cutoff, 0, 1e15)
        with self._transaction(root, policy) as (db, bundle):
            header = bundle["header"]
            key, who = payload["request_id"], actor_id(identity)
            old = bundle["requests"].get(key)
            if old is not None:
                self._identity(db, header, identity)
                if (
                    old["actor_id"] != who or old["payload"] != payload
                    or bundle["actors"][who]["identity"] != identity
                ):
                    raise ManagedPublicError("conflict")
                return old
            if header["closed"] or header["frozen"] is not None:
                raise ManagedPublicError("not_authorized")
            # Lookup is above the cap: original keys remain usable at saturation.
            if header["requests"] >= OWNER_LIMIT:
                raise ManagedPublicError("request_limit")
            duration = min(
                PUBLIC_SECONDS, cutoff - now, root.monotonic_deadline - now,
                root.deadline - wall,
            )
            if payload["operation"] == "public_read":
                duration = min(duration, 15)
            if duration <= 0:
                raise ManagedPublicError("expired")
            self._actor(db, bundle, identity)
            value = {
                "request_id": key, "actor_id": who, "payload": payload,
                "payload_digest": digest(payload), "expires_at": wall + duration,
                "monotonic_cutoff": now + duration, "boot_id": root.boot_id,
                "state": "accepted", "error": None, "result": None, "slot_id": None,
                "history_charges": 0, "page_charges": 0, "invitation": None,
            }
            _save(db, "public_requests", root.worker_id, key, value, insert=True)
            bundle["requests"][key] = value
            header["requests"] += 1
            self._save_header(db, bundle)
            return value

    @staticmethod
    def _active(bundle, request, current_boot, now, wall):
        if bundle["header"]["closed"] or bundle["header"]["frozen"] is not None:
            raise ManagedPublicError("not_authorized")
        if remaining(request, current_boot, now, wall) <= 0:
            raise ManagedPublicError("expired")
        actor = bundle["actors"][request["actor_id"]]
        if actor["closed"]:
            raise ManagedPublicError("actor_left")

    @staticmethod
    def _outstanding_posts(bundle):
        # A receipt converts its original storage reservation to the actual
        # retained record. Unknown/unacknowledged posts still hold the maximum.
        # Lifetime post accounting is separate and is never decremented.
        return sum(slot["receipt"] is None for slot in bundle["slots"].values()) + sum(
            request["invitation"] is not None and request["invitation"]["receipt"] is None
            for request in bundle["requests"].values()
        )

    @staticmethod
    def _reserve_post(bundle):
        header = bundle["header"]
        outstanding = PublicStore._outstanding_posts(bundle)
        if (
            header["post_reservations"] >= 7
            or header["records"] + outstanding + 1 > TRANSCRIPT_LIMIT
            or header["transcript_bytes"] + (outstanding + 1) * RECORD_LIMIT > TRANSCRIPT_BYTES
        ):
            raise ManagedPublicError("transcript_limit")
        header["post_reservations"] += 1

    def offer(self, root, policy, request_id, target_identity, cutoff, *, now=None, wall=None):
        now = time.monotonic() if now is None else now
        wall = time.time() if wall is None else wall
        with self._transaction(root, policy) as (db, bundle):
            request = bundle["requests"][request_id]
            if request["payload"]["operation"] not in {"public_activate", "public_turn"}:
                raise ManagedPublicError("conflict")
            if request["slot_id"] is not None:
                return bundle["slots"][request["slot_id"]]
            self._active(bundle, request, root.boot_id, now, wall)
            payload = request["payload"]
            expected = "root" if payload["operation"] == "public_turn" else payload["child_id"]
            if actor_id(target_identity) != expected:
                raise ManagedPublicError("not_authorized")
            if (
                payload["persona_key"] not in bundle["header"]["policy"]["personas"]
                or payload["instruction_key"] not in bundle["header"]["policy"]["instructions"]
            ):
                raise ManagedPublicError("not_authorized")
            actor = self._actor(db, bundle, target_identity)
            if actor["closed"]:
                raise ManagedPublicError("actor_left")
            if (
                bundle["header"]["slots"] >= SLOT_LIMIT
                or sum(item["actor_id"] == expected for item in bundle["slots"].values())
                >= ACTOR_SLOT_LIMIT
            ):
                raise ManagedPublicError("slot_limit")
            boundary = min(cutoff, request["monotonic_cutoff"], root.monotonic_deadline)
            # Every previously armed child watchdog can still retire this root.
            for child in db.execute("SELECT * FROM children WHERE worker_id=?", (root.worker_id,)):
                if child["boot_id"] != root.boot_id:
                    raise ManagedPublicError("expired")
                boundary = min(boundary, child["deadline"])
                if child["armed_deadline"] is not None:
                    boundary = min(boundary, child["armed_deadline"])
            duration = min(boundary - now, request["expires_at"] - wall)
            if duration <= 0:
                raise ManagedPublicError("expired")
            key = self._slot_identity(bundle["header"], actor, request)
            self._reserve_post(bundle)
            value = {
                "slot_id": key, "actor_id": expected,
                "activation_request_id": request_id, "activation_actor_id": "root",
                **{name: payload[name] for name in (
                    "persona_key", "instruction_key", "selected_message_ids", "reply_to",
                )},
                "expires_at": wall + duration, "monotonic_cutoff": now + duration,
                "boot_id": root.boot_id, "state": "offered", "reason": None,
                "context": None, "context_digest": None,
                "model_key": model_key(root.worker_id, root.attempt_id, expected, request_id, key),
                "model_call_digest": None, "response": None, "publication_intent": None,
                "receipt": None, "history_charges": 0, "page_charges": 0,
                "decision_request_id": request_id if expected == "root" else None,
            }
            request["slot_id"] = key
            _save(db, "public_slots", root.worker_id, key, value, insert=True)
            _save(db, "public_requests", root.worker_id, request_id, request)
            bundle["slots"][key] = value
            bundle["header"]["slots"] += 1
            self._save_header(db, bundle)
            return value

    def claim(self, root, policy, request_id, slot_id):
        with self._transaction(root, policy) as (db, bundle):
            request = bundle["requests"][request_id]
            slot = bundle["slots"].get(slot_id)
            if slot is None:
                raise ManagedPublicError("not_authorized")
            operation = request["payload"]["operation"]
            if operation not in {"public_pull", "public_decline", "public_turn", "public_status"}:
                raise ManagedPublicError("conflict")
            if (
                request["actor_id"] != slot["actor_id"]
                and not (operation == "public_status" and request["actor_id"] == "root")
            ):
                raise ManagedPublicError("not_authorized")
            if request["slot_id"] not in {None, slot_id}:
                raise ManagedPublicError("conflict")
            if operation != "public_status":
                if slot["decision_request_id"] not in {None, request_id}:
                    raise ManagedPublicError("conflict")
                if slot["decision_request_id"] is None:
                    self._active(bundle, request, root.boot_id, time.monotonic(), time.time())
                    if slot["state"] != "offered":
                        raise ManagedPublicError("conflict")
                    slot["decision_request_id"] = request_id
                    _save(db, "public_slots", root.worker_id, slot_id, slot)
            request["slot_id"] = slot_id
            _save(db, "public_requests", root.worker_id, request_id, request)
            return slot

    def failure(self, root, policy, request_id, code, *, slot_id=None, uncertain=False):
        if code not in CODES:
            raise ManagedPublicError("state_conflict")
        with self._transaction(root, policy) as (db, bundle):
            if bundle["header"]["frozen"] is not None:
                return
            request = bundle["requests"][request_id]
            if request["result"] is not None:
                return
            request["state"] = "uncertain" if uncertain else "refused"
            request["error"] = code
            _save(db, "public_requests", root.worker_id, request_id, request)
            if slot_id is not None:
                slot = bundle["slots"][slot_id]
                if slot["state"] not in TERMINAL:
                    slot["state"] = "uncertain" if uncertain else (
                        "expired" if code == "expired" else "refused"
                    )
                    slot["reason"] = code
                    _save(db, "public_slots", root.worker_id, slot_id, slot)

    def charge_history(self, root, policy, request_id, *, slot_id=None):
        """Charge before each actual history/watch RPC, including failed RPCs."""
        with self._transaction(root, policy) as (db, bundle):
            request = bundle["requests"][request_id]
            self._active(bundle, request, root.boot_id, time.monotonic(), time.time())
            value = request if slot_id is None else bundle["slots"][slot_id]
            if slot_id is None:
                if request["payload"]["operation"] != "public_read" or request["page_charges"]:
                    # An unknown dispatched read is not repeated on restart.
                    raise ManagedPublicError("publication_uncertain")
                limit = 1
            else:
                if value["decision_request_id"] != request_id or value["context"] is not None:
                    raise ManagedPublicError("conflict")
                if remaining(value, root.boot_id) <= 0:
                    raise ManagedPublicError("expired")
                limit = 8
            header = bundle["header"]
            history = 1 if value["history_charges"] == 0 else 0
            if (
                header["history_charges"] + history > HISTORY_LIMIT
                or header["page_charges"] >= PAGE_LIMIT
                or value["page_charges"] >= limit
            ):
                raise ManagedPublicError("transcript_limit")
            value["history_charges"] += history
            value["page_charges"] += 1
            header["history_charges"] += history
            header["page_charges"] += 1
            _save(db, "public_requests" if slot_id is None else "public_slots",
                  root.worker_id, request_id if slot_id is None else slot_id, value)
            self._save_header(db, bundle)

    @staticmethod
    def _records(db, bundle, records):
        header = bundle["header"]
        scope = PublicStore._scope(header)
        outstanding = PublicStore._outstanding_posts(bundle)
        for record in records:
            verify_record(record, scope)
            key = record["message_id"]
            old = bundle["records"].get(key)
            if old is not None:
                if old != record:
                    _conflict()
                continue
            size = len(canonical(record))
            if (
                header["records"] + outstanding + 1 > TRANSCRIPT_LIMIT
                or header["transcript_bytes"] + size + outstanding * RECORD_LIMIT > TRANSCRIPT_BYTES
            ):
                raise ManagedPublicError("transcript_limit")
            _save(db, "public_records", header["root"]["worker_id"], key, record, insert=True)
            bundle["records"][key] = record
            header["records"] += 1
            header["transcript_bytes"] += size

    def retain_page(self, root, policy, request_id, page):
        from .discussion_types import validate_history
        with self._transaction(root, policy) as (db, bundle):
            request = bundle["requests"][request_id]
            actor = bundle["actors"][request["actor_id"]]
            if request["payload"]["operation"] != "public_read" or request["page_charges"] != 1:
                raise ManagedPublicError("conflict")
            validate_history(page, actor["status"], request["payload"]["after"])
            if request["result"] is not None:
                if request["result"] != page:
                    raise ManagedPublicError("conflict")
                return page
            # Acknowledgement persistence is allowed after dispatch expiry.
            if bundle["header"]["frozen"] is not None:
                _conflict()
            self._records(db, bundle, [item["record"] for item in page["messages"]])
            request["result"] = page
            request["state"], request["error"] = "complete", None
            _save(db, "public_requests", root.worker_id, request_id, request)
            self._save_header(db, bundle)
            return page

    def freeze_context(self, root, policy, slot_id, records):
        with self._transaction(root, policy) as (db, bundle):
            slot = bundle["slots"][slot_id]
            if slot["context"] is not None:
                if slot["context"] != records:
                    raise ManagedPublicError("conflict")
                return slot
            if (
                slot["decision_request_id"] is None or slot["state"] != "offered"
                or len(records) > SELECTED_LIMIT
                or {item["message_id"] for item in records} != set(slot["selected_message_ids"])
                or len(records) != len(slot["selected_message_ids"])
                or sum(len(canonical(item)) for item in records) > SELECTED_BYTES
            ):
                raise ManagedPublicError("context_unavailable")
            self._records(db, bundle, records)
            slot["context"], slot["context_digest"] = records, digest(records)
            slot["state"] = "context_frozen"
            _save(db, "public_slots", root.worker_id, slot_id, slot)
            self._save_header(db, bundle)
            return slot

    def model_intent(self, root, policy, slot_id):
        with self._transaction(root, policy) as (db, bundle):
            slot = bundle["slots"][slot_id]
            actor = bundle["actors"][slot["actor_id"]]
            request = bundle["requests"][slot["decision_request_id"]]
            if slot["model_call_digest"] is None:
                self._active(bundle, request, root.boot_id, time.monotonic(), time.time())
                if slot["state"] != "context_frozen" or remaining(slot, root.boot_id) <= 0:
                    raise ManagedPublicError("expired")
                slot["model_call_digest"] = digest(public_model_payload(bundle["policy"], actor, slot))
                slot["state"] = "model_pending"
                _save(db, "public_slots", root.worker_id, slot_id, slot)
            return public_model_payload(bundle["policy"], actor, slot)

    def retain_response(self, root, policy, slot_id, output, *, fixed_decline=False):
        from .discussion_types import validate_output
        from .managed_public_types import DECLINE_TEXT
        validate_output(output)
        with self._transaction(root, policy) as (db, bundle):
            slot = bundle["slots"][slot_id]
            actor = bundle["actors"][slot["actor_id"]]
            request = bundle["requests"][slot["decision_request_id"]]
            if slot["response"] is not None:
                if slot["response"] != output:
                    raise ManagedPublicError("conflict")
                return slot
            if bundle["header"]["frozen"] is not None:
                _conflict()
            if fixed_decline:
                if (
                    request["payload"]["operation"] != "public_decline"
                    or slot["model_call_digest"] is not None
                    or output != {"kind": "decline", "content": DECLINE_TEXT}
                ):
                    raise ManagedPublicError("conflict")
            elif slot["model_call_digest"] is None:
                _conflict()
            intent = signed_intent(
                actor["status"], publication_key(slot_id), output["kind"], output["content"],
                reply_to=slot["reply_to"],
            )
            slot["response"], slot["publication_intent"] = output, intent
            if slot["state"] not in {"expired", "refused"}:
                slot["state"], slot["reason"] = "response_retained", None
            if output["kind"] == "leave":
                if actor["leave_slot"] not in {None, slot_id}:
                    raise ManagedPublicError("conflict")
                unresolved = [
                    item for item in bundle["slots"].values()
                    if item["actor_id"] == actor["actor_id"] and item["slot_id"] != slot_id
                    and item["publication_intent"] is not None
                    and item["state"] not in set(SUCCESSFUL) | {"expired", "refused"}
                ]
                unresolved_invitation = any(
                    item["actor_id"] == actor["actor_id"]
                    and item["invitation"] is not None
                    and item["invitation"]["state"] in {"publication_pending", "uncertain"}
                    for item in bundle["requests"].values()
                )
                if unresolved or unresolved_invitation:
                    raise ManagedPublicError("publication_uncertain")
                actor["closed"], actor["leave_slot"] = True, slot_id
                for other in bundle["slots"].values():
                    if (
                        other["actor_id"] == actor["actor_id"]
                        and other["slot_id"] != slot_id
                        and other["state"] in {"offered", "context_frozen"}
                        and other["model_call_digest"] is None
                    ):
                        other["state"], other["reason"] = "refused", "refused_left"
                        _save(db, "public_slots", root.worker_id, other["slot_id"], other)
                _save(db, "public_actors", root.worker_id, actor["actor_id"], actor)
            _save(db, "public_slots", root.worker_id, slot_id, slot)
            return slot

    def publication_intent(self, root, policy, slot_id):
        with self._transaction(root, policy) as (db, bundle):
            slot = bundle["slots"][slot_id]
            actor = bundle["actors"][slot["actor_id"]]
            if slot["state"] in SUCCESSFUL:
                return slot["publication_intent"]
            if (
                bundle["header"]["closed"] or bundle["header"]["frozen"] is not None
                or slot["publication_intent"] is None
                or slot["state"] in {"expired", "refused"}
                or remaining(slot, root.boot_id) <= 0
                or (actor["closed"] and actor["leave_slot"] != slot_id)
            ):
                raise ManagedPublicError("expired" if remaining(slot, root.boot_id) <= 0 else "not_authorized")
            for other in bundle["slots"].values():
                if (
                    other["actor_id"] == actor["actor_id"] and other["slot_id"] != slot_id
                    and other["state"] in {"publication_pending", "leave_pending", "uncertain"}
                    and other["publication_intent"] is not None
                ):
                    raise ManagedPublicError("publication_uncertain")
            for request in bundle["requests"].values():
                invitation = request["invitation"]
                if (
                    invitation is not None and request["actor_id"] == actor["actor_id"]
                    and invitation["state"] in {"publication_pending", "uncertain"}
                ):
                    raise ManagedPublicError("publication_uncertain")
            slot["state"] = "leave_pending" if slot["response"]["kind"] == "leave" else "publication_pending"
            slot["reason"] = None
            _save(db, "public_slots", root.worker_id, slot_id, slot)
            return slot["publication_intent"]

    def receipt(self, root, policy, slot_id, receipt):
        with self._transaction(root, policy) as (db, bundle):
            slot = bundle["slots"][slot_id]
            actor = bundle["actors"][slot["actor_id"]]
            validate_receipt(receipt, actor["status"], slot["publication_intent"])
            if slot["receipt"] is not None:
                if slot["receipt"] != receipt:
                    raise ManagedPublicError("conflict")
                return slot
            if bundle["header"]["frozen"] is not None:
                _conflict()
            # Convert only this acknowledged reservation in the same transaction,
            # including when history already retained the exact original record.
            slot["receipt"] = receipt
            self._records(db, bundle, [receipt["record"]])
            slot["state"] = {
                "message": "published", "decline": "declined", "leave": "left",
            }[slot["publication_intent"]["kind"]]
            slot["reason"] = None
            request = bundle["requests"][slot["decision_request_id"]]
            request["state"], request["error"] = "complete", None
            _save(db, "public_slots", root.worker_id, slot_id, slot)
            _save(db, "public_requests", root.worker_id, request["request_id"], request)
            self._save_header(db, bundle)
            return slot


    def invite(self, root, policy, request_id):
        with self._transaction(root, policy) as (db, bundle):
            request = bundle["requests"][request_id]
            if request["payload"]["operation"] != "public_invite":
                raise ManagedPublicError("conflict")
            if request["invitation"] is not None:
                return request["invitation"]
            self._active(bundle, request, root.boot_id, time.monotonic(), time.time())
            key = request["payload"]["invitation_key"]
            if key not in bundle["header"]["policy"]["invitations"]:
                raise ManagedPublicError("not_authorized")
            if any(item["invitation"] is not None for item in bundle["requests"].values()):
                raise ManagedPublicError("slot_limit")
            self._reserve_post(bundle)
            request["invitation"] = {
                "invitation_key": key, "publication_request_key": None,
                "state": "publication_pending", "reason": None, "intent": None,
                "receipt": None,
            }
            actor = bundle["actors"][request["actor_id"]]
            self._bind_invitation(bundle, actor, request)
            _save(db, "public_requests", root.worker_id, request_id, request)
            self._save_header(db, bundle)
            return request["invitation"]

    @staticmethod
    def _bind_invitation(bundle, actor, request):
        value = request["invitation"]
        if value is None or actor["status"] is None:
            return
        key = invitation_key(
            actor["status"]["author"], value["invitation_key"], request["request_id"],
        )
        approved = bundle["header"]["policy"]["invitations"][value["invitation_key"]]
        intent = signed_intent(
            actor["status"], key, "invite", approved["content"], target=approved["target"],
        )
        if value["publication_request_key"] not in {None, key} or (
            value["intent"] is not None and value["intent"] != intent
        ):
            _conflict()
        value["publication_request_key"], value["intent"] = key, intent

    def invitation_intent(self, root, policy, request_id):
        with self._transaction(root, policy) as (db, bundle):
            request = bundle["requests"][request_id]
            value = request["invitation"]
            if value is None:
                raise ManagedPublicError("conflict")
            if value["state"] == "published":
                return value["intent"]
            self._active(bundle, request, root.boot_id, time.monotonic(), time.time())
            actor = bundle["actors"][request["actor_id"]]
            if any(
                slot["actor_id"] == actor["actor_id"]
                and slot["state"] in {"publication_pending", "leave_pending", "uncertain"}
                and slot["publication_intent"] is not None
                for slot in bundle["slots"].values()
            ):
                raise ManagedPublicError("publication_uncertain")
            self._bind_invitation(bundle, actor, request)
            if value["intent"] is None:
                raise ManagedPublicError("state_conflict")
            value["state"], value["reason"] = "publication_pending", None
            _save(db, "public_requests", root.worker_id, request_id, request)
            return value["intent"]

    def invitation_receipt(self, root, policy, request_id, receipt):
        with self._transaction(root, policy) as (db, bundle):
            request = bundle["requests"][request_id]
            value = request["invitation"]
            actor = bundle["actors"][request["actor_id"]]
            if value is None or value["intent"] is None:
                _conflict()
            validate_receipt(receipt, actor["status"], value["intent"])
            if value["receipt"] is not None:
                if value["receipt"] != receipt:
                    raise ManagedPublicError("conflict")
                return value
            if bundle["header"]["frozen"] is not None:
                _conflict()
            value["receipt"], value["state"], value["reason"] = receipt, "published", None
            self._records(db, bundle, [receipt["record"]])
            request["state"], request["error"] = "complete", None
            _save(db, "public_requests", root.worker_id, request_id, request)
            self._save_header(db, bundle)
            return value

    def configuration_intent(self, root, policy, who, config):
        with self._transaction(root, policy) as (db, bundle):
            actor = bundle["actors"][who]
            if actor["config"] is not None:
                if actor["config"] != config:
                    raise ManagedPublicError("conflict")
                return False
            if bundle["header"]["closed"] or actor["closed"]:
                raise ManagedPublicError("not_authorized")
            if config["state"] != "preparing":
                _conflict()
            actor["config"] = config
            _save(db, "public_actors", root.worker_id, who, actor)
            return True

    def configuration_ready(self, root, policy, who, config):
        with self._transaction(root, policy) as (db, bundle):
            actor = bundle["actors"][who]
            if actor["config"] is None or actor["config"] | {"state": "ready"} != config:
                _conflict()
            actor["config"] = config
            _save(db, "public_actors", root.worker_id, who, actor)

    def bind_actor(self, root, policy, who, status, interpreter):
        with self._transaction(root, policy) as (db, bundle):
            actor = bundle["actors"][who]
            if actor["config"] is None or actor["config"]["state"] != "ready":
                _conflict()
            validate_status(status, bundle["header"]["policy"]["topic"])
            if status["swarm_id"] != bundle["header"]["policy"]["server"]["scope_key_sha256"]:
                raise ManagedPublicError("state_conflict")
            binding = {
                "schema_version": 1, "identity": actor["identity"],
                "config_sha256": actor["config"]["sha256"],
                "server": actor["config"]["server_binding"],
                "interpreter": interpreter, "status": status,
            }
            if actor["binding"] is not None:
                if actor["binding"] != binding:
                    raise ManagedPublicError("state_conflict")
                return actor
            if bundle["header"]["closed"] or actor["closed"]:
                raise ManagedPublicError("not_authorized")
            actor["status"], actor["binding"] = status, binding
            actor["binding_digest"] = digest(binding)
            _save(db, "public_actors", root.worker_id, who, actor)
            for request in bundle["requests"].values():
                if request["actor_id"] == who and request["invitation"] is not None:
                    self._bind_invitation(bundle, actor, request)
                    _save(db, "public_requests", root.worker_id, request["request_id"], request)
            return actor

    @staticmethod
    def _leave_recovery(bundle, who, slot_id):
        """Immutable exception identity, also checked after a receipt or freeze."""
        actor = bundle["actors"].get(who)
        slot = bundle["slots"].get(slot_id) if isinstance(slot_id, str) else None
        if actor is None or slot is None:
            _conflict()
        request = bundle["requests"].get(slot["decision_request_id"])
        if (
            not actor["closed"] or actor["leave_slot"] != slot_id
            or slot["actor_id"] != who or actor["binding_digest"] is None
            or request is None or request["actor_id"] != who
            or request["payload"]["operation"] not in {"public_pull", "public_turn"}
            or request["slot_id"] != slot_id
            or slot["response"] is None or slot["response"]["kind"] != "leave"
            or slot["publication_intent"] is None
            or slot["publication_intent"]["kind"] != "leave"
            or slot["publication_intent"]["request_key"] != publication_key(slot_id)
        ):
            _conflict()
        return {
            "schema_version": 1, "slot_id": slot_id,
            "decision_request_id": request["request_id"],
            "request_payload_digest": request["payload_digest"],
            "publication_intent_digest": digest(slot["publication_intent"]),
            "actor_binding_digest": actor["binding_digest"],
        }

    def process_intent(self, root, policy, who, stage, intent, *, recovery_slot=None):
        """A durable intent precedes Popen; an existing intent never relaunches."""
        intent = object_value(canonical(intent), retained=True)
        if "leave_recovery" in intent:
            # Only the store derives this exception from the original decision.
            _conflict()
        with self._transaction(root, policy) as (db, bundle):
            actor = bundle["actors"][who]
            if bundle["header"]["closed"] or bundle["header"]["frozen"] is not None:
                raise ManagedPublicError("not_authorized")
            if actor["closed"]:
                if recovery_slot is None:
                    raise ManagedPublicError("not_authorized")
                recovery = self._leave_recovery(bundle, who, recovery_slot)
                slot = bundle["slots"][recovery_slot]
                request = bundle["requests"][recovery["decision_request_id"]]
                if (
                    slot["receipt"] is not None or slot["state"] not in {
                        "response_retained", "publication_pending", "leave_pending", "uncertain",
                    } or request["state"] not in {"accepted", "uncertain"}
                    or actor["generations"] < 1
                ):
                    raise ManagedPublicError("not_authorized")
                if (
                    remaining(slot, root.boot_id) <= 0
                    or remaining(request, root.boot_id) <= 0
                    or root.monotonic_deadline <= time.monotonic()
                    or root.deadline <= time.time()
                ):
                    raise ManagedPublicError("expired")
                if intent["monotonic_cutoff"] > min(
                    slot["monotonic_cutoff"], request["monotonic_cutoff"],
                    root.monotonic_deadline,
                ):
                    _conflict()
                intent["leave_recovery"] = recovery
            elif recovery_slot is not None:
                raise ManagedPublicError("not_authorized")
            if actor["config"] is None or actor["config"]["state"] != "ready":
                _conflict()
            previous = [
                item for item in bundle["processes"].values() if item["actor_id"] == who
            ]
            if stage == "probe":
                if actor["generations"] >= 2 or any(item["state"] != "stopped" for item in previous):
                    raise ManagedPublicError("state_conflict")
                generation = actor["generations"] + 1
                actor["generations"] = generation
            elif stage == "server":
                generation = actor["generations"]
                probe = next((item for item in previous if (
                    item["generation"] == generation and item["stage"] == "probe"
                )), None)
                if probe is None or probe["state"] != "stopped":
                    raise ManagedPublicError("state_conflict")
            else:
                _conflict()
            key = digest([who, generation, stage])
            if key in bundle["processes"]:
                # Even exact replay cannot repeat an uncertain process start.
                raise ManagedPublicError("state_conflict")
            value = {
                "process_id": key, "actor_id": who, "generation": generation,
                "stage": stage, "intent": intent, "intent_digest": digest(intent),
                "state": "intent", "identity": None, "cleanup": None,
            }
            _save(db, "public_processes", root.worker_id, key, value, insert=True)
            _save(db, "public_actors", root.worker_id, who, actor)
            bundle["processes"][key] = value
            bundle["header"]["processes"] += 1
            self._save_header(db, bundle)
            return value

    def process_identity(self, root, policy, process_id, identity):
        with self._transaction(root, policy) as (db, bundle):
            value = bundle["processes"][process_id]
            if value["state"] not in {"intent", "running"} or (
                value["identity"] is not None and value["identity"] != identity
            ):
                _conflict()
            value["identity"], value["state"] = identity, "running"
            _save(db, "public_processes", root.worker_id, process_id, value)

    def process_finished(self, root, policy, process_id, identity, cleanup):
        with self._transaction(root, policy) as (db, bundle):
            value = bundle["processes"][process_id]
            if value["identity"] is not None and value["identity"] != identity:
                _conflict()
            if value["state"] == "stopped":
                if value["cleanup"] != cleanup:
                    _conflict()
                return
            if cleanup is not None:
                # The trusted owner may record both identity and positive cleanup
                # together if the first identity write failed before exposure.
                if identity is None:
                    _conflict()
                value["identity"], value["cleanup"], value["state"] = identity, cleanup, "stopped"
            else:
                value["identity"], value["state"] = identity, "unknown"
            _save(db, "public_processes", root.worker_id, process_id, value)

    def close(self, root, policy):
        """Close admission without waiting for any socket/model/process owner."""
        with self._transaction(root, policy) as (db, bundle):
            header = bundle["header"]
            if header["frozen"] is not None:
                return
            header["closed"] = True
            for actor in bundle["actors"].values():
                actor["closed"] = True
                _save(db, "public_actors", root.worker_id, actor["actor_id"], actor)
            for slot in bundle["slots"].values():
                if slot["state"] in {"offered", "context_frozen"} and slot["model_call_digest"] is None:
                    slot["state"], slot["reason"] = "refused", "not_authorized"
                    _save(db, "public_slots", root.worker_id, slot["slot_id"], slot)
            self._save_header(db, bundle)

    @staticmethod
    def _snapshot(bundle):
        """Freeze no private instruction text; all public records stay original."""
        header = bundle["header"]
        return {
            "schema_version": 1, "protocol": PROTOCOL, "topic": header["policy"]["topic"],
            "policy_digest": header["policy_digest"],
            "actors": [
                {
                    "actor_id": actor["actor_id"], "identity": actor["identity"],
                    "binding_digest": actor["binding_digest"],
                    "status": actor["status"], "closed": actor["closed"],
                }
                for actor in bundle["actors"].values()
            ],
            "slots": [
                {
                    name: slot[name] for name in (
                        "slot_id", "actor_id", "activation_request_id", "persona_key",
                        "instruction_key", "selected_message_ids", "reply_to",
                        "expires_at", "state", "reason", "context_digest",
                        "model_call_digest", "publication_intent", "receipt",
                    )
                }
                for slot in bundle["slots"].values()
            ],
            "records": list(bundle["records"].values()),
            "request_digest": digest(list(bundle["requests"].values())),
            "process_digest": digest(list(bundle["processes"].values())),
            "counts": {name: header[name] for name in (
                "actors", "requests", "slots", "records", "processes",
                "history_charges", "page_charges", "post_reservations", "transcript_bytes",
            )},
        }

    def freeze(self, root, policy, *, owners_quiescent):
        if owners_quiescent is not True:
            raise ManagedPublicError("retry_later")
        with self._transaction(root, policy) as (db, bundle):
            header = bundle["header"]
            if header["frozen"] is not None:
                return header["frozen"], header["freeze_digest"]
            if not header["closed"] or any(
                item["state"] != "stopped" for item in bundle["processes"].values()
            ):
                raise ManagedPublicError("state_conflict")
            # This is called only after every actual handler/task-group owner
            # exited. Unknown provider/post acknowledgements are retained as
            # uncertainty, never invented success or a replacement dispatch.
            for slot in bundle["slots"].values():
                if slot["state"] not in TERMINAL | {"uncertain"}:
                    if slot["state"] in {"model_pending", "publication_pending", "leave_pending"}:
                        slot["reason"] = (
                            "provider_uncertain" if slot["state"] == "model_pending"
                            else "publication_uncertain"
                        )
                        slot["state"] = "uncertain"
                    else:
                        slot["state"], slot["reason"] = "refused", "not_authorized"
                    _save(db, "public_slots", root.worker_id, slot["slot_id"], slot)
            for request in bundle["requests"].values():
                invitation = request["invitation"]
                if invitation is not None and invitation["state"] == "publication_pending":
                    invitation["state"], invitation["reason"] = "uncertain", "publication_uncertain"
                    _save(db, "public_requests", root.worker_id, request["request_id"], request)
            snapshot = self._snapshot(bundle)
            header["frozen"], header["freeze_digest"] = snapshot, digest(snapshot)
            self._save_header(db, bundle)
            return snapshot, header["freeze_digest"]

    def extensions(self, root, policy):
        from .managed_public_types import ROOT_CAPTURE_LIMIT, CHILD_CAPTURE_LIMIT
        bundle = self.view(root, policy)
        frozen, checksum = bundle["header"]["frozen"], bundle["header"]["freeze_digest"]
        if frozen is None:
            raise ManagedPublicError("retry_later")
        labels = {}
        child_number = 0
        for actor in frozen["actors"]:
            if actor["identity"]["role"] == "root":
                labels[actor["actor_id"]] = "root"
            else:
                child_number += 1
                labels[actor["actor_id"]] = "child-" + str(child_number)
        public = {
            "schema_version": 1, "protocol": PROTOCOL, "topic": frozen["topic"],
            "snapshot_sha256": checksum,
            "actors": [
                {"role": labels[actor["actor_id"]],
                 "binding_digest": actor["binding_digest"], "status": actor["status"],
                 "admission_closed": actor["closed"]}
                for actor in frozen["actors"]
            ],
            "slots": [
                {"slot_digest": slot["slot_id"], "role": labels[slot["actor_id"]],
                 "request_digest": digest(slot["activation_request_id"]),
                 "selected_message_ids": slot["selected_message_ids"],
                 "reply_to": slot["reply_to"], "state": slot["state"], "reason": slot["reason"],
                 "context_digest": slot["context_digest"],
                 "model_call_digest": slot["model_call_digest"],
                 "receipt_message_id": None if slot["receipt"] is None else slot["receipt"]["message_id"]}
                for slot in frozen["slots"]
            ],
            "records": frozen["records"], "counts": frozen["counts"],
        }
        canonical(public, limit=ROOT_CAPTURE_LIMIT)
        children = {}
        for child in self.journal.children(root.worker_id):
            who = child["child_id"]
            actor = next((item for item in frozen["actors"] if item["actor_id"] == who), None)
            private = {
                "schema_version": 1, "protocol": PROTOCOL, "snapshot_sha256": checksum,
                "actor": actor,
                "slots": [slot for slot in frozen["slots"] if slot["actor_id"] == who],
            }
            canonical(private, limit=CHILD_CAPTURE_LIMIT)
            children[who] = private
        return public, children
