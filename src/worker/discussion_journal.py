"""Private one-owner discussion allowance and immutable turn recovery.

Only explicit initialize creates state. Normal opens use an existing SQLite
file and exact binding. A provider reservation commits before its sole dispatch;
an unacknowledged reservation on reopen creates a journal-wide permanent hold.
"""

from __future__ import annotations

from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
import re
from pathlib import Path
import sqlite3
import stat
from urllib.parse import quote
from uuid import uuid4

from .discussion_types import (
    AUTHOR, CODES, CONTEXT_LIMIT, Deadline, DiscussionError, HEX32,
    PRIVATE_LIMIT, Policy, RECORD_LIMIT, TURN_LIMIT, Turn, absolute_path,
    boot_id, canonical, digest, fields, finite, integer, matches,
    present, private_directory, provider_request, publication_intent,
    read_private_bytes, strict_json, validate_history, validate_output, validate_receipt,
    validate_status, verify_record,
)


DATABASE = "discussion.sqlite3"
LOCK = "owner.lock"
BINDING = "binding.json"
ROW_LIMIT = 2097152
DATABASE_LIMIT = 536870912
META_SQL = "CREATE TABLE metadata (slot INTEGER PRIMARY KEY CHECK(slot=1), data TEXT NOT NULL)"
TURN_SQL = "CREATE TABLE turns (request_key TEXT PRIMARY KEY NOT NULL, data TEXT NOT NULL)"
STATES = {
    "prepared", "reserved", "response", "publishing", "complete", "rejected",
    "provider_uncertain", "publication_uncertain",
}
TURN_FIELDS = {
    "schema_version", "request_key", "request_hash", "request_json",
    "expires_at", "monotonic_cutoff", "boot_id", "state", "context",
    "context_hash", "provider_request", "provider_request_hash",
    "reserved_tokens", "response", "response_hash", "intent", "intent_hash",
    "receipt", "receipt_hash", "reason",
}


def _encoded(value, maximum=ROW_LIMIT):
    raw = canonical(value)
    if len(raw) > maximum:
        raise DiscussionError("private_state_invalid")
    return raw.decode("utf-8")


def _file(path, *, writable=False, empty=False):
    descriptor = None
    try:
        descriptor = os.open(
            path,
            (os.O_RDWR if writable else os.O_RDONLY)
            | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        )
        info = os.fstat(descriptor)
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.geteuid()
            or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1
            or not (0 if empty else 1) <= info.st_size <= DATABASE_LIMIT
        ):
            raise ValueError("invalid retained file")
        return descriptor, {"device": info.st_dev, "inode": info.st_ino}
    except Exception:
        if descriptor is not None:
            os.close(descriptor)
        raise DiscussionError("private_state_invalid") from None


def _write_new(path, raw):
    descriptor = os.open(
        path,
        os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
        0o600,
    )
    try:
        view = memoryview(raw)
        while view:
            written = os.write(descriptor, view)
            if written <= 0:
                raise OSError("private write did not progress")
            view = view[written:]
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def _interpreter(value, policy):
    fields(value, {
        "schema_version", "launch_path", "resolved_executable", "prefix",
    }, code="private_state_invalid")
    integer(value["schema_version"], 1, 1, "private_state_invalid")
    try:
        launch = absolute_path(policy.server["python"], executable=True)
        resolved = absolute_path(
            value["resolved_executable"], executable=True, code="private_state_invalid"
        )
        prefix = absolute_path(value["prefix"], code="private_state_invalid")
        if (
            value["launch_path"] != str(launch)
            or str(launch.resolve(strict=True)) != str(resolved)
            or not prefix.is_dir()
        ):
            raise ValueError("interpreter binding changed")
    except Exception:
        raise DiscussionError("private_state_invalid") from None
    return value


class DiscussionJournal:
    def __init__(self, policy, *, read_only=False, deadline=None):
        self.policy = policy
        self.read_only = read_only
        self.deadline = deadline or Deadline.observe()
        self.root = private_directory(policy.state)
        self.connection = None
        self.lock_fd = None
        try:
            self._reject_other_journals()
            self.lock_fd, lock_identity = _file(self.root / LOCK, writable=True)
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise DiscussionError("state_conflict") from None
            binding_fd, _ = _file(self.root / BINDING)
            os.close(binding_fd)
            binding_raw = read_private_bytes(
                self.root / BINDING, code="private_state_invalid"
            )
            self.binding = strict_json(binding_raw, code="private_state_invalid")
            fields(self.binding, {
                "schema_version", "instance_id", "policy", "interpreter",
                "status", "database", "lock",
            }, code="private_state_invalid")
            integer(self.binding["schema_version"], 1, 1, "private_state_invalid")
            matches(HEX32, self.binding["instance_id"], "private_state_invalid")
            if os.read(self.lock_fd, 65) != (
                self.binding["instance_id"] + "\n"
            ).encode("ascii"):
                raise DiscussionError("private_state_invalid")
            if canonical(self.binding["policy"]) != canonical(policy.binding()):
                raise DiscussionError("state_conflict")
            _interpreter(self.binding["interpreter"], policy)
            validate_status(self.binding["status"], policy.document["topic"])
            descriptor, database_identity = _file(
                self.root / DATABASE, writable=not read_only
            )
            os.close(descriptor)
            if (
                canonical(lock_identity) != canonical(self.binding["lock"])
                or canonical(database_identity) != canonical(self.binding["database"])
            ):
                raise DiscussionError("private_state_invalid")
            self.deadline.remaining()
            mode = "ro" if read_only else "rw"
            self.connection = sqlite3.connect(
                "file:" + quote(str(self.root / DATABASE), safe="/") + "?mode=" + mode,
                uri=True, timeout=1, isolation_level=None,
            )
            self.connection.row_factory = sqlite3.Row
            self.connection.execute("PRAGMA trusted_schema=OFF")
            if self.connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                raise DiscussionError("private_state_invalid")
            if not read_only:
                self.connection.execute("PRAGMA synchronous=FULL")
            self._validate_database()
            if not read_only:
                self._recover()
        except DiscussionError:
            self.close()
            raise
        except Exception:
            self.close()
            raise DiscussionError("private_state_invalid") from None

    @classmethod
    def initialize(cls, policy, interpreter, status, *, deadline=None):
        deadline = deadline or Deadline.observe()
        deadline.remaining()
        _interpreter(interpreter, policy)
        validate_status(status, policy.document["topic"])
        # Re-read both original private files after the non-inference preflight.
        refreshed = Policy.load(policy.path)
        if canonical(refreshed.binding()) != canonical(policy.binding()):
            raise DiscussionError("state_conflict")
        root = absolute_path(str(policy.state), code="private_state_invalid")
        if present(root) is not None:
            raise DiscussionError("already_initialized")
        lock_fd = None
        db = None
        try:
            # No normal command may repeat this absent-leaf creation path.
            root.mkdir(mode=0o700)
            private_directory(root)
            # Persist the newly owned leaf itself before any acknowledged
            # allowance can exist. Syncing only this leaf does not persist
            # its entry in the already-existing parent directory.
            parent_fd = os.open(
                root.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW
            )
            try:
                os.fsync(parent_fd)
            finally:
                os.close(parent_fd)
            instance = uuid4().hex
            _write_new(root / LOCK, (instance + "\n").encode("ascii"))
            lock_fd, lock_identity = _file(root / LOCK, writable=True)
            fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            _write_new(root / DATABASE, b"")
            descriptor, database_identity = _file(
                root / DATABASE, writable=True, empty=True
            )
            os.close(descriptor)
            binding = {
                "schema_version": 1,
                "instance_id": instance,
                "policy": policy.binding(),
                "interpreter": interpreter,
                "status": status,
                "database": database_identity,
                "lock": lock_identity,
            }
            binding_bytes = canonical(binding) + b"\n"
            if len(binding_bytes) > PRIVATE_LIMIT:
                raise DiscussionError("invalid_policy")
            db = sqlite3.connect(
                "file:" + quote(str(root / DATABASE), safe="/") + "?mode=rw",
                uri=True, timeout=1, isolation_level=None,
            )
            db.execute("PRAGMA journal_mode=DELETE")
            db.execute("PRAGMA synchronous=FULL")
            db.execute("BEGIN IMMEDIATE")
            db.execute(META_SQL)
            db.execute(TURN_SQL)
            db.execute(
                "INSERT INTO metadata VALUES(1,?)",
                (_encoded({
                    "schema_version": 1, "binding": binding, "calls": 0, "tokens": 0,
                    "provider_uncertain": False,
                }),),
            )
            db.execute("COMMIT")
            db.close()
            db = None
            deadline.remaining()
            # The final private binding is the completion marker. A killed
            # initializer leaves existing partial state that init must refuse.
            _write_new(root / BINDING, binding_bytes)
            directory_fd = os.open(root, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
            try:
                os.fsync(directory_fd)
            finally:
                os.close(directory_fd)
        except FileExistsError:
            raise DiscussionError("already_initialized") from None
        except DiscussionError:
            raise
        except Exception:
            raise DiscussionError("private_state_invalid") from None
        finally:
            if db is not None:
                db.close()
            if lock_fd is not None:
                os.close(lock_fd)
        return {"schema_version": 1, "state": "initialized", "policy": policy.raw_hash}

    def _reject_other_journals(self):
        for suffix in ("-wal", "-shm"):
            if present(self.root / (DATABASE + suffix)) is not None:
                raise DiscussionError("private_state_invalid")
        rollback = self.root / (DATABASE + "-journal")
        if present(rollback) is not None:
            descriptor, _ = _file(rollback, empty=True)
            os.close(descriptor)

    def close(self):
        try:
            if self.connection is not None:
                self.connection.close()
        finally:
            self.connection = None
            if self.lock_fd is not None:
                os.close(self.lock_fd)
                self.lock_fd = None

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()

    @contextmanager
    def _transaction(self, *, check_deadline=True):
        if self.read_only:
            raise DiscussionError("state_conflict")
        if check_deadline:
            self.deadline.remaining()
        self.connection.execute("BEGIN IMMEDIATE")
        try:
            yield
            self.connection.execute("COMMIT")
        except BaseException as error:
            if self.connection.in_transaction:
                try:
                    self.connection.execute("ROLLBACK")
                except Exception:
                    error.add_note("private transaction rollback failed")
            raise

    def _metadata(self):
        row = self.connection.execute("SELECT data FROM metadata WHERE slot=1").fetchone()
        if row is None:
            raise DiscussionError("private_state_invalid")
        value = strict_json(row[0].encode("utf-8"), ROW_LIMIT, "private_state_invalid")
        fields(value, {
            "schema_version", "binding", "calls", "tokens", "provider_uncertain",
        }, code="private_state_invalid")
        integer(value["schema_version"], 1, 1, "private_state_invalid")
        integer(value["calls"], 0, self.policy.allowance["calls"], "private_state_invalid")
        integer(value["tokens"], 0, self.policy.allowance["total"], "private_state_invalid")
        if (
            type(value["provider_uncertain"]) is not bool
            or canonical(value["binding"]) != canonical(self.binding)
        ):
            raise DiscussionError("private_state_invalid")
        return value

    def _context(self, value, turn):
        fields(value, {
            "status", "messages", "peer_gaps", "context_after", "next_cursor",
        }, code="private_state_invalid")
        if (
            canonical(value["status"]) != canonical(self.binding["status"])
            or value["context_after"] != turn.document["context_after"]
            or not isinstance(value["messages"], list)
            or len(value["messages"]) > 32
            or not isinstance(value["peer_gaps"], list)
            or len(value["peer_gaps"]) > 8
        ):
            raise DiscussionError("private_state_invalid")
        integer(value["context_after"], 0, (1 << 63) - 1, "private_state_invalid")
        integer(value["next_cursor"], 0, (1 << 63) - 1, "private_state_invalid")
        if (
            turn.document["stream_id"] is not None
            and turn.document["stream_id"] != value["status"]["stream_id"]
        ):
            raise DiscussionError("private_state_invalid")
        for gaps in value["peer_gaps"]:
            validate_history({
                "schema_version": 1,
                "session_id": self.binding["status"]["session_id"],
                "topic": self.binding["status"]["topic"],
                "stream_id": self.binding["status"]["stream_id"],
                "messages": [], "next_cursor": value["context_after"],
                "has_more": False, "gap": None, "peer_gaps": gaps,
            }, self.binding["status"], value["context_after"])
        seen = []
        position = value["context_after"]
        used = 0
        for item in value["messages"]:
            fields(item, {"cursor", "record", "reply_state"}, code="private_state_invalid")
            integer(item["cursor"], 0, (1 << 63) - 1, "private_state_invalid")
            if (
                item["cursor"] <= position
                or item["reply_state"] not in {
                    "none", "unresolved", "resolved", "cross_session",
                }
            ):
                raise DiscussionError("private_state_invalid")
            record = verify_record(item["record"], self.binding["status"])
            seen.append(record["message_id"])
            position = item["cursor"]
            used += len(canonical(record))
        if (
            used > CONTEXT_LIMIT or len(seen) != len(set(seen))
            or set(seen) != set(turn.document["selected_message_ids"])
            or value["next_cursor"] < position
            or len(canonical(value)) > 524288
        ):
            raise DiscussionError("private_state_invalid")
        return value

    def _turn(self, row):
        try:
            return self._checked_turn(row)
        except Exception:
            raise DiscussionError("private_state_invalid") from None

    def _checked_turn(self, row):
        value = strict_json(row["data"].encode("utf-8"), ROW_LIMIT, "private_state_invalid")
        fields(value, TURN_FIELDS, code="private_state_invalid")
        integer(value["schema_version"], 1, 1, "private_state_invalid")
        if value["state"] not in STATES or (
            value["reason"] is not None and value["reason"] not in CODES
        ):
            raise DiscussionError("private_state_invalid")
        raw = value["request_json"].encode("utf-8")
        turn = Turn.parse(raw)
        if (
            row["request_key"] != turn.key or value["request_key"] != turn.key
            or value["request_hash"] != turn.raw_hash
            or value["expires_at"] != turn.document["expires_at"]
        ):
            raise DiscussionError("private_state_invalid")
        finite(value["expires_at"], 0, 1e15, "private_state_invalid")
        finite(value["monotonic_cutoff"], 0, 1e15, "private_state_invalid")
        if not isinstance(value["boot_id"], str) or not re.fullmatch(
            r"[0-9a-f]{8}(?:-[0-9a-f]{4}){3}-[0-9a-f]{12}", value["boot_id"]
        ):
            raise DiscussionError("private_state_invalid")
        integer(
            value["reserved_tokens"], 0, self.policy.allowance["per_call"],
            "private_state_invalid",
        )
        for name in ("context", "provider_request", "response", "intent", "receipt"):
            if value[name] is None:
                if value[name + "_hash"] is not None:
                    raise DiscussionError("private_state_invalid")
            elif value[name + "_hash"] != digest(value[name]):
                raise DiscussionError("private_state_invalid")
        if value["context"] is not None:
            self._context(value["context"], turn)
        if value["reserved_tokens"] == 0:
            if value["state"] != "prepared" or any(
                value[name] is not None
                for name in ("provider_request", "response", "intent", "receipt")
            ):
                raise DiscussionError("private_state_invalid")
        else:
            if value["state"] == "prepared" or value["context"] is None:
                raise DiscussionError("private_state_invalid")
            expected = provider_request(
                self.policy, turn, value["context"], value["reserved_tokens"]
            )
            if canonical(value["provider_request"]) != canonical(expected):
                raise DiscussionError("private_state_invalid")
        has_response = value["state"] in {
            "response", "publishing", "complete", "publication_uncertain",
        }
        if has_response:
            validate_output(value["response"])
            intent = publication_intent(self.binding["status"], turn, value["response"])
            if canonical(value["intent"]) != canonical(intent):
                raise DiscussionError("private_state_invalid")
        elif value["response"] is not None or value["intent"] is not None:
            raise DiscussionError("private_state_invalid")
        if value["state"] == "complete":
            validate_receipt(value["receipt"], self.binding["status"], value["intent"])
        elif value["receipt"] is not None:
            raise DiscussionError("private_state_invalid")
        return value

    def _validate_database(self):
        actual = dict(self.connection.execute(
            "SELECT name,sql FROM sqlite_master WHERE type='table'"
        ))
        if actual != {"metadata": META_SQL, "turns": TURN_SQL}:
            raise DiscussionError("private_state_invalid")
        if self.connection.execute(
            "SELECT COUNT(*) FROM sqlite_master WHERE type IN ('trigger','view')"
        ).fetchone()[0] or self.connection.execute(
            "SELECT COUNT(*) FROM metadata"
        ).fetchone()[0] != 1:
            raise DiscussionError("private_state_invalid")
        meta = self._metadata()
        count = calls = tokens = 0
        uncertain = False
        for row in self.connection.execute("SELECT request_key,data FROM turns"):
            self.deadline.remaining()
            value = self._turn(row)
            count += 1
            calls += bool(value["reserved_tokens"])
            tokens += value["reserved_tokens"]
            uncertain |= value["state"] == "provider_uncertain"
        if (
            count > TURN_LIMIT or calls != meta["calls"] or tokens != meta["tokens"]
            or (uncertain and not meta["provider_uncertain"])
        ):
            raise DiscussionError("private_state_invalid")

    def _save_meta(self, meta):
        self.connection.execute("UPDATE metadata SET data=? WHERE slot=1", (_encoded(meta),))

    def _save(self, value):
        self.connection.execute(
            "UPDATE turns SET data=? WHERE request_key=?",
            (_encoded(value), value["request_key"]),
        )

    def _recover(self):
        with self._transaction():
            meta = self._metadata()
            for row in self.connection.execute("SELECT request_key,data FROM turns").fetchall():
                self.deadline.remaining()
                value = self._turn(row)
                if value["state"] == "reserved":
                    value["state"] = "provider_uncertain"
                    value["reason"] = "provider_uncertain"
                    meta["provider_uncertain"] = True
                    self._save(value)
                elif value["state"] == "publishing":
                    value["state"] = "publication_uncertain"
                    value["reason"] = "publication_uncertain"
                    self._save(value)
            self._save_meta(meta)

    def get(self, key):
        row = self.connection.execute(
            "SELECT request_key,data FROM turns WHERE request_key=?", (key,)
        ).fetchone()
        return None if row is None else self._turn(row)

    def _provider_blocked(self, meta):
        if meta["provider_uncertain"]:
            return True
        # A reservation that is still active in this owner is not permission
        # to start another key. Reopen makes the unknown outcome sticky.
        return any(
            self._turn(row)["state"] in {"reserved", "provider_uncertain"}
            for row in self.connection.execute("SELECT request_key,data FROM turns")
        )

    def _live(self, value):
        return Deadline.retained(
            value["expires_at"], value["monotonic_cutoff"], value["boot_id"]
        )

    def prepare(self, turn):
        with self._transaction():
            old = self.get(turn.key)
            if old is not None:
                if old["request_hash"] != turn.raw_hash:
                    raise DiscussionError("state_conflict")
                return old
            meta = self._metadata()
            if self._provider_blocked(meta):
                raise DiscussionError("provider_uncertain")
            if self.connection.execute("SELECT COUNT(*) FROM turns").fetchone()[0] >= TURN_LIMIT:
                raise DiscussionError("journal_full")
            deadline = Deadline.new(turn.document["expires_at"])
            value = {
                "schema_version": 1, "request_key": turn.key,
                "request_hash": turn.raw_hash, "request_json": turn.raw.decode("utf-8"),
                "expires_at": deadline.expires_at,
                "monotonic_cutoff": deadline.monotonic_cutoff, "boot_id": boot_id(),
                "state": "prepared", "context": None, "context_hash": None,
                "provider_request": None, "provider_request_hash": None,
                "reserved_tokens": 0, "response": None, "response_hash": None,
                "intent": None, "intent_hash": None, "receipt": None,
                "receipt_hash": None, "reason": None,
            }
            self.connection.execute(
                "INSERT INTO turns VALUES(?,?)", (turn.key, _encoded(value))
            )
            return value

    def freeze_context(self, key, context):
        with self._transaction():
            value = self.get(key)
            if value is None or value["state"] != "prepared":
                raise DiscussionError("state_conflict")
            self._live(value).remaining()
            self._context(context, Turn.parse(value["request_json"].encode("utf-8")))
            if value["context"] is not None:
                if canonical(value["context"]) != canonical(context):
                    raise DiscussionError("state_conflict")
            else:
                value["context"] = context
                value["context_hash"] = digest(context)
                self._save(value)
            return value

    def reserve(self, key):
        with self._transaction():
            value = self.get(key)
            meta = self._metadata()
            if self._provider_blocked(meta):
                raise DiscussionError("provider_uncertain")
            if value is None or value["state"] != "prepared" or value["context"] is None:
                raise DiscussionError("state_conflict")
            self._live(value).remaining()
            allowance = self.policy.allowance
            tokens = min(allowance["per_call"], allowance["total"] - meta["tokens"])
            if meta["calls"] >= allowance["calls"] or tokens <= 0:
                raise DiscussionError("budget_exhausted")
            request = provider_request(
                self.policy, Turn.parse(value["request_json"].encode("utf-8")),
                value["context"], tokens,
            )
            value.update(
                state="reserved", reserved_tokens=tokens, provider_request=request,
                provider_request_hash=digest(request), reason=None,
            )
            meta["calls"] += 1
            meta["tokens"] += tokens
            self._save(value)
            self._save_meta(meta)
            return value

    # These acknowledgements only retain an already-dispatched result. They
    # never authorize another network call or renew the original turn cutoff.
    # The orchestrator's cleanup envelope bounds post-dispatch bookkeeping.
    def provider_result(self, key, output):
        with self._transaction(check_deadline=False):
            value = self.get(key)
            if value is None or value["state"] != "reserved":
                raise DiscussionError("state_conflict")
            try:
                output = validate_output(output)
                intent = publication_intent(
                    self.binding["status"],
                    Turn.parse(value["request_json"].encode("utf-8")), output,
                )
            except DiscussionError:
                value.update(state="rejected", reason="provider_rejected")
                self._save(value)
                return value
            value.update(
                state="response", response=output, response_hash=digest(output),
                intent=intent, intent_hash=digest(intent), reason=None,
            )
            self._save(value)
            return value

    def provider_failed(self, key, *, uncertain):
        with self._transaction(check_deadline=False):
            value = self.get(key)
            if value is None or value["state"] != "reserved":
                raise DiscussionError("state_conflict")
            value.update(
                state="provider_uncertain" if uncertain else "rejected",
                reason="provider_uncertain" if uncertain else "provider_rejected",
            )
            self._save(value)
            if uncertain:
                meta = self._metadata()
                meta["provider_uncertain"] = True
                self._save_meta(meta)
            return value

    def begin_publication(self, key, status):
        with self._transaction():
            value = self.get(key)
            if value is None:
                raise DiscussionError("state_conflict")
            if value["state"] == "complete":
                return value
            if value["state"] not in {"response", "publishing", "publication_uncertain"}:
                raise DiscussionError("state_conflict")
            if canonical(status) != canonical(self.binding["status"]):
                raise DiscussionError("state_conflict")
            self._live(value).remaining()
            value.update(state="publishing", reason=None)
            self._save(value)
            return value

    def publication_result(self, key, receipt):
        with self._transaction(check_deadline=False):
            value = self.get(key)
            if value is None or value["state"] not in {"publishing", "publication_uncertain"}:
                raise DiscussionError("state_conflict")
            validate_receipt(receipt, self.binding["status"], value["intent"])
            value.update(
                state="complete", receipt=receipt, receipt_hash=digest(receipt), reason=None
            )
            self._save(value)
            return value

    def publication_failed(self, key):
        with self._transaction(check_deadline=False):
            value = self.get(key)
            if value is None or value["state"] != "publishing":
                raise DiscussionError("state_conflict")
            value.update(state="publication_uncertain", reason="publication_uncertain")
            self._save(value)
            return value

    def status(self):
        meta = self._metadata()
        counts = {}
        for row in self.connection.execute("SELECT request_key,data FROM turns"):
            self.deadline.remaining()
            value = self._turn(row)
            state = value["state"]
            if state == "reserved":
                state = "provider_uncertain"
            elif state == "publishing":
                state = "publication_uncertain"
            counts[state] = counts.get(state, 0) + 1
        return {
            "schema_version": 1, "policy": self.policy.raw_hash,
            "topic": self.binding["status"]["topic"],
            "author": self.binding["status"]["author"],
            "stream_id": self.binding["status"]["stream_id"],
            "calls_reserved": meta["calls"], "tokens_reserved": meta["tokens"],
            "provider_uncertain": meta["provider_uncertain"]
            or bool(counts.get("provider_uncertain")),
            "turns": counts,
        }

    def receipt(self, key):
        value = self.get(key)
        if value is None:
            raise DiscussionError("state_conflict")
        state = value["state"]
        if state == "reserved":
            state = "provider_uncertain"
        elif state == "publishing":
            state = "publication_uncertain"
        return {
            "schema_version": 1, "request_key": key, "state": state,
            "reserved_tokens": value["reserved_tokens"],
            "receipt": value["receipt"] if state == "complete" else None,
        }
