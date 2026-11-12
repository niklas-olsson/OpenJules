"""Durable delivery and execution intent, without another task/budget ledger."""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import json
from pathlib import Path
import sqlite3
import stat

from .child_types import ChildPolicy, RootContext, canonical, digest
from .child_sessions import (
    bind_session_grant,
    install_session_schema,
    retain_terminal_observation,
    _host_instruction,
    session_request_owner,
    validate_existing_session_schema,
)
from .lifecycle import LifecycleConflict, RuntimeUnavailable, WorkerSpec
from .managed_public_journal import (
    PUBLIC_SCHEMA_BIT, PublicStore, optional_schema, ordinary_request_key,
    prepare_public_worker,
)


class ChildJournal:
    def __init__(self, directory: str | Path):
        self.root = Path(directory).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_IMODE(self.root.stat().st_mode) & 0o077:
            raise ValueError("child supervisor state must be private")
        self.path = self.root / "children.sqlite3"
        self.service_lock = (self.root / "service.lock").open("a")
        try:
            fcntl.flock(self.service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self.service_lock.close()
            raise ValueError("another child supervisor owns this state") from None
        with self.connection() as db:
            db.executescript(
                "CREATE TABLE IF NOT EXISTS workers("
                "worker_id TEXT PRIMARY KEY,spec TEXT NOT NULL,policy_digest TEXT NOT NULL,"
                "context TEXT,closed INTEGER NOT NULL DEFAULT 0,close_reason TEXT,"
                "close_delivered INTEGER NOT NULL DEFAULT 0,retire INTEGER NOT NULL DEFAULT 0);"
                "CREATE TABLE IF NOT EXISTS intents("
                "worker_id TEXT NOT NULL,request_id TEXT NOT NULL,payload TEXT NOT NULL,"
                "delivery_key TEXT NOT NULL,child_id TEXT,status TEXT NOT NULL DEFAULT 'pending',"
                "PRIMARY KEY(worker_id,request_id));"
                "CREATE TABLE IF NOT EXISTS children("
                "child_id TEXT PRIMARY KEY,worker_id TEXT NOT NULL,ordinal INTEGER NOT NULL,"
                "uid INTEGER NOT NULL,grant_json TEXT NOT NULL,deadline REAL NOT NULL,boot_id TEXT NOT NULL,"
                "phase TEXT NOT NULL DEFAULT 'granted',exec_id TEXT,exec_dispatched INTEGER NOT NULL DEFAULT 0,armed_deadline REAL,"
                "exit_code INTEGER,revoked INTEGER NOT NULL DEFAULT 0,"
                "provisional TEXT NOT NULL DEFAULT '{}',capture TEXT,artifacts TEXT NOT NULL DEFAULT '{}',"
                "UNIQUE(worker_id,ordinal),UNIQUE(worker_id,uid));"
            )
            columns = {row[1] for row in db.execute("PRAGMA table_info(children)")}
            if "outcome_report" not in columns:
                db.execute("ALTER TABLE children ADD COLUMN outcome_report TEXT")

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.path, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    def prepare(self, worker_id: str, spec: WorkerSpec, policy: ChildPolicy):
        encoded = canonical(asdict(spec))
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            existing = db.execute(
                "SELECT 1 FROM workers WHERE worker_id=?", (worker_id,)
            ).fetchone()
            validate_existing_session_schema(db)
            if policy.session_protocol is not None:
                install_session_schema(db, require_existing=existing is not None)
            if getattr(policy, "public_discussion", None) is not None:
                prepare_public_worker(db, worker_id, policy, require_existing=existing is not None)
            elif optional_schema(db) & PUBLIC_SCHEMA_BIT:
                if db.execute(
                    "SELECT 1 FROM public_workers WHERE worker_id=?", (worker_id,),
                ).fetchone() is not None:
                    raise LifecycleConflict("ordinary worker cannot adopt retained public state")
            db.execute(
                "INSERT OR IGNORE INTO workers(worker_id,spec,policy_digest) VALUES(?,?,?)",
                (worker_id, encoded, policy.fingerprint),
            )
            row = db.execute(
                "SELECT * FROM workers WHERE worker_id=?", (worker_id,)
            ).fetchone()
            if row["spec"] != encoded or row["policy_digest"] != policy.fingerprint:
                raise LifecycleConflict("child worker immutable policy changed")
            if getattr(policy, "public_discussion", None) is not None:
                PublicStore(self)._checked(db, worker_id, policy)

    def worker(self, worker_id: str) -> dict:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM workers WHERE worker_id=?", (worker_id,)
            ).fetchone()
        if row is None:
            raise LifecycleConflict("child worker is not prepared")
        return dict(row)

    def context(self, worker_id: str) -> RootContext:
        value = self.worker(worker_id)["context"]
        if value is None:
            raise LifecycleConflict("root is not bound for child execution")
        return RootContext.from_dict(json.loads(value))

    def bind(self, context: RootContext):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = db.execute(
                "SELECT * FROM workers WHERE worker_id=?", (context.worker_id,)
            ).fetchone()
            if row is None or row["spec"] != canonical(asdict(context.spec)):
                raise LifecycleConflict("child root context changed its worker")
            if row["context"]:
                old = RootContext.from_dict(json.loads(row["context"]))
                # Later permission samples may shorten, but never replace or
                # extend, the original root cutoff or any immutable field.
                old_value, new_value = old.to_dict(), context.to_dict()
                old_value.pop("monotonic_deadline")
                new_value.pop("monotonic_deadline")
                old_value.pop("boot_id")
                new_value.pop("boot_id")
                if old_value != new_value:
                    raise LifecycleConflict("child root binding changed")
                context = (
                    old
                    if old.boot_id != context.boot_id
                    else RootContext.from_dict(
                        context.to_dict()
                        | {
                            "monotonic_deadline": min(
                                old.monotonic_deadline, context.monotonic_deadline
                            )
                        }
                    )
                )
            db.execute(
                "UPDATE workers SET context=? WHERE worker_id=?",
                (canonical(context.to_dict()), context.worker_id),
            )
        return context

    @staticmethod
    def _capacity_available(db, worker_id, policy):
        children = db.execute(
            "SELECT COUNT(*) FROM children WHERE worker_id=?", (worker_id,)
        ).fetchone()[0]
        pending = db.execute(
            "SELECT COUNT(*) FROM intents WHERE worker_id=? "
            "AND child_id IS NULL AND status!='rejected'", (worker_id,)
        ).fetchone()[0]
        return children + pending < policy.max_children

    def _reserve_in(
        self, db, worker_id, request_id, payload, policy, *, session_owner=None
    ):
        # An opted-in worker cannot lose its queued request ownership merely by
        # losing both optional tables. Only prepare of a new worker creates them.
        if policy.session_protocol is not None:
            install_session_schema(db, require_existing=True)
        ordinary_request_key(db, worker_id, request_id)
        if getattr(policy, "public_discussion", None) is not None:
            PublicStore(self)._checked(db, worker_id, policy)
        if (
            policy.session_protocol is not None
            and session_owner is None
            and _host_instruction(payload.get("instructions"))
        ):
            raise LifecycleConflict("cold instruction requires its original session")
        if session_request_owner(db, worker_id, request_id) != session_owner:
            raise LifecycleConflict("child request key belongs to another operation")
        encoded = canonical(payload)
        old = db.execute(
            "SELECT * FROM intents WHERE worker_id=? AND request_id=?",
            (worker_id, request_id),
        ).fetchone()
        if old:
            if old["payload"] != encoded:
                raise LifecycleConflict("child request key changed its payload")
            return dict(old)
        worker = db.execute(
            "SELECT * FROM workers WHERE worker_id=?", (worker_id,)
        ).fetchone()
        if worker is None or worker["context"] is None or worker["closed"]:
            raise LifecycleConflict("child admission is closed")
        if not self._capacity_available(db, worker_id, policy):
            raise LifecycleConflict("local lifetime child limit is reserved")
        root = json.loads(worker["context"])
        key = "openjules-child:" + digest(
            [worker_id, root["attempt_id"], request_id]
        )
        db.execute(
            "INSERT INTO intents(worker_id,request_id,payload,delivery_key) "
            "VALUES(?,?,?,?)",
            (worker_id, request_id, encoded, key),
        )
        return dict(db.execute(
            "SELECT * FROM intents WHERE worker_id=? AND request_id=?",
            (worker_id, request_id),
        ).fetchone())

    def reserve(
        self, worker_id: str, request_id: str, payload: dict, policy: ChildPolicy
    ) -> dict:
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            return self._reserve_in(db, worker_id, request_id, payload, policy)

    def reject(self, worker_id: str, request_id: str):
        with self.connection() as db:
            db.execute(
                "UPDATE intents SET status='rejected' WHERE worker_id=? AND request_id=? AND child_id IS NULL",
                (worker_id, request_id),
            )

    def intents(self, worker_id: str):
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM intents WHERE worker_id=? ORDER BY rowid",
                    (worker_id,),
                )
            ]

    def grant(
        self,
        worker_id: str,
        request_id: str,
        response: dict,
        deadline: float,
        boot_id: str,
        policy: ChildPolicy,
    ) -> dict:
        child_id = response["binding"]["child_id"]
        immutable = canonical(
            {"binding": response["binding"], "instructions": response["instructions"]}
        )
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            if policy.session_protocol is not None:
                install_session_schema(db, require_existing=True)
            ordinary_request_key(db, worker_id, request_id)
            if getattr(policy, "public_discussion", None) is not None:
                PublicStore(self)._checked(db, worker_id, policy)
            intent = db.execute(
                "SELECT * FROM intents WHERE worker_id=? AND request_id=?",
                (worker_id, request_id),
            ).fetchone()
            if (
                intent is None
                or intent["status"] == "rejected"
                or intent["child_id"] not in {None, child_id}
            ):
                raise LifecycleConflict("canonical child changed its delivery intent")
            old = db.execute(
                "SELECT * FROM children WHERE child_id=?", (child_id,)
            ).fetchone()
            if old:
                previous = json.loads(old["grant_json"])
                if (
                    old["worker_id"] != worker_id
                    or canonical(
                        {
                            "binding": previous["binding"],
                            "instructions": previous["instructions"],
                        }
                    )
                    != immutable
                ):
                    raise LifecycleConflict("canonical child binding changed")
                # A replay may return remaining_seconds=0 after cancellation
                # or final capture. That is current permission, not a rewrite
                # of the original runtime cutoff or evidence of a timeout.
            else:
                ordinal = db.execute(
                    "SELECT COUNT(*) FROM children WHERE worker_id=?", (worker_id,)
                ).fetchone()[0]
                if ordinal >= policy.max_children:
                    raise LifecycleConflict(
                        "canonical grants exceed the owned UID range"
                    )
                db.execute(
                    "INSERT INTO children(child_id,worker_id,ordinal,uid,grant_json,deadline,boot_id) VALUES(?,?,?,?,?,?,?)",
                    (
                        child_id,
                        worker_id,
                        ordinal,
                        policy.uid_start + ordinal,
                        canonical(response),
                        deadline,
                        boot_id,
                    ),
                )
            db.execute(
                "UPDATE intents SET child_id=?,status='bound' WHERE worker_id=? AND request_id=?",
                (child_id, worker_id, request_id),
            )
            bind_session_grant(db, worker_id, request_id, response)
        return self.child(worker_id, child_id)

    def child(self, worker_id: str, child_id: str) -> dict:
        with self.connection() as db:
            row = db.execute(
                "SELECT * FROM children WHERE worker_id=? AND child_id=?",
                (worker_id, child_id),
            ).fetchone()
        if row is None:
            raise LifecycleConflict("child does not belong to this root worker")
        return dict(row)

    def children(self, worker_id: str) -> list[dict]:
        with self.connection() as db:
            return [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM children WHERE worker_id=? ORDER BY ordinal",
                    (worker_id,),
                )
            ]

    def update(self, worker_id: str, child_id: str, **changes):
        allowed = {
            "phase",
            "exec_id",
            "exec_dispatched",
            "armed_deadline",
            "exit_code",
            "revoked",
            "provisional",
            "artifacts",
        }
        if not changes or not set(changes) <= allowed:
            raise ValueError("unsupported child journal transition")
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            old = db.execute(
                "SELECT * FROM children WHERE worker_id=? AND child_id=?",
                (worker_id, child_id),
            ).fetchone()
            if old is None:
                raise LifecycleConflict("child is not owned by this worker")
            if (
                old["exec_id"] is not None
                and changes.get("exec_id", old["exec_id"]) != old["exec_id"]
            ):
                raise LifecycleConflict("child exec identity cannot change")
            if old["exec_dispatched"] and changes.get("exec_dispatched", 1) != 1:
                raise LifecycleConflict("child dispatch intent cannot be cleared")
            if (
                old["armed_deadline"] is not None
                and changes.get("armed_deadline", old["armed_deadline"])
                > old["armed_deadline"]
            ):
                raise LifecycleConflict("armed child deadline cannot be extended")
            if old["revoked"] and changes.get("revoked", 1) != 1:
                raise LifecycleConflict("child revocation cannot be cleared")
            db.execute(
                "UPDATE children SET "
                + ",".join(name + "=?" for name in changes)
                + " WHERE worker_id=? AND child_id=?",
                (*changes.values(), worker_id, child_id),
            )
            if changes.get("phase") in {"exec_returned", "uncertain"}:
                retain_terminal_observation(db, worker_id, child_id)

    def retain_outcome(self, worker_id, child_id, request_key, outcome, summary):
        from src.agent.child_outcome import report_value

        report = report_value(request_key, outcome, summary)
        encoded = canonical(report)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            ordinary_request_key(db, worker_id, request_key)
            child = db.execute(
                "SELECT * FROM children WHERE worker_id=? AND child_id=?",
                (worker_id, child_id),
            ).fetchone()
            if child is None or not child["exec_dispatched"]:
                raise LifecycleConflict("child outcome lacks its dispatched execution")
            if child["outcome_report"] is not None:
                if child["outcome_report"] != encoded:
                    raise LifecycleConflict(
                        "child outcome slot already has different content"
                    )
                return json.loads(child["outcome_report"])
            if child["capture"] is not None:
                raise LifecycleConflict("final child capture is already frozen")
            db.execute(
                "UPDATE children SET outcome_report=? WHERE worker_id=? AND child_id=?",
                (encoded, worker_id, child_id),
            )
        return report

    def freeze_capture(self, worker_id, child_id, contents, state, *, expected_report):
        """Freeze one capture against the report used while reading its archive.

        Archive work stays outside the write transaction. A report arriving in
        the meantime causes a retry from a fresh child snapshot. No acknowledged
        report can be silently omitted from the immutable manifest.
        """
        encoded = canonical({"contents": contents, "state": state})
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            child = db.execute(
                "SELECT * FROM children WHERE worker_id=? AND child_id=?",
                (worker_id, child_id),
            ).fetchone()
            if child is None:
                raise LifecycleConflict("child is not owned by this worker")
            if child["capture"] is not None:
                if child["capture"] != encoded:
                    raise LifecycleConflict("final child capture cannot change")
                return
            if child["outcome_report"] != expected_report:
                raise RuntimeUnavailable(
                    "child report changed before capture freeze; retry"
                )
            db.execute(
                "UPDATE children SET capture=?,phase='captured' WHERE worker_id=? AND child_id=?",
                (encoded, worker_id, child_id),
            )

    def close_admission(self, worker_id: str, reason: str, *, retire=False):
        with self.connection() as db:
            db.execute(
                "UPDATE workers SET closed=1,close_reason=COALESCE(close_reason,?),retire=MAX(retire,?) WHERE worker_id=?",
                (reason, int(retire), worker_id),
            )

    def close_delivered(self, worker_id: str):
        with self.connection() as db:
            db.execute(
                "UPDATE workers SET close_delivered=1 WHERE worker_id=?", (worker_id,)
            )

    def close(self):
        self.service_lock.close()
