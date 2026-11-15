"""Original standalone receipt journal and single host-owner custody.

The journal records admission and observed handler returns, not task completion,
acceptance, cancellation, or release authority. Every possible adapter entry
retains its canonical target fence. There is deliberately no reset/delete API.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass, field
import fcntl
import hashlib
import hmac
import json
import os
from pathlib import Path
import secrets
import sqlite3
import stat
import threading
import time
from urllib.parse import quote

from src.api.ingress_policy import (
    IngressError, Policy, absolute_path, bounded_task, bounded_text,
    canonical_json, digest_json, exact_object, identifier, positive_integer,
    read_private_json, strict_json,
)
from src.worker.execution_context import LegacyExecutionRefused, require_legacy_execution

SCHEMA_VERSION = 1
PROTOCOL = "standalone-ingress-v1"
TASK_READ_LIMIT = 1_048_576
TASK_INVENTORY_ROWS = 32
TASK_INVENTORY_INPUT_LIMIT = 8 * 1_048_576
TASK_INVENTORY_VM_STEPS = 100_000
# A valid selected row has at most 1 MiB of normalized input and much less
# than 16 KiB of identifiers, binding metadata and closed dispatch result.
_INVENTORY_SQLITE_LENGTH = TASK_READ_LIMIT + 16_384
_TASK_COLUMNS = (
    "operation_id", "request_sha256", "principal_id", "binding_id",
    "repository_key", "target_key", "normalized_input", "state", "code",
    "result_json",
)
_RESULT_CODES = frozenset({
    "handler_returned", "handler_outcome_unknown", "registration_outcome_unknown",
    "repository_identity_mismatch", "pull_request_unsupported", "target_unavailable",
    "credential_unavailable", "adapter_refused", "adapter_outcome_unknown",
})
_PROJECTION_CODES = _RESULT_CODES | frozenset({
    "admitted", "dispatch_fenced", "handler_entered", "owner_interrupted",
    "owner_stopped_before_dispatch", "callback_authority_revoked",
    "callback_exit_unobserved", "owner_stopped_before_handler",
})
_SCHEMA = """
CREATE TABLE metadata (name TEXT PRIMARY KEY, value TEXT NOT NULL);
CREATE TABLE activations (
    declaration_id TEXT PRIMARY KEY, declaration_sha256 TEXT NOT NULL,
    operator TEXT NOT NULL, os_uid INTEGER NOT NULL, recorded_at INTEGER NOT NULL,
    journal_id TEXT NOT NULL, policy_id TEXT NOT NULL, policy_digest TEXT NOT NULL,
    repositories_json TEXT NOT NULL, assertion TEXT NOT NULL
);
CREATE TABLE activated_repositories (
    repository_key TEXT PRIMARY KEY, declaration_id TEXT NOT NULL REFERENCES activations(declaration_id)
);
CREATE TABLE policy_enrollments (
    sequence INTEGER PRIMARY KEY AUTOINCREMENT, policy_id TEXT UNIQUE NOT NULL,
    policy_digest TEXT NOT NULL, enrolled_at INTEGER NOT NULL
);
CREATE TABLE binding_identities (binding_id TEXT PRIMARY KEY, identity_sha256 TEXT NOT NULL);
CREATE TABLE principal_identities (principal_id TEXT PRIMARY KEY, authentication_kind TEXT NOT NULL);
CREATE TABLE receipts (
    operation_id TEXT PRIMARY KEY, source_key TEXT UNIQUE NOT NULL,
    request_sha256 TEXT NOT NULL, policy_id TEXT NOT NULL, policy_digest TEXT NOT NULL,
    principal_id TEXT NOT NULL, binding_id TEXT NOT NULL, repository_key TEXT NOT NULL,
    target_key TEXT NOT NULL, normalized_input TEXT NOT NULL, created_at INTEGER NOT NULL,
    state TEXT NOT NULL, code TEXT NOT NULL, result_json TEXT,
    owner_epoch TEXT, nonce_sha256 TEXT, callback_entered INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE target_fences (
    target_key TEXT PRIMARY KEY, operation_id TEXT UNIQUE NOT NULL REFERENCES receipts(operation_id)
);
PRAGMA user_version=1;
"""


def _unavailable(code="receipt_store_unavailable"):
    raise IngressError(code, 503)


def _private_directory(path: Path, *, create=False):
    try:
        if create and not path.exists():
            path.mkdir(mode=0o700)
        info = path.lstat()
        if (
            not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077 or path.resolve(strict=True) != path
        ):
            _unavailable("private_directory_required")
    except OSError:
        _unavailable("private_directory_required")


def _regular_identity(path):
    try:
        info = path.lstat()
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077 or info.st_nlink != 1
        ):
            _unavailable()
        return info.st_dev, info.st_ino
    except OSError:
        _unavailable()


def _connect_existing(path):
    connection = sqlite3.connect(
        f"file:{quote(str(path), safe='/')}?mode=rw", uri=True,
        isolation_level=None, timeout=0, check_same_thread=False,
    )
    connection.row_factory = sqlite3.Row
    connection.execute("PRAGMA foreign_keys=ON")
    connection.execute("PRAGMA trusted_schema=OFF")
    connection.execute("PRAGMA synchronous=FULL")
    return connection


def initialize_store(path):
    """Create a private original journal and its lock, never replace either."""
    require_legacy_execution()
    path = absolute_path(os.fspath(path))
    _private_directory(path.parent, create=True)
    lock_path = Path(str(path) + ".lock")
    if os.path.lexists(path) or os.path.lexists(lock_path):
        raise IngressError("receipt_store_exists", 409)
    connection, lock_fd = None, None
    try:
        # Creation is intentionally fail closed: a partial failed initialization
        # is not silently deleted or reinterpreted as a fresh journal.
        lock_fd = os.open(lock_path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        fcntl.flock(lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
        fd = os.open(path, os.O_RDWR | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
        os.close(fd)
        journal_id, lock_id = secrets.token_hex(16), secrets.token_hex(16)
        connection = _connect_existing(path)
        connection.executescript(_SCHEMA)
        lock_info = os.fstat(lock_fd)
        connection.execute("BEGIN IMMEDIATE")
        connection.executemany("INSERT INTO metadata(name,value) VALUES(?,?)", [
            ("schema_version", str(SCHEMA_VERSION)), ("journal_id", journal_id),
            ("lock_id", lock_id), ("lock_device", str(lock_info.st_dev)),
            ("lock_inode", str(lock_info.st_ino)),
        ])
        connection.execute("COMMIT")
        device, inode = _regular_identity(path)
        data = canonical_json({
            "schema_version": 1, "journal_id": journal_id, "lock_id": lock_id,
            "store_device": device, "store_inode": inode,
        }).encode("utf-8")
        os.write(lock_fd, data)
        os.fsync(lock_fd)
        directory_fd = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory_fd)
        finally:
            os.close(directory_fd)
        return {"schema_version": SCHEMA_VERSION, "journal_id": journal_id}
    except FileExistsError:
        raise IngressError("receipt_store_exists", 409) from None
    except (OSError, sqlite3.Error):
        _unavailable()
    finally:
        if connection is not None:
            connection.close()
        if lock_fd is not None:
            os.close(lock_fd)


class _Owner:
    def __init__(self, path, journal_id):
        self.pid = os.getpid()
        self.path = absolute_path(os.fspath(path))
        self.lock_path = Path(str(self.path) + ".lock")
        self.connection = None
        self.lock_fd = None
        _private_directory(self.path.parent)
        try:
            self.lock_identity = _regular_identity(self.lock_path)
            self.lock_fd = os.open(self.lock_path, os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK)
            info = os.fstat(self.lock_fd)
            if (info.st_dev, info.st_ino) != self.lock_identity:
                _unavailable("receipt_store_replaced")
            try:
                fcntl.flock(self.lock_fd, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                _unavailable("receipt_store_owned")
            lock = strict_json(os.read(self.lock_fd, 4097), 4096)
            exact_object(lock, {"schema_version", "journal_id", "lock_id", "store_device", "store_inode"})
            if (type(lock["schema_version"]) is not int or lock["schema_version"] != 1
                    or lock["journal_id"] != journal_id
                    or type(lock["store_device"]) is not int or type(lock["store_inode"]) is not int):
                _unavailable("receipt_store_identity_mismatch")
            self.store_identity = _regular_identity(self.path)
            if self.store_identity != (lock["store_device"], lock["store_inode"]):
                _unavailable("receipt_store_replaced")
            self.connection = _connect_existing(self.path)
            if self.connection.execute("PRAGMA user_version").fetchone()[0] != SCHEMA_VERSION:
                _unavailable("receipt_schema_unsupported")
            if self.connection.execute("PRAGMA journal_mode").fetchone()[0] != "delete":
                _unavailable("receipt_schema_unsupported")
            meta = dict(self.connection.execute("SELECT name,value FROM metadata").fetchall())
            if (meta.get("schema_version"), meta.get("journal_id"), meta.get("lock_id")) != ("1", journal_id, lock["lock_id"]):
                _unavailable("receipt_store_identity_mismatch")
            if (meta.get("lock_device"), meta.get("lock_inode")) != tuple(str(part) for part in self.lock_identity):
                _unavailable("receipt_store_replaced")
            self.verify()
        except IngressError:
            self.close()
            raise
        except (OSError, sqlite3.Error, ValueError, TypeError):
            self.close()
            _unavailable()

    def verify(self):
        if os.getpid() != self.pid:
            _unavailable("owner_process_changed")
        if self.lock_fd is None or self.connection is None:
            _unavailable()
        _private_directory(self.path.parent)
        if _regular_identity(self.path) != self.store_identity or _regular_identity(self.lock_path) != self.lock_identity:
            _unavailable("receipt_store_replaced")
        info = os.fstat(self.lock_fd)
        if (info.st_dev, info.st_ino) != self.lock_identity:
            _unavailable("receipt_store_replaced")

    def close(self):
        if self.connection is not None:
            self.connection.close()
            self.connection = None
        if self.lock_fd is not None:
            os.close(self.lock_fd)
            self.lock_fd = None


@contextmanager
def _transaction(owner):
    owner.verify()
    try:
        owner.connection.execute("BEGIN IMMEDIATE")
        yield owner.connection
        owner.verify()
        owner.connection.execute("COMMIT")
    except BaseException as exc:
        if owner.connection.in_transaction:
            owner.connection.execute("ROLLBACK")
        if isinstance(exc, (sqlite3.Error, OSError)):
            _unavailable()
        raise


def _metadata(connection):
    return dict(connection.execute("SELECT name,value FROM metadata").fetchall())


def enroll_policy(policy: Policy, activation_path=None, *, review_activation_paths=()):
    """Stopped-owner enrollment, retaining every prior identity and fence.

    A first activation is an attributable host assertion of isolated fresh
    scope. It is not inferred from an empty database or proof about other hosts.
    Existing or unknown prior work has no import/override route in this slice.
    """
    require_legacy_execution()
    policy.ensure_current()
    owner = _Owner(policy.store_path, policy.journal_id)
    try:
        with _transaction(owner) as connection:
            repositories = {b.canonical_repository for b in policy.bindings.values()
                if b.review_profile is None or any("task.start" in p.grants.get(b.binding_id, ())
                    for p in policy.principals.values())}
            existing = {row[0] for row in connection.execute("SELECT repository_key FROM activated_repositories")}
            newly_activated = repositories - existing
            if newly_activated:
                if activation_path is None:
                    raise IngressError("fresh_activation_required", 409)
                declaration = read_private_json(activation_path)
                exact_object(declaration, {
                    "schema_version", "declaration_id", "journal_id", "policy_id", "policy_digest",
                    "repositories", "operator", "assertion",
                })
                if type(declaration["schema_version"]) is not int or declaration["schema_version"] != 1:
                    raise IngressError("invalid_activation", 422)
                declaration_id = identifier(declaration["declaration_id"])
                operator = bounded_text(declaration["operator"], 256)
                if any(ord(c) < 32 or ord(c) == 127 for c in operator):
                    raise IngressError("invalid_activation", 422)
                declared_repositories = declaration["repositories"]
                if (
                    declaration["assertion"] != "fresh_isolated_scope"
                    or declaration["journal_id"] != policy.journal_id
                    or declaration["policy_id"] != policy.policy_id
                    or declaration["policy_digest"] != policy.digest
                    or type(declared_repositories) is not list
                    or any(not isinstance(value, str) for value in declared_repositories)
                    or len(declared_repositories) != len(set(declared_repositories))
                    or set(declared_repositories) != newly_activated
                ):
                    raise IngressError("invalid_activation", 422)
                if connection.execute("SELECT 1 FROM activations WHERE declaration_id=?", (declaration_id,)).fetchone():
                    raise IngressError("activation_exists", 409)
                connection.execute("INSERT INTO activations VALUES(?,?,?,?,?,?,?,?,?,?)", (
                    declaration_id, digest_json(declaration), operator, os.getuid(), int(time.time()),
                    policy.journal_id, policy.policy_id, policy.digest,
                    canonical_json(sorted(newly_activated)), "fresh_isolated_scope",
                ))
                connection.executemany("INSERT INTO activated_repositories VALUES(?,?)", [
                    (repository, declaration_id) for repository in sorted(newly_activated)
                ])
            elif activation_path is not None:
                raise IngressError("activation_already_recorded", 409)
            from src.storage.review_receipts import enroll_review_scopes
            enroll_review_scopes(connection, policy, review_activation_paths)
            previous = connection.execute("SELECT policy_digest FROM policy_enrollments WHERE policy_id=?", (policy.policy_id,)).fetchone()
            if previous is not None and previous[0] != policy.digest:
                raise IngressError("policy_identity_conflict", 409)
            for binding in policy.bindings.values():
                binding_digest = digest_json(binding.effect_input())
                row = connection.execute("SELECT identity_sha256 FROM binding_identities WHERE binding_id=?", (binding.binding_id,)).fetchone()
                if row is not None and row[0] != binding_digest:
                    raise IngressError("binding_identity_conflict", 409)
                connection.execute("INSERT OR IGNORE INTO binding_identities VALUES(?,?)", (binding.binding_id, binding_digest))
            for principal in policy.principals.values():
                row = connection.execute("SELECT authentication_kind FROM principal_identities WHERE principal_id=?", (principal.principal_id,)).fetchone()
                if row is not None and row[0] != principal.kind:
                    raise IngressError("principal_identity_conflict", 409)
                connection.execute("INSERT OR IGNORE INTO principal_identities VALUES(?,?)", (principal.principal_id, principal.kind))
            if previous is None:
                connection.execute("INSERT INTO policy_enrollments(policy_id,policy_digest,enrolled_at) VALUES(?,?,?)", (policy.policy_id, policy.digest, int(time.time())))
            connection.executemany("INSERT OR REPLACE INTO metadata(name,value) VALUES(?,?)", [
                ("active_policy_id", policy.policy_id), ("active_policy_digest", policy.digest),
            ])
        return {"schema_version": 1, "journal_id": policy.journal_id, "policy_id": policy.policy_id, "policy_digest": policy.digest, "enrolled": True}
    finally:
        owner.close()


@dataclass(frozen=True)
class DispatchTicket:
    operation_id: str
    _owner_epoch: str = field(repr=False)
    _nonce: str = field(repr=False)


@dataclass(frozen=True)
class CallbackInvocation:
    """One actual callback wrapper, including its post-handler cleanup tail."""

    operation_id: str
    _ticket: DispatchTicket = field(repr=False)
    _invocation_id: str = field(repr=False)


def _projection(row):
    state = row["state"]
    statuses = {"reserved": "admitted", "may_have_started": "admitted", "returned": "observed", "refused_before_effect": "refused", "reconciliation_required": "unknown"}
    if state not in statuses or row["code"] not in _PROJECTION_CODES:
        _unavailable("receipt_state_invalid")
    result = {
        "schema_version": 1, "protocol": PROTOCOL, "operation_id": row["operation_id"],
        "status": statuses[state], "dispatch_state": state,
        "managed_authority": False, "release_authorized": False, "code": row["code"],
    }
    if row["result_json"] is not None:
        try:
            observed = json.loads(row["result_json"])
        except (ValueError, TypeError, RecursionError):
            _unavailable("receipt_state_invalid")
        from src.storage.review_receipts import is_review, project_review_result
        if is_review(row):
            observed = project_review_result(row, observed)
            if result["status"] != "unknown" and observed["status"] in {"refused", "unknown"}:
                result["status"] = observed["status"]
        elif type(observed) is not dict or set(observed) != {"handler_return"} or type(observed["handler_return"]) is not bool:
            _unavailable("receipt_state_invalid")
        result["result"] = observed
    return result


def _task_projection(row, binding, policy, *, summary=False):
    """Validate the original admission before projecting any retained task text."""
    try:
        retained = row["normalized_input"]
        if type(retained) is not str:
            raise ValueError()
        normalized = strict_json(retained.encode("utf-8"), TASK_READ_LIMIT)
        exact_object(normalized, {"principal_id", "binding_id", "binding", "task",
            "source_kind", "source_id", "request_key", "actor_id"})
        task = bounded_task(normalized["task"])
        if (
            digest_json(normalized) != row["request_sha256"]
            or normalized["principal_id"] != row["principal_id"]
            or normalized["binding_id"] != row["binding_id"]
            or normalized["binding"] != binding.effect_input()
            or row["repository_key"] != binding.canonical_repository
            or row["target_key"] != f"{binding.canonical_repository}:issue:{task['issue_id']}:task.start"
            or normalized["source_kind"] not in {"operator_task", "github_issue_initial", "github_issue_comment"}
        ):
            raise ValueError()
        policy.assert_no_ingress_secrets(normalized)
        result = {
            "schema_version": 1, "protocol": PROTOCOL, "observation": "retained_dispatch",
            "operation_id": row["operation_id"], "binding_id": row["binding_id"],
            "repository": {"forge": binding.forge, "repository": binding.repository,
                "repository_id": binding.repository_id},
            "task": {name: task[name] for name in ("issue_id", "issue_title")} if summary else task,
            "receipt": _projection(row),
            "managed_authority": False, "release_authorized": False,
        }
        if len(canonical_json(result).encode("utf-8")) > TASK_READ_LIMIT:
            raise ValueError()
    except (IngressError, ValueError, TypeError, KeyError, UnicodeError, RecursionError):
        _unavailable("task_state_invalid")
    return result


@contextmanager
def _inventory_query_limits(connection):
    """Bound this query's VM work and values, then restore before transaction cleanup.

    The connection is owned here and normally has no progress handler. Both
    selections share at most 100,000 progress callbacks with interval one.
    SQLite's instruction interval is approximate; this is not a bound on
    filesystem syscall or wall-clock duration.
    """
    previous_length = connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
    remaining = TASK_INVENTORY_VM_STEPS

    def progress():
        nonlocal remaining
        remaining -= 1
        return remaining <= 0

    try:
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH,
                            min(previous_length, _INVENTORY_SQLITE_LENGTH))
        connection.set_progress_handler(progress, 1)
        yield
    except sqlite3.Error:
        _unavailable("task_inventory_unavailable")
    finally:
        connection.set_progress_handler(None, 0)
        connection.setlimit(sqlite3.SQLITE_LIMIT_LENGTH, previous_length)


class ReceiptStore:
    """One service owner; use a fresh object after a fully stopped epoch."""

    def __init__(self, policy: Policy, *, epoch_validator=None, review_credentials=None):
        require_legacy_execution()
        policy.ensure_current()
        self.policy = policy
        self._epoch_validator = epoch_validator
        self._review_credentials = dict(review_credentials or {})
        if epoch_validator is not None:
            epoch_validator()
        self._mutex = threading.RLock()
        self._owner = _Owner(policy.store_path, policy.journal_id)
        self._epoch = secrets.token_hex(16)
        self._admitting = True
        self._closed = False
        self._tickets = {}
        self._entered = set()
        self._invocations = {}
        self._claim_owners = {}
        try:
            with _transaction(self._owner) as connection:
                self._check_policy(connection, admission=True)
                # Nothing is rescheduled after an owner interruption. A reserved
                # row proves the prequeue durable fence was never acquired.
                connection.execute("UPDATE receipts SET state='reconciliation_required',code='owner_interrupted',nonce_sha256=NULL WHERE state='may_have_started'")
                connection.execute("DELETE FROM target_fences WHERE operation_id IN (SELECT operation_id FROM receipts WHERE state='reserved')")
                connection.execute("UPDATE receipts SET state='refused_before_effect',code='owner_stopped_before_dispatch',nonce_sha256=NULL WHERE state='reserved'")
        except BaseException:
            self._owner.close()
            raise

    def __enter__(self):
        return self

    def __exit__(self, *_):
        self.close_admission()
        self.close()

    def _check_policy(self, connection, *, admission=False):
        self.policy.ensure_current()
        metadata = _metadata(connection)
        if (metadata.get("active_policy_id"), metadata.get("active_policy_digest")) != (self.policy.policy_id, self.policy.digest):
            _unavailable("policy_not_enrolled")
        from src.storage.review_receipts import ensure_review_scopes
        ensure_review_scopes(connection, self.policy)
        if admission and self._epoch_validator is not None:
            self._epoch_validator()

    def _check_open(self, *, admission=False):
        if self._closed:
            _unavailable("receipt_store_closed")
        if admission and not self._admitting:
            _unavailable("admission_closed")

    def _row(self, connection, operation_id):
        row = connection.execute("SELECT * FROM receipts WHERE operation_id=?", (operation_id,)).fetchone()
        if row is None:
            raise IngressError("receipt_not_found", 404)
        return row

    def _visible_conflict(self, row, principal_id):
        from src.storage.review_receipts import is_review
        operation = ("review.start" if is_review(row) else "task.start") if row["principal_id"] == principal_id else "receipt.read"
        try:
            self.policy.require_grant(principal_id, row["binding_id"], operation)
        except IngressError:
            return None
        return _projection(row)

    def reserve(self, principal_id, binding_id, source_kind, source_id, request_key, task, actor_id=None, *, allow_new=True):
        with self._mutex:
            self._check_open()
            if type(allow_new) is not bool:
                raise IngressError("invalid_admission_capacity", 422)
            self.policy.ensure_current()
            binding = self.policy.require_grant(principal_id, binding_id, "task.start")
            principal = self.policy.principals[principal_id]
            task = bounded_task(task)
            if source_kind == "operator_task":
                if principal.kind != "bearer" or source_id is not None or actor_id is not None:
                    raise IngressError("invalid_source", 422)
                bounded_text(request_key, 256)
                if any(ord(c) < 33 or ord(c) > 126 for c in request_key):
                    raise IngressError("invalid_idempotency_key", 422)
                source = ["operator", principal_id, request_key]
            elif source_kind in ("github_issue_initial", "github_issue_comment"):
                positive_integer(source_id)
                positive_integer(actor_id)
                if principal.kind != "github_hmac_sha256" or actor_id not in principal.actor_ids or request_key is not None:
                    raise IngressError("scope_denied", 403)
                if source_kind == "github_issue_initial" and source_id != task["issue_id"]:
                    raise IngressError("invalid_source", 422)
                source = ["github", binding.repository_id, "task.start", source_kind, source_id]
            else:
                raise IngressError("unsupported_source", 404)
            normalized = {
                "principal_id": principal_id, "binding_id": binding_id,
                "binding": binding.effect_input(), "task": task,
                "source_kind": source_kind, "source_id": source_id,
                "request_key": request_key, "actor_id": actor_id,
            }
            self.policy.assert_no_ingress_secrets(normalized)
            source_key = digest_json(source)
            request_digest = digest_json(normalized)
            target_key = f"{binding.canonical_repository}:issue:{task['issue_id']}:task.start"
            with _transaction(self._owner) as connection:
                self._check_policy(connection)
                row = connection.execute("SELECT * FROM receipts WHERE source_key=?", (source_key,)).fetchone()
                if row is not None:
                    if row["request_sha256"] != request_digest:
                        raise IngressError("source_identity_conflict", 409, receipt=self._visible_conflict(row, principal_id))
                    return _projection(row)
                fenced = connection.execute("SELECT receipts.* FROM target_fences JOIN receipts USING(operation_id) WHERE target_fences.target_key=?", (target_key,)).fetchone()
                if fenced:
                    raise IngressError("target_action_fenced", 409, receipt=self._visible_conflict(fenced, principal_id))
                self._check_open(admission=True)
                if not allow_new:
                    raise IngressError("ingress_callbacks_unavailable", 503)
                if self._epoch_validator is not None:
                    self._epoch_validator()
                operation_id = secrets.token_hex(16)
                connection.execute("""INSERT INTO receipts
                    (operation_id,source_key,request_sha256,policy_id,policy_digest,principal_id,binding_id,
                     repository_key,target_key,normalized_input,created_at,state,code)
                    VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?)""", (
                    operation_id, source_key, request_digest, self.policy.policy_id, self.policy.digest,
                    principal_id, binding_id, binding.canonical_repository, target_key,
                    canonical_json(normalized), int(time.time()), "reserved", "admitted",
                ))
                connection.execute("INSERT INTO target_fences VALUES(?,?)", (target_key, operation_id))
                return _projection(self._row(connection, operation_id))

    def reserve_review(self, principal_id, binding_id, review, actor_id, *, allow_new=True):
        from src.storage.review_receipts import reserve_review
        return reserve_review(self, principal_id, binding_id, review, actor_id, allow_new=allow_new)

    def review_claim(self, invocation, original):
        from src.storage.review_receipts import make_claim
        return make_claim(self, invocation, original)

    def finish_review(self, invocation, outcome):
        from src.storage.review_receipts import finish_review
        return finish_review(self, invocation, outcome)

    def fence(self, operation_id, principal_id):
        identifier(operation_id)
        identifier(principal_id)
        with self._mutex:
            self._check_open()
            with _transaction(self._owner) as connection:
                self._check_policy(connection)
                row = self._row(connection, operation_id)
                if row["principal_id"] != principal_id:
                    raise IngressError("scope_denied", 403)
                from src.storage.review_receipts import is_review, bind_fence_clock
                self.policy.require_grant(principal_id, row["binding_id"], "review.start" if is_review(row) else "task.start")
                if row["state"] != "reserved":
                    return None
                try:
                    self._check_open(admission=True)
                    if self._epoch_validator is not None:
                        self._epoch_validator()
                except IngressError as exc:
                    raise IngressError(exc.code, exc.status, receipt=_projection(row)) from None
                ticket = DispatchTicket(operation_id, self._epoch, secrets.token_hex(32))
                if is_review(row):
                    bind_fence_clock(self, connection, row)
                connection.execute("UPDATE receipts SET state='may_have_started',code='dispatch_fenced',owner_epoch=?,nonce_sha256=? WHERE operation_id=? AND state='reserved'", (
                    self._epoch, hashlib.sha256(ticket._nonce.encode()).hexdigest(), operation_id,
                ))
            self._tickets[operation_id] = ticket
            return ticket

    def _matches(self, ticket, row):
        return (
            isinstance(ticket, DispatchTicket) and ticket._owner_epoch == self._epoch
            and self._tickets.get(ticket.operation_id) == ticket
            and row["owner_epoch"] == self._epoch and row["nonce_sha256"] is not None
            and hmac.compare_digest(row["nonce_sha256"], hashlib.sha256(ticket._nonce.encode()).hexdigest())
        )

    def begin_callback(self, ticket):
        """Register the actual wrapper before it waits for an execution slot."""
        with self._mutex:
            if self._closed or not isinstance(ticket, DispatchTicket) or self._tickets.get(ticket.operation_id) != ticket:
                return None
            invocation = CallbackInvocation(ticket.operation_id, ticket, secrets.token_hex(16))
            self._invocations[invocation._invocation_id] = invocation
            return invocation

    def _owns_invocation(self, invocation):
        return isinstance(invocation, CallbackInvocation) and self._invocations.get(invocation._invocation_id) == invocation

    def claim_callback(self, invocation):
        with self._mutex:
            if self._closed or not self._owns_invocation(invocation):
                return None
            ticket = invocation._ticket
            if self._tickets.get(ticket.operation_id) != ticket or ticket.operation_id in self._entered:
                return None
            with _transaction(self._owner) as connection:
                row = self._row(connection, ticket.operation_id)
                if row["state"] != "may_have_started" or not self._matches(ticket, row) or row["callback_entered"]:
                    return None
                refusal = None
                try:
                    if not self._admitting:
                        raise IngressError("admission_closed", 503)
                    self._check_policy(connection, admission=True)
                    from src.storage.review_receipts import is_review, validate_original
                    if is_review(row):
                        binding = self.policy.require_grant(row["principal_id"], row["binding_id"], "review.start")
                        normalized = validate_original(self, connection, row, binding)
                    else:
                        binding = self.policy.require_grant(row["principal_id"], row["binding_id"], "task.start")
                        normalized = strict_json(row["normalized_input"].encode(), 1_048_576)
                        if digest_json(normalized) != row["request_sha256"] or normalized.get("binding") != binding.effect_input():
                            raise IngressError("original_input_unavailable", 503)
                        bounded_task(normalized["task"])
                        if normalized.get("principal_id") != row["principal_id"] or normalized.get("binding_id") != row["binding_id"]:
                            raise IngressError("original_input_unavailable", 503)
                        self.policy.assert_no_ingress_secrets(normalized)
                except (IngressError, LegacyExecutionRefused, KeyError, TypeError):
                    refusal = "callback_authority_revoked"
                if refusal:
                    connection.execute("UPDATE receipts SET state='refused_before_effect',code=?,nonce_sha256=NULL WHERE operation_id=? AND callback_entered=0", (refusal, ticket.operation_id))
                    connection.execute("DELETE FROM target_fences WHERE operation_id=?", (ticket.operation_id,))
                    return None
                connection.execute("UPDATE receipts SET callback_entered=1,code='handler_entered' WHERE operation_id=? AND callback_entered=0", (ticket.operation_id,))
            self._entered.add(ticket.operation_id)
            self._claim_owners[ticket.operation_id] = invocation._invocation_id
            normalized["operation_id"] = ticket.operation_id
            return normalized

    def finish(self, invocation, *, handler_return, code="handler_returned"):
        if handler_return is not None and type(handler_return) is not bool:
            raise IngressError("invalid_handler_result", 422)
        if code not in _RESULT_CODES:
            raise IngressError("invalid_result_code", 422)
        with self._mutex:
            self._check_open()
            if not self._owns_invocation(invocation):
                raise IngressError("callback_not_owned", 409)
            ticket = invocation._ticket
            with _transaction(self._owner) as connection:
                row = self._row(connection, ticket.operation_id)
                from src.storage.review_receipts import is_review
                if is_review(row):
                    raise IngressError("invalid_handler_result", 422)
                if self._claim_owners.get(ticket.operation_id) != invocation._invocation_id or ticket.operation_id not in self._entered or not self._matches(ticket, row) or not row["callback_entered"]:
                    raise IngressError("callback_not_owned", 409)
                result = None if handler_return is None else canonical_json({"handler_return": handler_return})
                connection.execute("UPDATE receipts SET state='returned',code=?,result_json=? WHERE operation_id=?", (code, result, ticket.operation_id))
                result = _projection(self._row(connection, ticket.operation_id))
            self._entered.discard(ticket.operation_id)
            # Retain the ticket until the caller's finally acknowledges that its
            # actual thread has exited, including shutdown/cancellation paths.
            return result

    def _unknown(self, ticket, code, *, invocation=None):
        if code not in _RESULT_CODES:
            raise IngressError("invalid_result_code", 422)
        with self._mutex:
            self._check_open()
            with _transaction(self._owner) as connection:
                row = self._row(connection, ticket.operation_id)
                if self._tickets.get(ticket.operation_id) != ticket or ticket._owner_epoch != self._epoch:
                    raise IngressError("callback_not_owned", 409)
                if invocation is not None and (not self._owns_invocation(invocation) or self._claim_owners.get(ticket.operation_id) not in (None, invocation._invocation_id)):
                    raise IngressError("callback_not_owned", 409)
                if row["state"] not in ("returned", "refused_before_effect"):
                    connection.execute("UPDATE receipts SET state='reconciliation_required',code=? WHERE operation_id=?", (code, ticket.operation_id))
                result = _projection(self._row(connection, ticket.operation_id))
            if invocation is not None:
                self._entered.discard(ticket.operation_id)
            return result

    def uncertain(self, invocation, code="handler_outcome_unknown"):
        if not isinstance(invocation, CallbackInvocation):
            raise IngressError("callback_not_owned", 409)
        return self._unknown(invocation._ticket, code, invocation=invocation)

    def registration_failed(self, ticket):
        return self._unknown(ticket, "registration_outcome_unknown")

    def callback_quiesced(self, invocation):
        """Caller acknowledgement after the actual callback/thread has ended."""
        with self._mutex:
            if self._closed:
                return
            if isinstance(invocation, DispatchTicket):
                ticket = invocation
                # Only failed registration has no actual invocation. An original
                # dispatch ticket cannot acknowledge any running wrapper.
                if any(item.operation_id == ticket.operation_id for item in self._invocations.values()):
                    return
            elif self._owns_invocation(invocation):
                ticket = invocation._ticket
            else:
                return
            if self._tickets.get(ticket.operation_id) != ticket:
                return
            with _transaction(self._owner) as connection:
                row = self._row(connection, ticket.operation_id)
                owns_claim = isinstance(invocation, CallbackInvocation) and self._claim_owners.get(ticket.operation_id) == invocation._invocation_id
                others = any(item.operation_id == ticket.operation_id and item != invocation for item in self._invocations.values())
                unobserved_exit = row["state"] == "may_have_started" and (
                    owns_claim or isinstance(invocation, DispatchTicket)
                    or (not others and ticket.operation_id not in self._claim_owners)
                )
                if unobserved_exit:
                    connection.execute("UPDATE receipts SET state='reconciliation_required',code='callback_exit_unobserved',nonce_sha256=NULL WHERE operation_id=?", (ticket.operation_id,))
            if isinstance(invocation, CallbackInvocation):
                self._invocations.pop(invocation._invocation_id, None)
                if owns_claim:
                    self._entered.discard(ticket.operation_id)
                    self._claim_owners.pop(ticket.operation_id, None)
            if not any(item.operation_id == ticket.operation_id for item in self._invocations.values()):
                # The final wrapper acknowledgement releases local custody,
                # never the canonical fence of a possible adapter attempt.
                if row["state"] != "may_have_started" or unobserved_exit:
                    self._tickets.pop(ticket.operation_id, None)

    def read(self, operation_id, principal_id):
        identifier(operation_id)
        identifier(principal_id)
        with self._mutex:
            self._check_open()
            with _transaction(self._owner) as connection:
                self._check_policy(connection)
                row = self._row(connection, operation_id)
                # Scope uses the original binding. A newly named alias does not
                # expose another binding's retained private receipt.
                try:
                    self.policy.require_grant(principal_id, row["binding_id"], "receipt.read")
                except IngressError:
                    raise IngressError("receipt_not_found", 404) from None
                return _projection(row)

    def read_task(self, operation_id, principal_id):
        """Read original admitted task data, never a live execution or task ledger.

        task.read is independent of task.start and receipt.read. It permits
        this closed task projection, including its dispatch observation, only
        under the original stored repository binding and current host policy.
        """
        identifier(operation_id)
        identifier(principal_id)
        with self._mutex:
            self._check_open()
            with _transaction(self._owner) as connection:
                self._check_policy(connection)
                row = connection.execute("SELECT * FROM receipts WHERE operation_id=?", (operation_id,)).fetchone()
                if row is None:
                    raise IngressError("task_not_found", 404)
                try:
                    binding = self.policy.require_grant(principal_id, row["binding_id"], "task.read")
                except IngressError:
                    raise IngressError("task_not_found", 404) from None
                if type(row["target_key"]) is not str:
                    _unavailable("task_state_invalid")
                if not row["target_key"].endswith(":task.start"):
                    raise IngressError("task_not_found", 404)
                return _task_projection(row, binding, self.policy)

    def list_tasks(self, principal_id):
        """A complete bounded snapshot of original, exactly scoped task admissions.

        task.read also permits discovery within its original binding. Neither
        legacy dashboard IDs nor repository aliases grant access to these rows.
        """
        identifier(principal_id)
        with self._mutex:
            self._check_open()
            with _transaction(self._owner) as connection:
                self._check_policy(connection)
                principal = self.policy.principals.get(principal_id)
                bindings = {} if principal is None else {
                    name: self.policy.require_grant(principal_id, name, "task.read")
                    for name, operations in principal.grants.items()
                    if "task.read" in operations
                }
                if not bindings:
                    raise IngressError("scope_denied", 403)
                result = {
                    "schema_version": 1, "protocol": PROTOCOL,
                    "observation": "retained_dispatch_inventory", "tasks": [],
                    "managed_authority": False, "release_authorized": False,
                }
                with _inventory_query_limits(connection):
                    # Count and size the authorized task rows before fetching
                    # their full private data. The original transaction keeps
                    # both selections on the same journal snapshot. LIMIT alone
                    # does not bound the scan, hence the shared VM allowance.
                    placeholders = ",".join("?" for _ in bindings)
                    sizes = "+".join(f"coalesce(length(CAST({name} AS BLOB)),0)"
                                     for name in _TASK_COLUMNS)
                    selected = connection.execute(
                        "SELECT CASE WHEN typeof(operation_id)='text' "
                        "AND length(CAST(operation_id AS BLOB))<=128 THEN operation_id END AS operation_id,"
                        "(typeof(target_key)='text' AND substr(target_key,-11)=':task.start') AS is_task,"
                        f"({sizes}) AS selected_bytes FROM receipts "
                        f"WHERE binding_id IN ({placeholders}) "
                        "AND NOT (typeof(target_key)='text' AND substr(target_key,-13)=':review.start') "
                        "ORDER BY operation_id LIMIT ?",
                        (*sorted(bindings), TASK_INVENTORY_ROWS + 1),
                    ).fetchall()
                    if len(selected) > TASK_INVENTORY_ROWS:
                        _unavailable("task_inventory_unavailable")
                    if sum(row["selected_bytes"] for row in selected) > TASK_INVENTORY_INPUT_LIMIT:
                        _unavailable("task_inventory_unavailable")
                    operations = []
                    for row in selected:
                        try:
                            if row["is_task"] != 1:
                                raise IngressError("task_state_invalid", 503)
                            operations.append(identifier(row["operation_id"]))
                        except IngressError:
                            _unavailable("task_state_invalid")
                    if operations:
                        slots = ",".join("?" for _ in operations)
                        cursor = connection.execute(
                            f"SELECT {','.join(_TASK_COLUMNS)} FROM receipts "
                            f"WHERE operation_id IN ({slots}) ORDER BY operation_id", operations)
                        for row in cursor:
                            item = _task_projection(row, bindings[row["binding_id"]], self.policy,
                                                    summary=True)
                            result["tasks"].append({name: item[name] for name in (
                                "operation_id", "binding_id", "repository", "task", "receipt")})
                    if len(canonical_json(result).encode("utf-8")) > TASK_READ_LIMIT:
                        _unavailable("task_inventory_unavailable")
                return result

    def close_admission(self):
        with self._mutex:
            if self._closed:
                return
            self._admitting = False
            with _transaction(self._owner) as connection:
                # These rows prove no callback crossed the entire adapter
                # boundary. Entered/unknown/returned fences are never released.
                connection.execute("DELETE FROM target_fences WHERE operation_id IN (SELECT operation_id FROM receipts WHERE state IN ('reserved','may_have_started') AND callback_entered=0)")
                connection.execute("UPDATE receipts SET state='refused_before_effect',code='owner_stopped_before_handler',nonce_sha256=NULL WHERE state IN ('reserved','may_have_started') AND callback_entered=0")

    def close(self):
        with self._mutex:
            if self._closed:
                return
            if self._tickets or self._entered or self._invocations:
                raise IngressError("callbacks_active", 503)
            self._admitting = False
            self._owner.close()
            self._closed = True
