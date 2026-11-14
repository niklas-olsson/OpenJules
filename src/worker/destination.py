"""Opt-in identity for one original local execution journal set.

Only explicit host initialization creates identities. The HTTP protocol exposes
opaque identifiers; complete policy fingerprints and state paths stay private.
This is not distributed authority, an admission ceiling or rollback protection.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import dataclass
import fcntl
import json
import os
from pathlib import Path
import re
import sqlite3
import stat
from uuid import uuid4


IDENTITY_TABLE = "openjules_destination_identity"
APPLICATION_ID = 0x4F4A4432  # OJD2: survives loss of the identity table.
BINDING_FIELDS = frozenset({
    "destination_id", "journal_incarnation", "policy_binding_id",
    "policy_binding_version",
})
DESTINATION_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}\Z")
OPAQUE_ID = re.compile(r"[0-9a-f]{32}\Z")
MAX_STATE_BYTES = 1_000_000
REQUIRED_FEATURES = ["identity_binding_v1"]
MARKER_COLUMNS = (
    "singleton", "format_version", "required_features", "destination_id",
    "journal_incarnation", "member", "application_schema",
)
APPLICATION_TABLES = {
    "lifecycle": {"managed_workers", "worker_operations", "worker_executions"},
    "runtime": {"profiles", "workers", "attempts", "child_profiles"},
    "dispatcher": {"deliveries"},
    "models": {"policies", "workers", "calls"},
    "children": {"workers", "intents", "children"},
}


class DestinationConflict(ValueError):
    """Supplied identity does not match the original scoped destination."""


class DestinationUnavailable(ValueError):
    """Original destination state is absent, unsupported or inconsistent."""


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def registry_identity(value):
    # Only the documented one-way bootstrap readiness transition is mutable.
    # Formats, required features, paths, identities and policy approvals are not.
    return canonical(value | {"phase": "initialized"})


@contextmanager
def initialization_lock(root):
    lock = root / "destination-init.lock"
    descriptor = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW | os.O_NONBLOCK, 0o600)
    with os.fdopen(descriptor, "r+") as handle:
        _private_regular(lock)
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            raise DestinationUnavailable("destination initialization is already owned") from None
        yield


def parse_binding(value):
    if (
        not isinstance(value, dict) or set(value) != BINDING_FIELDS
        or not isinstance(value["destination_id"], str)
        or not DESTINATION_ID.fullmatch(value["destination_id"])
        or any(
            not isinstance(value[name], str) or not OPAQUE_ID.fullmatch(value[name])
            for name in ("journal_incarnation", "policy_binding_id")
        )
        or type(value["policy_binding_version"]) is not int
        or value["policy_binding_version"] != 1
    ):
        raise ValueError("invalid destination binding")
    return dict(value)


def _path(value):
    if not isinstance(value, (str, Path)):
        raise ValueError("destination paths must be canonical absolute paths")
    path = Path(value)
    if not path.is_absolute() or path != path.resolve():
        raise ValueError("destination paths must be canonical absolute paths")
    return path


def _private_directory(path, *, create=False):
    path = _path(path)
    if create:
        path.mkdir(mode=0o700, parents=True, exist_ok=True)
    info = path.lstat()
    if (
        not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise DestinationUnavailable("destination state directory is not private")
    return path


def _private_regular(path):
    info = path.lstat()
    if (
        not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
        or stat.S_IMODE(info.st_mode) & 0o077
    ):
        raise DestinationUnavailable("destination state member is not private")


def _read(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(descriptor, "rb") as handle:
        info = os.fstat(handle.fileno())
        if (
            not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) & 0o077
            or not 0 < info.st_size <= MAX_STATE_BYTES
        ):
            raise DestinationUnavailable("destination metadata is not private bounded state")
        raw = handle.read(MAX_STATE_BYTES + 1)
    if len(raw) != info.st_size:
        raise DestinationUnavailable("destination metadata changed during inspection")
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise DestinationUnavailable("destination metadata has duplicate fields")
            result[key] = value
        return result

    def constant(_value):
        raise DestinationUnavailable("destination metadata has a non-JSON constant")

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_constant=constant)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise DestinationUnavailable("destination metadata is not valid bounded JSON") from None


def _write(path, value):
    raw = (canonical(value) + "\n").encode()
    if len(raw) > MAX_STATE_BYTES:
        raise ValueError("destination metadata exceeds its bound")
    temporary = path.with_name(path.name + "." + uuid4().hex + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    try:
        with os.fdopen(descriptor, "wb") as handle:
            handle.write(raw)
            handle.flush()
            os.fsync(handle.fileno())
        os.replace(temporary, path)
        parent = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(parent)
        finally:
            os.close(parent)
    finally:
        temporary.unlink(missing_ok=True)


def destination_configuration(config):
    value = config.get("execution_destination")
    if value is None:
        if "execution_destination" in config:
            raise ValueError("invalid execution destination configuration")
        return None
    if (
        not isinstance(value, dict) or set(value) != {"destination_id"}
        or not isinstance(value["destination_id"], str)
        or not DESTINATION_ID.fullmatch(value["destination_id"])
    ):
        raise ValueError("invalid execution destination configuration")
    return value["destination_id"]


def journal_members(config):
    root = _path(config["state_directory"])
    members = {
        "lifecycle": _path(config["lifecycle_database"]),
        "runtime": root / "runtime" / "journal.sqlite3",
        "dispatcher": root / "dispatcher" / "dispatch.sqlite3",
    }
    if config.get("models"):
        members["models"] = root / "models" / "inference.sqlite3"
    if config.get("children"):
        members["children"] = root / "children" / "children.sqlite3"
    if len(set(members.values())) != len(members):
        raise ValueError("destination journals must have distinct paths")
    return {name: str(_path(path)) for name, path in members.items()}


def policy_fingerprints(config):
    # Share the native pure policy phase with service startup and validation.
    # This destination API also accepts the existing profile-only config shape.
    from .managed_configuration import prepare_profiles

    prepared = prepare_profiles(config)
    if len(prepared.profiles) > 256:
        raise ValueError("destination requires bounded approved profiles")
    return prepared.fingerprints()

@dataclass(frozen=True)
class JournalBinding:
    path: str
    member: str
    destination_id: str
    journal_incarnation: str
    registry_path: str
    registry_json: str

    def verify(self, connection, *, initializing=False):
        try:
            registry = _read(self.registry_path)
            if (
                not isinstance(registry, dict) or registry_identity(registry) != self.registry_json
                or registry.get("phase") not in ("initializing", "initialized", "ready")
            ):
                raise DestinationUnavailable("original destination registry changed")
            if not initializing and registry["phase"] != "ready":
                raise DestinationUnavailable("destination application journals are not initialized")
            self._verify_member(connection, allow_unsealed=initializing and registry["phase"] != "ready")
            if not initializing:
                # Runtime/model/direct component calls receive the same whole-set
                # fence as HTTP requests, including after a later partial loss.
                for member, path in registry["members"].items():
                    if member == self.member:
                        continue
                    _private_regular(Path(path))
                    other = sqlite3.connect(Path(path).as_uri() + "?mode=ro", uri=True, timeout=10)
                    try:
                        JournalBinding(path, member, self.destination_id, self.journal_incarnation,
                                       self.registry_path, self.registry_json)._verify_member(other, allow_unsealed=False)
                    finally:
                        other.close()
        except (OSError, sqlite3.Error, json.JSONDecodeError):
            raise DestinationUnavailable("original destination journal identity is unavailable") from None

    def _verify_member(self, connection, *, allow_unsealed):
        try:
            if connection.execute("PRAGMA application_id").fetchone()[0] != APPLICATION_ID:
                raise DestinationUnavailable("original destination format sentinel is unavailable")
            columns = connection.execute("PRAGMA table_info(" + IDENTITY_TABLE + ")").fetchall()
            if tuple(row[1] for row in columns) != MARKER_COLUMNS:
                raise DestinationUnavailable("unsupported destination journal format")
            rows = connection.execute(
                "SELECT format_version,required_features,destination_id,journal_incarnation,member,application_schema FROM "
                + IDENTITY_TABLE
            ).fetchall()
        except (OSError, sqlite3.Error, json.JSONDecodeError):
            raise DestinationUnavailable("original destination journal identity is unavailable") from None
        if len(rows) != 1 or tuple(rows[0])[:-1] != (
            1, canonical(REQUIRED_FEATURES), self.destination_id, self.journal_incarnation, self.member,
        ):
            raise DestinationUnavailable("original destination journal identity changed")
        if self.member == "children":
            from .managed_public_journal import optional_schema
            from .lifecycle import LifecycleConflict
            try:
                optional_schema(connection)
            except (LifecycleConflict, sqlite3.Error):
                raise DestinationUnavailable("original optional child schema is unavailable") from None
        encoded = rows[0][-1]
        if encoded is None and not allow_unsealed:
            raise DestinationUnavailable("destination application journal has not been initialized")
        if encoded is not None:
            try:
                required = json.loads(encoded)
                if (
                    not isinstance(required, dict) or set(required) != {"tables", "indexes"}
                    or canonical(required) != encoded
                    or not isinstance(required["tables"], dict)
                    or set(required["tables"]) != APPLICATION_TABLES[self.member]
                    or not isinstance(required["indexes"], dict)
                    or len(encoded) > MAX_STATE_BYTES
                    or any(not isinstance(sql, str) or not sql for sql in required["tables"].values())
                    or any(
                        not isinstance(record, dict) or set(record) != {"table", "sql"}
                        or record["table"] not in APPLICATION_TABLES[self.member]
                        or (record["sql"] is not None and not isinstance(record["sql"], str))
                        for record in required["indexes"].values()
                    )
                ):
                    raise ValueError("invalid schema inventory")
                current = self._application_schema(connection)
                if current["tables"] != required["tables"] or any(
                    current["indexes"].get(name) != value
                    for name, value in required["indexes"].items()
                ):
                    raise ValueError("original application schema changed")
            except (ValueError, TypeError, KeyError, sqlite3.Error):
                raise DestinationUnavailable("original destination application schema is unavailable") from None

    def _application_schema(self, connection):
        tables = APPLICATION_TABLES[self.member]
        rows = connection.execute("SELECT type,name,tbl_name,sql FROM sqlite_master").fetchall()
        definitions = {row[1]: row[3] for row in rows if row[0] == "table" and row[1] in tables}
        if set(definitions) != tables:
            raise DestinationUnavailable("original destination application table is unavailable")
        return {
            "tables": definitions,
            "indexes": {row[1]: {"table": row[2], "sql": row[3]} for row in rows
                        if row[0] == "index" and row[2] in tables},
        }

    def seal(self, connection):
        """Finish first effect-free schema setup before readiness or work.

        Once retained, table and index definitions are checked on every connection;
        constructors cannot mistake their loss for a fresh application journal.
        Table migrations require explicit supported-format maintenance. New
        required behavior must also advance the registry's required feature floor.
        """
        self.verify(connection, initializing=True)
        if connection.execute("SELECT application_schema FROM " + IDENTITY_TABLE).fetchone()[0] is None:
            connection.execute(
                "UPDATE " + IDENTITY_TABLE + " SET application_schema=? WHERE singleton=1 AND application_schema IS NULL",
                (canonical(self._application_schema(connection)),),
            )
        self.verify(connection, initializing=True)


def connect_journal(database, *, binding=None, initializing=False, read_only=False, **kwargs):
    """Existing-only bound opens; legacy opens cannot downgrade stamped state."""
    connection = None
    try:
        if binding is not None:
            if not isinstance(binding, JournalBinding) or str(_path(database)) != binding.path:
                raise DestinationUnavailable("destination journal path changed")
            _private_regular(Path(database))
            mode = "ro" if read_only else "rw"
            connection = sqlite3.connect(Path(database).as_uri() + "?mode=" + mode, uri=True, **kwargs)
            binding.verify(connection, initializing=initializing)
        else:
            connection = sqlite3.connect(database, **kwargs)
            stamped = connection.execute(
                "SELECT 1 FROM sqlite_master WHERE name=?", (IDENTITY_TABLE,)
            ).fetchone()
            if stamped is not None or connection.execute("PRAGMA application_id").fetchone()[0] == APPLICATION_ID:
                raise DestinationUnavailable("bound journal requires its original destination context")
        return connection
    except (OSError, sqlite3.Error):
        if connection is not None:
            connection.close()
        raise DestinationUnavailable("original destination journal is unavailable") from None
    except BaseException:
        if connection is not None:
            connection.close()
        raise


class DestinationState:
    def __init__(self, config, value):
        self.config = config
        self.root = _private_directory(config["state_directory"])
        self.path = self.root / "destination.json"
        if (
            not isinstance(value, dict) or set(value) != {
                "schema_version", "phase", "destination_id", "journal_incarnation",
                "members", "policies", "required_features",
            }
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["required_features"] != REQUIRED_FEATURES
            or not isinstance(value["phase"], str) or value["phase"] not in {"initializing", "initialized", "ready"}
            or value["destination_id"] != destination_configuration(config)
            or not isinstance(value["journal_incarnation"], str)
            or not OPAQUE_ID.fullmatch(value["journal_incarnation"])
            or value["members"] != journal_members(config)
            or not isinstance(value["policies"], list) or not 1 <= len(value["policies"]) <= 256
        ):
            raise DestinationUnavailable("destination metadata does not match its original configuration")
        self.value = value
        self.destination_id = value["destination_id"]
        self.incarnation = value["journal_incarnation"]
        self.policies = {}
        self.ids = set()
        for policy in value["policies"]:
            if not isinstance(policy, dict) or set(policy) != {"scope", "id", "fingerprints"}:
                raise DestinationUnavailable("invalid retained destination policy")
            key, identity = policy["scope"], policy["id"]
            fingerprints = policy["fingerprints"]
            if (
                not isinstance(key, list) or len(key) != 3
                or any(not isinstance(v, str) or not v for v in key)
                or not isinstance(identity, str) or not OPAQUE_ID.fullmatch(identity)
                or tuple(key) in self.policies or identity in self.ids
                or not isinstance(fingerprints, dict)
                or set(fingerprints) != {"version", "docker", "model", "children"}
                or type(fingerprints["version"]) is not int or fingerprints["version"] != 1
                or any(
                    not isinstance(fingerprints[name], str)
                    or not re.fullmatch(r"[0-9a-f]{64}", fingerprints[name])
                    for name in ("docker", "model", "children")
                    if name == "docker" or fingerprints[name] is not None
                )
            ):
                raise DestinationUnavailable("invalid retained destination policy")
            self.policies[tuple(key)] = policy
            self.ids.add(identity)
        self.current = policy_fingerprints(config)
        if value["phase"] != "ready" and self.current != {
            key: item["fingerprints"] for key, item in self.policies.items()
        }:
            raise DestinationConflict("original destination initialization policy changed")

    @classmethod
    def load(cls, config):
        selected = destination_configuration(config)
        root = _path(config["state_directory"]) if selected is not None else Path(config["state_directory"])
        path = root / "destination.json"
        if selected is None:
            if path.exists() or path.is_symlink():
                raise DestinationUnavailable("bound destination cannot downgrade to legacy configuration")
            return None
        try:
            state = cls(config, _read(path))
            state.verify(initializing=True)
            return state
        except (OSError, sqlite3.Error, json.JSONDecodeError):
            raise DestinationUnavailable("original destination state is unavailable") from None

    def member(self, name):
        return JournalBinding(
            self.value["members"][name], name, self.destination_id, self.incarnation,
            str(self.path), registry_identity(self.value),
        )

    def verify(self, *, initializing=False):
        try:
            if self.value["phase"] not in {"initialized", "ready"} or _read(self.path) != self.value:
                raise DestinationUnavailable("original destination initialization is incomplete or changed")
            if not initializing and self.value["phase"] != "ready":
                raise DestinationUnavailable("destination application journals are not initialized")
            for name, path in self.value["members"].items():
                # Verify each member once; direct component opens separately
                # perform the whole-set check before their own transaction.
                connection = connect_journal(path, binding=self.member(name), initializing=True, read_only=True)
                try:
                    if not initializing:
                        self.member(name)._verify_member(connection, allow_unsealed=False)
                finally:
                    connection.close()
        except (OSError, sqlite3.Error, json.JSONDecodeError):
            raise DestinationUnavailable("original destination state is unavailable") from None

    def activate(self):
        """Publish readiness only after every effect-free constructor sealed state."""
        with initialization_lock(self.root):
            self.verify(initializing=True)
            for name, path in self.value["members"].items():
                connection = connect_journal(path, binding=self.member(name), initializing=True, read_only=True)
                try:
                    self.member(name)._verify_member(connection, allow_unsealed=False)
                finally:
                    connection.close()
            if self.value["phase"] != "ready":
                self.value = self.value | {"phase": "ready"}
                _write(self.path, self.value)
        self.verify()

    def binding(self, scope, profile):
        key = (scope.deployment_id, scope.repository, profile)
        policy = self.policies.get(key)
        if policy is None:
            raise DestinationConflict("destination policy binding does not match")
        return {
            "destination_id": self.destination_id,
            "journal_incarnation": self.incarnation,
            "policy_binding_id": policy["id"],
            "policy_binding_version": 1,
        }

    def validate(self, scope, profile, supplied, *, admission=False):
        actual = parse_binding(supplied)
        self.verify()
        expected = self.binding(scope, profile)
        if actual != expected:
            raise DestinationConflict("destination binding does not match")
        key = (scope.deployment_id, scope.repository, profile)
        if admission and self.current.get(key) != self.policies[key]["fingerprints"]:
            raise DestinationUnavailable("original destination policy is not approved for new admission")
        return actual

    def profile_for_binding(self, scope, supplied):
        actual = parse_binding(supplied)
        self.verify()
        for key, policy in self.policies.items():
            if key[:2] == (scope.deployment_id, scope.repository) and policy["id"] == actual["policy_binding_id"]:
                self.validate(scope, key[2], actual)
                return key[2]
        raise DestinationConflict("destination binding does not match")

    def usable(self, scope, profile):
        try:
            self.validate(scope, profile, self.binding(scope, profile), admission=True)
            return True
        except (ValueError, OSError):
            return False

    def inspection(self):
        self.verify(initializing=True)
        return {
            "schema_version": 2,
            "destination_id": self.destination_id,
            "journal_incarnation": self.incarnation,
            "identity_binding": 1,
            "portable_manifest": False,
            "local_admission": False,
            "journals_initialized": self.value["phase"] == "ready",
            "profiles": [{
                "deployment_id": key[0], "repository": key[1], "profile": key[2],
                "destination_binding": {
                    "destination_id": self.destination_id,
                    "journal_incarnation": self.incarnation,
                    "policy_binding_id": policy["id"], "policy_binding_version": 1,
                },
                "current_policy_matches": self.current.get(key) == policy["fingerprints"],
            } for key, policy in sorted(self.policies.items())],
        }


def initialize_destination(config):
    destination_id = destination_configuration(config)
    if destination_id is None:
        raise ValueError("explicit execution destination configuration is required")
    members = journal_members(config)
    fingerprints = policy_fingerprints(config)
    root = _private_directory(config["state_directory"], create=True)
    path = root / "destination.json"
    with initialization_lock(root):
        if path.exists() or path.is_symlink():
            state = DestinationState(config, _read(path))
            if state.value["phase"] in {"initialized", "ready"}:
                return state.inspection()
            if {key: item["fingerprints"] for key, item in state.policies.items()} != fingerprints:
                raise DestinationConflict("original destination initialization policy changed")
        else:
            if any(entry.name != "destination-init.lock" for entry in root.iterdir()) or any(
                Path(member).exists() or Path(member).is_symlink() for member in members.values()
            ):
                raise DestinationConflict("destination initialization refuses existing journals")
            value = {
                "schema_version": 1, "phase": "initializing",
                "required_features": REQUIRED_FEATURES,
                "destination_id": destination_id, "journal_incarnation": uuid4().hex,
                "members": members,
                "policies": [{"scope": list(key), "id": uuid4().hex, "fingerprints": value}
                             for key, value in sorted(fingerprints.items())],
            }
            _write(path, value)
            state = DestinationState(config, value)
        for name, member in members.items():
            target = Path(member)
            _private_directory(target.parent, create=True)
            if not target.exists():
                temporary = target.with_name(target.name + "." + uuid4().hex + ".initializing")
                descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
                os.close(descriptor)
                try:
                    connection = sqlite3.connect(temporary)
                    try:
                        connection.execute("PRAGMA synchronous=FULL")
                        connection.execute("PRAGMA application_id=" + str(APPLICATION_ID))
                        connection.execute(
                            "CREATE TABLE " + IDENTITY_TABLE + " ("
                            "singleton INTEGER PRIMARY KEY CHECK(singleton=1),"
                            "format_version INTEGER NOT NULL,required_features TEXT NOT NULL,"
                            "destination_id TEXT NOT NULL,journal_incarnation TEXT NOT NULL,member TEXT NOT NULL,"
                            "application_schema TEXT)"
                        )
                        connection.execute(
                            "INSERT INTO " + IDENTITY_TABLE + " VALUES (1,1,?,?,?,?,NULL)",
                            (canonical(REQUIRED_FEATURES), destination_id, state.incarnation, name),
                        )
                        connection.commit()
                    finally:
                        connection.close()
                    # Publish a complete marker without replacing another file.
                    # A crash before this link leaves the original init intent;
                    # a retry can finish it without adopting an empty database.
                    os.link(temporary, target, follow_symlinks=False)
                finally:
                    temporary.unlink(missing_ok=True)
                descriptor = os.open(target.parent, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            connection = connect_journal(target, binding=state.member(name), initializing=True, read_only=True)
            connection.close()
        state.value["phase"] = "initialized"
        _write(path, state.value)
        return state.inspection()
