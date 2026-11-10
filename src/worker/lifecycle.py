"""Durable worker capacity and admission facts, separate from task authority.

The runtime is deliberately injected. A deployment must provide a trusted
driver that verifies its Polyphony capabilities and owns real execution and
capture. This module never falls back to the legacy BackgroundTasks executor.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import json
from pathlib import Path
import sqlite3
from typing import Iterator, Protocol
from uuid import uuid4


SCHEMA_VERSION = 1
OPERATIONS = ("ensure", "discover", "observe", "drain", "stop")
STATES = frozenset(
    {"starting", "ready", "busy", "draining", "stopped", "failed", "unknown"}
)


class LifecycleConflict(RuntimeError):
    """An operation contradicts an existing immutable binding or admission."""


class WorkerNotFound(LookupError):
    """The requested worker does not exist in the authorized scope."""


class RuntimeUnavailable(RuntimeError):
    """Required runtime or canonical authority capabilities are unavailable."""


def _text(value: object, name: str) -> str:
    if (
        not isinstance(value, str)
        or not value
        or value != value.strip()
        or len(value) > 512
        or any(character.isspace() for character in value)
    ):
        raise ValueError(f"{name} must be a nonempty bounded identifier")
    return value


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


@dataclass(frozen=True)
class WorkerScope:
    deployment_id: str
    repository: str

    def __post_init__(self) -> None:
        _text(self.deployment_id, "deployment_id")
        _text(self.repository, "repository")


@dataclass(frozen=True)
class WorkerSpec:
    deployment_id: str
    repository: str
    slot_id: str
    generation: int
    launch_key: str
    profile: str
    schema_version: int = SCHEMA_VERSION

    def __post_init__(self) -> None:
        self.scope
        for name in ("slot_id", "launch_key", "profile"):
            _text(getattr(self, name), name)
        if type(self.generation) is not int or not 1 <= self.generation <= (1 << 63) - 1:
            raise ValueError("generation must be a positive signed 64-bit integer")
        if type(self.schema_version) is not int or self.schema_version != 1:
            raise ValueError("unsupported schema_version")

    @property
    def scope(self) -> WorkerScope:
        return WorkerScope(self.deployment_id, self.repository)


@dataclass(frozen=True)
class RuntimeCapabilities:
    managed_dispatch: bool = False
    profile_supported: bool = False
    repository_access: bool = False
    reason: str = "No managed runtime adapter is configured"

    @property
    def usable(self) -> bool:
        return all(
            value is True
            for value in (
                self.managed_dispatch,
                self.profile_supported,
                self.repository_access,
            )
        )


@dataclass(frozen=True)
class RuntimeObservation:
    state: str
    runtime_id: str | None = None
    reason: str = ""
    termination_confirmed: bool = False
    artifacts_captured: bool = False
    not_started: bool = False
    launch_fenced: bool = False

    def __post_init__(self) -> None:
        if self.state not in STATES:
            raise ValueError("unsupported runtime state")
        if self.runtime_id is not None:
            _text(self.runtime_id, "runtime_id")
        for value in (
            self.termination_confirmed,
            self.artifacts_captured,
            self.not_started,
            self.launch_fenced,
        ):
            if type(value) is not bool:
                raise ValueError("runtime evidence flags must be boolean")


class WorkerRuntime(Protocol):
    """Trusted adapter, not an agent-controlled execution interface.

    The worker ID is a durable launch identity, permanently bound to its spec.
    Every command is idempotent for that identity, including after a lost reply
    or supervisor restart. Ensure must reconcile its own durable launch record,
    never create a second process for the same identity or adopt a PID/name.
    Drain and stop are monotonic, durable commands. They must fence concurrent
    or delayed ensures and prevent later recreation of the same incarnation.
    Observation is read-only. Terminal receipts cover all owned descendants,
    durable artifacts, and a durable launch tombstone (launch_fenced=True).
    not_started alone never proves that a launch cannot still happen.
    Missing runtime knowledge remains unknown. A successful non-unknown
    command response acknowledges durable acceptance of that command.
    Every real root/child launch must use the lifecycle admission methods AND
    its canonical Polyphony authorization; neither substitutes for the other.
    """

    def capabilities(
        self, scope: WorkerScope, profile: str
    ) -> RuntimeCapabilities: ...

    def ensure(self, worker_id: str, spec: WorkerSpec) -> RuntimeObservation: ...

    def observe(
        self, worker_id: str, spec: WorkerSpec, runtime_id: str | None
    ) -> RuntimeObservation: ...

    def drain(
        self, worker_id: str, spec: WorkerSpec, runtime_id: str | None
    ) -> RuntimeObservation: ...

    def stop(
        self, worker_id: str, spec: WorkerSpec, runtime_id: str | None
    ) -> RuntimeObservation: ...


class UnavailableRuntime:
    """Fail-closed default until a real authenticated adapter is installed."""

    def capabilities(
        self, scope: WorkerScope, profile: str
    ) -> RuntimeCapabilities:
        return RuntimeCapabilities()

    def ensure(self, worker_id: str, spec: WorkerSpec) -> RuntimeObservation:
        raise RuntimeUnavailable("No managed runtime adapter is configured")

    def observe(
        self, worker_id: str, spec: WorkerSpec, runtime_id: str | None
    ) -> RuntimeObservation:
        return RuntimeObservation("unknown", reason="Managed runtime unavailable")

    drain = observe
    stop = observe


class WorkerLifecycle:
    """SQLite journal for worker identity, operation intent and local admission.

    It stores no task requirements, task budgets, candidates or task acceptance.
    One SQLite file and its runtime lock directory on local storage are shared
    by API processes on this Linux/Unix host. Multiple hosts require a separate
    coordinator. Host locks serialize backend calls; backend idempotency and
    launch fences remain essential across a crash or lost remote response.
    """

    def __init__(self, database: str | Path, runtime: WorkerRuntime | None = None):
        if str(database) == ":memory:":
            raise ValueError("a persistent lifecycle database path is required")
        self.database = str(Path(database).resolve())
        self.runtime = runtime or UnavailableRuntime()
        Path(self.database).parent.mkdir(parents=True, exist_ok=True)
        self._lock_directory = Path(self.database + ".runtime-locks")
        self._lock_directory.mkdir(parents=True, exist_ok=True)
        with self._transaction() as connection:
            connection.executescript(
                """
                CREATE TABLE IF NOT EXISTS managed_workers (
                    worker_id TEXT PRIMARY KEY,
                    deployment_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    slot_id TEXT NOT NULL,
                    generation INTEGER NOT NULL,
                    spec TEXT NOT NULL,
                    runtime_id TEXT,
                    state TEXT NOT NULL,
                    reason TEXT NOT NULL,
                    draining INTEGER NOT NULL DEFAULT 0,
                    termination_confirmed INTEGER NOT NULL DEFAULT 0,
                    artifacts_captured INTEGER NOT NULL DEFAULT 0,
                    UNIQUE (deployment_id, repository, slot_id, generation)
                );
                CREATE TABLE IF NOT EXISTS worker_operations (
                    deployment_id TEXT NOT NULL,
                    repository TEXT NOT NULL,
                    request_key TEXT NOT NULL,
                    action TEXT NOT NULL,
                    worker_id TEXT NOT NULL,
                    payload TEXT NOT NULL,
                    completed INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (deployment_id, repository, request_key),
                    FOREIGN KEY (worker_id) REFERENCES managed_workers(worker_id)
                );
                CREATE UNIQUE INDEX IF NOT EXISTS managed_worker_runtime_id
                    ON managed_workers(runtime_id) WHERE runtime_id IS NOT NULL;
                CREATE TABLE IF NOT EXISTS worker_executions (
                    worker_id TEXT NOT NULL,
                    execution_id TEXT NOT NULL,
                    parent_id TEXT,
                    termination_confirmed INTEGER NOT NULL DEFAULT 0,
                    artifacts_captured INTEGER NOT NULL DEFAULT 0,
                    PRIMARY KEY (worker_id, execution_id),
                    FOREIGN KEY (worker_id) REFERENCES managed_workers(worker_id)
                );
                """
            )

    @contextmanager
    def _runtime_lock(self, worker_id: str) -> Iterator[bool]:
        """Serialize runtime I/O and receipt application without holding SQL.

        Never steal an in-flight call on a timeout. Returning the durable
        reservation lets callers retry while a slow driver still owns the
        lock. Kernel locks are released when the supervising process exits.
        """
        with (self._lock_directory / (worker_id + ".lock")).open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def _current(self, scope: WorkerScope, worker_id: str) -> dict:
        with self._transaction() as connection:
            return self._view(connection, self._get(connection, scope, worker_id))

    @staticmethod
    def _terminal(row: sqlite3.Row) -> bool:
        return bool(
            row["state"] in ("stopped", "failed")
            and row["termination_confirmed"]
            and row["artifacts_captured"]
        )

    def _complete(self, scope: WorkerScope, request_key: str) -> None:
        with self._transaction() as connection:
            connection.execute(
                "UPDATE worker_operations SET completed=1 WHERE deployment_id=? "
                "AND repository=? AND request_key=?",
                (scope.deployment_id, scope.repository, request_key),
            )

    @contextmanager
    def _transaction(self) -> Iterator[sqlite3.Connection]:
        connection = sqlite3.connect(self.database, timeout=30, isolation_level=None)
        connection.row_factory = sqlite3.Row
        connection.execute("PRAGMA foreign_keys = ON")
        connection.execute("BEGIN IMMEDIATE")
        try:
            yield connection
            connection.commit()
        except BaseException:
            connection.rollback()
            raise
        finally:
            connection.close()

    @staticmethod
    def _get(
        connection: sqlite3.Connection, scope: WorkerScope, worker_id: str
    ) -> sqlite3.Row:
        row = connection.execute(
            "SELECT * FROM managed_workers WHERE worker_id = ? "
            "AND deployment_id = ? AND repository = ?",
            (worker_id, scope.deployment_id, scope.repository),
        ).fetchone()
        if row is None:
            raise WorkerNotFound("Worker not found in the authorized scope")
        return row

    @staticmethod
    def _active(connection: sqlite3.Connection, worker_id: str) -> list[sqlite3.Row]:
        return connection.execute(
            "SELECT * FROM worker_executions WHERE worker_id = ? "
            "AND NOT (termination_confirmed = 1 AND artifacts_captured = 1) "
            "ORDER BY execution_id",
            (worker_id,),
        ).fetchall()

    def capabilities(self, scope: WorkerScope, profile: str) -> dict:
        _text(profile, "profile")
        try:
            capabilities = self.runtime.capabilities(scope, profile)
            if not isinstance(capabilities, RuntimeCapabilities):
                raise TypeError("invalid capability response")
        except Exception:
            capabilities = RuntimeCapabilities(reason="Runtime preflight unavailable")
        return {
            "schema_version": SCHEMA_VERSION,
            "deployment_id": scope.deployment_id,
            "repository": scope.repository,
            "profile": profile,
            "operations": list(OPERATIONS),
            **asdict(capabilities),
        }

    def _usable(self, scope: WorkerScope, profile: str) -> bool:
        capabilities = self.capabilities(scope, profile)
        return all(
            capabilities.get(key) is True
            for key in ("managed_dispatch", "profile_supported", "repository_access")
        )

    @staticmethod
    def _operation(
        connection: sqlite3.Connection,
        scope: WorkerScope,
        key: str,
        action: str,
        worker_id: str | None,
        payload: str,
    ) -> sqlite3.Row | None:
        _text(key, "request_key")
        row = connection.execute(
            "SELECT * FROM worker_operations WHERE deployment_id = ? "
            "AND repository = ? AND request_key = ?",
            (scope.deployment_id, scope.repository, key),
        ).fetchone()
        if row is not None and (
            row["action"] != action
            or row["payload"] != payload
            or (worker_id is not None and row["worker_id"] != worker_id)
        ):
            raise LifecycleConflict("Operation key is already bound to different input")
        return row

    def ensure_worker(self, spec: WorkerSpec) -> dict:
        payload = _json(asdict(spec))
        with self._transaction() as connection:
            existing = self._operation(
                connection, spec.scope, spec.launch_key, "ensure", None, payload
            )
            existing_id = existing["worker_id"] if existing else None
        if existing_id:
            return self._resume_ensure(spec, existing_id)
        if not self._usable(spec.scope, spec.profile):
            raise RuntimeUnavailable("Managed runtime preflight is not ready")

        with self._transaction() as connection:
            existing = self._operation(
                connection, spec.scope, spec.launch_key, "ensure", None, payload
            )
            if existing:
                worker_id = existing["worker_id"]
            else:
                previous = connection.execute(
                    "SELECT * FROM managed_workers WHERE deployment_id = ? "
                    "AND repository = ? AND slot_id = ? ORDER BY generation DESC",
                    (spec.deployment_id, spec.repository, spec.slot_id),
                ).fetchall()
                for row in previous:
                    if spec.generation <= row["generation"]:
                        raise LifecycleConflict("Slot generation must increase")
                    if not (
                        row["state"] in ("stopped", "failed")
                        and row["termination_confirmed"]
                        and row["artifacts_captured"]
                        and not self._active(connection, row["worker_id"])
                    ):
                        raise LifecycleConflict("Previous slot incarnation is unresolved")
                worker_id = uuid4().hex
                connection.execute(
                    "INSERT INTO managed_workers "
                    "(worker_id,deployment_id,repository,slot_id,generation,spec,state,reason) "
                    "VALUES (?,?,?,?,?,?,?,?)",
                    (
                        worker_id,
                        spec.deployment_id,
                        spec.repository,
                        spec.slot_id,
                        spec.generation,
                        payload,
                        "unknown",
                        "Launch intent committed; runtime outcome not yet observed",
                    ),
                )
                connection.execute(
                    "INSERT INTO worker_operations "
                    "(deployment_id,repository,request_key,action,worker_id,payload) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        spec.deployment_id,
                        spec.repository,
                        spec.launch_key,
                        "ensure",
                        worker_id,
                        payload,
                    ),
                )
        return self._resume_ensure(spec, worker_id)

    def _resume_ensure(self, spec: WorkerSpec, worker_id: str) -> dict:
        with self._runtime_lock(worker_id) as acquired:
            if not acquired:
                return self._current(spec.scope, worker_id)
            observed = self._observe_locked(spec.scope, worker_id)
            with self._transaction() as connection:
                row = self._get(connection, spec.scope, worker_id)
                operation = self._operation(
                    connection, spec.scope, spec.launch_key, "ensure", worker_id,
                    _json(asdict(spec)),
                )
                terminal = self._terminal(row)
                completed, draining = operation["completed"], row["draining"]
            if terminal or observed["state"] in ("starting", "ready", "busy", "draining"):
                self._complete(spec.scope, spec.launch_key)
                return observed
            if completed or draining or not self._usable(spec.scope, spec.profile):
                # A control intent supersedes a pending launch. Its runtime
                # command must still establish a durable cancellation fence.
                return observed
            try:
                observation = self.runtime.ensure(worker_id, spec)
                if not isinstance(observation, RuntimeObservation):
                    raise TypeError("invalid runtime response")
            except Exception:
                observation = RuntimeObservation("unknown", reason="Launch outcome unknown")
            result = self._apply(spec.scope, worker_id, observation)
            if result["state"] != "unknown":
                self._complete(spec.scope, spec.launch_key)
            return result

    def _apply(
        self, scope: WorkerScope, worker_id: str, observation: RuntimeObservation
    ) -> dict:
        with self._transaction() as connection:
            row = self._get(connection, scope, worker_id)
            spec = WorkerSpec(**json.loads(row["spec"]))
        usable = self._usable(scope, spec.profile)
        with self._transaction() as connection:
            row = self._get(connection, scope, worker_id)
            if self._terminal(row):
                return self._view(connection, row)
            runtime_id = row["runtime_id"]
            state, reason = observation.state, observation.reason
            terminated = observation.termination_confirmed
            captured = observation.artifacts_captured
            if runtime_id and (
                observation.not_started or observation.runtime_id != runtime_id
            ):
                state, reason = "unknown", "Runtime incarnation does not match its binding"
                terminated = captured = False
            elif not runtime_id and observation.runtime_id:
                bound = connection.execute(
                    "SELECT worker_id FROM managed_workers WHERE runtime_id=? AND worker_id<>?",
                    (observation.runtime_id, worker_id),
                ).fetchone()
                if bound is not None:
                    state, reason = "unknown", "Runtime incarnation is already bound to another worker"
                    terminated = captured = False
                else:
                    runtime_id = observation.runtime_id
            if state in ("stopped", "failed"):
                if not (
                    terminated
                    and captured
                    and observation.launch_fenced
                    and (runtime_id or observation.not_started)
                    and not self._active(connection, worker_id)
                ):
                    state, reason = "unknown", "Termination, capture or launch fence unresolved"
            elif state in ("ready", "busy"):
                if not runtime_id or not usable:
                    state, reason = "unknown", "Managed readiness is not established"
            if row["draining"] and state in ("starting", "ready", "busy"):
                state = "draining"
            connection.execute(
                "UPDATE managed_workers SET runtime_id=?,state=?,reason=?,"
                "termination_confirmed=?,artifacts_captured=? WHERE worker_id=?",
                (runtime_id, state, reason, int(terminated), int(captured), worker_id),
            )
            return self._view(connection, self._get(connection, scope, worker_id))

    def _view(self, connection: sqlite3.Connection, row: sqlite3.Row) -> dict:
        spec = json.loads(row["spec"])
        active = self._active(connection, row["worker_id"])
        state = row["state"]
        if state == "ready" and active:
            state = "busy"
        return {
            **spec,
            "worker_id": row["worker_id"],
            "state": state,
            "reason": row["reason"],
            "termination_confirmed": bool(row["termination_confirmed"])
            and all(item["termination_confirmed"] for item in active),
            "artifacts_captured": bool(row["artifacts_captured"])
            and all(item["artifacts_captured"] for item in active),
            "admission_open": not row["draining"] and state in ("ready", "busy"),
            "active_executions": [record["execution_id"] for record in active],
        }

    def observe_worker(self, scope: WorkerScope, worker_id: str) -> dict:
        # Authorize before creating any lock file for a caller-supplied ID.
        self._current(scope, worker_id)
        with self._runtime_lock(worker_id) as acquired:
            if not acquired:
                return self._current(scope, worker_id)
            return self._observe_locked(scope, worker_id)

    def _observe_locked(self, scope: WorkerScope, worker_id: str) -> dict:
        with self._transaction() as connection:
            row = self._get(connection, scope, worker_id)
            if self._terminal(row):
                return self._view(connection, row)
            spec, runtime_id = WorkerSpec(**json.loads(row["spec"])), row["runtime_id"]
        try:
            observation = self.runtime.observe(worker_id, spec, runtime_id)
            if not isinstance(observation, RuntimeObservation):
                raise TypeError("invalid runtime response")
        except Exception:
            observation = RuntimeObservation("unknown", reason="Runtime observation unavailable")
        return self._apply(scope, worker_id, observation)

    def discover_workers(
        self, scope: WorkerScope, launch_key: str | None = None
    ) -> list[dict]:
        if launch_key is not None:
            _text(launch_key, "launch_key")
        with self._transaction() as connection:
            rows = connection.execute(
                "SELECT worker_id,spec FROM managed_workers WHERE deployment_id=? "
                "AND repository=? ORDER BY slot_id,generation",
                (scope.deployment_id, scope.repository),
            ).fetchall()
        return [
            self.observe_worker(scope, row["worker_id"])
            for row in rows
            if launch_key is None or json.loads(row["spec"])["launch_key"] == launch_key
        ]

    def _control(
        self, scope: WorkerScope, worker_id: str, request_key: str, action: str
    ) -> dict:
        payload = _json({"worker_id": worker_id, "action": action})
        with self._transaction() as connection:
            row = self._get(connection, scope, worker_id)
            existing = self._operation(
                connection, scope, request_key, action, worker_id, payload
            )
            if not existing:
                connection.execute(
                    "INSERT INTO worker_operations "
                    "(deployment_id,repository,request_key,action,worker_id,payload) "
                    "VALUES (?,?,?,?,?,?)",
                    (
                        scope.deployment_id,
                        scope.repository,
                        request_key,
                        action,
                        worker_id,
                        payload,
                    ),
                )
            connection.execute(
                "UPDATE managed_workers SET draining=1, "
                "state=CASE WHEN state IN ('ready','busy','starting') "
                "THEN 'draining' ELSE state END WHERE worker_id=?", (worker_id,)
            )
        with self._runtime_lock(worker_id) as acquired:
            if not acquired:
                return self._current(scope, worker_id)
            observed = self._observe_locked(scope, worker_id)
            with self._transaction() as connection:
                row = self._get(connection, scope, worker_id)
                operation = self._operation(
                    connection, scope, request_key, action, worker_id, payload
                )
                terminal, completed = self._terminal(row), operation["completed"]
                spec, runtime_id = WorkerSpec(**json.loads(row["spec"])), row["runtime_id"]
            if terminal:
                self._complete(scope, request_key)
                return observed
            if completed:
                return observed
            try:
                observation = getattr(self.runtime, action)(worker_id, spec, runtime_id)
                if not isinstance(observation, RuntimeObservation):
                    raise TypeError("invalid runtime response")
            except Exception:
                observation = RuntimeObservation(
                    "unknown", reason=f"{action.capitalize()} outcome unknown"
                )
            result = self._apply(scope, worker_id, observation)
            if result["state"] != "unknown":
                self._complete(scope, request_key)
            return result

    def drain_worker(self, scope: WorkerScope, worker_id: str, request_key: str) -> dict:
        return self._control(scope, worker_id, request_key, "drain")

    def stop_worker(self, scope: WorkerScope, worker_id: str, request_key: str) -> dict:
        return self._control(scope, worker_id, request_key, "stop")

    def begin_execution(
        self,
        scope: WorkerScope,
        worker_id: str,
        execution_id: str,
        parent_id: str | None = None,
    ) -> None:
        """Trusted adapter admission after canonical task/grant authorization.

        This is not a public agent endpoint and does not grant task permission.
        Call before the corresponding process/model invocation. A registered
        root may have depth-one children; drain and registration serialize.
        """
        _text(execution_id, "execution_id")
        if parent_id is not None:
            _text(parent_id, "parent_id")
        # Cached snapshots are useful to observers while a driver call is in
        # flight, but cannot authorize new execution. Refresh and register
        # under the same runtime lock so admission never uses that fallback.
        self._current(scope, worker_id)
        with self._runtime_lock(worker_id) as acquired:
            if not acquired:
                raise LifecycleConflict("Runtime observation is in progress; admission is closed")
            self._observe_locked(scope, worker_id)
            with self._transaction() as connection:
                row = self._get(connection, scope, worker_id)
                previous = connection.execute(
                    "SELECT * FROM worker_executions WHERE worker_id=? AND execution_id=?",
                    (worker_id, execution_id),
                ).fetchone()
                if previous is not None:
                    # A duplicate admission can observe its old record, never launch again.
                    raise LifecycleConflict("Execution identity already has an admission record")
                if row["draining"] or row["state"] not in ("ready", "busy"):
                    raise LifecycleConflict("Worker admission is closed")
                active = self._active(connection, worker_id)
                if parent_id is None and active:
                    raise LifecycleConflict("Worker already owns an unresolved root execution")
                if parent_id is not None and not any(
                    item["execution_id"] == parent_id and item["parent_id"] is None
                    for item in active
                ):
                    raise LifecycleConflict("Child requires its active admitted root")
                connection.execute(
                    "INSERT INTO worker_executions (worker_id,execution_id,parent_id) VALUES (?,?,?)",
                    (worker_id, execution_id, parent_id),
                )

    def record_execution_end(
        self,
        scope: WorkerScope,
        worker_id: str,
        execution_id: str,
        *,
        termination_confirmed: bool,
        artifacts_captured: bool,
    ) -> None:
        """Record trusted runtime/capture facts, without task acceptance."""
        if type(termination_confirmed) is not bool or type(artifacts_captured) is not bool:
            raise ValueError("runtime evidence flags must be boolean")
        with self._transaction() as connection:
            self._get(connection, scope, worker_id)
            result = connection.execute(
                "UPDATE worker_executions SET "
                "termination_confirmed=MAX(termination_confirmed,?),"
                "artifacts_captured=MAX(artifacts_captured,?) "
                "WHERE worker_id=? AND execution_id=?",
                (int(termination_confirmed), int(artifacts_captured), worker_id, execution_id),
            )
            if result.rowcount != 1:
                raise WorkerNotFound("Execution not found in this worker")
