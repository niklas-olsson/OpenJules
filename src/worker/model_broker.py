"""Bounded model inference over a worker-specific Unix socket.

Only the trusted host constructs this service and binds canonical attempts.
The socket grants inference, never commands, task ownership or acceptance.
"""

from __future__ import annotations

import asyncio
from collections import deque
from contextlib import contextmanager
from dataclasses import asdict, dataclass
import fcntl
import hashlib
import json
import math
import os
from pathlib import Path
import re
import socket
import socketserver
import sqlite3
import stat
import struct
import threading
import time
from typing import Callable, Mapping
from urllib.parse import urlsplit
from uuid import uuid4

from src.worker.bounded_http import HTTPResponseRejected, post_bounded_json

from src.agent.managed_runner import TOOL_DEFINITIONS
from src.worker.lifecycle import WorkerSpec

_TOOLS = {item["function"]["name"] for item in TOOL_DEFINITIONS}
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")


def _json(value) -> str:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    )


def _hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


class BrokerDenied(RuntimeError):
    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True)
class ModelPolicy:
    endpoint: str
    model: str
    token_ref: str
    max_calls: int = 25
    max_output_tokens: int = 2048
    max_total_output_tokens: int = 32768
    request_timeout_seconds: float = 30
    max_request_bytes: int = 524288
    max_response_bytes: int = 2097152
    token_parameter: str = "max_tokens"

    def __post_init__(self):
        parts = urlsplit(self.endpoint)
        if (
            parts.scheme not in {"https", "http"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or not parts.path.endswith("/chat/completions")
            or (
                parts.scheme == "http"
                and parts.hostname not in {"127.0.0.1", "::1", "localhost"}
            )
        ):
            raise ValueError(
                "model endpoint requires an HTTPS completions URL or loopback HTTP"
            )
        parts.port
        if (
            not isinstance(self.model, str)
            or not self.model
            or len(self.model) > 256
            or any(c.isspace() for c in self.model)
        ):
            raise ValueError("an explicit bounded model identifier is required")
        if not isinstance(self.token_ref, str) or not re.fullmatch(
            r"env:[A-Z_][A-Z0-9_]*", self.token_ref
        ):
            raise ValueError("model credential must be an environment reference")
        for name, lower, upper in (
            ("max_calls", 1, 1000),
            ("max_output_tokens", 1, 32768),
            ("max_total_output_tokens", 1, 10_000_000),
            ("max_request_bytes", 1024, 524288),
            ("max_response_bytes", 1024, 2097152),
        ):
            value = getattr(self, name)
            if type(value) is not int or not lower <= value <= upper:
                raise ValueError(f"invalid model {name}")
        if (
            type(self.request_timeout_seconds) not in {int, float}
            or not math.isfinite(self.request_timeout_seconds)
            or not 0 < self.request_timeout_seconds <= 120
        ):
            raise ValueError("invalid model request timeout")
        if self.token_parameter not in {"max_tokens", "max_completion_tokens"}:
            raise ValueError("unsupported model output token parameter")

    @property
    def fingerprint(self) -> str:
        return _hash(_json(asdict(self)))


@dataclass(frozen=True)
class ModelBinding:
    worker_id: str
    attempt_id: str
    spec: WorkerSpec

    @property
    def scope(self):
        return self.spec.scope


def _tool_call(value, tools=None):
    if (
        not isinstance(value, dict)
        or set(value) != {"id", "type", "function"}
        or value["type"] != "function"
    ):
        raise BrokerDenied("invalid_request")
    function = value["function"]
    if (
        not isinstance(value["id"], str)
        or not _IDENTIFIER.fullmatch(value["id"])
        or not isinstance(function, dict)
        or set(function) != {"name", "arguments"}
        or function["name"] not in (_TOOLS if tools is None else tools)
        or not isinstance(function["arguments"], str)
        or len(function["arguments"].encode()) > 150000
    ):
        raise BrokerDenied("invalid_request")
    return value


def _messages(value, tools=None):
    if not isinstance(value, list) or not 1 <= len(value) <= 256:
        raise BrokerDenied("invalid_request")
    for message in value:
        if not isinstance(message, dict) or message.get("role") not in {
            "system",
            "user",
            "assistant",
            "tool",
        }:
            raise BrokerDenied("invalid_request")
        role = message["role"]
        allowed = {"role", "content"}
        required = {"role", "content"}
        if role == "assistant":
            allowed.add("tool_calls")
        elif role == "tool":
            allowed.add("tool_call_id")
            required.add("tool_call_id")
        if not required <= set(message) or not set(message) <= allowed:
            raise BrokerDenied("invalid_request")
        if not isinstance(message["content"], str) and not (
            role == "assistant" and message["content"] is None
        ):
            raise BrokerDenied("invalid_request")
        if role == "tool" and (
            not isinstance(message["tool_call_id"], str)
            or not _IDENTIFIER.fullmatch(message["tool_call_id"])
        ):
            raise BrokerDenied("invalid_request")
        calls = message.get("tool_calls", [])
        if not isinstance(calls, list) or len(calls) > 8:
            raise BrokerDenied("invalid_request")
        for call in calls:
            _tool_call(call, tools)
    return value


def _assistant(value, tools=None):
    if not isinstance(value, dict) or value.get("role") != "assistant":
        raise BrokerDenied("provider_unavailable")
    result = {"role": "assistant", "content": value.get("content")}
    if value.get("tool_calls"):
        result["tool_calls"] = value["tool_calls"]
    try:
        _messages([result], tools)
    except BrokerDenied:
        raise BrokerDenied("provider_unavailable") from None
    return result


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate JSON field")
        value[key] = item
    return value


class _UnixServer(socketserver.UnixStreamServer):
    request_queue_size = 4
    timeout = 0.1

    def __init__(self, address, handler, *, peer_uid):
        if type(peer_uid) is not int or not 0 <= peer_uid <= (1 << 31) - 1:
            raise ValueError("socket endpoint requires an immutable peer UID")
        self.peer_uid = peer_uid
        self._stopping = threading.Event()
        self._condition = threading.Condition()
        self._pending = deque()
        self._active = None
        # One fixed handler preserves model/control/outcome serialization.
        # The owner acceptor thread joins it before releasing endpoint ownership.
        self._worker = threading.Thread(
            target=self._work, daemon=True, name="worker-socket-handler"
        )
        self._worker_started = False
        super().__init__(address, handler)

    def handle_error(self, request, client_address):
        # Socket failures and untrusted content must not print provider data.
        pass

    def verify_request(self, request, client_address):
        if self._stopping.is_set():
            return False
        try:
            _, uid, _ = struct.unpack(
                "3i",
                request.getsockopt(
                    socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                ),
            )
            if uid == self.peer_uid:
                return True
            # The immutable binding is checked without a database read or body
            # parsing, even while the only effect handler awaits its provider.
            encoded = _json(
                {
                    "schema_version": 1,
                    "request_id": "invalid",
                    "ok": False,
                    "error": "not_authorized",
                }
            ).encode()
            request.settimeout(5)
            request.sendall(struct.pack("!I", len(encoded)) + encoded)
        except Exception:
            pass
        return False

    def process_request(self, request, client_address):
        with self._condition:
            if not self._stopping.is_set() and len(self._pending) < 4:
                self._pending.append((request, client_address))
                self._condition.notify()
                return
        # Saturation and stop do not parse, reserve or acknowledge an operation.
        self.shutdown_request(request)

    def _work(self):
        try:
            while True:
                with self._condition:
                    while not self._pending and not self._stopping.is_set():
                        self._condition.wait()
                    if self._stopping.is_set():
                        return
                    request, address = self._pending.popleft()
                    # Transfer queue ownership to the one active handler under
                    # the same fence that stop uses to discard pending work.
                    self._active = request
                try:
                    if not self._stopping.is_set():
                        self.finish_request(request, address)
                except Exception:
                    self.handle_error(request, address)
                except BaseException:
                    return
                finally:
                    try:
                        self.shutdown_request(request)
                    finally:
                        with self._condition:
                            self._active = None
        finally:
            # A failed handler cannot leave a live acceptor claiming readiness.
            self.stop()

    def serve(self):
        with self._condition:
            if self._stopping.is_set():
                return
            self._worker.start()
            self._worker_started = True
        while not self._stopping.is_set():
            self.handle_request()

    def stop(self):
        with self._condition:
            self._stopping.set()
            pending = list(self._pending)
            self._pending.clear()
            self._condition.notify_all()
        for request, _ in pending:
            self.shutdown_request(request)

    def server_close(self):
        self.stop()
        try:
            super().server_close()
        finally:
            if self._worker_started:
                self._worker.join()


class _Endpoint:
    def __init__(
        self, broker, worker_id: str, directory: Path, *, socket_name="model.sock"
    ):
        if socket_name not in {"model.sock", "outcome.sock"}:
            raise ValueError("unsupported host endpoint name")
        self.stop_requested = threading.Event()
        self.directory = directory
        self.directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.socket_path = directory / socket_name
        if self.socket_path.exists() or self.socket_path.is_symlink():
            if self.socket_path.is_symlink() or not stat.S_ISSOCK(
                self.socket_path.lstat().st_mode
            ):
                os.close(self.directory_fd)
                raise ValueError("model endpoint path is not an owned socket")
            self.socket_path.unlink()
        # Linux pathname lookup through an open directory avoids the 108-byte
        # Unix sockaddr limit for long deployment paths. The guest uses its
        # short, fixed mount path; the actual socket remains in this directory.
        address = f"/proc/self/fd/{self.directory_fd}/{socket_name}"

        class Handler(socketserver.BaseRequestHandler):
            def handle(self):
                request_id = "invalid"
                try:
                    _, uid, _ = struct.unpack(
                        "3i",
                        self.request.getsockopt(
                            socket.SOL_SOCKET, socket.SO_PEERCRED, struct.calcsize("3i")
                        ),
                    )
                    if uid != broker.peer_uid_for_worker(worker_id):
                        raise BrokerDenied("not_authorized")
                    deadline = time.monotonic() + 5
                    length = struct.unpack(
                        "!I", broker._read(self.request, 4, deadline)
                    )[0]
                    policy = broker.policy_for_worker(worker_id)
                    if not 1 <= length <= policy.max_request_bytes:
                        raise BrokerDenied("invalid_request")
                    body = broker._read(self.request, length, deadline)
                    payload = json.loads(body, object_pairs_hook=_pairs)
                    if (
                        isinstance(payload, dict)
                        and isinstance(payload.get("request_id"), str)
                        and _IDENTIFIER.fullmatch(payload["request_id"])
                    ):
                        request_id = payload["request_id"]
                    result = broker.complete(worker_id, payload)
                except BrokerDenied as exc:
                    result = {
                        "schema_version": 1,
                        "request_id": request_id,
                        "ok": False,
                        "error": exc.code,
                    }
                except Exception:
                    result = {
                        "schema_version": 1,
                        "request_id": request_id,
                        "ok": False,
                        "error": "invalid_request",
                    }
                encoded = _json(result).encode()
                self.request.settimeout(5)
                self.request.sendall(struct.pack("!I", len(encoded)) + encoded)

        self.server = None
        self.thread = threading.Thread(
            target=self._serve, daemon=True, name="worker-model-broker"
        )
        try:
            self.server = _UnixServer(
                address,
                Handler,
                peer_uid=broker.peer_uid_for_worker(worker_id),
            )
            self.socket_path.chmod(0o666)
            self.thread.start()
        except BaseException:
            if self.server is not None:
                self.server.server_close()
                if self.socket_path.exists():
                    self.socket_path.unlink()
            os.close(self.directory_fd)
            raise

    def _serve(self):
        try:
            self.server.serve()
        finally:
            self.server.server_close()
            if self.socket_path.exists():
                self.socket_path.unlink()
            os.close(self.directory_fd)

    def stop(self):
        self.stop_requested.set()
        self.server.stop()


class ModelBroker:
    def __init__(
        self,
        state_directory: str | Path,
        policies: Mapping[tuple[str, str, str], ModelPolicy],
        permission: Callable[[ModelBinding], float],
        *,
        peer_uids: Mapping[tuple[str, str, str], int] | None = None,
    ):
        self.root = Path(state_directory).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        if stat.S_IMODE(self.root.stat().st_mode) & 0o077:
            raise ValueError("model broker state directory must have mode 0700")
        self.policies = dict(policies)
        if (
            not self.policies
            or not callable(permission)
            or not all(isinstance(p, ModelPolicy) for p in self.policies.values())
        ):
            raise ValueError(
                "approved model policies and canonical permission callback required"
            )
        self.peer_uids = {key: 65532 for key in self.policies}
        configured_uids = dict(peer_uids or {})
        if set(configured_uids) - set(self.policies) or any(
            type(uid) is not int or not 0 <= uid <= (1 << 31) - 1
            for uid in configured_uids.values()
        ):
            raise ValueError("model peer UIDs must match approved profile scopes")
        self.peer_uids.update(configured_uids)
        self.policy_digests = {
            key: _hash(
                _json({"policy": policy.fingerprint, "peer_uid": self.peer_uids[key]})
            )
            for key, policy in self.policies.items()
        }
        self.permission = permission
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.database = self.root / "inference.sqlite3"
        self.guard = threading.RLock()
        self.endpoints = {}
        self.inference_locks = {}
        self.child_supervisor = None
        self.public_supervisor = None
        self.public_calls = 0
        self.public_condition = threading.Condition(self.guard)
        self.closed = False
        self._service_lock = (self.root / "service.lock").open("a")
        try:
            fcntl.flock(self._service_lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            self._service_lock.close()
            raise ValueError("another model broker owns this state") from None
        try:
            with self.connection() as db:
                db.executescript(
                    "CREATE TABLE IF NOT EXISTS policies(scope TEXT PRIMARY KEY,fingerprint TEXT NOT NULL);"
                    "CREATE TABLE IF NOT EXISTS workers (worker_id TEXT PRIMARY KEY, spec TEXT NOT NULL, "
                    "policy_digest TEXT NOT NULL, attempt_id TEXT, deadline REAL, boot_id TEXT, revoked INTEGER NOT NULL DEFAULT 0);"
                    "CREATE TABLE IF NOT EXISTS calls (worker_id TEXT NOT NULL, attempt_id TEXT NOT NULL, request_id TEXT NOT NULL, "
                    "payload_hash TEXT NOT NULL, reserved_tokens INTEGER NOT NULL, status TEXT NOT NULL, response TEXT, "
                    "PRIMARY KEY(worker_id,attempt_id,request_id));"
                )
                db.execute("BEGIN IMMEDIATE")
                for key, policy in self.policies.items():
                    if not isinstance(key, tuple) or len(key) != 3:
                        raise ValueError(
                            "model policy requires deployment, repository and profile"
                        )
                    WorkerSpec(key[0], key[1], "policy", 1, "policy", key[2])
                    scope = _json(key)
                    fingerprint = self.policy_digests[key]
                    db.execute(
                        "INSERT OR IGNORE INTO policies VALUES(?,?)",
                        (scope, fingerprint),
                    )
                    if (
                        db.execute(
                            "SELECT fingerprint FROM policies WHERE scope=?", (scope,)
                        ).fetchone()[0]
                        != fingerprint
                    ):
                        raise ValueError(
                            "approved model policy changed; use a new profile name"
                        )
        except BaseException:
            self._service_lock.close()
            raise

    @contextmanager
    def connection(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA synchronous=FULL")
        try:
            with db:
                yield db
        finally:
            db.close()

    @staticmethod
    def _read(connection, size: int, deadline: float) -> bytes:
        content = bytearray()
        while len(content) < size:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise BrokerDenied("invalid_request")
            connection.settimeout(remaining)
            part = connection.recv(min(65536, size - len(content)))
            if not part:
                raise BrokerDenied("invalid_request")
            content.extend(part)
        return bytes(content)

    def _worker(self, db, worker_id):
        row = db.execute(
            "SELECT * FROM workers WHERE worker_id=?", (worker_id,)
        ).fetchone()
        if row is None:
            raise BrokerDenied("not_authorized")
        return row

    def _policy(self, spec):
        policy = self.policies.get((spec.deployment_id, spec.repository, spec.profile))
        if policy is None:
            raise BrokerDenied("not_authorized")
        return policy

    def policy_for_worker(self, worker_id):
        with self.connection() as db:
            return self._policy(
                WorkerSpec(**json.loads(self._worker(db, worker_id)["spec"]))
            )

    def peer_uid_for_worker(self, worker_id):
        with self.connection() as db:
            spec = WorkerSpec(**json.loads(self._worker(db, worker_id)["spec"]))
        return self.peer_uids[(spec.deployment_id, spec.repository, spec.profile)]

    def check_ready(self) -> None:
        """Prove local transport availability without creating an inference grant.

        The service must restore its known live workers first. This probe does
        not infer which journalled workers the canonical runtime still owns.
        """
        with self.guard:
            if self.closed or any(
                not endpoint.thread.is_alive()
                for endpoint in self.endpoints.values()
                if not endpoint.stop_requested.is_set()
            ):
                raise BrokerDenied("model_transport_unavailable")
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            name = "probe-" + uuid4().hex
            path = self.root / name
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as probe:
                    probe.bind(f"/proc/self/fd/{descriptor}/{name}")
                    probe.listen(1)
            except OSError:
                raise BrokerDenied("model_transport_unavailable") from None
            finally:
                if path.exists():
                    path.unlink()
                os.close(descriptor)

    def restore_workers(
        self, live_workers: Mapping[str, WorkerSpec]
    ) -> dict[str, Path]:
        """Rebind listeners for the trusted runtime's exact live worker set.

        Only existing, unrevoked immutable records may be restored. Historical
        rows do not create listeners or new authority merely on broker restart.
        """
        restored = {}
        for worker_id, spec in live_workers.items():
            with self.connection() as db:
                row = self._worker(db, worker_id)
                if row["revoked"] or row["spec"] != _json(asdict(spec)):
                    raise BrokerDenied("not_authorized")
            restored[worker_id] = self.prepare_worker(worker_id, spec)
        return restored

    def prepare_worker(self, worker_id: str, spec: WorkerSpec) -> Path:
        if not isinstance(worker_id, str) or not re.fullmatch(
            r"[0-9a-f]{32}", worker_id
        ):
            raise ValueError("model endpoint requires an immutable worker UUID")
        self._policy(spec)
        fingerprint = self.policy_digests[
            (spec.deployment_id, spec.repository, spec.profile)
        ]
        with self.guard:
            if self.closed:
                raise ValueError("model broker is closed")
            with self.connection() as db:
                db.execute("BEGIN IMMEDIATE")
                db.execute(
                    "INSERT OR IGNORE INTO workers(worker_id,spec,policy_digest) VALUES(?,?,?)",
                    (worker_id, _json(asdict(spec)), fingerprint),
                )
                row = self._worker(db, worker_id)
                if (
                    row["spec"] != _json(asdict(spec))
                    or row["policy_digest"] != fingerprint
                ):
                    raise ValueError("worker model binding changed")
            directory = self.root / worker_id
            if not directory.exists():
                directory.mkdir(mode=0o711)
                directory.chmod(0o711)
            if (
                directory.is_symlink()
                or stat.S_IMODE(directory.stat().st_mode) != 0o711
            ):
                raise ValueError(
                    "model endpoint directory must be an owned mode0711 directory"
                )
            endpoint = self.endpoints.get(worker_id)
            if not row["revoked"] and (
                endpoint is None or not endpoint.thread.is_alive()
            ):
                self.endpoints[worker_id] = _Endpoint(self, worker_id, directory)
            return directory

    def bind_attempt(
        self,
        worker_id: str,
        spec: WorkerSpec,
        attempt_id: str,
        remaining_seconds: float,
        *,
        deadline_monotonic: float | None = None,
    ):
        started = time.monotonic()
        if not isinstance(attempt_id, str) or not _IDENTIFIER.fullmatch(attempt_id):
            raise ValueError("invalid canonical attempt identity")
        if (
            type(remaining_seconds) not in {int, float}
            or not math.isfinite(remaining_seconds)
            or not 0 < remaining_seconds <= 86400
        ):
            raise ValueError("invalid canonical remaining duration")
        deadline = started + remaining_seconds
        if deadline_monotonic is not None:
            if (
                type(deadline_monotonic) not in {int, float}
                or not math.isfinite(deadline_monotonic)
                or deadline_monotonic <= 0
            ):
                raise ValueError("invalid original monotonic cutoff")
            deadline = min(deadline, deadline_monotonic)
        if deadline <= time.monotonic():
            raise BrokerDenied("not_authorized")
        self.prepare_worker(worker_id, spec)
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._worker(db, worker_id)
            if row["revoked"] or (
                row["attempt_id"] is not None and row["attempt_id"] != attempt_id
            ):
                raise BrokerDenied("not_authorized")
            if row["boot_id"] is not None and row["boot_id"] != self.boot_id:
                raise BrokerDenied("not_authorized")
            if row["deadline"] is not None:
                deadline = min(deadline, row["deadline"])
            if deadline <= time.monotonic():
                raise BrokerDenied("not_authorized")
            db.execute(
                "UPDATE workers SET attempt_id=?,deadline=?,boot_id=? WHERE worker_id=?",
                (attempt_id, deadline, self.boot_id, worker_id),
            )

    def revoke_attempt(self, worker_id: str, attempt_id: str):
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            row = self._worker(db, worker_id)
            if row["attempt_id"] != attempt_id:
                raise BrokerDenied("not_authorized")
            db.execute("UPDATE workers SET revoked=1 WHERE worker_id=?", (worker_id,))
        with self.guard:
            endpoint = self.endpoints.get(worker_id)
            if endpoint:
                endpoint.stop()

    def _authorized(self, worker_id):
        if self.closed:
            raise BrokerDenied("not_authorized")
        with self.connection() as db:
            row = dict(self._worker(db, worker_id))
        if (
            self.closed
            or row["revoked"]
            or not row["attempt_id"]
            or row["boot_id"] != self.boot_id
            or row["deadline"] <= time.monotonic()
        ):
            raise BrokerDenied("not_authorized")
        spec = WorkerSpec(**json.loads(row["spec"]))
        policy = self._policy(spec)
        if (
            self.policy_digests[(spec.deployment_id, spec.repository, spec.profile)]
            != row["policy_digest"]
        ):
            raise BrokerDenied("not_authorized")
        started = time.monotonic()
        try:
            remaining = self.permission(
                ModelBinding(worker_id, row["attempt_id"], spec)
            )
        except Exception:
            raise BrokerDenied("not_authorized") from None
        if (
            type(remaining) not in {int, float}
            or not math.isfinite(remaining)
            or remaining <= 0
        ):
            raise BrokerDenied("not_authorized")
        # Permission transport can outlive a local cancellation, shutdown or
        # shortened binding. Never turn its delayed reply into fresh admission.
        with self.guard:
            with self.connection() as db:
                current = dict(self._worker(db, worker_id))
            if (
                self.closed
                or current["revoked"]
                or any(
                    current[key] != row[key]
                    for key in ("spec", "policy_digest", "attempt_id", "boot_id")
                )
                or current["deadline"] <= time.monotonic()
            ):
                raise BrokerDenied("not_authorized")
        deadline = min(row["deadline"], current["deadline"], started + remaining)
        if deadline <= time.monotonic():
            raise BrokerDenied("not_authorized")
        return row, policy, deadline

    def complete(self, worker_id: str, payload: dict) -> dict:
        return self._serialized_complete(worker_id, payload)

    def complete_child(self, worker_id: str, child_id: str, payload: dict) -> dict:
        if self.child_supervisor is None:
            raise BrokerDenied("not_authorized")
        return self._serialized_complete(worker_id, payload, child_id)

    def complete_public(self, worker_id, payload, *, child_id=None):
        """Trusted host entry only; public guest sockets never select this mode."""
        with self.public_condition:
            if (
                self.closed or self.public_supervisor is None
                or (child_id is not None and self.child_supervisor is None)
            ):
                raise BrokerDenied("not_authorized")
            self.public_calls += 1
        try:
            return self._serialized_complete(worker_id, payload, child_id, public=True)
        except BrokerDenied:
            raise
        except Exception:
            raise BrokerDenied("uncertain") from None
        finally:
            with self.public_condition:
                self.public_calls -= 1
                self.public_condition.notify_all()

    def inspect_public(self, worker_id, attempt_id, payload, *, child_id=None):
        """Read an original public call without permission refresh or dispatch."""
        binding = self._public_bound(worker_id, child_id, payload, admission=False)
        from .managed_public_types import canonical
        normalized = canonical(payload).decode()
        with self.connection() as db:
            worker = self._worker(db, worker_id)
            if (
                worker["attempt_id"] != attempt_id
                or binding["actor"]["identity"]["root_attempt_id"] != attempt_id
            ):
                raise BrokerDenied("conflict")
            row = db.execute(
                "SELECT * FROM calls WHERE worker_id=? AND attempt_id=? AND request_id=?",
                (worker_id, attempt_id, payload["request_id"]),
            ).fetchone()
        if row is None:
            return {"status": "missing", "result": None}
        if row["payload_hash"] != _hash(normalized) or row["status"] not in {
            "child_authorizing", "reserved", "uncertain", "complete",
        }:
            raise BrokerDenied("conflict")
        result = None
        if row["status"] == "complete":
            try:
                result = json.loads(row["response"], object_pairs_hook=_pairs)
                if _json(result) != row["response"]:
                    raise ValueError("noncanonical retained response")
                self._public_result(result, payload, binding)
            except BrokerDenied:
                raise
            except Exception:
                raise BrokerDenied("uncertain") from None
        elif row["response"] is not None:
            raise BrokerDenied("conflict")
        return {"status": row["status"], "result": result}

    def _public_bound(self, worker_id, child_id, payload, *, admission):
        from .managed_public_types import (
            PublicPolicy, canonical, digest, finite, public_model_payload,
        )
        if self.public_supervisor is None:
            raise BrokerDenied("not_authorized")
        try:
            # This trusted callback reads original local actor/slot state only.
            # It must not acquire an operation lease or make a network call.
            binding = self.public_supervisor.model_binding(
                worker_id, child_id, payload, admission=admission,
            )
            if (
                not isinstance(binding, dict)
                or set(binding) != {"policy", "actor", "slot", "cutoff"}
                or not isinstance(binding["policy"], PublicPolicy)
            ):
                raise BrokerDenied("not_authorized")
            finite(binding["cutoff"], 0, 1e15)
            actor, slot = binding["actor"], binding["slot"]
            if (
                actor["identity"]["worker_id"] != worker_id
                or actor["identity"]["child_id"] != child_id
                or actor["identity"]["role"] != ("root" if child_id is None else "child")
                or slot["actor_id"] != ("root" if child_id is None else child_id)
                or binding["cutoff"] > slot["monotonic_cutoff"]
            ):
                raise BrokerDenied("not_authorized")
            expected = public_model_payload(binding["policy"], actor, slot)
            if canonical(payload) != canonical(expected) or slot["model_call_digest"] != digest(expected):
                raise BrokerDenied("conflict")
            if admission and binding["cutoff"] <= time.monotonic():
                raise BrokerDenied("not_authorized")
            return binding
        except BrokerDenied:
            raise
        except Exception:
            raise BrokerDenied("not_authorized") from None

    @staticmethod
    def _public_body(policy, binding, payload, tokens):
        from .discussion_types import public_provider_request
        from .managed_public_types import canonical
        approved, slot = binding["policy"].document, binding["slot"]
        body = public_provider_request(
            model=policy.model,
            persona=approved["personas"][slot["persona_key"]],
            instruction=approved["instructions"][slot["instruction_key"]],
            context=slot["context"], tokens=tokens,
            token_parameter=policy.token_parameter, token_limit=policy.max_output_tokens,
        )
        if (
            body["messages"] != payload["messages"]
            or len(canonical(body)) > min(131072, policy.max_request_bytes)
        ):
            raise BrokerDenied("invalid_request")
        return body

    @staticmethod
    def _public_result(result, payload, binding):
        from .discussion_types import validate_output
        from .managed_public_types import publication_key, signed_intent
        if (
            not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("request_id") != payload["request_id"]
            or type(result.get("ok")) is not bool
        ):
            raise BrokerDenied("uncertain")
        if result["ok"] is False:
            if set(result) != {"schema_version", "request_id", "ok", "error"} or result["error"] != "not_authorized":
                raise BrokerDenied("uncertain")
            return result
        if set(result) != {"schema_version", "request_id", "ok", "output"}:
            raise BrokerDenied("uncertain")
        try:
            output = validate_output(result["output"])
            slot = binding["slot"]
            if slot["response"] is not None and slot["response"] != output:
                raise BrokerDenied("conflict")
            signed_intent(
                binding["actor"]["status"], publication_key(slot["slot_id"]),
                output["kind"], output["content"], reply_to=slot["reply_to"],
            )
        except BrokerDenied:
            raise
        except Exception:
            raise BrokerDenied("uncertain") from None
        return result

    def _serialized_complete(self, worker_id, payload, child_id=None, *, public=False):
        # A known live call is busy, not a lost provider outcome. No journal or
        # canonical turn effects occur before this common root/child gate.
        with self.connection() as db:
            worker = self._worker(db, worker_id)
            spec = WorkerSpec(**json.loads(worker["spec"]))
        with self.guard:
            gate = self.inference_locks.setdefault(worker_id, threading.Lock())
        if not gate.acquire(timeout=0.05):
            raise BrokerDenied("retry_later")
        try:
            if (
                child_id is not None
                and self.child_supervisor.policy(spec).session_protocol is not None
            ):
                # This is a new-call admission check only. Once it succeeds,
                # existing permission rechecks remain unchanged for this call.
                try:
                    admission_open = self.child_supervisor.model_admission_open(
                        worker_id, child_id
                    )
                except Exception:
                    admission_open = False
                if not admission_open:
                    raise BrokerDenied("not_authorized")
            if public:
                return self._complete_serial(worker_id, payload, child_id, public=True)
            return self._complete_serial(worker_id, payload, child_id)
        finally:
            gate.release()

    @contextmanager
    def child_followup_gate(self, worker_id, attempt_id):
        """Borrow the existing gate without waiting or dispatching inference."""
        with self.guard:
            gate = self.inference_locks.setdefault(worker_id, threading.Lock())
        if not gate.acquire(blocking=False):
            yield "busy"
            return
        try:
            with self.connection() as db:
                row = self._worker(db, worker_id)
                if (
                    self.closed or row["revoked"]
                    or row["attempt_id"] != attempt_id
                    or row["boot_id"] != self.boot_id
                    or row["deadline"] <= time.monotonic()
                ):
                    raise BrokerDenied("not_authorized")
                unresolved = db.execute(
                    "SELECT 1 FROM calls WHERE worker_id=? AND attempt_id=? "
                    "AND status IN ('reserved','uncertain','child_authorizing') LIMIT 1",
                    (worker_id, attempt_id),
                ).fetchone()
            yield "clear" if unresolved is None else "unresolved"
        finally:
            gate.release()

    def _context_permission(self, worker_id, child_id=None):
        row, policy, deadline = self._authorized(worker_id)
        if child_id is not None:
            from .child_supervisor import ChildDenied

            try:
                deadline = min(
                    deadline, self.child_supervisor.permission(worker_id, child_id)
                )
            except Exception:
                raise BrokerDenied("not_authorized") from None
            # Child authority transport can outlive root cancellation too.
            current, _, root_deadline = self._authorized(worker_id)
            if current["attempt_id"] != row["attempt_id"]:
                raise BrokerDenied("not_authorized")
            try:
                deadline = min(
                    deadline,
                    root_deadline,
                    self.child_supervisor.local_cutoff(worker_id, child_id),
                )
            except ChildDenied:
                raise BrokerDenied("not_authorized") from None
        if deadline <= time.monotonic():
            raise BrokerDenied("not_authorized")
        return row, policy, deadline

    def _complete_serial(self, worker_id: str, payload: dict, child_id=None, *, public=False) -> dict:
        binding = None
        if public:
            binding = self._public_bound(worker_id, child_id, payload, admission=True)
            definitions = None
        else:
            if (
                not isinstance(payload, dict)
                or set(payload) != {"schema_version", "request_id", "messages"}
                or type(payload["schema_version"]) is not int
                or payload["schema_version"] != 1
                or not isinstance(payload["request_id"], str)
                or not _IDENTIFIER.fullmatch(payload["request_id"])
            ):
                raise BrokerDenied("invalid_request")
            definitions = TOOL_DEFINITIONS
            if self.child_supervisor is not None:
                with self.connection() as db:
                    spec = WorkerSpec(**json.loads(self._worker(db, worker_id)["spec"]))
                if child_id is None and self.child_supervisor.enabled(spec):
                    from src.agent.child_tools import CHILD_TOOL_DEFINITIONS

                    definitions = [*TOOL_DEFINITIONS, *CHILD_TOOL_DEFINITIONS]
                    if self.child_supervisor.policy(spec).session_protocol is not None:
                        from src.agent.child_tools import SESSION_TOOL_DEFINITIONS

                        definitions = [*definitions, *SESSION_TOOL_DEFINITIONS]
                elif (
                    child_id is not None
                    and self.child_supervisor.policy(spec).outcome_protocol is not None
                ):
                    from src.agent.child_outcome import OUTCOME_TOOL_DEFINITIONS

                    definitions = [*TOOL_DEFINITIONS, *OUTCOME_TOOL_DEFINITIONS]
            tool_names = {item["function"]["name"] for item in definitions}
            _messages(payload["messages"], tool_names)
            if self.public_supervisor is not None:
                with self.connection() as db:
                    spec = WorkerSpec(**json.loads(self._worker(db, worker_id)["spec"]))
                if self.public_supervisor.enabled(spec) and payload["request_id"].startswith("mpub1:"):
                    raise BrokerDenied("invalid_request")
        row, policy, deadline = self._context_permission(worker_id, child_id)
        if public:
            from .managed_public_types import canonical
            normalized = canonical(payload).decode()
            if binding["actor"]["identity"]["root_attempt_id"] != row["attempt_id"]:
                raise BrokerDenied("not_authorized")
            deadline = min(deadline, binding["cutoff"])
            # Authority transport must not spend an already expired public slot.
            if deadline <= time.monotonic():
                raise BrokerDenied("not_authorized")
            # Check the complete no-tools body before any durable allocation.
            try:
                self._public_body(policy, binding, payload, policy.max_output_tokens)
            except BrokerDenied:
                raise
            except Exception:
                raise BrokerDenied("invalid_request") from None
        else:
            normalized = _json(payload)
        if len(normalized.encode()) > policy.max_request_bytes or (public and len(normalized.encode()) > 131072):
            raise BrokerDenied("invalid_request")
        stored_id = (
            payload["request_id"]
            if public or child_id is None
            else "/child/" + _hash(_json([child_id, payload["request_id"]]))
        )
        identity = (worker_id, row["attempt_id"], stored_id)
        digest = _hash(normalized)
        cached = None
        with self.connection() as db:
            db.execute("BEGIN IMMEDIATE")
            current = self._worker(db, worker_id)
            if (
                current["revoked"]
                or current["attempt_id"] != row["attempt_id"]
                or current["deadline"] <= time.monotonic()
                or (public and deadline <= time.monotonic())
            ):
                # BEGIN IMMEDIATE can wait. Use the original sampled cutoff,
                # without a public-journal callback under this write lock.
                raise BrokerDenied("not_authorized")
            prior = db.execute(
                "SELECT * FROM calls WHERE worker_id=? AND attempt_id=? AND request_id=?",
                identity,
            ).fetchone()
            if prior:
                if prior["payload_hash"] != digest:
                    raise BrokerDenied("conflict")
                if prior["status"] == "complete":
                    cached = (
                        json.loads(prior["response"], object_pairs_hook=_pairs)
                        if public else json.loads(prior["response"])
                    )
                    if public and _json(cached) != prior["response"]:
                        raise BrokerDenied("uncertain")
                elif child_id is None or prior["status"] != "child_authorizing":
                    raise BrokerDenied("uncertain")
                tokens = prior["reserved_tokens"]
            else:
                pending = db.execute(
                    "SELECT status FROM calls WHERE worker_id=? AND attempt_id=? AND status!='complete'",
                    identity[:2],
                ).fetchall()
                if pending:
                    # Another child may still be resolving only its canonical
                    # turn. It has not dispatched a provider request, so peers
                    # wait without creating another reservation or exiting.
                    if all(item["status"] == "child_authorizing" for item in pending):
                        raise BrokerDenied("retry_later")
                    raise BrokerDenied("uncertain")
                count, reserved = db.execute(
                    "SELECT COUNT(*),COALESCE(SUM(reserved_tokens),0) FROM calls WHERE worker_id=? AND attempt_id=?",
                    identity[:2],
                ).fetchone()
                available = policy.max_total_output_tokens - reserved
                if count >= policy.max_calls or available <= 0:
                    raise BrokerDenied("budget_exhausted")
                tokens = min(policy.max_output_tokens, available)
                if public and deadline <= time.monotonic():
                    raise BrokerDenied("not_authorized")
                db.execute(
                    "INSERT INTO calls VALUES(?,?,?,?,?,?,NULL)",
                    (
                        *identity,
                        digest,
                        tokens,
                        "child_authorizing" if child_id is not None else "reserved",
                    ),
                )
        if cached is not None:
            self._context_permission(worker_id, child_id)
            if public:
                self._public_bound(worker_id, child_id, payload, admission=True)
                self._public_result(cached, payload, binding)
            return cached
        if child_id is not None:
            from .child_supervisor import ChildDenied, ChildTurnExpired
            from src.polyphony.child_client import ChildRejected
            from src.polyphony.managed_client import AuthorityUnavailable

            if public and deadline <= time.monotonic():
                # Keep any original authorizing reservation unresolved. Expiry
                # grants no canonical retry and is not a canonical denial reply.
                raise BrokerDenied("not_authorized")
            try:
                if public:
                    turn_deadline = self.child_supervisor.reserve_turn(
                        worker_id, child_id, payload["request_id"], digest,
                        admission_cutoff=deadline,
                    )
                else:
                    turn_deadline = self.child_supervisor.reserve_turn(
                        worker_id, child_id, payload["request_id"], digest
                    )
                deadline = min(deadline, turn_deadline)
                self._context_permission(worker_id, child_id)
            except ChildTurnExpired:
                # No canonical turn request was dispatched. Keep the original
                # model reservation held without inventing a denial or refund.
                raise BrokerDenied("not_authorized") from None
            except (ChildDenied, ChildRejected, BrokerDenied):
                denied = {
                    "schema_version": 1,
                    "request_id": payload["request_id"],
                    "ok": False,
                    "error": "not_authorized",
                }
                with self.connection() as db:
                    db.execute(
                        "UPDATE calls SET status='complete',response=? WHERE worker_id=? AND attempt_id=? AND request_id=? AND status='child_authorizing'",
                        (_json(denied), *identity),
                    )
                raise BrokerDenied("not_authorized") from None
            except AuthorityUnavailable:
                # Only the canonical turn reservation may repeat at this phase.
                raise BrokerDenied("canonical_pending") from None
            with self.connection() as db:
                db.execute(
                    "UPDATE calls SET status='reserved' WHERE worker_id=? AND attempt_id=? AND request_id=? AND status='child_authorizing'",
                    identity,
                )
        try:
            # Reserving the durable budget may wait on a database writer. Do
            # not dispatch using permission sampled before that wait.
            _, _, current_deadline = self._context_permission(worker_id, child_id)
            deadline = min(deadline, current_deadline)
            if public:
                binding = self._public_bound(worker_id, child_id, payload, admission=True)
                deadline = min(deadline, binding["cutoff"])
                forward = self._forward_public(policy, binding, payload, tokens, deadline)
            else:
                forward = (
                    self._forward(policy, payload["messages"], tokens, deadline)
                    if definitions is TOOL_DEFINITIONS
                    else self._forward(
                        policy, payload["messages"], tokens, deadline, definitions
                    )
                )
            response = asyncio.run(forward)
            result = {
                "schema_version": 1,
                "request_id": payload["request_id"],
                "ok": True,
                "message": response,
            }
            if public:
                result["output"] = result.pop("message")
                self._public_result(result, payload, binding)
            with self.connection() as db:
                db.execute(
                    "UPDATE calls SET status='complete',response=? WHERE worker_id=? AND attempt_id=? AND request_id=?",
                    (_json(result), *identity),
                )
            # Revocation can race an already dispatched inference call. Its
            # budget stays charged, but it grants no fresh permission or output.
            self._context_permission(worker_id, child_id)
            if public:
                self._public_bound(worker_id, child_id, payload, admission=True)
            return result
        except BrokerDenied:
            with self.connection() as db:
                db.execute(
                    "UPDATE calls SET status='uncertain' WHERE worker_id=? AND attempt_id=? AND request_id=? AND status='reserved'",
                    identity,
                )
            raise
        except Exception:
            with self.connection() as db:
                db.execute(
                    "UPDATE calls SET status='uncertain' WHERE worker_id=? AND attempt_id=? AND request_id=? AND status='reserved'",
                    identity,
                )
            raise BrokerDenied("uncertain") from None

    async def _forward_public(self, policy, binding, payload, tokens, deadline):
        from .managed_public_types import public_output, publication_key, signed_intent
        token = os.environ.get(policy.token_ref[4:], "")
        if not token or any(c.isspace() for c in token):
            raise BrokerDenied("provider_unavailable")
        remaining = min(policy.request_timeout_seconds, deadline - time.monotonic())
        if remaining <= 0:
            raise BrokerDenied("not_authorized")
        body = self._public_body(policy, binding, payload, tokens)

        def decode(raw):
            output = public_output(raw, token)
            # The public record's escaped envelope must fit before raw provider
            # text can enter the common completed-response cache.
            slot = binding["slot"]
            signed_intent(
                binding["actor"]["status"], publication_key(slot["slot_id"]),
                output["kind"], output["content"], reply_to=slot["reply_to"],
            )
            return output

        try:
            return await post_bounded_json(
                policy.endpoint, body,
                {"Authorization": "Bearer " + token, "Accept-Encoding": "identity"},
                timeout_seconds=remaining,
                max_response_bytes=min(262144, policy.max_response_bytes),
                decode=decode,
            )
        except HTTPResponseRejected:
            raise BrokerDenied("provider_unavailable") from None
        except BrokerDenied:
            raise
        except Exception:
            raise BrokerDenied("uncertain") from None

    async def _forward(self, policy, messages, tokens, deadline, definitions=None):
        token = os.environ.get(policy.token_ref[4:], "")
        if not token or any(c.isspace() for c in token):
            raise BrokerDenied("provider_unavailable")
        remaining = min(policy.request_timeout_seconds, deadline - time.monotonic())
        if remaining <= 0:
            raise BrokerDenied("not_authorized")
        body = {
            "model": policy.model,
            "messages": messages,
            "tools": TOOL_DEFINITIONS if definitions is None else definitions,
            "tool_choice": "auto",
            "stream": False,
            policy.token_parameter: tokens,
        }
        try:
            try:
                value = await post_bounded_json(
                    policy.endpoint,
                    body,
                    {
                        "Authorization": "Bearer " + token,
                        "Accept-Encoding": "identity",
                    },
                    timeout_seconds=remaining,
                    max_response_bytes=policy.max_response_bytes,
                    decode=lambda raw: json.loads(raw, object_pairs_hook=_pairs),
                )
            except HTTPResponseRejected:
                raise BrokerDenied("provider_unavailable") from None
            choices = value.get("choices") if isinstance(value, dict) else None
            if (
                not isinstance(choices, list)
                or not choices
                or not isinstance(choices[0], dict)
            ):
                raise BrokerDenied("provider_unavailable")
            allowed_tools = (
                None
                if definitions is None
                else {item["function"]["name"] for item in definitions}
            )
            return _assistant(choices[0].get("message"), allowed_tools)
        except BrokerDenied:
            raise
        except Exception:
            raise BrokerDenied("uncertain") from None

    def close(self):
        with self.guard:
            if self.closed:
                return
            self.closed = True
            endpoints = list(self.endpoints.values())
            self.endpoints.clear()
            for endpoint in endpoints:
                endpoint.stop()
        deadline = time.monotonic() + 1
        for endpoint in endpoints:
            endpoint.thread.join(max(0, deadline - time.monotonic()))
        # Do not release ownership while an in-flight thread can still mutate
        # this journal. Callers may retry close after the bounded request ends.
        with self.public_condition:
            public_active = self.public_calls != 0
        if any(endpoint.thread.is_alive() for endpoint in endpoints) or public_active:

            def release_when_stopped():
                for endpoint in endpoints:
                    endpoint.thread.join()
                with self.public_condition:
                    self.public_condition.wait_for(lambda: self.public_calls == 0)
                self._service_lock.close()

            threading.Thread(target=release_when_stopped, daemon=True).start()
        else:
            self._service_lock.close()
