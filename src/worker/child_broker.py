"""Host-bound root controls and child inference endpoints.

The guest request never selects its actor. Linux SO_PEERCRED and a fixed endpoint
context distinguish the root and every child UID inside this worker.
"""

from __future__ import annotations

import json
import os
from pathlib import Path
import socket
import socketserver
import stat
import struct
import threading
import time
from types import SimpleNamespace

from src.polyphony.managed_client import AuthorityUnavailable
from .child_supervisor import ChildDenied
from .child_types import IDENTIFIER
from .lifecycle import LifecycleConflict, RuntimeUnavailable
from .model_broker import BrokerDenied, _Endpoint, _UnixServer, _json, _pairs


class _ControlEndpoint:
    def __init__(self, adapter, worker_id, directory):
        self.stop_requested = threading.Event()
        self.directory_fd = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.socket_path = Path(directory) / "control.sock"
        if self.socket_path.exists() or self.socket_path.is_symlink():
            if self.socket_path.is_symlink() or not stat.S_ISSOCK(
                self.socket_path.lstat().st_mode
            ):
                os.close(self.directory_fd)
                raise ValueError("child control path is not an owned socket")
            self.socket_path.unlink()

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
                    if uid != adapter.model.peer_uid_for_worker(worker_id):
                        raise ChildDenied("not_authorized")
                    deadline = time.monotonic() + 5
                    length = struct.unpack(
                        "!I", adapter.model._read(self.request, 4, deadline)
                    )[0]
                    if not 1 <= length <= 131072:
                        raise ChildDenied("invalid_request")
                    payload = json.loads(
                        adapter.model._read(self.request, length, deadline),
                        object_pairs_hook=_pairs,
                    )
                    if (
                        isinstance(payload, dict)
                        and isinstance(payload.get("request_id"), str)
                        and IDENTIFIER.fullmatch(payload["request_id"])
                    ):
                        request_id = payload["request_id"]
                    result = adapter.supervisor.handle(worker_id, payload)
                except ChildDenied as exc:
                    result = {
                        "schema_version": 1,
                        "request_id": request_id,
                        "ok": False,
                        "error": exc.code,
                    }
                except LifecycleConflict:
                    result = {
                        "schema_version": 1,
                        "request_id": request_id,
                        "ok": False,
                        "error": "conflict",
                    }
                except AuthorityUnavailable:
                    # The exact intent is retained. Only its canonical delivery
                    # may repeat; this never replays an uncertain Docker exec.
                    result = {
                        "schema_version": 1,
                        "request_id": request_id,
                        "ok": False,
                        "error": "canonical_pending",
                    }
                except RuntimeUnavailable:
                    result = {
                        "schema_version": 1,
                        "request_id": request_id,
                        "ok": False,
                        "error": "retry_later",
                    }
                except Exception:
                    result = {
                        "schema_version": 1,
                        "request_id": request_id,
                        "ok": False,
                        "error": "invalid_request",
                    }
                encoded = _json(result).encode()
                if len(encoded) > 524288:
                    encoded = _json(
                        {
                            "schema_version": 1,
                            "request_id": request_id,
                            "ok": False,
                            "error": "invalid_response",
                        }
                    ).encode()
                self.request.settimeout(5)
                self.request.sendall(struct.pack("!I", len(encoded)) + encoded)

        self.server = None
        self.thread = threading.Thread(
            target=self._serve, daemon=True, name="root-child-control"
        )
        try:
            self.server = _UnixServer(
                f"/proc/self/fd/{self.directory_fd}/control.sock",
                Handler,
                peer_uid=adapter.model.peer_uid_for_worker(worker_id),
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


class _ChildModelContext:
    """Only the endpoint construction code chooses this immutable context."""

    def __init__(self, adapter, root, child_id):
        self.adapter, self.root, self.child_id = adapter, root, child_id

    def _bound(self, child_id):
        if child_id != self.child_id:
            raise BrokerDenied("not_authorized")
        return self.adapter.supervisor.journal.child(self.root.worker_id, self.child_id)

    def peer_uid_for_worker(self, child_id):
        return self._bound(child_id)["uid"]

    def policy_for_worker(self, child_id):
        self._bound(child_id)
        return self.adapter.model.policy_for_worker(self.root.worker_id)

    def _read(self, *args):
        return self.adapter.model._read(*args)

    def complete(self, child_id, payload):
        self._bound(child_id)
        return self.adapter.model.complete_child(
            self.root.worker_id, self.child_id, payload
        )


class _ChildOutcomeContext(_ChildModelContext):
    def policy_for_worker(self, child_id):
        self._bound(child_id)
        return SimpleNamespace(max_request_bytes=65536)

    def complete(self, child_id, payload):
        self._bound(child_id)
        try:
            return self.adapter.supervisor.report_outcome(
                self.root.worker_id, self.child_id, payload
            )
        except ChildDenied as error:
            raise BrokerDenied(error.code) from None
        except LifecycleConflict:
            raise BrokerDenied("conflict") from None


class ChildBroker:
    def __init__(self, supervisor, model_broker):
        self.supervisor, self.model = supervisor, model_broker
        self.controls = {}
        self.children = {}
        self.outcomes = {}
        self.guard = threading.RLock()
        self.closed = False

    def prepare_root(self, worker_id, spec, directory):
        expected = self.model.root / worker_id
        if Path(directory) != expected or expected.is_symlink():
            raise ValueError("child endpoint must use the owned worker model mount")
        with self.guard:
            if self.closed:
                raise RuntimeUnavailable("child transport is closed")
            old = self.controls.get(worker_id)
            if old is None or not old.thread.is_alive():
                self.controls[worker_id] = _ControlEndpoint(self, worker_id, expected)

    def prepare_child(self, root, child):
        child_id = child["child_id"]
        with self.guard:
            if self.closed:
                raise RuntimeUnavailable("child transport is closed")
            existing = self.children.get(child_id)
            parent = self.model.root / root.worker_id / "children"
            directory = parent / child_id
            for path in (parent, directory):
                if not path.exists():
                    path.mkdir(mode=0o711)
                    path.chmod(0o711)
                if (
                    path.is_symlink()
                    or not path.is_dir()
                    or stat.S_IMODE(path.stat().st_mode) != 0o711
                ):
                    raise ValueError(
                        "child endpoint directories must be owned mode0711 directories"
                    )
            endpoint = existing
            if existing is None or not existing.thread.is_alive():
                context = _ChildModelContext(self, root, child_id)
                endpoint = _Endpoint(context, child_id, directory)
            with self.model.guard:
                if self.model.closed:
                    endpoint.stop()
                    raise RuntimeUnavailable("root model broker is closed")
                # Include these listeners in the root broker's close/join fence.
                # The reserved key cannot be supplied as a worker UUID.
                self.model.endpoints["/child/" + child_id] = endpoint
            self.children[child_id] = endpoint
            if self.supervisor.policy(root.spec).outcome_protocol is not None:
                outcome = self.outcomes.get(child_id)
                if outcome is None or not outcome.thread.is_alive():
                    context = _ChildOutcomeContext(self, root, child_id)
                    outcome = _Endpoint(
                        context, child_id, directory, socket_name="outcome.sock"
                    )
                    with self.model.guard:
                        if self.model.closed:
                            outcome.stop()
                            raise RuntimeUnavailable("root model broker is closed")
                        self.model.endpoints["/child-outcome/" + child_id] = outcome
                    self.outcomes[child_id] = outcome

    def restore(self, worker_id):
        root = self.supervisor.journal.context(worker_id)
        self.prepare_root(worker_id, root.spec, self.model.root / worker_id)
        for child in self.supervisor.journal.children(worker_id):
            if child["phase"] in {"running", "exec_returned"} and not child["revoked"]:
                self.prepare_child(root, child)

    def check_ready(self):
        if self.closed or any(
            not endpoint.thread.is_alive()
            for endpoint in [
                *self.controls.values(),
                *self.children.values(),
                *self.outcomes.values(),
            ]
            if not endpoint.stop_requested.is_set()
        ):
            raise RuntimeUnavailable("child transport listener is unavailable")
        self.model.check_ready()

    def revoke(self, worker_id):
        with self.guard:
            control = self.controls.get(worker_id)
            if control is not None:
                control.stop()
            for child in self.supervisor.journal.children(worker_id):
                endpoint = self.children.get(child["child_id"])
                if endpoint is not None:
                    endpoint.stop()
                outcome = self.outcomes.get(child["child_id"])
                if outcome is not None:
                    outcome.stop()

    def close(self, released):
        with self.guard:
            self.closed = True
            endpoints = [
                *self.controls.values(),
                *self.children.values(),
                *self.outcomes.values(),
            ]
            for endpoint in endpoints:
                endpoint.stop()
        deadline = time.monotonic() + 1
        for endpoint in endpoints:
            endpoint.thread.join(max(0, deadline - time.monotonic()))
        if any(endpoint.thread.is_alive() for endpoint in endpoints):

            def release_when_stopped():
                for endpoint in endpoints:
                    endpoint.thread.join()
                released()

            threading.Thread(target=release_when_stopped, daemon=True).start()
        else:
            released()
