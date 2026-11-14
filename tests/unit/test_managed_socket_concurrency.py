"""Bounded real Unix transport with explicit effect and authority fixtures.

These tests exercise queueing, actual socket closure and retained ownership.
The named transport context is not a canonical authority or model provider.
The ownership regression separately uses the real ModelBroker, SQLite and HTTP.
"""

from contextlib import contextmanager
import fcntl
import json
import os
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from src.agent.managed_runner import BrokerClient, BrokerError
from src.worker.child_broker import ChildBroker, _ControlEndpoint
from src.worker.model_broker import BrokerDenied, ModelBroker, _Endpoint
from tests.unit.test_managed_agent import (
    MESSAGES,
    SCOPE_KEY,
    SPEC,
    WORKER,
    broker_client,
    message,
    provider,
    response,
)
from tests.unit.test_managed_model_socket import _read_response


class TransportContext:
    """Controlled effects behind the production endpoint framing and UID gates."""

    _read = staticmethod(ModelBroker._read)

    def __init__(self, uid):
        self.uid = uid
        self.entered = threading.Event()
        self.release = threading.Event()
        self.lock = threading.Lock()
        self.calls = []
        self.concurrent = 0
        self.maximum = 0

    def peer_uid_for_worker(self, worker_id):
        return self.uid

    def policy_for_worker(self, worker_id):
        return SimpleNamespace(max_request_bytes=1024)

    def complete(self, worker_id, payload):
        key = payload["request_id"]
        with self.lock:
            self.calls.append(key)
            self.concurrent += 1
            self.maximum = max(self.maximum, self.concurrent)
        try:
            if key == "active":
                self.entered.set()
                assert self.release.wait(10), "transport fixture was not released"
            return {
                "schema_version": 1,
                "request_id": key,
                "ok": True,
                "handled": key,
            }
        finally:
            with self.lock:
                self.concurrent -= 1

    def handle(self, worker_id, payload):
        return self.complete(worker_id, payload)


def _new_endpoint(directory, context, kind):
    if kind == "control":
        return _ControlEndpoint(
            SimpleNamespace(model=context, supervisor=context), WORKER, directory
        )
    return _Endpoint(
        context,
        WORKER,
        directory,
        socket_name="outcome.sock" if kind == "outcome" else "model.sock",
    )


@contextmanager
def _endpoint(tmp_path, kind="model", uid=None):
    context = TransportContext(os.getuid() if uid is None else uid)
    directory = tmp_path / "endpoint"
    directory.mkdir(mode=0o711)
    endpoint = _new_endpoint(directory, context, kind)
    try:
        yield endpoint, context
    finally:
        original_error = sys.exc_info()[1]
        context.release.set()
        endpoint.stop()
        endpoint.thread.join(7)
        if endpoint.thread.is_alive():
            if original_error is not None:
                original_error.add_note("transport fixture did not stop")
            else:
                pytest.fail("transport fixture did not stop")


def _connect(endpoint, key=None):
    connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    connection.settimeout(2)
    try:
        connection.connect(
            f"/proc/self/fd/{endpoint.directory_fd}/{endpoint.socket_path.name}"
        )
        if key is not None:
            payload = json.dumps({"schema_version": 1, "request_id": key}).encode()
            connection.sendall(struct.pack("!I", len(payload)) + payload)
        return connection
    except BaseException:
        connection.close()
        raise


def _eventually(predicate, timeout=2):
    deadline = time.monotonic() + timeout
    while not predicate():
        assert time.monotonic() < deadline, "bounded transport observation timed out"
        time.sleep(0.01)


def _service_lease_available(path):
    # File.closed can become visible before close(2) releases its flock. Probe
    # the kernel lease, then synchronously close the probe before returning.
    with path.open("r+") as handle:
        try:
            fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
        except BlockingIOError:
            return False
        return True


def _pending(endpoint):
    with endpoint.server._condition:
        return len(endpoint.server._pending)


def _closed(connection):
    try:
        assert connection.recv(1) == b"", "unadmitted request received data"
    except ConnectionResetError:
        pass


@pytest.mark.parametrize("kind", ["model", "outcome", "control"])
def test_saturation_and_stop_discard_queued_requests_without_effects(tmp_path, kind):
    with _endpoint(tmp_path, kind) as (endpoint, context):
        sockets = []
        try:
            active = _connect(endpoint, "active")
            sockets.append(active)
            assert context.entered.wait(2)
            for index in range(4):
                queued = _connect(endpoint, f"queued-{index}")
                sockets.append(queued)
            _eventually(lambda: _pending(endpoint) == 4)

            # A sixth accepted connection is closed before reading any body.
            overflow = _connect(endpoint)
            sockets.append(overflow)
            _closed(overflow)
            assert _pending(endpoint) == 4
            assert context.calls == ["active"] and context.maximum == 1
            worker = endpoint.server._worker
            assert worker.is_alive() and endpoint.thread.is_alive()

            endpoint.stop()
            assert _pending(endpoint) == 0
            for queued in sockets[1:5]:
                _closed(queued)
            assert context.calls == ["active"]
            assert worker.is_alive() and endpoint.thread.is_alive()
            assert endpoint.socket_path.exists()

            context.release.set()
            assert _read_response(active)["handled"] == "active"
            endpoint.thread.join(2)
            assert not endpoint.thread.is_alive() and not worker.is_alive()
            assert not endpoint.socket_path.exists()
            assert context.calls == ["active"]
        finally:
            for connection in sockets:
                connection.close()


def test_authorized_requests_remain_fifo_and_serialized(tmp_path):
    with _endpoint(tmp_path, "outcome") as (endpoint, context):
        sockets = []
        try:
            sockets.append(_connect(endpoint, "active"))
            assert context.entered.wait(2)
            expected = ["active", *[f"queued-{index}" for index in range(4)]]
            for key in expected[1:]:
                sockets.append(_connect(endpoint, key))
            _eventually(lambda: _pending(endpoint) == 4)
            assert context.calls == ["active"]
            context.release.set()
            for connection, key in zip(sockets, expected):
                assert _read_response(connection)["handled"] == key
            assert context.calls == expected
            assert context.maximum == 1
        finally:
            for connection in sockets:
                connection.close()


def test_early_wrong_uid_denial_needs_no_live_context_read(tmp_path):
    with _endpoint(tmp_path, uid=os.getuid() + 1) as (endpoint, context):
        def forbidden(*args):
            pytest.fail("wrong UID reached live context or payload processing")

        context.peer_uid_for_worker = forbidden
        context.policy_for_worker = forbidden
        context.complete = forbidden
        with _connect(endpoint) as connection:
            result = _read_response(connection)
        assert result == {
            "schema_version": 1,
            "request_id": "invalid",
            "ok": False,
            "error": "not_authorized",
        }
        assert _pending(endpoint) == 0 and not context.calls


def test_handler_still_revalidates_identity_after_cached_acceptance(tmp_path):
    with _endpoint(tmp_path) as (endpoint, context):
        # Controlled context mutation is not supported host policy. It proves
        # that the early cache does not replace the handler's live guard.
        context.uid += 1
        with _connect(endpoint) as connection:
            assert _read_response(connection)["error"] == "not_authorized"
        assert not context.calls


@pytest.mark.parametrize("uid", [True, -1, 1 << 31, None])
def test_endpoint_rejects_invalid_immutable_uid_without_a_socket(tmp_path, uid):
    directory = tmp_path / "endpoint"
    directory.mkdir()
    with pytest.raises(ValueError, match="immutable peer UID"):
        _new_endpoint(directory, TransportContext(uid), "model")
    assert not (directory / "model.sock").exists()


def test_incomplete_active_frame_has_no_effect_and_keeps_original_read_bound(tmp_path):
    with _endpoint(tmp_path) as (endpoint, context):
        reading = threading.Event()

        def observed_read(connection, size, deadline):
            reading.set()
            return ModelBroker._read(connection, size, deadline)

        context._read = observed_read
        with _connect(endpoint) as connection:
            # One byte cannot complete the existing four-byte frame header.
            connection.sendall(b"\x00")
            assert reading.wait(2)
            endpoint.stop()
            assert endpoint.thread.is_alive()
            assert not context.calls
            connection.settimeout(6)
            result = _read_response(connection)
            assert result["error"] == "invalid_request"
            endpoint.thread.join(2)
            assert not endpoint.thread.is_alive()
            assert not context.calls


def test_service_lease_observation_waits_for_kernel_release(tmp_path):
    path = tmp_path / "service.lock"
    with path.open("a") as original:
        fcntl.flock(original, fcntl.LOCK_EX | fcntl.LOCK_NB)
        retained = os.dup(original.fileno())
        try:
            original.close()
            # A duplicate gives a deterministic closed-object/held-kernel-lease
            # state, without relying on the native close scheduling window.
            assert original.closed
            assert not _service_lease_available(path)
        finally:
            os.close(retained)
    assert _service_lease_available(path)


def test_model_service_lease_survives_close_until_active_http_handler_exits(
    tmp_path, monkeypatch
):
    entered = threading.Event()
    release = threading.Event()
    result = {}

    def held_provider(handler, requests):
        entered.set()
        assert release.wait(10), "held HTTP fixture was not released"
        response(handler, message())

    with provider(held_provider) as (url, requests):
        with broker_client(tmp_path, monkeypatch, url, uds=True) as (broker, old, _):
            endpoint = broker.endpoints[WORKER]
            client = BrokerClient(old.socket_path, timeout_seconds=20)

            def call():
                try:
                    result["reply"] = client.complete(MESSAGES, "closing-active")
                except BrokerError as error:
                    result["error"] = str(error)

            caller = threading.Thread(target=call, daemon=True)
            caller.start()
            try:
                assert entered.wait(2)
                with broker.connection() as db:
                    before = [
                        dict(row) for row in db.execute("SELECT * FROM calls")
                    ]
                assert len(before) == 1 and before[0]["status"] == "reserved"
                broker.close()
                assert endpoint.thread.is_alive()
                assert endpoint.server._worker.is_alive()
                with pytest.raises(ValueError, match="another model broker owns"):
                    ModelBroker(
                        broker.root,
                        broker.policies,
                        lambda _: 60,
                        peer_uids={SCOPE_KEY: os.getuid()},
                    )
                with broker.connection() as db:
                    assert [
                        dict(row) for row in db.execute("SELECT * FROM calls")
                    ] == before
                assert len(requests) == 1

                release.set()
                caller.join(3)
                endpoint.thread.join(3)
                assert not caller.is_alive() and not endpoint.thread.is_alive()
                assert "reply" not in result
                assert result["error"] == "model broker refused request: not_authorized"
                _eventually(
                    lambda: _service_lease_available(broker.root / "service.lock")
                )
                restored = ModelBroker(
                    broker.root,
                    broker.policies,
                    lambda _: 60,
                    peer_uids={SCOPE_KEY: os.getuid()},
                )
                try:
                    with restored.connection() as db:
                        calls = [dict(row) for row in db.execute("SELECT * FROM calls")]
                    assert len(calls) == len(requests) == 1
                    assert calls[0]["status"] == "complete"
                    assert calls[0]["reserved_tokens"] == before[0]["reserved_tokens"]
                    assert calls[0]["request_id"] == before[0]["request_id"]
                finally:
                    restored.close()
            finally:
                release.set()
                caller.join(10)


def test_child_release_callback_waits_for_active_control_handler(tmp_path):
    with _endpoint(tmp_path, "control") as (endpoint, context):
        adapter = ChildBroker(context, context)
        adapter.controls[WORKER] = endpoint
        released = threading.Event()
        with _connect(endpoint, "active") as connection:
            assert context.entered.wait(2)
            adapter.close(released.set)
            assert not released.is_set()
            assert endpoint.thread.is_alive() and endpoint.server._worker.is_alive()
            context.release.set()
            assert _read_response(connection)["handled"] == "active"
            assert released.wait(2)
            assert not endpoint.thread.is_alive()
            assert context.calls == ["active"]


def test_unexpected_handler_exit_is_a_readiness_failure(tmp_path, monkeypatch):
    with provider() as (url, requests):
        with broker_client(tmp_path, monkeypatch, url, uds=True) as (broker, _, _):
            endpoint = broker.endpoints[WORKER]

            def failed_handler(*args):
                raise SystemExit("explicit worker-failure fixture")

            monkeypatch.setattr(broker, "complete", failed_handler)
            with _connect(endpoint, "worker-failure") as connection:
                _closed(connection)
            endpoint.thread.join(2)
            assert not endpoint.thread.is_alive()
            assert not endpoint.stop_requested.is_set()
            with pytest.raises(BrokerDenied, match="model_transport_unavailable"):
                broker.check_ready()
            with broker.connection() as db:
                assert db.execute("SELECT COUNT(*) FROM calls").fetchone()[0] == 0
            assert not requests


@pytest.mark.parametrize("kind", ["model", "control"])
def test_owner_start_failure_removes_socket_and_closes_directory(
    tmp_path, monkeypatch, kind
):
    directory = tmp_path / "endpoint"
    directory.mkdir()
    opened = []
    real_open = os.open
    real_start = threading.Thread.start

    def recording_open(path, flags, *args, **kwargs):
        descriptor = real_open(path, flags, *args, **kwargs)
        if path == directory:
            opened.append(descriptor)
        return descriptor

    def fail_owner(thread):
        if thread.name in {"worker-model-broker", "root-child-control"}:
            raise RuntimeError("explicit owner-start failure")
        return real_start(thread)

    monkeypatch.setattr(os, "open", recording_open)
    monkeypatch.setattr(threading.Thread, "start", fail_owner)
    with pytest.raises(RuntimeError, match="owner-start failure"):
        _new_endpoint(directory, TransportContext(os.getuid()), kind)
    assert len(opened) == 1
    with pytest.raises(OSError):
        os.fstat(opened[0])
    assert not list(directory.iterdir())


def test_handler_start_failure_cannot_leave_ready_listener(tmp_path, monkeypatch):
    with provider() as (url, requests):
        with broker_client(tmp_path, monkeypatch, url, uds=True) as (broker, _, _):
            original = broker.endpoints[WORKER]
            original.stop()
            original.thread.join(2)
            assert not original.thread.is_alive()
            real_start = threading.Thread.start
            failures = []

            def fail_handler(thread):
                if thread.name == "worker-socket-handler":
                    raise RuntimeError("explicit handler-start failure")
                return real_start(thread)

            # Capture the owned background failure instead of printing it.
            monkeypatch.setattr(
                threading, "excepthook", lambda args: failures.append(args.exc_type)
            )
            monkeypatch.setattr(threading.Thread, "start", fail_handler)
            broker.prepare_worker(WORKER, SPEC)
            endpoint = broker.endpoints[WORKER]
            assert endpoint is not original
            endpoint.thread.join(2)
            assert not endpoint.thread.is_alive()
            assert not endpoint.server._worker.is_alive()
            assert not endpoint.stop_requested.is_set()
            assert failures == [RuntimeError]
            assert not endpoint.socket_path.exists()
            with pytest.raises(BrokerDenied, match="model_transport_unavailable"):
                broker.check_ready()
            assert not requests
