"""Mandatory actual Unix-socket identity and local-receipt qualification.

The host process represents one child UID. Its sibling endpoint expects another
UID and must reject it before parsing JSON. Docker tests cover the guest UIDs.
Authority/runtime fixtures never make this a canonical or provider trial.
"""

import json
import os
import socket
import struct
import threading
from types import SimpleNamespace

import pytest

from src.agent.child_outcome import OutcomeClient, OutcomeError
from src.worker.child_broker import ChildBroker
from src.worker.model_broker import ModelBroker
from tests.unit.test_child_outcome import outcome_supervisor
from tests.unit.test_child_supervisor import spawn


def exchange(path, payload=None, *, raw=None, allow_early_denial=False):
    with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(str(path))
        if payload is not None or raw is not None:
            encoded = raw if raw is not None else json.dumps(payload).encode()
            try:
                connection.sendall(struct.pack("!I", len(encoded)) + encoded)
            except BrokenPipeError:
                if not allow_early_denial:
                    raise
                # A foreign UID is rejected before payload parsing. Its peer
                # may close the read side first; the complete denial is required
                # below, and a write error alone never counts as a denial.
        frame = b""
        while len(frame) < 4:
            part = connection.recv(4 - len(frame))
            assert part, "outcome endpoint closed before its frame"
            frame += part
        size = struct.unpack("!I", frame)[0]
        assert 1 <= size <= 65536
        response = b""
        while len(response) < size:
            part = connection.recv(size - len(response))
            assert part, "outcome endpoint closed before its response"
            response += part
        return json.loads(response)


def test_real_child_outcome_socket_uid_schema_and_reconnect(tmp_path):
    supervisor, root, _, engine = outcome_supervisor(tmp_path, uid_start=os.getuid())
    model_root = tmp_path / "model-mount"
    (model_root / root.worker_id).mkdir(parents=True)
    model = SimpleNamespace(
        root=model_root,
        guard=threading.RLock(),
        closed=False,
        endpoints={},
        _read=ModelBroker._read,
        check_ready=lambda: None,
        peer_uid_for_worker=lambda _: 65532,
        complete_child=lambda *_: pytest.fail("outcome callback attempted inference"),
    )
    descriptors = []
    try:
        first = spawn(supervisor, root, "first")["child_id"]
        sibling = spawn(supervisor, root, "second")["child_id"]
        supervisor.endpoints = ChildBroker(supervisor, model)
        for child in supervisor.journal.children(root.worker_id):
            supervisor.endpoints.prepare_child(root, child)
        for child_id in (first, sibling):
            path = model_root / root.worker_id / "children" / child_id
            descriptors.append(os.open(path, os.O_RDONLY | os.O_DIRECTORY))
        own = f"/proc/self/fd/{descriptors[0]}/outcome.sock"
        foreign = f"/proc/self/fd/{descriptors[1]}/outcome.sock"
        assert exchange(foreign)["error"] == "not_authorized"
        for payload in (
            {
                "schema_version": 1,
                "request_id": "bad",
                "outcome": "completed",
                "summary": "",
                "actor": first,
            },
            {
                "schema_version": 1,
                "request_id": "bad",
                "outcome": "completed",
                "summary": "",
                "child_id": first,
            },
            {
                "schema_version": True,
                "request_id": "bad",
                "outcome": "completed",
                "summary": "",
            },
        ):
            assert exchange(own, payload)["error"] == "invalid_request"
        assert (
            exchange(
                own,
                raw=b'{"schema_version":1,"request_id":"one","request_id":"two","outcome":"completed","summary":""}',
            )["error"]
            == "invalid_request"
        )
        assert supervisor.journal.child(root.worker_id, first)["outcome_report"] is None
        before = list(supervisor.authority.events)
        client = OutcomeClient(own)
        first_receipt = client.report("needs_clarification", "Private λ question")
        payload = {
            "schema_version": 1,
            "request_id": client.request_key,
            "outcome": "needs_clarification",
            "summary": "Private λ question",
        }
        assert exchange(own, payload) == first_receipt
        assert (
            exchange(own, payload | {"request_id": "different"})["error"] == "conflict"
        )
        assert exchange(foreign, payload, allow_early_denial=True)["error"] == "not_authorized"
        assert supervisor.authority.events == before
        assert len(engine.created) == len(engine.started) == 4
        completed = threading.Event()
        supervisor.endpoints.close(completed.set)
        assert completed.wait(3)
        supervisor.endpoints = ChildBroker(supervisor, model)
        for child in supervisor.journal.children(root.worker_id):
            supervisor.endpoints.prepare_child(root, child)
        assert exchange(own, payload) == first_receipt
        with pytest.raises(OutcomeError):
            client.report("completed", "Changed claim")
        assert (
            supervisor.journal.child(root.worker_id, sibling)["outcome_report"] is None
        )
    finally:
        supervisor.close()
        for descriptor in descriptors:
            os.close(descriptor)


def test_explicit_foreign_probe_requires_denial_after_actual_early_read_shutdown(tmp_path, monkeypatch):
    real_socket, shut_read = socket.socket, socket.SHUT_RD
    response = {
        "schema_version": 1, "request_id": "invalid", "ok": False,
        "error": "not_authorized",
    }
    encoded = json.dumps(response).encode()
    frame = struct.pack("!I", len(encoded)) + encoded

    for allowed in (False, True):
        path = tmp_path / ("early-" + str(int(allowed)) + ".sock")
        listener = real_socket(socket.AF_UNIX, socket.SOCK_STREAM)
        listener.bind(str(path))
        listener.listen(1)
        listener.settimeout(3)
        ready, release = threading.Event(), threading.Event()
        errors, broken_writes = [], []

        def deny_before_body():
            try:
                connection, _ = listener.accept()
                with connection:
                    connection.settimeout(3)
                    connection.sendall(frame)
                    connection.shutdown(shut_read)
                    ready.set()
                    assert release.wait(3)
            except BaseException as error:
                errors.append(error)

        class PausedSocket(real_socket):
            def connect(self, address):
                super().connect(address)
                assert ready.wait(3)

            def sendall(self, value):
                try:
                    return super().sendall(value)
                except BrokenPipeError:
                    broken_writes.append(True)
                    raise

        peer = threading.Thread(target=deny_before_body)
        peer.start()
        try:
            # Replace this test module's constructor only. Both endpoints are
            # actual Unix sockets and BrokenPipeError comes from the real kernel.
            with monkeypatch.context() as patch:
                patch.setitem(exchange.__globals__, "socket", SimpleNamespace(
                    AF_UNIX=socket.AF_UNIX, SOCK_STREAM=socket.SOCK_STREAM,
                    socket=PausedSocket,
                ))
                if allowed:
                    assert exchange(path, {"untrusted": "body"}, allow_early_denial=True) == response
                else:
                    with pytest.raises(BrokenPipeError):
                        exchange(path, {"untrusted": "body"})
                assert broken_writes == [True]
        finally:
            release.set()
            peer.join(5)
            listener.close()
        assert not peer.is_alive() and not errors
