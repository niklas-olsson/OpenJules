"""Bounded wire and daemon lifecycle with an explicit socket substitution.

The real Unix fixture is retained for supported integration environments;
these deterministic tests do not claim Unix or Docker qualification.
"""
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import tempfile
import unittest
from unittest import mock

from tests.unit.review_native_fixture import archive_bytes, fixture, git
from tests.unit.review_native_daemon_fixture import MemoryDockerFixture, UnixDockerFixture
from src.worker.review_contract import ReviewError
from src.worker.review_github import OriginalHTTPReply, decode_object
from src.worker.review_native import ReviewNativeBackend, WireReader, demultiplex, HEADER_BYTES
from src.worker.standalone_review import ReviewOperation


class MemorySocket:
    def __init__(self, raw):
        self.raw = io.BytesIO(raw)
        self.maximum_read = 0
    def settimeout(self, value):
        if value <= 0:
            raise AssertionError("renewed/expired read")
    def recv(self, count):
        self.maximum_read = max(self.maximum_read, count)
        return self.raw.read(count)


class WireTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.claim, self.op, _, _ = fixture(Path(self.temp.name))

    def tearDown(self):
        self.temp.cleanup()

    def response(self, raw, maximum=16):
        effect = self.op.reserve("guest_api", response_bytes=maximum)
        connection = MemorySocket(raw)
        result = self.op.invoke(effect, lambda: WireReader(connection, self.op, effect).response(maximum))
        return result, effect, connection

    def test_fixed_length_and_chunked_bytes_are_bounded_and_not_acked(self):
        result, effect, connection = self.response(b"HTTP/1.1 200 OK\r\nContent-Length: 4\r\n\r\ndata")
        self.assertEqual(result, (200, b"data"))
        self.assertEqual(self.op.snapshot()["effects"][0]["response_bytes"], 4)
        self.assertFalse(self.op.snapshot()["effects"][0]["acknowledged"])
        self.assertLessEqual(connection.maximum_read, 16)
        result, _, _ = self.response(b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n2\r\nab\r\n2\r\ncd\r\n0\r\n\r\n")
        self.assertEqual(result[1], b"abcd")

    def test_oversized_length_refuses_before_body_read_or_accumulation(self):
        connection = MemorySocket(b"HTTP/1.1 200 OK\r\nContent-Length: 17\r\n\r\n" + b"x" * 17)
        effect = self.op.reserve("guest_api", response_bytes=16)
        with self.assertRaises(ReviewError):
            self.op.invoke(effect, lambda: WireReader(connection, self.op, effect).response(16))
        self.assertEqual(connection.raw.read(), b"x" * 17)
        self.assertEqual(self.op.snapshot()["effects"][0]["response_bytes"], 0)

    def test_header_and_framing_bounds_duplicate_length_and_incomplete_body(self):
        inputs = [b"HTTP/1.1 200 OK\r\nX: " + b"x" * HEADER_BYTES + b"\r\n\r\n",
                  b"HTTP/1.1 200 OK\r\nContent-Length: 1\r\nContent-Length: 1\r\n\r\nx",
                  b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nx",
                  b"HTTP/1.1 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n10000000\r\n",
                  b"HTTP/1.1 200 OK\r\nContent-Encoding: gzip\r\nContent-Length: 0\r\n\r\n"]
        for raw in inputs:
            _, operation, _, _ = fixture(Path(tempfile.mkdtemp(dir=self.temp.name)))
            effect = operation.reserve("guest_api", response_bytes=16)
            with self.assertRaises(ReviewError):
                operation.invoke(effect, lambda: WireReader(MemorySocket(raw), operation, effect).response(16))
            self.assertFalse(operation.snapshot()["effects"][0]["acknowledged"])

    def test_exec_demultiplex_refuses_unbounded_or_incomplete_frames(self):
        self.assertEqual(demultiplex(b"\x01\0\0\0\0\0\0\x02ok", 2), b"ok")
        for raw in (b"\x01\0\0\0\xff\xff\xff\xff", b"\x03\0\0\0\0\0\0\0", b"short"):
            with self.assertRaises(ReviewError):
                demultiplex(raw, 2)

    def test_json_duplicate_depth_nonfinite_and_invalid_utf8_refuse(self):
        for raw in (b'{"a":1,"a":2}', b'{"n":NaN}', b'{"n":1e999}', b'{"x":"\xff"}',
                    b'{"a":' + b'[' * 34 + b'0' + b']' * 34 + b'}'):
            with self.assertRaises(ReviewError):
                decode_object(raw)

    def test_validated_http_reply_cannot_join_after_original_effect_deadline(self):
        now = [0.0]
        op = ReviewOperation(replace(self.claim, started_at=0.0), clock=lambda: now[0])
        effect = op.reserve("guest_api")
        op.invoke(effect, lambda: None)
        op.observe(effect, "closed", data={"local_closed": True})
        reply = OriginalHTTPReply(200, b"{}", effect)
        now[0] = effect.deadline + .001
        with self.assertRaises(ReviewError) as caught:
            reply.acknowledge(op)
        self.assertEqual(caught.exception.code, "deadline_exhausted")
        self.assertFalse(op.snapshot()["effects"][0]["acknowledged"])
        self.assertTrue(op.snapshot()["effects"][0]["outcome_unknown"])


class ControlledDaemonTests(unittest.TestCase):
    daemon_factory = MemoryDockerFixture

    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.claim, self.op, self.saved, self.source_path = fixture(self.root)
        self.backend = ReviewNativeBackend(self.claim)
        self.backend.original_checked = True
        self.source = self.backend.prepare_source(self.op)
        (self.source_path / "hello.txt").write_text("corrected\n")
        self.patch = git(self.source_path, "diff", "--binary", "--full-index")
        self.daemon = self.daemon_factory(self.root / "docker.sock", self.claim.profile.document["guest"]["image"], archive_bytes(self.patch))

    def tearDown(self):
        if not self.backend.retiring:
            self.backend.retire(self.op)
        self.daemon.close()
        self.assertFalse(self.daemon.errors)
        self.temp.cleanup()

    def test_original_offline_guest_capture_compose_and_exact_six_cleanup_calls(self):
        guest = self.backend.create_guest(self.op, self.source)
        self.op.note("guest", {"retained": True})
        observed = self.backend.execute(self.op, guest, "printf selected")
        self.assertEqual(observed.exit_code, 0)
        self.assertTrue(observed.exchange_id.startswith("exec_"))
        capture = self.backend.stop_and_capture(self.op, guest)
        candidate = self.backend.compose(self.op, self.source, capture)
        self.assertEqual(git(candidate.handle.repository, "show", candidate.commit_sha + ":hello.txt"), b"corrected\n")
        self.backend.retire(self.op)
        result = self.op.snapshot()
        self.assertEqual(result["counters"]["guest_api_cleanup"], 6)
        self.assertEqual(result["counters"]["guest_api"], len(self.daemon.requests))
        self.assertEqual(result["counters"]["exec"], 3)
        self.assertTrue(result["facts"]["capture"]["durable"])
        self.assertEqual(result["facts"]["capture"]["container_id"], self.daemon.container_id)
        self.assertTrue(result["facts"]["cleanup"]["container_removed"])
        self.assertTrue(result["facts"]["cleanup"]["volume_removed"])
        self.assertFalse(result["facts"]["cleanup"]["resources_retained"])
        self.assertFalse(result["facts"]["guest"]["retained"])
        create = self.daemon.container
        self.assertEqual(create["User"], "1000:1000")
        self.assertEqual(create["HostConfig"]["NetworkMode"], "none")
        self.assertEqual(create["HostConfig"]["LogConfig"]["Type"], "none")
        self.assertEqual(create["Healthcheck"], {"Test": ["NONE"]})
        self.assertNotIn(self.claim.credentials.forge["token"].encode(), b"".join(row["body"] for row in self.daemon.requests))
        self.assertTrue(all(row["path"].startswith("/v1.45/") for row in self.daemon.requests))
        self.assertFalse(any("/version" in row["path"] or "/images/create" in row["path"] for row in self.daemon.requests))
        self.assertTrue(all(row["closed"] for row in result["effects"]))

    def test_unknown_stop_is_not_retried_or_promoted_by_later_stopped_observation(self):
        guest = self.backend.create_guest(self.op, self.source)
        def original_stop(request):
            if request["path"].endswith("/stop?t=0"):
                self.daemon.running = False
                return "DROP"
        self.daemon.override = original_stop
        with self.assertRaises(ReviewError):
            self.backend.stop_and_capture(self.op, guest)
        self.backend.retire(self.op)
        self.assertEqual(sum(row["path"].endswith("/stop?t=0") for row in self.daemon.requests), 1)
        self.assertIsNone(self.backend.capture)
        self.assertFalse(any(row["method"] == "DELETE" for row in self.daemon.requests))
        result = self.op.snapshot()
        self.assertTrue(result["facts"]["guest"]["stopped"])
        self.assertTrue(result["facts"]["cleanup"]["resources_retained"])
        self.assertEqual(result["status"], "unknown")

    def test_malformed_original_image_reply_is_returned_closed_unacknowledged(self):
        self.daemon.override = lambda request: (200, b'{"Id":')
        with self.assertRaises(ReviewError):
            self.backend.create_guest(self.op, self.source)
        effect = self.op.snapshot()["effects"][-1]
        self.assertEqual(effect["kind"], "guest_api")
        self.assertTrue(effect["returned"])
        self.assertTrue(effect["closed"])
        self.assertFalse(effect["acknowledged"])
        self.assertTrue(effect["outcome_unknown"])
        self.assertEqual(len(self.daemon.requests), 1)

    def test_http_500_and_redirect_never_count_as_semantic_ack_or_follow(self):
        self.daemon.override = lambda request: (500, {"message": "private diagnostic"})
        with self.assertRaises(ReviewError):
            self.backend.create_guest(self.op, self.source)
        self.assertEqual(len(self.daemon.requests), 1)
        self.assertFalse(self.op.snapshot()["effects"][-1]["acknowledged"])
        self.assertNotIn("private diagnostic", json.dumps(self.op.snapshot()))

    def test_redirect_response_does_not_follow_or_ack(self):
        self.daemon.override = lambda request: b"HTTP/1.1 302 Found\r\nLocation: http://unselected.invalid/payload\r\nContent-Length: 2\r\n\r\n{}"
        with self.assertRaises(ReviewError):
            self.backend.create_guest(self.op, self.source)
        self.assertEqual(len(self.daemon.requests), 1)
        self.assertFalse(self.op.snapshot()["effects"][-1]["acknowledged"])

    def test_original_create_lost_reply_keeps_unknown_identity_without_recreation(self):
        def create(request):
            if request["path"].startswith("/v1.45/containers/create?"):
                self.daemon.container = json.loads(request["body"])
                return "DROP"
        self.daemon.override = create
        with self.assertRaises(ReviewError):
            self.backend.create_guest(self.op, self.source)
        self.backend.retire(self.op)
        result = self.op.snapshot()
        self.assertTrue(result["facts"]["guest"]["create_entered"])
        self.assertFalse(result["facts"]["guest"]["create_acknowledged"])
        self.assertNotIn("container_id", result["facts"]["guest"])
        self.assertTrue(result["facts"]["cleanup"]["resources_retained"])
        self.assertEqual(sum("/containers/create?" in row["path"] for row in self.daemon.requests), 1)
        self.assertFalse(any(row["method"] == "DELETE" for row in self.daemon.requests))

    def test_expired_total_cutoff_never_dispatches_new_cleanup_request(self):
        self.backend.create_guest(self.op, self.source)
        original = len(self.daemon.requests)
        with mock.patch.object(self.op, "_clock", return_value=self.op.total_deadline + .001):
            self.backend.retire(self.op)
        self.assertEqual(len(self.daemon.requests), original)
        self.assertTrue(self.op.snapshot()["facts"]["cleanup"]["resources_retained"])
        self.assertTrue(all(row["closed"] for row in self.backend.connections))

    def test_original_cleanup_survives_productive_revocation_without_credentials(self):
        self.backend.create_guest(self.op, self.source)
        def revoked():
            raise ValueError("productive epoch revoked")
        object.__setattr__(self.claim, "validate_productive", revoked)
        with self.assertRaises(ReviewError):
            self.op.check()
        previous = len(self.daemon.requests)
        with mock.patch.object(self.claim.credentials, "validate_epoch", side_effect=AssertionError("cleanup requested productive credentials")) as credential:
            self.backend.retire(self.op)
        credential.assert_not_called()
        cleanup = self.daemon.requests[previous:]
        self.assertEqual(len(cleanup), 6)
        self.assertTrue(cleanup[0]["path"].endswith("/stop?t=0"))
        self.assertEqual(self.op.snapshot()["first_failure"]["code"], "authority_changed")
        self.assertFalse(self.op.snapshot()["facts"]["cleanup"]["resources_retained"])

    def test_revocation_after_original_http_entry_retains_unknown_and_closed(self):
        revoked = [False]
        def validate():
            if revoked[0]:
                raise ValueError("revoked fixture")
        object.__setattr__(self.claim, "validate_productive", validate)
        self.daemon.before_response = lambda request, response: revoked.__setitem__(0, True)
        with self.assertRaises(ReviewError) as caught:
            self.backend.create_guest(self.op, self.source)
        self.assertEqual(caught.exception.code, "authority_changed")
        effect = self.op.snapshot()["effects"][-1]
        self.assertTrue(effect["entered"])
        self.assertTrue(effect["returned"])
        self.assertTrue(effect["closed"])
        self.assertTrue(effect["outcome_unknown"])
        self.assertFalse(effect["acknowledged"])
        self.assertEqual(len(self.daemon.requests), 1)

    def test_connect_revocation_prevents_first_request_bytes(self):
        if self.daemon_factory is not MemoryDockerFixture:
            self.skipTest("controlled synchronous connect refusal is exercised by the explicit socket fixture")
        revoked = [False]
        def validate():
            if revoked[0]:
                raise ValueError("revoked after connect")
        object.__setattr__(self.claim, "validate_productive", validate)
        original = self.daemon.socket
        def socket(*args):
            connection = original(*args)
            connect = connection.connect
            def controlled(endpoint):
                connect(endpoint)
                revoked[0] = True
            connection.connect = controlled
            return connection
        with mock.patch("src.worker.review_native.socket.socket", side_effect=socket):
            with self.assertRaises(ReviewError):
                self.backend.create_guest(self.op, self.source)
        self.assertEqual(len(self.daemon.connections), 1)
        self.assertEqual(self.daemon.connections[0].request, b"")
        self.assertFalse(self.backend.connections[-1]["request_entered"])
        self.assertTrue(self.backend.connections[-1]["closed"])
        self.assertEqual(self.op.snapshot()["first_failure"]["code"], "authority_changed")

    def test_prefix_write_revocation_prevents_body_and_retains_partial_entry(self):
        if self.daemon_factory is not MemoryDockerFixture:
            self.skipTest("controlled partial-write refusal is exercised by the explicit socket fixture")
        revoked = [False]
        def validate():
            if revoked[0]:
                raise ValueError("revoked after original prefix")
        object.__setattr__(self.claim, "validate_productive", validate)
        original = self.daemon.socket
        def socket(*args):
            connection = original(*args)
            send = connection.sendall
            def controlled(raw):
                send(raw)
                if raw.startswith(b"POST "):
                    revoked[0] = True
            connection.sendall = controlled
            return connection
        with mock.patch("src.worker.review_native.socket.socket", side_effect=socket):
            with self.assertRaises(ReviewError):
                self.backend.create_guest(self.op, self.source)
        prefix = bytes(self.daemon.connections[-1].request)
        self.assertTrue(prefix.startswith(b"POST /v1.45/volumes/create "))
        self.assertTrue(prefix.endswith(b"\r\n\r\n"))
        self.assertTrue(self.backend.connections[-1]["request_entered"])
        self.assertTrue(self.backend.connections[-1]["closed"])
        self.assertTrue(self.op.snapshot()["effects"][-1]["outcome_unknown"])
        self.assertFalse(self.op.snapshot()["effects"][-1]["acknowledged"])

    def test_image_with_undeclared_inherited_env_is_refused_before_creation(self):
        self.daemon.override = lambda request: (200, {"Id": self.daemon.image,
            "Config": {"Env": ["PYTHON_VERSION=3.12.0"], "Volumes": None}})
        with self.assertRaises(ReviewError):
            self.backend.create_guest(self.op, self.source)
        self.assertEqual(len(self.daemon.requests), 1)
        self.assertIsNone(self.backend.original_guest)

    def test_reconstructed_guest_handle_cannot_execute_or_allocate_again(self):
        guest = self.backend.create_guest(self.op, self.source)
        previous = len(self.daemon.requests)
        with self.assertRaises(ReviewError):
            self.backend.execute(self.op, replace(guest), "true")
        self.assertEqual(len(self.daemon.requests), previous)

    def test_same_counted_daemon_deadline_is_not_renewed_for_exec_children(self):
        guest = self.backend.create_guest(self.op, self.source)
        self.backend.execute(self.op, guest, "true")
        effects = self.op.snapshot()["effects"]
        logical = next(row for row in reversed(effects) if row["kind"] == "exec")
        children = [row for row in effects if row["id"] > logical["id"]]
        self.assertEqual(len(children), 3)
        self.assertTrue(all(row["deadline_ms"] <= logical["deadline_ms"] for row in children))
        self.assertTrue(all(row["kind"] == "guest_api" for row in children))


@unittest.skipUnless(os.environ.get("OPENJULES_REVIEW_UNIX_TESTS") == "1", "real Unix transport requires explicit supported test environment")
class RealUnixDaemonTests(ControlledDaemonTests):
    """The same contract through actual local Unix sockets when CI enables it.

    Explicit enablement never converts an unavailable socket into a skip.
    """
    daemon_factory = UnixDockerFixture
    # These two tests deliberately inject synchronous socket method behavior.
    # Their memory-fixture coverage is separate from the real transport suite.
    test_connect_revocation_prevents_first_request_bytes = None
    test_prefix_write_revocation_prevents_body_and_retains_partial_entry = None


if __name__ == "__main__":
    unittest.main()
