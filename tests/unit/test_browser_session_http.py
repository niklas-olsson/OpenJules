"""Real interlock/auth composition through injected ASGI and client fixtures.

No listener, TLS connection, browser, website or model is started. The optional
Node fixture exercises the actual client model with deterministic fetch replies;
it does not qualify rendering or a real user journey.
"""

import asyncio
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch

from src.browser_session.control import SessionControl
from src.browser_session.http_app import HTTPBounds, SessionHTTP
from src.browser_session.pairing import PairingBroker
from src.browser_session.types import Limits, SessionDenied, SessionSpec
from tests.unit.test_browser_session_control import Clock, FakeAdapter


ORIGIN = "https://control.example:8443"


class HTTPTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name)
        self.parent.chmod(0o700)
        self.clock = Clock()
        self.adapter = FakeAdapter(self.clock)
        self.spec = SessionSpec("session", "context", "target", "document", "driver", "human",
            ("https://one.example", "https://two.example"), ("price",), self.clock.wall + 300_000,
            self.clock.wall + 600_000, Limits(action_timeout_ms=30, fence_timeout_ms=30, stop_timeout_ms=30,
                                             frame_interval_ms=1))
        self.core = SessionControl.create(self.parent / "state", self.spec, self.adapter, self.clock)
        self.adapter.core = self.core
        self.tokens = {
            "driver": self.core.issue_grant("driver", {"observe": self.clock.wall + 30_000, "control": self.clock.wall + 30_000}),
            "human": self.core.issue_grant("human", {"observe": self.clock.wall + 1000, "control": self.clock.wall + 1000,
                                                     "stop": self.clock.wall + 10_000}),
            "observer": self.core.issue_grant("observer", {"observe": self.clock.wall + 30_000})}
        self.core.publish_observation(self.adapter.observation())
        self.broker = PairingBroker(self.core, ORIGIN, clock=self.clock)
        self.notice = Mock()
        self.app = SessionHTTP(self.core, self.broker, ORIGIN, notify_pending=self.notice)
        self.aliases, self.csrf = {}, {}

    async def asyncTearDown(self):
        tasks = list(self.core._tasks.values()) + [self.core._transition_task, self.core._stop_task]
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()  # Deterministic fixture cleanup, never native teardown evidence.
        await asyncio.sleep(0)
        self.core.close()
        self.temporary.cleanup()

    async def request(self, method, path, *, actor=None, value=None, raw=None, headers=None,
                      scheme="https", query=b"", events=None, sender=None, receiver=None, app=None):
        content = json.dumps(value).encode() if raw is None and value is not None else (raw or b"")
        selected = [(b"host", b"control.example:8443")]
        if method == "POST":
            selected += [(b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
                         (b"content-length", str(len(content)).encode())]
        else:
            selected.append((b"sec-fetch-site", b"same-origin"))
        if actor is not None:
            selected.append((b"cookie", self.aliases[actor].encode()))
            if method == "POST":
                selected.append((b"x-csrf-token", self.csrf[actor].encode()))
        if headers is not None:
            selected = headers
        scope = {"type": "http", "http_version": "1.1", "scheme": scheme, "method": method,
                 "path": path, "raw_path": path.encode(), "query_string": query, "headers": selected}
        pending = iter(events or [{"type": "http.request", "body": content, "more_body": False}])
        async def receive():
            if receiver is not None:
                return await receiver()
            return next(pending)
        messages = []
        async def send(message):
            if sender is not None:
                await sender(message)
            messages.append(message)
        await (app or self.app)(scope, receive, send)
        if not messages:
            return None, {}, b""
        self.assertEqual(messages[0]["type"], "http.response.start")
        result_headers = {key.decode(): value.decode() for key, value in messages[0]["headers"]}
        body = b"".join(message.get("body", b"") for message in messages[1:])
        return messages[0]["status"], result_headers, body

    async def pair(self, actor, *, code=None):
        right = "stop" if actor == "human" else "observe"
        code = code or self.broker.issue_code(self.tokens[actor], self.clock.wall + 500, binding_right=right)
        status, headers, raw = await self.request("POST", "/pair", value={"code": code})
        self.assertEqual(status, 200)
        self.aliases[actor] = headers["set-cookie"].split(";", 1)[0]
        self.csrf[actor] = json.loads(raw)["csrf_token"]
        return code, raw

    async def action(self, actor="driver", key="original-action"):
        status, _, raw = await self.request("GET", "/observation", actor=actor)
        self.assertEqual(status, 200)
        view = json.loads(raw)
        return {name: view[name] for name in ("session_id", "context_id", "target_id", "control_generation", "document_id", "document_generation")} | {
            "operation_id": key, "observation_id": view["frame"]["observation_id"], "action": "click",
            "parameters": {"x": 12, "y": 34, "button": "left"}}

    async def test_closed_static_client_and_security_headers_contain_no_authority(self):
        status, headers, raw = await self.request("GET", "/")
        self.assertEqual(status, 200)
        self.assertIn(b"Stop session", raw)
        self.assertEqual(headers["cache-control"], "no-store")
        self.assertIn("frame-ancestors 'none'", headers["content-security-policy"])
        self.assertNotIn("access-control-allow-origin", headers)
        for path in ("/create", "/grant", "/resume", "/cdp", "/client/../control.py", "/results/../../session.json"):
            self.assertEqual((await self.request("GET", path))[0], 404)
        self.assertEqual(self.adapter.executions + self.adapter.fences + self.adapter.stops, [])
        self.notice.assert_not_called()

    async def test_pairing_and_reload_retain_scoped_cookie_nonce_and_original_expiry(self):
        code, raw = await self.pair("human")
        self.assertNotIn(self.tokens["human"].encode(), raw)
        self.assertNotIn(code.encode(), raw)
        status, _, first = await self.request("GET", "/session", actor="human")
        self.assertEqual(status, 200)
        view = json.loads(first)
        self.assertEqual(view["csrf_token"], self.csrf["human"])
        self.assertEqual(view["binding_right"], "stop")
        self.assertEqual(set(view["rights"]), {"observe", "control", "stop"})
        self.clock.advance(1001)
        status, _, last = await self.request("GET", "/session", actor="human")
        self.assertEqual(status, 200)
        refreshed = json.loads(last)
        self.assertEqual(refreshed["cookie_expires_at_ms"], view["cookie_expires_at_ms"])
        self.assertEqual(refreshed["csrf_token"], view["csrf_token"])
        self.assertFalse(refreshed["rights"]["observe"]["available"])
        self.assertTrue(refreshed["rights"]["stop"]["available"])
        self.assertEqual((await self.request("POST", "/pair", value={"code": code}))[0], 403)

    async def test_invalid_context_origin_duplicate_headers_and_forwarded_tls_never_pair(self):
        code = self.broker.issue_code(self.tokens["human"], self.clock.wall + 500, binding_right="stop")
        raw = json.dumps({"code": code}).encode()
        headers = [(b"host", b"control.example:8443"), (b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
                   (b"content-length", str(len(raw)).encode())]
        cases = [headers + [(b"Host", b"foreign.example")], headers + [(b"Origin", ORIGIN.encode())],
                 headers + [(b"content-length", str(len(raw)).encode())],
                 [(name, b"https://foreign.example" if name == b"origin" else value) for name, value in headers]]
        for values in cases:
            self.assertIn((await self.request("POST", "/pair", raw=raw, headers=values))[0], {400, 403})
        status, _, _ = await self.request("POST", "/pair", raw=raw, headers=headers + [(b"x-forwarded-proto", b"https")], scheme="http")
        self.assertEqual(status, 400)
        self.assertEqual((await self.request("POST", "/pair", raw=raw, query=b"code=not-allowed"))[0], 400)
        await self.pair("human", code=code)  # Denied requests did not consume it.

    async def test_closed_bodies_cannot_choose_rights_or_enlarge_pairing(self):
        code = self.broker.issue_code(self.tokens["observer"], self.clock.wall + 500)
        for raw in (json.dumps({"code": code, "right": "stop"}).encode(), b'{"code":"a","code":"b"}', b"[true]", b"x" * 16385):
            self.assertIn((await self.request("POST", "/pair", raw=raw))[0], {400, 403})
        await self.pair("observer", code=code)
        self.assertEqual((await self.request("POST", "/stop", actor="observer", value={"operation_id": "no-stop"}))[0], 403)
        self.assertEqual((await self.request("POST", "/takeover", actor="observer", value={"operation_id": "no-turn", "control_generation": 0}))[0], 403)
        self.assertEqual(self.adapter.stops + self.adapter.fences, [])

    async def test_durable_action_notifies_only_the_host_and_public_ack_hides_tickets(self):
        await self.pair("driver")
        value = await self.action()
        status, _, raw = await self.request("POST", "/actions", actor="driver", value=value)
        self.assertEqual(status, 202)
        reply = json.loads(raw)
        self.assertEqual(reply["state"], "queued")
        self.assertEqual(set(reply), {"schema_version", "operation_id", "actor_id", "kind", "state", "control_generation", "audit_persisted", "dispatch_notice"})
        for secret in (self.tokens["driver"], hashlib.sha256(self.tokens["driver"].encode()).hexdigest(), "ticket", "parameters", "deadline"):
            self.assertNotIn(secret.encode(), raw)
        self.notice.assert_called_once_with()
        self.assertEqual(self.adapter.executions, [])
        await self.core.execute_next()  # The independently owned host dispatcher.
        self.assertEqual(len(self.adapter.executions), 1)
        status, _, raw = await self.request("GET", "/operations/original-action", actor="driver")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "applied")
        self.assertEqual((await self.request("GET", "/operations/extra/original-action", actor="driver"))[0], 403)

    async def test_notification_failure_keeps_original_queued_intent_and_never_dispatches(self):
        await self.pair("driver")
        self.notice.side_effect = RuntimeError("private token must not leak")
        status, _, raw = await self.request("POST", "/actions", actor="driver", value=await self.action())
        self.assertEqual(status, 202)
        self.assertEqual(json.loads(raw)["dispatch_notice"], "unknown")
        self.assertNotIn(b"private token", raw)
        self.assertEqual(self.core.operation(self.tokens["driver"], "original-action")["state"], "queued")
        self.assertEqual(self.adapter.executions, [])

    async def test_real_gateway_takeover_correction_and_handback_keep_one_original_target(self):
        await self.pair("driver")
        await self.pair("human")
        queued = await self.action()
        await self.request("POST", "/actions", actor="driver", value=queued)
        status, _, raw = await self.request("POST", "/takeover", actor="human",
            value={"operation_id": "take-original", "control_generation": 0})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "applied")
        self.assertEqual(self.core.operation(self.tokens["driver"], "original-action")["state"], "not_applied")
        self.assertEqual(self.adapter.executions, [])
        correction = await self.action("human", "human-correction")
        correction.update(action="correction", parameters={"text": "Compare the corrected fixture filter."})
        self.assertEqual((await self.request("POST", "/actions", actor="human", value=correction))[0], 202)
        await self.core.execute_next()
        status, _, raw = await self.request("GET", "/observation", actor="human")
        self.assertEqual(status, 200)
        view = json.loads(raw)
        self.assertEqual(view["mode"], "human")
        self.assertEqual(view["target_id"], "target")
        self.assertEqual(view["corrections"], [{"operation_id": "human-correction", "actor_id": "human",
            "text": "Compare the corrected fixture filter.", "generation": 1}])
        status, _, raw = await self.request("POST", "/handback", actor="human",
            value={"operation_id": "return-original", "control_generation": 1, "observation_id": view["frame"]["observation_id"]})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "applied")
        self.assertEqual(self.core.observe(self.tokens["driver"])["mode"], "driver")
        self.assertEqual(self.core.identity()["control_generation"], 2)
        stale = correction | {"operation_id": "stale-human-input"}
        self.assertEqual((await self.request("POST", "/actions", actor="human", value=stale))[0], 403)
        self.assertEqual(len(self.adapter.fences), 2)
        self.assertEqual({ticket.target_id for ticket in self.adapter.fences}, {"target"})
        self.assertEqual(self.adapter.executions, [])

    async def test_lost_response_leaves_original_key_readable_without_second_action(self):
        await self.pair("driver")
        async def lost(_):
            raise ConnectionError("private transport detail")
        result = await self.request("POST", "/actions", actor="driver", value=await self.action(), sender=lost)
        self.assertIsNone(result[0])
        await self.core.execute_next()
        status, _, raw = await self.request("GET", "/operations/original-action", actor="driver")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "applied")
        self.assertEqual(len(self.adapter.executions), 1)
        self.assertEqual(self.app._active, 0)

    async def test_expired_observe_does_not_consume_owner_stop_or_stop_status(self):
        await self.pair("human")
        self.clock.advance(1001)
        self.assertEqual((await self.request("GET", "/observation", actor="human"))[0], 403)
        status, _, raw = await self.request("POST", "/stop", actor="human", value={"operation_id": "owner-stop"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "confirmed")
        status, _, raw = await self.request("GET", "/stop-operations/owner-stop", actor="human")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "confirmed")
        self.assertEqual((await self.request("GET", "/operations/owner-stop", actor="human"))[0], 403)
        self.assertEqual((await self.request("GET", "/results/result.json", actor="human"))[0], 403)
        self.assertEqual(len(self.adapter.stops), 1)

    async def test_stop_only_read_cannot_observe_an_ordinary_operation_or_create_stop(self):
        await self.pair("driver")
        await self.pair("human")
        await self.request("POST", "/actions", actor="driver", value=await self.action())
        for key in ("original-action", "absent-stop"):
            self.assertEqual((await self.request("GET", "/stop-operations/" + key, actor="human"))[0], 403)
        self.assertEqual(self.adapter.stops, [])
        self.assertEqual(self.core.operation(self.tokens["driver"], "original-action")["state"], "queued")

    async def test_original_stop_status_tracks_late_receipt_without_observe_or_reissue(self):
        await self.pair("human")
        self.clock.advance(1001)
        self.adapter.stop_gate = asyncio.Event()
        status, _, raw = await self.request("POST", "/stop", actor="human", value={"operation_id": "late-stop"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "unknown")
        self.assertFalse(self.core._stop_task.done())
        self.adapter.stop_gate.set()
        await self.core._stop_task
        await asyncio.sleep(0)
        status, _, raw = await self.request("GET", "/stop-operations/late-stop", actor="human")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "confirmed")
        self.assertEqual(len(self.adapter.stops), 1)

    async def test_concurrent_http_pairing_consumes_one_original_code(self):
        code = self.broker.issue_code(self.tokens["observer"], self.clock.wall + 500)
        results = await asyncio.gather(*(self.request("POST", "/pair", value={"code": code}) for _ in range(2)))
        self.assertEqual(sorted(value[0] for value in results), [200, 403])
        self.assertEqual(sum("set-cookie" in value[1] for value in results), 1)
        self.assertEqual(self.adapter.executions + self.adapter.fences + self.adapter.stops, [])

    async def test_stop_and_reload_have_independent_capacity_after_ordinary_budget(self):
        await self.pair("human")
        self.app._requests = self.app._bounds.ordinary_requests
        self.app._bytes = self.app._bounds.ordinary_response_bytes
        self.app._active = self.app._bounds.ordinary_concurrency
        self.assertEqual((await self.request("GET", "/observation", actor="human"))[0], 429)
        status, _, raw = await self.request("GET", "/session", actor="human")
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["csrf_token"], self.csrf["human"])
        status, _, raw = await self.request("POST", "/stop", actor="human", value={"operation_id": "reserved-stop"})
        self.assertEqual(status, 200)
        self.assertEqual(json.loads(raw)["state"], "confirmed")
        self.assertEqual((await self.request("GET", "/stop-operations/reserved-stop", actor="human"))[0], 200)
        self.assertEqual(self.app._stop_active, 0)

    async def test_slow_observer_does_not_queue_frames_or_stall_owner_stop(self):
        await self.pair("observer")
        await self.pair("human")
        gate, entered = asyncio.Event(), asyncio.Event()
        async def slow(message):
            if message["type"] == "http.response.body":
                entered.set()
                await gate.wait()
        viewing = asyncio.create_task(self.request("GET", "/observation", actor="observer", sender=slow))
        await entered.wait()
        for _ in range(3):
            self.clock.advance(2)
            self.core.publish_observation(self.adapter.observation())
        self.assertEqual(self.core._frame[0]["sequence"], 4)
        self.assertEqual((await self.request("POST", "/stop", actor="human", value={"operation_id": "stop-with-slow-view"}))[0], 200)
        gate.set()
        await viewing
        self.assertEqual(len(self.adapter.stops), 1)
        self.assertEqual(self.app._active, 0)

    async def test_slow_observer_session_reply_cannot_occupy_owner_stop_capacity(self):
        await self.pair("observer")
        await self.pair("human")
        gate, entered = asyncio.Event(), asyncio.Event()
        async def slow(message):
            if message["type"] == "http.response.body":
                entered.set()
                await gate.wait()
        viewing = asyncio.create_task(self.request("GET", "/session", actor="observer", sender=slow))
        await entered.wait()
        self.assertEqual(self.app._active, 1)
        self.assertEqual(self.app._stop_active, 0)
        self.assertEqual(self.app._owner_read_active, 0)
        self.assertEqual((await self.request("POST", "/stop", actor="human", value={"operation_id": "stop-beside-session-read"}))[0], 200)
        gate.set()
        await viewing
        self.assertEqual(len(self.adapter.stops), 1)

    async def test_unauthenticated_slow_body_cannot_reserve_stop_by_route_name(self):
        await self.pair("human")
        gate, entered = asyncio.Event(), asyncio.Event()
        async def slow_receive():
            entered.set()
            await gate.wait()
            return {"type": "http.request", "body": b"", "more_body": False}
        anonymous = asyncio.create_task(self.request("GET", "/session", receiver=slow_receive))
        await entered.wait()
        self.assertEqual(self.app._stop_active, 0)
        self.assertEqual((await self.request("POST", "/stop", actor="human", value={"operation_id": "stop-beside-anonymous-body"}))[0], 200)
        gate.set()
        self.assertEqual((await anonymous)[0], 403)
        self.assertEqual(len(self.adapter.stops), 1)

    async def test_owner_read_quota_and_slow_owner_reload_leave_a_stop_mutation_reserve(self):
        await self.pair("human")
        gate, entered = asyncio.Event(), asyncio.Event()
        async def slow(message):
            if message["type"] == "http.response.body":
                entered.set()
                await gate.wait()
        reading = asyncio.create_task(self.request("GET", "/session", actor="human", sender=slow))
        await entered.wait()
        self.assertEqual(self.app._owner_read_active, 1)
        self.assertEqual(self.app._stop_active, 0)
        self.app._owner_read_requests = self.app._bounds.owner_read_requests
        self.app._owner_read_bytes = self.app._bounds.owner_read_response_bytes
        self.assertEqual((await self.request("POST", "/stop", actor="human", value={"operation_id": "stop-after-owner-reads"}))[0], 200)
        gate.set()
        await reading
        self.assertEqual(self.app._stop_requests, 1)
        self.assertEqual(len(self.adapter.stops), 1)

    async def test_view_disconnect_and_asgi_shutdown_leave_host_lifetime_owned(self):
        result = await self.request("GET", "/", events=[{"type": "http.disconnect"}])
        self.assertIsNone(result[0])
        self.assertEqual(self.app._active, 0)
        pending = iter([{"type": "lifespan.startup"}, {"type": "lifespan.shutdown"}])
        sent = []
        async def receive(): return next(pending)
        async def send(value): sent.append(value)
        await self.app({"type": "lifespan"}, receive, send)
        self.assertEqual([value["type"] for value in sent], ["lifespan.startup.complete", "lifespan.shutdown.complete"])
        self.assertEqual(self.adapter.stops, [])
        self.assertEqual(self.core.identity()["control_generation"], 0)

    async def test_body_chunk_and_byte_bounds_refuse_before_core_effect(self):
        await self.pair("human")
        empty_chunks = [{"type": "http.request", "body": b"", "more_body": True}] * 129
        status, _, raw = await self.request("POST", "/stop", actor="human", raw=b"", events=empty_chunks)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"], "body_chunk_budget")
        self.assertEqual((await self.request("POST", "/stop", actor="human", raw=b"{}", events=[{"type": "http.request", "body": b"{}extra"}]))[0], 400)
        self.assertEqual(self.adapter.stops, [])
        self.assertEqual(self.app._stop_active, 0)

    async def test_header_and_csrf_denial_never_reaches_a_mutation(self):
        await self.pair("human")
        raw = b'{"operation_id":"owner-stop"}'
        headers = [(b"host", b"control.example:8443"), (b"origin", ORIGIN.encode()), (b"content-type", b"application/json"),
                   (b"content-length", str(len(raw)).encode()), (b"cookie", self.aliases["human"].encode())]
        self.assertEqual((await self.request("POST", "/stop", raw=raw, headers=headers))[0], 403)
        self.assertEqual((await self.request("POST", "/stop", raw=raw, headers=headers + [(b"x-csrf-token", self.csrf["human"].encode()),
                             (b"X-CSRF-Token", self.csrf["human"].encode())]))[0], 400)
        self.assertEqual(self.adapter.stops, [])

    async def test_oversized_body_chunk_is_refused_before_application_copy(self):
        await self.pair("human")
        copied = []
        class TrackedBuffer(bytearray):
            def extend(self, chunk):
                copied.append(len(chunk))
                super().extend(chunk)
        events = [{"type": "http.request", "body": b"a", "more_body": True},
                  {"type": "http.request", "body": b"x" * 1048576, "more_body": False}]
        with patch("src.browser_session.http_app.bytearray", TrackedBuffer, create=True):
            status, _, raw = await self.request("POST", "/stop", actor="human", raw=b"ab", events=events)
        self.assertEqual(status, 400)
        self.assertEqual(json.loads(raw)["error"], "invalid_body_bounds")
        self.assertEqual(copied, [1])  # Only the first admissible byte entered the application buffer.
        self.assertEqual(self.adapter.stops, [])
        self.assertEqual(self.app._stop_active, 0)

    async def test_no_yield_body_or_parsing_overrun_cannot_introduce_an_action(self):
        await self.pair("driver")
        value = await self.action(key="expired-transport")
        raw = json.dumps(value).encode()
        loop = asyncio.get_running_loop()
        for boundary in ("body", "request", "before_route", "before_mutation"):
            with self.subTest(boundary=boundary):
                bounds = HTTPBounds(body_seconds=0.001 if boundary == "body" else 1,
                    request_seconds=15 if boundary == "body" else 0.002)
                app = SessionHTTP(self.core, self.broker, ORIGIN, notify_pending=self.notice, bounds=bounds)
                now = [loop.time()]
                async def receive_without_yield():
                    if boundary in {"body", "request"}:
                        now[0] += 0.01
                    return {"type": "http.request", "body": raw, "more_body": False}
                original_body, original_object = app._body, app._object
                async def late_body(*arguments):
                    result = await original_body(*arguments)
                    if boundary == "before_route":
                        now[0] += 0.01
                    return result
                def late_parse(*arguments):
                    result = original_object(*arguments)
                    if boundary == "before_mutation":
                        now[0] += 0.01
                    return result
                with patch.object(loop, "time", side_effect=lambda: now[0]), \
                        patch.object(app, "_body", side_effect=late_body), \
                        patch.object(app, "_object", side_effect=late_parse):
                    status, _, _ = await self.request("POST", "/actions", actor="driver", raw=raw,
                        receiver=receive_without_yield, app=app)
                self.assertEqual(status, 503 if boundary == "body" else None)
                with self.assertRaises(SessionDenied):
                    self.core.operation(self.tokens["driver"], "expired-transport")
                self.notice.assert_not_called()
                self.assertEqual(self.adapter.executions + self.adapter.fences + self.adapter.stops, [])
                self.assertEqual(app._active, 0)

    async def test_client_timeout_retains_original_transfer_and_owned_late_task(self):
        await self.pair("human")
        self.adapter.fence_gate = asyncio.Event()
        short = SessionHTTP(self.core, self.broker, ORIGIN, notify_pending=self.notice,
                            bounds=HTTPBounds(request_seconds=0.002))
        status, _, _ = await self.request("POST", "/takeover", actor="human",
            value={"operation_id": "timed-transfer", "control_generation": 0}, app=short)
        self.assertIsNone(status)  # The absolute request deadline also bounds final output.
        original = self.core.operation(self.tokens["human"], "timed-transfer")
        self.assertEqual(original["state"], "unknown")
        self.assertEqual(self.core.observe(self.tokens["human"])["mode"], "fenced")
        self.adapter.fence_gate.set()
        await self.core._transition_task
        await asyncio.sleep(0)
        self.assertEqual(self.core.observe(self.tokens["human"])["mode"], "fenced")
        self.assertEqual(short._active, 0)

    async def test_retained_original_bytes_survive_stop_reload_and_deliberate_regrant(self):
        await self.pair("human")
        content = b'{"comparison":19}\n'
        self.core.retain_result("result.json", content)
        self.core.retain_result("screenshot.jpg", b"\xff\xd8original\xff\xd9")
        await self.request("POST", "/stop", actor="human", value={"operation_id": "clean-stop"})
        status, headers, raw = await self.request("GET", "/results/result.json", actor="human")
        self.assertEqual((status, raw), (200, content))
        self.assertEqual(headers["x-content-sha256"], hashlib.sha256(content).hexdigest())
        self.core.close()
        self.core = SessionControl.reopen(self.parent / "state", self.clock)
        self.broker = PairingBroker(self.core, ORIGIN, clock=self.clock)
        self.app = SessionHTTP(self.core, self.broker, ORIGIN, notify_pending=self.notice)
        self.assertEqual((await self.request("GET", "/results/result.json", actor="human"))[0], 403)
        self.tokens["observer"] = self.core.issue_grant("observer", {"observe": self.clock.wall + 1000})
        await self.pair("observer")  # Explicit trusted-host retained-observation grant.
        status, _, again = await self.request("GET", "/results/result.json", actor="observer")
        self.assertEqual((status, again), (200, content))
        status, _, raw = await self.request("GET", "/observation", actor="observer")
        self.assertEqual(status, 200)
        self.assertIsNone(json.loads(raw)["frame"])
        self.assertEqual(len(self.adapter.stops), 1)
        self.assertEqual(self.adapter.executions, [])

    async def test_private_exception_details_are_not_an_http_response(self):
        await self.pair("observer")
        with patch.object(self.core, "observe", side_effect=RuntimeError("/private/state token=secret")):
            status, _, raw = await self.request("GET", "/observation", actor="observer")
        self.assertEqual(status, 503)
        self.assertEqual(json.loads(raw), {"error": "session_unavailable"})
        self.assertNotIn(b"secret", raw)


class ClientSourceTests(unittest.TestCase):
    @unittest.skipUnless(shutil.which("node"), "optional deterministic JS source fixture requires Node, never a browser")
    def test_rendered_same_observation_recovers_from_hidden_and_age_updates_without_polling(self):
        path = Path(__file__).resolve().parents[2] / "src/browser_session/client/app.js"
        script = r'''
const assert=require("node:assert/strict"),nativeCrypto=require("node:crypto").webcrypto;
// Keep real hashing, but delay it past the former two-turn readiness guess.
const crypto={randomUUID:()=>nativeCrypto.randomUUID(),subtle:{digest:async(...args)=>{
  await new Promise(resolve=>setImmediate(()=>setImmediate(()=>setImmediate(resolve))));
  return nativeCrypto.subtle.digest(...args);
}}};
const {mountSessionClient}=require(process.argv[1]);
const elements=new Map();
const element=()=>({textContent:"",hidden:false,disabled:false,value:"",src:"",children:[],listeners:{},
  classList:{toggle(){}},addEventListener(name,callback){this.listeners[name]=callback},
  replaceChildren(){this.children=[]},append(value){this.children.push(value)},
  getBoundingClientRect(){return {left:0,top:0,width:800,height:600}}});
let frameSource="",resolveFirstFrame;
const firstFrame=new Promise(resolve=>{resolveFirstFrame=resolve});
const document={hidden:false,getElementById(id){
  if(!elements.has(id)){
    const item=element();
    if(id==="frame")Object.defineProperty(item,"src",{get:()=>frameSource,set:value=>{
      frameSource=value;if(value)resolveFirstFrame();
    }});
    elements.set(id,item);
  }
  return elements.get(id);
},createElement:element};
const bytes=Buffer.from([255,216,255,217]),hash=require("node:crypto").createHash("sha256").update(bytes).digest("hex");
const session={actor_id:"human",session_id:"s",context_id:"c",target_id:"t",csrf_token:"x".repeat(43),
  rights:{observe:{available:true,expires_at_ms:999999},control:{available:true,expires_at_ms:999999},stop:{available:true,expires_at_ms:999999}}};
const view={session_id:"s",context_id:"c",target_id:"t",backend_epoch:"b",control_generation:1,document_id:"d",document_generation:0,
  mode:"human",actor_id:"human",server_time_ms:10000,frame_max_age_ms:2000,corrections:[],results:[],
  frame:{session_id:"s",context_id:"c",target_id:"t",backend_epoch:"b",control_generation:1,document_id:"d",sequence:1,captured_at_ms:10000,
    width:800,height:600,observation_id:"same-original",projection:{url:"https://one.example",title:"Fixture",fields:{}},
    jpeg_base64:bytes.toString("base64"),jpeg_sha256:hash}};
let fail=false,now=0,requests=0,ageTick;
const fetcher=async(path)=>{requests++;if(path==="/observation"&&fail)throw new Error("temporarily unavailable");
  return new Response(JSON.stringify(path==="/session"?session:view),{status:200});};
global.setTimeout=()=>1;global.clearTimeout=()=>{};global.setInterval=callback=>{ageTick=callback;return 1};
(async()=>{
  const client=mountSessionClient(document,fetcher,crypto,()=>now);
  await firstFrame; // Observe this owned render, without another refresh or poll.
  assert.equal(elements.get("frame").hidden,false);const original=elements.get("frame").src;
  fail=true;await client.poll();assert.equal(elements.get("frame").hidden,true);
  fail=false;await client.poll();assert.equal(elements.get("frame").hidden,false);assert.equal(elements.get("frame").src,original);
  const before=requests;now=3001;ageTick();assert.equal(requests,before);
  assert.equal(elements.get("frame-label").textContent,"No live frame");assert.equal(elements.get("input-controls").disabled,true);
  assert.equal(elements.get("stop").disabled,false);
  console.log("render source checks passed: same original frame recovery, independent age, Stop separation");
})().catch(error=>{console.error(error);process.exitCode=1});
'''
        result = subprocess.run([shutil.which("node"), "-e", script, str(path)], capture_output=True, text=True,
                                timeout=10, env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("render source checks passed", result.stdout)

    @unittest.skipUnless(shutil.which("node"), "optional deterministic JS source fixture requires Node, never a browser")
    def test_actual_client_model_freshness_original_unknown_and_independent_stop(self):
        path = Path(__file__).resolve().parents[2] / "src/browser_session/client/app.js"
        script = r'''
const assert = require("node:assert/strict");
const crypto = require("node:crypto").webcrypto;
const {SessionClient} = require(process.argv[1]);
const bytes = Buffer.from([255,216,255,217]);
const hash = require("node:crypto").createHash("sha256").update(bytes).digest("hex");
const session = {actor_id:"human",session_id:"s",context_id:"c",target_id:"t",csrf_token:"x".repeat(43),
  rights:{observe:{available:true},control:{available:true},stop:{available:true}}};
const view = {session_id:"s",context_id:"c",target_id:"t",backend_epoch:"b",control_generation:1,document_id:"d",document_generation:0,
  mode:"human",actor_id:"human",server_time_ms:10000,frame_max_age_ms:2000,corrections:[],results:[],
  frame:{session_id:"s",context_id:"c",target_id:"t",backend_epoch:"b",control_generation:1,document_id:"d",sequence:1,
    captured_at_ms:10000,width:800,height:600,observation_id:"observed",jpeg_base64:bytes.toString("base64"),jpeg_sha256:hash}};
const response = value => new Response(JSON.stringify(value), {status:200,headers:{"content-type":"application/json"}});
let now=0, requests=[];
const fetcher = async (path, options) => { requests.push([path,options]);
  if(path==="/session") return response(session);
  if(path==="/observation") return response(view);
  if(path==="/actions") throw new Error("lost response");
  if(path.startsWith("/operations/")) return response({operation_id:path.split("/").pop(),kind:"action",state:"unknown",control_generation:1});
  if(path==="/stop") return response({operation_id:JSON.parse(options.body).operation_id,kind:"stop",state:"confirmed",control_generation:2});
  throw new Error("unexpected route"); };
(async () => {
  const client = new SessionClient(fetcher, crypto, () => now);
  await client.refresh(); await client.poll(); assert.equal(client.canInput(),true);
  assert.equal("csrf_token" in client.session,false);
  now=2001; assert.equal(client.canInput(),false); await client.input("key",{key:"enter"});
  assert.equal(requests.filter(([p])=>p==="/actions").length,0);
  now=0; await client.poll(); const original=await client.input("key",{key:"enter"});
  assert.equal(original.state,"unknown"); assert.equal(client.canInput(),false);
  for(let i=0;i<25;i++) await client.checkOperation();
  assert.equal(requests.filter(([p])=>p==="/actions").length,1);
  assert.equal(requests.filter(([p])=>p.startsWith("/operations/")).length,20);
  assert(requests.filter(([p])=>p.startsWith("/operations/")).every(([p])=>p.endsWith(original.operation_id)));
  client.session.rights.observe.available=false; assert.equal(client.canStop(),true);
  await client.stop(); assert.equal(client.operation.state,"confirmed");
  assert.equal(requests.filter(([p])=>p==="/handback").length,0);
  assert(requests.every(([,o])=>o.credentials==="same-origin" && o.redirect==="error"));

  // A late ordinary response cannot replace the later owner's Stop identity.
  let release, actionStarted; const entered=new Promise(resolve=>actionStarted=resolve);
  const deferred = async(path,options)=>{
    if(path==="/session") return response(session);
    if(path==="/observation") return response(view);
    if(path==="/actions") { actionStarted(); return new Promise(resolve=>release=()=>resolve(response({operation_id:JSON.parse(options.body).operation_id,kind:"action",state:"applied",control_generation:1}))); }
    if(path==="/stop") return response({operation_id:JSON.parse(options.body).operation_id,kind:"stop",state:"confirmed",control_generation:2});
    throw new Error("unexpected route"); };
  const second=new SessionClient(deferred,crypto,()=>0);
  await second.refresh(); await second.poll(); const action=second.input("key",{key:"enter"}); await entered;
  const stop=await second.stop(); release(); const prior=await action;
  assert.notEqual(stop.operation_id,prior.operation_id); assert.equal(second.operation.operation_id,stop.operation_id);
  assert.equal(second.operations.length,2); assert.equal(second.canInput(),false);

  // The whole network/body/hash interval contributes to conservative frame age.
  let elapsed=0;
  const slowFetch=async(path)=>{if(path==="/session")return response(session);elapsed+=3000;return response(view)};
  const delayed=new SessionClient(slowFetch,crypto,()=>elapsed);
  await delayed.refresh();await delayed.poll();assert.equal(delayed.frameAge(),3000);assert.equal(delayed.canInput(),false);
  elapsed=2999;assert.equal(delayed.frameAge(),Infinity);assert.equal(delayed.canInput(),false);

  // A delayed pre-Stop observation cannot overwrite its acknowledged generation.
  let releaseView,viewStarted,number=0;const reading=new Promise(resolve=>viewStarted=resolve);
  const orderedFetch=async(path,options)=>{
    if(path==="/session")return response(session);
    if(path==="/observation") {if(number++===0)return response(view);viewStarted();return new Promise(resolve=>releaseView=()=>resolve(response(view)))}
    if(path==="/stop")return response({operation_id:JSON.parse(options.body).operation_id,kind:"stop",state:"confirmed",control_generation:2});
    throw new Error("unexpected route");};
  const ordered=new SessionClient(orderedFetch,crypto,()=>0);await ordered.refresh();await ordered.poll();
  const oldView=ordered.poll();await reading;await ordered.stop();releaseView();await oldView;
  assert.equal(ordered.view,null);assert.equal(ordered.operation.state,"confirmed");assert.equal(ordered.canInput(),false);

  // An older frame within one generation cannot replace its newer observation.
  let sequence=5;
  const sequenceFetch=async(path)=>path==="/session"?response(session):response({...view,frame:{...view.frame,sequence:sequence--}});
  const sequenced=new SessionClient(sequenceFetch,crypto,()=>0);await sequenced.refresh();await sequenced.poll();await sequenced.poll();
  assert.equal(sequenced.view.frame.sequence,5);
  console.log("client source checks passed: conservative transit age, clock refusal, scoped transport, original unknown, bounded polling, independent Stop, late response and generation/sequence ordering");
})().catch(error=>{console.error(error);process.exitCode=1});
'''
        result = subprocess.run([shutil.which("node"), "-e", script, str(path)], capture_output=True, text=True,
                                timeout=10, env={"PATH": os.environ.get("PATH", "")})
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertIn("client source checks passed", result.stdout)


if __name__ == "__main__":
    unittest.main()
