"""Original model-call accounting with controlled HTTP objects, no network."""

import asyncio
import copy
from dataclasses import replace
import json
import threading
import time
import unittest
from unittest.mock import patch

from src.worker.review_contract import ReviewError
from src.worker.standalone_review import ReviewOperation
from src.worker.standalone_review_model import StandaloneReviewModel
import src.worker.standalone_review_model as model_module
from src.agent.standalone_review_engine import tool_definitions
from tests.unit.test_standalone_review_operation import fixture


def reply(content="bounded response", *, calls=None, finish=None):
    message = {"role": "assistant", "content": content}
    if calls is not None:
        message["tool_calls"] = calls
    return json.dumps({"choices": [{"index": 0, "message": message,
                                    "finish_reason": finish or ("tool_calls" if calls else "stop")}]}).encode()


class Response:
    def __init__(self, fixture):
        self.fixture = fixture
        self.status_code = fixture.status
        self.headers = {"Content-Encoding": fixture.encoding}

    async def aiter_raw(self):
        for chunk in self.fixture.chunks:
            if self.fixture.chunk_hook:
                self.fixture.chunk_hook()
            yield chunk

    async def aclose(self):
        self.fixture.response_close_calls += 1
        self.fixture.active_closes += 1
        if self.fixture.close_started:
            self.fixture.close_started.set()
        try:
            if self.fixture.release_close:
                while not self.fixture.release_close.is_set():
                    await asyncio.sleep(0.001)
            if self.fixture.close_error:
                raise OSError("private close error")
            self.fixture.response_closed = True
        finally:
            self.fixture.active_closes -= 1


class Client:
    def __init__(self, fixture, options):
        self.fixture = fixture
        fixture.options.append(options)

    def build_request(self, method, endpoint, **kwargs):
        if self.fixture.build_hook:
            self.fixture.build_hook()
        return (method, endpoint, kwargs)

    async def send(self, request, *, stream):
        self.fixture.calls.append((request, stream))
        if self.fixture.send_hook:
            self.fixture.send_hook()
        if self.fixture.send_error:
            raise OSError("provider private payload")
        return Response(self.fixture)

    async def aclose(self):
        self.fixture.client_close_calls += 1
        self.fixture.client_closed = True


class HTTPFixture:
    def __init__(self, raw=None):
        self.chunks = [reply() if raw is None else raw]
        self.status, self.encoding = 200, "identity"
        self.options, self.calls = [], []
        self.build_hook = self.send_hook = self.chunk_hook = None
        self.send_error = self.close_error = False
        self.client_closed = self.response_closed = False
        self.close_started = self.release_close = None
        self.response_close_calls = self.client_close_calls = self.active_closes = 0

    def factory(self, **kwargs):
        return Client(self, kwargs)


MESSAGES = [{"role": "user", "content": "Review the original bounded source."}]


class ModelTests(unittest.TestCase):
    def setup_model(self, raw=None, **limits):
        claim, now, saved = fixture(**limits)
        operation = ReviewOperation(claim, clock=lambda: now[0])
        http = HTTPFixture(raw)
        model = StandaloneReviewModel(client_factory=http.factory)
        return claim, now, saved, operation, http, model

    def test_one_original_post_and_no_payload_in_result(self):
        claim, now, saved, op, http, model = self.setup_model()
        self.assertFalse(http.options)
        result = model.complete(op, MESSAGES)
        model.retire(op)
        self.assertEqual(result.content, "bounded response")
        self.assertEqual(len(http.calls), 1)
        request, stream = http.calls[0]
        self.assertEqual(request[:2], ("POST", claim.profile.document["model"]["url"]))
        self.assertTrue(stream)
        payload = json.loads(request[2]["content"])
        self.assertIs(payload["stream"], False)
        self.assertNotIn("tools", payload)
        self.assertEqual(payload["max_tokens"], 128)
        self.assertEqual(http.options[0], {"trust_env": False, "follow_redirects": False, "timeout": 0.3})
        effect = op.snapshot()["effects"][0]
        self.assertTrue(all(effect[key] for key in ("entered", "returned", "acknowledged", "closed")))
        self.assertEqual(effect["response_bytes"], len(http.chunks[0]))
        self.assertEqual(set(effect["data"]), {"payload_sha256", "route_sha256", "local_closed"})
        projected = json.dumps(op.snapshot())
        for secret in ("bounded response", MESSAGES[0]["content"], claim.credentials.model_key):
            self.assertNotIn(secret, projected)
        self.assertTrue(http.client_closed and http.response_closed)

    def test_expiry_during_request_preparation_sends_nothing(self):
        claim, now, saved, op, http, model = self.setup_model()
        http.build_hook = lambda: now.__setitem__(0, 0.301)
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        self.assertEqual(http.calls, [])
        self.assertTrue(http.client_closed)
        self.assertFalse(op.snapshot()["effects"][0]["entered"])
        self.assertEqual(op.snapshot()["first_failure"]["code"], "deadline_exhausted")

    def test_policy_change_during_request_preparation_sends_nothing(self):
        claim, now, saved, op, http, model = self.setup_model()
        def revoke():
            object.__setattr__(claim, "validate_productive", lambda: (_ for _ in ()).throw(ReviewError("authority_changed")))
        http.build_hook = revoke
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        self.assertEqual(http.calls, [])
        self.assertTrue(http.client_closed)
        self.assertFalse(op.snapshot()["effects"][0]["entered"])
        self.assertEqual(op.snapshot()["first_failure"]["code"], "authority_changed")
        model.retire(op)
        self.assertFalse(op.fact("model")["provider_outcome_unknown"])

    def test_revocation_during_original_send_preserves_unvalidated_outcome(self):
        claim, now, saved, op, http, model = self.setup_model()
        def revoke():
            object.__setattr__(claim, "validate_productive", lambda: (_ for _ in ()).throw(ReviewError("authority_changed")))
        http.send_hook = revoke
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        model.retire(op)
        result = op.snapshot()
        effect = result["effects"][0]
        self.assertTrue(effect["entered"] and effect["returned"] and effect["closed"] and effect["outcome_unknown"])
        self.assertFalse(effect["acknowledged"] or effect["refused"])
        self.assertEqual(effect["response_bytes"], 0)
        self.assertEqual(result["first_failure"], {"code": "authority_changed", "unknown": False})
        self.assertEqual(result["status"], "unknown")
        self.assertTrue(result["facts"]["model"]["provider_outcome_unknown"])
        self.assertEqual((len(http.calls), http.response_close_calls, http.client_close_calls), (1, 1, 1))

    def test_client_preparation_failure_does_not_invent_provider_entry(self):
        claim, now, saved, op, http, model = self.setup_model()
        model = StandaloneReviewModel(client_factory=lambda **kwargs: (_ for _ in ()).throw(ValueError("local preparation")))
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        model.retire(op)
        effect = op.snapshot()["effects"][0]
        self.assertFalse(effect["entered"] or effect["returned"] or effect["outcome_unknown"])
        self.assertTrue(effect["refused"])
        self.assertFalse(op.fact("model")["provider_outcome_unknown"])
        self.assertEqual(http.calls, [])

    def test_expiry_during_durable_reservation_constructs_no_client(self):
        claim, now, saved, op, http, model = self.setup_model()
        def persist(value):
            saved.append(copy.deepcopy(value))
            if value["effects"]:
                now[0] = 0.301
        object.__setattr__(claim, "persist_result", persist)
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        self.assertFalse(http.options)
        self.assertFalse(http.calls)

    def test_schema_error_has_no_retry_or_tool_fallback(self):
        claim, now, saved, op, http, model = self.setup_model(b"tool schema is unsupported")
        http.status = 400
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES, tools=tool_definitions())
        self.assertEqual(len(http.calls), 1)
        self.assertIn("tools", json.loads(http.calls[0][0][2]["content"]))
        self.assertEqual(op.snapshot()["first_failure"]["code"], "model_refused")
        self.assertTrue(http.client_closed and http.response_closed)
        model.retire(op)
        self.assertFalse(op.fact("model")["provider_outcome_unknown"])

    def test_oversized_chunk_is_observed_without_accumulation_or_refund(self):
        claim, now, saved, op, http, model = self.setup_model(b"x" * 50, model_response_bytes=16)
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        effect = op.snapshot()["effects"][0]
        self.assertEqual((effect["response_reserved"], effect["response_bytes"]), (16, 50))
        self.assertTrue(effect["outcome_unknown"])
        self.assertFalse(effect["acknowledged"])
        self.assertEqual(op.snapshot()["counters"]["model_output_tokens"], 128)
        self.assertTrue(http.client_closed and http.response_closed)

    def test_call_token_and_input_aggregate_refuse_before_next_client(self):
        for limits in ({"model_calls": 1}, {"model_output_tokens_total": 128},
                       {"model_request_bytes": 250, "model_request_total_bytes": 280}):
            with self.subTest(limits=limits):
                claim, now, saved, op, http, model = self.setup_model(**limits)
                model.complete(op, MESSAGES)
                with self.assertRaises(ReviewError):
                    model.complete(op, MESSAGES)
                self.assertEqual(len(http.calls), 1)
                self.assertEqual(len(http.options), 1)

    def test_malformed_duplicate_and_truncated_responses_refuse(self):
        values = [b'{"choices":[],"choices":[]}', reply(finish="length"), b'not JSON']
        for raw in values:
            with self.subTest(raw=raw):
                claim, now, saved, op, http, model = self.setup_model(raw)
                with self.assertRaises(ReviewError):
                    model.complete(op, MESSAGES)
                self.assertEqual(len(http.calls), 1)
                self.assertEqual(op.snapshot()["first_failure"]["code"], "model_refused")
                self.assertTrue(http.client_closed and http.response_closed)

    def test_missing_original_reply_stops_all_new_work(self):
        claim, now, saved, op, http, model = self.setup_model()
        http.send_error = True
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        effect = op.snapshot()["effects"][0]
        self.assertTrue(effect["entered"] and effect["outcome_unknown"] and effect["closed"])
        self.assertFalse(effect["returned"] or effect["acknowledged"])
        self.assertEqual(len(http.calls), 1)
        self.assertNotIn("provider private", json.dumps(op.snapshot()))

    def test_post_reply_store_fault_keeps_original_response_for_closure(self):
        claim, now, saved, op, http, model = self.setup_model()
        def persist(value):
            if value["effects"] and value["effects"][0]["returned"]:
                raise OSError("private store failure")
            saved.append(copy.deepcopy(value))
        object.__setattr__(claim, "persist_result", persist)
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        self.assertTrue(http.client_closed and http.response_closed)
        self.assertTrue(op.snapshot()["effects"][0]["closed"])
        self.assertEqual(op.snapshot()["first_failure"]["code"], "record_unavailable")

    def test_late_body_cannot_ack_or_license_a_second_request(self):
        claim, now, saved, op, http, model = self.setup_model()
        http.chunk_hook = lambda: now.__setitem__(0, 0.4)
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        self.assertFalse(op.snapshot()["effects"][0]["acknowledged"])
        self.assertEqual(op.snapshot()["effects"][0]["response_bytes"], len(http.chunks[0]))
        with self.assertRaises(ReviewError):
            op.reserve("model", output_tokens=1)
        self.assertEqual(len(http.calls), 1)

    def test_original_call_expiry_during_parser_never_acknowledges_usable_reply(self):
        claim, now, saved, op, http, model = self.setup_model()
        original = model_module._response
        def slow_parse(*args, **kwargs):
            result = original(*args, **kwargs)
            now[0] = 0.301
            return result
        with patch.object(model_module, "_response", slow_parse):
            with self.assertRaises(ReviewError):
                model.complete(op, MESSAGES)
        effect = op.snapshot()["effects"][0]
        self.assertFalse(effect["acknowledged"])
        self.assertTrue(effect["returned"] and effect["closed"] and effect["outcome_unknown"])
        self.assertEqual(op.snapshot()["first_failure"]["code"], "deadline_exhausted")
        self.assertLess(now[0], op.work_deadline)
        self.assertEqual(len(http.calls), 1)

    def test_validator_and_ack_persistence_cannot_renew_original_call(self):
        for point in ("validator", "ack_persist"):
            with self.subTest(point=point):
                claim, now, saved, op, http, model = self.setup_model()
                parsed = []
                original = model_module._response
                def parse(*args, **kwargs):
                    result = original(*args, **kwargs)
                    parsed.append(True)
                    return result
                def validate():
                    if parsed and point == "validator":
                        now[0] = 0.301
                def persist(value):
                    saved.append(copy.deepcopy(value))
                    if point == "ack_persist" and value["effects"] and value["effects"][0]["acknowledged"]:
                        now[0] = 0.301
                object.__setattr__(claim, "validate_productive", validate)
                object.__setattr__(claim, "persist_result", persist)
                with patch.object(model_module, "_response", parse):
                    with self.assertRaises(ReviewError):
                        model.complete(op, MESSAGES)
                effect = op.snapshot()["effects"][0]
                self.assertEqual(effect["acknowledged"], point == "ack_persist")
                self.assertTrue(effect["outcome_unknown"] and effect["closed"])
                self.assertEqual(op.snapshot()["first_failure"]["code"], "deadline_exhausted")
                self.assertEqual(len(http.calls), 1)

    def test_unknown_tool_and_duplicate_original_call_ids_refuse(self):
        call = {"id": "original", "type": "function", "function": {"name": "run_command", "arguments": '{"command":"true"}'}}
        unknown = copy.deepcopy(call)
        unknown["function"]["name"] = "publish"
        for calls in ([unknown], [call, call]):
            claim, now, saved, op, http, model = self.setup_model(reply(None, calls=calls))
            with self.assertRaises(ReviewError):
                model.complete(op, MESSAGES, tools=tool_definitions())
            self.assertEqual(len(http.calls), 1)
            self.assertEqual(op.snapshot()["counters"]["exec"], 0)

    def test_decoded_json_secret_never_reaches_tool_or_history(self):
        claim, _, _ = fixture()
        secret = claim.credentials.model_key
        escaped = "".join("\\u%04x" % ord(char) for char in secret)
        argument_variants = [
            '{"path":"demo.txt","content":"' + escaped + '"}',
            '{"path":"demo.txt","content":{"nested":["' + escaped + '"]}}',
            '{"path":"demo.txt","' + escaped + '":"bounded"}',
        ]
        wires = [reply(None, calls=[{"id": "original", "type": "function", "function": {
            "name": "write_file", "arguments": args}}]) for args in argument_variants]
        wires.append(reply(secret).replace(secret.encode(), escaped.encode()))
        for wire in wires:
            with self.subTest(wire_length=len(wire)):
                claim, now, saved, op, http, model = self.setup_model(wire)
                self.assertNotIn(secret.encode(), wire)
                with self.assertRaises(ReviewError):
                    model.complete(op, MESSAGES, tools=tool_definitions())
                self.assertEqual(op.snapshot()["first_failure"]["code"], "secret_in_data")
                self.assertEqual(op.snapshot()["counters"]["exec"], 0)
                self.assertEqual(len(http.calls), 1)
                self.assertTrue(http.response_closed and http.client_closed)

    def test_original_close_future_keeps_callback_live_after_cutoff(self):
        claim, now, saved, op, http, model = self.setup_model()
        http.close_started, http.release_close = threading.Event(), threading.Event()
        results = []
        def callback():
            try:
                model.complete(op, MESSAGES)
            except ReviewError as error:
                results.append(error.code)
        thread = threading.Thread(target=callback)
        thread.start()
        self.assertTrue(http.close_started.wait(2))
        now[0] = 1.1
        self.assertTrue(thread.is_alive())
        self.assertFalse(op.snapshot()["effects"][0]["closed"])
        self.assertEqual(len(http.calls), 1)
        http.release_close.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results, ["deadline_exhausted"])
        self.assertTrue(op.snapshot()["effects"][0]["closed"])

    def test_failed_close_is_inactive_unknown_and_retire_never_retries_it(self):
        claim, now, saved, op, http, model = self.setup_model()
        http.close_error = True
        with self.assertRaises(ReviewError):
            model.complete(op, MESSAGES)
        self.assertEqual(http.active_closes, 0)
        self.assertEqual((http.response_close_calls, http.client_close_calls), (1, 1))
        self.assertFalse(http.response_closed)
        self.assertTrue(http.client_closed)
        self.assertFalse(op.snapshot()["effects"][0]["closed"])
        with self.assertRaises(ReviewError):
            model.retire(op)
        model.retire(op)
        self.assertEqual((http.response_close_calls, http.client_close_calls), (1, 1))
        self.assertIs(op.fact("model")["local_closed"], False)
        self.assertIs(op.fact("model")["provider_outcome_unknown"], True)


class AsyncCustodyTests(unittest.IsolatedAsyncioTestCase):
    async def test_cancel_during_original_close_and_store_failure_keeps_same_task(self):
        claim, now, saved = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        http = HTTPFixture()
        http.close_started, http.release_close = threading.Event(), threading.Event()
        model = StandaloneReviewModel(client_factory=http.factory)
        effect = op.reserve("model", request_bytes=2, response_bytes=4096, output_tokens=128)
        task = asyncio.create_task(model._exchange(op, effect, claim.profile.document["model"]["url"], b"{}", {}, False))
        for _ in range(200):
            if http.close_started.is_set():
                break
            await asyncio.sleep(0.001)
        self.assertTrue(http.close_started.is_set())
        object.__setattr__(claim, "persist_result", lambda value: (_ for _ in ()).throw(OSError()))
        task.cancel()
        await asyncio.sleep(0.005)
        self.assertFalse(task.done())
        self.assertEqual(http.active_closes, 1)
        self.assertEqual(http.response_close_calls, 1)
        self.assertFalse(op.snapshot()["effects"][0]["closed"])
        http.release_close.set()
        await task
        self.assertEqual(http.active_closes, 0)
        self.assertEqual((http.response_close_calls, http.client_close_calls), (1, 1))
        self.assertTrue(op.snapshot()["effects"][0]["closed"])
        self.assertTrue(op.snapshot()["effects"][0]["outcome_unknown"])
        self.assertEqual(op.snapshot()["first_failure"]["code"], "model_outcome_unknown")


if __name__ == "__main__":
    unittest.main()
