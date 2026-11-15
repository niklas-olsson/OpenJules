"""Actual ASGI/HMAC/SQLite and original callback lifetime, controlled adapter."""

import asyncio
import copy
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.ingress_http import CallbackQueue
from src.api.ingress_policy import IngressError, load_policy
from src.api.webhook import create_app
from src.storage.ingress_receipts import ReceiptStore, enroll_policy
from tests.unit.ingress_core_support import write_private
from tests.unit.review_ingress_support import event, host, normalized, result


def signed(value, *, event_header="pull_request_review", secret="test-hmac-value", delivery="original"):
    body = json.dumps(value, separators=(",", ":")).encode()
    signature = "sha256=" + hmac.new(secret.encode(), body, hashlib.sha256).hexdigest()
    return body, {"Content-Type": "application/json", "X-Hub-Signature-256": signature,
        "X-GitHub-Event": event_header, "X-GitHub-Delivery": delivery}


class ReviewHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy, self.path, self.environment, self.document, _, _, _ = host(self.root)
        self.env_patch = patch.dict(os.environ, self.environment)
        self.env_patch.start()
        self.addCleanup(self.env_patch.stop)
        self.calls = []

    def adapter(self, original, claim):
        claim.validate_productive()
        self.calls.append(original)
        claim.persist_result(result(claim))
        return result(claim, status="returned")

    def client(self, adapter=None):
        app = create_app(policy_path=str(self.path), review_adapter=adapter or self.adapter)
        return TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 34567))

    def post(self, client, value=None, **kwargs):
        body, headers = signed(event() if value is None else value, **kwargs)
        return client.post("/api/webhook", content=body, headers=headers)

    def observed(self, client, operation):
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            response = client.get("/api/ingress/receipts/" + operation,
                headers={"Authorization": "Bearer test-operator-value"})
            self.assertEqual(response.status_code, 200, response.text)
            if response.json()["dispatch_state"] not in {"reserved", "may_have_started"}:
                return response.json()
            time.sleep(0.01)
        self.fail("original callback did not finish within fixture deadline")

    def test_real_signed_review_uses_original_receipt_and_headers_cannot_repeat_it(self):
        with self.client() as client:
            admitted = self.post(client)
            self.assertEqual(admitted.status_code, 202, admitted.text)
            original = admitted.json()["operation_id"]
            observed = self.observed(client, original)
            repeated = self.post(client, delivery="different-unsigned-delivery")
            self.assertEqual(repeated.status_code, 202, repeated.text)
            self.assertEqual(repeated.json(), observed)
            self.assertEqual(len(self.calls), 1)
            self.assertEqual(self.calls[0]["operation_id"], original)
            self.assertEqual(self.calls[0]["review"]["head_ref"], "refs/heads/topic")
            self.assertFalse(observed["managed_authority"])
            self.assertFalse(observed["release_authorized"])
        with sqlite3.connect(self.policy.store_path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM target_fences").fetchone()[0], 1)
        raw = self.policy.store_path.read_bytes()
        for value in self.environment.values():
            self.assertNotIn(value.encode(), raw)

    def test_bad_signature_wrong_event_and_fork_have_no_callback_or_receipt(self):
        with self.client() as client:
            self.assertEqual(self.post(client, secret="incorrect").status_code, 401)
            self.assertEqual(self.post(client, event_header="issue_comment").status_code, 404)
            fork = event()
            fork["pull_request"]["head"]["repo"]["id"] = 999
            self.assertEqual(self.post(client, fork).status_code, 404)
            ambiguous = event()
            ambiguous["issue"] = {"number": 7}
            self.assertEqual(self.post(client, ambiguous).status_code, 404)
            self.assertEqual(self.calls, [])
        with sqlite3.connect(self.policy.store_path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM receipts").fetchone()[0], 0)

    def test_changed_original_review_conflicts_and_new_review_keeps_target_fence(self):
        with self.client() as client:
            admitted = self.post(client)
            observed = self.observed(client, admitted.json()["operation_id"])
            changed = event()
            changed["review"]["body"] += " Modified instruction."
            conflict = self.post(client, changed)
            self.assertEqual(conflict.status_code, 409, conflict.text)
            self.assertIn("source_identity_conflict", conflict.text)
            later = event()
            later["review"]["id"] += 1
            fenced = self.post(client, later)
            self.assertEqual(fenced.status_code, 409, fenced.text)
            self.assertIn("target_action_fenced", fenced.text)
            self.assertEqual(len(self.calls), 1)

    def test_queue_capacity_does_not_hide_original_but_refuses_new_effects(self):
        with self.client() as client:
            admitted = self.post(client)
            observed = self.observed(client, admitted.json()["operation_id"])
            with patch.object(client.app.state.ingress_callbacks, "can_accept", return_value=False):
                self.assertEqual(self.post(client).json(), observed)
                different = event()
                different["review"]["id"] += 1
                different["pull_request"]["number"] += 1
                response = self.post(client, different)
                self.assertEqual(response.status_code, 503, response.text)
                self.assertEqual(len(self.calls), 1)

    def test_receipt_reader_requires_original_binding_scope(self):
        with self.client() as client:
            admitted = self.post(client)
            self.observed(client, admitted.json()["operation_id"])
            response = client.get("/api/ingress/receipts/" + admitted.json()["operation_id"])
            self.assertEqual(response.status_code, 401)
            self.assertNotIn("refs/heads/topic", response.text)

    def test_original_selected_secret_literal_is_refused_before_storage(self):
        value = event()
        value["review"]["body"] += " " + self.environment["REVIEW_FIXTURE_TOKEN"]
        with self.client() as client:
            response = self.post(client, value)
            self.assertEqual(response.status_code, 422, response.text)
            self.assertEqual(self.calls, [])
        self.assertNotIn(self.environment["REVIEW_FIXTURE_TOKEN"].encode(), self.policy.store_path.read_bytes())

    def test_alias_cannot_disclose_old_receipt_or_replace_original_target(self):
        with self.client() as client:
            admitted = self.post(client)
            observed = self.observed(client, admitted.json()["operation_id"])
        self.document["policy_id"] = "alias-policy"
        alias = copy.deepcopy(self.document["bindings"][0])
        alias["binding_id"] = "alias"
        self.document["bindings"].append(alias)
        for principal in self.document["principals"]:
            principal["grants"][0]["binding_id"] = "alias"
        write_private(self.path, self.document)
        replacement = load_policy(self.path)
        enroll_policy(replacement)
        with self.client() as client:
            response = self.post(client)
            self.assertEqual(response.status_code, 409, response.text)
            self.assertNotIn(observed["operation_id"], response.text)
            later = event()
            later["review"]["id"] += 1
            response = self.post(client, later)
            self.assertEqual(response.status_code, 409, response.text)
            self.assertNotIn(observed["operation_id"], response.text)
            response = client.get("/api/ingress/receipts/" + observed["operation_id"],
                headers={"Authorization": "Bearer test-operator-value"})
            self.assertEqual(response.status_code, 404)
            self.assertEqual(len(self.calls), 1)


class OriginalCallbackCustodyTests(unittest.IsolatedAsyncioTestCase):
    async def test_shutdown_waits_for_the_actual_original_callback_after_deadline(self):
        with tempfile.TemporaryDirectory() as directory:
            def short(document):
                limits = document["bindings"][0]["standalone_review"]["limits"]
                limits["total_ms"], limits["cleanup_reserve_ms"] = 20, 5
            policy, _, _, _, _, _, credentials = host(Path(directory), mutate=short)
            store = ReceiptStore(policy, review_credentials=credentials)
            entered, release = threading.Event(), threading.Event()
            def adapter(original, claim):
                claim.persist_result(result(claim))
                entered.set()
                if not release.wait(5):
                    raise AssertionError("fixture did not release original callback")
                claim.validate_retirement()
                return result(claim, status="unknown", failure={"code": "deadline_exhausted", "unknown": True})
            queue = CallbackQueue(store, None, adapter)
            _, review, actor = normalized(policy)
            receipt = store.reserve_review("webhook", "repo", review, actor)
            queue.submit(store.fence(receipt["operation_id"], "webhook"))
            self.assertTrue(await asyncio.to_thread(entered.wait, 5))
            await asyncio.sleep(0.04)
            closing = asyncio.create_task(queue.close())
            try:
                await asyncio.sleep(0.02)
                self.assertFalse(closing.done())
                self.assertFalse(store._closed)
                with self.assertRaises(IngressError) as error:
                    store.close()
                self.assertEqual(error.exception.code, "callbacks_active")
                self.assertTrue(store._invocations)
            finally:
                release.set()
                await asyncio.wait_for(closing, 5)
            self.assertTrue(store._closed)
            with sqlite3.connect(policy.store_path) as connection:
                self.assertEqual(connection.execute("SELECT state FROM receipts").fetchone()[0], "reconciliation_required")
                self.assertEqual(connection.execute("SELECT count(*) FROM target_fences").fetchone()[0], 1)


if __name__ == "__main__":
    unittest.main()
