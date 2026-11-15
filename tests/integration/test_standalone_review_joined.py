"""Real HTTP/journal plus selected engine/model, with controlled native ports.

This joins component ownership and result persistence; it is not a daemon or
forge execution claim. The native Docker fixture is qualified separately.
"""

import json
import os
from pathlib import Path
import tempfile
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.webhook import create_app
from src.storage.ingress_receipts import ReceiptStore
from src.worker.standalone_review import StandaloneReviewAdapter
from src.worker.standalone_review_model import StandaloneReviewModel
from tests.integration.test_review_ingress_http import signed
from tests.unit.review_ingress_support import event, host, normalized
from tests.unit.test_standalone_review_engine import NativeFixture, PLAN, SequenceHTTP
from tests.unit.test_standalone_review_model import reply


class JoinedReviewTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp.cleanup)
        self.root = Path(self.temp.name)
        self.policy, self.path, self.environment, _, _, _, _ = host(self.root)
        self.selected = patch.dict(os.environ, self.environment)
        self.selected.start()
        self.addCleanup(self.selected.stop)
        self.native = []
        self.http = SequenceHTTP([reply(PLAN), reply("TASK_COMPLETED")])
        self.original = event()
        self.original["pull_request"]["head"]["sha"] = "1" * 40
        self.original["review"]["commit_id"] = "1" * 40

    def native_factory(self, claim):
        native = NativeFixture(claim)
        self.native.append(native)
        return native

    def run_original(self):
        adapter = StandaloneReviewAdapter(native_factory=self.native_factory,
            model_factory=lambda: StandaloneReviewModel(client_factory=self.http.factory))
        app = create_app(policy_path=str(self.path), review_adapter=adapter)
        with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 34567)) as client:
            body, headers = signed(self.original)
            admitted = client.post("/api/webhook", content=body, headers=headers)
            self.assertEqual(admitted.status_code, 202, admitted.text)
            operation = admitted.json()["operation_id"]
            deadline = time.monotonic() + 5
            while time.monotonic() < deadline:
                response = client.get("/api/ingress/receipts/" + operation,
                    headers={"Authorization": "Bearer test-operator-value"})
                self.assertEqual(response.status_code, 200, response.text)
                value = response.json()
                if value["dispatch_state"] not in {"reserved", "may_have_started"}:
                    break
                time.sleep(0.01)
            else:
                self.fail("joined original callback did not finish")
        return value

    def test_typed_results_survive_every_joined_phase_and_original_journal_reopen(self):
        observed = self.run_original()
        self.assertEqual(observed["dispatch_state"], "returned", observed)
        result = observed["result"]
        self.assertEqual(result["status"], "returned", result)
        self.assertEqual(result["counters"]["model"], 2)
        self.assertEqual(result["counters"]["forge_get"], 4)
        self.assertEqual(result["counters"]["guest_api_cleanup"], 6)
        self.assertEqual(result["facts"]["publication"]["status"], "acknowledged")
        self.assertTrue(all(effect["closed"] for effect in result["effects"]))
        self.assertFalse(result["facts"]["guest"]["retained"])
        self.assertEqual(len(self.native), 1)
        self.assertEqual(len(self.http.calls), 2)
        encoded = json.dumps(observed)
        for private in ("Fix the original fixture", PLAN, "bounded fixture patch", "README: fixture source"):
            self.assertNotIn(private, encoded)
        with ReceiptStore(self.policy) as store:
            binding, review, actor = normalized(self.policy, self.original)
            self.assertEqual(store.reserve_review("webhook", binding.binding_id, review, actor), observed)
        self.assertEqual(len(self.native), 1)

    def test_missing_original_model_reply_is_sticky_through_cleanup_and_reopen(self):
        self.http.send_error = True
        observed = self.run_original()
        self.assertEqual(observed["dispatch_state"], "reconciliation_required", observed)
        result = observed["result"]
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["first_failure"], {"code": "model_outcome_unknown", "unknown": True})
        self.assertEqual(result["counters"]["model"], 1)
        self.assertEqual(len(self.http.calls), 1)
        self.assertNotIn("publish", self.native[0].events)
        self.assertNotIn("exec", self.native[0].events)
        self.assertTrue(result["facts"]["model"]["provider_outcome_unknown"])
        self.assertTrue(result["facts"]["model"]["local_closed"])
        with ReceiptStore(self.policy) as store:
            binding, review, actor = normalized(self.policy, self.original)
            self.assertEqual(store.reserve_review("webhook", binding.binding_id, review, actor), observed)
        self.assertEqual(len(self.http.calls), 1)


if __name__ == "__main__":
    unittest.main()
