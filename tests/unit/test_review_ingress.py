"""Review admission and original journal custody with real local storage."""

import copy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from unittest.mock import patch

from src.api.ingress_adapter import ReviewCredentialSnapshot
from src.api.ingress_policy import IngressError, load_policy
from src.api.review_policy import _model_endpoint, parse_review_profile, scan_review_secrets
from src.storage.ingress_receipts import ReceiptStore, enroll_policy
from src.worker.review_contract import ReviewError
from tests.unit.ingress_core_support import reserve as reserve_task, write_private
from tests.unit.review_ingress_support import claim_review, declaration, event, host, normalized, profile, result


class ReviewIngressTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.root = Path(self.temp.name)
        self.addCleanup(self.temp.cleanup)

    def assert_code(self, expected, call, *args, **kwargs):
        with self.assertRaises(IngressError) as failure:
            call(*args, **kwargs)
        self.assertEqual(failure.exception.code, expected)
        return failure.exception

    def test_exact_profile_is_deeply_immutable_and_no_implicit_limits(self):
        value = profile(self.root)
        parsed = parse_review_profile(value, None)
        with self.assertRaises(TypeError):
            parsed.document["model"]["url"] = "https://other.invalid/model"
        value["model"]["url"] = "https://other.invalid/model"
        self.assertNotEqual(parsed.document["model"]["url"], value["model"]["url"])
        for category, key in (("limits", "model_calls"), ("guest", "docker_api_version"), ("model", "credential_ref")):
            malformed = profile(self.root)
            del malformed[category][key]
            with self.assertRaises(IngressError):
                parse_review_profile(malformed, None)

    def test_model_endpoint_delimiters_and_scanner_integer_overflow_are_closed(self):
        for suffix in ("?", "#", "?key=x", "#fragment"):
            self.assert_code("invalid_review_model_endpoint", _model_endpoint,
                "http://127.0.0.1/v1/chat/completions" + suffix)
        for value in (10**400, -10**400, float("inf"), float("nan"), object()):
            self.assert_code("invalid_review_structure", scan_review_secrets, {"value": value}, ())
        scan_review_secrets({"observed": True, "temperature": 0.5}, ())

    def test_selected_profile_rejects_ambient_routes_and_unreserved_capacity(self):
        cases = [("guest", "docker_endpoint", "tcp://127.0.0.1:2375"),
            ("guest", "docker_api_version", "auto"), ("guest", "uid", 0),
            ("limits", "guest_api_cleanup_calls", 5), ("limits", "receipt_result_bytes", 1),
            ("model", "url", "http://localhost/v1/chat/completions"),
            ("model", "credential_ref", "env:OPENJULES_INGRESS_HMAC_WEBHOOK"),
            ("forge_auth", "username", "name:password")]
        for category, key, value in cases:
            with self.subTest(category=category, key=key):
                candidate = profile(self.root)
                candidate[category][key] = value
                with self.assertRaises(IngressError):
                    parse_review_profile(candidate, None)

    def test_review_only_enrollment_needs_its_own_scope_without_a_task_declaration(self):
        policy, _, _, _, _, activation, credentials = host(self.root, enrolled=False)
        self.assert_code("review_scope_activation_required", enroll_policy, policy)
        enroll_policy(policy, review_activation_paths=[activation])
        with sqlite3.connect(policy.store_path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM activations").fetchone()[0], 0)
            self.assertEqual(connection.execute("SELECT count(*) FROM review_activations").fetchone()[0], 1)
        with ReceiptStore(policy, review_credentials=credentials):
            self.assert_code("receipt_store_owned", enroll_policy, policy)
        self.assert_code("review_activation_exists_or_unselected", enroll_policy, policy,
            review_activation_paths=[activation])

    def test_unsupported_source_and_composition_bounds_refuse_before_runtime(self):
        ceilings = {"patch_bytes": 4_000_000, "source_bytes": 32_000_000,
            "blob_bytes": 4_000_000, "files": 20_000, "path_bytes": 4096,
            "patch_records": 40_000, "object_count": 200_000,
            "object_bytes": 128_000_000, "git_output_bytes": 32_000_000,
            "source_objects": 100_000}
        with patch("subprocess.Popen", side_effect=AssertionError("process during policy parsing")), \
             patch("socket.socket", side_effect=AssertionError("socket during policy parsing")), \
             patch("pathlib.Path.mkdir", side_effect=AssertionError("storage during policy parsing")):
            for key, maximum in ceilings.items():
                with self.subTest(limit=key):
                    candidate = profile(self.root)
                    candidate["limits"][key] = maximum
                    candidate["limits"]["git_output_total_bytes"] = 32_000_001
                    parse_review_profile(candidate, None)
                    candidate["limits"][key] = maximum + 1
                    code = ("unsupported_review_source_bounds" if key == "source_objects"
                        else "unsupported_review_composition_bounds")
                    self.assert_code(code, parse_review_profile, candidate, None)

    def test_task_activation_alone_never_enables_review_and_transaction_rolls_back(self):
        policy, _, _, _, task_activation, review_activation, _ = host(self.root, enrolled=False, task=True)
        self.assert_code("review_scope_activation_required", enroll_policy, policy, task_activation)
        with sqlite3.connect(policy.store_path) as connection:
            self.assertEqual(connection.execute("SELECT count(*) FROM activations").fetchone()[0], 0)
            self.assertIsNone(connection.execute("SELECT name FROM sqlite_master WHERE name='review_activations'").fetchone())
        enroll_policy(policy, task_activation, review_activation_paths=[review_activation])

    def test_resolved_scope_needs_evidence_and_cannot_override_an_existing_fence(self):
        policy, _, _, _, _, activation, credentials = host(self.root, enrolled=False)
        value = declaration(policy, assertion="resolved_review_scope")
        write_private(activation, value)
        self.assert_code("review_resolution_evidence_required", enroll_policy, policy,
            review_activation_paths=[activation])
        value["evidence"]["records"] = [{"reference": "host-inspection-1", "sha256": "3" * 64}]
        write_private(activation, value)
        enroll_policy(policy, review_activation_paths=[activation])
        with ReceiptStore(policy, review_credentials=credentials) as store:
            receipt, invocation, claim = claim_review(store, policy)
            store.finish_review(invocation, result(claim, status="returned"))
            store.callback_quiesced(invocation)
        enroll_policy(policy)
        with ReceiptStore(policy, review_credentials=credentials) as store:
            _, review, actor = normalized(policy)
            review["review_id"] += 1
            self.assert_code("target_action_fenced", store.reserve_review, "webhook", "repo", review, actor)

    def test_scope_and_task_rows_survive_new_policy_and_profile_epoch(self):
        policy, path, environment, document, _, _, credentials = host(self.root, task=True)
        with ReceiptStore(policy, review_credentials=credentials) as store:
            task = reserve_task(store)
            task_ticket = store.fence(task["operation_id"], "operator")
            task_invocation = store.begin_callback(task_ticket)
            store.claim_callback(task_invocation)
            task_result = store.finish(task_invocation, handler_return=True)
            store.callback_quiesced(task_invocation)
            receipt, invocation, claim = claim_review(store, policy)
            observed = store.finish_review(invocation, result(claim, status="returned"))
            store.callback_quiesced(invocation)
        with sqlite3.connect(policy.store_path) as connection:
            original = connection.execute("SELECT * FROM review_activations").fetchall()
        document["policy_id"] = "policy-2"
        document["bindings"][0]["standalone_review"]["model"]["model"] = "fixture-changed"
        write_private(path, document)
        replacement = load_policy(path, environment)
        enroll_policy(replacement)
        with ReceiptStore(replacement) as store:
            _, review, actor = normalized(replacement)
            self.assertEqual(store.reserve_review("webhook", "repo", review, actor), observed)
            self.assertEqual(reserve_task(store), task_result)
        with sqlite3.connect(policy.store_path) as connection:
            self.assertEqual(connection.execute("SELECT * FROM review_activations").fetchall(), original)

    def test_original_clock_is_fenced_before_queue_and_not_recaptured(self):
        policy, _, _, _, _, _, credentials = host(self.root)
        with ReceiptStore(policy, review_credentials=credentials) as store:
            _, review, actor = normalized(policy)
            receipt = store.reserve_review("webhook", "repo", review, actor)
            with patch("src.storage.review_receipts.time.monotonic", return_value=123.25):
                ticket = store.fence(receipt["operation_id"], "webhook")
            with patch("src.storage.review_receipts.time.monotonic", side_effect=AssertionError("clock renewed")):
                invocation = store.begin_callback(ticket)
                claim = store.review_claim(invocation, store.claim_callback(invocation))
                self.assertEqual(claim.started_at, 123.25)
                self.assertIsNone(store.fence(receipt["operation_id"], "webhook"))
            store.finish_review(invocation, result(claim, status="returned"))
            store.callback_quiesced(invocation)

    def test_receipt_identity_failure_and_unknown_facts_cannot_be_rewritten(self):
        policy, _, _, _, _, _, credentials = host(self.root)
        with ReceiptStore(policy, review_credentials=credentials) as store:
            _, invocation, claim = claim_review(store, policy)
            value = result(claim)
            claim.persist_result(value)
            changed = copy.deepcopy(value)
            changed["identity"]["review_id"] += 1
            with self.assertRaises(ReviewError):
                claim.persist_result(changed)
            value["status"] = "unknown"
            value["first_failure"] = {"code": "model_outcome_unknown", "unknown": True}
            claim.persist_result(value)
            with self.assertRaises(ReviewError):
                claim.persist_result(result(claim, status="returned"))
            observed = store.finish_review(invocation, value)
            self.assertEqual(observed["status"], "unknown")
            self.assertFalse(observed["release_authorized"])
            store.callback_quiesced(invocation)

    def test_original_retirement_survives_policy_revocation_and_store_failure(self):
        policy, path, _, document, _, _, credentials = host(self.root)
        store = ReceiptStore(policy, review_credentials=credentials)
        _, invocation, claim = claim_review(store, policy)
        document["policy_id"] = "changed"
        write_private(path, document)
        with self.assertRaises(IngressError):
            claim.validate_productive()
        claim.validate_retirement()
        with patch.object(store._owner, "verify", side_effect=IngressError("receipt_store_unavailable", 503)):
            claim.validate_retirement()
            with self.assertRaises(IngressError):
                claim.persist_result(result(claim))
        self.assert_code("callbacks_active", store.close)
        store.uncertain(invocation)
        store.callback_quiesced(invocation)
        store.close()
        with self.assertRaises(ReviewError):
            claim.validate_retirement()

    def test_changed_selected_credential_revokes_but_ambient_provider_does_not(self):
        policy, _, environment, _, _, _, credentials = host(self.root)
        snapshot = credentials["repo"]
        environment["OPENAI_API_KEY"] = "unselected-synthetic-value"
        snapshot.validate_epoch()
        self.assertIsNone(snapshot.model_key)
        environment["REVIEW_FIXTURE_TOKEN"] = "changed-selected-value"
        with self.assertRaises(IngressError):
            snapshot.validate_epoch()
        environment["REVIEW_FIXTURE_TOKEN"] = "synthetic-review-token-for-tests"
        self.assert_code("review_credentials_changed", snapshot.validate_epoch)

    def test_selected_ingress_credential_alias_refused_without_any_client(self):
        policy, _, environment, _, _, _, _ = host(self.root)
        environment["REVIEW_FIXTURE_TOKEN"] = environment["OPENJULES_INGRESS_HMAC_WEBHOOK"]
        with self.assertRaises(IngressError):
            ReviewCredentialSnapshot(policy.bindings["repo"], policy)

    def test_managed_foreign_changed_review_and_empty_commands_refused(self):
        policy, *_ = host(self.root)
        changes = [lambda e: e["pull_request"]["head"]["repo"].update(id=999),
            lambda e: e["pull_request"].update(body="<!-- openjules-publication: managed -->"),
            lambda e: e["review"].update(commit_id="3" * 40),
            lambda e: e["sender"].update(id=789), lambda e: e["review"].update(body="/jules review"),
            lambda e: e["review"].update(body=" /jules review instruction"),
            lambda e: e["review"].update(body="/jules reviewer instruction"),
            lambda e: e["pull_request"].update(body=False)]
        for change in changes:
            value = event()
            change(value)
            with self.assertRaises(IngressError):
                normalized(policy, value)

    def test_restart_never_redispatches_a_possible_original_callback(self):
        policy, path, environment, _, _, _, _ = host(self.root)
        program = """
import os,sys
from src.api.ingress_policy import load_policy
from src.api.ingress_adapter import ReviewCredentialSnapshot
from src.storage.ingress_receipts import ReceiptStore
from tests.unit.review_ingress_support import normalized
p=load_policy(sys.argv[1]); c={'repo':ReviewCredentialSnapshot(p.bindings['repo'],p)}
s=ReceiptStore(p,review_credentials=c); b,r,a=normalized(p)
receipt=s.reserve_review('webhook','repo',r,a); s.fence(receipt['operation_id'],'webhook')
os._exit(0)
"""
        child = subprocess.run([sys.executable, "-c", program, str(path)],
            env={**os.environ, **environment}, capture_output=True, text=True, timeout=10)
        self.assertEqual(child.returncode, 0, child.stderr)
        with ReceiptStore(policy) as store:
            _, review, actor = normalized(policy)
            observed = store.reserve_review("webhook", "repo", review, actor)
            self.assertEqual(observed["status"], "unknown")
            self.assertEqual(observed["code"], "owner_interrupted")
            self.assertIsNone(store.fence(observed["operation_id"], "webhook"))
            review["review_id"] += 1
            self.assert_code("target_action_fenced", store.reserve_review, "webhook", "repo", review, actor)


if __name__ == "__main__":
    unittest.main()
