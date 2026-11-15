"""Original producer identities and one selected credential, with no forge IO."""
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest import mock

from tests.unit.review_native_fixture import fixture, freeze, producer_payloads
from src.worker.review_contract import ReviewError
from src.worker.review_github import OriginalHTTPReply
from src.worker.review_native import ReviewNativeBackend
from src.worker.standalone_review import ReviewOperation


class OriginalForgeFixture:
    """Counted fixed replies, deliberately replacing only the external forge."""
    def __init__(self, backend, responses):
        self.backend, self.responses, self.requests = backend, list(responses), []

    def request(self, operation, kind, method, path, payload, headers):
        effect = operation.reserve(kind, response_bytes=operation.limits["forge_response_bytes"])
        self.requests.append({"kind": kind, "method": method, "path": path, "payload": payload, "headers": headers})
        original = {"effect": effect, "request_entered": False, "validated": False, "closed": False, "socket": None}
        self.backend.connections.append(original)
        def entered():
            original["request_entered"] = True
            status, value = self.responses.pop(0)
            return status, value if type(value) is bytes else json.dumps(value).encode()
        status, raw = operation.invoke(effect, entered)
        operation.consume(effect, response_bytes=len(raw))
        original["closed"] = True
        operation.observe(effect, "closed", data={"local_closed": True})
        return OriginalHTTPReply(status, raw, effect, False, original)


class ProducerTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.claim, self.operation, _, _ = fixture(Path(self.temp.name))
        self.backend = ReviewNativeBackend(self.claim)

    def tearDown(self):
        if self.backend.operation is not None and not self.backend.retiring:
            self.backend.retire(self.operation)
        self.temp.cleanup()

    def forge(self, responses):
        service = OriginalForgeFixture(self.backend, responses)
        self.backend.github.request = service.request
        return service

    def test_constructor_creates_no_client_process_or_transport(self):
        with mock.patch("src.worker.review_native.socket.socket") as socket, \
             mock.patch("src.git_manager.review_publication.subprocess.Popen") as process:
            ReviewNativeBackend(self.claim)
        socket.assert_not_called()
        process.assert_not_called()

    def test_original_four_gets_and_pat_without_any_mint_or_payload_url(self):
        pull, review = producer_payloads(self.claim)
        pull["url"] = "https://unselected.invalid/never"
        review["url"] = "https://unselected.invalid/never"
        service = self.forge([(200, pull), (200, review), (200, pull), (200, review)])
        self.backend.check_original(self.operation, phase="initial")
        # The separate capture/candidate gates are tested through the real ports.
        self.backend.capture = self.backend.candidate = object()
        self.backend.check_original(self.operation, phase="publication")
        self.assertEqual([row["path"] for row in service.requests],
                         ["/repos/fixture/project/pulls/3", "/repos/fixture/project/pulls/3/reviews/9"] * 2)
        self.assertEqual(self.operation.snapshot()["counters"]["forge_get"], 4)
        self.assertEqual(self.operation.snapshot()["counters"]["forge_token"], 0)
        self.assertTrue(all(row["acknowledged"] for row in self.operation.snapshot()["effects"]))
        with self.assertRaises(ReviewError):
            self.backend.check_original(self.operation, phase="publication")
        self.assertEqual(len(service.requests), 4)

    def test_changed_head_ref_fork_review_body_author_commit_and_state_refuse(self):
        changes = [("pull", lambda value: value["head"].update(sha="e" * 40)),
                   ("pull", lambda value: value["head"].update(ref="other")),
                   ("pull", lambda value: value["head"]["repo"].update(id=88)),
                   ("pull", lambda value: value.update(body="<!-- openjules-publication: forbidden -->")),
                   ("review", lambda value: value.update(body=value["body"] + " changed")),
                   ("review", lambda value: value["user"].update(id=11)),
                   ("review", lambda value: value.update(commit_id="f" * 40)),
                   ("review", lambda value: value.update(state="APPROVED"))]
        for index, (kind, change) in enumerate(changes):
            root = Path(self.temp.name) / str(index)
            root.mkdir()
            claim, op, _, _ = fixture(root)
            backend = ReviewNativeBackend(claim)
            pull, review = producer_payloads(claim)
            change(pull if kind == "pull" else review)
            service = OriginalForgeFixture(backend, [(200, pull), (200, review)])
            backend.github.request = service.request
            with self.assertRaises(ReviewError):
                backend.check_original(op, phase="initial")
            self.assertFalse(backend.original_checked)
            self.assertFalse(op.snapshot()["effects"][-1]["acknowledged"])
            self.assertTrue(op.snapshot()["effects"][-1]["outcome_unknown"])
            self.assertEqual(len(service.requests), 1 if kind == "pull" else 2)
            backend.retire(op)

    def test_decoding_or_validation_past_call_deadline_cannot_admit_second_get(self):
        now = [0.0]
        claim = replace(self.claim, started_at=0.0)
        operation = ReviewOperation(claim, clock=lambda: now[0])
        backend = ReviewNativeBackend(claim)
        pull, review = producer_payloads(claim)
        service = OriginalForgeFixture(backend, [(200, pull), (200, review)])
        backend.github.request = service.request
        original = backend.github.validate_pull
        def late(value):
            original(value)
            now[0] = 5.001
        with mock.patch.object(backend.github, "validate_pull", side_effect=late):
            with self.assertRaises(ReviewError) as caught:
                backend.check_original(operation, phase="initial")
        self.assertEqual(caught.exception.code, "deadline_exhausted")
        self.assertEqual(len(service.requests), 1)
        self.assertFalse(operation.snapshot()["effects"][0]["acknowledged"])
        self.assertTrue(operation.snapshot()["effects"][0]["outcome_unknown"])
        backend.retire(operation)

    def test_revocation_during_validated_reply_preserves_first_error_and_unknown(self):
        pull, review = producer_payloads(self.claim)
        service = self.forge([(200, pull), (200, review)])
        original = self.backend.github.validate_pull
        def revoked(value):
            original(value)
            object.__setattr__(self.claim, "validate_productive",
                               lambda: (_ for _ in ()).throw(ValueError("private authority reason")))
        with mock.patch.object(self.backend.github, "validate_pull", side_effect=revoked):
            with self.assertRaises(ReviewError) as caught:
                self.backend.check_original(self.operation, phase="initial")
        self.assertEqual(caught.exception.code, "authority_changed")
        result = self.operation.snapshot()
        self.assertEqual(result["first_failure"]["code"], "authority_changed")
        self.assertTrue(result["effects"][0]["closed"])
        self.assertTrue(result["effects"][0]["outcome_unknown"])
        self.assertFalse(result["effects"][0]["acknowledged"])
        self.assertEqual(len(service.requests), 1)

    def app_claim(self):
        from cryptography.hazmat.primitives.asymmetric import rsa
        from cryptography.hazmat.primitives.serialization import Encoding, PrivateFormat, NoEncryption
        key = rsa.generate_private_key(public_exponent=65537, key_size=2048).private_bytes(
            Encoding.PEM, PrivateFormat.PKCS8, NoEncryption()).decode()
        class AppCredentials:
            forge = freeze({"kind": "app", "app_id": 2, "installation_id": 8,
                            "private_key": key, "username": "x-access-token"})
            model_key = None
            literal_secrets = (key,)
            def validate_epoch(self):
                return None
        return replace(self.claim, credentials=AppCredentials())

    def test_one_selected_app_mint_exact_repository_permissions_and_no_remint(self):
        claim = self.app_claim()
        operation, backend = ReviewOperation(claim), ReviewNativeBackend(claim)
        pull, review = producer_payloads(claim)
        token = "ephemeral-fixture-installation-token"
        minted = {"token": token, "expires_at": "2099-01-01T00:00:00Z", "repository_selection": "selected",
                  "permissions": {"contents": "write", "pull_requests": "read", "metadata": "read"},
                  "repositories": [{"id": 7}]}
        service = OriginalForgeFixture(backend, [(201, minted), (200, pull), (200, review), (200, pull), (200, review)])
        backend.github.request = service.request
        backend.check_original(operation, phase="initial")
        backend.capture = backend.candidate = object()
        backend.check_original(operation, phase="publication")
        self.assertEqual(service.requests[0]["method"], "POST")
        self.assertEqual(service.requests[0]["path"], "/app/installations/8/access_tokens")
        self.assertEqual(service.requests[0]["payload"], {"repository_ids": [7], "permissions": {"contents": "write", "pull_requests": "read"}})
        self.assertEqual(operation.snapshot()["counters"]["forge_token"], 1)
        self.assertEqual(operation.snapshot()["counters"]["forge_get"], 4)
        self.assertNotIn(token, json.dumps(operation.snapshot()))
        with self.assertRaises(ReviewError):
            operation.assert_safe(token.encode())
        backend.retire(operation)

    def test_mint_rejection_keeps_selected_secret_and_never_falls_back_or_retries(self):
        claim = self.app_claim()
        operation, backend = ReviewOperation(claim), ReviewNativeBackend(claim)
        token = "rejected-fixture-installation-token"
        service = OriginalForgeFixture(backend, [(201, {"token": token, "permissions": {"contents": "admin"}})])
        backend.github.request = service.request
        with self.assertRaises(ReviewError):
            backend.check_original(operation, phase="initial")
        self.assertEqual(len(service.requests), 1)
        self.assertFalse(operation.snapshot()["effects"][0]["acknowledged"])
        self.assertIsNone(backend.github.token)
        self.assertIn(token.encode(), operation._secrets)
        with self.assertRaises(ReviewError):
            backend.github.credential(operation)
        self.assertEqual(len(service.requests), 1)
        backend.retire(operation)


if __name__ == "__main__":
    unittest.main()
