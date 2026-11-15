"""Real operation accounting and closed facts, without external effects."""

import copy
from dataclasses import replace
from types import MappingProxyType
import unittest

from src.worker.review_contract import ReviewClaim, ReviewError, ReviewProfile
from src.worker.review_result import required_result_capacity, validate_result, validate_review_result
from src.worker.standalone_review import ReviewOperation


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({k: freeze(v) for k, v in value.items()})
    if type(value) is list:
        return tuple(freeze(v) for v in value)
    return value


class Credentials:
    model_key = "fixture-model-key-that-is-not-a-real-credential"
    forge = MappingProxyType({"kind": "pat", "token": "fixture-forge-token", "username": "fixture"})
    literal_secrets = (model_key, "fixture-forge-token")

    def validate_epoch(self):
        return None


def fixture(**changes):
    clock, saved = [0.0], []
    limits = {"total_ms": 1000, "cleanup_reserve_ms": 100,
              "model_call_ms": 300, "exec_call_ms": 300, "guest_api_ms": 300,
              "git_call_ms": 300, "forge_call_ms": 300,
              "agent_turns": 4, "model_calls": 8, "model_request_bytes": 20000,
              "model_request_total_bytes": 160000, "model_response_bytes": 4096,
              "model_response_total_bytes": 32768, "model_output_tokens_per_call": 128,
              "model_output_tokens_total": 1024, "exec_calls": 30, "exec_input_bytes": 20000,
              "exec_output_bytes": 8192, "exec_output_total_bytes": 245760,
              "guest_api_calls": 100, "guest_api_cleanup_calls": 6,
              "source_bytes": 100000, "source_objects": 100, "context_bytes": 10000,
              "archive_bytes": 100000, "patch_bytes": 20000, "log_bytes": 20000,
              "files": 100, "path_bytes": 512, "blob_bytes": 20000, "patch_records": 100,
              "object_bytes": 100000, "object_count": 100, "git_calls": 100,
              "git_output_bytes": 20000, "git_output_total_bytes": 2000000,
              "forge_response_bytes": 20000, "forge_response_total_bytes": 100000,
              "receipt_result_bytes": 2000000}
    limits.update(changes)
    profile = {"schema": "standalone-review-source-cas-v1", "limits": limits,
               "guest": {"test_command": "python -m unittest", "docker_endpoint": "unix:///run/docker.sock",
                         "docker_api_version": "1.45"},
               "model": {"url": "http://127.0.0.1:8080/v1/chat/completions", "model": "fixture",
                         "temperature": 0.0, "credential_ref": None}}
    original = {"operation_id": "op-fixture", "binding": {"repository_id": 7}, "request_digest": "a" * 64,
                "review": {"pull_number": 3, "review_id": 9, "head_ref": "refs/heads/topic",
                           "head_sha": "1" * 40, "instruction": "Fix the selected test."}}
    claim = ReviewClaim("op-fixture", "owner-fixture", 0.0, freeze(original),
                        ReviewProfile(freeze(profile), "b" * 64), "c" * 64, Credentials(),
                        lambda: None, lambda: None, lambda result: saved.append(copy.deepcopy(result)))
    return claim, clock, saved


class OperationTests(unittest.TestCase):
    def test_parent_deadline_only_tightens_and_is_immutable(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git", deadline=0.15)
        self.assertEqual(effect.deadline, 0.15)
        with self.assertRaises(AttributeError):
            effect.deadline = 10
        with self.assertRaises(AttributeError):
            op.work_deadline = 10
        self.assertEqual(op.reserve("git", deadline=100).deadline, 0.3)

    def test_persistence_cannot_renew_native_admission(self):
        claim, now, saved = fixture()
        def persist(value):
            saved.append(copy.deepcopy(value))
            if value["effects"]:
                now[0] = 0.901
        op = ReviewOperation(replace(claim, persist_result=persist), clock=lambda: now[0])
        effect = op.reserve("git")
        calls = []
        with self.assertRaises(ReviewError):
            op.invoke(effect, lambda: calls.append(1))
        self.assertEqual(calls, [])
        self.assertFalse(op.snapshot()["effects"][0]["entered"])
        self.assertEqual(op.snapshot()["first_failure"]["code"], "deadline_exhausted")

    def test_validator_elapsed_time_prevents_native_entry(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git")
        object.__setattr__(claim, "validate_productive", lambda: now.__setitem__(0, 0.901))
        calls = []
        with self.assertRaises(ReviewError):
            op.invoke(effect, lambda: calls.append(1))
        self.assertFalse(calls)
        self.assertFalse(op.snapshot()["effects"][0]["entered"])

    def test_effect_cannot_be_reused_or_forged(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git")
        self.assertEqual(op.invoke(effect, lambda: 4), 4)
        with self.assertRaises(ReviewError):
            op.invoke(effect, lambda: self.fail("second call"))

    def test_cleanup_subset_survives_productive_exhaustion(self):
        claim, now, _ = fixture(guest_api_calls=8)
        op = ReviewOperation(claim, clock=lambda: now[0])
        op.reserve("guest_api")
        op.reserve("guest_api")
        with self.assertRaises(ReviewError):
            op.reserve("guest_api")
        for _ in range(6):
            effect = op.reserve("guest_api", cleanup=True)
            op.invoke(effect, lambda: None)
            op.observe(effect, "acknowledged")
            op.observe(effect, "closed")
        self.assertEqual(op.snapshot()["counters"]["guest_api"], 8)
        self.assertEqual(op.snapshot()["first_failure"]["code"], "capacity_exhausted")

    def test_retirement_survives_revocation_but_not_total_deadline(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        object.__setattr__(claim, "validate_productive", lambda: (_ for _ in ()).throw(ValueError("private")))
        with self.assertRaises(ReviewError):
            op.reserve("git")
        now[0] = 0.95
        effect = op.reserve("guest_api", cleanup=True)
        self.assertEqual(effect.deadline, 1.0)
        self.assertEqual(op.invoke(effect, lambda: 1), 1)
        now[0] = 1.001
        with self.assertRaises(ReviewError):
            op.reserve("guest_api", cleanup=True)
        self.assertEqual(op.snapshot()["first_failure"]["code"], "authority_changed")
        self.assertEqual(op.snapshot()["status"], "unknown")

    def test_late_original_handle_is_returned_without_new_authority(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git")
        handle = object()
        def original():
            now[0] = 0.4
            return handle
        self.assertIs(op.invoke(effect, original), handle)
        op.observe(effect, "acknowledged")
        op.observe(effect, "closed")
        with self.assertRaises(ReviewError):
            op.reserve("git")
        self.assertTrue(op.snapshot()["effects"][0]["outcome_unknown"])
        self.assertTrue(op.snapshot()["effects"][0]["acknowledged"])

    def test_actual_overflow_retained_without_overflow_allowance(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git", response_bytes=4)
        op.invoke(effect, lambda: None)
        with self.assertRaises(ReviewError):
            op.consume(effect, response_bytes=5)
        result = op.snapshot()
        self.assertEqual(result["effects"][0]["response_bytes"], 5)
        self.assertEqual(result["effects"][0]["response_reserved"], 4)
        self.assertEqual(result["status"], "unknown")

    def test_capacity_and_cleanup_reserved_before_effect(self):
        claim, now, _ = fixture(guest_api_cleanup_calls=5)
        with self.assertRaises(ReviewError):
            ReviewOperation(claim, clock=lambda: now[0])
        claim, now, _ = fixture(receipt_result_bytes=10)
        with self.assertRaises(ReviewError):
            ReviewOperation(claim, clock=lambda: now[0])

    def test_fixed_fact_schema_rejects_paths_and_raw_output(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        with self.assertRaises(ReviewError):
            op.note("source", {"path": "/private/host"})
        self.assertNotIn("/private", repr(op.snapshot()))
        op.note("guest", {"incarnation": "original-guest"})
        with self.assertRaises(ReviewError):
            op.note("guest", {"incarnation": "replacement"})

    def test_persistence_fault_blocks_new_effect_and_keeps_first_error(self):
        claim, now, saved = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        with self.assertRaises(ReviewError):
            op.fail("source_refused")
        object.__setattr__(claim, "persist_result", lambda value: (_ for _ in ()).throw(RuntimeError("private")))
        op.note("cleanup", {"resources_retained": True})
        self.assertEqual(op.snapshot()["first_failure"]["code"], "source_refused")
        with self.assertRaises(ReviewError):
            op.reserve("guest_api")
        effect = op.reserve("guest_api", cleanup=True)
        op.invoke(effect, lambda: None)
        op.observe(effect, "acknowledged")
        op.observe(effect, "closed")
        self.assertTrue(op.snapshot()["effects"][-1]["closed"])

    def test_result_detaches_snapshots_and_never_invents_capture(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        result = op.snapshot()
        result["facts"]["guest"]["stopped"] = True
        self.assertNotIn("stopped", op.fact("guest"))
        with self.assertRaises(ReviewError):
            op.note("capture", {"durable": True})

    def test_post_return_store_failure_preserves_original_handle(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git")
        original = object()
        object.__setattr__(claim, "persist_result", lambda value: (_ for _ in ()).throw(OSError("private")))
        self.assertIs(op.invoke(effect, lambda: original), original)
        snapshot = op.snapshot()
        self.assertTrue(snapshot["effects"][0]["returned"])
        self.assertFalse(snapshot["effects"][0]["acknowledged"])
        self.assertEqual(snapshot["first_failure"]["code"], "record_unavailable")
        with self.assertRaises(ReviewError):
            op.reserve("guest_api")
        cleanup = op.reserve("guest_api", cleanup=True)
        self.assertIsNone(op.invoke(cleanup, lambda: None))
        op.observe(cleanup, "closed")

    def test_journal_projection_preserves_identity_first_error_and_effect_facts(self):
        claim, now, saved = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        before = op.snapshot()
        effect = op.reserve("git", response_bytes=10)
        op.invoke(effect, lambda: None)
        op.consume(effect, response_bytes=2)
        op.observe(effect, "acknowledged")
        after = op.snapshot()
        maximum = claim.profile.limits["receipt_result_bytes"]
        self.assertEqual(validate_review_result(after, maximum, before), after)
        for mutation in (lambda v: v.__setitem__("request_digest", "d" * 64),
                         lambda v: v["effects"][0].__setitem__("entered", False),
                         lambda v: v["effects"][0].__setitem__("deadline_ms", 800),
                         lambda v: v["counters"].__setitem__("git", 0)):
            invalid = copy.deepcopy(after)
            mutation(invalid)
            with self.assertRaises(ReviewError):
                validate_review_result(invalid, maximum, after)
        with self.assertRaises(ReviewError):
            op.fail("source_refused")
        failed = op.snapshot()
        invalid = copy.deepcopy(failed)
        invalid["first_failure"] = {"code": "protocol_refused", "unknown": False}
        with self.assertRaises(ReviewError):
            validate_review_result(invalid, maximum, failed)
        previous = None
        for saved_result in saved:
            validate_review_result(saved_result, maximum, previous)
            previous = saved_result

    def test_cleanup_facts_can_release_retained_resources_in_one_observation(self):
        claim, now, saved = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        op.note("cleanup", {"resources_retained": True})
        previous = op.snapshot()
        op.note("cleanup", {"container_removed": True, "volume_removed": True,
                            "local_processes_closed": True, "local_exchanges_closed": True,
                            "resources_retained": False})
        validate_review_result(op.snapshot(), claim.profile.limits["receipt_result_bytes"], previous)

    def test_finished_operation_and_closed_reservation_cannot_enter(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        op.finish()
        for cleanup in (False, True):
            with self.assertRaises(ReviewError):
                op.reserve("guest_api", cleanup=cleanup)
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git")
        op.observe(effect, "closed")
        calls = []
        with self.assertRaises(ReviewError):
            op.invoke(effect, lambda: calls.append(1))
        self.assertEqual(calls, [])
        self.assertFalse(op.snapshot()["effects"][0]["entered"])

    def test_finish_never_calls_pending_local_work_closed(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        effect = op.reserve("git")
        op.invoke(effect, lambda: None)
        result = op.finish()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["first_failure"]["code"], "cleanup_unconfirmed")
        self.assertFalse(result["effects"][0]["closed"])

    def test_store_failure_never_bypasses_original_retirement_deadline_or_owner(self):
        claim, now, _ = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        object.__setattr__(claim, "persist_result", lambda value: (_ for _ in ()).throw(OSError()))
        op.note("cleanup", {"resources_retained": True})
        effect = op.reserve("guest_api", cleanup=True)
        now[0] = 1.001
        calls = []
        with self.assertRaises(ReviewError):
            op.invoke(effect, lambda: calls.append(1))
        self.assertEqual(calls, [])
        self.assertEqual(op.snapshot()["first_failure"]["code"], "record_unavailable")


if __name__ == "__main__":
    unittest.main()
