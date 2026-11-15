"""Restricted orchestration against controlled ports, no provider or daemon."""

import copy
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tempfile
import threading
import unittest

from src.agent.standalone_review_engine import tool_command
from src.worker.review_contract import (
    OriginalReviewGuest, PreparedReviewSource, ReviewCandidate, ReviewCapture,
    ReviewError, ReviewExecObservation, ReviewPublication,
)
from src.worker.review_result import validate_review_result
from src.worker.standalone_review import ReviewOperation, StandaloneReviewAdapter
from src.worker.standalone_review_model import StandaloneReviewModel
from tests.unit.test_standalone_review_operation import fixture
from tests.unit.test_standalone_review_model import Client, HTTPFixture, reply


PLAN = json.dumps({"rationale": "Fix the requested file.", "target_files": ["demo.txt"],
                   "planned_tests": ["python -m unittest"], "action_steps": ["Edit", "Verify"]})


def call(identifier, name, arguments):
    return {"id": identifier, "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)}}


class SequenceClient(Client):
    async def send(self, request, *, stream):
        self.fixture.chunks = [self.fixture.responses.pop(0)]
        return await super().send(request, stream=stream)


class SequenceHTTP(HTTPFixture):
    def __init__(self, responses):
        super().__init__()
        self.responses = list(responses)

    def factory(self, **kwargs):
        return SequenceClient(self, kwargs)


class NativeFixture:
    """Every admitted fixture effect uses the real original operation facade."""

    def __init__(self, claim):
        self.claim = claim
        self.events, self.commands = [], []
        self.guest = None
        self.no_change = False
        self.verification_exit = 0
        self.prove_stop = True
        self.publish_status = "acknowledged"
        self.revoke_before_publication = False
        self.retire_started = self.retire_release = None

    def effect(self, op, kind, *, cleanup=False, deadline=None):
        effect = op.reserve(kind, cleanup=cleanup, deadline=deadline)
        op.invoke(effect, lambda: None)
        op.observe(effect, "acknowledged")
        op.observe(effect, "closed")
        return effect

    def check_original(self, op, *, phase):
        self.events.append(phase)
        if phase == "publication" and self.revoke_before_publication:
            object.__setattr__(self.claim, "validate_productive", lambda: (_ for _ in ()).throw(ReviewError("authority_changed")))
        for _ in range(2):
            self.effect(op, "forge_get")

    def prepare_source(self, op):
        self.events.append("source")
        self.effect(op, "git")
        source = PreparedReviewSource(object(), "1" * 40, "2" * 40, "3" * 64, 12, "README: fixture source.")
        op.note("source", {"base_sha": source.base_sha, "tree_sha": source.tree_sha,
                           "snapshot_sha256": source.snapshot_sha256, "source_bytes": source.source_bytes,
                           "source_objects": 1})
        return source

    def create_guest(self, op, source):
        self.events.append("guest")
        for _ in range(3):
            self.effect(op, "guest_api")
        self.guest = OriginalReviewGuest(object(), "original-guest")
        op.note("guest", {"incarnation": self.guest.incarnation, "container_id": "original-container",
                          "volume_name": "original-volume", "create_entered": True, "create_acknowledged": True,
                          "start_entered": True, "start_acknowledged": True, "retained": True})
        return self.guest

    def execute(self, op, guest, command):
        if guest is not self.guest:
            op.fail("protocol_refused")
        self.events.append("exec")
        self.commands.append(command)
        logical = op.reserve("exec", request_bytes=len(command.encode()), response_bytes=100)
        def execute_original():
            for _ in range(3):
                self.effect(op, "guest_api", deadline=logical.deadline)
            return b"fixture guest output"
        output = op.invoke(logical, execute_original)
        op.consume(logical, response_bytes=len(output))
        code = self.verification_exit if command == self.claim.profile.document["guest"]["test_command"] else 0
        op.observe(logical, "acknowledged", data={"exit_code": code})
        op.observe(logical, "closed", data={"local_closed": True})
        return ReviewExecObservation("exec-" + str(logical.id), code, output, True)

    def stop_and_capture(self, op, guest):
        self.events.append("capture")
        for _ in range(3):
            self.effect(op, "guest_api", cleanup=True)
        patch, log = b"bounded fixture patch", b"bounded fixture log"
        capture = ReviewCapture(object(), "original-capture", "a" * 64, 60,
                                hashlib.sha256(patch).hexdigest(), patch,
                                hashlib.sha256(log).hexdigest(), log, "b" * 64)
        if self.prove_stop:
            op.note("guest", {"stopped": True, "local_closed": True})
            op.note("capture", {"retained_id": capture.retained_id, "container_id": "original-container",
                                "archive_sha256": capture.archive_sha256, "archive_bytes": capture.archive_bytes,
                                "patch_sha256": capture.patch_sha256, "patch_bytes": len(patch),
                                "log_sha256": capture.log_sha256, "log_bytes": len(log),
                                "manifest_sha256": capture.manifest_sha256, "durable": True, "termination_confirmed": True})
        return capture

    def compose(self, op, source, capture):
        self.events.append("compose")
        self.effect(op, "git")
        candidate = ReviewCandidate(object(), source.base_sha, source.tree_sha if self.no_change else "5" * 40,
                                    None if self.no_change else "4" * 40)
        op.note("candidate", {"parent_sha": candidate.parent_sha, "tree_sha": candidate.tree_sha,
                              "commit_sha": candidate.commit_sha, "no_change": self.no_change})
        return candidate

    def publish(self, op, candidate):
        self.events.append("publish")
        self.effect(op, "git")
        op.note("publication", {"status": self.publish_status, "original_ref": "refs/heads/topic",
                                "expected_head": "1" * 40, "candidate_sha": candidate.commit_sha,
                                "invoked": True, "local_closed": True})
        return ReviewPublication(self.publish_status, True)

    def retire(self, op):
        self.events.append("retire")
        if self.retire_started:
            self.retire_started.set()
            self.retire_release.wait(2)
        if self.guest is not None:
            for _ in range(3):
                self.effect(op, "guest_api", cleanup=True)
            op.note("cleanup", {"container_removed": True, "volume_removed": True, "auth_removed": True,
                                "local_processes_closed": True, "local_exchanges_closed": True,
                                "resources_retained": False})
            op.note("guest", {"retained": False})


class EngineTests(unittest.TestCase):
    def setup_adapter(self, responses=None, **limits):
        claim, now, saved = fixture(**limits)
        native = NativeFixture(claim)
        http = SequenceHTTP(responses or [reply(PLAN), reply("TASK_COMPLETED")])
        model = StandaloneReviewModel(client_factory=http.factory)
        adapter = StandaloneReviewAdapter(native_factory=lambda original: native,
                                          model_factory=lambda: model, clock=lambda: now[0])
        return claim, now, saved, native, http, adapter

    def test_actual_restricted_loop_and_fixed_verification_before_host_publication(self):
        commands = [call("write-one", "write_file", {"path": "demo.txt", "content": "changed\n"}),
                    call("inspect-one", "run_command", {"command": "cat demo.txt"})]
        claim, now, saved, native, http, adapter = self.setup_adapter([
            reply(PLAN), reply(None, calls=commands), reply("TASK_COMPLETED")])
        self.assertFalse(native.events)
        result = adapter(claim.original, claim)
        self.assertEqual(result["status"], "returned")
        self.assertEqual(native.events, ["initial", "source", "guest", "exec", "exec", "exec",
                                         "capture", "compose", "publication", "publish", "retire"])
        self.assertEqual(native.commands[-1], claim.profile.document["guest"]["test_command"])
        self.assertEqual(result["facts"]["publication"]["status"], "acknowledged")
        self.assertEqual(result["facts"]["verification"]["exit_code"], 0)
        self.assertEqual(result["counters"]["model"], 3)
        self.assertEqual(len(http.calls), 3)
        self.assertNotIn("tools", json.loads(http.calls[0][0][2]["content"]))
        self.assertEqual(len(json.loads(http.calls[1][0][2]["content"])["tools"]), 5)
        previous = None
        for snapshot in saved:
            validate_review_result(snapshot, claim.profile.limits["receipt_result_bytes"], previous)
            previous = snapshot

    def test_model_completion_never_substitutes_for_actual_verification(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        native.verification_exit = 1
        result = adapter(claim.original, claim)
        self.assertEqual(result["first_failure"]["code"], "verification_failed")
        self.assertEqual(native.commands, [claim.profile.document["guest"]["test_command"]])
        self.assertNotIn("compose", native.events)
        self.assertNotIn("publish", native.events)
        self.assertEqual(native.events[-1], "retire")

    def test_capture_dataclass_is_not_stop_or_durability_proof(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        native.prove_stop = False
        result = adapter(claim.original, claim)
        self.assertEqual(result["first_failure"]["code"], "capture_refused")
        self.assertNotIn("compose", native.events)
        self.assertNotIn("publish", native.events)
        self.assertNotIn("stopped", result["facts"]["guest"])

    def test_empty_change_and_already_candidate_are_not_publication(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        native.no_change = True
        result = adapter(claim.original, claim)
        self.assertEqual(result["status"], "returned")
        self.assertEqual(result["facts"]["publication"], {})
        self.assertNotIn("publication", native.events)
        self.assertEqual(result["counters"]["forge_get"], 2)
        claim, now, saved, native, http, adapter = self.setup_adapter()
        native.publish_status = "observed_no_update"
        result = adapter(claim.original, claim)
        self.assertEqual(result["facts"]["publication"]["status"], "observed_no_update")
        self.assertEqual(native.events.count("publish"), 1)

    def test_bad_plan_and_text_tool_fallback_never_execute(self):
        for responses in ([reply("not a plan")], [reply(PLAN), reply('{"tool":"run_command","arguments":{"command":"true"}}')]):
            claim, now, saved, native, http, adapter = self.setup_adapter(responses)
            result = adapter(claim.original, claim)
            self.assertEqual(result["first_failure"]["code"], "model_refused")
            self.assertEqual(native.commands, [])
            self.assertNotIn("publish", native.events)
            self.assertEqual(native.events[-1], "retire")

    def test_decoded_plan_and_direct_tool_inputs_are_literal_checked(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        secret = claim.credentials.model_key
        escaped = "".join("\\u%04x" % ord(char) for char in secret)
        encoded_plan = '{"rationale":"' + escaped + '","target_files":[],"planned_tests":[],"action_steps":[]}'
        wire = reply(encoded_plan)
        self.assertNotIn(secret.encode(), wire)
        http.responses = [wire]
        result = adapter(claim.original, claim)
        self.assertEqual(result["first_failure"]["code"], "secret_in_data")
        self.assertEqual(native.commands, [])
        self.assertEqual(len(http.calls), 1)
        claim, now, _ = fixture()
        operation = ReviewOperation(claim, clock=lambda: now[0])
        with self.assertRaises(ReviewError):
            tool_command(operation, "write_file", {"path": "demo.txt", "content": claim.credentials.model_key})
        self.assertEqual(operation.snapshot()["first_failure"]["code"], "secret_in_data")
        self.assertEqual(operation.snapshot()["effects"], [])

    def test_entire_tool_reply_validated_before_first_command(self):
        calls = [call("one", "run_command", {"command": "true"}),
                 call("two", "write_file", {"path": "../outside", "content": "bad"})]
        claim, now, saved, native, http, adapter = self.setup_adapter([reply(PLAN), reply(None, calls=calls)])
        result = adapter(claim.original, claim)
        self.assertEqual(result["first_failure"]["code"], "protocol_refused")
        self.assertEqual(native.commands, [])

    def test_turn_limit_is_not_a_default_plan_or_extra_model_allowance(self):
        calls = [call("one", "run_command", {"command": "true"})]
        claim, now, saved, native, http, adapter = self.setup_adapter([reply(PLAN), reply(None, calls=calls)], agent_turns=1)
        result = adapter(claim.original, claim)
        self.assertEqual(result["first_failure"]["code"], "capacity_exhausted")
        self.assertEqual(len(http.calls), 2)
        self.assertEqual(native.commands, ["true"])
        self.assertNotIn("publish", native.events)

    def test_original_callback_waits_for_its_native_retirement(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        native.retire_started, native.retire_release = threading.Event(), threading.Event()
        results = []
        thread = threading.Thread(target=lambda: results.append(adapter(claim.original, claim)))
        thread.start()
        self.assertTrue(native.retire_started.wait(2))
        now[0] = 1.1
        self.assertTrue(thread.is_alive())
        self.assertEqual(results, [])
        native.retire_release.set()
        thread.join(2)
        self.assertFalse(thread.is_alive())
        self.assertEqual(results[0]["status"], "unknown")
        self.assertEqual(native.events.count("publish"), 1)
        self.assertEqual(results[0]["facts"]["publication"]["status"], "acknowledged")

    def test_replacement_original_refuses_before_factory_or_persistence(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        with self.assertRaises(ReviewError):
            adapter(dict(claim.original), claim)
        self.assertEqual(native.events, [])
        self.assertEqual(saved, [])

    def test_original_queue_age_prevents_effectful_factory_entry(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        now[0] = 0.901
        created = []
        adapter = StandaloneReviewAdapter(native_factory=lambda value: created.append(value), clock=lambda: now[0])
        result = adapter(claim.original, claim)
        self.assertEqual(result["first_failure"]["code"], "deadline_exhausted")
        self.assertEqual(created, [])
        self.assertEqual(result["effects"], [])

    def test_revocation_after_capture_retains_capture_and_prevents_publication(self):
        claim, now, saved, native, http, adapter = self.setup_adapter()
        native.revoke_before_publication = True
        result = adapter(claim.original, claim)
        self.assertEqual(result["first_failure"]["code"], "authority_changed")
        self.assertIs(result["facts"]["capture"]["durable"], True)
        self.assertNotIn("publish", native.events)
        self.assertEqual(result["counters"]["forge_get"], 2)
        self.assertIs(result["facts"]["cleanup"]["container_removed"], True)

    def test_guest_tool_quoting_and_original_file_semantics_in_controlled_process(self):
        claim, now, saved = fixture()
        op = ReviewOperation(claim, clock=lambda: now[0])
        with tempfile.TemporaryDirectory(dir=os.getcwd()) as directory:
            content = "literal $(touch injected) 'quoted' \"double\"\n"
            for name, args in [
                ("write_file", {"path": "nested/demo.txt", "content": content}),
                ("read_file", {"path": "nested/demo.txt", "offset": 1, "limit": 2}),
                ("list_files", {"directory": ".", "max_depth": 3}),
                ("apply_patch", {"path": "nested/demo.txt", "patch_str": "<<<<<<< SEARCH\n" + content + "=======\nchanged\n>>>>>>> REPLACE\n"}),
            ]:
                command = tool_command(op, name, args)
                process = subprocess.run(command, shell=True, cwd=directory, capture_output=True, timeout=2)
                self.assertEqual(process.returncode, 0, process.stderr)
            self.assertEqual(Path(directory, "nested/demo.txt").read_text(), "changed\n")
            self.assertFalse(Path(directory, "injected").exists())
        self.assertEqual(op.snapshot()["effects"], [])  # This test does not claim a daemon effect.


if __name__ == "__main__":
    unittest.main()
