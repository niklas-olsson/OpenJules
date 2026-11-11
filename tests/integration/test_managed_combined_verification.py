"""A composed tree must pass its own configured check.

Real Docker execution, Git, Unix sockets and retained host journals are used.
The provider and canonical authority are named protocol fixtures. Reopening the
service objects below is not a new OS process or a live Polyphony restart.
"""

from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import tarfile

import pytest

from tests.integration.test_managed_agent_container import agent_image  # noqa: F401
from tests.integration.test_managed_children_runtime import (
    CHILD_VERIFY,
    child_stack,
    reopen_stack,
    wait_complete,
)
from tests.unit.test_managed_agent import message, provider, response

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OPENJULES_MANAGED_DOCKER_TESTS") != "1",
        reason="real managed Docker qualification requires explicit opt-in",
    ),
]

# Both isolated children and their parent execute this identical semantic check.
# Each child's private tree has one implementation; the exact union has two.
VERIFY = """import json,pathlib,unittest
class CombinedVerification(unittest.TestCase):
    def test_at_most_one_implementation(self):
        states=[]
        for name in ('left','right'):
            content=pathlib.Path(name+'.txt').read_text()
            self.assertIn(content,('old\\n',name+' implemented\\n'))
            states.append(int(content==name+' implemented\\n'))
        print(json.dumps({'verification_inputs':states}),flush=True)
        self.assertLessEqual(sum(states),1,'COMBINED_IMPLEMENTATION_LIMIT')
unittest.main(verbosity=1)
"""


def verification_event(log):
    events = []
    for line in log.splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue  # The same retained log also contains Git command output.
        if isinstance(value, dict) and value.get("event") == "configured_verification":
            events.append(value)
    assert len(events) == 1, log
    assert events[0]["state"] == "exited", events[0]
    return events[0]


def verification_inputs(event):
    values = []
    for line in event["output"].splitlines():
        try:
            value = json.loads(line)
        except json.JSONDecodeError:
            continue
        if isinstance(value, dict) and set(value) == {"verification_inputs"}:
            values.append(value["verification_inputs"])
    assert len(values) == 1, event
    return values[0]


def retained_state(stack):
    """Read original identities, captures and budgets, excluding live countdowns."""
    with stack.broker.connection() as db:
        workers = [
            dict(row) for row in db.execute("SELECT * FROM workers ORDER BY worker_id")
        ]
        calls = [dict(row) for row in db.execute("SELECT * FROM calls ORDER BY rowid")]
    return {
        "runtime": dict(stack.runtime._row(stack.worker_id, stack.spec)),
        "attempt": dict(stack.runtime._attempt(stack.worker_id)),
        "delivery": dict(stack.dispatcher.journal.get(stack.worker_id)),
        "child_worker": stack.children.journal.worker(stack.worker_id),
        "children": stack.children.journal.children(stack.worker_id),
        "model_workers": workers,
        "model_calls": calls,
        "canonical": deepcopy(
            {
                "claims": stack.authority.claims,
                "candidate_attempts": stack.authority.candidates,
                "artifacts": stack.authority.artifacts,
                "terminal_receipts": stack.authority.terminals,
                "events": stack.authority.events,
                "children": stack.child_authority.records,
                "turns": stack.child_authority.turns,
                "admission_closed": stack.child_authority.closed,
            }
        ),
    }


def test_passing_children_with_failed_combined_check_retain_capture_without_candidate(
    tmp_path, monkeypatch, agent_image
):
    root_turn = 0
    child_turns = {"left": 0, "right": 0}
    child_ids = []
    patches = []

    def deterministic(handler, requests):
        nonlocal root_turn
        messages = requests[-1]["body"]["messages"]
        initial = messages[1]["content"]
        if initial.startswith("CHILD_"):
            name = "left" if initial.startswith("CHILD_left:") else "right"
            assert initial.startswith("CHILD_" + name + ":")
            child_turns[name] += 1
            assert child_turns[name] <= 2
            answer = (
                message(
                    "write_file", path=name + ".txt", content=name + " implemented\n"
                )
                if child_turns[name] == 1
                else message("finish", summary="Verify the isolated " + name + " tree")
            )
        else:
            assert initial.startswith("ROOT_COMPOSE:")
            root_turn += 1
            if root_turn in {2, 3}:
                child_ids.append(json.loads(messages[-1]["content"])["child_id"])
            if root_turn in {4, 5}:
                value = json.loads(messages[-1]["content"])
                assert value["final"] is False
                assert value["artifact_sha256"] == hashlib.sha256(
                    value["content"].encode()
                ).hexdigest()
                patches.append(value["content"])
            if root_turn <= 2:
                name = "left" if root_turn == 1 else "right"
                answer = message(
                    "spawn_child",
                    instructions="CHILD_" + name + ": change only " + name + ".txt",
                    seconds=35,
                    max_turns=3,
                    capabilities=["python"],
                )
            elif root_turn in {3, 4}:
                answer = message(
                    "child_result", child_id=child_ids[root_turn - 3], kind="patch"
                )
            elif root_turn == 5:
                assert len(patches) == 2 and all(patches)
                # The parent applies only the two actual returned child patches.
                script = "import pathlib,subprocess\n"
                script += (
                    "subprocess.run(['git','apply','-'],input="
                    + repr("".join(patches))
                    + ",text=True,check=True)\n"
                )
                for name in ("left", "right"):
                    script += (
                        "assert pathlib.Path("
                        + repr(name + ".txt")
                        + ").read_text()=="
                        + repr(name + " implemented\n")
                        + "\n"
                    )
                script += "print('ROOT_COMPOSED_EXACT_CHILD_UNION')\n"
                answer = message("run_command", argv=["python3", "-I", "-c", script])
            else:
                result = json.loads(messages[-1]["content"])
                assert root_turn == 6 and result["state"] == "exited"
                assert result["exit_code"] == 0
                assert "ROOT_COMPOSED_EXACT_CHILD_UNION" in result["output"]
                answer = message(
                    "finish", summary="Run the configured check on the combined tree"
                )
        response(handler, answer)

    with provider(deterministic) as (endpoint, requests):
        with child_stack(
            tmp_path,
            monkeypatch,
            agent_image,
            endpoint,
            root_verify_argv=("python3", "-I", "-c", VERIFY),
            child_verify_argv=("python3", "-I", "-c", CHILD_VERIFY + "\n" + VERIFY),
        ) as stack:
            # Authority.candidates appends every candidate-method attempt. The
            # existing successful real-child test exercises its len == 1 control.
            assert stack.authority.candidates == []
            wait_complete(stack)
            root = stack.children.journal.context(stack.worker_id)
            children = stack.children.journal.children(stack.worker_id)
            assert [child["child_id"] for child in children] == child_ids
            assert len(children) == 2 and {child["uid"] for child in children} == {
                60000,
                60001,
            }
            receipt = stack.runtime.inspect_attempt(
                stack.worker_id, stack.spec, root.attempt_id
            )
            assert receipt.state == "exited" and receipt.exit_code == 3, receipt.log
            assert (
                receipt.termination_confirmed
                and receipt.launch_fenced
                and receipt.artifacts_captured
            )
            root_verification = verification_event(receipt.log)
            assert root_verification["exit_code"] == 1, root_verification
            assert verification_inputs(root_verification) == [1, 1]
            assert "COMBINED_IMPLEMENTATION_LIMIT" in root_verification["output"]
            assert "FAILED (failures=1)" in root_verification["output"]
            assert receipt.patch == "".join(patches)

            for index, child in enumerate(children):
                assert child["phase"] == "completed" and child["exit_code"] == 0
                captured = json.loads(child["capture"])
                assert captured["state"] == "exited"
                contents = captured["contents"]
                assert contents["patch"] == patches[index]
                event = verification_event(contents["log"])
                assert event["exit_code"] == 0, event
                assert verification_inputs(event) == (
                    [1, 0] if index == 0 else [0, 1]
                )
                assert (
                    "CHILD_IDENTITY_VERIFIED uid=" + str(child["uid"])
                    in event["output"]
                )
                assert "OK" in event["output"]
                manifest = json.loads(contents["manifest"])
                assert manifest["archive_sha256"] == receipt.capture_sha256
                assert manifest["termination_method"] == "whole-container fence"
                assert manifest["exec_id"] == child["exec_id"]
                assert manifest["exec_start_dispatched"] is True
                assert manifest["termination_confirmed"] is True
                assert manifest["launch_fenced"] is True
                canonical = next(
                    record
                    for record in stack.child_authority.records.values()
                    if record["response"]["binding"]["child_id"] == child["child_id"]
                )
                assert canonical["terminal"] is True
                assert canonical["artifacts"] == contents

            # The root failure still delivers immutable terminal capture after
            # both child receipts, without requesting a canonical candidate.
            observed = stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)
            assert observed["termination_confirmed"] and observed["artifacts_captured"]
            assert observed["admission_open"] is False
            assert observed["active_executions"] == []
            assert stack.child_authority.closed is True
            assert len(stack.authority.claims) == 1
            assert stack.authority.candidates == []
            events = [event for event, _ in stack.authority.events]
            assert events[:2] == ["child_terminal", "child_terminal"]
            assert events[-1] == "root_terminal"
            assert stack.authority.artifacts == {
                "patch": receipt.patch,
                "log": receipt.log,
                "manifest": (
                    receipt.manifest
                    if isinstance(receipt.manifest, str)
                    else json.dumps(
                        receipt.manifest, sort_keys=True, separators=(",", ":")
                    )
                ),
            }
            assert root_turn == 6 and child_turns == {"left": 2, "right": 2}
            assert len(requests) == 10 and len(stack.child_authority.turns) == 4

            archive = Path(receipt.capture_path).read_bytes()
            assert hashlib.sha256(archive).hexdigest() == receipt.capture_sha256
            with tarfile.open(receipt.capture_path) as captured:
                for index, name in enumerate(("left", "right")):
                    assert captured.extractfile(
                        "workspace/run/repo/" + name + ".txt"
                    ).read() == (name + " implemented\n").encode()
                    assert (stack.source / (name + ".txt")).read_text() == "old\n"
                    for child_index, child in enumerate(children):
                        expected = (
                            name + " implemented\n"
                            if index == child_index
                            else "old\n"
                        )
                        assert captured.extractfile(
                            "workspace/children/"
                            + child["child_id"]
                            + "/run/repo/"
                            + name
                            + ".txt"
                        ).read() == expected.encode()
            container = stack.client.containers.get(
                stack.runtime._name(stack.worker_id)
            )
            container.reload()
            assert container.attrs["State"]["Running"] is False

            retained = retained_state(stack)
            assert len(retained["model_calls"]) == 10
            assert all(row["status"] == "complete" for row in retained["model_calls"])
            assert (
                sum(row["reserved_tokens"] for row in retained["model_calls"])
                == 10 * 2048
            )
            assert sum(
                row["request_id"].startswith("/child/")
                for row in retained["model_calls"]
            ) == 4
            assert retained["delivery"]["phase"] == "completed"
            attempt = retained["attempt"]
            bound = json.loads(retained["delivery"]["binding"])
            assert attempt["attempt_id"] == root.attempt_id
            assert attempt["input_sha256"] == hashlib.sha256(
                bound["requirements"].encode()
            ).hexdigest()

            # Reopen only these host service objects and their original SQLite
            # journals. The canonical fixture stays in this same Python process.
            stack.dispatcher.stop()
            stack.children.close()
            stack.broker.close()
            reopen_stack(stack, tmp_path)
            assert not stack.broker.endpoints and not stack.children.endpoints.controls
            stack.dispatcher.tick_worker(
                stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)
            )
            replay = stack.runtime.execute_attempt(
                stack.worker_id,
                stack.spec,
                attempt["attempt_id"],
                bound["requirements"],
                attempt["seconds"],
                deadline_monotonic=attempt["deadline"],
            )
            assert replay == receipt
            assert Path(receipt.capture_path).read_bytes() == archive
            assert retained_state(stack) == retained
            assert root_turn == 6 and child_turns == {"left": 2, "right": 2}
            assert len(requests) == 10 and len(stack.child_authority.turns) == 4
            assert stack.authority.candidates == []
            current = stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)
            assert current["admission_open"] is False
            assert current["active_executions"] == []
