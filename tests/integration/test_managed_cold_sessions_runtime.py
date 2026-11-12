"""Actual Docker cold clarification, original-key recovery and final capture.

Root and children use the trusted image and real kernel-authenticated sockets.
Canonical authority and provider decisions are deterministic protocol fixtures;
the separate installed trial supplies actual three-service interoperability.
"""

import json
import os
from pathlib import Path
import tarfile
import time

import pytest

from src.worker.child_types import digest, text_hash
from tests.integration.test_managed_agent_container import agent_image  # noqa: F401
from tests.integration.test_managed_children_runtime import (
    child_stack, reopen_stack, wait_complete,
)
from tests.unit.test_managed_agent import message, provider, response
from tests.unit.test_managed_model_integration import TOKEN_VALUE

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OPENJULES_MANAGED_DOCKER_TESTS") != "1",
        reason="real managed Docker qualification requires explicit opt-in",
    ),
]

INITIAL = "Consider changing left.txt; request clarification if the scope is ambiguous."
FOLLOWUP = "Change only right.txt; do not carry forward the provisional left edit."
PARTIAL = "provisional first-round change\n"
CLARIFICATION = "Clarify whether to keep left or change only right. Private question λ."
CONTROL = "/run/openjules-model/control.sock"
READY = "/workspace/run/repo/.cold-queued.json"
RELEASE = "/workspace/run/repo/.cold-continue"

# This command runs outside inference, so the shared model gate stays available
# to the child. Its optional file gate pauses only this test's guest command.
POLL = """import json,pathlib,runpy,subprocess,sys,time
options=json.loads(sys.argv[1])
control=runpy.run_path('/opt/openjules/child_tools.py')['ControlClient'](
 '/run/openjules-model/control.sock')
deadline=time.monotonic()+20
if 'queued' in options:
 ready=pathlib.Path(options['ready']);release=pathlib.Path(options['release'])
 temporary=ready.with_suffix('.tmp')
 temporary.write_text(json.dumps(options['queued']),encoding='utf-8')
 temporary.replace(ready)
 while not release.exists():
  assert time.monotonic()<deadline,'fixture observation gate expired'
  time.sleep(0.05)
 ready.unlink();release.unlink()
while True:
 value=control.request('session_status',session_id=options['session_id'])
 row=value['rounds'][-1]
 if row['logical_round']==options['round'] and row['runtime_state']=='exec_returned':
  assert row['exit_code']==0
  break
 assert time.monotonic()<deadline,'child did not return within the original test bound'
 time.sleep(0.05)
if options['round']==2:
 assert value['phase']=='closed' and value['logical_outcome']=='completed'
 assert value['model_fence']=='established'
 assert not value['all_child_receipts_final'] and not value['release_authorized']
 patch=control.request('result',child_id=row['child_id'],kind='patch',offset=0,limit=65536)
 assert patch['final'] is False and '+right implemented' in patch['content']
 assert pathlib.Path('left.txt').read_text()=='old\\n'
 subprocess.run(['git','apply','-'],input=patch['content'],text=True,check=True)
 assert pathlib.Path('left.txt').read_text()=='old\\n'
 assert pathlib.Path('right.txt').read_text()=='right implemented\\n'
print(json.dumps(value))
"""

RPC = """import json,runpy,sys
operation,request_id,fields=json.loads(sys.argv[1])
client=runpy.run_path('/opt/openjules/child_tools.py')['ControlClient'](
 '/run/openjules-model/control.sock')
print(json.dumps(client.request(operation,request_id=request_id,**fields)))
"""


def guest_python(container, uid, script, *arguments):
    result = container.exec_run(
        ["python3", "-I", "-S", "-c", script, *arguments],
        user=f"{uid}:{uid}",
        workdir="/",
        privileged=False,
    )
    assert result.exit_code == 0, result.output.decode(errors="replace")
    return result.output.decode("utf-8")


def request(container, uid, operation, request_id, **fields):
    return json.loads(
        guest_python(container, uid, RPC, json.dumps([operation, request_id, fields]))
    )


def test_real_cold_followup_reopens_same_queue_and_captures_both_physical_children(
    tmp_path, monkeypatch, agent_image
):
    root_turns = 0
    child_turns = {1: 0, 2: 0}
    observed = {}
    agent_image[0].api.max_redirects = 0

    def deterministic(handler, requests):
        nonlocal root_turns
        body = requests[-1]["body"]
        messages = body["messages"]
        initial = messages[1]["content"]
        tool_names = {tool["function"]["name"] for tool in body["tools"]}
        if initial.startswith("{"):
            envelope = json.loads(initial.split("\n\nRoot repository instructions:\n", 1)[0])
            assert envelope["protocol"] == "openjules-cold-clarification-v1"
            assert envelope["initial_instructions"] == INITIAL
            ordinal = envelope["logical_round"]
            assert ordinal in {1, 2}
            child_turns[ordinal] += 1
            assert "report_outcome" in tool_names
            assert not {
                "spawn_child", "start_child_session", "continue_child_session",
                "child_session_status",
            } & tool_names
            observed.setdefault("envelopes", {})[ordinal] = envelope
            observed.setdefault("instructions", {})[ordinal] = initial.split(
                "\n\nRoot repository instructions:\n", 1
            )[0]
            if ordinal == 1:
                assert envelope["followup"] is None and envelope["predecessor"] is None
                if child_turns[1] == 1:
                    answer = message("write_file", path="left.txt", content=PARTIAL)
                else:
                    assert child_turns[1] == 2
                    answer = message(
                        "report_outcome", outcome="needs_clarification",
                        summary=CLARIFICATION,
                    )
            else:
                assert envelope["session_id"] == observed["session_id"]
                assert envelope["followup"] == FOLLOWUP
                predecessor = envelope["predecessor"]
                assert digest(predecessor) == observed["predecessor_digest"]
                assert predecessor["exec_id"] == observed["first_exec"]
                assert predecessor["work_outcome"]["report"]["summary"] == CLARIFICATION
                assert predecessor["work_outcome"]["canonical_committed"] is False
                assert predecessor["work_outcome"]["release_authorized"] is False
                if child_turns[2] == 1:
                    fresh = (
                        "import pathlib\n"
                        "assert pathlib.Path('left.txt').read_text()=='old\\n'\n"
                        "assert pathlib.Path('right.txt').read_text()=='old\\n'\n"
                        "pathlib.Path('right.txt').write_text('right implemented\\n')\n"
                        "print('FRESH_SECOND_CHECKOUT')\n"
                    )
                    answer = message("run_command", argv=["python3", "-I", "-c", fresh])
                else:
                    assert child_turns[2] == 2
                    result = json.loads(messages[-1]["content"])
                    assert result["exit_code"] == 0
                    assert "FRESH_SECOND_CHECKOUT" in result["output"]
                    answer = message("finish", summary="Changed only right after clarification.")
        else:
            assert initial.startswith("ROOT_COMPOSE:")
            assert {
                "start_child_session", "continue_child_session", "child_session_status"
            } <= tool_names
            root_turns += 1
            if root_turns == 1:
                answer = message(
                    "start_child_session", instructions=INITIAL, seconds=35,
                    max_turns=2, capabilities=["python"],
                )
            elif root_turns == 2:
                value = json.loads(messages[-1]["content"])
                observed["session_id"] = value["session_id"]
                answer = message(
                    "run_command",
                    argv=["python3", "-I", "-S", "-c", POLL, json.dumps({
                        "session_id": value["session_id"], "round": 1,
                    })],
                )
            elif root_turns == 3:
                result = json.loads(messages[-1]["content"])
                assert result["exit_code"] == 0, result
                value = json.loads(result["output"])
                assert value["phase"] == "awaiting_followup"
                assert value["rounds"][0]["initial_outcome"]["report"]["outcome"] == (
                    "needs_clarification"
                )
                observed["first_status"] = value
                observed["first_exec"] = value["rounds"][0]["exec_id"]
                observed["predecessor_digest"] = value["predecessor_digest"]
                answer = message(
                    "continue_child_session", session_id=value["session_id"],
                    predecessor_digest=value["predecessor_digest"],
                    instructions=FOLLOWUP, seconds=35, max_turns=2,
                )
            elif root_turns == 4:
                value = json.loads(messages[-1]["content"])
                assert value["phase"] == "followup_queued"
                assert value["model_fence"] == "requested"
                assert value["rounds"][1]["child_id"] is None
                observed["queued"] = value
                answer = message(
                    "run_command",
                    argv=["python3", "-I", "-S", "-c", POLL, json.dumps({
                        "session_id": value["session_id"], "round": 2,
                        "queued": value, "ready": READY, "release": RELEASE,
                    })],
                )
            elif root_turns == 5:
                result = json.loads(messages[-1]["content"])
                assert result["exit_code"] == 0, result
                observed["second_status"] = json.loads(result["output"])
                answer = message(
                    "child_session_status", session_id=observed["session_id"]
                )
            else:
                assert root_turns == 6
                value = json.loads(messages[-1]["content"])
                assert value["logical_outcome"] == "completed"
                assert value["all_child_receipts_final"] is False
                assert value["release_authorized"] is False
                observed["before_finish"] = value
                observed["active_before_finish"] = set(
                    stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)[
                        "active_executions"
                    ]
                )
                answer = message(
                    "finish",
                    summary="Composed the second child's patch and retained the clarification history.",
                )
        response(handler, answer)

    with provider(deterministic) as (endpoint, requests):
        with child_stack(
            tmp_path, monkeypatch, agent_image, endpoint,
            outcome_protocol="initial-v1", session_protocol="cold-clarification-v1",
        ) as stack:
            # This first tick reconciles before launching the root. With no
            # subsequent tick, status/tools can queue but cannot promote round2.
            stack.dispatcher.tick_worker(stack.worker)
            container = stack.client.containers.get(stack.runtime._name(stack.worker_id))
            probe = (
                "import pathlib,sys\np=pathlib.Path(sys.argv[1])\n"
                "print(p.read_text() if p.exists() else '')"
            )
            until = time.monotonic() + 15
            queued = None
            while time.monotonic() < until:
                value = guest_python(container, stack.profile.uid, probe, READY).strip()
                if value:
                    queued = json.loads(value)
                    break
                time.sleep(0.05)
            assert queued is not None, "root did not reach the queued observation gate"
            assert queued == observed["queued"]
            root = stack.children.journal.context(stack.worker_id)
            session_id = queued["session_id"]
            first_id = queued["rounds"][0]["child_id"]
            first = stack.children.journal.child(stack.worker_id, first_id)
            assert first["phase"] == "exec_returned" and first["exit_code"] == 0
            assert first["capture"] is None
            assert len(stack.child_authority.records) == 1
            assert len(stack.children.journal.intents(stack.worker_id)) == 1
            assert set(stack.lifecycle.observe_worker(
                stack.spec.scope, stack.worker_id
            )["active_executions"]) == {root.attempt_id, first_id}
            with stack.broker.connection() as db:
                calls = db.execute("SELECT * FROM calls").fetchall()
                assert len(calls) == len(requests) == 6
                assert all(row["status"] == "complete" for row in calls)
            original_session = stack.children.sessions.get(root, stack.policy, session_id)
            frozen = original_session["rounds"][1]["predecessor"]
            immutable = {
                name: first[name] for name in (
                    "child_id", "uid", "grant_json", "deadline", "boot_id",
                    "exec_id", "exec_dispatched", "armed_deadline",
                )
            }

            # No active model request crosses this service restart: the trusted
            # root is waiting in its bounded local command, outside inference.
            stack.dispatcher.stop()
            stack.children.close()
            stack.broker.close()
            reopen_stack(stack, tmp_path)
            assert first_id not in stack.children.endpoints.children
            assert stack.children.endpoints.outcomes[first_id].thread.is_alive()
            restored = stack.children.journal.child(stack.worker_id, first_id)
            assert {name: restored[name] for name in immutable} == immutable
            assert stack.children.sessions.get(root, stack.policy, session_id)[
                "rounds"
            ][1]["predecessor"] == frozen
            for number in range(2):
                status = request(
                    container, stack.profile.uid, "session_status",
                    "cold-observe-" + str(number), session_id=session_id,
                )
                assert status["phase"] == "followup_queued"
                assert status["predecessor_digest"] == observed["predecessor_digest"]
                assert status["rounds"][1]["child_id"] is None
            replay = request(
                container, stack.profile.uid, "session_followup",
                queued["followup_request_id"], session_id=session_id,
                predecessor_digest=queued["predecessor_digest"],
                instructions=FOLLOWUP, seconds=35, max_turns=2,
            )
            assert replay["followup_request_id"] == queued["followup_request_id"]
            assert replay["rounds"][1]["child_id"] is None
            assert len(stack.child_authority.records) == 1
            assert len(stack.children.journal.intents(stack.worker_id)) == 1
            assert len(requests) == 6 and len(stack.child_authority.turns) == 2

            guest_python(
                container, stack.profile.uid,
                "import pathlib,sys;pathlib.Path(sys.argv[1]).write_text('continue')",
                RELEASE,
            )
            wait_complete(stack)
            children = stack.children.journal.children(stack.worker_id)
            assert len(children) == 2
            child_ids = {child["child_id"] for child in children}
            assert len(child_ids) == len({child["exec_id"] for child in children}) == 2
            assert {child["uid"] for child in children} == {60000, 60001}
            assert {child["phase"] for child in children} == {"completed"}
            assert observed["active_before_finish"] == {root.attempt_id, *child_ids}
            assert len(stack.child_authority.records) == 2
            assert sum(
                record["request"]["seconds"] for record in stack.child_authority.records.values()
            ) == 70
            second = next(child for child in children if child["child_id"] != first_id)
            assert second["armed_deadline"] <= first["armed_deadline"]
            assert restored["exec_id"] == first["exec_id"]
            grants = [json.loads(child["grant_json"])["binding"] for child in children]
            assert len({grant["grant_digest"] for grant in grants}) == 2
            assert {envelope["session_id"] for envelope in observed["envelopes"].values()} == {
                session_id
            }
            assert {
                grant["instructions_digest"] for grant in grants
            } == {text_hash(value) for value in observed["instructions"].values()}
            assert {grant["base"] for grant in grants} == {root.base}
            assert {grant["requirements_revision"] for grant in grants} == {
                root.requirements_revision
            }
            receipt = stack.runtime.inspect_attempt(
                stack.worker_id, stack.spec, root.attempt_id
            )
            assert receipt.exit_code == 0, receipt.log
            assert receipt.termination_confirmed and receipt.launch_fenced
            assert receipt.artifacts_captured
            assert "+right implemented" in receipt.patch
            assert "provisional first-round change" not in receipt.patch
            assert len(stack.authority.candidates) == 1
            with tarfile.open(receipt.capture_path) as archive:
                assert archive.extractfile("workspace/run/repo/left.txt").read() == b"old\n"
                assert archive.extractfile("workspace/run/repo/right.txt").read() == (
                    b"right implemented\n"
                )
                for child in children:
                    prefix = f"workspace/children/{child['child_id']}/run/repo/"
                    assert archive.getmember(prefix + ".git/HEAD").uid == child["uid"]
                    expected = PARTIAL.encode() if child["child_id"] == first_id else b"old\n"
                    assert archive.extractfile(prefix + "left.txt").read() == expected
            for child in children:
                capture = json.loads(child["capture"])["contents"]
                manifest = json.loads(capture["manifest"])
                outcome = manifest["work_outcome"]
                assert outcome["ordinal"] == 1 and outcome["child_id"] == child["child_id"]
                assert manifest["archive_sha256"] == receipt.capture_sha256
                assert manifest["termination_method"] == "whole-container fence"
                assert manifest["exec_start_dispatched"] is True
                assert TOKEN_VALUE not in "".join(capture.values())
                assert json.loads(child["artifacts"]) == {
                    name: text_hash(value) for name, value in capture.items()
                }
                if child["child_id"] == first_id:
                    assert outcome["report"]["outcome"] == "needs_clarification"
                    assert outcome["report"]["summary"] == CLARIFICATION
                    assert "+provisional first-round change" in capture["patch"]
                    assert "CHILD_IDENTITY_VERIFIED" not in capture["log"]
                else:
                    assert outcome["report"]["outcome"] == "completed"
                    assert "+right implemented" in capture["patch"]
                    assert "CHILD_IDENTITY_VERIFIED" in capture["log"]
            final = stack.children.sessions.project(root, stack.policy, session_id)
            assert final["logical_outcome"] == "completed"
            assert final["all_child_receipts_final"] is True
            assert final["canonical_session"] is False
            assert final["release_authorized"] is False
            assert final["predecessor_digest"] == observed["predecessor_digest"]
            assert stack.children.sessions.get(root, stack.policy, session_id)[
                "rounds"
            ][1]["predecessor"] == frozen
            assert all(
                row["initial_outcome"]["canonical_committed"]
                and row["evidence"] == "canonical_child_final"
                for row in final["rounds"]
            )
            events = [event for event, _ in stack.authority.events]
            assert events[:2] == ["child_terminal", "child_terminal"]
            assert events[-1] == "root_terminal"
            with stack.broker.connection() as db:
                calls = db.execute("SELECT * FROM calls").fetchall()
                assert len(calls) == len(requests) == 10
                assert sum(row["reserved_tokens"] for row in calls) == 10 * 2048
                assert all(row["status"] == "complete" for row in calls)
                assert sum(row["request_id"].startswith("/child/") for row in calls) == 4
            assert child_turns == {1: 2, 2: 2} and root_turns == 6
            assert len(stack.child_authority.turns) == 4
            assert not stack.lifecycle.observe_worker(
                stack.spec.scope, stack.worker_id
            )["active_executions"]
            assert (stack.source / "left.txt").read_text() == "old\n"
            assert (stack.source / "right.txt").read_text() == "old\n"
            assert Path(receipt.capture_path).is_file()
