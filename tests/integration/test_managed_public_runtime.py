"""Actual Docker root/child public sockets with explicit authority/model/A fixtures.

The trusted image, Linux UIDs, original private execs, Unix framing, model ledger,
SDK/stdio owners, Ed25519 signatures and capture/archive paths are real. Authority
and provider replies are deterministic fixtures. The retained local transcript
is an A-shaped fixture, not installed Polyphony, peer discovery or live inference.
The complete two-child installed choreography remains a separate ZPM trial.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import tarfile

import docker
import pytest

from src.worker.child_types import text_hash
from src.worker.discussion_types import verify_record
from src.worker.managed_public_types import canonical
from tests.integration.test_managed_agent_container import agent_image  # noqa: F401
from tests.integration.test_managed_children_runtime import (
    child_stack, reopen_stack, wait_complete,
)
from tests.unit.test_managed_agent import message, provider, response
from tests.unit.test_managed_model_integration import TOKEN_VALUE
from tests.unit.test_managed_public_host import install_public_fixture, public_completion
from tests.unit.test_managed_public_profiles import wait_until
from tests.unit.test_managed_public_types import public_document


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OPENJULES_MANAGED_DOCKER_TESTS") != "1",
        reason="real managed public qualification requires explicit Docker opt-in",
    ),
]
ROOT_PRIVATE = "PRIVATE_ROOT_PUBLIC_COMPONENT_CANARY"
CHILD_PRIVATE = "PRIVATE_CHILD_PUBLIC_COMPONENT_CANARY"
PROPOSAL = "I propose the independently reviewable left-file change."
DECLINE = "I decline the public proposal while completing my private assignment."


GUEST_CLIENT = r"""
import hashlib,importlib.util,json,os,pathlib,socket,struct,time
path=pathlib.Path('/opt/openjules/public_tools.py')
assert hashlib.sha256(path.read_bytes()).hexdigest()==PUBLIC_SOURCE_SHA256
spec=importlib.util.spec_from_file_location('approved_public_fixture_tools',path)
module=importlib.util.module_from_spec(spec)
spec.loader.exec_module(module)
def receive(connection,size):
    data=b''
    while len(data)<size:
        part=connection.recv(size-len(data))
        assert part, 'public peer closed without a framed refusal'
        data+=part
    return data
def denied(path):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(path)
        size=struct.unpack('!I',receive(connection,4))[0]
        assert 0<size<=4096
        reply=json.loads(receive(connection,size))
        assert reply['ok'] is False and reply['error']=='not_authorized', reply
"""

CHILD_ACTION = r"""
assert os.getuid()==60000 and not os.access('/workspace/run',os.R_OK)
assert not os.access('/workspace/children',os.W_OK)
child_id=pathlib.Path.cwd().parents[1].name
assert child_id and pathlib.Path.cwd().name=='repo'
denied('/run/openjules-model/public.sock')
client=module.PublicClient('/run/openjules-model/children/'+child_id+'/public.sock',
                           role='child',timeout_seconds=15)
until=time.monotonic()+12
while True:
    pending=client.request('public_pending',request_id='mpub1:component-pending')
    if pending['slots']:
        break
    assert time.monotonic()<until, 'original public offer did not arrive'
    time.sleep(.05)
assert len(pending['slots'])==1
slot=pending['slots'][0]
assert slot['state']=='offered' and slot['actor']['child_id']==child_id
assert len(slot['selected_message_ids'])==1
assert slot['reply_to']==slot['selected_message_ids'][0]
pulled=client.request('public_pull',request_id='mpub1:component-child-pull',
                      slot_id=slot['slot_id'])
assert pulled['execution_authorized'] is False
assert pulled['slot']['state']=='declined'
replayed=client.request('public_pull',request_id='mpub1:component-child-pull',
                        slot_id=slot['slot_id'])
assert replayed==pulled
pathlib.Path('left.txt').write_text('left implemented\n')
print(json.dumps({'uid':os.getuid(),'child_id':child_id,'replayed':True,
                  'slot':pulled['slot']}))
"""


def close_services(stack):
    """Observe the actual old service locks before constructing new owners."""
    old_children, old_model = stack.children, stack.broker
    old_public = old_children.public_supervisor
    old_children.close()
    old_model.close()
    old_public.profiles.thread.join(timeout=6)
    wait_until(
        lambda: (
            old_children.journal.service_lock.closed
            and old_model._service_lock.closed
            and not old_public.profiles.thread.is_alive()
        ),
    )


def test_real_root_child_public_pull_uid_boundaries_and_frozen_capture_reopen(
    tmp_path, monkeypatch, agent_image,
):
    fixture_root = tmp_path / "named-public-stdio"
    fixture_root.mkdir(mode=0o700)
    document = public_document(fixture_root)
    document["instructions"]["criticism"] = "Independently assess the selected public proposal."
    install_public_fixture(document)
    guest_path = Path(__file__).resolve().parents[2] / "src/agent/public_tools.py"
    guest_sha = hashlib.sha256(guest_path.read_bytes()).hexdigest()
    guest_preamble = "PUBLIC_SOURCE_SHA256=" + repr(guest_sha) + "\n" + GUEST_CLIENT
    root_turn = child_turn = 0
    public_kinds = []
    root_slot = child_slot = child_output = None
    child_id = None
    supplied_public = []
    agent_image[0].api.max_redirects = 0

    def deterministic(handler, requests):
        nonlocal root_turn, child_turn, root_slot, child_slot, child_output, child_id
        body = requests[-1]["body"]
        messages = body["messages"]
        if "tools" not in body:
            assert len(messages) == 2
            assert set(body) == {"model", "stream", "max_tokens", "messages"}
            assert body["stream"] is False and body["max_tokens"] == 2048
            assert all(
                secret not in json.dumps(body)
                for secret in (ROOT_PRIVATE, CHILD_PRIVATE, TOKEN_VALUE)
            )
            selected = json.loads(messages[1]["content"])
            assert set(selected) == {"instruction", "public_context"}
            supplied_public.append(deepcopy(selected))
            if selected["instruction"] == document["instructions"]["proposal"]:
                assert selected["public_context"] == []
                public_kinds.append("message")
                public_completion(handler, kind="message", content=PROPOSAL)
            else:
                assert selected["instruction"] == document["instructions"]["criticism"]
                assert root_slot is not None
                assert selected["public_context"] == [root_slot["receipt"]["record"]]
                public_kinds.append("decline")
                public_completion(handler, kind="decline", content=DECLINE)
            return
        names = {item["function"]["name"] for item in body["tools"]}
        initial = messages[1]["content"]
        if initial.startswith(CHILD_PRIVATE):
            child_turn += 1
            assert {"public_pending", "public_pull", "public_decline"} <= names
            assert not {"public_activate", "public_turn", "public_invite"} & names
            if child_turn == 1:
                answer = message(
                    "run_command", argv=["python3", "-I", "-S", "-c",
                                         guest_preamble + CHILD_ACTION],
                )
            else:
                assert child_turn == 2
                result = json.loads(messages[-1]["content"])
                assert result["exit_code"] == 0, result
                child_output = json.loads(result["output"])
                assert child_output["uid"] == 60000 and child_output["replayed"] is True
                assert child_output["slot"]["receipt"]["record"]["body"]["content"] == DECLINE
                answer = message("finish", summary="Private work completed; public disagreement retained.")
        else:
            assert initial.startswith(ROOT_PRIVATE)
            root_turn += 1
            assert {"public_turn", "public_activate", "public_invite"} <= names
            assert not {"public_pending", "public_pull", "public_decline"} & names
            if root_turn == 1:
                answer = message(
                    "public_turn", persona_key="independent", instruction_key="proposal",
                    selected_message_ids=[], reply_to=None,
                )
            elif root_turn == 2:
                result = json.loads(messages[-1]["content"])
                assert result["execution_authorized"] is False
                root_slot = result["slot"]
                assert root_slot["state"] == "published"
                answer = message(
                    "spawn_child", instructions=CHILD_PRIVATE + ": change only left.txt.",
                    seconds=50, max_turns=3, capabilities=["python"],
                )
            elif root_turn == 3:
                child_id = json.loads(messages[-1]["content"])["child_id"]
                proposal_id = root_slot["receipt"]["message_id"]
                answer = message(
                    "public_activate", child_id=child_id, persona_key="independent",
                    instruction_key="criticism", selected_message_ids=[proposal_id],
                    reply_to=proposal_id,
                )
            elif root_turn == 4:
                result = json.loads(messages[-1]["content"])
                child_slot = result["slot"]
                assert child_slot["state"] == "offered" and child_slot["actor"]["child_id"] == child_id
                answer = message("child_result", child_id=child_id, kind="patch")
            elif root_turn == 5:
                patch = json.loads(messages[-1]["content"])
                assert patch["final"] is False
                assert patch["artifact_sha256"] == text_hash(patch["content"])
                assert "+left implemented" in patch["content"]
                script = guest_preamble + "\nimport subprocess\n"
                script += "assert os.getuid()==65532\n"
                script += "denied(" + repr("/run/openjules-model/children/" + child_id + "/public.sock") + ")\n"
                script += "client=module.PublicClient('/run/openjules-model/public.sock',role='root',timeout_seconds=10)\n"
                script += (
                    "replay=client.request('public_turn',request_id="
                    + repr(root_slot["activation_request_id"])
                    + ",persona_key='independent',instruction_key='proposal',selected_message_ids=[],reply_to=None)\n"
                )
                script += "assert replay['slot']==json.loads(" + repr(json.dumps(root_slot)) + ")\n"
                script += (
                    "subprocess.run(['git','apply','-'],input=" + repr(patch["content"])
                    + ",text=True,check=True)\n"
                )
                script += "assert pathlib.Path('left.txt').read_text()=='left implemented\\n'\n"
                script += "assert pathlib.Path('right.txt').read_text()=='old\\n'\n"
                script += "print('ROOT_PUBLIC_REPLAY_AND_CHILD_BOUNDARY')\n"
                answer = message("run_command", argv=["python3", "-I", "-S", "-c", script])
            else:
                assert root_turn == 6
                result = json.loads(messages[-1]["content"])
                assert result["exit_code"] == 0, result
                assert "ROOT_PUBLIC_REPLAY_AND_CHILD_BOUNDARY" in result["output"]
                answer = message("finish", summary="Composed the private patch; public disagreement remains independent.")
        response(handler, answer)

    with provider(deterministic) as (endpoint, requests):
        with child_stack(
            tmp_path, monkeypatch, agent_image, endpoint,
            seconds=75, child_seconds=55, outcome_protocol="initial-v1",
            public_discussion=document,
        ) as stack:
            stack.authority.requirements = ROOT_PRIVATE + ": compose the one child's reviewed left-file patch."
            wait_complete(stack, timeout=70)
            assert (root_turn, child_turn, public_kinds) == (6, 2, ["message", "decline"])
            assert len(requests) == 10 and len(supplied_public) == 2
            assert child_output["child_id"] == child_id
            assert child_output["slot"]["slot_id"] == child_slot["slot_id"]
            root = stack.children.journal.context(stack.worker_id)
            children = stack.children.journal.children(stack.worker_id)
            assert len(children) == 1
            child = children[0]
            assert child["child_id"] == child_id and child["uid"] == 60000
            assert child["phase"] == "completed" and child["exit_code"] == 0
            public = stack.children.public_supervisor
            view = public.store.view(root, stack.policy)
            assert view["header"]["closed"] is True and view["header"]["frozen"] is not None
            assert len(view["actors"]) == len(view["slots"]) == len(view["records"]) == 2
            assert len(view["processes"]) == 4
            assert all(row["state"] == "stopped" for row in view["processes"].values())
            assert not public.active and not public.profiles.entries and not public.endpoints.endpoints
            authors = {row["status"]["author"] for row in view["actors"].values()}
            assert len(authors) == 2
            slots = list(view["slots"].values())
            assert {row["state"] for row in slots} == {"published", "declined"}
            for slot in slots:
                actor = view["actors"][slot["actor_id"]]
                record = slot["receipt"]["record"]
                assert verify_record(record, actor["status"]) == record
                assert record["body"]["references"] == []
            with closing(sqlite3.connect(fixture_root / "public-records.sqlite3")) as db:
                assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 2
            with stack.broker.connection() as db:
                calls = [dict(row) for row in db.execute("SELECT * FROM calls ORDER BY rowid")]
            assert len(calls) == 10 and all(row["status"] == "complete" for row in calls)
            assert sum(row["reserved_tokens"] for row in calls) == 10 * 2048
            assert len(stack.child_authority.turns) == 3

            original = stack.runtime.inspect_attempt(stack.worker_id, stack.spec, root.attempt_id)
            assert original.exit_code == 0
            assert original.termination_confirmed and original.launch_fenced and original.artifacts_captured
            raw_manifest = json.loads(original.manifest)
            effective = json.loads(stack.authority.artifacts["manifest"])
            extension, private = public.store.extensions(root, stack.policy)
            assert "managed_public_v1" not in raw_manifest
            assert effective == raw_manifest | {
                "managed_public_v1": extension,
                "managed_public_original_manifest_sha256": text_hash(original.manifest),
            }
            assert stack.authority.artifacts["manifest"] == canonical(effective).decode()
            assert stack.authority.artifacts["patch"] == original.patch
            assert stack.authority.artifacts["log"] == original.log
            public_bytes = canonical(extension).decode()
            assert all(secret not in public_bytes for secret in (
                ROOT_PRIVATE, CHILD_PRIVATE, TOKEN_VALUE, child_id, stack.worker_id,
                child["exec_id"], '"uid":', '"grant_digest":',
            ))
            capture = json.loads(child["capture"])["contents"]
            child_manifest = json.loads(capture["manifest"])
            assert child_manifest["managed_public_v1"] == private[child_id]
            assert child_manifest["root_manifest_sha256"] == text_hash(stack.authority.artifacts["manifest"])
            assert child_manifest["root_manifest_sha256"] != text_hash(original.manifest)
            assert child_manifest["work_outcome"]["report"]["outcome"] == "completed"
            assert "CHILD_IDENTITY_VERIFIED uid=60000" in capture["log"]
            assert "+left implemented" in original.patch and "+left implemented" in capture["patch"]
            assert "+right implemented" not in original.patch
            assert len(stack.authority.candidates) == 1
            with tarfile.open(original.capture_path) as archive:
                assert archive.extractfile("workspace/run/repo/left.txt").read() == b"left implemented\n"
                child_head = archive.getmember("workspace/children/" + child_id + "/run/repo/.git/HEAD")
                assert child_head.uid == 60000
            assert (stack.source / "left.txt").read_text() == "old\n"

            container = stack.client.containers.get(stack.runtime._name(stack.worker_id))
            container.reload()
            assert container.attrs["State"]["Running"] is False
            container_id = container.id
            volume = next(mount["Name"] for mount in container.attrs["Mounts"] if mount["Destination"] == "/workspace")
            archive_bytes = Path(original.capture_path).read_bytes()
            retained = (
                deepcopy(stack.authority.artifacts), child["capture"],
                deepcopy(view["header"]["frozen"]), view["header"]["freeze_digest"],
            )
            cleaned = stack.dispatcher.cleanup_worker(stack.spec.scope, stack.worker_id)
            assert cleaned["state"] == "cleaned", cleaned
            with pytest.raises(docker.errors.NotFound):
                stack.client.containers.get(container_id)
            with pytest.raises(docker.errors.NotFound):
                stack.client.volumes.get(volume)
            assert Path(original.capture_path).read_bytes() == archive_bytes
            assert stack.runtime.inspect_attempt(stack.worker_id, stack.spec, root.attempt_id) == original

            close_services(stack)
            reopen_stack(stack, tmp_path)
            reopened = stack.children.public_supervisor
            assert not reopened.profiles.entries and not reopened.endpoints.endpoints
            assert stack.dispatcher.cleanup_worker(stack.spec.scope, stack.worker_id) == cleaned
            assert stack.runtime.ensure(stack.worker_id, stack.spec).state == "stopped"
            again = reopened.store.view(stack.children.journal.context(stack.worker_id), stack.policy)
            saved_child = stack.children.journal.child(stack.worker_id, child_id)
            assert (
                stack.authority.artifacts, saved_child["capture"],
                again["header"]["frozen"], again["header"]["freeze_digest"],
            ) == retained
            assert len(again["processes"]) == 4
            assert stack.runtime.inspect_attempt(stack.worker_id, stack.spec, root.attempt_id) == original
            assert Path(original.capture_path).read_bytes() == archive_bytes
            assert len(requests) == 10 and len(stack.child_authority.turns) == 3
            with stack.broker.connection() as db:
                assert [dict(row) for row in db.execute("SELECT * FROM calls ORDER BY rowid")] == calls
            close_services(stack)
