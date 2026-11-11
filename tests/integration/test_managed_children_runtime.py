"""Actual Docker/UID/socket qualification with explicit authority/model fixtures.

This qualifies OpenJules execution and recovery, not a real Polyphony authority
or a live model provider. Once opted in, unavailable Docker/socket access fails.
"""

from contextlib import contextmanager
from dataclasses import asdict
import hashlib
import json
import multiprocessing
import os
from pathlib import Path
import subprocess
import tarfile
import time
from types import SimpleNamespace

import docker
import pytest

from src.polyphony.child_client import ChildRejected
from src.worker.child_broker import ChildBroker
from src.worker.child_supervisor import ChildSupervisor
from src.worker.child_types import ChildPolicy, digest, text_hash
from src.worker.docker_runtime import DockerProfile, ManagedDockerRuntime
from src.worker.lifecycle import RuntimeCapabilities, WorkerLifecycle, WorkerSpec
from src.worker.managed_dispatch import ManagedDispatcher
from src.worker.model_broker import ModelBinding, ModelBroker, ModelPolicy
from tests.integration.test_managed_agent_container import agent_image  # noqa: F401
from tests.unit.test_child_authority_contract import grant
from tests.unit.test_managed_agent import message, provider, response
from tests.unit.test_managed_model_integration import (
    FixtureAuthority,
    TOKEN_REFERENCE,
    TOKEN_VALUE,
)

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OPENJULES_MANAGED_DOCKER_TESTS") != "1",
        reason="real managed Docker qualification requires explicit opt-in",
    ),
]


class RootAuthorityFixture(FixtureAuthority):
    def __init__(self, seconds):
        super().__init__()
        self.cutoff = time.monotonic() + seconds
        self.deadline = time.time() + seconds
        self.requirements = "ROOT_COMPOSE: delegate left.txt and right.txt to two bounded children, apply both returned patches, and verify the result."
        self.child_authority = None
        self.events = []
        self.terminal_receipt = None

    def call(self, operation, scope, **data):
        if operation == "capture":
            assert all(
                value["terminal"] for value in self.child_authority.records.values()
            )
            self.events.append(("root_capture", data["kind"]))
        if operation == "observe" and data["termination_confirmed"]:
            assert all(
                value["terminal"] for value in self.child_authority.records.values()
            )
            self.events.append(("root_terminal", data["attempt_id"]))
            self.terminal_receipt = {
                name: data[name]
                for name in (
                    "state",
                    "termination_confirmed",
                    "launch_fenced",
                    "artifacts",
                )
            }
        result = super().call(operation, scope, **data)
        if operation in {"claim", "permission"}:
            result["binding"]["deadline"] = self.deadline
            result["attempt"]["task"] = "task-1"
            result["remaining_seconds"] = (
                max(0, self.cutoff - time.monotonic()) if self.allowed else 0
            )
            result["launch_allowed"] = self.allowed and result["remaining_seconds"] > 0
            if self.terminal_receipt is not None:
                result["launch_allowed"] = False
                result["attempt"].update(
                    runtime_binding=result["binding"],
                    state=self.terminal_receipt["state"],
                    termination_confirmed=True,
                    launch_fenced=True,
                    captured_artifacts=self.terminal_receipt["artifacts"],
                    runtime_receipt=self.terminal_receipt,
                    child_admission_closed=self.child_authority.closed,
                    child_lineage=sorted(
                        [
                            {
                                "child_id": record["response"]["binding"]["child_id"],
                                "grant_digest": record["response"]["binding"][
                                    "grant_digest"
                                ],
                                "artifacts": {
                                    kind: text_hash(content)
                                    for kind, content in record["artifacts"].items()
                                },
                            }
                            for record in self.child_authority.records.values()
                        ],
                        key=lambda value: value["child_id"],
                    ),
                )
        return result


class ChildAuthorityFixture:
    """Deterministic canonical protocol fixture. No claim of external acceptance."""

    def __init__(self, stack):
        self.stack = stack
        self.records = {}
        self.closed = False
        self.turns = {}

    def permitted(self, record):
        remaining = max(
            0, min(record["cutoff"], self.stack.authority.cutoff) - time.monotonic()
        )
        allowed = (
            self.stack.authority.allowed
            and not record["revoked"]
            and not record["terminal"]
            and remaining > 0
        )
        return record["response"] | {
            "launch_allowed": allowed,
            "remaining_seconds": remaining if allowed else 0,
            "reason": "allowed" if allowed else "closed",
        }

    def call(self, operation, scope, attempt_id, **payload):
        root = self.stack.children.journal.context(self.stack.worker_id)
        assert scope == root.spec.scope and attempt_id == root.attempt_id
        if operation == "close":
            self.closed = True
            return {"action": "close"}
        if operation == "grant":
            key = payload["request_key"]
            request = {
                name: payload[name]
                for name in ("instructions", "seconds", "max_turns", "capabilities")
            }
            if key not in self.records:
                if self.closed:
                    raise ChildRejected(409, child_not_allocated=True)
                assert len(self.records) < self.stack.policy.max_children
                identity = "child_" + f"{len(self.records) + 1:032x}"
                approved = grant(root, request, identity)
                approved["binding"]["deadline"] = min(
                    root.deadline, time.time() + request["seconds"]
                )
                approved["binding"]["grant_digest"] = digest(
                    {
                        name: value
                        for name, value in approved["binding"].items()
                        if name != "grant_digest"
                    }
                )
                self.records[key] = {
                    "response": approved,
                    "request": request,
                    "cutoff": time.monotonic() + request["seconds"],
                    "revoked": False,
                    "terminal": False,
                    "artifacts": {},
                }
            assert self.records[key]["request"] == request
            return self.permitted(self.records[key])
        child_id = payload["child_id"]
        record = next(
            value
            for value in self.records.values()
            if value["response"]["binding"]["child_id"] == child_id
        )
        if operation == "permission":
            return self.permitted(record)
        if operation == "turn":
            key = (child_id, payload["request_key"])
            if key in self.turns:
                assert self.turns[key] == payload["request_digest"]
            else:
                assert (
                    sum(item[0] == child_id for item in self.turns)
                    < record["request"]["max_turns"]
                )
                self.turns[key] = payload["request_digest"]
            return self.permitted(record) | {
                "turn": {
                    "child_id": child_id,
                    "root_attempt_id": attempt_id,
                    "request_digest": payload["request_digest"],
                }
            }
        if operation == "revoke":
            record["revoked"] = True
            return {"action": "revoke"}
        if operation == "capture":
            record["artifacts"][payload["kind"]] = payload["content"]
            return {
                "child_id": child_id,
                "kind": payload["kind"],
                "artifact_id": text_hash(payload["content"]),
                "runtime_principal": root.runtime_principal,
            }
        if operation == "observe":
            assert (
                payload["termination_confirmed"] is True
                and payload["launch_fenced"] is True
            )
            hashes = {
                kind: text_hash(value) for kind, value in record["artifacts"].items()
            }
            assert (
                set(hashes) == {"patch", "log", "manifest"}
                and hashes == payload["artifacts"]
            )
            record["terminal"] = True
            self.stack.authority.events.append(("child_terminal", child_id))
            result = {
                "child": record["response"]["child"]
                | {
                    "state": payload["state"],
                    "termination_confirmed": True,
                    "launch_fenced": True,
                    "captured_artifacts": hashes,
                }
            }
            outcome = json.loads(record["artifacts"]["manifest"]).get("work_outcome")
            if outcome is not None:
                result["child"]["initial_outcome"] = outcome | {
                    "artifacts": hashes,
                    "canonical_committed": True,
                    "release_authorized": False,
                }
            return result
        raise AssertionError(operation)

    def children(self, scope, attempt_id):
        return {"children": [self.permitted(value) for value in self.records.values()]}


CHILD_VERIFY = """import json,os,pathlib,socket,struct
assert os.getuid() in (60000,60001)
assert not os.access('/workspace/run',os.R_OK)
assert not os.access('/workspace/children',os.W_OK)
assert not pathlib.Path('/var/run/docker.sock').exists()
assert not any(k in os.environ for k in ('MODEL_INTEGRATION_FIXTURE_TOKEN','POLYPHONY_RUNTIME_TOKEN','OPENJULES_WORKER_TOKEN','OPENAI_API_KEY'))
def deny(path):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:
        s.settimeout(5);s.connect(path)
        length=struct.unpack('!I',s.recv(4))[0]
        data=b''
        while len(data)<length: data+=s.recv(length-len(data))
        assert json.loads(data)['error']=='not_authorized'
deny('/run/openjules-model/model.sock')
deny('/run/openjules-model/control.sock')
print('CHILD_IDENTITY_VERIFIED uid='+str(os.getuid()))
"""


SIBLING_VERIFY = """import json,os,pathlib,socket,struct,sys
own,others=json.loads(sys.argv[1])
assert os.getuid()==own['uid'] and os.getgid()==own['uid']
for name in own['files']:
    assert pathlib.Path(name).read_bytes(), name
def denied(action,label):
    try:
        action()
    except PermissionError:
        return
    raise AssertionError('private child access was permitted: '+label)
def receive(connection,size):
    data=b''
    while len(data)<size:
        part=connection.recv(size-len(data))
        assert part, 'socket closed without an authenticated refusal'
        data+=part
    return data
def probe_socket(path,own_socket=False):
    with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as connection:
        connection.settimeout(5)
        connection.connect(path)
        if own_socket:
            # Authentication precedes frame validation. No inference is asked
            # for: this positive control must reach invalid_request, not denial.
            connection.sendall(struct.pack('!I',0))
        length=struct.unpack('!I',receive(connection,4))[0]
        assert 0<length<=4096
        reply=json.loads(receive(connection,length))
        assert reply['ok'] is False
        assert reply['error']==('invalid_request' if own_socket else 'not_authorized'), reply
probe_socket(own['socket'],True)
for other in others:
    denied(lambda: list(pathlib.Path(other['directory']).iterdir()),other['directory'])
    for name in other['files']:
        denied(lambda: pathlib.Path(name).read_bytes(),'read '+name)
        denied(lambda: pathlib.Path(name).open('ab'),'write '+name)
    denied(lambda: os.chmod(other['directory'],0o777),'chmod '+other['directory'])
    denied(lambda: os.setuid(other['uid']),'setuid '+str(other['uid']))
    probe_socket(other['socket'])
print(json.dumps({'uid':os.getuid(),'denied_uids':[item['uid'] for item in others]}))
"""


def make_source(tmp_path):
    source = tmp_path / "source"
    source.mkdir()
    for name in ("left", "right"):
        (source / (name + ".txt")).write_text("old\n")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=Fixture",
            "-c",
            "user.email=fixture@example.invalid",
            "commit",
            "-qm",
            "base",
        ],
        check=True,
    )
    base = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    return source, base


@contextmanager
def child_stack(
    tmp_path,
    monkeypatch,
    agent_image,
    endpoint,
    *,
    sleeping_root=False,
    seconds=60,
    child_seconds=40,
    outcome_protocol=None,
):
    client, image = agent_image
    source, base = make_source(tmp_path)
    monkeypatch.setenv(TOKEN_REFERENCE[4:], TOKEN_VALUE)
    command = (
        "python3",
        "-I",
        "-S",
        "/opt/openjules/managed_root_runner.py",
        "--socket",
        "/run/openjules-model/model.sock",
        "--control-socket",
        "/run/openjules-model/control.sock",
        "--max-turns",
        "10",
    )
    if sleeping_root:
        command = ("python3", "-I", "-c", "import time;time.sleep(90)")
    profile = DockerProfile(
        "bounded-children-v1",
        "child-runtime-test",
        "github:github.com/fixture/child-runtime",
        str(source),
        image,
        command,
        base,
        max_seconds=90,
    )
    spec = WorkerSpec(
        profile.deployment_id, profile.repository, "slot", 1, "launch", profile.name
    )
    key = (spec.deployment_id, spec.repository, spec.profile)
    policy = ChildPolicy(
        2,
        child_seconds,
        4,
        ("python",),
        verify_argv=("python3", "-I", "-c", CHILD_VERIFY),
        outcome_protocol=outcome_protocol,
    )
    stack = SimpleNamespace(
        client=client,
        source=source,
        profile=profile,
        spec=spec,
        key=key,
        policy=policy,
        authority=RootAuthorityFixture(seconds),
        dispatcher=None,
        children=None,
        worker_id=None,
    )
    stack.broker = ModelBroker(
        tmp_path / "models",
        {
            key: ModelPolicy(
                endpoint,
                "deterministic-child-fixture",
                TOKEN_REFERENCE,
                max_calls=16,
                max_output_tokens=2048,
                max_total_output_tokens=32768,
                request_timeout_seconds=5,
            )
        },
        lambda binding: stack.dispatcher.model_permission(binding),
        peer_uids={key: profile.uid},
    )
    stack.runtime = ManagedDockerRuntime(
        tmp_path / "runtime",
        [profile],
        lambda *_: RuntimeCapabilities(True, True, True, "explicit authority fixture"),
        client,
        model_broker=stack.broker,
        child_policies={key: policy},
    )
    stack.lifecycle = WorkerLifecycle(tmp_path / "lifecycle.db", stack.runtime)
    stack.children = ChildSupervisor(
        tmp_path / "children",
        {key: policy},
        None,
        stack.lifecycle,
        stack.runtime,
        stack.broker,
        lambda root: stack.dispatcher.model_permission(
            ModelBinding(root.worker_id, root.attempt_id, root.spec)
        ),
        lambda root: stack.dispatcher.child_root_active(root),
    )
    stack.child_authority = ChildAuthorityFixture(stack)
    stack.authority.child_authority = stack.child_authority
    stack.children.authority = stack.child_authority
    stack.children.endpoints = ChildBroker(stack.children, stack.broker)
    stack.runtime.child_supervisor = stack.broker.child_supervisor = stack.children
    stack.dispatcher = ManagedDispatcher(
        stack.lifecycle,
        stack.runtime,
        stack.authority,
        [profile],
        tmp_path / "dispatch",
        model_broker=stack.broker,
        child_supervisor=stack.children,
    )
    try:
        stack.worker = stack.lifecycle.ensure_worker(spec)
        stack.worker_id = stack.worker["worker_id"]
        assert stack.worker["state"] == "ready", stack.worker
        yield stack
    finally:
        stack.dispatcher.stop()
        stack.children.close()
        stack.broker.close()
        if stack.worker_id is not None:
            try:
                client.containers.get(stack.runtime._name(stack.worker_id)).remove(
                    force=True
                )
            except docker.errors.NotFound:
                pass
            try:
                client.volumes.get(
                    "openjules-work-"
                    + hashlib.sha256(stack.worker_id.encode()).hexdigest()[:40]
                ).remove()
            except docker.errors.NotFound:
                pass


def wait_complete(stack, timeout=50):
    until = time.monotonic() + timeout
    while time.monotonic() < until:
        worker = stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)
        stack.dispatcher.tick_worker(worker)
        if stack.dispatcher.journal.get(stack.worker_id)["phase"] == "completed":
            return
        time.sleep(0.05)
    pytest.fail(
        "managed child dispatcher did not complete within the qualification bound"
    )


def reopen_stack(stack, tmp_path):
    """New service objects recover the original journals and socket identities."""
    models = dict(stack.broker.policies)
    stack.broker = ModelBroker(
        tmp_path / "models",
        models,
        lambda binding: stack.dispatcher.model_permission(binding),
        peer_uids={stack.key: stack.profile.uid},
    )
    stack.runtime = ManagedDockerRuntime(
        tmp_path / "runtime",
        [stack.profile],
        lambda *_: RuntimeCapabilities(True, True, True, "explicit authority fixture"),
        stack.client,
        model_broker=stack.broker,
        child_policies={stack.key: stack.policy},
    )
    stack.lifecycle = WorkerLifecycle(tmp_path / "lifecycle.db", stack.runtime)
    stack.children = ChildSupervisor(
        tmp_path / "children",
        {stack.key: stack.policy},
        None,
        stack.lifecycle,
        stack.runtime,
        stack.broker,
        lambda root: stack.dispatcher.model_permission(
            ModelBinding(root.worker_id, root.attempt_id, root.spec)
        ),
        lambda root: stack.dispatcher.child_root_active(root),
    )
    stack.children.authority = stack.child_authority
    stack.children.endpoints = ChildBroker(stack.children, stack.broker)
    stack.runtime.child_supervisor = stack.broker.child_supervisor = stack.children
    stack.dispatcher = ManagedDispatcher(
        stack.lifecycle,
        stack.runtime,
        stack.authority,
        [stack.profile],
        tmp_path / "dispatch",
        model_broker=stack.broker,
        child_supervisor=stack.children,
    )
    stack.runtime.restore_model_endpoints()


def _cleanup_subprocess(directory, payload, crash_after_container):
    """Fresh real process and journals; reuse the explicit canonical fixture."""
    profile = DockerProfile(**payload["profile"])
    spec = WorkerSpec(**payload["spec"])
    key = (spec.deployment_id, spec.repository, spec.profile)
    client = docker.from_env(timeout=5)
    client.api.max_redirects = 0
    authority = RootAuthorityFixture(1)
    authority.binding = payload["binding"]
    authority.requirements = payload["requirements"]
    authority.deadline = payload["binding"]["deadline"]
    authority.terminal_receipt = payload["terminal"]
    child_authority = SimpleNamespace(records=payload["children"], closed=True)
    authority.child_authority = child_authority
    stack = SimpleNamespace(
        client=client,
        profile=profile,
        spec=spec,
        key=key,
        policy=ChildPolicy(**payload["policy"]),
        broker=SimpleNamespace(policies={key: ModelPolicy(**payload["model"])}),
        authority=authority,
        child_authority=child_authority,
        worker_id=payload["worker_id"],
        dispatcher=None,
    )
    reopen_stack(stack, directory)
    try:
        assert not stack.broker.endpoints and not stack.children.endpoints.controls
        if crash_after_container:
            original_update = stack.runtime._update

            def interrupted(worker_id, **values):
                if "cleanup" in values:
                    progress = json.loads(values["cleanup"])
                    if progress["container_removed"] and not progress["completed"]:
                        # The real Docker container is absent; intentionally die
                        # before acknowledging that progress durably. No unwind.
                        os._exit(91)
                return original_update(worker_id, **values)

            stack.runtime._update = interrupted
        result = stack.dispatcher.cleanup_worker(spec.scope, stack.worker_id)
        assert result["state"] == "cleaned", result
    finally:
        stack.children.close()
        stack.broker.close()
        client.close()


def cleanup_process(directory, payload, *, crash=False):
    process = multiprocessing.get_context("spawn").Process(
        target=_cleanup_subprocess, args=(directory, payload, crash)
    )
    process.start()
    process.join(30)
    if process.is_alive():
        process.kill()  # Only this test-owned cleanup process.
        process.join(5)
        pytest.fail("test-owned cleanup process did not finish")
    assert process.exitcode == (91 if crash else 0)


def test_two_real_children_use_unique_uids_share_allowance_and_compose_root(
    tmp_path, monkeypatch, agent_image
):
    root_turn = 0
    child_turns = {"left": 0, "right": 0}
    child_ids = []
    patches = []
    # Qualify creation through the same stock no-retry/no-redirect Unix
    # transport used by the production managed runtime.
    agent_image[0].api.max_redirects = 0

    def deterministic(handler, requests):
        nonlocal root_turn
        messages = requests[-1]["body"]["messages"]
        initial = messages[1]["content"]
        if initial.startswith("CHILD_"):
            name = "left" if initial.startswith("CHILD_left") else "right"
            child_turns[name] += 1
            answer = (
                message(
                    "write_file", path=name + ".txt", content=name + " implemented\n"
                )
                if child_turns[name] == 1
                else message("finish", summary="Completed " + name)
            )
            assert child_turns[name] <= 2
        else:
            root_turn += 1
            if root_turn in {2, 3}:
                child_ids.append(json.loads(messages[-1]["content"])["child_id"])
            if root_turn in {4, 5}:
                value = json.loads(messages[-1]["content"])
                assert value["final"] is False and value[
                    "artifact_sha256"
                ] == text_hash(value["content"])
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
                assert len(patches) == 2 and all(
                    "implemented" in patch for patch in patches
                )
                script = "import json,os,pathlib,socket,struct,subprocess\n"
                script += (
                    "subprocess.run(['git','apply','-'],input="
                    + repr("".join(patches))
                    + ",text=True,check=True)\n"
                )
                script += "assert pathlib.Path('left.txt').read_text()=='left implemented\\n'\nassert pathlib.Path('right.txt').read_text()=='right implemented\\n'\n"
                script += "assert os.getuid()==65532 and not os.access('/workspace/children',os.W_OK)\n"
                script += (
                    "for child in "
                    + repr(child_ids)
                    + ":\n with socket.socket(socket.AF_UNIX,socket.SOCK_STREAM) as s:\n  s.settimeout(5);s.connect('/run/openjules-model/children/'+child+'/model.sock')\n  n=struct.unpack('!I',s.recv(4))[0];data=b''\n  while len(data)<n: data+=s.recv(n-len(data))\n  assert json.loads(data)['error']=='not_authorized'\n"
                )
                script += "print('ROOT_COMPOSED_BOTH_CHILD_PATCHES')\n"
                answer = message("run_command", argv=["python3", "-I", "-c", script])
            else:
                assert (
                    root_turn == 6
                    and json.loads(messages[-1]["content"])["exit_code"] == 0
                )
                answer = message(
                    "finish",
                    summary="Composed both verified provisional child patches; request review",
                )
        response(handler, answer)

    with provider(deterministic) as (endpoint, requests):
        with child_stack(tmp_path, monkeypatch, agent_image, endpoint) as stack:
            wait_complete(stack)
            root = stack.children.journal.context(stack.worker_id)
            children = stack.children.journal.children(stack.worker_id)
            assert len(children) == 2 and {child["uid"] for child in children} == {
                60000,
                60001,
            }
            assert {child["phase"] for child in children} == {"completed"}
            receipt = stack.runtime.inspect_attempt(
                stack.worker_id, stack.spec, root.attempt_id
            )
            assert receipt.exit_code == 0, receipt.log
            assert (
                receipt.termination_confirmed
                and receipt.launch_fenced
                and receipt.artifacts_captured
            )
            assert (
                "+left implemented" in receipt.patch
                and "+right implemented" in receipt.patch
            )
            assert (
                len(stack.authority.candidates) == 1
                and not stack.lifecycle.observe_worker(
                    stack.spec.scope, stack.worker_id
                )["active_executions"]
            )
            events = [event for event, _ in stack.authority.events]
            assert (
                events[:2] == ["child_terminal", "child_terminal"]
                and events[-1] == "root_terminal"
            )
            for child in children:
                captured = json.loads(child["capture"])["contents"]
                manifest = json.loads(captured["manifest"])
                assert (
                    "CHILD_IDENTITY_VERIFIED uid=" + str(child["uid"])
                    in captured["log"]
                )
                assert (
                    manifest["archive_sha256"] == receipt.capture_sha256
                    and manifest["termination_method"] == "whole-container fence"
                )
                assert manifest["exec_start_dispatched"] is True
                assert TOKEN_VALUE not in "".join(captured.values())
            with stack.broker.connection() as db:
                calls = db.execute("SELECT * FROM calls ORDER BY rowid").fetchall()
                assert len(calls) == len(requests) == 10
                assert sum(row["reserved_tokens"] for row in calls) == 10 * 2048
                assert all(row["status"] == "complete" for row in calls)
                assert (
                    sum(row["request_id"].startswith("/child/") for row in calls) == 4
                )
            assert len(stack.child_authority.turns) == 4
            with tarfile.open(receipt.capture_path) as captured:
                assert (
                    captured.extractfile("workspace/run/repo/left.txt").read()
                    == b"left implemented\n"
                )
                for child in children:
                    member = captured.getmember(
                        f"workspace/children/{child['child_id']}/run/repo/.git/HEAD"
                    )
                    assert member.uid == child["uid"]
            assert (stack.source / "left.txt").read_text() == "old\n"
            container = stack.client.containers.get(
                stack.runtime._name(stack.worker_id)
            )
            container.reload()
            assert container.attrs["State"]["Running"] is False
            assert (
                container.attrs["Config"]["Labels"]["openjules.child_policy"]
                == stack.policy.fingerprint
            )
            assert container.attrs["HostConfig"]["CapDrop"] == ["ALL"]
            original_id = container.id
            volume_name = next(
                mount["Name"]
                for mount in container.attrs["Mounts"]
                if mount["Destination"] == "/workspace"
            )
            archive_bytes = Path(receipt.capture_path).read_bytes()
            retained_children = {
                child["child_id"]: child["capture"] for child in children
            }
            bound = json.loads(stack.dispatcher.journal.get(stack.worker_id)["binding"])
            payload = {
                "profile": asdict(stack.profile),
                "spec": asdict(stack.spec),
                "policy": asdict(stack.policy),
                "model": asdict(stack.broker.policies[stack.key]),
                "worker_id": stack.worker_id,
                "binding": bound["binding"],
                "requirements": bound["requirements"],
                "terminal": stack.authority.terminal_receipt,
                "children": stack.child_authority.records,
            }
            stack.children.close()
            stack.broker.close()
            cleanup_process(tmp_path, payload, crash=True)
            with pytest.raises(docker.errors.NotFound):
                stack.client.containers.get(original_id)
            assert stack.client.volumes.get(volume_name)
            interrupted = json.loads(
                stack.runtime._row(stack.worker_id, stack.spec)["cleanup"]
            )
            assert interrupted["container_removed"] is False
            assert Path(receipt.capture_path).read_bytes() == archive_bytes
            cleanup_process(tmp_path, payload)
            reopen_stack(stack, tmp_path)
            assert not stack.broker.endpoints and not stack.children.endpoints.controls
            cleaned = stack.dispatcher.cleanup_worker(stack.spec.scope, stack.worker_id)
            assert cleaned["state"] == "cleaned", cleaned
            with pytest.raises(docker.errors.NotFound):
                stack.client.containers.get(original_id)
            with pytest.raises(docker.errors.NotFound):
                stack.client.volumes.get(volume_name)
            assert Path(receipt.capture_path).read_bytes() == archive_bytes
            assert {
                child["child_id"]: child["capture"]
                for child in stack.children.journal.children(stack.worker_id)
            } == retained_children
            stack.children.close()
            stack.broker.close()
            reopen_stack(stack, tmp_path)
            assert (
                stack.dispatcher.cleanup_worker(stack.spec.scope, stack.worker_id)
                == cleaned
            )
            assert stack.runtime.ensure(stack.worker_id, stack.spec).state == "stopped"
            assert (
                stack.runtime.inspect_attempt(
                    stack.worker_id, stack.spec, root.attempt_id
                )
                == receipt
            )
            assert len(requests) == 10 and len(stack.child_authority.turns) == 4
            assert Path(receipt.capture_path).read_bytes() == archive_bytes


def test_real_siblings_and_root_cannot_read_private_artifacts_or_use_other_sockets(
    tmp_path, monkeypatch, agent_image
):
    turns = {"left": 0, "right": 0}

    def deterministic(handler, requests):
        initial = requests[-1]["body"]["messages"][1]["content"]
        name = "left" if initial.startswith("CHILD_left") else "right"
        assert initial.startswith("CHILD_" + name)
        turns[name] += 1
        assert turns[name] <= 2
        answer = (
            message("write_file", path=name + ".txt", content=name + " private\n")
            if turns[name] == 1
            else message("finish", summary="Retain private " + name + " artifacts")
        )
        response(handler, answer)

    with provider(deterministic) as (endpoint, requests):
        with child_stack(
            tmp_path, monkeypatch, agent_image, endpoint, sleeping_root=True
        ) as stack:
            stack.dispatcher.tick_worker(stack.worker)
            root = stack.children.journal.context(stack.worker_id)
            children = []
            for name in turns:
                result = stack.children.handle(
                    stack.worker_id,
                    {
                        "schema_version": 1,
                        "request_id": "isolation-" + name,
                        "operation": "spawn",
                        "instructions": "CHILD_" + name + ": edit " + name + ".txt",
                        "seconds": 35,
                        "max_turns": 3,
                        "capabilities": ["python"],
                    },
                )
                children.append(result["child_id"])
            until = time.monotonic() + 20
            while time.monotonic() < until:
                records = [
                    stack.children.driver.observe(
                        root, stack.children.journal.child(stack.worker_id, child_id)
                    )
                    for child_id in children
                ]
                if all(child["phase"] == "exec_returned" for child in records):
                    break
                time.sleep(0.05)
            assert {child["phase"] for child in records} == {"exec_returned"}
            assert {child["uid"] for child in records} == {60000, 60001}
            assert turns == {"left": 2, "right": 2} and len(requests) == 4
            assert not any(child["capture"] for child in records)

            # An exec return is provisional. The production model endpoints,
            # container and all three execution references are still live.
            container = stack.client.containers.get(
                stack.runtime._name(stack.worker_id)
            )
            container.reload()
            assert container.attrs["State"]["Running"] is True
            assert (
                len(
                    stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)[
                        "active_executions"
                    ]
                )
                == 3
            )
            contexts = []
            for name, child in zip(turns, records):
                directory = "/workspace/children/" + child["child_id"]
                contexts.append(
                    {
                        "uid": child["uid"],
                        "directory": directory,
                        "files": [
                            directory + "/input.txt",
                            directory + "/run/repo/" + name + ".txt",
                            directory + "/run/change.patch",
                            directory + "/run/output.log",
                        ],
                        "socket": "/run/openjules-model/children/"
                        + child["child_id"]
                        + "/model.sock",
                    }
                )
            root_context = {
                "uid": stack.profile.uid,
                "files": ["/workspace/run/repo/left.txt"],
                "socket": "/run/openjules-model/model.sock",
            }
            for own, others in (
                (contexts[0], [contexts[1]]),
                (contexts[1], [contexts[0]]),
                (root_context, contexts),
            ):
                checked = container.exec_run(
                    ["python3", "-I", "-c", SIBLING_VERIFY, json.dumps([own, others])],
                    user=f"{own['uid']}:{own['uid']}",
                    workdir="/",
                    privileged=False,
                )
                assert checked.exit_code == 0, checked.output.decode(errors="replace")
                assert json.loads(checked.output) == {
                    "uid": own["uid"],
                    "denied_uids": [other["uid"] for other in others],
                }
            assert len(requests) == len(stack.child_authority.turns) == 4
            with stack.broker.connection() as db:
                reserved = db.execute(
                    "SELECT COUNT(*),SUM(reserved_tokens) FROM calls"
                ).fetchone()
                assert tuple(reserved) == (4, 4 * 2048)

            stack.children.handle(
                stack.worker_id,
                {
                    "schema_version": 1,
                    "request_id": "finish-isolation",
                    "operation": "cancel",
                    "child_id": children[0],
                    "reason": "Isolation probes complete; fence and capture the worker",
                },
            )
            wait_complete(stack)
            for name, child_id in zip(turns, children):
                child = stack.children.journal.child(stack.worker_id, child_id)
                assert child["phase"] == "completed"
                captured = json.loads(child["capture"])["contents"]
                assert "+" + name + " private" in captured["patch"]
                assert "CHILD_IDENTITY_VERIFIED" in captured["log"]
            assert len(requests) == 4


def test_earliest_child_watchdog_survives_host_shutdown_and_exec_return(
    tmp_path, monkeypatch, agent_image
):
    calls = 0

    def descendant(handler, requests):
        nonlocal calls
        calls += 1
        if calls == 1:
            script = "import subprocess;subprocess.Popen(['python3','-I','-c','import time;time.sleep(90)'],start_new_session=True,stdout=subprocess.DEVNULL,stderr=subprocess.DEVNULL);print('DESCENDANT_STARTED')"
            answer = message("run_command", argv=["python3", "-I", "-c", script])
        else:
            assert calls == 2
            answer = message(
                "finish", summary="Fixture leaves a UID descendant for watchdog proof"
            )
        response(handler, answer)

    with provider(descendant) as (endpoint, requests):
        with child_stack(
            tmp_path,
            monkeypatch,
            agent_image,
            endpoint,
            sleeping_root=True,
            seconds=45,
            child_seconds=20,
        ) as stack:
            stack.dispatcher.tick_worker(stack.worker)
            assert (
                stack.dispatcher.journal.get(stack.worker_id)["phase"] == "dispatching"
            )
            result = stack.children.handle(
                stack.worker_id,
                {
                    "schema_version": 1,
                    "request_id": "deadline-child",
                    "operation": "spawn",
                    "instructions": "CHILD_deadline: start the controlled descendant and finish",
                    "seconds": 12,
                    "max_turns": 3,
                    "capabilities": ["python"],
                },
            )
            child_id = result["child_id"]
            root = stack.children.journal.context(stack.worker_id)
            until = time.monotonic() + 8
            while time.monotonic() < until:
                child = stack.children.driver.observe(
                    root, stack.children.journal.child(stack.worker_id, child_id)
                )
                if child["phase"] == "exec_returned":
                    break
                time.sleep(0.05)
            assert child["phase"] == "exec_returned" and child["capture"] is None
            container = stack.client.containers.get(
                stack.runtime._name(stack.worker_id)
            )
            scan = "import pathlib\ncount=0\nfor p in pathlib.Path('/proc').glob('[0-9]*/status'):\n try: count+=any(line.startswith('Uid:') and line.split()[1]=='60000' for line in p.read_text().splitlines())\n except FileNotFoundError: pass\nprint(count)"
            checked = container.exec_run(
                ["python3", "-I", "-c", scan], user="65534:65534"
            )
            assert checked.exit_code == 0 and int(checked.output.strip()) >= 1
            stack.dispatcher.stop()
            stack.children.close()
            stack.broker.close()
            # No dispatcher tick, child signal, Docker stop, or deadline helper
            # runs here. The already armed container PID1 must enforce expiry.
            while time.monotonic() < child["armed_deadline"] + 4:
                container.reload()
                if not container.attrs["State"]["Running"]:
                    break
                time.sleep(0.05)
            assert container.attrs["State"]["Running"] is False
            assert time.monotonic() < stack.authority.cutoff
            assert (
                stack.runtime._attempt(stack.worker_id)["deadline"]
                > child["armed_deadline"]
            )
            assert not stack.authority.terminals and not stack.authority.candidates
            reopen_stack(stack, tmp_path)
            wait_complete(stack, timeout=8)
            recovered = stack.children.journal.child(stack.worker_id, child_id)
            assert (
                recovered["exec_id"] == child["exec_id"]
                and recovered["deadline"] == child["deadline"]
            )
            assert recovered["phase"] == "completed"
            assert json.loads(recovered["capture"])["state"] == "timed_out"
            assert not stack.lifecycle.observe_worker(
                stack.spec.scope, stack.worker_id
            )["active_executions"]
            assert len(stack.authority.claims) == len(stack.authority.terminals) == 1
            assert calls == len(requests) == 2


def test_real_lost_child_exec_start_reply_is_fenced_without_relaunch(
    tmp_path, monkeypatch, agent_image
):
    with provider() as (endpoint, requests):
        with child_stack(
            tmp_path,
            monkeypatch,
            agent_image,
            endpoint,
            sleeping_root=True,
            seconds=45,
            child_seconds=20,
        ) as stack:
            stack.dispatcher.tick_worker(stack.worker)
            create, start = stack.client.api.exec_create, stack.client.api.exec_start
            child_execs, starts = [], []

            def tracked_create(*args, **kwargs):
                execution = create(*args, **kwargs)
                if kwargs.get("user") == "60000:60000":
                    child_execs.append(execution["Id"])
                return execution

            def lost_reply(identity, *args, **kwargs):
                result = start(identity, *args, **kwargs)
                if identity in child_execs:
                    starts.append(identity)
                    raise TimeoutError(
                        "controlled lost exec-start response after actual Docker start"
                    )
                return result

            monkeypatch.setattr(stack.client.api, "exec_create", tracked_create)
            monkeypatch.setattr(stack.client.api, "exec_start", lost_reply)
            result = stack.children.handle(
                stack.worker_id,
                {
                    "schema_version": 1,
                    "request_id": "lost-start",
                    "operation": "spawn",
                    "instructions": "Finish the controlled fixture",
                    "seconds": 15,
                    "max_turns": 2,
                    "capabilities": ["python"],
                },
            )
            assert result["state"] == "uncertain" and stack.children.retiring(
                stack.worker_id
            )
            wait_complete(stack, timeout=12)
            child = stack.children.journal.child(stack.worker_id, result["child_id"])
            assert child_execs == starts == [child["exec_id"]]
            assert child["phase"] == "completed" and child["exec_dispatched"] == 1
            manifest = json.loads(json.loads(child["capture"])["contents"]["manifest"])
            assert manifest["termination_method"] == "whole-container fence"
            assert manifest["workspace_present"] and manifest["exec_start_dispatched"]
            assert not stack.lifecycle.observe_worker(
                stack.spec.scope, stack.worker_id
            )["active_executions"]
            assert stack.authority.events[-1][0] == "root_terminal"
            assert not stack.authority.candidates
