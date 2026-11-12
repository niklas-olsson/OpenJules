"""Real SDK over a named stdio conversation fixture, not actual Polyphony A."""

from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
import json
import os
from pathlib import Path
import signal
import sys
import time
import venv

import anyio
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from src.polyphony.conversation_client import CleanupObserver, connect
from src.worker.discussion_types import (
    CHILD_ENVIRONMENT, Deadline, DiscussionError, Policy, canonical, publication_intent,
)
from tests.unit.test_discussion_journal import (
    fixture_policy, fixture_status, fixture_turn, private_json, signed_record,
)


FIXTURE_SERVER = r'''
import argparse,hashlib,json,os,pathlib,signal,sqlite3,subprocess,sys,threading,time
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat

def enc(value):
    return json.dumps(value,sort_keys=True,separators=(',',':'),allow_nan=False).encode()

args=argparse.ArgumentParser()
args.add_argument('--config',required=True)
config=json.loads(pathlib.Path(args.parse_args().config).read_text())
root=pathlib.Path(__file__).resolve().parents[2]
scenario=json.loads((root/'fixture.json').read_text())
mode=scenario.get('mode','normal')
state=pathlib.Path(config['state_directory'])
state.mkdir(mode=0o700,exist_ok=True)

def private(path,value):
    path.write_bytes(enc(value)+b'\n')
    path.chmod(0o600)

private(state/'environment.json',dict(os.environ))
private(state/'leader.json',{'pid':os.getpid(),'group':os.getpgrp()})
if mode=='leader_exit_pipe':
    child=subprocess.Popen([sys.executable,'-c','import time;time.sleep(60)'])
    private(state/'descendant.json',{'pid':child.pid,'group':os.getpgrp()})
    os._exit(0)
if mode=='oversized':
    os.write(1,b'x'*262145)
    time.sleep(60)
if mode=='partial':
    os.write(1,b'{"jsonrpc":"2.0"')
    time.sleep(60)
if mode=='stderr_overflow':
    os.write(2,b'x'*65537)
    time.sleep(60)

key=Ed25519PrivateKey.from_private_bytes(b'\x17'*32)
public=key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw).hex()
swarm=hashlib.sha256(pathlib.Path(config['scope_key_file']).read_bytes()).hexdigest()
topic=config['topic']
session=hashlib.sha256(enc(['polyphony-public-conversation-v1',swarm,topic])).hexdigest()
status={'schema_version':1,'profile':'polyphony-public-conversation','topic':topic,
'swarm_id':swarm,'session_id':session,'author':hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16],
'public_key':public,'stream_id':('b' if mode=='changed_identity' else 'a')*32,
'visibility':'public','execution_authorized':False}
S={'type':'string'}
I={'type':'integer'}
N=lambda kind:{'anyOf':[kind,{'type':'null'}],'default':None}
R={'type':'array','items':{'type':'object','additionalProperties':{'type':'string'}}}
def schema(properties,required):
    return {'type':'object','properties':properties,'required':required}
schemas=[
('conversation_status',schema({},[])),
('conversation_start',schema({'topic':S,'request_key':N(S)},['topic'])),
('conversation_join',schema({'topic':S,'decision':dict(S,default='join'),
'message':dict(S,default=''),'request_key':N(S)},['topic'])),
('conversation_say',schema({'topic':S,'message':S,'request_key':N(S),
'reply_to':N(S),'kind':dict(S,default='message'),'target':N(S),'references':N(R)},['topic','message'])),
('conversation_history',schema({'topic':S,'after':dict(I,default=0),'limit':dict(I,default=100),
'stream_id':N(S)},['topic'])),
('conversation_watch',schema({'topic':S,'after':dict(I,default=0),'limit':dict(I,default=100),
'stream_id':N(S),'timeout':{'type':'number','default':30}},['topic'])),
]
tools=[{'name':name,'inputSchema':shape} for name,shape in schemas]
if mode=='extra_tool':
    tools.append({'name':'execute_command','inputSchema':schema({'command':S},['command'])})
if mode=='output_schema':
    tools[0]['outputSchema']={'type':'object'}
if mode=='task_tool':
    tools[0]['execution']={'taskSupport':'optional'}
if mode=='wrong_input':
    tools[1]['inputSchema']['required']=[]
write_lock=threading.Lock()
def emit(value):
    raw=enc(value)
    if mode=='wire_padding':
        raw+=b' '*200000
    with write_lock:
        sys.stdout.buffer.write(raw+b'\n');sys.stdout.buffer.flush()
def reply(identifier,result):
    emit({'jsonrpc':'2.0','id':identifier,'result':result})
def app(identifier,value):
    reply(identifier,{'content':[{'type':'text','text':enc(value).decode()}],'isError':False})
def notify_after_provider():
    for _ in range(1000):
        if (state/'provider-entered.flag').exists():
            emit({'jsonrpc':'2.0','method':'notifications/tools/list_changed'})
            return
        time.sleep(.01)
if mode=='notify_during_provider':
    threading.Thread(target=notify_after_provider,daemon=True).start()
database=sqlite3.connect(state/'fixture-posts.sqlite3')
os.chmod(state/'fixture-posts.sqlite3',0o600)
database.execute('CREATE TABLE IF NOT EXISTS posts (key TEXT PRIMARY KEY,intent TEXT,record TEXT)')
database.commit()
for line in sys.stdin.buffer:
    request=json.loads(line)
    with (state/'requests.jsonl').open('ab') as log:
        log.write(enc(request)+b'\n')
    os.chmod(state/'requests.jsonl',0o600)
    method=request.get('method')
    if method=='notifications/initialized':
        continue
    identifier=request['id']
    if method=='initialize':
        caps={'tools':{}}
        if mode=='resources':
            caps['resources']={}
        reply(identifier,{'protocolVersion':request['params']['protocolVersion'],
        'capabilities':caps,'serverInfo':{'name':'named-conversation-fixture','version':'1'}})
    elif method=='tools/list':
        result={'tools':tools}
        if mode=='tool_pagination':
            result['nextCursor']='unexpected'
        reply(identifier,result)
        if mode=='list_changed':
            emit({'jsonrpc':'2.0','method':'notifications/tools/list_changed'})
    elif method=='tools/call':
        name=request['params']['name']
        arguments=request['params']['arguments']
        if name=='conversation_status':
            result=status
            if mode=='bool_status':
                result=dict(status,schema_version=True)
            app(identifier,result)
        elif name in ('conversation_history','conversation_watch'):
            if name=='conversation_watch':
                time.sleep(arguments['timeout'])
            after=arguments['after']
            available=[item for item in scenario.get('records',[]) if item['cursor']>after]
            messages=[];used=0
            for item in available[:arguments['limit']]:
                size=len(enc(item))
                if used+size>24576:
                    break
                messages.append(item);used+=size
            next_cursor=messages[-1]['cursor'] if messages else after
            page={'schema_version':1,'session_id':session,'topic':topic,
            'stream_id':status['stream_id'],'messages':messages,'next_cursor':next_cursor,
            'has_more':len(available)>len(messages),'gap':None,'peer_gaps':{'count':0,'items':[]}}
            if mode=='gap':
                page.update(messages=[],next_cursor=0,
                gap='local history stream changed or cursor is ahead')
            if mode=='stalled':
                page['has_more']=True
            app(identifier,page)
        elif name=='conversation_say':
            intent={'topic':topic,'session_id':session,'swarm_id':swarm,'visibility':'public',
            'request_key':arguments['request_key'],'kind':arguments['kind'],
            'content':arguments['message'],'reply_to':arguments['reply_to'],
            'target':arguments['target'],'references':arguments['references']}
            retained=database.execute('SELECT intent,record FROM posts WHERE key=?',
            (arguments['request_key'],)).fetchone()
            created=False
            if retained:
                if retained[0]!=enc(intent).decode():
                    emit({'jsonrpc':'2.0','id':identifier,'error':{'code':-32602,'message':'conflict'}})
                    continue
                record=json.loads(retained[1])
            else:
                body=dict(intent,schema_version=1,author=status['author'],public_key=public,timestamp=time.time())
                body_bytes=enc(body)
                record={'message_id':hashlib.sha256(body_bytes).hexdigest(),'body':body,
                'signature':key.sign(body_bytes).hex()}
                database.execute('INSERT INTO posts VALUES(?,?,?)',
                (arguments['request_key'],enc(intent).decode(),enc(record).decode()))
                database.commit()
                created=True
            if mode=='lost_ack_once' and created:
                os._exit(0)
            if mode=='bad_receipt':
                record=dict(record,signature='0'*128)
            ack={'schema_version':1,'message_id':record['message_id'],'session_id':session,
            'author':status['author'],'stored':True,'visibility':'public','delivery':'submitted',
            'execution_authorized':False,'record':record}
            app(identifier,ack)
        else:
            emit({'jsonrpc':'2.0','id':identifier,'error':{'code':-32601,'message':'not used'}})
    else:
        raise RuntimeError('fixture received unexpected client method')
database.close()
'''


def install_fixture(policy, *, mode="normal", records=None):
    checkout = Path(policy.server["cwd"])
    package = checkout / "src" / "liminal_bridge"
    package.mkdir(parents=True, exist_ok=True)
    (checkout / "src" / "__init__.py").write_text("", encoding="utf-8")
    (package / "__init__.py").write_text("", encoding="utf-8")
    (package / "conversation_server.py").write_text(FIXTURE_SERVER, encoding="utf-8")
    private_json(checkout / "fixture.json", {"mode": mode, "records": records or []})


def server_requests(policy):
    path = Path(policy.a_config["state_directory"]) / "requests.jsonl"
    if not path.exists():
        return []
    return [json.loads(line) for line in path.read_bytes().splitlines()]


def application_requests(policy):
    return [
        item["params"] for item in server_requests(policy)
        if item.get("method") == "tools/call"
    ]


def short_deadline(seconds=3):
    return Deadline(time.time() + seconds, time.monotonic() + seconds)


@pytest.mark.parametrize("source", ["policy", "launch"])
def test_real_sdk_exact_tools_status_environment_and_original_venv_path(
    tmp_path, monkeypatch, source,
):
    policy, _, status = fixture_policy(tmp_path)
    prefix = tmp_path / "approved-venv"
    venv.EnvBuilder(
        system_site_packages=True, with_pip=False, symlinks=True
    ).create(prefix)
    launch = prefix / "bin" / "python"
    assert launch.is_symlink()
    assert launch != launch.resolve(strict=True)
    document = deepcopy(policy.document)
    document["server"]["python"] = str(launch)
    private_json(policy.path, document)
    policy = Policy.load(policy.path)
    interpreter = {
        "schema_version": 1, "launch_path": str(launch),
        "resolved_executable": str(launch.resolve(strict=True)),
        "prefix": str(prefix.resolve(strict=True)),
    }
    install_fixture(policy)
    monkeypatch.setenv("HOME", "private-home-canary")
    monkeypatch.setenv("HTTPS_PROXY", "http://private-proxy-canary")
    monkeypatch.setenv("DISCUSSION_FIXTURE_TOKEN", "private-provider-canary")
    monkeypatch.setenv("PYTHONPATH", "private-pythonpath-canary")
    cleanup = CleanupObserver()

    async def run():
        approved = policy if source == "policy" else policy.launch
        async with connect(
            approved, Deadline.observe(), expected_status=status, cleanup=cleanup,
        ) as client:
            assert client.status == status
            assert client.interpreter == interpreter
            assert cleanup.result.attempted_processes == 2
            assert cleanup.result.cleaned_processes == 1
            assert cleanup.result.active_processes == 1
            assert cleanup.result.confirmed is False
            assert await client.check_status(status) == status
            assert (await client.history())["messages"] == []

    asyncio.run(run())
    assert cleanup.result.confirmed is True
    assert cleanup.result.attempted_processes == 2
    assert cleanup.result.cleaned_processes == 2
    state = Path(policy.a_config["state_directory"])
    assert json.loads((state / "environment.json").read_bytes()) == CHILD_ENVIRONMENT
    requests = server_requests(policy)
    assert [request["method"] for request in requests[:3]] == [
        "initialize", "notifications/initialized", "tools/list",
    ]
    assert requests[0]["params"]["capabilities"] == {}
    assert application_requests(policy)[0]["name"] == "conversation_status"
    assert all("private-" not in canonical(request).decode() for request in requests)


@pytest.mark.parametrize("mode", [
    "extra_tool", "output_schema", "task_tool", "wrong_input",
    "resources", "tool_pagination",
])
def test_unapproved_surface_is_rejected_before_first_status(tmp_path, mode):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy, mode=mode)

    async def run():
        async with connect(policy, Deadline.observe()):
            pytest.fail("unapproved profile entered")

    with pytest.raises(DiscussionError, match="unsupported_profile"):
        asyncio.run(run())
    assert application_requests(policy) == []


@pytest.mark.parametrize("mode", ["list_changed", "bool_status"])
def test_dynamic_or_malformed_profile_cannot_enter(tmp_path, mode):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy, mode=mode)

    async def run():
        async with connect(policy, Deadline.observe()):
            pytest.fail("invalid profile entered")

    with pytest.raises(DiscussionError):
        asyncio.run(run())


def test_trusted_status_and_caller_errors_survive_sdk_task_group_exit(tmp_path):
    policy, _, status = fixture_policy(tmp_path)
    install_fixture(policy)
    wrong = dict(status, stream_id="b" * 32)

    async def changed():
        async with connect(policy, Deadline.observe(), expected_status=wrong):
            pytest.fail("changed stream entered")

    with pytest.raises(DiscussionError, match="^state_conflict$"):
        asyncio.run(changed())

    async def caller():
        async with connect(policy, Deadline.observe()):
            raise DiscussionError("invalid_context")

    with pytest.raises(DiscussionError, match="^invalid_context$"):
        asyncio.run(caller())


@pytest.mark.parametrize("mode", ["oversized", "partial", "stderr_overflow"])
def test_bounded_real_pipes_reject_and_reap_original_leader(tmp_path, mode):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy, mode=mode)
    started = time.monotonic()

    async def run():
        async with connect(policy, short_deadline()):
            pytest.fail("bad stream entered")

    with pytest.raises(DiscussionError):
        asyncio.run(run())
    assert time.monotonic() - started < 9
    leader = json.loads(
        (Path(policy.a_config["state_directory"]) / "leader.json").read_bytes()
    )
    with pytest.raises(ChildProcessError):
        os.waitpid(leader["pid"], os.WNOHANG)


def test_cumulative_raw_wire_limit_counts_valid_padded_frames(tmp_path):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy, mode="wire_padding")

    async def run():
        async with connect(policy, Deadline.observe()) as client:
            for _ in range(8):
                await client.history()

    with pytest.raises(DiscussionError, match="transport_invalid"):
        asyncio.run(run())
    # Every frame is individually below262144 and contains valid protocol JSON.
    # The aggregate fails before all eight additional observations can complete.
    assert len(application_requests(policy)) < 9


def test_leader_exit_with_descendant_pipe_still_terminates_owned_group(tmp_path):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy, mode="leader_exit_pipe")
    state = Path(policy.a_config["state_directory"])

    async def run():
        async with connect(policy, short_deadline()):
            pytest.fail("exited leader entered")

    with pytest.raises(DiscussionError):
        asyncio.run(run())
    leader = json.loads((state / "leader.json").read_bytes())
    descendant = json.loads((state / "descendant.json").read_bytes())
    try:
        with pytest.raises(ChildProcessError):
            os.waitpid(leader["pid"], os.WNOHANG)
        assert descendant["group"] == leader["pid"]
        path = Path(f"/proc/{descendant['pid']}/stat")
        if path.exists():
            tail = path.read_bytes().rsplit(b")", 1)[1].split()
            assert tail[0] in {b"Z", b"X"}
    finally:
        # Test cleanup only, even if a future regression skips group signaling.
        path = Path(f"/proc/{descendant['pid']}/stat")
        if path.exists():
            tail = path.read_bytes().rsplit(b")", 1)[1].split()
            if int(tail[2]) == leader["pid"] and tail[0] not in {b"Z", b"X"}:
                os.kill(descendant["pid"], signal.SIGKILL)


def test_watch_uses_its_explicit_wait_instead_of_default_ten_second_rpc(tmp_path):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy)

    async def run():
        async with connect(policy, Deadline.observe()) as client:
            started = time.monotonic()
            page = await client.history(watch=11)
            assert page["messages"] == []
            assert 10 <= time.monotonic() - started < 16

    asyncio.run(run())
    calls = application_requests(policy)
    watch = next(item for item in calls if item["name"] == "conversation_watch")
    assert watch["arguments"]["timeout"] == 11
    assert watch["arguments"]["stream_id"] == fixture_status()["stream_id"]


@pytest.mark.parametrize("mode", ["gap", "stalled"])
def test_gap_or_nonprogress_cannot_silently_reset_selected_context(tmp_path, mode):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy, mode=mode)
    turn = fixture_turn(selected_message_ids=["f" * 64])

    async def run():
        async with connect(policy, Deadline.observe()) as client:
            await client.selected_context(turn)

    with pytest.raises(DiscussionError, match="invalid_history"):
        asyncio.run(run())
    assert len([x for x in application_requests(policy)
                if x["name"] == "conversation_history"]) == 1


def signed_item(index, content="A public context item.", status=None, *, signing_key=None):
    status = status or fixture_status()
    intent = publication_intent(
        status, fixture_turn(f"record-{index}"), {"kind": "message", "content": content}
    )
    if signing_key is None:
        record = signed_record(status, intent)
    else:
        public = signing_key.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
        body = {
            **intent, "schema_version": 1, "public_key": public,
            "author": hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16],
            "timestamp": 1234.5,
        }
        encoded = canonical(body)
        record = {
            "message_id": hashlib.sha256(encoded).hexdigest(), "body": body,
            "signature": signing_key.sign(encoded).hex(),
        }
    return {"cursor": index + 1, "record": record, "reply_state": "none"}


def test_selected_signed_records_keep_sparse_cursor_order(tmp_path):
    policy, _, status = fixture_policy(tmp_path)
    peer_key = Ed25519PrivateKey.from_private_bytes(b"\x33" * 32)
    records = [signed_item(2), signed_item(8, signing_key=peer_key)]
    assert records[1]["record"]["body"]["author"] != status["author"]
    install_fixture(policy, records=records)
    turn = fixture_turn(
        selected_message_ids=[item["record"]["message_id"] for item in reversed(records)]
    )

    async def run():
        async with connect(policy, Deadline.observe(), expected_status=status) as client:
            context = await client.selected_context(turn)
            assert context["messages"] == records
            assert context["context_after"] == 0
            assert context["next_cursor"] == 9
            assert context["status"] == status

    asyncio.run(run())


@pytest.mark.parametrize("kind", ["changed_body", "foreign_scope"])
def test_untrusted_signed_context_is_rejected_before_it_can_be_selected(tmp_path, kind):
    policy, _, _ = fixture_policy(tmp_path)
    if kind == "foreign_scope":
        item = signed_item(0, status=fixture_status("another-public-topic"))
    else:
        item = signed_item(0)
        item["record"]["body"]["content"] = "Changed without a new signature."
    install_fixture(policy, records=[item])
    turn = fixture_turn(selected_message_ids=[item["record"]["message_id"]])

    async def run():
        async with connect(policy, Deadline.observe()) as client:
            await client.selected_context(turn)

    with pytest.raises(DiscussionError, match="^invalid_record$"):
        asyncio.run(run())
    assert all(item["name"] != "conversation_say" for item in application_requests(policy))


def test_cumulative_selected_record_bytes_have_a_real_paged_boundary(tmp_path):
    policy, _, _ = fixture_policy(tmp_path)
    records = [signed_item(index, "x" * 4096) for index in range(32)]
    assert all(len(canonical(item)) * 5 <= 24576 for item in records)
    assert sum(len(canonical(item["record"])) for item in records[:24]) <= 131072
    assert sum(len(canonical(item["record"])) for item in records) > 131072
    install_fixture(policy, records=records)
    good = fixture_turn("within", selected_message_ids=[
        item["record"]["message_id"] for item in records[:24]
    ])

    async def positive():
        async with connect(policy, Deadline.observe()) as client:
            assert (await client.selected_context(good))["messages"] == records[:24]

    asyncio.run(positive())
    before = len(application_requests(policy))
    bad = fixture_turn("exceeds", selected_message_ids=[
        item["record"]["message_id"] for item in records
    ])

    async def negative():
        async with connect(policy, Deadline.observe()) as client:
            await client.selected_context(bad)

    with pytest.raises(DiscussionError, match="^invalid_context$"):
        asyncio.run(negative())
    new_calls = application_requests(policy)[before:]
    histories = [item for item in new_calls if item["name"] == "conversation_history"]
    assert 1 < len(histories) < 8
    assert all(item["name"] != "conversation_say" for item in new_calls)


def test_eight_page_discovery_limit_preserves_last_allowed_positive(tmp_path):
    policy, _, _ = fixture_policy(tmp_path)
    records = [signed_item(index, "\u0800" * 2400) for index in range(9)]
    assert all(len(canonical(item["record"])) <= 16384 for item in records)
    assert all(12288 < len(canonical(item)) <= 24576 for item in records)
    install_fixture(policy, records=records)
    allowed = fixture_turn("eighth", selected_message_ids=[records[7]["record"]["message_id"]])

    async def positive():
        async with connect(policy, Deadline.observe()) as client:
            context = await client.selected_context(allowed)
            assert context["messages"] == [records[7]]

    asyncio.run(positive())
    before = len(application_requests(policy))
    refused = fixture_turn("ninth", selected_message_ids=[records[8]["record"]["message_id"]])

    async def negative():
        async with connect(policy, Deadline.observe()) as client:
            await client.selected_context(refused)

    with pytest.raises(DiscussionError, match="^invalid_context$"):
        asyncio.run(negative())
    histories = [
        item for item in application_requests(policy)[before:]
        if item["name"] == "conversation_history"
    ]
    assert len(histories) == 8
    assert [item["arguments"]["after"] for item in histories] == list(range(8))
