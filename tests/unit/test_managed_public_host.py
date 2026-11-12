"""Joined host tests with real Unix/HTTP/SQLite and owned MCP fixture processes.

The authority, root exec and child launch facts are explicit component fixtures.
The public fixture has distinct real signing keys and a local retained transcript;
it is not installed A, native discovery, Docker UID confinement or a live provider.
"""

from contextlib import closing, contextmanager
from copy import deepcopy
from dataclasses import asdict, replace
import hashlib
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import struct
import tarfile
import threading
import time
from types import SimpleNamespace

import pytest

from src.agent.public_tools import PublicClient, PublicError, PublicTools
from src.worker.child_broker import ChildBroker
from src.worker.child_journal import ChildJournal
from src.worker.child_runtime import ChildRuntime
from src.worker.child_supervisor import ChildDenied, ChildSupervisor
from src.worker.discussion_types import Deadline, boot_id
from src.worker.docker_runtime import ExecutionReceipt
from src.worker.lifecycle import LifecycleConflict, RuntimeUnavailable
from src.worker.managed_public import PublicSupervisor
from src.worker.managed_public_broker import PublicBroker
from src.worker import managed_public_types as public
from src.worker.model_broker import BrokerDenied, ModelBroker, ModelPolicy
from tests.unit.test_child_authority_contract import context, policy as child_policy, request
from tests.unit.test_child_session_store import database_snapshot
from tests.unit.test_child_supervisor import FixtureAuthority, FixtureDriver, FixtureLifecycle
from tests.unit.test_managed_agent import provider, TEST_TOKEN
from tests.unit.test_managed_public_journal import operation, selection
from tests.unit.test_managed_public_profiles import install_owned_fixture, wait_until
from tests.unit.test_managed_public_types import public_document


def install_public_fixture(document, mode="normal"):
    """Named per-actor signer and shared local transcript, never a mesh claim."""
    install_owned_fixture(document, mode)
    source_path = Path(document["server"]["cwd"]) / "src/liminal_bridge/conversation_server.py"
    source = source_path.read_text()
    old = r"key=Ed25519PrivateKey.from_private_bytes(b'\x17'*32)"
    assert source.count(old) == 1
    source = source.replace(
        old,
        "key=Ed25519PrivateKey.from_private_bytes(hashlib.sha256(state.parent.name.encode()).digest())",
    )
    old = "'stream_id':('b' if mode=='changed_identity' else 'a')*32,"
    assert source.count(old) == 1
    source = source.replace(
        old,
        "'stream_id':hashlib.sha256(('stream:'+state.parent.name).encode()).hexdigest()[:32],",
    )
    marker = "database.commit()\nfor line in sys.stdin.buffer:"
    assert source.count(marker) == 1
    source = source.replace(marker, """
database.commit()
shared=sqlite3.connect(root/'public-records.sqlite3',timeout=5)
shared.execute('CREATE TABLE IF NOT EXISTS records (cursor INTEGER PRIMARY KEY AUTOINCREMENT,message_id TEXT UNIQUE,record TEXT)')
shared.commit()
os.chmod(root/'public-records.sqlite3',0o600)
for line in sys.stdin.buffer:""")
    old = "available=[item for item in scenario.get('records',[]) if item['cursor']>after]"
    assert source.count(old) == 1
    source = source.replace(old, """
            available=[]
            for cursor,raw in shared.execute('SELECT cursor,record FROM records WHERE cursor>? ORDER BY cursor',(after,)):
                record=json.loads(raw)
                available.append({'cursor':cursor,'record':record,
                    'reply_state':'resolved' if record['body']['reply_to'] is not None else 'none'})
""".strip())
    marker = "            if mode=='lost_ack_once' and created:"
    assert source.count(marker) == 1
    source = source.replace(marker, """
            shared.execute('INSERT OR IGNORE INTO records(message_id,record) VALUES(?,?)',
                           (record['message_id'],enc(record).decode()))
            shared.commit()
""" + marker)
    source = source.replace("database.close()", "shared.close()\ndatabase.close()")
    source_path.write_text(source, encoding="utf-8")


def public_completion(handler, *, kind="message", content="Approved public reasoning."):
    raw = json.dumps({
        "choices": [{
            "message": {"role": "assistant", "content": json.dumps({"kind": kind, "content": content})},
            "finish_reason": "stop",
        }],
    }).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(raw)))
    handler.end_headers()
    handler.wfile.write(raw)


class NamedAuthority(FixtureAuthority):
    """Original grant/turn fixture with a real-clock unchanged permission bound."""

    def call(self, operation, scope, attempt_id, **payload):
        result = super().call(operation, scope, attempt_id, **payload)
        if "binding" in result:
            return result | {"remaining_seconds": max(0, min(40, self.root.deadline - time.time()))}
        if operation == "observe":
            manifest = json.loads(self.artifacts[(payload["child_id"], "manifest")])
            outcome = manifest.get("work_outcome")
            if outcome is not None:
                result["child"]["initial_outcome"] = outcome | {
                    "artifacts": payload["artifacts"], "canonical_committed": True,
                    "release_authorized": False,
                }
        return result


class NamedDriver(FixtureDriver):
    def launch(self, root, child, cutoff):
        super().launch(root, child, cutoff)
        self.supervisor.journal.update(
            root.worker_id, child["child_id"], armed_deadline=cutoff,
        )

    def final_capture(self, root, child, receipt):
        return ChildRuntime(self.supervisor.runtime, self.supervisor).final_capture(
            root, child, receipt,
        )


class HostFixture:
    def __init__(self, path, monkeypatch, endpoint, *, mode="normal"):
        self.model = self.children = self.public = self.descriptor = None
        self.path = path
        self.document = public_document(path)
        install_public_fixture(self.document, mode)
        self.root = replace(
            context(), deadline=time.time() + 90,
            monotonic_deadline=time.monotonic() + 90, boot_id=boot_id(),
        )
        self.policy = replace(
            child_policy(), max_child_seconds=45, outcome_protocol="initial-v1",
            public_discussion=self.document,
        )
        self.scope = (self.root.spec.deployment_id, self.root.spec.repository, self.root.spec.profile)
        self.allowed = True
        self.root_input = "PRIVATE_ROOT_INSTRUCTION_CANARY"
        self.attempt = {
            "attempt_id": self.root.attempt_id,
            "input_sha256": hashlib.sha256(self.root_input.encode()).hexdigest(),
            "exec_id": "named-root-exec", "exec_dispatched": 1,
            "deadline": self.root.monotonic_deadline,
        }
        self.runtime_row = {"create_dispatched": 1, "container_id": "named-container"}
        self.runtime = SimpleNamespace(
            _attempt=lambda worker: deepcopy(self.attempt) if worker == self.root.worker_id else None,
            _row=lambda worker, spec: deepcopy(self.runtime_row)
                if worker == self.root.worker_id and spec == self.root.spec else None,
            _profile=lambda spec: SimpleNamespace(uid=os.getuid()),
        )
        monkeypatch.setenv("MOCK_MODEL_TOKEN", TEST_TOKEN)
        self.model_policy = ModelPolicy(
            endpoint, "fixture-public-model", "env:MOCK_MODEL_TOKEN",
            max_calls=12, max_output_tokens=128, max_total_output_tokens=1536,
            request_timeout_seconds=5,
        )
        self.lifecycle = FixtureLifecycle(self.root)
        self.authority = NamedAuthority(self.root)
        self._start_services()

    def _start_services(self):
        self.model = ModelBroker(
            self.path / "models", {self.scope: self.model_policy},
            lambda _binding: max(0, self.root.monotonic_deadline - time.monotonic())
                if self.allowed else 0,
            peer_uids={self.scope: os.getuid()},
        )
        self.children = ChildSupervisor(
            self.path / "children", {self.scope: self.policy}, None,
            self.lifecycle, self.runtime, self.model,
            lambda _root: max(0, self.root.monotonic_deadline - time.monotonic())
                if self.allowed else 0,
            lambda _root: self.allowed,
        )
        self.children.authority = self.authority
        self.children.driver = NamedDriver(self.children)
        self.children.endpoints = ChildBroker(self.children, self.model)
        self.public = PublicSupervisor(self.children)
        self.children.public_supervisor = self.public
        self.public.endpoints = PublicBroker(self.public)
        self.model.child_supervisor = self.children
        self.model.public_supervisor = self.public
        self.children.journal.prepare(self.root.worker_id, self.root.spec, self.policy)
        self.root = self.children.journal.bind(self.root)
        directory = self.model.prepare_worker(self.root.worker_id, self.root.spec)
        self.model.bind_attempt(
            self.root.worker_id, self.root.spec, self.root.attempt_id, 90,
            deadline_monotonic=self.root.monotonic_deadline,
        )
        self.children.prepare_worker(self.root.worker_id, self.root.spec, directory)
        self.descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.socket_path = f"/proc/self/fd/{self.descriptor}/public.sock"
        self.client = PublicClient(self.socket_path, role="root", timeout_seconds=8)

    def request(self, name, key, *, who=None, **values):
        if who is None:
            return self.client.request(name, request_id=key, **values)
        return self.public.handle(
            self.root.worker_id, operation(name, key, **values), child_id=who,
        )["result"]

    def spawn(self, key="ordinary-child-one"):
        result = self.children.handle(
            self.root.worker_id, operation(
                "spawn", key, **(request() | {
                    "instructions": "PRIVATE_CHILD_INSTRUCTION_CANARY:" + key,
                    "seconds": 40, "max_turns": 3,
                }),
            ),
        )
        return result["child_id"]

    def view(self):
        return self.public.store.view(self.root, self.policy)

    def calls(self):
        with self.model.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM calls ORDER BY rowid")]

    def audit(self, who="root"):
        actor = self.view()["actors"][who]
        return self.path / "observations" / actor["identity_digest"]

    def wire_requests(self, who="root"):
        path = self.audit(who) / "requests.jsonl"
        return [] if not path.exists() else [json.loads(line) for line in path.read_bytes().splitlines()]

    def capture(self):
        archive_path = self.path / "named-whole-worker.tar"
        with tarfile.open(archive_path, "w") as archive:
            files = {"workspace/run/change.patch": b"", "workspace/run/output.log": b"root log"}
            for child in self.children.journal.children(self.root.worker_id):
                prefix = "workspace/children/" + child["child_id"] + "/run/"
                files[prefix + "change.patch"] = b""
                files[prefix + "output.log"] = b"child private log"
            for name, value in files.items():
                info = tarfile.TarInfo(name)
                info.size = len(value)
                archive.addfile(info, io.BytesIO(value))
        archive_hash = hashlib.sha256(archive_path.read_bytes()).hexdigest()
        manifest = public.canonical({
            "schema_version": 1, "worker_id": self.root.worker_id,
            "attempt_id": self.root.attempt_id, "archive_sha256": archive_hash,
            "termination_confirmed": True, "launch_fenced": True,
        }).decode()
        return ExecutionReceipt(
            state="completed", termination_confirmed=True, launch_fenced=True,
            artifacts_captured=True, capture_path=str(archive_path),
            capture_sha256=archive_hash, manifest=manifest, exit_code=0,
        )

    def close(self):
        try:
            if self.children is not None:
                self.children.close()
        finally:
            if self.model is not None:
                self.model.close()
        try:
            if self.public is not None:
                self.public.profiles.thread.join(timeout=6)
                assert not self.public.profiles.thread.is_alive()
                wait_until(lambda: not self.public.active)
            if self.children is not None:
                wait_until(lambda: self.children.journal.service_lock.closed)
            if self.model is not None:
                wait_until(lambda: self.model._service_lock.closed)
        finally:
            if self.descriptor is not None:
                os.close(self.descriptor)
                self.descriptor = None

    def reopen(self):
        self.close()
        self._start_services()


@pytest.fixture
def host_factory(tmp_path, monkeypatch):
    fixtures = []
    def create(endpoint, mode="normal"):
        path = tmp_path / str(len(fixtures))
        path.mkdir(mode=0o700)
        fixture = HostFixture.__new__(HostFixture)
        fixtures.append(fixture)
        fixture.__init__(path, monkeypatch, endpoint, mode=mode)
        return fixture
    try:
        yield create
    finally:
        for fixture in reversed(fixtures):
            fixture.close()


def fresh_client(fixture):
    return PublicClient(fixture.socket_path, role="root", timeout_seconds=8)


class OriginalKeyClient(PublicClient):
    """Trusted retry fixture; model-visible fields never choose a request key."""

    def __init__(self, fixture, request_id):
        super().__init__(fixture.socket_path, role="root", timeout_seconds=8)
        self.original_request_id = request_id
        self.dispatches = []

    def request(self, name, **arguments):
        assert "request_id" not in arguments
        self.dispatches.append((name, deepcopy(arguments)))
        return super().request(name, request_id=self.original_request_id, **arguments)


def test_real_root_socket_and_child_pull_share_accounting_and_selected_signed_context(host_factory):
    def answer(handler, requests):
        public_completion(
            handler, content="Public proposal." if len(requests) == 1 else "Independent public criticism.",
        )
    with provider(answer) as (endpoint, requests):
        fixture = host_factory(endpoint)
        first = fixture.request("public_turn", "mpub1:proposal", **selection())["slot"]
        record = first["receipt"]["record"]
        assert first["state"] == "published"
        assert fixture.calls()[0]["status"] == "complete"
        child = fixture.spawn()
        before_model, before_authority = fixture.calls(), list(fixture.children.authority.events)
        offered = fixture.request(
            "public_activate", "mpub1:offer", child_id=child,
            **selection(selected_message_ids=[record["message_id"]], reply_to=record["message_id"]),
        )["slot"]
        assert offered["state"] == "offered" and offered["actor"]["status"] is None
        assert fixture.calls() == before_model
        # An offer checks the child's existing permission without a grant or turn.
        assert fixture.children.authority.events == before_authority + [
            ("permission", {"child_id": child}),
        ]
        assert fixture.view()["actors"][child]["generations"] == 0
        result = fixture.request(
            "public_pull", "mpub1:child-decision", who=child, slot_id=offered["slot_id"],
        )["slot"]
        assert result["state"] == "published"
        assert result["receipt"]["record"]["body"]["reply_to"] == record["message_id"]
        assert result["actor"]["status"]["author"] != first["actor"]["status"]["author"]
        view = fixture.view()
        assert view["slots"][result["slot_id"]]["context"] == [record]
        assert requests[1]["body"]["messages"] == public.public_messages(
            public.PublicPolicy.parse(fixture.document), "independent", "proposal", [record],
        )
        assert all("tools" not in item["body"] and item["body"]["stream"] is False for item in requests)
        assert len(fixture.calls()) == 2
        assert all(row["status"] == "complete" and row["request_id"].startswith("/public/")
                   for row in fixture.calls())
        turns = [payload for name, payload in fixture.children.authority.events if name == "turn"]
        assert len(turns) == 1 and turns[0]["child_id"] == child
        public_bytes = json.dumps([item["body"] for item in requests]) + json.dumps(view["records"])
        assert fixture.root_input not in public_bytes
        assert "PRIVATE_CHILD_INSTRUCTION_CANARY" not in public_bytes
        assert "private-scope-canary" not in public_bytes and TEST_TOKEN not in public_bytes
        snapshot = database_snapshot(fixture.children.journal)
        model_rows, authority = fixture.calls(), list(fixture.children.authority.events)
        root_wire, child_wire = fixture.wire_requests(), fixture.wire_requests(child)
        assert fresh_client(fixture).request(
            "public_turn", request_id="mpub1:proposal", **selection(),
        )["slot"] == first
        assert fixture.request(
            "public_pull", "mpub1:child-decision", who=child, slot_id=offered["slot_id"],
        )["slot"] == result
        assert database_snapshot(fixture.children.journal) == snapshot
        assert fixture.calls() == model_rows and fixture.children.authority.events == authority
        assert fixture.wire_requests() == root_wire and fixture.wire_requests(child) == child_wire
        assert len(requests) == 2


@pytest.mark.parametrize("conflict", ["changed_payload", "sibling_owner"])
def test_rejected_key_collision_cannot_fail_original_unfinished_owner(host_factory, conflict):
    with provider(lambda handler, _: public_completion(handler)) as (endpoint, requests):
        fixture = host_factory(endpoint)
        child = fixture.spawn()
        key = "mpub1:original-unfinished"
        payload = operation("public_turn", key, **selection())
        identity = fixture.public._identity(fixture.root, fixture.policy)
        fixture.public.store.accept(
            fixture.root, fixture.policy, identity, payload, fixture.root.monotonic_deadline,
        )
        slot = fixture.public.store.offer(
            fixture.root, fixture.policy, key, identity, fixture.root.monotonic_deadline,
        )
        before = database_snapshot(fixture.children.journal)
        calls, authority = fixture.calls(), list(fixture.children.authority.events)
        if conflict == "changed_payload":
            with pytest.raises(PublicError) as error:
                fresh_client(fixture).request(
                    "public_turn", request_id=key,
                    **selection(selected_message_ids=["0" * 64]),
                )
        else:
            with pytest.raises(public.ManagedPublicError) as error:
                fixture.request("public_pending", key, who=child)
        assert error.value.code == "conflict"
        assert database_snapshot(fixture.children.journal) == before
        assert fixture.calls() == calls and fixture.children.authority.events == authority
        assert requests == []
        assert fixture.view()["slots"][slot["slot_id"]]["state"] == "offered"
        result = fresh_client(fixture).request(
            "public_turn", request_id=key, **selection(),
        )["slot"]
        assert result["state"] == "published" and len(requests) == 1


@pytest.mark.parametrize("effect", ["public_turn", "public_invite"])
@pytest.mark.parametrize("later", ["permission_denied", "original_expiry"])
def test_unknown_publication_retry_keeps_uncertainty_on_wire_and_in_rows(
    host_factory, effect, later,
):
    with provider(lambda handler, _: public_completion(handler)) as (endpoint, requests):
        fixture = host_factory(endpoint, mode="lost_ack_once")
        fixture.request("public_read", "mpub1:open-profile", after=0, stream_id=None, watch_seconds=0)
        key = "mpub1:original-post"
        values = selection() if effect == "public_turn" else {"invitation_key": "peer"}
        payload = operation(effect, key, **values)
        cutoff = time.monotonic() + 2 if later == "original_expiry" else fixture.root.monotonic_deadline
        fixture.public.store.accept(
            fixture.root, fixture.policy, fixture.public._identity(fixture.root, fixture.policy),
            payload, cutoff,
        )
        with pytest.raises(PublicError) as first:
            fresh_client(fixture).request(effect, request_id=key, **values)
        assert first.value.code == "publication_uncertain"
        original = fixture.view()
        owner = original["requests"][key]
        assert owner["state"] == "uncertain" and owner["error"] == "publication_uncertain"
        # The real server committed and sent no acknowledgement. This proves the
        # later denial is about an actually unknown post, not preflight refusal.
        with closing(sqlite3.connect(fixture.path / "public-records.sqlite3")) as db:
            records = list(db.execute("SELECT record FROM records"))
        assert len(records) == 1
        original_record = json.loads(records[0][0])
        assert original_record["body"]["kind"] == ("message" if effect == "public_turn" else "invite")
        if later == "permission_denied":
            fixture.allowed = False
        else:
            wait_until(lambda: time.monotonic() >= owner["monotonic_cutoff"], seconds=3)
            assert owner["expires_at"] <= time.time()
        rows, wire = fixture.calls(), fixture.wire_requests()
        processes = deepcopy(original["processes"])
        retry_client = OriginalKeyClient(fixture, key)
        retry_tools = PublicTools(SimpleNamespace(), retry_client)
        snapshot = database_snapshot(fixture.children.journal)
        # An untrusted model cannot inject the transport's reserved request ID.
        assert json.loads(retry_tools.call(effect, values | {"request_id": key})) == {
            "ok": False, "error": "invalid_request",
        }
        assert retry_client.dispatches == []
        assert database_snapshot(fixture.children.journal) == snapshot
        with pytest.raises(PublicError) as repeated:
            retry_tools.call(effect, values)
        assert retry_client.dispatches == [(effect, values)]
        assert repeated.value.code == "publication_uncertain"
        assert repeated.value.request_id == key
        final = fixture.view()
        assert final["requests"][key]["state"] == "uncertain"
        assert final["requests"][key]["error"] == "publication_uncertain"
        assert final["requests"][key]["monotonic_cutoff"] == owner["monotonic_cutoff"]
        assert final["processes"] == processes
        assert fixture.calls() == rows and fixture.wire_requests() == wire
        assert len(requests) == (1 if effect == "public_turn" else 0)


def test_lost_acknowledgement_recovers_only_original_record_without_inference(host_factory):
    with provider(lambda handler, _: public_completion(handler)) as (endpoint, requests):
        fixture = host_factory(endpoint, mode="lost_ack_once")
        with pytest.raises(PublicError) as error:
            fixture.request("public_turn", "mpub1:recover-original", **selection())
        assert error.value.code == "publication_uncertain"
        before = fixture.view()
        slot = next(iter(before["slots"].values()))
        assert slot["response"] == {"kind": "message", "content": "Approved public reasoning."}
        assert slot["receipt"] is None and slot["state"] == "uncertain"
        with closing(sqlite3.connect(fixture.path / "public-records.sqlite3")) as db:
            original_record = json.loads(db.execute("SELECT record FROM records").fetchone()[0])
        calls = fixture.calls()
        result = fresh_client(fixture).request(
            "public_turn", request_id="mpub1:recover-original", **selection(),
        )["slot"]
        assert result["receipt"]["record"] == original_record
        assert fixture.calls() == calls and len(requests) == 1
        final = fixture.view()
        assert final["actors"]["root"]["generations"] == 2
        assert final["actors"]["root"]["status"] == before["actors"]["root"]["status"]
        assert final["slots"][slot["slot_id"]]["monotonic_cutoff"] == slot["monotonic_cutoff"]
        assert final["slots"][slot["slot_id"]]["publication_intent"] == slot["publication_intent"]
        with closing(sqlite3.connect(fixture.path / "public-records.sqlite3")) as db:
            assert db.execute("SELECT COUNT(*) FROM records").fetchone()[0] == 1


def test_actor_leave_finishes_while_other_actor_stays_owned_and_independent(host_factory):
    def answer(handler, requests):
        public_completion(
            handler, kind="leave" if len(requests) == 2 else "message",
            content="A deliberate public leave." if len(requests) == 2 else "Public reasoning.",
        )
    with provider(answer) as (endpoint, requests):
        fixture = host_factory(endpoint)
        first = fixture.request("public_turn", "mpub1:first", **selection())["slot"]
        child = fixture.spawn()
        offered = fixture.request(
            "public_activate", "mpub1:child-offer", child_id=child, **selection(),
        )["slot"]
        fixture.request("public_read", "mpub1:child-observe", who=child,
                        after=0, stream_id=None, watch_seconds=0)
        child_before = deepcopy(fixture.children.journal.child(fixture.root.worker_id, child))
        child_owner = fixture.public.profiles.entries[(fixture.root.worker_id, child)]
        assert not child_owner.done.is_set()
        left = fixture.request("public_turn", "mpub1:leave", **selection())["slot"]
        assert left["state"] == "left" and left["actor"]["admission_closed"] is True
        assert left["receipt"]["record"]["body"]["kind"] == "leave"
        # The old whole-worker quiescent check would wait for this live positive.
        assert not child_owner.done.is_set()
        assert fixture.public.profiles.quiescent(fixture.root.worker_id, who="root")
        assert not fixture.public.profiles.quiescent(fixture.root.worker_id)
        assert fixture.children.journal.child(fixture.root.worker_id, child) == child_before
        before = fixture.calls()
        with pytest.raises(PublicError) as closed:
            fixture.request("public_turn", "mpub1:forbidden-after-leave", **selection())
        assert closed.value.code == "actor_left"
        assert fixture.calls() == before
        assert fixture.request(
            "public_status", "mpub1:historical-status", slot_id=first["slot_id"],
        )["slot"]["actor"]["admission_closed"] is True
        result = fixture.request(
            "public_pull", "mpub1:still-independent", who=child, slot_id=offered["slot_id"],
        )["slot"]
        assert result["state"] == "published" and not result["actor"]["admission_closed"]
        assert result["actor"]["status"]["author"] != left["actor"]["status"]["author"]
        assert len(requests) == 3


@pytest.mark.parametrize("closure", ["retirement", "service_close"])
def test_accepted_original_retry_crossing_lease_closure_still_reports_uncertainty(
    host_factory, monkeypatch, closure,
):
    with provider(lambda handler, _: public_completion(handler)) as (endpoint, requests):
        fixture = host_factory(endpoint, mode="lost_ack_once")
        child = fixture.spawn()
        key = "mpub1:lease-boundary"
        with pytest.raises(PublicError) as first:
            fixture.request("public_turn", key, **selection())
        assert first.value.code == "publication_uncertain"
        entered, resume = threading.Event(), threading.Event()
        old = fixture.public._lease

        @contextmanager
        def paused(*args):
            entered.set()
            assert resume.wait(5)
            with old(*args) as lease:
                yield lease

        monkeypatch.setattr(fixture.public, "_lease", paused)
        outcome = []
        retry_client = OriginalKeyClient(fixture, key)
        def repeat():
            try:
                PublicTools(SimpleNamespace(), retry_client).call(
                    "public_turn", selection(),
                )
            except BaseException as error:
                outcome.append(error)

        caller = threading.Thread(target=repeat)
        caller.start()
        try:
            assert entered.wait(4)
            endpoint_owner = fixture.public.endpoints.endpoints[(fixture.root.worker_id, "root")]
            assert endpoint_owner.thread.is_alive() and endpoint_owner.server._active is not None
            if closure == "retirement":
                fixture.public.retire(fixture.root.worker_id)
            else:
                fixture.children.close()
                assert not fixture.children.journal.service_lock.closed
            snapshot = database_snapshot(fixture.children.journal)
            calls = fixture.calls()
            # The early classifier must not disclose the original uncertainty
            # to a changed payload or another registered actor with the same key.
            monkeypatch.setattr(fixture.public, "_lease", old)
            for child_id, changed in (
                (None, operation("public_turn", key, **selection(selected_message_ids=["0" * 64]))),
                (child, operation("public_pending", key)),
            ):
                with pytest.raises(public.ManagedPublicError) as refused:
                    fixture.public.handle(fixture.root.worker_id, changed, child_id=child_id)
                assert refused.value.code == "not_authorized"
                assert database_snapshot(fixture.children.journal) == snapshot
            resume.set()
            caller.join(5)
            assert not caller.is_alive()
            assert len(outcome) == 1 and isinstance(outcome[0], PublicError)
            assert outcome[0].code == "publication_uncertain"
            assert outcome[0].request_id == key
            assert retry_client.dispatches == [("public_turn", selection())]
            assert database_snapshot(fixture.children.journal) == snapshot
            assert fixture.calls() == calls and len(requests) == 1
        finally:
            resume.set()
            caller.join(6)


@pytest.mark.parametrize("alias", [
    "spawn", "status", "result", "close", "cancel", "outcome", "root_model", "child_model",
])
def test_public_namespace_cannot_be_adopted_by_any_existing_effect_path(host_factory, alias):
    with provider(lambda handler, _: public_completion(handler)) as (endpoint, requests):
        fixture = host_factory(endpoint)
        child = fixture.spawn()
        key = "mpub1:owned-public-request"
        identity = fixture.public._identity(fixture.root, fixture.policy)
        fixture.public.store.accept(
            fixture.root, fixture.policy, identity,
            operation("public_turn", key, **selection()), fixture.root.monotonic_deadline,
        )
        snapshot = database_snapshot(fixture.children.journal)
        calls, authority = fixture.calls(), list(fixture.children.authority.events)
        def invoke(request_id):
            if alias in {"root_model", "child_model"}:
                payload = {"schema_version": 1, "request_id": request_id,
                           "messages": [{"role": "user", "content": "Ordinary private coding."}]}
                if alias == "root_model":
                    return fixture.model.complete(fixture.root.worker_id, payload)
                return fixture.model.complete_child(fixture.root.worker_id, child, payload)
            if alias == "outcome":
                return fixture.children.report_outcome(fixture.root.worker_id, child, {
                    "schema_version": 1, "request_id": request_id,
                    "outcome": "needs_clarification", "summary": "PRIVATE_OUTCOME_CANARY",
                })
            arguments = {
                "spawn": request(),
                "status": {"child_id": child},
                "result": {"child_id": child, "kind": "log", "offset": 0, "limit": 32},
                "close": {"reason": "explicit private close"},
                "cancel": {"child_id": child, "reason": "explicit private cancellation"},
            }[alias]
            return fixture.children.handle(
                fixture.root.worker_id, operation(alias, request_id, **arguments),
            )
        with pytest.raises((ChildDenied, BrokerDenied)) as error:
            invoke(key)
        assert error.value.code == "invalid_request"
        assert database_snapshot(fixture.children.journal) == snapshot
        assert fixture.calls() == calls and fixture.children.authority.events == authority
        assert requests == []
        # The same supported private operation is still available in its original namespace.
        assert invoke("ordinary-positive-" + alias)["ok"] is True


def test_mixed_local_read_keys_hit_lifetime_cap_without_growth_and_original_pull_survives(host_factory):
    with provider(lambda handler, _: public_completion(handler)) as (endpoint, requests):
        fixture = host_factory(endpoint)
        child = fixture.spawn()
        slot = fixture.request(
            "public_activate", "mpub1:cap-offer", child_id=child, **selection(),
        )["slot"]
        decision = operation("public_pull", "mpub1:cap-decision", slot_id=slot["slot_id"])
        fixture.public.store.accept(
            fixture.root, fixture.policy, fixture.public._identity(fixture.root, fixture.policy, child),
            decision, fixture.root.monotonic_deadline,
        )
        fixture.public.store.claim(fixture.root, fixture.policy, decision["request_id"], slot["slot_id"])
        for number in range(126):
            key = "mpub1:read-" + str(number)
            if number % 2:
                fixture.request("public_pending", key, who=child)
            else:
                fixture.request("public_status", key, slot_id=slot["slot_id"])
        before = fixture.view()
        assert before["header"]["requests"] == 128
        assert before["header"]["processes"] == 0 and fixture.calls() == [] and requests == []
        snapshot, authority = database_snapshot(fixture.children.journal), list(fixture.authority.events)
        with pytest.raises(PublicError) as root_error:
            fixture.request("public_turn", "mpub1:over-cap-root", **selection())
        with pytest.raises(public.ManagedPublicError) as child_error:
            fixture.request("public_pending", "mpub1:over-cap-child", who=child)
        assert root_error.value.code == child_error.value.code == "request_limit"
        assert database_snapshot(fixture.children.journal) == snapshot
        assert fixture.authority.events == authority and requests == []
        result = fixture.request(
            "public_pull", decision["request_id"], who=child, slot_id=slot["slot_id"],
        )["slot"]
        assert result["state"] == "published"
        page = fixture.request("public_pending", "mpub1:read-1", who=child)
        assert [item["state"] for item in page["slots"]] == ["published"]
        assert fixture.view()["header"]["requests"] == 128
        assert len(requests) == 1 and len(fixture.calls()) == 1


def freeze_capture(fixture, original):
    result = []
    def ready():
        try:
            result.append(fixture.public.effective_receipt(
                fixture.root.worker_id, original, prepare=True,
            ))
        except RuntimeUnavailable:
            return False
        return True
    wait_until(ready)
    return result[-1]


def test_retirement_keeps_active_socket_and_service_leases_until_real_provider_completion(host_factory):
    entered, release = threading.Event(), threading.Event()
    def answer(handler, requests):
        entered.set()
        assert release.wait(5)
        public_completion(handler, content="Completed before final permission refusal.")

    with provider(answer) as (endpoint, requests):
        fixture = host_factory(endpoint)
        child = fixture.spawn()
        original = fixture.capture()  # Explicit named whole-worker facts, not a Docker proof.
        outcome = []
        def invoke():
            try:
                fixture.request("public_turn", "mpub1:inflight", **selection())
            except BaseException as error:
                outcome.append(error)

        caller = threading.Thread(target=invoke)
        queued = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        descriptor = None
        caller.start()
        try:
            assert entered.wait(4)
            assert len(fixture.calls()) == 1 and fixture.calls()[0]["status"] == "reserved"
            slot = next(iter(fixture.view()["slots"].values()))
            assert slot["state"] == "model_pending" and slot["response"] is None
            owner = fixture.public.endpoints.endpoints[(fixture.root.worker_id, "root")]
            assert owner.server._active is not None

            # A different real Unix peer UID receives the complete denial frame
            # before sending a body, while the root's real HTTP request is held.
            child_row = fixture.children.journal.child(fixture.root.worker_id, child)
            assert child_row["uid"] != os.getuid()
            descriptor = os.open(
                fixture.model.root / fixture.root.worker_id / "children" / child,
                os.O_RDONLY | os.O_DIRECTORY,
            )
            snapshot = database_snapshot(fixture.children.journal)
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as foreign:
                foreign.settimeout(1)
                foreign.connect(f"/proc/self/fd/{descriptor}/public.sock")
                deadline = time.monotonic() + 1
                length = struct.unpack("!I", ModelBroker._read(foreign, 4, deadline))[0]
                assert 1 <= length <= 1024
                denied = json.loads(ModelBroker._read(foreign, length, deadline))
            assert denied == {
                "schema_version": 1, "request_id": "invalid",
                "ok": False, "error": "not_authorized",
            }
            assert database_snapshot(fixture.children.journal) == snapshot

            queued.settimeout(1)
            queued.connect(fixture.socket_path)
            raw = public.canonical(operation(
                "public_status", "mpub1:queued-unowned", slot_id=slot["slot_id"],
            ))
            queued.sendall(struct.pack("!I", len(raw)) + raw)
            def actually_queued():
                with owner.server._condition:
                    return len(owner.server._pending) == 1
            wait_until(actually_queued, seconds=1)
            fixture.children.mark_retiring(fixture.root.worker_id)
            assert fixture.view()["header"]["closed"] is True
            assert "mpub1:queued-unowned" not in fixture.view()["requests"]
            with owner.server._condition:
                assert not owner.server._pending
            try:
                assert queued.recv(1) == b""
            except ConnectionResetError:
                pass  # The retained accepted queue was explicitly discarded.
            assert owner.thread.is_alive() and owner.server._active is not None
            with pytest.raises(RuntimeUnavailable, match="owners are still active"):
                fixture.public.effective_receipt(fixture.root.worker_id, original, prepare=True)
            assert fixture.view()["header"]["frozen"] is None
            assert fixture.lifecycle.active == [fixture.root.attempt_id, child]

            fixture.children.close()
            fixture.model.close()
            assert not fixture.children.journal.service_lock.closed
            assert not fixture.model._service_lock.closed
            with pytest.raises(ValueError, match="another child supervisor"):
                ChildJournal(fixture.path / "children")
            with pytest.raises(ValueError, match="another model broker"):
                ModelBroker(
                    fixture.path / "models", {fixture.scope: fixture.model_policy},
                    lambda _: 1, peer_uids={fixture.scope: os.getuid()},
                )
            release.set()
            caller.join(6)
            assert not caller.is_alive()
            assert len(outcome) == 1 and isinstance(outcome[0], PublicError)
            assert outcome[0].code == "not_authorized"
            assert fixture.calls()[0]["status"] == "complete"
            retained = fixture.view()["slots"][slot["slot_id"]]
            assert retained["response"] == {
                "kind": "message", "content": "Completed before final permission refusal.",
            }
            assert retained["receipt"] is None
            status = fixture.view()["actors"]["root"]["status"]
            assert retained["publication_intent"] == {
                "topic": status["topic"], "session_id": status["session_id"],
                "swarm_id": status["swarm_id"], "visibility": "public",
                "request_key": "oj-public:" + slot["slot_id"],
                "kind": "message", "content": "Completed before final permission refusal.",
                "reply_to": None, "target": None, "references": [],
            }
            assert retained["state"] == "refused" and retained["reason"] == "not_authorized"
            assert len(requests) == 1
            assert not any(
                item.get("params", {}).get("name") == "conversation_say"
                for item in fixture.wire_requests()
            )
            fixture.close()
            before = fixture.view()
            assert all(row["state"] == "stopped" for row in before["processes"].values())
            fixture._start_services()
            assert not Path(fixture.socket_path).exists()
            effective = freeze_capture(fixture, original)
            assert json.loads(effective.manifest)["managed_public_v1"]["slots"][0]["state"] == "refused"
            assert fixture.view()["processes"] == before["processes"]
            # A real private child need not accept any public participation.
            # Its ordinary archive capture still receives the explicit empty
            # private projection, without registering another public actor.
            untouched_child = fixture.children.journal.child(fixture.root.worker_id, child)
            child_capture = fixture.children.driver.final_capture(fixture.root, untouched_child, effective)
            child_manifest = json.loads(child_capture["manifest"])
            assert child_manifest["managed_public_v1"] == {
                "schema_version": 1, "protocol": public.PROTOCOL,
                "snapshot_sha256": fixture.view()["header"]["freeze_digest"],
                "actor": None, "slots": [],
            }
            assert child_manifest["root_manifest_sha256"] == hashlib.sha256(effective.manifest.encode()).hexdigest()
            assert child_capture["log"] == "child private log"
            assert child not in fixture.view()["actors"]
            assert len(requests) == 1 and len(fixture.calls()) == 1
        finally:
            release.set()
            caller.join(6)
            queued.close()
            if descriptor is not None:
                os.close(descriptor)


def test_frozen_root_public_and_child_private_capture_rederive_exactly_after_service_reopen(host_factory):
    with provider(lambda handler, _: public_completion(handler)) as (endpoint, requests):
        fixture = host_factory(endpoint)
        proposal = fixture.request("public_turn", "mpub1:capture-proposal", **selection())["slot"]
        child = fixture.spawn()
        offered = fixture.request(
            "public_activate", "mpub1:capture-offer", child_id=child,
            **selection(selected_message_ids=[proposal["receipt"]["message_id"]]),
        )["slot"]
        contribution = fixture.request(
            "public_pull", "mpub1:capture-pull", who=child, slot_id=offered["slot_id"],
        )["slot"]
        fixture.children.report_outcome(fixture.root.worker_id, child, {
            "schema_version": 1, "request_id": "ordinary-completed-report",
            "outcome": "completed", "summary": "PRIVATE_COMPLETION_SUMMARY_CANARY",
        })
        fixture.children.journal.update(
            fixture.root.worker_id, child, phase="exec_returned", exit_code=0,
        )
        original = fixture.capture()
        original_bytes = original.manifest.encode()
        original_hash = hashlib.sha256(original_bytes).hexdigest()
        calls, process_rows = fixture.calls(), deepcopy(fixture.view()["processes"])
        effective = freeze_capture(fixture, original)
        assert original.manifest.encode() == original_bytes
        assert effective.patch == original.patch and effective.log == original.log
        assert effective.capture_path == original.capture_path
        assert effective.capture_sha256 == original.capture_sha256
        root_manifest = json.loads(effective.manifest)
        extension = root_manifest.pop("managed_public_v1")
        assert root_manifest.pop("managed_public_original_manifest_sha256") == original_hash
        assert public.canonical(root_manifest) == original_bytes
        assert [record["message_id"] for record in extension["records"]] == [
            proposal["receipt"]["message_id"], contribution["receipt"]["message_id"],
        ]
        assert [actor["role"] for actor in extension["actors"]] == ["root", "child-1"]
        encoded_extension = public.canonical(extension).decode()
        child_row = fixture.children.journal.child(fixture.root.worker_id, child)
        grant = json.loads(child_row["grant_json"])["binding"]
        for private in (
            child, child_row["exec_id"], grant["grant_digest"], grant["instructions_digest"],
            "PRIVATE_CHILD_INSTRUCTION_CANARY", "PRIVATE_COMPLETION_SUMMARY_CANARY",
            fixture.root_input, "private-scope-canary", TEST_TOKEN,
        ):
            assert private not in encoded_extension
        assert not {"uid", "exec_id", "grant_digest", "identity"} & set(extension["actors"][1])
        assert all(row["state"] == "stopped" for row in fixture.view()["processes"].values())
        assert len(fixture.view()["processes"]) == len(process_rows) == 4

        contents = fixture.children.driver.final_capture(fixture.root, child_row, effective)
        manifest = json.loads(contents["manifest"])
        private = manifest["managed_public_v1"]
        assert private["actor"]["identity"]["child_id"] == child
        assert private["actor"]["identity"]["uid"] == child_row["uid"]
        assert private["actor"]["identity"]["exec_id"] == child_row["exec_id"]
        assert private["actor"]["identity"]["grant_digest"] == grant["grant_digest"]
        assert [slot["slot_id"] for slot in private["slots"]] == [contribution["slot_id"]]
        assert manifest["root_manifest_sha256"] == hashlib.sha256(effective.manifest.encode()).hexdigest()
        assert manifest["root_manifest_sha256"] != original_hash
        assert manifest["work_outcome"]["report"]["summary"] == "PRIVATE_COMPLETION_SUMMARY_CANARY"
        assert contents["patch"] == "" and contents["log"] == "child private log"

        fixture.children.finalize(fixture.root.worker_id, effective)
        final_child = fixture.children.journal.child(fixture.root.worker_id, child)
        assert final_child["phase"] == "completed"
        assert fixture.lifecycle.active == [fixture.root.attempt_id]
        assert fixture.authority.artifacts[(child, "manifest")] == contents["manifest"]
        snapshot = database_snapshot(fixture.children.journal)
        assert fixture.public.effective_receipt(
            fixture.root.worker_id, original, prepare=False,
        ).manifest == effective.manifest
        assert database_snapshot(fixture.children.journal) == snapshot
        assert fixture.calls() == calls and len(requests) == 2

        fixture.reopen()
        assert not Path(fixture.socket_path).exists()
        assert fixture.public.profiles.entries == {}
        assert fixture.public.effective_receipt(
            fixture.root.worker_id, original, prepare=False,
        ).manifest == effective.manifest
        assert database_snapshot(fixture.children.journal) == snapshot
        assert fixture.calls() == calls and len(requests) == 2
