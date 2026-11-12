"""Owned profile tests with real files, SQLite and the pinned MCP SDK.

The local stdio fixture signs real records but is explicitly not installed A,
a network peer, a canonical grant service or a model provider. Named child exec
and model-intent inputs are labelled where used. Owned subprocess facts come
from the actual bounded transport and Linux kernel.
"""

import asyncio
from contextlib import closing
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sys
import threading
import time
from types import SimpleNamespace

import pytest

from src.worker.child_journal import ChildJournal
from src.worker.discussion_types import CHILD_ENVIRONMENT, Deadline, boot_id
from src.worker.lifecycle import LifecycleConflict
from src.worker.managed_public_journal import PublicStore
from src.worker.managed_public_profiles import ProfileFiles, OwnedProfiles
from src.worker import managed_public_types as public
from tests.unit.test_child_authority_contract import context
from tests.unit.test_child_session_store import database_snapshot
from tests.unit.test_conversation_client import FIXTURE_SERVER
from tests.unit.test_managed_public_journal import (
    PublicFixture, StoragePolicy, operation, selection, rewrite,
)
from tests.unit.test_managed_public_types import public_document


def wait_until(predicate, seconds=6):
    cutoff = time.monotonic() + seconds
    while not predicate() and time.monotonic() < cutoff:
        time.sleep(0.01)
    assert predicate()


def process_intent(fixture, slot, stage="probe"):
    actor = fixture.view()["actors"][slot["actor_id"]]
    request = fixture.view()["requests"][slot["decision_request_id"]]
    return {
        "schema_version": 1, "stage": stage, "launch_path": sys.executable,
        "cwd": fixture.document["server"]["cwd"],
        "config_sha256": actor["config"]["sha256"],
        "argv_sha256": public.digest(["named-owned-process-fixture", stage]),
        "environment_sha256": public.digest(CHILD_ENVIRONMENT),
        "monotonic_cutoff": min(slot["monotonic_cutoff"], request["monotonic_cutoff"]),
        "boot_id": fixture.root.boot_id,
    }


def retained_leave(fixture, *, child=False):
    who = fixture.child() if child else "root"
    slot = fixture.offer(who=who)
    if child:
        fixture.store.accept(
            fixture.root, fixture.policy, fixture.identity(who),
            operation("public_pull", "mpub1:shorter-original-pull", slot_id=slot["slot_id"]),
            fixture.clock.now + 10,
        )
        fixture.store.claim(
            fixture.root, fixture.policy, "mpub1:shorter-original-pull", slot["slot_id"],
        )
    fixture.bind(who)
    # Explicit named previous ownership; these rows do not claim real PIDs.
    fixture.stopped(fixture.process(who, "probe"))
    fixture.stopped(fixture.process(who, "server"), pid=12346)
    fixture.store.freeze_context(fixture.root, fixture.policy, slot["slot_id"], [])
    fixture.store.model_intent(fixture.root, fixture.policy, slot["slot_id"])
    fixture.store.retain_response(
        fixture.root, fixture.policy, slot["slot_id"],
        {"kind": "leave", "content": "I leave this public discussion."},
    )
    fixture.store.publication_intent(fixture.root, fixture.policy, slot["slot_id"])
    return fixture.view()["slots"][slot["slot_id"]]


@pytest.fixture
def stored(tmp_path, monkeypatch):
    fixture = PublicFixture(tmp_path, monkeypatch)
    try:
        yield fixture
    finally:
        fixture.close()


@pytest.mark.parametrize("fault", [
    "omitted_exception", "wrong_slot", "decision_expired", "slot_expired",
    "wrong_boot", "closed_header", "frozen_header", "expired_slot", "refused_slot",
    "acknowledged", "unknown_owner", "running_owner", "late_process_cutoff",
])
def test_leave_recovery_refuses_every_nonoriginal_or_unavailable_owner(stored, fault):
    fixture = stored
    slot = retained_leave(fixture, child=True)
    who, slot_id = slot["actor_id"], slot["slot_id"]
    intent = process_intent(fixture, slot)
    supplied_slot = slot_id
    root = fixture.root
    if fault == "omitted_exception":
        supplied_slot = None
    elif fault == "wrong_slot":
        supplied_slot = "0" * 64
    elif fault == "decision_expired":
        fixture.clock.now += 11
        fixture.clock.wall += 11
        assert public_remaining(fixture, slot) > 0
    elif fault == "slot_expired":
        fixture.clock.now += 46
        fixture.clock.wall += 46
    elif fault == "wrong_boot":
        root = replace(root, boot_id="different-boot")
    elif fault == "closed_header":
        fixture.store.close(root, fixture.policy)
    elif fault == "frozen_header":
        fixture.store.close(root, fixture.policy)
        fixture.store.freeze(root, fixture.policy, owners_quiescent=True)
    elif fault in {"expired_slot", "refused_slot"}:
        fixture.store.failure(
            root, fixture.policy, slot["decision_request_id"],
            "expired" if fault == "expired_slot" else "not_authorized", slot_id=slot_id,
        )
    elif fault == "acknowledged":
        fixture.store.receipt(root, fixture.policy, slot_id, fixture.sign(who, slot["publication_intent"]))
    elif fault in {"unknown_owner", "running_owner"}:
        row = next(row for row in fixture.view()["processes"].values() if row["stage"] == "server")
        def change(value):
            value["state"] = "unknown" if fault == "unknown_owner" else "running"
            value["cleanup"] = None
        rewrite(fixture.journal, "public_processes", "process_id", row["process_id"], change)
    elif fault == "late_process_cutoff":
        intent["monotonic_cutoff"] = slot["monotonic_cutoff"]
        assert intent["monotonic_cutoff"] > fixture.view()["requests"][slot["decision_request_id"]]["monotonic_cutoff"]
    before = database_snapshot(fixture.journal)
    with pytest.raises((public.ManagedPublicError, LifecycleConflict)):
        fixture.store.process_intent(
            root, fixture.policy, who, "probe", intent, recovery_slot=supplied_slot,
        )
    assert database_snapshot(fixture.journal) == before
    assert fixture.view()["actors"][who]["closed"] is True


def public_remaining(fixture, slot):
    from src.worker.managed_public_journal import remaining
    return remaining(slot, fixture.root.boot_id)


def test_leave_recovery_retains_exact_exception_and_original_receipt(stored):
    fixture = stored
    slot = retained_leave(fixture, child=True)
    who, slot_id = slot["actor_id"], slot["slot_id"]
    original = deepcopy(slot)
    created = []
    for stage in ("probe", "server"):
        row = fixture.store.process_intent(
            fixture.root, fixture.policy, who, stage, process_intent(fixture, slot, stage),
            recovery_slot=slot_id,
        )
        fixture.stopped(row, pid=12347 if stage == "probe" else 12348)
        created.append(row)
    expected = {
        "schema_version": 1, "slot_id": slot_id,
        "decision_request_id": slot["decision_request_id"],
        "request_payload_digest": fixture.view()["requests"][slot["decision_request_id"]]["payload_digest"],
        "publication_intent_digest": public.digest(slot["publication_intent"]),
        "actor_binding_digest": fixture.view()["actors"][who]["binding_digest"],
    }
    assert all(row["generation"] == 2 and row["intent"]["leave_recovery"] == expected for row in created)
    assert fixture.view()["slots"][slot_id] == original
    actual = fixture.sign(who, slot["publication_intent"])
    fixture.store.receipt(fixture.root, fixture.policy, slot_id, actual)
    before = database_snapshot(fixture.journal)
    assert fixture.store.receipt(fixture.root, fixture.policy, slot_id, actual)["receipt"] == actual
    assert database_snapshot(fixture.journal) == before
    fixture.reopen()
    assert fixture.view()["actors"][who]["closed"] is True
    assert fixture.view()["slots"][slot_id]["receipt"] == actual
    assert fixture.view()["actors"][who]["generations"] == 2


@pytest.mark.parametrize("fault", ["schema_boolean", "decision_key", "intent_hash", "probe_server_mismatch"])
def test_coherently_rehashed_leave_recovery_binding_is_rejected(stored, fault):
    fixture = stored
    slot = retained_leave(fixture)
    rows = []
    for stage in ("probe", "server"):
        row = fixture.store.process_intent(
            fixture.root, fixture.policy, "root", stage, process_intent(fixture, slot, stage),
            recovery_slot=slot["slot_id"],
        )
        fixture.stopped(row, pid=12347 if stage == "probe" else 12348)
        rows.append(row)
    before = database_snapshot(fixture.journal)
    fixture.reopen()
    assert database_snapshot(fixture.journal) == before
    for row in (rows if fault != "probe_server_mismatch" else rows[:1]):
        def change(value):
            if fault == "probe_server_mismatch":
                # Both individual intent forms remain valid. Only the
                # generation's probe/server agreement can reject this pair.
                del value["intent"]["leave_recovery"]
            else:
                binding = value["intent"]["leave_recovery"]
                if fault == "schema_boolean":
                    binding["schema_version"] = True
                elif fault == "decision_key":
                    binding["decision_request_id"] = "mpub1:another"
                else:
                    binding["publication_intent_digest"] = "0" * 64
            value["intent_digest"] = public.digest(value["intent"])
        rewrite(fixture.journal, "public_processes", "process_id", row["process_id"], change)
    with pytest.raises(LifecycleConflict, match="retained state"):
        fixture.store.view(fixture.root, fixture.policy)


def test_profile_files_are_exact_private_and_idempotent_after_durable_ready(stored):
    fixture = stored
    fixture.offer()
    files = ProfileFiles(fixture.store)
    launch = files.prepare(fixture.root, fixture.policy, "root")
    actor = fixture.view()["actors"]["root"]
    path = Path(actor["config"]["path"])
    assert launch.config == str(path)
    assert path.read_bytes() == public.canonical(actor["config"]["document"])
    assert actor["config"]["state"] == "ready"
    assert path.stat().st_mode & 0o777 == 0o600
    assert path.parent.stat().st_mode & 0o777 == 0o700
    assert (path.parent / "state").stat().st_mode & 0o777 == 0o700
    assert list((path.parent / "state").iterdir()) == []
    assert fixture.view()["processes"] == {}
    original = database_snapshot(fixture.journal)
    assert files.prepare(fixture.root, fixture.policy, "root").config_sha256 == launch.config_sha256
    assert database_snapshot(fixture.journal) == original


def test_profile_directory_sync_failure_leaves_preparing_and_never_repairs(stored, monkeypatch):
    fixture = stored
    fixture.offer()
    real = os.fsync
    seen = []
    def fail_directory(fd):
        name = os.readlink("/proc/self/fd/" + str(fd))
        if name.endswith("/public"):
            seen.append(name)
            raise OSError("named directory persistence failure")
        return real(fd)
    with monkeypatch.context() as patch:
        patch.setattr(os, "fsync", fail_directory)
        with pytest.raises(public.ManagedPublicError, match="state_conflict"):
            ProfileFiles(fixture.store).prepare(fixture.root, fixture.policy, "root")
    assert seen
    assert fixture.view()["actors"]["root"]["config"]["state"] == "preparing"
    assert fixture.view()["processes"] == {}
    fixture.reopen()
    before = database_snapshot(fixture.journal)
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        ProfileFiles(fixture.store).prepare(fixture.root, fixture.policy, "root")
    assert database_snapshot(fixture.journal) == before


def install_owned_fixture(document, mode):
    """Adapt only state/log placement in the existing named MCP fixture."""
    checkout = Path(document["server"]["cwd"])
    package = checkout / "src" / "liminal_bridge"
    package.mkdir(parents=True)
    (checkout / "src" / "__init__.py").write_text("")
    (package / "__init__.py").write_text("")
    source = FIXTURE_SERVER
    source = source.replace(
        "state.mkdir(mode=0o700,exist_ok=True)",
        "state.mkdir(mode=0o700,exist_ok=True)\n"
        "audit=root/'observations'/state.parent.name\n"
        "audit.mkdir(mode=0o700,parents=True,exist_ok=True)",
    )
    for name in ("environment.json", "leader.json", "descendant.json", "provider-entered.flag", "requests.jsonl"):
        source = source.replace("state/'" + name + "'", "audit/'" + name + "'")
    source = source.replace("fixture-posts.sqlite3", "conversation.sqlite3")
    marker = "S={'type':'string'}"
    assert source.count(marker) == 1
    source = source.replace(marker, """
import fcntl
from cryptography.hazmat.primitives.serialization import PrivateFormat,NoEncryption
owner=(state/'owner.lock').open('ab')
os.chmod(state/'owner.lock',0o600)
fcntl.flock(owner,fcntl.LOCK_EX|fcntl.LOCK_NB)
identity=state/'identity.pem'
if not identity.exists():
    identity.write_bytes(key.private_bytes(Encoding.PEM,PrivateFormat.PKCS8,NoEncryption()))
    identity.chmod(0o600)
binding=state/'binding.json'
if binding.exists():
    assert json.loads(binding.read_bytes())==status
else:
    binding.write_bytes(enc(status))
    binding.chmod(0o600)
""" + marker)
    marker = "            after=arguments['after']"
    assert source.count(marker) == 1
    source = source.replace(marker, """
            if mode=='held_history':
                private(audit/'history-entered.json',{'entered':True})
                time.sleep(60)
""" + marker)
    (package / "conversation_server.py").write_text(source, encoding="utf-8")
    scenario = checkout / "fixture.json"
    scenario.write_text(json.dumps({"mode": mode, "records": []}))
    scenario.chmod(0o600)


class LiveProfileFixture(PublicFixture):
    """Actual clock and process owner; no monkeypatched global time functions."""

    def __init__(self, path, mode="normal"):
        self.document = public_document(path)
        install_owned_fixture(self.document, mode)
        self.policy = StoragePolicy(self.document)
        self.root = replace(
            context(), deadline=time.time() + 60,
            monotonic_deadline=time.monotonic() + 60, boot_id=boot_id(),
        )
        self.clock = SimpleNamespace(now=time.monotonic(), wall=time.time())
        self.path = path / "journal"
        self.journal = ChildJournal(self.path)
        self.journal.prepare(self.root.worker_id, self.root.spec, self.policy)
        self.root = self.journal.bind(self.root)
        self.store = PublicStore(self.journal)
        self.keys = {}
        self.pool = OwnedProfiles(self.store)

    def offer(self, key="mpub1:live", **values):
        payload = operation("public_turn", key, **selection(**values))
        self.store.accept(
            self.root, self.policy, self.identity(), payload, self.root.monotonic_deadline,
        )
        return self.store.offer(
            self.root, self.policy, key, self.identity(), self.root.monotonic_deadline,
        )

    def deadline(self, seconds=45):
        return Deadline(
            min(time.time() + seconds, self.root.deadline),
            min(time.monotonic() + seconds, self.root.monotonic_deadline),
        )

    def call(self, action, arguments=None, *, deadline=None, recovery_slot=None):
        return self.pool.call(
            self.root, self.policy, "root", deadline or self.deadline(),
            action, arguments, recovery_slot=recovery_slot,
        )

    def audit(self):
        actor = self.view()["actors"]["root"]
        return Path(self.document["server"]["cwd"]) / "observations" / actor["identity_digest"]

    def requests(self):
        path = self.audit() / "requests.jsonl"
        return [] if not path.exists() else [json.loads(line) for line in path.read_bytes().splitlines()]

    def close(self):
        self.pool.close()
        self.pool.thread.join(timeout=6)
        try:
            assert not self.pool.thread.is_alive()
        finally:
            self.journal.close()


@pytest.fixture
def live_factory(tmp_path):
    fixtures = []
    def create(mode="normal"):
        path = tmp_path / str(len(fixtures))
        path.mkdir(mode=0o700)
        fixture = LiveProfileFixture(path, mode)
        fixtures.append(fixture)
        return fixture
    try:
        yield create
    finally:
        for fixture in reversed(fixtures):
            fixture.close()


def test_real_sdk_profile_reuse_and_cleanup_keep_original_identity_and_cutoff(live_factory):
    fixture = live_factory()
    fixture.offer()
    deadline = fixture.deadline()
    actor = fixture.call("ready", deadline=deadline)
    initial = fixture.view()
    assert actor["status"] is not None and actor["binding_digest"] is not None
    assert actor["generations"] == 1
    rows = list(initial["processes"].values())
    assert len(rows) == 2
    assert {row["stage"]: row["state"] for row in rows} == {"probe": "stopped", "server": "running"}
    server = next(row for row in rows if row["stage"] == "server")
    assert server["intent"]["monotonic_cutoff"] == deadline.monotonic_cutoff
    assert json.loads((fixture.audit() / "environment.json").read_bytes()) == CHILD_ENVIRONMENT
    page = fixture.call(
        "history", {"after": 0, "stream_id": None, "watch": 0},
        deadline=fixture.deadline(10),
    )
    assert page["messages"] == []
    assert fixture.view()["processes"] == initial["processes"]
    assert fixture.view()["actors"]["root"]["binding"] == actor["binding"]
    assert fixture.view()["actors"]["root"]["generations"] == 1
    fixture.pool.stop_worker(fixture.root.worker_id)
    wait_until(lambda: fixture.pool.quiescent(fixture.root.worker_id))
    final = fixture.view()
    assert all(row["state"] == "stopped" for row in final["processes"].values())
    assert all(row["cleanup"]["leader_reaped"] is True for row in final["processes"].values())
    with pytest.raises(ChildProcessError):
        os.waitpid(server["identity"]["pid"], os.WNOHANG)
    # Private cleanup acknowledgement does not itself close publication or freeze.
    assert final["header"]["closed"] is False and final["header"]["frozen"] is None


@pytest.mark.parametrize("fault", ["attempt", "boot", "profile", "policy", "deadline_extension"])
def test_live_owner_refuses_changed_binding_before_command_or_new_generation(live_factory, fault):
    fixture = live_factory()
    fixture.offer()
    original = fixture.call("ready")
    root, policy = fixture.root, fixture.policy
    if fault == "attempt":
        root = replace(root, attempt_id="other-attempt")
    elif fault == "boot":
        root = replace(root, boot_id="another-boot")
    elif fault == "profile":
        root = replace(root, profile_digest="0" * 64)
    elif fault == "policy":
        document = deepcopy(fixture.document)
        document["instructions"]["proposal"] = "A changed approval is not the original actor."
        policy = StoragePolicy(document)
    else:
        shortened = replace(root, monotonic_deadline=root.monotonic_deadline - 5)
        assert fixture.pool.call(
            shortened, policy, "root", fixture.deadline(), "ready",
        )["binding_digest"] == original["binding_digest"]
        # The old larger sample cannot undo the already observed shortening.
    before, requests = database_snapshot(fixture.journal), fixture.requests()
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        fixture.pool.call(
            root, policy, "root", fixture.deadline(), "history",
            {"after": 0, "stream_id": None, "watch": 0},
        )
    assert database_snapshot(fixture.journal) == before
    assert fixture.requests() == requests
    assert fixture.view()["actors"]["root"]["generations"] == 1


def test_later_rpc_cannot_extend_original_owned_connection_deadline(live_factory):
    fixture = live_factory("held_history")
    fixture.offer()
    original = fixture.deadline(3)
    fixture.call("ready", deadline=original)
    before = fixture.view()
    started = time.monotonic()
    with pytest.raises(public.ManagedPublicError) as error:
        fixture.call(
            "history", {"after": 0, "stream_id": None, "watch": 0},
            deadline=fixture.deadline(30),
        )
    assert error.value.code in {"expired", "transport_unavailable"}
    assert (fixture.audit() / "history-entered.json").exists()
    wait_until(lambda: fixture.pool.quiescent(fixture.root.worker_id))
    assert time.monotonic() - started < 8
    after = fixture.view()
    assert after["actors"]["root"]["generations"] == 1
    assert set(after["processes"]) == set(before["processes"])
    assert all(row["state"] == "stopped" for row in after["processes"].values())
    assert next(row for row in after["processes"].values() if row["stage"] == "server")[
        "intent"
    ]["monotonic_cutoff"] == original.monotonic_cutoff


def test_real_lost_leave_ack_recovery_uses_exact_original_record_and_never_reopens_actor(live_factory):
    fixture = live_factory("lost_ack_once")
    slot = fixture.offer()
    slot_id = slot["slot_id"]
    deadline = Deadline(slot["expires_at"], slot["monotonic_cutoff"])
    actor = fixture.call("ready", deadline=deadline)
    # Explicit named model completion: the transport test allocates no provider
    # call. Common ModelBroker dispatch is qualified in its separate real-HTTP tests.
    fixture.store.freeze_context(fixture.root, fixture.policy, slot_id, [])
    fixture.store.model_intent(fixture.root, fixture.policy, slot_id)
    fixture.store.retain_response(
        fixture.root, fixture.policy, slot_id,
        {"kind": "leave", "content": "I leave this public discussion."},
    )
    intent = fixture.store.publication_intent(fixture.root, fixture.policy, slot_id)
    with pytest.raises(public.ManagedPublicError, match="transport_unavailable"):
        fixture.call("say", {"intent": intent}, deadline=deadline)
    fixture.store.failure(
        fixture.root, fixture.policy, slot["decision_request_id"], "publication_uncertain",
        slot_id=slot_id, uncertain=True,
    )
    wait_until(lambda: fixture.pool.quiescent(fixture.root.worker_id))
    first = fixture.view()
    assert first["actors"]["root"]["closed"] is True
    assert first["actors"]["root"]["generations"] == 1
    assert all(row["state"] == "stopped" for row in first["processes"].values())
    import sqlite3
    with closing(sqlite3.connect(first["actors"]["root"]["config"]["state_directory"] + "/conversation.sqlite3")) as db:
        retained = db.execute("SELECT intent,record FROM posts").fetchall()
    assert len(retained) == 1 and json.loads(retained[0][0]) == intent
    original_record = json.loads(retained[0][1])
    before, requests = database_snapshot(fixture.journal), fixture.requests()
    with pytest.raises(public.ManagedPublicError, match="actor_left"):
        fixture.call(
            "history", {"after": 0, "stream_id": None, "watch": 0},
            deadline=deadline, recovery_slot=slot_id,
        )
    assert database_snapshot(fixture.journal) == before
    assert fixture.requests() == requests
    receipt = fixture.call("say", {"intent": intent}, deadline=deadline, recovery_slot=slot_id)
    assert receipt["record"] == original_record
    fixture.store.receipt(fixture.root, fixture.policy, slot_id, receipt)
    fixture.pool.stop_actor(fixture.root.worker_id, "root")
    wait_until(lambda: fixture.pool.quiescent(fixture.root.worker_id))
    final = fixture.view()
    assert final["actors"]["root"]["binding"] == actor["binding"]
    assert final["actors"]["root"]["closed"] is True
    assert final["actors"]["root"]["generations"] == 2
    assert final["slots"][slot_id]["state"] == "left"
    assert final["slots"][slot_id]["receipt"] == receipt
    assert len(final["processes"]) == 4
    assert all(row["state"] == "stopped" for row in final["processes"].values())
    before = database_snapshot(fixture.journal)
    assert fixture.store.receipt(fixture.root, fixture.policy, slot_id, receipt)["receipt"] == receipt
    assert database_snapshot(fixture.journal) == before
    with closing(sqlite3.connect(final["actors"]["root"]["config"]["state_directory"] + "/conversation.sqlite3")) as db:
        assert db.execute("SELECT intent,record FROM posts").fetchall() == retained


@pytest.mark.parametrize("fault", ["missing_identity", "missing_binding", "config_symlink", "state_symlink", "scope_replaced"])
def test_owned_recovery_refuses_missing_or_changed_profile_without_new_process(live_factory, fault):
    fixture = live_factory()
    fixture.offer()
    fixture.call("ready")
    fixture.pool.stop_actor(fixture.root.worker_id, "root")
    wait_until(lambda: fixture.pool.quiescent(fixture.root.worker_id))
    actor = fixture.view()["actors"]["root"]
    config = Path(actor["config"]["path"])
    state = Path(actor["config"]["state_directory"])
    if fault == "missing_identity":
        (state / "identity.pem").unlink()
    elif fault == "missing_binding":
        (state / "binding.json").unlink()
    elif fault == "config_symlink":
        moved = config.with_name("moved.json")
        config.rename(moved)
        config.symlink_to(moved)
    elif fault == "state_symlink":
        moved = state.with_name("moved-state")
        state.rename(moved)
        state.symlink_to(moved, target_is_directory=True)
    else:
        scope = Path(fixture.document["server"]["scope_key_file"])
        moved = scope.with_name("scope-replacement")
        moved.write_bytes(scope.read_bytes())
        moved.chmod(0o600)
        os.replace(moved, scope)
    before, requests = database_snapshot(fixture.journal), fixture.requests()
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        fixture.call("ready")
    assert database_snapshot(fixture.journal) == before
    assert fixture.requests() == requests
    assert fixture.view()["actors"]["root"]["generations"] == 1


def test_startup_shortening_before_owner_scope_prevents_late_popen(live_factory, monkeypatch):
    from src.worker import managed_public_profiles as profiles
    fixture = live_factory()
    fixture.offer()
    entered, shortened_seen, release = threading.Event(), threading.Event(), threading.Event()
    original_run = profiles._Profile.run
    original_reuse = profiles._Profile.reuse_deadline
    errors = []
    scopes = []
    async def delayed_run(owner):
        entered.set()
        while not release.is_set():
            await asyncio.sleep(0.01)
        await original_run(owner)
    def observed_reuse(owner, root, policy, deadline):
        shorter = root.monotonic_deadline < owner.root_cutoff
        if shorter:
            scopes.append(owner.scope)
        value = original_reuse(owner, root, policy, deadline)
        if shorter:
            shortened_seen.set()
        return value
    def invoke(root):
        try:
            fixture.pool.call(root, fixture.policy, "root", fixture.deadline(30), "ready")
        except public.ManagedPublicError as error:
            errors.append(error.code)
    with monkeypatch.context() as patch:
        patch.setattr(profiles._Profile, "run", delayed_run)
        patch.setattr(profiles._Profile, "reuse_deadline", observed_reuse)
        first = threading.Thread(target=invoke, args=(fixture.root,))
        second = None
        first.start()
        try:
            assert entered.wait(5)
            shortened = replace(fixture.root, monotonic_deadline=time.monotonic() + 0.3)
            second = threading.Thread(target=invoke, args=(shortened,))
            second.start()
            assert shortened_seen.wait(5)
            assert scopes == [None]
            wait_until(lambda: time.monotonic() >= shortened.monotonic_deadline, seconds=2)
            release.set()
        finally:
            release.set()
            first.join(timeout=6)
            if second is not None:
                second.join(timeout=6)
        assert not first.is_alive() and second is not None and not second.is_alive()
    assert len(errors) == 2 and set(errors) == {"expired"}
    assert fixture.view()["processes"] == {}
    assert fixture.view()["actors"]["root"]["config"] is None
    assert not (Path(fixture.document["server"]["cwd"]) / "observations").exists()
    # Same real fixture/transport can start under an otherwise live original root.
    control = live_factory()
    control.offer()
    assert control.call("ready")["status"] is not None


def test_first_owner_cutoff_is_clipped_to_original_root_before_process_intent(live_factory):
    fixture = live_factory()
    fixture.offer()
    supplied = Deadline(fixture.root.deadline + 10, fixture.root.monotonic_deadline + 10)
    fixture.call("ready", deadline=supplied)
    row = next(row for row in fixture.view()["processes"].values() if row["stage"] == "server")
    assert row["intent"]["monotonic_cutoff"] == fixture.root.monotonic_deadline
    assert row["intent"]["monotonic_cutoff"] < supplied.monotonic_cutoff
