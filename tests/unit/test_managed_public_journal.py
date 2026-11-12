"""Real SQLite ownership/durability tests for dormant managed-public storage.

A validated named fixture policy exposes the future opt-in to the storage API.
Actual ChildPolicy/config admission remains disabled in this prerequisite.
Named grants, exec facts and cleanup receipts are component inputs, not Docker,
Polyphony, model-provider or process-termination qualification.
"""

from copy import deepcopy
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from src.worker.child_journal import ChildJournal
from src.worker.child_sessions import SESSION_SQL, ROUND_SQL
from src.worker.child_types import RootContext
from src.worker.lifecycle import LifecycleConflict
from src.worker.managed_public_journal import (
    PublicStore, PUBLIC_SQL, optional_schema, remaining,
)
from src.worker import managed_public_types as public
from tests.unit.test_child_authority_contract import context, grant, policy, request
from tests.unit.test_child_session_store import database_snapshot
from tests.unit.test_managed_public_types import public_document


class StoragePolicy:
    """Explicit fixture interface, never a production policy-admission bypass."""

    def __init__(self, document):
        self.base = replace(policy(), outcome_protocol="initial-v1")
        self.approved = public.PublicPolicy.parse(document)

    @property
    def public_discussion(self):
        return self.approved.document

    @property
    def fingerprint(self):
        return public.digest({
            "fixture_original_child_policy": self.base.fingerprint,
            "approved_public_policy": self.public_discussion,
        })

    def __getattr__(self, name):
        return getattr(self.base, name)


def operation(name, key, **values):
    return {"schema_version": 1, "operation": name, "request_id": key, **values}


def selection(**changes):
    return {
        "persona_key": "independent", "instruction_key": "proposal",
        "selected_message_ids": [], "reply_to": None, **changes,
    }


class PublicFixture:
    def __init__(self, tmp_path, monkeypatch):
        self.document = public_document(tmp_path)
        self.policy = StoragePolicy(self.document)
        self.root = context()
        self.clock = SimpleNamespace(now=100.0, wall=1_700_000_000.0)
        monkeypatch.setattr("src.worker.managed_public_journal.time.monotonic", lambda: self.clock.now)
        monkeypatch.setattr("src.worker.managed_public_journal.time.time", lambda: self.clock.wall)
        self.path = tmp_path / "journal"
        self.journal = ChildJournal(self.path)
        self.journal.prepare(self.root.worker_id, self.root.spec, self.policy)
        self.root = self.journal.bind(self.root)
        self.store = PublicStore(self.journal)
        self.keys = {}

    def close(self):
        self.journal.close()

    def reopen(self):
        self.close()
        self.journal = ChildJournal(self.path)
        self.journal.prepare(self.root.worker_id, self.root.spec, self.policy)
        self.root = self.journal.bind(self.root)
        self.store = PublicStore(self.journal)
        return self.view()

    def view(self):
        return self.store.view(self.root, self.policy)

    def identity(self, who="root"):
        value = {
            "schema_version": 1, "protocol": public.PROTOCOL,
            "worker_id": self.root.worker_id, "root_attempt_id": self.root.attempt_id,
            "task_id": self.root.task_id, "requirements_revision": self.root.requirements_revision,
            "profile_digest": self.root.profile_digest, "child_policy_digest": self.policy.fingerprint,
            "role": "root", "child_id": None, "uid": 65532,
            "exec_id": "exec-root", "grant_digest": None, "instructions_digest": "9" * 64,
        }
        if who != "root":
            child = self.journal.child(self.root.worker_id, who)
            binding = json.loads(child["grant_json"])["binding"]
            value.update({
                "role": "child", "child_id": who, "uid": child["uid"],
                "exec_id": child["exec_id"], "grant_digest": binding["grant_digest"],
                "instructions_digest": binding["instructions_digest"],
            })
        return value

    def child(self, *, deadline=500, armed=450):
        number = len(self.journal.children(self.root.worker_id)) + 1
        identifier = "child_" + f"{number:032x}"
        key = "ordinary-child-" + str(number)
        payload = request() | {"instructions": "private-instruction-canary-" + str(number)}
        self.journal.reserve(self.root.worker_id, key, payload, self.policy)
        self.journal.grant(
            self.root.worker_id, key, grant(self.root, payload, identifier),
            deadline, self.root.boot_id, self.policy,
        )
        self.journal.update(
            self.root.worker_id, identifier, phase="running",
            exec_id="exec-" + identifier, exec_dispatched=1, armed_deadline=armed,
        )
        return identifier

    def accept(self, name, key, *, who="root", **values):
        return self.store.accept(
            self.root, self.policy, self.identity(who), operation(name, key, **values), 900,
        )

    def offer(self, key="mpub1:activate", *, who="root", **values):
        name = "public_turn" if who == "root" else "public_activate"
        payload = selection(**values)
        if who != "root":
            payload["child_id"] = who
        self.accept(name, key, **payload)
        return self.store.offer(self.root, self.policy, key, self.identity(who), 900)

    def bind(self, who="root", seed=11):
        current = self.view()["actors"][who]
        base = (
            self.journal.root / "public"
            / public.digest([self.root.worker_id, self.root.attempt_id])
            / current["identity_digest"]
        )
        document = {
            "schema_version": 1, "topic": self.document["topic"],
            "scope_key_file": self.document["server"]["scope_key_file"],
            "state_directory": str(base / "state"),
        }
        config = {
            "state": "preparing", "path": str(base / "profile.json"),
            "state_directory": str(base / "state"), "document": document,
            "sha256": public.digest(document), "server_binding": self.policy.approved.check_server(),
        }
        # These explicit local config facts do not create or launch an A process.
        self.store.configuration_intent(self.root, self.policy, who, config)
        self.store.configuration_ready(self.root, self.policy, who, config | {"state": "ready"})
        key = Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)
        raw = key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        scope = self.document["server"]["scope_key_sha256"]
        status = {
            "schema_version": 1, "profile": "polyphony-public-conversation",
            "topic": self.document["topic"], "swarm_id": scope,
            "session_id": public.digest(["polyphony-public-conversation-v1", scope, self.document["topic"]]),
            "author": hashlib.sha256(raw).hexdigest()[:16], "public_key": raw.hex(),
            "stream_id": public.digest(["fixture-stream", who, seed])[:32],
            "visibility": "public", "execution_authorized": False,
        }
        interpreter = {
            "schema_version": 1, "launch_path": sys.executable,
            "resolved_executable": str(Path(sys.executable).resolve()), "prefix": sys.prefix,
        }
        self.keys[who] = key
        return self.store.bind_actor(self.root, self.policy, who, status, interpreter)

    def claim(self, slot, key="mpub1:pull", name="public_pull"):
        who = slot["actor_id"]
        self.accept(name, key, who=who, slot_id=slot["slot_id"])
        return self.store.claim(self.root, self.policy, key, slot["slot_id"])

    def receipt(self, slot, *, content="A public contribution.", kind="message", fixed=False):
        who = slot["actor_id"]
        if not fixed:
            self.store.freeze_context(self.root, self.policy, slot["slot_id"], [])
            payload = self.store.model_intent(self.root, self.policy, slot["slot_id"])
            assert payload["request_id"] == slot["model_key"]
        output = {"kind": kind, "content": content}
        self.store.retain_response(self.root, self.policy, slot["slot_id"], output, fixed_decline=fixed)
        intent = self.store.publication_intent(self.root, self.policy, slot["slot_id"])
        receipt = self.sign(who, intent)
        self.store.receipt(self.root, self.policy, slot["slot_id"], receipt)
        return receipt

    def sign(self, who, intent):
        actor = self.view()["actors"][who]
        status = actor["status"]
        body = deepcopy(intent) | {
            "schema_version": 1, "author": status["author"],
            "public_key": status["public_key"], "timestamp": self.clock.wall,
        }
        record = {
            "message_id": public.digest(body), "body": body,
            "signature": self.keys[who].sign(public.canonical(body)).hex(),
        }
        return {
            "schema_version": 1, "message_id": record["message_id"],
            "session_id": status["session_id"], "author": status["author"],
            "stored": True, "visibility": "public", "delivery": "submitted",
            "execution_authorized": False, "record": record,
        }

    def process(self, who, stage):
        actor = self.view()["actors"][who]
        intent = {
            "schema_version": 1, "stage": stage, "launch_path": sys.executable,
            "cwd": self.document["server"]["cwd"],
            "config_sha256": actor["config"]["sha256"],
            "argv_sha256": public.digest(["named-owner-fixture", stage]),
            "environment_sha256": public.digest({"LANG": "C.UTF-8"}),
            "monotonic_cutoff": 500, "boot_id": self.root.boot_id,
        }
        return self.store.process_intent(self.root, self.policy, who, stage, intent)

    def stopped(self, process, pid=12345):
        identity = {"pid": pid, "starttime": 100, "pgid": pid, "boot_id": self.root.boot_id}
        self.store.process_identity(self.root, self.policy, process["process_id"], identity)
        cleanup = {
            "identity": identity, "leader_terminated": True,
            "leader_reaped": True, "group_terminated": True,
        }
        self.store.process_finished(self.root, self.policy, process["process_id"], identity, cleanup)
        return identity, cleanup


@pytest.fixture
def public_fixture(tmp_path, monkeypatch):
    fixture = PublicFixture(tmp_path, monkeypatch)
    try:
        yield fixture
    finally:
        fixture.close()


def rewrite(journal, table, key_name, key, transform):
    """Coherently rehash an impossible retained row, not just break its checksum."""
    with journal.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        row = db.execute("SELECT data FROM " + table + " WHERE " + key_name + "=?", (key,)).fetchone()
        value = json.loads(row[0])
        transform(value)
        db.execute(
            "UPDATE " + table + " SET data=?,digest=? WHERE " + key_name + "=?",
            (public.canonical(value).decode(), public.digest(value), key),
        )


def test_legacy_and_cold_registry_keep_original_schema_without_enabling_public(tmp_path):
    journal = ChildJournal(tmp_path / "journal")
    try:
        root = context()
        journal.prepare(root.worker_id, root.spec, policy())
        with journal.connection() as db:
            assert optional_schema(db) == 0
            assert not db.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'public_%'").fetchall()
        cold = replace(policy(), outcome_protocol="initial-v1", session_protocol="cold-clarification-v1")
        journal.prepare("b" * 32, replace(root.spec, slot_id="cold"), cold)
        with journal.connection() as db:
            assert optional_schema(db) == 1
            assert db.execute("SELECT sql FROM sqlite_master WHERE name='cold_sessions'").fetchone()[0] == SESSION_SQL
            assert db.execute("SELECT sql FROM sqlite_master WHERE name='cold_rounds'").fetchone()[0] == ROUND_SQL
            assert not db.execute("SELECT 1 FROM sqlite_master WHERE name LIKE 'public_%'").fetchall()
    finally:
        journal.close()


def test_public_install_and_failed_worker_binding_commit_as_one_transaction(tmp_path):
    document = public_document(tmp_path)
    selected = StoragePolicy(document)
    journal = ChildJournal(tmp_path / "journal")
    try:
        with journal.connection() as db:
            db.execute(
                "CREATE TRIGGER reject_worker BEFORE INSERT ON workers "
                "BEGIN SELECT RAISE(ABORT,'fixture publication failure'); END"
            )
        before = database_snapshot(journal)
        with pytest.raises(sqlite3.IntegrityError, match="fixture publication failure"):
            journal.prepare(context().worker_id, context().spec, selected)
        assert database_snapshot(journal) == before
        with journal.connection() as db:
            db.execute("DROP TRIGGER reject_worker")
        journal.prepare(context().worker_id, context().spec, selected)
        with journal.connection() as db:
            assert optional_schema(db) == 2
            assert db.execute("SELECT COUNT(*) FROM public_workers").fetchone()[0] == 1
    finally:
        journal.close()


@pytest.mark.parametrize("have_request", [False, True])
@pytest.mark.parametrize("new_public", [False, True])
def test_missing_public_schema_cannot_be_recreated_by_another_worker(public_fixture, have_request, new_public):
    f = public_fixture
    if have_request:
        f.accept("public_read", "mpub1:owned", after=0, stream_id=None, watch_seconds=0)
    with f.journal.connection() as db:
        for table in PUBLIC_SQL:
            db.execute("DROP TABLE " + table)
    broken = database_snapshot(f.journal)
    chosen = f.policy if new_public else policy()
    with pytest.raises(LifecycleConflict, match="schema"):
        f.journal.prepare("b" * 32, replace(f.root.spec, slot_id="other"), chosen)
    assert database_snapshot(f.journal) == broken
    with pytest.raises(LifecycleConflict, match="schema"):
        f.view()
    assert database_snapshot(f.journal) == broken


@pytest.mark.parametrize("mutation", ["unknown", "marker_zero", "one_table", "altered_table"])
def test_optional_schema_corruption_refuses_ordinary_writes_without_repair(public_fixture, mutation):
    f = public_fixture
    with f.journal.connection() as db:
        if mutation == "unknown":
            db.execute("PRAGMA user_version=99")
        elif mutation == "marker_zero":
            db.execute("PRAGMA user_version=0")
        elif mutation == "one_table":
            db.execute("DROP TABLE public_requests")
        else:
            db.execute("ALTER TABLE public_requests ADD COLUMN unauthorized TEXT")
    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict, match="schema"):
        f.journal.prepare("c" * 32, replace(f.root.spec, slot_id="ordinary"), policy())
    assert database_snapshot(f.journal) == before


def test_mixed_public_cold_and_ordinary_workers_have_exact_distinct_optional_state(public_fixture):
    f = public_fixture
    cold = replace(policy(), outcome_protocol="initial-v1", session_protocol="cold-clarification-v1")
    f.journal.prepare("b" * 32, replace(f.root.spec, slot_id="cold"), cold)
    f.journal.prepare("c" * 32, replace(f.root.spec, slot_id="ordinary"), policy())
    with f.journal.connection() as db:
        assert optional_schema(db) == 3
        assert db.execute("SELECT COUNT(*) FROM public_workers").fetchone()[0] == 1
        assert db.execute("SELECT sql FROM sqlite_master WHERE name='cold_sessions'").fetchone()[0] == SESSION_SQL
    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict):
        f.journal.prepare(f.root.worker_id, f.root.spec, policy())
    assert database_snapshot(f.journal) == before


def test_global_original_key_owns_actor_and_operation_before_any_slot(public_fixture):
    f = public_fixture
    child = f.child()
    original = f.accept("public_read", "mpub1:owned", who=child, after=0, stream_id=None, watch_seconds=0)
    before = database_snapshot(f.journal)
    assert f.accept("public_read", "mpub1:owned", who=child, after=0, stream_id=None, watch_seconds=0) == original
    for who, name, values in (
        ("root", "public_read", {"after": 0, "stream_id": None, "watch_seconds": 0}),
        (child, "public_pending", {}),
        (child, "public_read", {"after": 1, "stream_id": "a" * 32, "watch_seconds": 0}),
    ):
        with pytest.raises(public.ManagedPublicError, match="conflict"):
            f.accept(name, "mpub1:owned", who=who, **values)
    with pytest.raises(LifecycleConflict, match="public operation namespace"):
        f.journal.reserve(f.root.worker_id, "mpub1:owned", request(), f.policy)
    with pytest.raises(LifecycleConflict, match="public operation namespace"):
        f.journal.retain_outcome(f.root.worker_id, child, "mpub1:owned", "declined", "private")
    assert database_snapshot(f.journal) == before
    assert f.reopen()["requests"]["mpub1:owned"] == original


def test_total_128_owner_cap_survives_mixed_operations_and_reopen(public_fixture):
    f = public_fixture
    child = f.child()
    for index in range(128):
        if index % 2:
            f.accept("public_pending", f"mpub1:{index}", who=child)
        else:
            f.accept("public_read", f"mpub1:{index}", after=0, stream_id=None, watch_seconds=0)
    before = database_snapshot(f.journal)
    with pytest.raises(public.ManagedPublicError, match="request_limit"):
        f.accept("public_read", "mpub1:overflow", after=0, stream_id=None, watch_seconds=0)
    assert database_snapshot(f.journal) == before
    assert f.view()["header"]["slots"] == f.view()["header"]["history_charges"] == 0
    f.reopen()
    assert f.accept("public_pending", "mpub1:1", who=child)["request_id"] == "mpub1:1"
    with pytest.raises(public.ManagedPublicError, match="request_limit"):
        f.accept("public_pending", "mpub1:new", who=child)
    assert database_snapshot(f.journal) == before


def test_original_deadline_and_earliest_armed_child_bound_survive_restart(public_fixture):
    f = public_fixture
    child = f.child(deadline=120, armed=109)
    slot = f.offer(who=child)
    assert f.root.monotonic_deadline == 1000
    assert slot["monotonic_cutoff"] == 109
    assert slot["expires_at"] == f.clock.wall + 9
    original = deepcopy(slot)
    f.clock.now = 108
    f.clock.wall -= 1000
    assert remaining(slot, f.root.boot_id) == 1
    f.reopen()
    assert f.view()["slots"][slot["slot_id"]] == original
    f.clock.now = 110
    assert remaining(slot, f.root.boot_id) == 0
    assert remaining(slot, "different-boot") == 0
    # Replaying activation cannot allocate another slot or extend its cutoff.
    assert f.offer(who=child) == original
    assert len(f.view()["slots"]) == 1
    f.claim(slot)
    f.bind(child)
    f.store.freeze_context(f.root, f.policy, slot["slot_id"], [])
    with pytest.raises(public.ManagedPublicError, match="expired"):
        f.store.model_intent(f.root, f.policy, slot["slot_id"])
    assert f.view()["slots"][slot["slot_id"]]["model_call_digest"] is None


def test_exact_actor_binding_is_distinct_and_cannot_be_replaced(public_fixture):
    f = public_fixture
    first, second = f.child(), f.child()
    f.offer("mpub1:first", who=first)
    f.offer("mpub1:second", who=second)
    actor = f.bind(first, seed=11)
    before = database_snapshot(f.journal)
    # Distinct transport actors cannot claim the same retained public author.
    with pytest.raises(LifecycleConflict):
        f.bind(second, seed=11)
    assert f.view()["actors"][first] == actor
    assert f.view()["actors"][second]["status"] is None
    # The successful config preparation is independent from the refused binding.
    assert database_snapshot(f.journal) != before
    bound = f.bind(second, seed=12) if f.view()["actors"][second]["config"] is None else None
    if bound is None:
        second_actor = f.view()["actors"][second]
        second_key = Ed25519PrivateKey.from_private_bytes(bytes([12]) * 32)
        raw = second_key.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        changed = deepcopy(actor["status"]) | {
            "public_key": raw.hex(), "author": hashlib.sha256(raw).hexdigest()[:16],
            "stream_id": public.digest(["separate", second])[:32],
        }
        f.store.bind_actor(f.root, f.policy, second, changed, actor["binding"]["interpreter"])
    stable = database_snapshot(f.journal)
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        f.store.bind_actor(
            f.root, f.policy, first, actor["status"] | {"stream_id": "0" * 32},
            actor["binding"]["interpreter"],
        )
    assert database_snapshot(f.journal) == stable
    f.reopen()
    assert f.view()["actors"][first]["binding_digest"] == actor["binding_digest"]


def test_six_slots_two_per_actor_and_one_invitation_do_not_change_canonical_costs(public_fixture):
    f = public_fixture
    children = [f.child(), f.child()]
    original_children = f.journal.children(f.root.worker_id)
    for who in ["root", *children]:
        for index in range(2):
            f.offer(f"mpub1:{who}-{index}", who=who)
    value = f.view()
    assert value["header"]["slots"] == 6
    assert value["header"]["post_reservations"] == 6
    f.accept("public_invite", "mpub1:invite", invitation_key="peer")
    f.store.invite(f.root, f.policy, "mpub1:invite")
    assert f.view()["header"]["post_reservations"] == 7
    for who in ["root", *children]:
        key = "mpub1:extra-" + who
        with pytest.raises(public.ManagedPublicError, match="slot_limit"):
            f.offer(key, who=who)
        assert f.view()["header"]["slots"] == 6
    f.accept("public_invite", "mpub1:invite-two", invitation_key="peer")
    with pytest.raises(public.ManagedPublicError, match="slot_limit"):
        f.store.invite(f.root, f.policy, "mpub1:invite-two")
    assert f.journal.children(f.root.worker_id) == original_children
    assert not any(slot["model_call_digest"] for slot in f.view()["slots"].values())


def test_fixed_child_decline_has_original_receipt_without_model_or_new_key(public_fixture):
    f = public_fixture
    child = f.child()
    slot = f.offer(who=child)
    f.claim(slot, "mpub1:decline", "public_decline")
    f.bind(child)
    original_children = f.journal.children(f.root.worker_id)
    receipt = f.receipt(slot, kind="decline", content=public.DECLINE_TEXT, fixed=True)
    value = f.view()["slots"][slot["slot_id"]]
    assert value["state"] == "declined"
    assert value["context"] is value["model_call_digest"] is None
    assert value["receipt"] == receipt and receipt["record"]["body"]["references"] == []
    before = database_snapshot(f.journal)
    f.clock.now = 500
    f.clock.wall += 1000
    f.reopen()
    assert f.store.receipt(f.root, f.policy, slot["slot_id"], receipt)["receipt"] == receipt
    assert f.store.claim(f.root, f.policy, "mpub1:decline", slot["slot_id"])["state"] == "declined"
    assert database_snapshot(f.journal) == before
    assert f.journal.children(f.root.worker_id) == original_children


def test_late_local_receipt_can_be_retained_after_expiry_without_new_dispatch(public_fixture):
    f = public_fixture
    slot = f.offer()
    f.bind()
    f.store.freeze_context(f.root, f.policy, slot["slot_id"], [])
    f.store.model_intent(f.root, f.policy, slot["slot_id"])
    output = {"kind": "message", "content": "Retained original public result."}
    f.store.retain_response(f.root, f.policy, slot["slot_id"], output)
    original_intent = f.store.publication_intent(f.root, f.policy, slot["slot_id"])
    receipt = f.sign("root", original_intent)
    f.clock.now = 200
    f.clock.wall += 100
    f.store.close(f.root, f.policy)
    with pytest.raises(public.ManagedPublicError):
        f.store.publication_intent(f.root, f.policy, slot["slot_id"])
    f.store.receipt(f.root, f.policy, slot["slot_id"], receipt)
    assert f.view()["slots"][slot["slot_id"]]["receipt"] == receipt
    assert f.view()["header"]["closed"] is True
    assert f.view()["header"]["requests"] == f.view()["header"]["slots"] == 1


def test_leave_is_sticky_and_does_not_cancel_private_work_or_hide_lifetime_slots(public_fixture):
    f = public_fixture
    child = f.child()
    first = f.offer("mpub1:first", who=child)
    second = f.offer("mpub1:second", who=child)
    f.claim(first)
    f.bind(child)
    original_children = f.journal.children(f.root.worker_id)
    receipt = f.receipt(first, kind="leave", content="I leave this public discussion.")
    current = f.view()
    actor = current["actors"][child]
    assert actor["closed"] is True and actor["leave_slot"] == first["slot_id"]
    assert current["slots"][first["slot_id"]]["state"] == "left"
    assert current["slots"][second["slot_id"]]["state"] == "refused"
    assert current["slots"][second["slot_id"]]["reason"] == "refused_left"
    assert [slot["slot_id"] for slot in current["slots"].values()] == [first["slot_id"], second["slot_id"]]
    assert f.journal.children(f.root.worker_id) == original_children
    f.reopen()
    assert f.view()["slots"][first["slot_id"]]["receipt"] == receipt
    with pytest.raises(public.ManagedPublicError, match="actor_left"):
        f.offer("mpub1:cannot-reopen", who=child)
    # A public leave has not changed the original private outcome/capture API.
    report = f.journal.retain_outcome(
        f.root.worker_id, child, "private-final", "completed", "private-outcome-canary",
    )
    assert report["outcome"] == "completed"
    assert not f.journal.child(f.root.worker_id, child)["revoked"]


def test_pending_invitation_must_recover_before_leave_closes_actor(public_fixture):
    f = public_fixture
    f.accept("public_invite", "mpub1:invite", invitation_key="peer")
    f.store.invite(f.root, f.policy, "mpub1:invite")
    f.bind()
    intent = f.store.invitation_intent(f.root, f.policy, "mpub1:invite")
    original_receipt = f.sign("root", intent)
    f.store.failure(f.root, f.policy, "mpub1:invite", "publication_uncertain", uncertain=True)
    slot = f.offer("mpub1:leave")
    f.store.freeze_context(f.root, f.policy, slot["slot_id"], [])
    f.store.model_intent(f.root, f.policy, slot["slot_id"])
    output = {"kind": "leave", "content": "I leave after resolving the original invitation."}
    before = database_snapshot(f.journal)
    with pytest.raises(public.ManagedPublicError, match="publication_uncertain"):
        f.store.retain_response(f.root, f.policy, slot["slot_id"], output)
    assert database_snapshot(f.journal) == before
    assert f.view()["actors"]["root"]["closed"] is False
    f.reopen()
    assert f.store.invitation_intent(f.root, f.policy, "mpub1:invite") == intent
    f.store.invitation_receipt(f.root, f.policy, "mpub1:invite", original_receipt)
    f.store.retain_response(f.root, f.policy, slot["slot_id"], output)
    leave_intent = f.store.publication_intent(f.root, f.policy, slot["slot_id"])
    f.store.receipt(f.root, f.policy, slot["slot_id"], f.sign("root", leave_intent))
    assert f.view()["actors"]["root"]["closed"] is True
    assert f.view()["requests"]["mpub1:invite"]["invitation"]["receipt"] == original_receipt
    assert f.view()["header"]["requests"] == 2


def test_real_signatures_context_and_original_receipts_cannot_be_rewritten(public_fixture):
    f = public_fixture
    first = f.offer("mpub1:proposal")
    f.bind()
    receipt = f.receipt(first)
    record = receipt["record"]
    second = f.offer(
        "mpub1:followup", selected_message_ids=[record["message_id"]], reply_to=record["message_id"],
    )
    bad = deepcopy(record)
    bad["signature"] = "0" * 128
    assert bad["message_id"] == public.digest(bad["body"]) == record["message_id"]
    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict):
        f.store.freeze_context(f.root, f.policy, second["slot_id"], [bad])
    assert database_snapshot(f.journal) == before
    f.store.freeze_context(f.root, f.policy, second["slot_id"], [record])
    retained = f.view()["slots"][second["slot_id"]]
    assert retained["context"] == [record]
    assert retained["context_digest"] == public.digest([record])
    payload = f.store.model_intent(f.root, f.policy, second["slot_id"])
    assert json.loads(payload["messages"][1]["content"])["public_context"] == [record]
    f.reopen()
    assert f.view()["slots"][second["slot_id"]]["context"] == [record]
    before = database_snapshot(f.journal)
    altered_receipt = deepcopy(receipt)
    altered_receipt["record"]["body"]["content"] = "changed"
    with pytest.raises(LifecycleConflict):
        f.store.receipt(f.root, f.policy, first["slot_id"], altered_receipt)
    assert database_snapshot(f.journal) == before


def test_history_charge_precedes_receipt_and_unknown_read_is_not_redispatched(public_fixture):
    f = public_fixture
    first = f.offer()
    f.bind()
    receipt = f.receipt(first)
    actor = f.view()["actors"]["root"]
    key = "mpub1:read"
    f.accept("public_read", key, after=0, stream_id=None, watch_seconds=0)
    f.store.charge_history(f.root, f.policy, key)
    before = database_snapshot(f.journal)
    assert f.view()["header"]["history_charges"] == f.view()["header"]["page_charges"] == 1
    with pytest.raises(public.ManagedPublicError, match="publication_uncertain"):
        f.store.charge_history(f.root, f.policy, key)
    assert database_snapshot(f.journal) == before
    page = {
        "schema_version": 1, "session_id": actor["status"]["session_id"],
        "topic": actor["status"]["topic"], "stream_id": actor["status"]["stream_id"],
        "messages": [{"cursor": 4, "record": receipt["record"], "reply_state": "none"}],
        "next_cursor": 4, "has_more": False, "gap": None, "peer_gaps": {"count": 0, "items": []},
    }
    f.clock.now = 200
    f.clock.wall += 100
    assert f.store.retain_page(f.root, f.policy, key, page) == page
    f.reopen()
    assert f.store.retain_page(f.root, f.policy, key, page) == page
    assert f.view()["header"]["records"] == 1
    changed = deepcopy(page)
    changed["next_cursor"] = 5
    with pytest.raises(LifecycleConflict):
        f.store.retain_page(f.root, f.policy, key, changed)


@pytest.mark.parametrize("field,value", [
    ("requests", True), ("requests", 0), ("history_charges", True),
    ("page_charges", True), ("post_reservations", True), ("transcript_bytes", True),
])
def test_coherently_rehashed_impossible_counters_fail_before_another_operation(public_fixture, field, value):
    f = public_fixture
    f.offer()
    rewrite(f.journal, "public_workers", "worker_id", f.root.worker_id, lambda row: row.__setitem__(field, value))
    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict, match="retained state"):
        f.view()
    with pytest.raises(LifecycleConflict):
        f.accept("public_read", "mpub1:next", after=0, stream_id=None, watch_seconds=0)
    assert database_snapshot(f.journal) == before


@pytest.mark.parametrize("fault", ["path", "config_hash", "interpreter", "scope", "actor_uid"])
def test_bound_profile_and_actor_facts_cannot_be_coherently_replaced(public_fixture, fault):
    f = public_fixture
    child = f.child()
    f.offer(who=child)
    f.bind(child)

    def mutate(actor):
        if fault == "path":
            actor["config"]["path"] += ".replacement"
        elif fault == "config_hash":
            actor["binding"]["config_sha256"] = "0" * 64
        elif fault == "interpreter":
            actor["binding"]["interpreter"]["launch_path"] = "/unapproved/python"
        elif fault == "scope":
            actor["config"]["server_binding"]["scope"]["sha256"] = "0" * 64
        else:
            actor["identity"]["uid"] += 1
            actor["identity_digest"] = public.digest(actor["identity"])
            actor["binding"]["identity"] = deepcopy(actor["identity"])
        actor["binding_digest"] = public.digest(actor["binding"])

    rewrite(f.journal, "public_actors", "actor_id", child, mutate)
    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict):
        f.view()
    assert database_snapshot(f.journal) == before


def test_unknown_pre_popen_intent_blocks_relaunch_and_final_freeze_after_reopen(public_fixture):
    f = public_fixture
    f.offer()
    f.bind()
    started = f.process("root", "probe")
    before = database_snapshot(f.journal)
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        f.process("root", "probe")
    assert database_snapshot(f.journal) == before
    f.reopen()
    assert f.view()["processes"][started["process_id"]]["identity"] is None
    f.store.close(f.root, f.policy)
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        f.store.freeze(f.root, f.policy, owners_quiescent=True)
    assert f.view()["header"]["frozen"] is None


def test_known_process_identity_and_positive_cleanup_bound_two_generations(public_fixture):
    f = public_fixture
    f.offer()
    f.bind()
    for generation in (1, 2):
        probe = f.process("root", "probe")
        assert probe["generation"] == generation
        identity, cleanup = f.stopped(probe, pid=12000 + generation)
        server = f.process("root", "server")
        assert server["generation"] == generation
        server_identity = {"pid": 13000 + generation, "starttime": 200,
                           "pgid": 13000 + generation, "boot_id": f.root.boot_id}
        f.store.process_identity(f.root, f.policy, server["process_id"], server_identity)
        before = database_snapshot(f.journal)
        with pytest.raises(LifecycleConflict):
            f.store.process_finished(
                f.root, f.policy, server["process_id"], server_identity,
                {"identity": server_identity, "leader_terminated": True,
                 "leader_reaped": True, "group_terminated": False},
            )
        assert database_snapshot(f.journal) == before
        valid = {"identity": server_identity, "leader_terminated": True,
                 "leader_reaped": True, "group_terminated": True}
        f.store.process_finished(f.root, f.policy, server["process_id"], server_identity, valid)
        f.reopen()
    assert len(f.view()["processes"]) == 4
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        f.process("root", "probe")
    f.store.close(f.root, f.policy)
    with pytest.raises(public.ManagedPublicError, match="retry_later"):
        f.store.freeze(f.root, f.policy, owners_quiescent=False)
    snapshot, digest = f.store.freeze(f.root, f.policy, owners_quiescent=True)
    assert digest == public.digest(snapshot)
    assert f.reopen()["header"]["freeze_digest"] == digest


def test_frozen_public_root_projection_excludes_private_mapping_and_keeps_child_binding(public_fixture):
    f = public_fixture
    child = f.child()
    slot = f.offer(who=child)
    f.claim(slot)
    f.bind(child)
    receipt = f.receipt(slot, content="Separate attributable public criticism.")
    f.journal.retain_outcome(
        f.root.worker_id, child, "private-report", "completed", "private-outcome-canary",
    )
    f.store.close(f.root, f.policy)
    snapshot, checksum = f.store.freeze(f.root, f.policy, owners_quiescent=True)
    root, children = f.store.extensions(f.root, f.policy)
    assert root["snapshot_sha256"] == checksum
    assert root["records"] == [receipt["record"]]
    raw = public.canonical(root)
    for private in (
        child.encode(), ("exec-" + child).encode(), b"private-instruction-canary",
        b"private-outcome-canary", b"private-scope-canary", b"scope_key_file",
        b'"uid"', b'"grant_digest"', b'"instructions_digest"',
    ):
        assert private not in raw
    private = children[child]
    assert private["actor"]["identity"]["child_id"] == child
    assert private["actor"]["identity"]["exec_id"] == "exec-" + child
    assert private["slots"][0]["receipt"] == receipt
    before = database_snapshot(f.journal)
    f.reopen()
    assert f.store.extensions(f.root, f.policy) == (root, children)
    assert f.store.freeze(f.root, f.policy, owners_quiescent=True) == (snapshot, checksum)
    with pytest.raises(public.ManagedPublicError, match="not_authorized"):
        f.accept("public_read", "mpub1:after-freeze", after=0, stream_id=None, watch_seconds=0)
    assert database_snapshot(f.journal) == before


def test_acknowledged_owner_survives_real_writer_process_exit(tmp_path):
    document = public_document(tmp_path)
    selected = StoragePolicy(document)
    root = context()
    journal_path = tmp_path / "journal"
    identity = {
        "schema_version": 1, "protocol": public.PROTOCOL,
        "worker_id": root.worker_id, "root_attempt_id": root.attempt_id,
        "task_id": root.task_id, "requirements_revision": root.requirements_revision,
        "profile_digest": root.profile_digest, "child_policy_digest": selected.fingerprint,
        "role": "root", "child_id": None, "uid": 65532, "exec_id": "exec-root",
        "grant_digest": None, "instructions_digest": "9" * 64,
    }
    payload = operation("public_read", "mpub1:crash-ack", after=0, stream_id=None, watch_seconds=0)
    script = (
        "import json,os,sys\n"
        "from src.worker.child_journal import ChildJournal\n"
        "from src.worker.child_types import RootContext\n"
        "from src.worker.managed_public_journal import PublicStore\n"
        "from tests.unit.test_managed_public_journal import StoragePolicy\n"
        "path,document,root,identity,payload=sys.argv[1:]\n"
        "policy=StoragePolicy(json.loads(document)); root=RootContext.from_dict(json.loads(root))\n"
        "journal=ChildJournal(path); journal.prepare(root.worker_id,root.spec,policy); journal.bind(root)\n"
        "result=PublicStore(journal).accept(root,policy,json.loads(identity),json.loads(payload),900,now=100,wall=1700000000)\n"
        "assert result['request_id']=='mpub1:crash-ack'\n"
        "os._exit(17)\n"
    )
    result = subprocess.run(
        [sys.executable, "-c", script, str(journal_path), json.dumps(document),
         json.dumps(root.to_dict()), json.dumps(identity), json.dumps(payload)],
        stdin=subprocess.DEVNULL, capture_output=True, timeout=10, check=False,
    )
    assert result.returncode == 17 and result.stdout == result.stderr == b""
    journal = ChildJournal(journal_path)
    try:
        journal.prepare(root.worker_id, root.spec, selected)
        journal.bind(root)
        store = PublicStore(journal)
        before = database_snapshot(journal)
        original = store.accept(root, selected, identity, payload, 900, now=800, wall=1800000000)
        assert original["monotonic_cutoff"] == 115
        assert original["expires_at"] == 1700000015
        assert database_snapshot(journal) == before
        with pytest.raises(public.ManagedPublicError, match="conflict"):
            store.accept(root, selected, identity, payload | {"after": 1, "stream_id": "a" * 32},
                         900, now=100, wall=1700000000)
        assert database_snapshot(journal) == before
    finally:
        journal.close()


@pytest.mark.parametrize("fault", ["monotonic", "boot", "wall"])
def test_coherently_rehashed_request_and_slot_cannot_exceed_original_root(public_fixture, fault):
    f = public_fixture
    slot = f.offer()
    key = slot["activation_request_id"]
    field, value = {
        "monotonic": ("monotonic_cutoff", f.root.monotonic_deadline + 1),
        "boot": ("boot_id", "foreign-boot"),
        "wall": ("expires_at", f.root.deadline + 1),
    }[fault]
    with f.journal.connection() as db:
        db.execute("BEGIN IMMEDIATE")
        for table, column, identity in (
            ("public_requests", "request_id", key),
            ("public_slots", "slot_id", slot["slot_id"]),
        ):
            row = db.execute("SELECT data FROM " + table + " WHERE " + column + "=?", (identity,)).fetchone()
            value_row = json.loads(row[0])
            value_row[field] = value
            db.execute(
                "UPDATE " + table + " SET data=?,digest=? WHERE " + column + "=?",
                (public.canonical(value_row).decode(), public.digest(value_row), identity),
            )
    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict):
        f.view()
    assert database_snapshot(f.journal) == before


def test_live_local_observation_key_keeps_original_ownership_while_network_page_is_separate(public_fixture):
    f = public_fixture
    child = f.child()
    original = f.accept("public_pending", "mpub1:pending", who=child)
    assert list(f.view()["slots"]) == []
    first = f.offer("mpub1:first", who=child)
    assert f.accept("public_pending", "mpub1:pending", who=child) == original
    assert list(f.view()["slots"]) == [first["slot_id"]]
    second = f.offer("mpub1:second", who=child)
    f.claim(first, "mpub1:decline", "public_decline")
    f.bind(child)
    f.receipt(first, kind="decline", content=public.DECLINE_TEXT, fixed=True)
    before = database_snapshot(f.journal)
    current = f.reopen()
    assert f.accept("public_pending", "mpub1:pending", who=child) == original
    own = [PublicStore.project_slot(current, value["slot_id"]) for value in current["slots"].values()
           if value["actor_id"] == child]
    assert [value["slot_id"] for value in own] == [first["slot_id"], second["slot_id"]]
    assert [value["state"] for value in own] == ["declined", "offered"]
    assert current["requests"]["mpub1:pending"]["result"] is None
    assert current["header"]["history_charges"] == current["header"]["page_charges"] == 0
    assert database_snapshot(f.journal) == before


def test_fresh_request_clips_to_original_wall_deadline_and_retained_cutoff_is_not_rewritten(public_fixture):
    f = public_fixture
    original = f.offer()
    f.root = f.journal.bind(replace(f.root, monotonic_deadline=120))
    assert f.view()["slots"][original["slot_id"]]["monotonic_cutoff"] == 145
    # A later shorter permission sample restricts new work but is not a rewrite
    # of the original request record; live dispatch still needs its caller gate.
    value = f.accept("public_read", "mpub1:shorter", after=0, stream_id=None, watch_seconds=0)
    assert value["monotonic_cutoff"] == 115
    f.clock.wall = f.root.deadline - 2
    clipped = f.accept("public_read", "mpub1:wall", after=0, stream_id=None, watch_seconds=0)
    assert clipped["expires_at"] == f.root.deadline
    assert clipped["monotonic_cutoff"] == f.clock.now + 2
    f.clock.wall = f.root.deadline + 1
    before = database_snapshot(f.journal)
    with pytest.raises(public.ManagedPublicError, match="expired"):
        f.accept("public_read", "mpub1:past-wall", after=0, stream_id=None, watch_seconds=0)
    assert database_snapshot(f.journal) == before


@pytest.mark.parametrize("case", ["slot_count", "invitation_count", "escaped_bytes", "already_observed"])
def test_original_receipt_converts_only_its_outstanding_storage_reservation(public_fixture, case):
    f = public_fixture
    content = "\n" * 7400 if case == "escaped_bytes" else "Original approved public contribution."
    invitation = case == "invitation_count"
    if invitation:
        key = "mpub1:invite"
        f.accept("public_invite", key, invitation_key="peer")
        f.store.invite(f.root, f.policy, key)
        f.bind()
        intent = f.store.invitation_intent(f.root, f.policy, key)
        slot = None
    else:
        slot = f.offer()
        key = slot["activation_request_id"]
        f.bind()
        f.store.freeze_context(f.root, f.policy, slot["slot_id"], [])
        f.store.model_intent(f.root, f.policy, slot["slot_id"])
        f.store.retain_response(
            f.root, f.policy, slot["slot_id"], {"kind": "message", "content": content},
        )
        intent = f.store.publication_intent(f.root, f.policy, slot["slot_id"])
    original = f.sign("root", intent)
    f.store.failure(
        f.root, f.policy, key, "publication_uncertain",
        slot_id=None if invitation else slot["slot_id"], uncertain=True,
    )

    other_slot = None
    if case == "already_observed":
        child = f.child()
        other_slot = f.offer("mpub1:other-activation", who=child)
        f.claim(other_slot, "mpub1:other-pull")
        f.bind(child, seed=12)
        f.store.freeze_context(f.root, f.policy, other_slot["slot_id"], [])
        f.store.model_intent(f.root, f.policy, other_slot["slot_id"])
        f.store.retain_response(
            f.root, f.policy, other_slot["slot_id"],
            {"kind": "message", "content": "A different unacknowledged public contribution."},
        )
        f.store.publication_intent(f.root, f.policy, other_slot["slot_id"])
        f.store.failure(
            f.root, f.policy, "mpub1:other-pull", "publication_uncertain",
            slot_id=other_slot["slot_id"], uncertain=True,
        )

    status = f.view()["actors"]["root"]["status"]
    peer_key = Ed25519PrivateKey.from_private_bytes(bytes([41]) * 32)
    peer_raw = peer_key.public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw,
    )
    peer_status = status | {
        "author": hashlib.sha256(peer_raw).hexdigest()[:16], "public_key": peer_raw.hex(),
    }
    assert peer_status["author"] != status["author"]

    def peer_record(number):
        text = content if case == "escaped_bytes" else "Independent public record " + str(number)
        body = public.signed_intent(peer_status, "peer:" + str(number), "message", text) | {
            "schema_version": 1, "author": peer_status["author"],
            "public_key": peer_status["public_key"], "timestamp": f.clock.wall,
        }
        return {
            "message_id": public.digest(body), "body": body,
            "signature": peer_key.sign(public.canonical(body)).hex(),
        }

    cursor = 0
    read_number = 0

    def retain(records, *, refused=False):
        nonlocal cursor, read_number
        read_number += 1
        read_key = "mpub1:capacity-read-" + str(read_number)
        f.accept(
            "public_read", read_key, after=cursor,
            stream_id=status["stream_id"] if cursor else None, watch_seconds=0,
        )
        f.store.charge_history(f.root, f.policy, read_key)
        page = {
            "schema_version": 1, "session_id": status["session_id"],
            "topic": status["topic"], "stream_id": status["stream_id"],
            "messages": [
                {"cursor": cursor + index + 1, "record": record, "reply_state": "none"}
                for index, record in enumerate(records)
            ],
            "next_cursor": cursor + len(records), "has_more": False,
            "gap": None, "peer_gaps": {"count": 0, "items": []},
        }
        assert sum(len(public.canonical(item)) for item in page["messages"]) <= 24576
        if refused:
            # The read dispatch charge is already durable. Only its impossible
            # transcript insertion must roll back without dropping any owner.
            before = database_snapshot(f.journal)
            with pytest.raises(public.ManagedPublicError, match="transcript_limit"):
                f.store.retain_page(f.root, f.policy, read_key, page)
            assert database_snapshot(f.journal) == before
        else:
            assert f.store.retain_page(f.root, f.policy, read_key, page) == page
            cursor = page["next_cursor"]

    count = 15 if case == "escaped_bytes" else 29 if case == "already_observed" else 31
    records = [peer_record(index) for index in range(count)]
    if case == "already_observed":
        records.append(original["record"])
    page_size = 1 if case == "escaped_bytes" else 15
    for index in range(0, len(records), page_size):
        retain(records[index:index + page_size])
    before_ack = f.view()
    original_records = before_ack["header"]["records"]
    lifetime = 2 if other_slot is not None else 1
    assert before_ack["header"]["post_reservations"] == lifetime
    if case == "escaped_bytes":
        used = before_ack["header"]["transcript_bytes"]
        actual = len(public.canonical(original["record"]))
        assert used + public.RECORD_LIMIT <= public.TRANSCRIPT_BYTES
        assert used + actual <= public.TRANSCRIPT_BYTES
        assert used + actual + public.RECORD_LIMIT > public.TRANSCRIPT_BYTES
    else:
        # Even an unknown acknowledgement keeps its maximum storage reserved.
        retain([peer_record(900)], refused=True)
    f.reopen()

    def acknowledge():
        if invitation:
            return f.store.invitation_receipt(f.root, f.policy, key, original)
        return f.store.receipt(f.root, f.policy, slot["slot_id"], original)

    assert acknowledge()["receipt"] == original
    current = f.view()
    expected_records = original_records if case == "already_observed" else original_records + 1
    assert current["header"]["records"] == expected_records
    assert current["records"][original["message_id"]] == original["record"]
    assert current["header"]["post_reservations"] == lifetime
    assert current["header"]["transcript_bytes"] == sum(
        len(public.canonical(record)) for record in current["records"].values()
    )
    if other_slot is not None:
        assert current["slots"][other_slot["slot_id"]]["receipt"] is None
        assert current["slots"][other_slot["slot_id"]]["state"] == "uncertain"
        retain([peer_record(901)])
        assert f.view()["header"]["records"] == 31
    before_replay = database_snapshot(f.journal)
    f.reopen()
    assert acknowledge()["receipt"] == original
    assert database_snapshot(f.journal) == before_replay
    # Replay cannot release again, and another unknown post remains reserved.
    retain([peer_record(902)], refused=True)


@pytest.mark.parametrize("entry", ["running", "stopped"])
@pytest.mark.parametrize("fault", ["foreign_boot", "empty_boot", "boolean_pgid", "float_pgid"])
def test_process_identity_uses_original_boot_and_strict_group_before_commit(public_fixture, entry, fault):
    f = public_fixture
    f.offer()
    f.bind()
    process = f.process("root", "probe")
    valid = {"pid": 1, "starttime": 100, "pgid": 1, "boot_id": f.root.boot_id}
    bad = dict(valid)
    if fault.endswith("boot"):
        bad["boot_id"] = "" if fault == "empty_boot" else "another-boot"
    else:
        bad["pgid"] = True if fault == "boolean_pgid" else 1.0

    def cleanup(identity):
        return {
            "identity": identity, "leader_terminated": True,
            "leader_reaped": True, "group_terminated": True,
        }

    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict):
        if entry == "running":
            f.store.process_identity(f.root, f.policy, process["process_id"], bad)
        else:
            f.store.process_finished(f.root, f.policy, process["process_id"], bad, cleanup(bad))
    assert database_snapshot(f.journal) == before
    assert f.view()["processes"][process["process_id"]]["state"] == "intent"
    if entry == "running":
        f.store.process_identity(f.root, f.policy, process["process_id"], valid)
        assert f.reopen()["processes"][process["process_id"]]["identity"] == valid
    f.store.process_finished(f.root, f.policy, process["process_id"], valid, cleanup(valid))
    assert f.reopen()["processes"][process["process_id"]]["state"] == "stopped"
    f.store.close(f.root, f.policy)
    snapshot, checksum = f.store.freeze(f.root, f.policy, owners_quiescent=True)
    assert checksum == public.digest(snapshot)


@pytest.mark.parametrize("fault", ["foreign_boot", "empty_boot", "boolean_pgid", "float_pgid"])
def test_coherently_rehashed_process_and_cleanup_cannot_replace_original_boot_or_group(public_fixture, fault):
    f = public_fixture
    f.offer()
    f.bind()
    process = f.process("root", "probe")
    f.stopped(process, pid=1)

    def mutate(value):
        if fault.endswith("boot"):
            value["identity"]["boot_id"] = "" if fault == "empty_boot" else "another-boot"
        else:
            value["identity"]["pgid"] = True if fault == "boolean_pgid" else 1.0
        # Do not rely on identity-versus-cleanup mismatch or a broken checksum.
        value["cleanup"]["identity"] = deepcopy(value["identity"])

    rewrite(f.journal, "public_processes", "process_id", process["process_id"], mutate)
    before = database_snapshot(f.journal)
    with pytest.raises(LifecycleConflict):
        f.reopen()
    assert database_snapshot(f.journal) == before
