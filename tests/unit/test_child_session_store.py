"""Cold-session correlation with real SQLite and explicit runtime facts.

These tests use named canonical-grant fixtures and the production child journal.
They do not run a child, contact Polyphony, establish an inference gate, or prove
Docker termination. The caller-owned gates are exercised by separate tests.
"""

from dataclasses import replace
import json
import sqlite3
import subprocess
import sys

import pytest

from src.worker.child_journal import ChildJournal
from src.worker.child_outcomes import work_outcome
from src.worker.child_sessions import (
    ColdSessionStore,
    INSTRUCTION_PROTOCOL,
    SESSION_PROTOCOL,
    object_value,
    predecessor_snapshot,
)
from src.worker.child_types import canonical, digest, text_hash, verify_grant
from src.worker.lifecycle import LifecycleConflict
from tests.unit.test_child_authority_contract import context, grant, policy, request


def start_request(request_id="session-start", **changes):
    return {
        "schema_version": 1,
        "request_id": request_id,
        "operation": "session_start",
        **request(),
        **changes,
    }


def database_snapshot(journal):
    """Retain rows and exact schema, not volatile SQLite/WAL file bytes."""
    with journal.connection() as db:
        db.execute("BEGIN")
        schema = [
            tuple(row)
            for row in db.execute(
                "SELECT type,name,tbl_name,sql FROM sqlite_master "
                "WHERE name NOT LIKE 'sqlite_%' ORDER BY type,name"
            )
        ]
        tables = [
            row[0]
            for row in db.execute(
                "SELECT name FROM sqlite_master WHERE type='table' "
                "AND name NOT LIKE 'sqlite_%' ORDER BY name"
            )
        ]
        return {
            "version": db.execute("PRAGMA user_version").fetchone()[0],
            "schema": schema,
            "rows": {
                name: [
                    tuple(row)
                    for row in db.execute("SELECT * FROM " + name + " ORDER BY rowid")
                ]
                for name in tables
            },
        }


class SessionFixture:
    """An owned journal with explicit, deterministic local execution witnesses."""

    def __init__(self, path, *, max_children=2):
        self.path = path
        self.root = context()
        self.policy = replace(
            policy(),
            max_children=max_children,
            outcome_protocol="initial-v1",
            session_protocol=SESSION_PROTOCOL,
        )
        self.journal = ChildJournal(path)
        self.journal.prepare(self.root.worker_id, self.root.spec, self.policy)
        self.root = self.journal.bind(self.root)
        self.store = ColdSessionStore(self.journal)

    def close(self):
        self.journal.close()

    def reopen(self):
        self.close()
        self.journal = ChildJournal(self.path)
        self.journal.prepare(self.root.worker_id, self.root.spec, self.policy)
        self.root = self.journal.bind(self.root)
        self.store = ColdSessionStore(self.journal)

    def start(self, request_id="session-start", **changes):
        value = start_request(request_id, **changes)
        return self.store.start(self.root, self.policy, value)

    def bind_child(
        self, session_id, ordinal=1, *, dispatched=True, deadline=110, armed=109
    ):
        row = self.store.get(self.root, self.policy, session_id)["rounds"][ordinal - 1]
        number = len(self.journal.children(self.root.worker_id)) + 1
        child_id = "child_" + f"{number:032x}"
        response = grant(self.root, row["payload"], child_id)
        response["remaining_seconds"] = min(9, row["payload"]["seconds"])
        verify_grant(response, self.root, self.policy, requested=row["payload"])
        self.journal.grant(
            self.root.worker_id,
            row["request_id"],
            response,
            deadline,
            self.root.boot_id,
            self.policy,
        )
        if dispatched:
            self.journal.update(
                self.root.worker_id,
                child_id,
                phase="running",
                exec_id="exec-" + child_id,
                exec_dispatched=1,
                armed_deadline=armed,
            )
        return self.journal.child(self.root.worker_id, child_id)

    def report(self, child, outcome="needs_clarification", summary="Which value?"):
        return self.journal.retain_outcome(
            self.root.worker_id,
            child["child_id"],
            "report-" + child["child_id"],
            outcome,
            summary,
        )

    def followup(self, session_id, request_id="session-followup", **changes):
        first = self.store.get(self.root, self.policy, session_id)["rounds"][0]
        return {
            "schema_version": 1,
            "request_id": request_id,
            "operation": "session_followup",
            "session_id": session_id,
            "predecessor_digest": digest(predecessor_snapshot(first["child"])),
            "instructions": "Use the value selected by the parent.",
            "seconds": 8,
            "max_turns": 1,
            **changes,
        }

    def queued(self):
        session_id = self.start()
        child = self.bind_child(session_id)
        self.report(child)
        followup = self.followup(session_id)
        self.store.queue(self.root, self.policy, followup, now=101)
        return session_id, child, followup

    def returned(self, child, exit_code=0):
        self.journal.update(
            self.root.worker_id,
            child["child_id"],
            phase="exec_returned",
            exit_code=exit_code,
        )

    def finish(self, child):
        """Supply local capture facts; no real canonical receipt is claimed."""
        saved = self.journal.child(self.root.worker_id, child["child_id"])
        report = (
            None
            if saved["outcome_report"] is None
            else json.loads(saved["outcome_report"])
        )
        binding = json.loads(saved["grant_json"])["binding"]
        contents = {
            "patch": "fixture patch\n",
            "log": "fixture configured verification exited 0\n",
            "manifest": canonical({"work_outcome": work_outcome(binding, report)}),
        }
        self.journal.freeze_capture(
            self.root.worker_id,
            child["child_id"],
            contents,
            "exited",
            expected_report=saved["outcome_report"],
        )
        self.journal.update(
            self.root.worker_id,
            child["child_id"],
            phase="completed",
            artifacts=canonical(
                {name: text_hash(value) for name, value in contents.items()}
            ),
        )
        return contents


@pytest.fixture
def stored(tmp_path):
    fixture = SessionFixture(tmp_path / "children")
    try:
        yield fixture
    finally:
        fixture.close()


def test_default_worker_does_not_create_or_adopt_session_state(tmp_path):
    root, approved = context(), policy()
    journal = ChildJournal(tmp_path / "children")
    try:
        journal.prepare(root.worker_id, root.spec, approved)
        journal.bind(root)
        before = database_snapshot(journal)
        assert before["version"] == 0
        assert set(before["rows"]) == {"workers", "intents", "children"}
        with pytest.raises(LifecycleConflict, match="not enabled"):
            ColdSessionStore(journal).start(root, approved, start_request())
        assert database_snapshot(journal) == before
        ordinary = journal.reserve(root.worker_id, "ordinary", request(), approved)
        assert ordinary["status"] == "pending"
        assert set(database_snapshot(journal)["rows"]) == set(before["rows"])
    finally:
        journal.close()


def test_schema_and_new_worker_share_one_sqlite_transaction(tmp_path):
    root = context()
    approved = replace(
        policy(), outcome_protocol="initial-v1", session_protocol=SESSION_PROTOCOL
    )
    journal = ChildJournal(tmp_path / "children")
    try:
        with journal.connection() as db:
            db.execute(
                "CREATE TRIGGER refuse_worker BEFORE INSERT ON workers BEGIN "
                "SELECT RAISE(ABORT,'fixture worker publication failure'); END"
            )
        before = database_snapshot(journal)
        with pytest.raises(sqlite3.IntegrityError, match="fixture worker publication"):
            journal.prepare(root.worker_id, root.spec, approved)
        assert database_snapshot(journal) == before
        with journal.connection() as db:
            db.execute("DROP TRIGGER refuse_worker")
        journal.prepare(root.worker_id, root.spec, approved)
        assert database_snapshot(journal)["version"] == 1
        assert len(database_snapshot(journal)["rows"]["workers"]) == 1
    finally:
        journal.close()


def test_existing_ordinary_worker_cannot_be_upgraded_in_place(tmp_path):
    root = context()
    journal = ChildJournal(tmp_path / "children")
    try:
        journal.prepare(root.worker_id, root.spec, policy())
        journal.bind(root)
        before = database_snapshot(journal)
        approved = replace(
            policy(),
            outcome_protocol="initial-v1",
            session_protocol=SESSION_PROTOCOL,
        )
        with pytest.raises(LifecycleConflict, match="recovery schema"):
            journal.prepare(root.worker_id, root.spec, approved)
        assert database_snapshot(journal) == before
    finally:
        journal.close()


def test_start_replay_and_reopen_preserve_one_original_intent(stored):
    session_id = stored.start()
    saved = stored.store.get(stored.root, stored.policy, session_id)
    first = saved["rounds"][0]
    assert first["state"] == "linked"
    assert first["cutoff"] == stored.root.monotonic_deadline
    assert first["child"] is None
    assert json.loads(first["payload"]["instructions"]) == {
        "schema_version": 1,
        "protocol": INSTRUCTION_PROTOCOL,
        "session_id": session_id,
        "logical_round": 1,
        "initial_instructions": request()["instructions"],
        "followup": None,
        "predecessor": None,
    }
    before = database_snapshot(stored.journal)
    assert stored.start() == session_id
    stored.reopen()
    assert stored.start() == session_id
    assert stored.store.get(stored.root, stored.policy, session_id) == saved
    assert database_snapshot(stored.journal) == before
    projection = stored.store.project(stored.root, stored.policy, session_id)
    assert projection["phase"] == "round1"
    assert projection["reason"] == "awaiting_canonical"
    assert projection["canonical_session"] is False
    assert projection["release_authorized"] is False
    assert projection["all_child_receipts_final"] is False


@pytest.mark.parametrize(
    "changes",
    [
        {"instructions": "A changed instruction."},
        {"seconds": 9},
        {"max_turns": 1},
    ],
)
def test_start_key_cannot_change_its_original_request(stored, changes):
    stored.start()
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="changed"):
        stored.start(**changes)
    assert database_snapshot(stored.journal) == before


@pytest.mark.parametrize(
    "changes",
    [
        {"attempt_id": "attempt_other"},
        {"requirements_revision": 2},
        {"runtime_principal": "another-runtime"},
    ],
)
def test_retained_binding_rejects_a_different_root_identity(stored, changes):
    session_id = stored.start()
    before = database_snapshot(stored.journal)
    changed = replace(stored.root, **changes)
    with pytest.raises(LifecycleConflict, match="changed"):
        stored.store.get(changed, stored.policy, session_id)
    assert database_snapshot(stored.journal) == before


def test_start_and_ordinary_spawn_do_not_share_request_ownership(stored):
    stored.journal.reserve(stored.root.worker_id, "ordinary", request(), stored.policy)
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="another operation"):
        stored.start("ordinary")
    assert database_snapshot(stored.journal) == before
    session_id = stored.start("session-key")
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="another operation"):
        stored.journal.reserve(
            stored.root.worker_id, "session-key", request(), stored.policy
        )
    assert database_snapshot(stored.journal) == before
    assert stored.store.get(stored.root, stored.policy, session_id)["rounds"][0][
        "intent"
    ]["status"] == "pending"


def test_queued_followup_owns_its_key_without_reserving_a_second_child(stored):
    session_id, child, followup = stored.queued()
    session = stored.store.get(stored.root, stored.policy, session_id)
    first, second = session["rounds"]
    assert first["model_closed"] == 1 and first["fence_established"] == 0
    assert second["state"] == "queued"
    assert second["intent"] is None and second["child"] is None
    assert second["cutoff"] == 109
    binding = json.loads(child["grant_json"])["binding"]
    report = json.loads(first["child"]["outcome_report"])
    predecessor = {
        "exec_id": "exec-" + child["child_id"],
        "work_outcome": {
            "schema_version": 1,
            "work_turn_id": digest(
                [
                    "polyphony-child-work-v1",
                    child["child_id"],
                    binding["grant_digest"],
                    1,
                ]
            ),
            "ordinal": 1,
            "child_id": child["child_id"],
            "root_attempt_id": stored.root.attempt_id,
            "parent_attempt_id": stored.root.attempt_id,
            "task_id": stored.root.task_id,
            "requirements_revision": stored.root.requirements_revision,
            "grant_digest": binding["grant_digest"],
            "instructions_digest": binding["instructions_digest"],
            "source": "child_report_via_bound_runtime",
            "report": report,
            "canonical_committed": False,
            "release_authorized": False,
        },
    }
    assert second["predecessor_value"] == predecessor
    assert second["predecessor"] == canonical(predecessor)
    assert second["predecessor_digest"] == digest(predecessor)
    assert json.loads(second["payload"]["instructions"]) == {
        "schema_version": 1,
        "protocol": INSTRUCTION_PROTOCOL,
        "session_id": session_id,
        "logical_round": 2,
        "initial_instructions": request()["instructions"],
        "followup": followup["instructions"],
        "predecessor": predecessor,
    }
    assert len(stored.journal.intents(stored.root.worker_id)) == 1
    assert len(stored.journal.children(stored.root.worker_id)) == 1
    assert stored.store.admission_closed(stored.root, stored.policy, child["child_id"])
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="another operation"):
        stored.journal.reserve(
            stored.root.worker_id, followup["request_id"], request(), stored.policy
        )
    with pytest.raises(LifecycleConflict, match="another operation"):
        stored.start(followup["request_id"])
    assert database_snapshot(stored.journal) == before
    projection = stored.store.project(stored.root, stored.policy, session_id)
    assert projection["phase"] == "followup_queued"
    assert projection["reason"] == "awaiting_exec_return"
    assert projection["predecessor_digest"] == followup["predecessor_digest"]
    assert projection["model_fence"] == "requested"
    assert projection["rounds"][0]["initial_outcome"]["canonical_committed"] is False
    assert projection["all_child_receipts_final"] is False


@pytest.mark.parametrize("changed_field", ["request_id", "instructions", "seconds"])
def test_queued_followup_exact_replay_survives_reopen_but_cannot_change(
    stored, changed_field
):
    session_id, _, followup = stored.queued()
    before = database_snapshot(stored.journal)
    stored.store.queue(stored.root, stored.policy, followup, now=102)
    stored.reopen()
    stored.store.queue(stored.root, stored.policy, followup, now=1001)
    assert database_snapshot(stored.journal) == before
    changed = dict(followup)
    changed[changed_field] = {
        "request_id": "another-followup",
        "instructions": "Changed follow-up.",
        "seconds": 7,
    }[changed_field]
    with pytest.raises(LifecycleConflict, match="different original request"):
        stored.store.queue(stored.root, stored.policy, changed, now=1002)
    assert database_snapshot(stored.journal) == before
    assert stored.store.project(stored.root, stored.policy, session_id)[
        "followup_request_id"
    ] == followup["request_id"]


@pytest.mark.parametrize(
    "changes",
    [
        {"predecessor_digest": "0" * 64},
        {"seconds": 11},
        {"max_turns": 3},
    ],
)
def test_followup_cannot_expand_the_first_request_or_replace_its_predecessor(
    stored, changes
):
    session_id = stored.start()
    child = stored.bind_child(session_id)
    stored.report(child)
    request_value = stored.followup(session_id, **changes)
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="original allowance"):
        stored.store.queue(stored.root, stored.policy, request_value, now=101)
    assert database_snapshot(stored.journal) == before


def test_promotion_requires_return_and_links_only_one_new_ordinary_intent(stored):
    session_id, child, followup = stored.queued()
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="eligible original predecessor"):
        stored.store.promote(stored.root, stored.policy, session_id, now=102)
    assert database_snapshot(stored.journal) == before
    stored.returned(child)
    assert stored.store.project(stored.root, stored.policy, session_id)[
        "reason"
    ] == "awaiting_model_fence"
    stored.store.promote(stored.root, stored.policy, session_id, now=102)
    session = stored.store.get(stored.root, stored.policy, session_id)
    first, second = session["rounds"]
    assert first["fence_established"] == 1
    assert second["state"] == "linked"
    assert second["intent"]["request_id"] == followup["request_id"]
    assert second["intent"]["payload"] == second["grant_payload"]
    assert second["intent"]["status"] == "pending"
    assert second["child"] is None
    assert len(stored.journal.children(stored.root.worker_id)) == 1
    assert len(stored.journal.intents(stored.root.worker_id)) == 2
    before = database_snapshot(stored.journal)
    stored.reopen()
    stored.store.promote(stored.root, stored.policy, session_id, now=103)
    assert database_snapshot(stored.journal) == before
    second_child = stored.bind_child(session_id, 2, dispatched=False)
    assert second_child["child_id"] != child["child_id"]
    assert second_child["uid"] != child["uid"]
    assert second_child["ordinal"] == child["ordinal"] + 1
    assert stored.journal.child(stored.root.worker_id, child["child_id"])[
        "grant_json"
    ] == child["grant_json"]
    projection = stored.store.project(stored.root, stored.policy, session_id)
    assert projection["phase"] == "round2"
    assert projection["model_fence"] == "established"
    assert projection["all_child_receipts_final"] is False


def test_pending_ordinary_spawn_can_win_the_remaining_lifetime_slot(stored):
    session_id, child, followup = stored.queued()
    other = stored.journal.reserve(
        stored.root.worker_id, "ordinary-competitor", request(), stored.policy
    )
    assert other["status"] == "pending"
    stored.returned(child)
    stored.store.promote(stored.root, stored.policy, session_id, now=102)
    session = stored.store.get(stored.root, stored.policy, session_id)
    assert session["closure"] == "refused"
    assert session["close_reason"] == "lifetime_limit"
    assert session["rounds"][1]["state"] == "refused"
    assert session["rounds"][1]["intent"] is None
    assert len(stored.journal.children(stored.root.worker_id)) == 1
    assert [x["request_id"] for x in stored.journal.intents(stored.root.worker_id)] == [
        "session-start",
        "ordinary-competitor",
    ]
    stored.journal.reject(stored.root.worker_id, other["request_id"])
    before = database_snapshot(stored.journal)
    stored.store.promote(stored.root, stored.policy, session_id, now=103)
    stored.store.queue(stored.root, stored.policy, followup, now=103)
    assert database_snapshot(stored.journal) == before
    assert stored.store.project(stored.root, stored.policy, session_id)[
        "logical_outcome"
    ] == "refused"


def test_rejected_delivery_does_not_remove_the_bounded_session_history(stored):
    original_ids = []
    for index in range(stored.policy.max_children):
        request_id = "start-" + str(index)
        session_id = stored.start(request_id)
        original_ids.append(session_id)
        stored.journal.reject(stored.root.worker_id, request_id)
        stored.store.observe(stored.root, stored.policy, now=101, boot_id="boot-one")
    assert stored.journal.children(stored.root.worker_id) == []
    assert all(
        x["status"] == "rejected"
        for x in stored.journal.intents(stored.root.worker_id)
    )
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="lifetime record bound"):
        stored.start("one-too-many")
    assert database_snapshot(stored.journal) == before
    stored.reopen()
    assert [stored.start("start-" + str(i)) for i in range(2)] == original_ids
    assert database_snapshot(stored.journal) == before


def test_original_armed_cutoff_limits_successor_delivery_and_launch(stored):
    session_id, first_child, followup = stored.queued()
    stored.returned(first_child)
    stored.store.promote(stored.root, stored.policy, session_id, now=102)
    second_child = stored.bind_child(session_id, 2, dispatched=False, deadline=115)
    original = stored.store.get(stored.root, stored.policy, session_id)["rounds"][1]
    assert original["cutoff"] == 109
    assert original["request"]["seconds"] == 8
    assert stored.store.launch_cutoff(
        stored.root, stored.policy, second_child["child_id"], cutoff=115, now=103
    ) == 109
    assert stored.store.delivery_expired(
        stored.root, stored.policy, followup["request_id"], now=108, boot_id="boot-one"
    ) is False
    assert stored.store.delivery_expired(
        stored.root, stored.policy, followup["request_id"], now=109, boot_id="boot-one"
    ) is True
    before = database_snapshot(stored.journal)
    stored.reopen()
    assert stored.store.get(stored.root, stored.policy, session_id)["rounds"][1][
        "cutoff"
    ] == 109
    with pytest.raises(LifecycleConflict, match="original interval expired"):
        stored.store.launch_cutoff(
            stored.root, stored.policy, second_child["child_id"], cutoff=1000, now=109
        )
    assert database_snapshot(stored.journal) == before
    assert stored.store.delivery_expired(
        stored.root, stored.policy, followup["request_id"], now=103, boot_id="boot-new"
    ) is True


def test_later_permission_can_only_shorten_the_successor_cutoff(stored):
    session_id, first_child, followup = stored.queued()
    stored.returned(first_child)
    stored.store.promote(stored.root, stored.policy, session_id, now=102)
    second_child = stored.bind_child(session_id, 2, dispatched=False)
    stored.journal.update(
        stored.root.worker_id, first_child["child_id"], armed_deadline=106
    )
    stored.root = stored.journal.bind(
        replace(stored.root, monotonic_deadline=105)
    )
    assert stored.store.launch_cutoff(
        stored.root, stored.policy, second_child["child_id"], cutoff=110, now=104
    ) == 105
    assert stored.store.get(stored.root, stored.policy, session_id)["rounds"][1][
        "cutoff"
    ] == 109
    assert stored.store.delivery_expired(
        stored.root, stored.policy, followup["request_id"], now=105, boot_id="boot-one"
    ) is True
    with pytest.raises(LifecycleConflict, match="cannot be extended"):
        stored.journal.update(
            stored.root.worker_id, first_child["child_id"], armed_deadline=107
        )
    stored.root = stored.journal.bind(
        replace(stored.root, monotonic_deadline=2000)
    )
    assert stored.root.monotonic_deadline == 105


def test_exec_return_without_report_is_closed_before_a_late_report(stored):
    session_id = stored.start()
    child = stored.bind_child(session_id)
    stored.returned(child)
    # No store.observe call: closure must share the exec-return write transaction.
    with stored.journal.connection() as db:
        row = db.execute(
            "SELECT closure,close_reason FROM cold_sessions WHERE session_id=?",
            (session_id,),
        ).fetchone()
        assert tuple(row) == ("unreported", None)
    report = stored.report(child)
    assert stored.report(child) == report
    followup = stored.followup(session_id)
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="logically closed"):
        stored.store.queue(stored.root, stored.policy, followup, now=101)
    assert database_snapshot(stored.journal) == before
    stored.reopen()
    projection = stored.store.project(stored.root, stored.policy, session_id)
    assert projection["logical_outcome"] == "unreported"
    assert projection["all_child_receipts_final"] is False
    assert projection["rounds"][0]["initial_outcome"]["report"] == report
    stored.finish(child)
    stored.store.validate_final(stored.root, stored.policy)
    projection = stored.store.project(stored.root, stored.policy, session_id)
    assert projection["logical_outcome"] == "unreported"
    assert projection["all_child_receipts_final"] is True
    assert projection["rounds"][0]["initial_outcome"]["report"] == report
    assert projection["release_authorized"] is False


@pytest.mark.parametrize(
    "event,outcome,reason",
    [
        ("completed", "completed", None),
        ("declined", "declined", None),
        ("failed", "failed", "runtime_failed"),
        ("uncertain", None, "launch_uncertain"),
        ("model_unresolved", None, "model_unresolved"),
        ("cancelled", "cancelled", "admission_closed"),
        ("expired", "expired", "expired"),
        ("reboot", "expired", "expired"),
    ],
)
def test_observed_closure_is_sticky_and_does_not_finalize_runtime(
    stored, event, outcome, reason
):
    session_id = stored.start()
    child = stored.bind_child(session_id)
    now, boot = 101, "boot-one"
    if event in {"completed", "declined"}:
        stored.report(child, event, "A bounded semantic result.")
    elif event == "failed":
        stored.returned(child, exit_code=7)
    elif event == "uncertain":
        stored.journal.update(
            stored.root.worker_id, child["child_id"], phase="uncertain"
        )
    elif event == "model_unresolved":
        stored.store.block_uncertain(stored.root, stored.policy, session_id)
    elif event == "cancelled":
        stored.journal.close_admission(stored.root.worker_id, "fixture root stopped")
    elif event == "expired":
        now = 109
    elif event == "reboot":
        boot = "boot-two"
    stored.store.observe(stored.root, stored.policy, now=now, boot_id=boot)
    projection = stored.store.project(stored.root, stored.policy, session_id)
    assert projection["logical_outcome"] == outcome
    assert projection["reason"] == reason
    assert projection["phase"] == (
        "uncertain" if event in {"uncertain", "model_unresolved"} else "closed"
    )
    assert projection["all_child_receipts_final"] is False
    assert projection["release_authorized"] is False
    before = database_snapshot(stored.journal)
    stored.reopen()
    stored.store.observe(stored.root, stored.policy, now=9999, boot_id="later-boot")
    assert database_snapshot(stored.journal) == before
    with pytest.raises(LifecycleConflict, match="final receipts"):
        stored.store.validate_final(stored.root, stored.policy)


def test_round_two_clarification_is_terminal_and_both_captures_remain_required(stored):
    session_id, first_child, followup = stored.queued()
    stored.returned(first_child)
    stored.store.promote(stored.root, stored.policy, session_id, now=102)
    second_child = stored.bind_child(session_id, 2)
    stored.report(second_child, summary="Still ambiguous.")
    stored.returned(second_child)
    projection = stored.store.project(stored.root, stored.policy, session_id)
    assert projection["logical_outcome"] == "needs_clarification"
    assert projection["reason"] == "round_limit"
    assert [row["logical_round"] for row in projection["rounds"]] == [1, 2]
    before = database_snapshot(stored.journal)
    with pytest.raises(LifecycleConflict, match="different original request"):
        stored.store.queue(
            stored.root,
            stored.policy,
            followup | {"request_id": "third-round"},
            now=103,
        )
    assert database_snapshot(stored.journal) == before
    stored.finish(first_child)
    assert stored.store.project(stored.root, stored.policy, session_id)[
        "all_child_receipts_final"
    ] is False
    with pytest.raises(LifecycleConflict, match="final receipts"):
        stored.store.validate_final(stored.root, stored.policy)
    stored.finish(second_child)
    stored.store.validate_final(stored.root, stored.policy)
    final = stored.store.project(stored.root, stored.policy, session_id)
    assert final["all_child_receipts_final"] is True
    assert final["canonical_session"] is False
    assert final["release_authorized"] is False
    assert all(
        row["evidence"] == "canonical_child_final"
        and row["initial_outcome"]["canonical_committed"] is True
        and row["initial_outcome"]["release_authorized"] is False
        for row in final["rounds"]
    )
    before = database_snapshot(stored.journal)
    stored.reopen()
    stored.store.queue(stored.root, stored.policy, followup, now=2000)
    assert stored.store.project(stored.root, stored.policy, session_id) == final
    assert database_snapshot(stored.journal) == before


def ordinary_root(root, worker_id="e" * 32):
    return replace(
        root,
        worker_id=worker_id,
        spec=replace(root.spec, profile="ordinary-profile"),
        attempt_id="attempt_ordinary_" + worker_id,
        task_id="task_ordinary",
    )


def test_healthy_global_schema_preserves_ordinary_instruction_data(stored):
    root, approved = ordinary_root(stored.root), policy()
    journal = stored.journal
    journal.prepare(root.worker_id, root.spec, approved)
    journal.bind(root)
    payload = request() | {
        "instructions": canonical(
            {"protocol": INSTRUCTION_PROTOCOL, "ordinary_data": "not a session"}
        )
    }
    journal.reserve(root.worker_id, "ordinary-json", payload, approved)
    response = grant(root, payload, "child_" + "f" * 32)
    verify_grant(response, root, approved, requested=payload)
    journal.grant(
        root.worker_id, "ordinary-json", response, 110, root.boot_id, approved
    )
    child_id = response["binding"]["child_id"]
    journal.update(
        root.worker_id,
        child_id,
        phase="running",
        exec_id="exec-ordinary",
        exec_dispatched=1,
        armed_deadline=109,
    )
    journal.update(root.worker_id, child_id, phase="exec_returned", exit_code=0)
    contents = {
        "patch": "ordinary fixture patch",
        "log": "ordinary fixture log",
        "manifest": canonical({"ordinary_fixture": True}),
    }
    journal.freeze_capture(
        root.worker_id, child_id, contents, "exited", expected_report=None
    )
    journal.update(
        root.worker_id,
        child_id,
        phase="completed",
        artifacts=canonical({key: text_hash(value) for key, value in contents.items()}),
    )
    assert journal.child(root.worker_id, child_id)["phase"] == "completed"
    state = database_snapshot(journal)
    assert state["version"] == 1
    assert state["rows"]["cold_sessions"] == []
    assert state["rows"]["cold_rounds"] == []
    assert stored.store.all(stored.root, stored.policy) == []
    before = database_snapshot(journal)
    with pytest.raises(LifecycleConflict, match="requires its original session"):
        journal.reserve(
            stored.root.worker_id, "cold-raw-envelope", payload, stored.policy
        )
    assert database_snapshot(journal) == before


@pytest.mark.parametrize("has_session", [False, True])
@pytest.mark.parametrize("damage", ["one_table", "both_tables", "columns", "version"])
def test_corrupt_global_schema_blocks_new_and_retained_workers_without_adoption(
    stored, has_session, damage
):
    if has_session:
        stored.start()
    root, approved = ordinary_root(stored.root), policy()
    journal = stored.journal
    journal.prepare(root.worker_id, root.spec, approved)
    journal.bind(root)
    journal.reserve(root.worker_id, "original-pending", request(), approved)
    response = grant(root, request(), "child_" + "f" * 32)
    with journal.connection() as db:
        if damage in {"one_table", "both_tables"}:
            db.execute("DROP TABLE cold_rounds")
            if damage == "both_tables":
                db.execute("DROP TABLE cold_sessions")
        elif damage == "columns":
            db.execute("ALTER TABLE cold_rounds ADD COLUMN unexpected TEXT")
        else:
            db.execute("PRAGMA user_version=2")
    before = database_snapshot(journal)
    if damage in {"one_table", "both_tables"}:
        assert before["version"] == 1
    new_root = ordinary_root(stored.root, worker_id="f" * 32)
    for operation in (
        lambda: journal.prepare(stored.root.worker_id, stored.root.spec, stored.policy),
        lambda: journal.prepare(new_root.worker_id, new_root.spec, approved),
        lambda: journal.prepare(new_root.worker_id, new_root.spec, stored.policy),
        lambda: journal.reserve(root.worker_id, "new-pending", request(), approved),
        lambda: journal.grant(
            root.worker_id,
            "original-pending",
            response,
            110,
            root.boot_id,
            approved,
        ),
    ):
        with pytest.raises(LifecycleConflict, match="schema"):
            operation()
        assert database_snapshot(journal) == before
    journal.close()
    stored.journal = ChildJournal(stored.path)
    stored.store = ColdSessionStore(stored.journal)
    with pytest.raises(LifecycleConflict, match="schema"):
        stored.journal.prepare(stored.root.worker_id, stored.root.spec, stored.policy)
    assert database_snapshot(stored.journal) == before


def test_schema_creation_crash_leaves_no_opted_in_worker_or_partial_tables(tmp_path):
    path = tmp_path / "children"
    original = context()
    journal = ChildJournal(path)
    journal.prepare(original.worker_id, original.spec, policy())
    journal.bind(original)
    before = database_snapshot(journal)
    journal.close()
    script = """
import os
import sys
from dataclasses import replace
from src.worker import child_journal as module
from src.worker.child_types import ChildPolicy
from tests.unit.test_child_authority_contract import context
original = module.install_session_schema
def interrupted(db, *, require_existing):
    original(db, require_existing=require_existing)
    assert db.in_transaction
    os._exit(23)
module.install_session_schema = interrupted
root = replace(context(), worker_id="e" * 32)
policy = ChildPolicy(
    2, 20, 3, ("python",),
    outcome_protocol="initial-v1",
    session_protocol="cold-clarification-v1",
)
journal = module.ChildJournal(sys.argv[1])
journal.prepare(root.worker_id, root.spec, policy)
raise AssertionError("fixture did not interrupt the worker transaction")
"""
    result = subprocess.run(
        [sys.executable, "-c", script, str(path)],
        check=False,
        capture_output=True,
        text=True,
        timeout=10,
    )
    assert result.returncode == 23, (result.stdout, result.stderr)
    reopened = ChildJournal(path)
    try:
        assert database_snapshot(reopened) == before
        second = replace(original, worker_id="e" * 32)
        approved = replace(
            policy(),
            outcome_protocol="initial-v1",
            session_protocol=SESSION_PROTOCOL,
        )
        reopened.prepare(second.worker_id, second.spec, approved)
        reopened.bind(second)
        assert database_snapshot(reopened)["version"] == 1
        assert len(database_snapshot(reopened)["rows"]["workers"]) == 2
    finally:
        reopened.close()


def test_grant_replay_preserves_original_uid_exec_and_deadline(stored):
    session_id = stored.start()
    child = stored.bind_child(session_id)
    first = stored.store.get(stored.root, stored.policy, session_id)["rounds"][0]
    original = json.loads(child["grant_json"])
    denied = original | {
        "launch_allowed": False,
        "remaining_seconds": 0,
        "reason": "revoked",
    }
    before = database_snapshot(stored.journal)
    stored.reopen()
    replay = stored.journal.grant(
        stored.root.worker_id,
        first["request_id"],
        denied,
        2000,
        "later-boot",
        stored.policy,
    )
    assert replay == child
    assert database_snapshot(stored.journal) == before
    changed = grant(stored.root, first["payload"], "child_" + "f" * 32)
    with pytest.raises(LifecycleConflict, match="delivery intent"):
        stored.journal.grant(
            stored.root.worker_id,
            first["request_id"],
            changed,
            2000,
            "later-boot",
            stored.policy,
        )
    assert database_snapshot(stored.journal) == before


def test_combined_escaped_instruction_bound_refuses_before_model_closure(stored):
    session_id = stored.start(instructions="é" * 4000)
    child = stored.bind_child(session_id)
    stored.report(child, summary="é" * 1000)
    oversized = stored.followup(session_id, instructions="é" * 8192)
    assert len(oversized["instructions"].encode("utf-8")) == 16384
    before = database_snapshot(stored.journal)
    with pytest.raises(ValueError, match="combined session instruction"):
        stored.store.queue(stored.root, stored.policy, oversized, now=101)
    assert database_snapshot(stored.journal) == before
    assert stored.store.admission_closed(
        stored.root, stored.policy, child["child_id"]
    ) is False
    accepted = stored.followup(session_id, instructions="é" * 200)
    stored.store.queue(stored.root, stored.policy, accepted, now=101)
    saved = stored.store.get(stored.root, stored.policy, session_id)["rounds"][1]
    assert len(saved["payload"]["instructions"].encode("utf-8")) <= 65536
    assert json.loads(saved["payload"]["instructions"])["followup"] == "é" * 200


@pytest.mark.parametrize(
    "seconds",
    [True, float("inf"), 10**10000],
    ids=["boolean", "infinite", "huge-integer"],
)
def test_invalid_duration_cannot_publish_a_partial_session(stored, seconds):
    before = database_snapshot(stored.journal)
    with pytest.raises(ValueError, match="bounded session duration"):
        stored.start(seconds=seconds)
    assert database_snapshot(stored.journal) == before


@pytest.mark.parametrize(
    "damage",
    [
        "session_removed",
        "round_removed",
        "intent_removed",
        "child_removed",
        "binding_identity",
        "request_payload",
        "instruction_payload",
        "predecessor_hash",
        "fence_without_model_closure",
    ],
)
def test_reopen_rejects_lost_or_changed_correlation_without_rebuilding(stored, damage):
    session_id, child, _ = stored.queued()
    with stored.journal.connection() as db:
        if damage == "session_removed":
            db.execute("DELETE FROM cold_sessions WHERE session_id=?", (session_id,))
        elif damage == "round_removed":
            db.execute("DELETE FROM cold_rounds WHERE session_id=?", (session_id,))
        elif damage == "intent_removed":
            db.execute("DELETE FROM intents WHERE request_id='session-start'")
        elif damage == "child_removed":
            db.execute("DELETE FROM children WHERE child_id=?", (child["child_id"],))
        elif damage == "binding_identity":
            binding = json.loads(
                db.execute(
                    "SELECT binding FROM cold_sessions WHERE session_id=?",
                    (session_id,),
                ).fetchone()[0]
            )
            binding["task_id"] = "another-task"
            db.execute(
                "UPDATE cold_sessions SET binding=?,binding_digest=? "
                "WHERE session_id=?",
                (canonical(binding), digest(binding), session_id),
            )
        elif damage == "request_payload":
            changed = start_request(instructions="Another original request.")
            db.execute(
                "UPDATE cold_rounds SET request_json=?,request_digest=? "
                "WHERE session_id=? AND ordinal=1",
                (canonical(changed), digest(changed), session_id),
            )
        elif damage == "instruction_payload":
            payload = json.loads(
                db.execute(
                    "SELECT grant_payload FROM cold_rounds "
                    "WHERE session_id=? AND ordinal=2",
                    (session_id,),
                ).fetchone()[0]
            )
            payload["instructions"] = "A substituted successor instruction."
            db.execute(
                "UPDATE cold_rounds SET grant_payload=?,instructions_digest=? "
                "WHERE session_id=? AND ordinal=2",
                (canonical(payload), text_hash(payload["instructions"]), session_id),
            )
        elif damage == "predecessor_hash":
            db.execute(
                "UPDATE cold_rounds SET predecessor_digest=? "
                "WHERE session_id=? AND ordinal=2",
                ("0" * 64, session_id),
            )
        else:
            db.execute(
                "UPDATE cold_rounds SET model_closed=0,fence_established=1 "
                "WHERE session_id=? AND ordinal=1",
                (session_id,),
            )
    before = database_snapshot(stored.journal)
    stored.reopen()
    for operation in (
        lambda: stored.store.get(stored.root, stored.policy, session_id),
        lambda: stored.store.start(stored.root, stored.policy, start_request("fresh")),
        lambda: stored.store.validate_final(stored.root, stored.policy),
    ):
        with pytest.raises(LifecycleConflict):
            operation()
        assert database_snapshot(stored.journal) == before


def test_final_capture_cannot_replace_the_original_outcome_even_with_fresh_hashes(
    stored,
):
    session_id = stored.start()
    child = stored.bind_child(session_id)
    stored.report(child, outcome="completed", summary="Original result.")
    stored.returned(child)
    stored.finish(child)
    stored.store.validate_final(stored.root, stored.policy)
    with stored.journal.connection() as db:
        row = db.execute(
            "SELECT capture,artifacts FROM children WHERE child_id=?",
            (child["child_id"],),
        ).fetchone()
        capture, artifacts = json.loads(row[0]), json.loads(row[1])
        manifest = json.loads(capture["contents"]["manifest"])
        manifest["work_outcome"]["report"]["summary"] = "Substituted final report."
        capture["contents"]["manifest"] = canonical(manifest)
        artifacts["manifest"] = text_hash(capture["contents"]["manifest"])
        db.execute(
            "UPDATE children SET capture=?,artifacts=? WHERE child_id=?",
            (canonical(capture), canonical(artifacts), child["child_id"]),
        )
    before = database_snapshot(stored.journal)
    stored.reopen()
    with pytest.raises(LifecycleConflict, match="original outcome"):
        stored.store.project(stored.root, stored.policy, session_id)
    with pytest.raises(LifecycleConflict, match="original outcome"):
        stored.store.validate_final(stored.root, stored.policy)
    assert database_snapshot(stored.journal) == before


@pytest.mark.parametrize("case", ["lone-surrogate", "nested-json", "overflow-number"])
def test_retained_record_decoder_normalizes_distinct_bounded_failures(case):
    if case == "lone-surrogate":
        value = '{"value":"\ud800"}'
        with pytest.raises(UnicodeEncodeError):
            value.encode("utf-8")
    elif case == "nested-json":
        # CPython v3.12.16 Include/cpython/pystate.h sets C_RECURSION_LIMIT
        # to at most 10000; _json.c consumes it for each nested array.
        depth = 10001
        value = '{"value":' + "[" * depth + "0" + "]" * depth + "}"
        assert len(value.encode("utf-8")) < 262144
        with pytest.raises(RecursionError):
            json.loads(value)
    else:
        value = '{"value":1e309}'
        assert json.loads(value)["value"] == float("inf")
    with pytest.raises(LifecycleConflict, match="^cold-session record is invalid$"):
        object_value(value)
    assert object_value('{"value":1}') == {"value": 1}
