"""Cold guest controls over real Unix framing and explicit stored-state fixtures.

The server responses are projections from the production store. Runtime/capture
facts in SessionFixture are named fixtures, not Docker or canonical receipts.
"""

from copy import deepcopy
from dataclasses import asdict, replace
from types import SimpleNamespace

import pytest

from src.agent.child_tools import (
    CHILD_TOOL_DEFINITIONS, SESSION_TOOL_DEFINITIONS, ControlClient, ControlError,
    RootTools,
)
from src.worker.child_types import PROTOCOL, canonical, digest
from tests.unit.test_child_authority_contract import policy
from tests.unit.test_child_session_store import SessionFixture, start_request
from tests.unit.test_child_tools import reply, server


@pytest.fixture
def session(tmp_path):
    value = SessionFixture(tmp_path / "children")
    try:
        yield value
    finally:
        value.close()


def two_round_projection(fixture):
    session_id, first, followup = fixture.queued()
    fixture.returned(first)
    fixture.store.promote(fixture.root, fixture.policy, session_id, now=102)
    second = fixture.bind_child(session_id, 2)
    fixture.report(second, "completed", "Second instruction completed")
    fixture.returned(second)
    fixture.store.observe(fixture.root, fixture.policy, 103, fixture.root.boot_id)
    return session_id, first, second, fixture.store.project(
        fixture.root, fixture.policy, session_id
    )


def test_omitted_fingerprint_and_existing_tools_are_unchanged():
    ordinary = policy()
    initial = replace(ordinary, outcome_protocol="initial-v1")
    for value in (ordinary, initial):
        old = asdict(value)
        old.pop("session_protocol")
        assert old.pop("public_discussion") is None
        if value.outcome_protocol is None:
            old.pop("outcome_protocol")
        assert value.fingerprint == digest(
            {"protocol": PROTOCOL, "watchdog_protocol": 1, **old}
        )
    cold = replace(initial, session_protocol="cold-clarification-v1")
    assert cold.fingerprint != initial.fingerprint
    assert canonical(cold.canonical_policy) == canonical(initial.canonical_policy)
    assert {tool["function"]["name"] for tool in CHILD_TOOL_DEFINITIONS} == {
        "spawn_child", "child_status", "child_result", "cancel_child", "close_children",
    }
    assert {tool["function"]["name"] for tool in SESSION_TOOL_DEFINITIONS} == {
        "start_child_session", "continue_child_session", "child_session_status",
    }
    assert all(
        "request_id" not in tool["function"]["parameters"]["properties"]
        and tool["function"]["parameters"]["additionalProperties"] is False
        for tool in SESSION_TOOL_DEFINITIONS
    )


@pytest.mark.parametrize("changes", [
    {"session_protocol": True},
    {"session_protocol": 1},
    {"session_protocol": "warm-v1"},
    {"session_protocol": "cold-clarification-v1", "outcome_protocol": None},
    {"session_protocol": "cold-clarification-v1", "max_children": 1},
    {"session_protocol": "cold-clarification-v1", "command": ("sh",)},
])
def test_policy_rejects_unsupported_session_semantics(changes):
    with pytest.raises(ValueError):
        replace(policy(), **({"outcome_protocol": "initial-v1"} | changes))


@pytest.mark.parametrize("changes", [
    {"seconds": True}, {"seconds": float("inf")}, {"seconds": 10 ** 1000},
    {"max_turns": True}, {"instructions": "x" * 16385},
    {"instructions": "\ud800"}, {"request_id": "model-selected"},
    {"actor": "sibling"}, {"command": ["sh"]},
])
def test_invalid_guest_mutation_never_connects(changes):
    ordinary = SimpleNamespace(call=lambda *_: "ordinary")
    fields = {name: value for name, value in start_request().items()
              if name not in {"schema_version", "operation", "request_id"}}
    with server(lambda request, _: reply(request)) as fixture:
        tools = RootTools(ordinary, ControlClient(fixture.path))
        assert tools.call("start_child_session", fields | changes).startswith("Tool error:")
        assert not fixture.requests


@pytest.mark.parametrize("operation", ["session_start", "session_followup"])
def test_uncertain_mutation_is_not_repeated_or_returned_to_model(operation):
    fields = (
        {"instructions": "Ask explicitly.", "seconds": 10, "max_turns": 2,
         "capabilities": ["python"]}
        if operation == "session_start"
        else {"session_id": "session_" + "a" * 64, "predecessor_digest": "b" * 64,
              "instructions": "The explicit answer.", "seconds": 8, "max_turns": 1}
    )
    tool = "start_child_session" if operation == "session_start" else "continue_child_session"
    with server(lambda *_: None) as fixture:
        tools = RootTools(SimpleNamespace(call=lambda *_: "ordinary"), ControlClient(fixture.path))
        with pytest.raises(ControlError, match="uncertain"):
            tools.call(tool, fields)
        assert len(fixture.requests) == 1
        assert fixture.requests[0]["operation"] == operation


def changed_projection(original, fault):
    value = deepcopy(original)
    first, second = value["rounds"]
    if fault == "duplicate_child":
        replacement = deepcopy(first)
        replacement.update(logical_round=2, request_id=second["request_id"])
        value["rounds"][1] = replacement
    elif fault == "unestablished_bound_successor":
        value["model_fence"] = "requested"
    elif fault == "provisional_claimed_final":
        value["all_child_receipts_final"] = True
    elif fault == "foreign_task":
        second["initial_outcome"]["task_id"] = "foreign-task"
    elif fault == "foreign_revision":
        second["initial_outcome"]["requirements_revision"] += 1
    elif fault == "boolean_ordinal":
        second["initial_outcome"]["ordinal"] = True
    elif fault == "third_round":
        value["rounds"].append(deepcopy(second))
    elif fault == "changed_predecessor":
        value["predecessor_digest"] = "0" * 64
    elif fault == "canonical_session":
        value["canonical_session"] = True
    else:
        raise AssertionError(fault)
    return value


@pytest.mark.parametrize("fault", [
    "duplicate_child", "unestablished_bound_successor", "provisional_claimed_final",
    "foreign_task", "foreign_revision", "boolean_ordinal", "third_round",
    "changed_predecessor", "canonical_session",
])
def test_real_unix_reply_rejects_impossible_cross_field_states(session, fault):
    session_id, _, _, original = two_round_projection(session)
    assert original["phase"] == "closed" and not original["all_child_receipts_final"]
    malformed = changed_projection(original, fault)
    with server(lambda request, _: reply(request, **malformed)) as fixture:
        with pytest.raises(ControlError, match="invalid_response"):
            ControlClient(fixture.path).request("session_status", session_id=session_id)
        assert len(fixture.requests) == 1


def test_provisional_to_final_and_unallocated_refused_projection_are_valid(session):
    session_id, first, second, provisional = two_round_projection(session)
    current = [provisional]
    with server(lambda request, _: reply(request, **current[0])) as fixture:
        client = ControlClient(fixture.path)
        observed = client.request("session_status", session_id=session_id)
        assert {row["initial_outcome"]["ordinal"] for row in observed["rounds"]} == {1}
        session.finish(first)
        session.finish(second)
        current[0] = session.store.project(session.root, session.policy, session_id)
        final = client.request("session_status", session_id=session_id)
        assert final["all_child_receipts_final"] is True
        assert all(row["evidence"] == "canonical_child_final" for row in final["rounds"])
        assert not final["canonical_session"] and not final["release_authorized"]
    # A conclusive unallocated queue is valid, unlike a provisional allocated
    # child falsely labelled final. Use a separate original session fixture.
    second_path = session.path.parent / "capacity"
    other = SessionFixture(second_path)
    try:
        sid, first, _ = other.queued()
        raw = {"instructions": "Ordinary work", "seconds": 8, "max_turns": 1,
               "capabilities": ["python"]}
        other.journal.reserve(other.root.worker_id, "ordinary-last-slot", raw, other.policy)
        other.returned(first)
        other.store.promote(other.root, other.policy, sid, now=102)
        other.finish(first)
        value = other.store.project(other.root, other.policy, sid)
        assert value["reason"] == "lifetime_limit"
        assert value["rounds"][1]["child_id"] is None
        assert value["all_child_receipts_final"] is True
        with server(lambda request, _: reply(request, **value)) as fixture:
            assert ControlClient(fixture.path).request(
                "session_status", session_id=sid
            )["logical_outcome"] == "refused"
    finally:
        other.close()


def test_late_actual_report_does_not_reopen_guest_logical_closure(session):
    sid = session.start()
    child = session.bind_child(sid)
    session.returned(child)
    current = [session.store.project(session.root, session.policy, sid)]
    assert current[0]["logical_outcome"] == "unreported"
    with server(lambda request, _: reply(request, **current[0])) as fixture:
        client = ControlClient(fixture.path)
        before = client.request("session_status", session_id=sid)
        assert before["rounds"][0]["initial_outcome"]["source"] == "unreported"
        report = session.report(child)
        current[0] = session.store.project(session.root, session.policy, sid)
        late = client.request("session_status", session_id=sid)
        assert late["logical_outcome"] == "unreported"
        assert late["rounds"][0]["initial_outcome"]["report"] == report
        session.finish(child)
        current[0] = session.store.project(session.root, session.policy, sid)
        final = client.request("session_status", session_id=sid)
        assert final["all_child_receipts_final"]
        assert final["logical_outcome"] == "unreported"
        assert final["rounds"][0]["initial_outcome"]["report"] == report


@pytest.mark.parametrize("fault", ["task_and_revision", "second_report", "final_artifact"])
def test_coherent_later_response_cannot_rewrite_observed_identity(session, fault):
    if fault == "task_and_revision":
        sid = session.start()
        first = session.bind_child(sid)
        session.report(first, "completed", "One instruction completed")
        session.returned(first)
        original = session.store.project(session.root, session.policy, sid)
        assert original["predecessor_digest"] is None
    else:
        sid, first, second, original = two_round_projection(session)
    if fault == "final_artifact":
        session.finish(first)
        session.finish(second)
        original = session.store.project(session.root, session.policy, sid)
    changed = deepcopy(original)
    if fault == "task_and_revision":
        for row in changed["rounds"]:
            row["initial_outcome"]["task_id"] = "different-task"
            row["initial_outcome"]["requirements_revision"] += 1
        assert changed["predecessor_digest"] is None
    elif fault == "second_report":
        report = changed["rounds"][1]["initial_outcome"]["report"]
        report["summary"] = "A different retained report"
        report["payload_digest"] = digest({
            name: report[name] for name in ("request_key", "outcome", "summary")
        })
    else:
        row = changed["rounds"][1]
        row["artifacts"]["patch"] = "f" * 64
        row["initial_outcome"]["artifacts"]["patch"] = "f" * 64
    with server(lambda request, number: reply(
        request, **(original if number == 1 else changed)
    )) as fixture:
        client = ControlClient(fixture.path)
        client.request("session_status", session_id=sid)
        with pytest.raises(ControlError, match="invalid_response"):
            client.request("session_status", session_id=sid)
        assert len(fixture.requests) == 2
