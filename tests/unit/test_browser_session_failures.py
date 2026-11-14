"""Review regressions at actual dispatch, callback and original-record seams."""

import asyncio
from copy import deepcopy
from dataclasses import replace
import json
from pathlib import Path
from unittest.mock import patch

import pytest

from src.browser_session.control import SessionControl
from src.browser_session.types import (FenceReceipt, Limits, OperationOutcome, SessionDenied,
    SessionSpec, SessionUnavailable, StopReceipt)
from tests.unit.test_browser_session_control import Clock, FakeAdapter


@pytest.fixture
def session(tmp_path):
    tmp_path.chmod(0o700)
    clock = Clock()
    adapter = FakeAdapter(clock)
    spec = SessionSpec("session", "context", "target", "document", "driver", "human",
        ("https://one.example", "https://two.example"), ("price",), clock.wall + 300_000,
        clock.wall + 600_000, Limits(action_timeout_ms=50, fence_timeout_ms=50, stop_timeout_ms=50,
                                    frame_interval_ms=1))
    core = SessionControl.create(tmp_path / "session", spec, adapter, clock)
    adapter.core = core
    driver = core.issue_grant("driver", {"observe": clock.wall + 5000, "control": clock.wall + 1000})
    human = core.issue_grant("human", {"observe": clock.wall + 5000, "control": clock.wall + 1000,
                                      "stop": clock.wall + 10_000})
    core.publish_observation(adapter.observation())
    try:
        yield core, adapter, clock, driver, human
    finally:
        core.close()


def request(core, token, key="original"):
    view = core.observe(token)
    values = {name: view[name] for name in ("session_id", "context_id", "target_id", "control_generation",
                                           "document_id", "document_generation")}
    return values | {"operation_id": key, "observation_id": view["frame"]["observation_id"],
                     "action": "click", "parameters": {"x": 1, "y": 2, "button": "left"}}


@pytest.mark.parametrize("change", [
    {"control_generation": False}, {"document_generation": False},
    {"control_generation": 0.0}, {"parameters": {"x": True, "y": 2, "button": "left"}},
])
def test_original_action_replay_checks_exact_types_before_python_equality(session, change):
    core, adapter, _, driver, _ = session
    original = request(core, driver)
    core.submit(driver, **original)
    with pytest.raises(SessionDenied):
        core.submit(driver, **(original | change))
    assert not adapter.executions


@pytest.mark.asyncio
async def test_original_transfer_replay_does_not_accept_boolean_generation(session):
    core, _, _, _, human = session
    await core.takeover(human, "takeover", control_generation=0)
    with pytest.raises(SessionDenied):
        await core.takeover(human, "takeover", control_generation=False)


@pytest.mark.asyncio
@pytest.mark.parametrize("method", ["execute", "quiesce", "stop"])
async def test_synchronous_adapter_invocation_failure_retains_unknown_and_fences(session, method):
    core, adapter, _, driver, human = session
    with patch.object(adapter, method, side_effect=RuntimeError("private-adapter-detail")) as invocation:
        if method == "execute":
            core.submit(driver, **request(core, driver))
            result = await core.execute_next()
        elif method == "quiesce":
            result = await core.takeover(human, "original", control_generation=0)
        else:
            result = await core.stop(human, "original")
    assert invocation.call_count == 1
    assert result["state"] == "unknown"
    assert core.observe(human)["mode"] == "fenced"
    assert core.operation(human, "original")["state"] == "unknown"
    assert "private-adapter-detail" not in core.store.journal.read_text()


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["action", "takeover", "stop"])
async def test_scheduling_failure_keeps_original_unknown_without_adapter_retry(session, kind):
    core, adapter, _, driver, human = session
    if kind == "action":
        core.submit(driver, **request(core, driver))
    with patch("src.browser_session.control.asyncio.create_task", side_effect=RuntimeError("schedule-failed")):
        if kind == "action":
            result = await core.execute_next()
        elif kind == "takeover":
            result = await core.takeover(human, "original", control_generation=0)
        else:
            result = await core.stop(human, "original")
    assert result["state"] == "unknown"
    assert core.observe(human)["mode"] == "fenced"
    assert not adapter.executions and not adapter.fences and not adapter.stops


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("control_generation", False), ("document_generation", False), ("state", [])])
async def test_malformed_action_outcomes_become_unknown_without_callback_escape(session, field, value):
    core, adapter, _, driver, human = session
    async def malformed(ticket):
        outcome = OperationOutcome(ticket.operation_id, ticket.backend_epoch, ticket.control_generation,
                                   ticket.document_generation, "applied")
        return replace(outcome, **{field: value})
    adapter.execute = malformed
    core.submit(driver, **request(core, driver))
    assert (await core.execute_next())["state"] == "unknown"
    assert core.observe(human)["mode"] == "fenced"


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("control_generation", True), ("quiescent", 1), ("outcomes", [])])
async def test_malformed_fence_receipts_never_transfer(session, field, value):
    core, adapter, _, _, human = session
    async def malformed(ticket):
        receipt = FenceReceipt(ticket.session_id, ticket.backend_epoch, ticket.operation_id,
            ticket.control_generation, True, (), adapter.observation(generation=ticket.control_generation))
        return replace(receipt, **{field: value})
    adapter.quiesce = malformed
    assert (await core.takeover(human, "original", control_generation=0))["state"] == "unknown"
    assert core.observe(human)["mode"] == "fenced"


@pytest.mark.asyncio
@pytest.mark.parametrize("field,value", [("control_generation", True), ("state", [])])
async def test_malformed_stop_receipts_never_establish_teardown(session, field, value):
    core, adapter, _, _, human = session
    async def malformed(ticket):
        receipt = StopReceipt(ticket.session_id, ticket.backend_epoch, ticket.operation_id,
                              ticket.control_generation, "confirmed")
        return replace(receipt, **{field: value})
    adapter.stop = malformed
    assert (await core.stop(human, "original"))["state"] == "unknown"
    assert core.observe(human)["mode"] == "fenced"


@pytest.mark.asyncio
async def test_dispatch_rechecks_shorter_control_lease_after_durable_write(session):
    core, adapter, clock, _, human = session
    driver = core.issue_grant("driver", {"observe": clock.wall + 1000, "control": clock.wall + 10})
    core.submit(driver, **request(core, driver))
    original_save = core.store.save
    def slow_save(state):
        original_save(state)
        if state["operations"]["original"]["state"] == "dispatched":
            clock.advance(11)
    with patch.object(core.store, "save", side_effect=slow_save):
        result = await core.execute_next()
    assert result["state"] == "not_applied"
    assert not adapter.executions
    assert core.observe(human)["mode"] == "fenced"


@pytest.mark.asyncio
async def test_dispatch_rechecks_after_the_owned_wrapper_was_scheduled(session):
    core, adapter, clock, _, _ = session
    driver = core.issue_grant("driver", {"observe": clock.wall + 1000, "control": clock.wall + 10})
    core.submit(driver, **request(core, driver))
    waiting = asyncio.create_task(core.execute_next())
    await asyncio.sleep(0)
    assert core._state["operations"]["original"]["state"] == "dispatched"
    assert not adapter.executions
    clock.advance(11)
    assert (await waiting)["state"] == "not_applied"
    assert not adapter.executions


@pytest.mark.asyncio
async def test_stop_fence_before_scheduled_action_start_prevents_invocation(session):
    core, adapter, _, driver, human = session
    core.submit(driver, **request(core, driver))
    waiting = asyncio.create_task(core.execute_next())
    await asyncio.sleep(0)
    await core.stop(human, "stop")
    assert (await waiting)["state"] == "not_applied"
    assert not adapter.executions
    assert len(adapter.stops) == 1


@pytest.mark.asyncio
async def test_late_action_completion_retains_knowledge_but_fences_without_timer_race(session):
    core, adapter, clock, driver, human = session
    async def late(ticket):
        adapter.executions.append(ticket)
        clock.advance(51)
        return OperationOutcome(ticket.operation_id, ticket.backend_epoch, ticket.control_generation,
                                ticket.document_generation, "applied")
    adapter.execute = late
    core.submit(driver, **request(core, driver))
    assert (await core.execute_next())["state"] == "applied"
    assert core.observe(human)["mode"] == "fenced"
    assert core.identity()["control_generation"] == 1
    assert len(adapter.executions) == 1


@pytest.mark.asyncio
@pytest.mark.parametrize("kind", ["takeover", "stop"])
async def test_control_and_stop_invocation_do_not_extend_expiry_during_audit_write(session, kind):
    core, adapter, clock, _, _ = session
    human = core.issue_grant("human", {"observe": clock.wall + 1000, "control": clock.wall + 10,
                                      "stop": clock.wall + 10})
    original_save = core.store.save
    def slow_save(state):
        original_save(state)
        if state["operations"].get("original", {}).get("state") == "dispatched":
            clock.advance(11)
    with patch.object(core.store, "save", side_effect=slow_save):
        result = (await core.takeover(human, "original", control_generation=0) if kind == "takeover"
                  else await core.stop(human, "original"))
    assert result["state"] == "unknown"
    assert not adapter.fences and not adapter.stops


@pytest.mark.asyncio
async def test_old_stop_evidence_cannot_downgrade_a_new_confirmed_stop(session):
    core, adapter, _, _, human = session
    adapter.stop_state = "unknown"
    assert (await core.stop(human, "first-stop"))["state"] == "unknown"
    old = adapter.stops[0]
    adapter.stop_state = "confirmed"
    assert (await core.stop(human, "second-stop"))["state"] == "confirmed"
    core._finish_stop(old, StopReceipt(old.session_id, old.backend_epoch, old.operation_id,
                                      old.control_generation, "failed"))
    assert core.observe(human)["mode"] == "stopped"
    assert core.operation(human, "first-stop")["state"] == "unknown"
    assert len(adapter.stops) == 2


@pytest.mark.parametrize("damage", ["request_boolean", "request_extra", "foreign_target", "ticket_boolean",
    "ticket_parameters", "queue_missing", "charge_missing", "event_boolean"])
def test_damaged_original_operation_record_refuses_reopen(session, damage):
    core, _, clock, driver, _ = session
    core.submit(driver, **request(core, driver))
    state = deepcopy(core._state)
    operation = state["operations"]["original"]
    if damage == "request_boolean":
        operation["request"]["control_generation"] = False
    elif damage == "request_extra":
        operation["request"]["extra"] = True
    elif damage == "foreign_target":
        operation["request"]["target_id"] = "foreign"
    elif damage == "ticket_boolean":
        operation["ticket"]["document_generation"] = False
    elif damage == "ticket_parameters":
        operation["ticket"]["parameters_json"] = '{"x":99,"y":2,"button":"left"}'
    elif damage == "queue_missing":
        state["queue"] = []
    elif damage == "charge_missing":
        state["raw_count"] = 0
    else:
        state["events"][0]["sequence"] = False
    directory = core.store.root
    core.close()
    (directory / "session.json").write_text(json.dumps(state))
    with pytest.raises(SessionUnavailable):
        SessionControl.reopen(directory, clock)


def test_entropy_collision_never_retargets_an_existing_grant(session):
    core, _, clock, driver, _ = session
    with patch("src.browser_session.control.secrets.token_urlsafe", return_value=driver):
        with pytest.raises(SessionDenied, match="entropy_unavailable"):
            core.issue_grant("human", {"stop": clock.wall + 1000})
    assert core.authorize(driver, "control").actor_id == "driver"


def test_client_cannot_claim_the_supervisors_original_operation_identity(session):
    core, adapter, _, driver, _ = session
    with pytest.raises(SessionDenied, match="reserved_operation_identity"):
        core.submit(driver, **request(core, driver, "host.browser-lifetime-expired"))
    assert not adapter.executions


@pytest.mark.asyncio
async def test_temporary_cleanup_error_fences_mutation_and_preserves_emergency_stop(session):
    core, adapter, _, driver, human = session
    original_unlink = Path.unlink
    def fail_cleanup(path, *args, **kwargs):
        if path.name.startswith(".session-"):
            raise OSError("private-filesystem-detail")
        return original_unlink(path, *args, **kwargs)
    with patch.object(Path, "unlink", new=fail_cleanup):
        with pytest.raises(SessionUnavailable):
            core.submit(driver, **request(core, driver))
        assert not adapter.executions
        result = await core.stop(human, "owner-stop")
    assert result["state"] == "confirmed" and result["audit_persisted"] is False
    assert len(adapter.stops) == 1
    assert core._state["mode"] == "stopped"


@pytest.mark.asyncio
async def test_applied_navigation_requires_new_authoritative_observation_before_more_input(session):
    core, adapter, clock, driver, human = session
    original = request(core, driver, "navigate")
    original.update(action="navigate", parameters={"url": "https://two.example/item"})
    core.submit(driver, **original)
    core.submit(driver, **request(core, driver, "old-click"))
    assert (await core.execute_next())["state"] == "applied"
    assert core.operation(human, "navigate")["state"] == "applied"
    assert core.observe(driver)["frame"] is None
    assert (await core.execute_next())["state"] == "not_applied"
    assert [ticket.operation_id for ticket in adapter.executions] == ["navigate"]
    clock.advance(2)
    core.publish_observation(adapter.observation(document="post-navigation-document"))
    core.submit(driver, **request(core, driver, "fresh-click"))
    assert (await core.execute_next())["state"] == "applied"
    assert [ticket.operation_id for ticket in adapter.executions] == ["navigate", "fresh-click"]
    assert adapter.executions[-1].document_id == "post-navigation-document"
    assert adapter.executions[-1].document_generation == 1


@pytest.mark.asyncio
async def test_navigation_cannot_reuse_a_new_sequence_captured_before_navigation_completion(session):
    core, adapter, clock, driver, _ = session
    stale = adapter.observation()
    original = request(core, driver)
    original.update(action="navigate", parameters={"url": "https://two.example/item"})
    core.submit(driver, **original)
    clock.advance(1)
    assert (await core.execute_next())["state"] == "applied"
    with pytest.raises(SessionDenied):
        core.publish_observation(stale)
    assert core.observe(driver)["frame"] is None


@pytest.mark.asyncio
async def test_navigation_refuses_unpublished_pre_navigation_capture_in_the_same_millisecond(session):
    core, adapter, clock, driver, _ = session
    stale = adapter.observation()
    original = request(core, driver)
    original.update(action="navigate", parameters={"url": "https://two.example/item"})
    core.submit(driver, **original)
    assert (await core.execute_next())["state"] == "applied"
    assert stale.captured_at_ms == clock.wall_ms()
    clock.advance(2)
    with pytest.raises(SessionDenied):
        core.publish_observation(stale)
    core.publish_observation(adapter.observation())
    assert core.observe(driver)["frame"] is not None


@pytest.mark.asyncio
async def test_original_stop_polling_uses_only_owner_stop_right_and_never_creates_an_operation(session):
    core, adapter, clock, driver, _ = session
    owner = core.issue_grant("human", {"observe": clock.wall + 1, "stop": clock.wall + 1000})
    observer = core.issue_grant("observer", {"observe": clock.wall + 1000})
    core.submit(driver, **request(core, driver, "ordinary-action"))
    adapter.stop_gate = asyncio.Event()
    assert (await core.stop(owner, "original-stop"))["state"] == "unknown"
    clock.advance(2)
    with pytest.raises(SessionDenied):
        core.observe(owner)
    for key in ("ordinary-action", "absent-stop"):
        with pytest.raises(SessionDenied, match="operation_absent"):
            core.stop_operation(owner, key)
    with pytest.raises(SessionDenied):
        core.stop_operation(observer, "original-stop")
    original_bytes = core.store.journal.read_bytes()
    for _ in range(3):
        result = core.stop_operation(owner, "original-stop")
        assert result["state"] == "unknown" and "ticket" not in result
    assert core.store.journal.read_bytes() == original_bytes
    assert len(adapter.stops) == 1 and not adapter.executions
    adapter.stop_gate.set()
    await core._stop_task
    await asyncio.sleep(0)
    assert core.stop_operation(owner, "original-stop")["state"] == "confirmed"
    assert len(adapter.stops) == 1


@pytest.mark.asyncio
async def test_stop_only_polling_preserves_known_confirmation_when_audit_storage_failed(session):
    core, adapter, _, _, human = session
    with patch.object(core.store, "save", side_effect=SessionUnavailable()):
        result = await core.stop(human, "original-stop")
        assert result["state"] == "confirmed" and result["audit_persisted"] is False
        polled = core.stop_operation(human, "original-stop")
        assert polled["state"] == "confirmed" and polled["audit_persisted"] is False
        assert "ticket" not in polled
    assert len(adapter.stops) == 1


@pytest.mark.asyncio
async def test_stop_preserves_unknown_then_accepts_exact_late_action_knowledge_without_resuming(session):
    core, adapter, _, driver, human = session
    adapter.execute_gate = asyncio.Event()
    core.submit(driver, **request(core, driver))
    waiting = asyncio.create_task(core.execute_next())
    await asyncio.sleep(0)
    await asyncio.sleep(0)
    assert len(adapter.executions) == 1
    assert (await core.stop(human, "original-stop"))["state"] == "confirmed"
    assert core.operation(human, "original")["state"] == "unknown"
    sealed = core.read_result(human, "events.json")
    adapter.execute_gate.set()
    assert (await waiting)["state"] == "applied"
    assert core.operation(human, "original")["state"] == "applied"
    assert core.observe(human)["mode"] == "stopped"
    assert core.read_result(human, "events.json") == sealed
    assert len(adapter.executions) == 1 and len(adapter.stops) == 1


@pytest.mark.asyncio
async def test_owner_stop_keys_cannot_exhaust_the_single_reserved_host_lifetime_record(tmp_path):
    tmp_path.chmod(0o700)
    clock = Clock()
    adapter = FakeAdapter(clock)
    spec = SessionSpec("session", "context", "target", "document", "driver", "human",
        ("https://one.example", "https://two.example"), (), clock.wall + 300_000, clock.wall + 600_000,
        Limits(operations=2))
    core = SessionControl.create(tmp_path / "small", spec, adapter, clock)
    adapter.core = core
    try:
        human = core.issue_grant("human", {"stop": clock.wall + 500_000})
        adapter.stop_state = "unknown"
        assert (await core.stop(human, "first-stop"))["state"] == "unknown"
        with pytest.raises(SessionDenied, match="operation_budget_exhausted"):
            await core.stop(human, "second-owner-stop")
        clock.advance(300_000)
        adapter.stop_state = "confirmed"
        await core.supervise()
        assert len(adapter.stops) == 2
        assert adapter.stops[-1].operation_id == "host.browser-lifetime-expired"
        assert len(core._state["operations"]) == 2
        assert core.stop_operation(human, "host.browser-lifetime-expired")["state"] == "confirmed"
        await core.supervise()
        assert len(adapter.stops) == 2
        core.close()
        core = SessionControl.reopen(tmp_path / "small", clock)
        assert core._state["mode"] == "lost"
    finally:
        core.close()
