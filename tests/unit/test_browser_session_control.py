"""Deterministic source-component proofs, without any browser or HTTP effects."""

import asyncio
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.browser_session.control import SessionControl
from src.browser_session.types import (FenceReceipt, Limits, Observation,
    OperationOutcome, SessionDenied, SessionSpec, SessionUnavailable, StopReceipt)


class Clock:
    def __init__(self):
        self.wall, self.mono = 1_000_000, 1000.0

    def wall_ms(self):
        return self.wall

    def monotonic(self):
        return self.mono

    def advance(self, milliseconds):
        self.wall += milliseconds
        self.mono += milliseconds / 1000


class FakeAdapter:
    """Exact fake owner responses. This is not a native confinement adapter."""
    def __init__(self, clock):
        self.clock, self.core, self.sequence = clock, None, 0
        self.executions, self.fences, self.stops = [], [], []
        self.execute_gate = self.fence_gate = self.stop_gate = None
        self.execute_state, self.stop_state = "applied", "confirmed"
        self.quiescent = True
        self.fence_outcome = "applied"
        self.wrong_fence = self.wrong_stop = False

    def observation(self, *, generation=None, document=None):
        self.sequence += 1
        identity = self.core.identity()
        return Observation(identity["session_id"], identity["context_id"], identity["target_id"],
            identity["backend_epoch"], identity["control_generation"] if generation is None else generation,
            document or identity["document_id"], self.sequence, self.clock.wall_ms(), 800, 600,
            json.dumps({"url": "https://one.example/item", "title": "Fixture", "fields": {"price": 19}}),
            b"\xff\xd8fake-frame\xff\xd9")

    async def execute(self, ticket):
        self.executions.append(ticket)
        if self.execute_gate:
            await self.execute_gate.wait()
        return OperationOutcome(ticket.operation_id, ticket.backend_epoch, ticket.control_generation,
                                ticket.document_generation, self.execute_state)

    async def quiesce(self, ticket):
        self.fences.append(ticket)
        if self.fence_gate:
            await self.fence_gate.wait()
        outcomes = tuple(OperationOutcome(value.operation_id, value.backend_epoch, value.control_generation,
            value.document_generation, self.fence_outcome) for value in ticket.inflight)
        return FenceReceipt(ticket.session_id, ticket.backend_epoch,
            "foreign-operation" if self.wrong_fence else ticket.operation_id, ticket.control_generation,
            self.quiescent, outcomes, self.observation(generation=ticket.control_generation))

    async def stop(self, ticket):
        self.stops.append(ticket)
        if self.stop_gate:
            await self.stop_gate.wait()
        return StopReceipt(ticket.session_id, ticket.backend_epoch,
            "foreign-stop" if self.wrong_stop else ticket.operation_id, ticket.control_generation, self.stop_state)


class SessionTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name)
        self.parent.chmod(0o700)
        self.directory = self.parent / "session"
        self.clock, self.adapter = Clock(), None
        self.adapter = FakeAdapter(self.clock)
        self.spec = SessionSpec("session", "context", "target", "document", "driver", "human",
            ("https://one.example", "https://two.example"), ("price",), self.clock.wall + 300_000,
            self.clock.wall + 600_000, Limits(action_timeout_ms=20, fence_timeout_ms=20, stop_timeout_ms=20,
                                           frame_interval_ms=1))
        self.core = SessionControl.create(self.directory, self.spec, self.adapter, self.clock)
        self.adapter.core = self.core
        self.driver = self.core.issue_grant("driver", {"observe": self.clock.wall + 300_000, "control": self.clock.wall + 250_000})
        self.human = self.core.issue_grant("human", {"observe": self.clock.wall + 300_000,
            "control": self.clock.wall + 250_000, "stop": self.clock.wall + 500_000})
        self.core.publish_observation(self.adapter.observation())

    async def asyncTearDown(self):
        for task in list(self.core._tasks.values()) + [self.core._transition_task, self.core._stop_task]:
            if task is not None and not task.done():
                # Test fixture teardown only. Cancellation is never asserted as
                # browser quiescence, and no real adapter exists in this suite.
                task.cancel()
        await asyncio.sleep(0)
        self.core.close()
        self.temporary.cleanup()

    def request(self, key="action-1", *, token=None, action="click", parameters=None):
        token = token or self.driver
        view = self.core.observe(token)
        values = {name: view[name] for name in ("session_id", "context_id", "target_id",
                    "control_generation", "document_id", "document_generation")}
        return {"operation_id": key, **values, "observation_id": view["frame"]["observation_id"],
            "action": action, "parameters": parameters or {"x": 10, "y": 20, "button": "left"}}

    def submit(self, key="action-1", **kwargs):
        token = kwargs.pop("token", self.driver)
        return self.core.submit(token, **self.request(key, token=token, **kwargs))

    async def test_original_intent_is_durable_before_single_adapter_effect_and_replay(self):
        request = self.request()
        self.core.submit(self.driver, **request)
        self.assertEqual(self.adapter.executions, [])
        retained = json.loads((self.directory / "session.json").read_bytes())
        self.assertEqual(retained["operations"]["action-1"]["state"], "queued")
        first = await self.core.execute_next()
        self.assertEqual(first["state"], "applied")
        self.assertEqual(self.core.submit(self.driver, **request)["state"], "applied")
        self.assertEqual(len(self.adapter.executions), 1)
        with self.assertRaisesRegex(SessionDenied, "operation_conflict"):
            self.core.submit(self.driver, **(request | {"parameters": {"x": 11, "y": 20, "button": "left"}}))
        self.assertEqual(len(self.adapter.executions), 1)

    async def test_rights_are_separate_fixed_and_no_bearer_secret_is_retained(self):
        observer = self.core.issue_grant("observer", {"observe": self.clock.wall + 1000})
        stopper = self.core.issue_grant("human", {"stop": self.clock.wall + 10_000})
        with self.assertRaises(SessionDenied):
            self.core.authorize(observer, "control")
        with self.assertRaises(SessionDenied):
            self.core.authorize(stopper, "observe")
        with self.assertRaises(SessionDenied):
            self.core.issue_grant("driver", {"stop": self.clock.wall + 1000})
        with self.assertRaises(SessionDenied):
            self.core.issue_grant("observer", {"control": self.clock.wall + 1000})
        for _ in range(3):
            self.core.observe(observer)
        self.clock.advance(1000)
        with self.assertRaises(SessionDenied):
            self.core.observe(observer)
        self.assertEqual((await self.core.stop(stopper, "owner-stop"))["state"], "confirmed")
        raw = (self.directory / "session.json").read_text()
        for token in (observer, stopper, self.driver, self.human):
            self.assertNotIn(token, raw)

    async def test_wrong_identity_and_action_catalog_never_dispatch(self):
        request = self.request()
        changes = ({"target_id": "foreign"}, {"context_id": "foreign"}, {"session_id": "foreign"},
            {"document_id": "foreign"}, {"document_generation": 1}, {"control_generation": 1},
            {"action": "evaluate", "parameters": {"source": "anything"}},
            {"action": "navigate", "parameters": {"url": "https://elsewhere.example"}},
            {"parameters": {"x": True, "y": 2, "button": "left"}},
            {"parameters": {"x": 0, "y": 2, "button": []}})
        for change in changes:
            with self.subTest(change=change), self.assertRaises(SessionDenied):
                self.core.submit(self.driver, **(request | change))
        self.assertEqual(self.adapter.executions, [])

    async def test_observation_is_exact_bounded_and_old_frame_cannot_drive(self):
        old = self.request()
        self.clock.advance(5)
        self.core.publish_observation(self.adapter.observation(document="document-2"))
        with self.assertRaises(SessionDenied):
            self.core.submit(self.driver, **old)
        frame = self.core.observe(self.driver)["frame"]
        self.assertEqual(frame["document_id"], "document-2")
        self.assertEqual(self.core.identity()["document_generation"], 1)
        self.assertEqual(self.core._frame[1], frame["jpeg"])
        for change in ({"target_id": "foreign"}, {"backend_epoch": "foreign"},
                       {"control_generation": 1}, {"width": 0}, {"jpeg": b"x"},
                       {"projection_json": '{"url":"https://one.example","title":"x","fields":{"secret":"x"}}'}):
            self.clock.advance(5)
            with self.subTest(change=change), self.assertRaises(SessionDenied):
                self.core.publish_observation(replace(self.adapter.observation(), **change))
        self.clock.advance(2001)
        self.assertIsNone(self.core.observe(self.driver)["frame"])

    async def test_queued_input_expires_when_frame_is_stale_before_dispatch(self):
        self.submit()
        self.clock.advance(2001)
        self.assertEqual((await self.core.execute_next())["state"], "not_applied")
        self.assertEqual(self.adapter.executions, [])

    async def test_raw_rate_and_semantic_count_are_distinct_server_budgets(self):
        self.submit(action="type", parameters={"text": "12345678901234567890"})
        await self.core.execute_next()
        self.assertEqual(self.core._state["raw_count"], 20)
        self.assertEqual(self.core._state["semantic_count"], 0)
        with self.assertRaisesRegex(SessionDenied, "action_budget_exhausted"):
            self.submit("rate-overflow", action="key", parameters={"key": "enter"})
        for number in range(20):
            self.submit("navigate-" + str(number), action="navigate", parameters={"url": "https://two.example/item"})
            await self.core.execute_next()
            self.clock.advance(2)
            self.core.publish_observation(self.adapter.observation())
        self.assertEqual(self.core._state["semantic_count"], 20)
        with self.assertRaisesRegex(SessionDenied, "action_budget_exhausted"):
            self.submit("semantic-overflow", action="navigate", parameters={"url": "https://one.example/item"})

    async def test_one_inflight_and_bounded_queue(self):
        self.adapter.execute_gate = asyncio.Event()
        self.submit()
        executing = asyncio.create_task(self.core.execute_next())
        await asyncio.sleep(0)
        for index in range(8):
            self.submit("queued-" + str(index))
        with self.assertRaisesRegex(SessionDenied, "queue_full"):
            self.submit("overflow")
        with self.assertRaisesRegex(SessionDenied, "input_fenced"):
            await self.core.execute_next()
        self.adapter.execute_gate.set()
        await executing
        self.assertEqual(len(self.adapter.executions), 1)

    async def test_timeout_does_not_cancel_or_invent_quiescence_and_late_result_stays_fenced(self):
        self.adapter.execute_gate = asyncio.Event()
        self.submit()
        self.assertEqual((await self.core.execute_next())["state"], "unknown")
        task = self.core._tasks["action-1"]
        self.assertFalse(task.done())
        self.assertFalse(task.cancelled())
        self.assertEqual(self.core.observe(self.human)["mode"], "fenced")
        self.adapter.execute_gate.set()
        await task
        await asyncio.sleep(0)
        self.assertEqual(self.core.operation(self.human, "action-1")["state"], "applied")
        self.assertEqual(self.core.observe(self.human)["mode"], "fenced")
        self.assertIsNone(self.core.observe(self.human)["actor_id"])

    async def test_cancelling_waiter_preserves_owned_original_task_and_unknown(self):
        self.adapter.execute_gate = asyncio.Event()
        self.submit()
        waiter = asyncio.create_task(self.core.execute_next())
        await asyncio.sleep(0)
        waiter.cancel()
        with self.assertRaises(asyncio.CancelledError):
            await waiter
        self.assertFalse(self.core._tasks["action-1"].done())
        self.assertEqual(self.core.operation(self.human, "action-1")["state"], "unknown")

    async def test_takeover_cancels_queue_and_requires_original_outcomes_and_fresh_generation(self):
        self.adapter.execute_gate = asyncio.Event()
        self.submit()
        executing = asyncio.create_task(self.core.execute_next())
        await asyncio.sleep(0)
        await asyncio.sleep(0)
        self.assertEqual(len(self.adapter.executions), 1)
        self.submit("queued")
        receipt = await self.core.takeover(self.human, "takeover", control_generation=0)
        self.assertEqual(receipt["state"], "applied")
        self.assertEqual(self.core.operation(self.human, "queued")["state"], "not_applied")
        self.assertEqual(self.core.operation(self.human, "action-1")["state"], "applied")
        self.assertEqual(len(self.adapter.fences[0].inflight), 1)
        self.assertEqual(self.core.observe(self.human)["mode"], "human")
        with self.assertRaises(SessionDenied):
            self.submit("old-driver")
        self.adapter.execute_gate.set()
        await executing
        self.assertEqual(self.core.observe(self.human)["mode"], "human")

    async def test_unknown_quiescence_never_transfers_or_resumes_on_late_receipt(self):
        self.adapter.fence_gate = asyncio.Event()
        result = await self.core.takeover(self.human, "takeover", control_generation=0)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(self.core.observe(self.human)["mode"], "fenced")
        original_task = self.core._transition_task
        self.adapter.fence_gate.set()
        await original_task
        await asyncio.sleep(0)
        self.assertEqual(self.core.observe(self.human)["mode"], "fenced")
        self.assertEqual((await self.core.takeover(self.human, "takeover", control_generation=0))["state"], "unknown")
        self.assertEqual(len(self.adapter.fences), 1)

    async def test_foreign_quiescence_and_unknown_original_refuse_transfer(self):
        self.adapter.wrong_fence = True
        result = await self.core.takeover(self.human, "takeover", control_generation=0)
        self.assertEqual(result["state"], "unknown")
        self.assertEqual(self.core.observe(self.human)["mode"], "fenced")

    async def test_human_correction_is_attributed_and_only_explicit_fresh_handback_resumes(self):
        await self.core.takeover(self.human, "takeover", control_generation=0)
        self.submit("correction", token=self.human, action="correction", parameters={"text": "Compare total cost."})
        await self.core.execute_next()
        human_view = self.core.observe(self.human)
        with self.assertRaisesRegex(SessionDenied, "fresh_observation_required"):
            await self.core.handback(self.human, "bad-handback", control_generation=1, observation_id="0" * 64)
        result = await self.core.handback(self.human, "handback", control_generation=1,
            observation_id=human_view["frame"]["observation_id"])
        self.assertEqual(result["state"], "applied")
        driver_view = self.core.observe(self.driver)
        self.assertEqual(driver_view["mode"], "driver")
        self.assertEqual(driver_view["corrections"], [{"operation_id": "correction", "actor_id": "human",
            "text": "Compare total cost.", "generation": 1}])
        self.assertEqual(self.adapter.executions, [])
        await self.core.stop(self.human, "stop")
        self.core.close()
        self.core = SessionControl.reopen(self.directory, self.clock)
        observer = self.core.issue_grant("returning-reader", {"observe": self.clock.wall + 1000})
        retained = self.core.observe(observer)
        self.assertEqual(retained["mode"], "lost")
        self.assertEqual(retained["corrections"], driver_view["corrections"])

    async def test_stop_invalidates_queued_inputs_and_duplicate_does_not_reissue(self):
        self.submit()
        result = await self.core.stop(self.human, "stop")
        self.assertEqual(result["state"], "confirmed")
        self.assertEqual(self.core.operation(self.human, "action-1")["state"], "not_applied")
        self.assertEqual((await self.core.stop(self.human, "stop"))["state"], "confirmed")
        self.assertEqual(len(self.adapter.stops), 1)
        with self.assertRaises(SessionDenied):
            self.core.authorize(self.driver, "control")
        self.assertEqual(self.adapter.executions, [])

    async def test_stop_timeout_is_unknown_not_teardown_and_late_exact_confirmation_is_retained(self):
        self.adapter.stop_gate = asyncio.Event()
        result = await self.core.stop(self.human, "stop")
        self.assertEqual(result["state"], "unknown")
        self.assertFalse(self.core._stop_task.done())
        self.assertEqual(self.core.observe(self.human)["mode"], "fenced")
        self.adapter.stop_gate.set()
        await self.core._stop_task
        await asyncio.sleep(0)
        self.assertEqual(self.core.operation(self.human, "stop")["state"], "confirmed")
        self.assertEqual(self.core.observe(self.human)["mode"], "stopped")

    async def test_journal_failure_prevents_effects_and_grants_but_does_not_strand_owner_stop(self):
        with patch.object(self.core.store, "save", side_effect=SessionUnavailable()):
            with self.assertRaises(SessionUnavailable):
                self.submit()
            with self.assertRaises(SessionUnavailable):
                self.core.issue_grant("other", {"observe": self.clock.wall + 1000})
            with self.assertRaises(SessionUnavailable):
                await self.core.execute_next()
            stopped = await self.core.stop(self.human, "emergency-stop")
            self.assertEqual(stopped["state"], "confirmed")
            self.assertFalse(stopped["audit_persisted"])
            self.assertEqual(len(self.adapter.stops), 1)
            self.assertEqual(self.adapter.executions, [])
            self.assertFalse((await self.core.stop(self.human, "emergency-stop"))["audit_persisted"])
            with self.assertRaisesRegex(SessionDenied, "stop_unavailable"):
                await self.core.stop(self.human, "different-stop")
            self.assertEqual(len(self.adapter.stops), 1)
            self.assertEqual(self.core._state["mode"], "stopped")
        retained = json.loads((self.directory / "session.json").read_bytes())
        self.assertNotIn("emergency-stop", retained["operations"])

    async def test_supervisor_enforces_absolute_lifetime_without_client_polling(self):
        self.clock.advance(300_000)
        await self.core.supervise()
        self.assertEqual(len(self.adapter.stops), 1)
        self.assertEqual(self.adapter.stops[0].operation_id, "host.browser-lifetime-expired")
        self.assertEqual(self.core._state["mode"], "stopped")

    async def test_wall_rollback_never_extends_control_or_owner_deadline(self):
        self.clock.wall -= 1
        with self.assertRaisesRegex(SessionDenied, "clock_rollback"):
            self.core.authorize(self.driver, "control")
        self.assertEqual(self.core.authorize(self.human, "stop").right, "stop")
        self.clock.mono += 501
        with self.assertRaises(SessionDenied):
            self.core.authorize(self.human, "stop")

    async def test_retained_results_and_sealed_events_survive_reopen_without_resuming(self):
        content = b'{"comparison":"fixture-only","price":19}\n'
        screenshot = b"\xff\xd8retained\xff\xd9"
        self.core.retain_result("result.json", content)
        self.core.retain_result("screenshot.jpg", screenshot)
        await self.core.stop(self.human, "stop")
        events = self.core.read_result(self.human, "events.json")
        self.assertNotIn(self.human.encode(), events)
        original_identity = self.core.identity()
        self.core.close()
        self.core = SessionControl.reopen(self.directory, self.clock)
        with self.assertRaises(SessionDenied):
            self.core.observe(self.human)
        observer = self.core.issue_grant("returning-observer", {"observe": self.clock.wall + 1000})
        self.assertEqual(self.core.observe(observer)["mode"], "lost")
        self.assertIsNone(self.core.observe(observer)["frame"])
        for field in ("session_id", "context_id", "target_id", "backend_epoch"):
            self.assertEqual(self.core.identity()[field], original_identity[field])
        self.assertEqual(self.core.read_result(observer, "result.json"), content)
        self.assertEqual(self.core.read_result(observer, "screenshot.jpg"), screenshot)
        self.assertEqual(self.core.read_result(observer, "events.json"), events)
        with self.assertRaises(SessionDenied):
            self.core.issue_grant("human", {"stop": self.clock.wall + 1000})
        self.assertIsNone(self.core.adapter)

    async def test_live_lock_prevents_second_open_and_create_then_release_reopens_lost(self):
        original = hashlib.sha256((self.directory / "session.json").read_bytes()).hexdigest()
        with self.assertRaises(SessionUnavailable):
            SessionControl.reopen(self.directory, self.clock)
        with self.assertRaises(SessionUnavailable):
            SessionControl.create(self.directory, self.spec, self.adapter, self.clock)
        self.assertEqual(hashlib.sha256((self.directory / "session.json").read_bytes()).hexdigest(), original)
        self.core.close()
        self.core = SessionControl.reopen(self.directory, self.clock)
        self.assertEqual(self.core._state["mode"], "lost")

    async def test_replaced_lock_cannot_admit_a_second_owner(self):
        lock = self.directory / "owner.lock"
        lock.unlink()
        lock.touch(mode=0o600)
        with self.assertRaises(SessionUnavailable):
            SessionControl.reopen(self.directory, self.clock)
        with self.assertRaises(SessionUnavailable):
            self.submit()
        self.assertEqual(self.adapter.executions, [])

    async def test_missing_corrupt_or_symlinked_original_journal_never_reinitializes(self):
        self.core.close()
        journal = self.directory / "session.json"
        content = journal.read_bytes()
        journal.unlink()
        with self.assertRaises(SessionUnavailable):
            SessionControl.reopen(self.directory, self.clock)
        outside = self.parent / "outside"
        outside.write_bytes(content)
        outside.chmod(0o600)
        journal.symlink_to(outside)
        with self.assertRaises(SessionUnavailable):
            SessionControl.reopen(self.directory, self.clock)
        journal.unlink()
        journal.write_bytes(b'{"schema_version":1}')
        journal.chmod(0o600)
        with self.assertRaises(SessionUnavailable):
            SessionControl.reopen(self.directory, self.clock)
        with self.assertRaises(SessionUnavailable):
            SessionControl.create(self.directory, self.spec, self.adapter, self.clock)

    async def test_unsafe_modes_and_external_journal_replacement_fail_before_dispatch(self):
        (self.directory / "session.json").chmod(0o644)
        with self.assertRaises(SessionUnavailable):
            self.submit()
        self.assertEqual(self.adapter.executions, [])

    async def test_total_retention_budget_includes_metadata_and_atomic_write_headroom(self):
        self.core.store.maximum = 50_000
        # Keep the immutable anchor truthful in this independent new fixture.
        self.core.close()
        other = self.parent / "small"
        spec = replace(self.spec, limits=replace(self.spec.limits, result_bytes=50_000))
        self.core = SessionControl.create(other, spec, self.adapter, self.clock)
        self.adapter.core = self.core
        token = self.core.issue_grant("human", {"stop": self.clock.wall + 1000})
        with self.assertRaises(SessionUnavailable):
            self.core.retain_result("result.json", json.dumps({"data": "x" * 49_000}).encode())
        self.assertLessEqual(sum(path.stat().st_size for path in other.rglob("*") if path.is_file()), 50_000)
        self.assertEqual((await self.core.stop(token, "emergency-stop"))["state"], "confirmed")


if __name__ == "__main__":
    unittest.main()
