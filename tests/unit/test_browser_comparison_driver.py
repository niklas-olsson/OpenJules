"""Real interlock/port composition, with deterministic fixture effects only."""

import asyncio
from copy import deepcopy
from dataclasses import replace
import hashlib
import json
from pathlib import Path
import tempfile
import unittest
from unittest.mock import patch

from src.browser_session import comparison_driver as subject
from src.browser_session.comparison_driver import (ABSENT, ALPHA_URL, BETA_URL, CORRECTION,
    ComparisonDriver, ComparisonPort, DriverDenied, DriverLimits, DriverSpec)
from src.browser_session.control import SessionControl
from src.browser_session.http_app import SessionHTTP, _ack
from src.browser_session.pairing import PairingBroker
from src.browser_session.types import Limits, Observation, SessionDenied, SessionSpec
from tests.unit.test_browser_session_control import Clock, FakeAdapter


class FixtureAdapter(FakeAdapter):
    """Fake DOM-derived scalars and links, never a native browser adapter."""

    def __init__(self, clock):
        super().__init__(clock)
        self.fixture, self.delivery, self.document, self.focus = "alpha", 5, 0, False

    def observation(self, *, generation=None, document=None):
        self.sequence += 1
        identity = self.core.identity()
        price, delivery, url, next_url = ((120, self.delivery, ALPHA_URL, BETA_URL) if self.fixture == "alpha"
                                         else (110, 8, BETA_URL, ALPHA_URL))
        fields = {"fixture": self.fixture, "price": price, "delivery": delivery, "total": price + delivery,
                  "next_url": next_url, "next_x": 100, "next_y": 80}
        return Observation(identity["session_id"], identity["context_id"], identity["target_id"], identity["backend_epoch"],
            identity["control_generation"] if generation is None else generation, document or f"fixture-document-{self.document}",
            self.sequence, self.clock.wall_ms(), 800, 600,
            json.dumps({"url": url, "title": self.fixture.title() + " fixture", "fields": fields}),
            b"\xff\xd8deterministic-fixture-frame\xff\xd9")

    async def execute(self, ticket):
        result = await super().execute(ticket)
        if result.state == "applied":
            parameters = json.loads(ticket.parameters_json)
            if ticket.action == "click" and parameters == {"x": 100, "y": 80, "button": "left"}:
                self.fixture = "beta" if self.fixture == "alpha" else "alpha"
                self.document += 1
                self.focus = False
            elif ticket.actor_id == "human" and self.fixture == "alpha":
                if ticket.action == "click" and parameters == {"x": 20, "y": 20, "button": "left"}:
                    self.focus = True
                elif ticket.action == "key" and parameters == {"key": "arrow_down"} and self.focus:
                    self.delivery = 12
                else:
                    raise AssertionError("unrecognized deterministic fixture input")
            else:
                raise AssertionError("unrecognized deterministic fixture input")
        return result


class ComparisonTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        # Test isolation models a fresh host process; production has no reset.
        self.claim = patch.object(subject, "_process_claim", None)
        self.claim.start()
        self.temporary = tempfile.TemporaryDirectory()
        self.parent = Path(self.temporary.name)
        self.parent.chmod(0o700)
        self.directory = self.parent / "session"
        self.clock = Clock()
        self.adapter = FixtureAdapter(self.clock)
        core_spec = SessionSpec("comparison-session", "context", "target", "fixture-document-0", "driver", "human",
            ("http://127.0.0.1:8765", "http://127.0.0.1:8766"),
            tuple(sorted(subject._FIELDS)), self.clock.wall + 300000, self.clock.wall + 600000,
            Limits(frame_interval_ms=1, action_timeout_ms=20, fence_timeout_ms=20, stop_timeout_ms=20))
        self.core = SessionControl.create(self.directory, core_spec, self.adapter, self.clock)
        self.adapter.core = self.core
        self.driver_token = self.core.issue_grant("driver", {"observe": self.clock.wall + 300000, "control": self.clock.wall + 290000})
        self.owner_token = self.core.issue_grant("human", {"observe": self.clock.wall + 300000,
            "control": self.clock.wall + 290000, "stop": self.clock.wall + 500000})
        self.app = SessionHTTP(self.core, PairingBroker(self.core, "https://control.example", clock=self.clock),
                               "https://control.example", notify_pending=lambda: None)
        identity = self.core.identity()
        self.spec = DriverSpec(identity["session_id"], identity["context_id"], identity["target_id"], identity["backend_epoch"],
                               "driver", "human", self.clock.wall, self.clock.wall + 290000, self.clock.mono + 290)
        self.calls, self.requests = [], []
        self.observe_hook = self.submit_hook = self.status_hook = None
        self.port = ComparisonPort(self.observe, self.submit, self.operation)
        self.driver = None
        self.core.publish_observation(self.adapter.observation())

    async def asyncTearDown(self):
        for task in list(self.core._tasks.values()) + [self.core._transition_task, self.core._stop_task]:
            if task is not None and not task.done():
                task.cancel()  # Fake fixture teardown, never native quiescence evidence.
        await asyncio.sleep(0)
        self.core.close()
        self.temporary.cleanup()
        self.claim.stop()

    def observe(self):
        self.calls.append(("observe", None, self.clock.monotonic()))
        view = self.app._observation(self.driver_token)
        return self.observe_hook(view) if self.observe_hook else view

    def submit(self, request):
        self.calls.append(("submit", request["operation_id"], self.clock.monotonic()))
        self.requests.append(deepcopy(request))
        if self.submit_hook:
            return self.submit_hook(request)
        return _ack(self.core.submit(self.driver_token, **request))

    def operation(self, key):
        self.calls.append(("operation", key, self.clock.monotonic()))
        if self.status_hook:
            return self.status_hook(key)
        try:
            return _ack(self.core.operation(self.driver_token, key))
        except SessionDenied as error:
            if error.code == "operation_absent":
                return ABSENT
            raise

    def create(self, **changes):
        self.driver = ComparisonDriver(replace(self.spec, **changes), self.port, self.clock)
        return self.driver

    def frame(self):
        if self.core._state["mode"] in {"driver", "human"}:
            self.core.publish_observation(self.adapter.observation())

    async def tick(self, *, dispatch=True, fresh=True):
        self.clock.advance(250)
        if fresh:
            self.frame()
        before = len(self.calls)
        progress = self.driver.step()
        self.assertLessEqual(len(self.calls) - before, 2)
        if dispatch and self.core._state["queue"]:
            await self.core.execute_next()  # The host, never ComparisonDriver.
            self.clock.advance(2)
            self.frame()
        return progress

    async def reach(self, phase, *, dispatch=True, maximum=30):
        for _ in range(maximum):
            value = await self.tick(dispatch=dispatch)
            if value.phase == phase and value.original_operation_id is None:
                return value
            self.assertNotIn(value.state, {"refused", "uncertain", "expired"}, value)
        self.fail(f"phase not reached: {phase}")

    async def human_action(self, key, action, parameters):
        view = self.core.observe(self.owner_token)
        request = {name: view[name] for name in ("session_id", "context_id", "target_id", "control_generation",
                                                "document_id", "document_generation")}
        self.core.submit(self.owner_token, operation_id=key, **request, observation_id=view["frame"]["observation_id"],
                         action=action, parameters=parameters)
        self.assertEqual((await self.core.execute_next())["state"], "applied")
        self.clock.advance(2)
        self.frame()

    async def takeover(self):
        result = await self.core.takeover(self.owner_token, "owner-takeover", control_generation=self.core.identity()["control_generation"])
        self.assertEqual(result["state"], "applied")

    async def correct(self, text=CORRECTION, key="owner-correction"):
        if self.adapter.delivery != 12:
            await self.human_action("owner-select", "click", {"x": 20, "y": 20, "button": "left"})
            await self.human_action("owner-express", "key", {"key": "arrow_down"})
        await self.human_action(key, "correction", {"text": text})

    async def handback(self):
        view = self.core.observe(self.owner_token)
        result = await self.core.handback(self.owner_token, "owner-handback", control_generation=view["control_generation"],
                                         observation_id=view["frame"]["observation_id"])
        self.assertEqual(result["state"], "applied")

    async def happy_result(self):
        await self.reach("await_human")
        await self.takeover()
        await self.correct()
        observed = await self.tick()
        self.assertEqual(observed.phase, "await_handback")
        await self.handback()
        return await self.reach("complete")

    async def test_complete_comparison_host_capture_stop_and_same_bytes_reopen(self):
        self.create()
        original_grants = deepcopy(self.core._state["grants"])
        done = await self.happy_result()
        result = json.loads(done.result)
        self.assertEqual((result["historical_standard"]["alpha"]["total"], result["historical_standard"]["beta"]["total"]), (125, 118))
        self.assertEqual(result["historical_standard"]["alpha_minus_beta"], 7)
        self.assertEqual((result["after_explicit_handback"]["alpha"]["total"], result["after_explicit_handback"]["beta"]["total"]), (132, 118))
        self.assertEqual(result["after_explicit_handback"]["alpha_minus_beta"], 14)
        self.assertEqual(result["owner_correction"]["actor_id"], "human")
        self.assertEqual(result["owner_correction"]["text"], CORRECTION)
        self.assertEqual([row["operation_id"] for row in result["original_operations"]], list(self.spec.operation_ids()))
        self.assertEqual(len([ticket for ticket in self.adapter.executions if ticket.actor_id == "driver"]), 3)
        self.assertEqual(len(self.requests), 3)
        self.assertTrue(all(request["action"] == "click" for request in self.requests))
        self.assertEqual(self.core._state["grants"], original_grants)
        self.assertLessEqual(len(done.result), 8192)
        self.assertNotIn(self.driver_token.encode(), done.result)
        self.assertNotIn(self.owner_token.encode(), done.result)
        count = len(self.calls)
        self.assertEqual(self.driver.step().result, done.result)
        self.assertEqual(len(self.calls), count)
        self.core.retain_result("result.json", done.result)  # Host capture before owner Stop.
        self.assertEqual((await self.core.stop(self.owner_token, "owner-stop"))["state"], "confirmed")
        self.assertEqual(self.core.read_result(self.driver_token, "result.json"), done.result)
        self.core.close()
        self.core = SessionControl.reopen(self.directory, self.clock)
        self.assertEqual(self.core._state["mode"], "lost")
        reader = self.core.issue_grant("reader", {"observe": self.clock.wall + 10000})
        self.assertEqual(self.core.read_result(reader, "result.json"), done.result)
        with self.assertRaises(SessionDenied):
            self.core.authorize(self.driver_token, "observe")

    async def test_process_claim_prevents_reconstruction_before_any_click_or_port_call(self):
        self.create()
        self.assertEqual(self.calls, [])
        with self.assertRaisesRegex(DriverDenied, "process_run_already_claimed"):
            ComparisonDriver(replace(self.spec, limits=DriverLimits(steps=100)), self.port, self.clock)
        self.assertEqual(self.calls, [])
        with self.assertRaises(AttributeError):
            self.driver.spec = replace(self.spec, expires_at_ms=self.spec.expires_at_ms + 1)

    async def test_original_ids_ignore_all_retry_budget_and_authority_generation_inputs(self):
        changed = replace(self.spec, started_at_ms=self.spec.started_at_ms + 1, expires_at_ms=self.spec.expires_at_ms - 1,
                          owner_actor_id="other-owner", limits=DriverLimits(steps=12, clicks=2))
        self.assertEqual(changed.operation_ids(), self.spec.operation_ids())
        for name in ("session_id", "context_id", "target_id", "backend_epoch", "driver_actor_id"):
            self.assertNotEqual(replace(self.spec, **{name: "other"}).operation_ids(), self.spec.operation_ids())

    async def test_rate_duplicate_step_and_reentrant_callback_do_not_create_another_effect(self):
        self.create()
        first = self.driver.step()
        calls = len(self.calls)
        self.assertEqual(first.port_calls, 2)
        self.assertEqual(self.driver.step().reason, "step_too_soon")
        self.assertEqual(len(self.calls), calls)
        await self.reach("initial_link")
        await self.tick()  # The separate current-key absence probe.
        busy = []
        self.observe_hook = lambda view: (busy.append(self.driver.step()), view)[1]
        value = await self.tick(dispatch=False)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(value.clicks, 1)
        self.assertEqual(busy[0].reason, "step_busy")
        self.assertEqual(self.adapter.executions, [])

    async def test_unknown_lookup_is_not_original_absence(self):
        self.create()
        self.status_hook = lambda _: (_ for _ in ()).throw(RuntimeError("private token/path"))
        value = await self.tick()
        self.assertEqual((value.state, value.reason, value.port_calls), ("refused", "port_unavailable", 1))
        self.assertEqual(self.requests, [])
        self.assertNotIn("private", repr(value))

    async def test_existing_cancelled_original_refuses_startup(self):
        key = self.spec.operation_ids()[0]
        view = self.core.observe(self.driver_token)
        request = {name: view[name] for name in ("session_id", "context_id", "target_id", "control_generation", "document_id", "document_generation")}
        self.core.submit(self.driver_token, operation_id=key, **request, observation_id=view["frame"]["observation_id"],
                         action="click", parameters={"x": 100, "y": 80, "button": "left"})
        await self.takeover()
        self.assertEqual(self.core.operation(self.driver_token, key)["state"], "not_applied")
        self.create()
        value = await self.tick()
        self.assertEqual(value.reason, "original_run_already_used")
        self.assertEqual(self.requests, [])
        self.assertEqual(self.adapter.executions, [])

    async def test_future_original_is_rechecked_after_startup_probes(self):
        self.create()
        await self.reach("return_to_alpha")
        view = self.core.observe(self.driver_token)
        request = {name: view[name] for name in ("session_id", "context_id", "target_id", "control_generation", "document_id", "document_generation")}
        self.core.submit(self.driver_token, operation_id=self.spec.operation_ids()[1], **request,
                         observation_id=view["frame"]["observation_id"], action="click", parameters={"x": 100, "y": 80, "button": "left"})
        value = await self.tick(dispatch=False)
        self.assertEqual(value.reason, "original_run_already_used")
        self.assertEqual(len(self.requests), 1)

    async def test_lost_submit_before_admission_uses_only_original_status(self):
        self.create()
        self.submit_hook = lambda _: (_ for _ in ()).throw(RuntimeError("lost before acceptance"))
        for _ in range(10):
            value = await self.tick()
            if value.state == "uncertain":
                break
        self.assertEqual(value.state, "uncertain")
        original = value.original_operation_id
        for _ in range(3):
            value = await self.tick()
        self.assertEqual((value.state, value.original_operation_id, len(self.requests)), ("uncertain", original, 1))
        self.assertEqual(self.calls[-3:][0][0], "operation")
        self.assertTrue(all(row[1] == original for row in self.calls[-3:]))
        self.assertEqual(self.adapter.executions, [])

    async def test_lost_accepted_reply_late_known_outcome_never_resumes_or_rekeys(self):
        self.create()
        def lost(request):
            self.assertEqual(self.driver._pending["request"], request)
            self.core.submit(self.driver_token, **request)
            raise RuntimeError("lost after durable acceptance")
        self.submit_hook = lost
        for _ in range(10):
            value = await self.tick()
            if value.state == "uncertain":
                break
        original = value.original_operation_id
        for _ in range(3):
            value = await self.tick()
        self.assertEqual((value.state, value.last_known_operation_state), ("uncertain", "applied"))
        self.assertEqual(value.original_operation_id, original)
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(len(self.adapter.executions), 1)
        self.assertIsNone(value.result)

    async def test_raw_core_acknowledgement_never_crosses_the_driver_port(self):
        self.create()
        self.submit_hook = lambda request: self.core.submit(self.driver_token, **request)
        for _ in range(10):
            value = await self.tick()
            if value.state == "uncertain":
                break
        self.assertEqual(value.reason, "invalid_projection")
        value = await self.tick()
        self.assertEqual(value.last_known_operation_state, "applied")
        self.assertEqual(value.state, "uncertain")
        self.assertEqual(len(self.requests), 1)

    async def test_expiry_during_observation_prevents_submit_and_later_calls(self):
        self.create()
        await self.reach("initial_link")
        await self.tick()
        def late(view):
            self.clock.advance(300000)
            return view
        self.observe_hook = late
        value = await self.tick()
        self.assertEqual(value.state, "expired")
        self.assertEqual(self.requests, [])
        count = len(self.calls)
        self.driver.step()
        self.assertEqual(len(self.calls), count)

    async def test_late_submit_ack_retains_knowledge_without_continuation(self):
        self.create()
        def late(request):
            value = _ack(self.core.submit(self.driver_token, **request))
            self.clock.advance(300000)
            return value
        self.submit_hook = late
        for _ in range(10):
            value = await self.tick(dispatch=False)
            if value.state == "expired":
                break
        self.assertEqual(value.state, "expired")
        self.assertEqual(value.last_known_operation_state, "queued")
        self.assertEqual(value.original_operation_id, self.spec.operation_ids()[0])
        count = len(self.calls)
        self.driver.step()
        self.assertEqual(len(self.calls), count)
        self.assertEqual(self.adapter.executions, [])

    async def test_applied_click_waits_for_a_strictly_newer_document(self):
        self.create()
        for _ in range(10):
            value = await self.tick()
            if value.original_operation_id is not None:
                break
        source_generation = self.requests[0]["document_generation"]
        self.observe_hook = lambda view: view | {"document_generation": source_generation}
        value = await self.tick()
        self.assertEqual(value.reason, "new_document_required")
        self.assertEqual(len(self.requests), 1)
        self.observe_hook = None
        value = await self.tick()
        self.assertEqual(value.phase, "return_to_alpha")

    async def test_no_driver_mutation_while_human_owns_control(self):
        self.create()
        await self.reach("await_human")
        await self.takeover()
        for _ in range(3):
            value = await self.tick()
            self.assertEqual(value.reason, "declared_correction_required")
        self.assertEqual(len(self.requests), 2)
        self.assertEqual(self.core._state["mode"], "human")

    async def test_a_later_retraction_cannot_be_hidden_by_an_earlier_matching_correction(self):
        self.create()
        await self.reach("await_human")
        await self.takeover()
        await self.correct()
        await self.tick()
        await self.correct("Use standard delivery instead.", "owner-retraction")
        await self.handback()  # Driver did not poll between the retraction and handback.
        value = await self.tick()
        self.assertEqual(value.reason, "observed_correction_required")
        self.assertEqual(len(self.requests), 2)
        self.assertIsNone(value.result)

    async def test_missed_human_turn_remains_an_honest_wait_without_resuming(self):
        self.create()
        await self.reach("await_human")
        await self.takeover()
        await self.correct()
        await self.handback()
        for _ in range(3):
            value = await self.tick()
        self.assertEqual(value.reason, "explicit_human_turn_not_observed")
        self.assertEqual(value.state, "waiting")
        self.assertEqual(len(self.requests), 2)

    async def test_closed_projection_rejects_aliases_foreign_scopes_and_invalid_equations(self):
        view = self.app._observation(self.driver_token)
        changes = [lambda x: x.update(target_id="foreign"), lambda x: x.update(backend_epoch="other"),
            lambda x: x.update(control_generation=True), lambda x: x.update(schema_version=True),
            lambda x: x["frame"]["projection"]["fields"].update(price=True),
            lambda x: x["frame"]["projection"]["fields"].update(total=126),
            lambda x: x["frame"]["projection"]["fields"].update(next_url="http://127.0.0.1:8766/foreign"),
            lambda x: x["frame"]["projection"]["fields"].update(next_x=800),
            lambda x: x["frame"].update(private_page_handle="not public")]
        for change in changes:
            broken = deepcopy(view)
            change(broken)
            with self.subTest(change=change), self.assertRaises((DriverDenied, SessionDenied)):
                subject._observation(broken, self.spec, self.clock.wall)
        self.assertEqual(self.adapter.executions, [])

    async def test_stale_observation_cannot_be_used_for_a_click(self):
        self.create()
        await self.reach("initial_link")
        await self.tick()
        def stale(view):
            view["frame"]["captured_at_ms"] = self.clock.wall - 5001
            return view
        self.observe_hook = stale
        value = await self.tick()
        self.assertEqual(value.reason, "fresh_observation_required")
        self.assertEqual(self.requests, [])

    async def test_step_and_port_caps_are_charged_before_calls(self):
        self.create(limits=DriverLimits(port_calls=1))
        value = await self.tick()
        self.assertEqual((value.state, value.reason, value.port_calls), ("refused", "port_budget", 1))
        self.assertEqual(len(self.calls), 1)
        self.assertEqual(self.requests, [])

    async def test_step_cap_survives_waiting(self):
        self.create(limits=DriverLimits(steps=1))
        await self.tick()
        value = await self.tick()
        self.assertEqual((value.reason, value.steps, value.port_calls), ("step_budget", 1, 2))

    async def test_result_cap_prevents_host_capture_of_an_oversized_proposal(self):
        self.create(limits=DriverLimits(result_bytes=1))
        await self.reach("await_human")
        await self.takeover()
        await self.correct()
        await self.tick()
        await self.handback()
        for _ in range(10):
            value = await self.tick()
            if value.state == "refused":
                break
        self.assertEqual(value.reason, "result_budget")
        self.assertIsNone(value.result)
        self.assertEqual(len(self.requests), 3)
        self.assertEqual(self.core._state["results"], {})

    async def test_clock_rollback_denies_before_any_port_call(self):
        self.create()
        self.clock.advance(-1)
        value = self.driver.step()
        self.assertEqual(value.reason, "clock_rollback")
        self.assertEqual(self.calls, [])

    async def test_original_monotonic_deadline_is_not_rebased_at_late_construction(self):
        # The wall clock has frozen since the host established the original
        # deadline, while 280 seconds actually elapsed on its monotonic clock.
        self.clock.mono += 280
        self.create()
        self.clock.mono += 10
        value = self.driver.step()
        self.assertEqual(value.state, "expired")
        self.assertEqual(self.calls, [])

    async def _interrupted_submit(self, exception_type):
        self.create()
        await self.reach("initial_link")
        await self.tick()
        def interrupted(request):
            self.core.submit(self.driver_token, **request)
            raise exception_type()
        self.submit_hook = interrupted
        with self.assertRaises(exception_type):
            await self.tick(dispatch=False)
        original = self.spec.operation_ids()[0]
        self.assertEqual(self.driver._pending["request"]["operation_id"], original)
        self.assertTrue(self.driver._uncertain)
        await self.core.execute_next()
        self.clock.advance(2)
        self.frame()
        value = await self.tick()
        self.assertEqual((value.state, value.last_known_operation_state), ("uncertain", "applied"))
        self.assertEqual(value.original_operation_id, original)
        self.assertEqual(len(self.requests), 1)
        self.assertIsNone(value.result)

    async def test_cancelled_callback_preserves_sticky_original_uncertainty(self):
        await self._interrupted_submit(asyncio.CancelledError)

    async def test_keyboard_interrupt_preserves_sticky_original_uncertainty(self):
        await self._interrupted_submit(KeyboardInterrupt)

    async def test_late_status_can_improve_facts_but_cannot_continue_after_expiry(self):
        self.create()
        for _ in range(10):
            value = await self.tick(dispatch=False)
            if value.original_operation_id:
                break
        original = value.original_operation_id
        def late(key):
            value = _ack(self.core.operation(self.driver_token, key))
            self.clock.advance(300000)
            return value
        self.status_hook = late
        before = len(self.calls)
        value = await self.tick(dispatch=False)
        self.assertEqual((value.state, value.last_known_operation_state), ("expired", "queued"))
        self.assertEqual(value.original_operation_id, original)
        self.assertEqual(len(self.calls) - before, 1)
        self.assertEqual(len(self.requests), 1)

    async def test_actual_core_unknown_then_late_action_does_not_resume_driver(self):
        self.create()
        for _ in range(10):
            value = await self.tick(dispatch=False)
            if value.original_operation_id:
                break
        original = value.original_operation_id
        self.adapter.execute_gate = asyncio.Event()
        self.assertEqual((await self.core.execute_next())["state"], "unknown")
        value = await self.tick(dispatch=False)
        self.assertEqual((value.state, value.last_known_operation_state), ("uncertain", "unknown"))
        self.clock.advance(30)
        native_fixture_task = self.core._tasks[original]
        self.adapter.execute_gate.set()
        await native_fixture_task
        await asyncio.sleep(0)
        value = await self.tick(dispatch=False)
        self.assertEqual((value.state, value.last_known_operation_state), ("uncertain", "applied"))
        self.assertEqual(value.original_operation_id, original)
        self.assertEqual(self.core._state["mode"], "fenced")
        self.assertEqual(len(self.requests), 1)

    async def test_core_rechecks_control_grant_expiring_during_observation(self):
        self.create()
        await self.reach("initial_link")
        await self.tick()
        self.driver_token = self.core.issue_grant("driver", {"observe": self.clock.wall + 10000, "control": self.clock.wall + 500})
        def delayed(view):
            self.clock.advance(500)
            return view
        self.observe_hook = delayed
        value = await self.tick()
        self.assertEqual((value.state, value.reason), ("uncertain", "port_unavailable"))
        self.assertEqual(len(self.requests), 1)
        self.assertEqual(self.adapter.executions, [])
        self.assertEqual(self.core._state["operations"], {})

    async def test_click_cap_survives_human_wait_and_handback(self):
        self.create(limits=DriverLimits(clicks=2))
        await self.reach("await_human")
        await self.takeover()
        await self.correct()
        await self.tick()
        await self.handback()
        for _ in range(6):
            value = await self.tick()
            if value.state == "refused":
                break
        self.assertEqual((value.reason, value.clicks), ("click_budget", 2))
        self.assertEqual(len(self.requests), 2)

    async def test_slow_call_does_not_compress_the_following_step_interval(self):
        self.create()
        def slow(_):
            self.clock.advance(100)
            return ABSENT
        self.status_hook = slow
        value = self.driver.step()
        self.assertEqual(value.port_calls, 2)
        before = len(self.calls)
        self.assertEqual(self.driver.step().reason, "step_too_soon")
        self.clock.advance(249)
        self.assertEqual(self.driver.step().reason, "step_too_soon")
        self.assertEqual(len(self.calls), before)

    async def test_invalid_original_deadlines_fail_before_claim_or_port_io(self):
        for value in (True, float("nan"), float("inf"), self.clock.mono, self.clock.mono + 301):
            with self.subTest(value=value), self.assertRaises(DriverDenied):
                ComparisonDriver(replace(self.spec, deadline_monotonic=value), self.port, self.clock)
        self.assertEqual(self.calls, [])
        self.create()  # Invalid declarations did not claim an otherwise unused process.

    async def test_duplicate_projected_correction_identity_is_ambiguous(self):
        await self.takeover()
        await self.correct()
        view = self.app._observation(self.driver_token)
        view["corrections"].append(deepcopy(view["corrections"][0]))
        with self.assertRaisesRegex(DriverDenied, "ambiguous_correction"):
            subject._observation(view, self.spec, self.clock.wall)

    async def test_post_return_clock_interruption_preserves_sticky_original(self):
        self.create()
        await self.reach("initial_link")
        await self.tick()
        armed = [False]
        original_clock = self.clock.monotonic
        def submit_then_arm(request):
            result = _ack(self.core.submit(self.driver_token, **request))
            armed[0] = True
            return result
        def interrupt_once():
            if armed[0]:
                armed[0] = False
                raise KeyboardInterrupt()
            return original_clock()
        self.submit_hook = submit_then_arm
        with patch.object(self.clock, "monotonic", side_effect=interrupt_once):
            with self.assertRaises(KeyboardInterrupt):
                await self.tick(dispatch=False)
        self.assertTrue(self.driver._uncertain)
        await self.core.execute_next()
        self.clock.advance(2)
        self.frame()
        value = await self.tick()
        self.assertEqual((value.state, value.last_known_operation_state), ("uncertain", "applied"))
        self.assertEqual(value.original_operation_id, self.spec.operation_ids()[0])
        self.assertEqual(len(self.requests), 1)

    async def final_beta_pending(self):
        await self.reach("await_human")
        await self.takeover()
        await self.correct()
        await self.tick()
        await self.handback()
        for _ in range(10):
            value = await self.tick()
            if len(self.requests) == 3:
                return value
        self.fail("third original link was not submitted")

    async def test_frozen_wall_during_final_observe_cannot_publish_a_stale_result(self):
        self.create()
        await self.final_beta_pending()
        def delayed(view):
            self.clock.mono += 6
            return view
        self.observe_hook = delayed
        value = await self.tick()
        self.assertEqual((value.state, value.reason), ("waiting", "fresh_observation_required"))
        self.assertEqual(value.original_operation_id, self.spec.operation_ids()[2])
        self.assertEqual(value.last_known_operation_state, "applied")
        self.assertIsNone(value.result)
        self.assertIsNone(self.core.observe(self.driver_token)["frame"])
        self.observe_hook = None
        done = await self.tick()  # A new observation, never another click.
        self.assertEqual(done.state, "completed")
        self.assertEqual(len(self.requests), 3)

    async def test_quote_processing_age_is_rechecked_before_submit(self):
        self.create()
        await self.reach("initial_link")
        await self.tick()
        original_quote = self.driver._quote
        def delayed(view):
            value = original_quote(view)
            self.clock.mono += 6
            return value
        with patch.object(self.driver, "_quote", side_effect=delayed):
            value = await self.tick()
        self.assertEqual(value.reason, "fresh_observation_required")
        self.assertEqual(self.requests, [])
        self.assertEqual(value.clicks, 0)

    async def test_result_serialization_age_is_rechecked_without_replaying_the_link(self):
        self.create()
        await self.final_beta_pending()
        canonical = subject.canonical
        def delayed(value):
            raw = canonical(value)
            if value.get("task") == "alpha-beta-express-comparison":
                self.clock.mono += 6
            return raw
        with patch.object(subject, "canonical", side_effect=delayed):
            value = await self.tick()
        self.assertEqual(value.reason, "fresh_observation_required")
        self.assertIsNone(value.result)
        self.assertEqual(value.last_known_operation_state, "applied")
        done = await self.tick()
        self.assertEqual(done.state, "completed")
        self.assertEqual(len(self.requests), 3)

    def test_actual_fixture_sources_remain_the_reviewed_inputs(self):
        base = Path(__file__).resolve().parents[1] / "fixtures" / "browser-engine"
        expected = {"alpha.html": "25c477fbaf017fc40b90e8f8dbc0ae9c7b8c90a63bb802d60f75662c9a5e253c",
                    "beta.html": "3b081cd51fd41673dca4ff787a5f9d8952ce104c20c0445fa7097f80dc5d9abd"}
        for name, digest in expected.items():
            self.assertEqual(hashlib.sha256((base / name).read_bytes()).hexdigest(), digest)
