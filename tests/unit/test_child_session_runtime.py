"""Actual Unix/HTTP model fences with explicit canonical and execution fixtures.

The host test UID represents the child socket identity through a named peer-UID
fixture. Distinct guest UIDs and real child processes are qualified separately
by test_managed_cold_sessions_runtime.py. SQLite, listeners, shared inference
gates, HTTP dispatch and service ownership here are production objects.
"""

from contextlib import contextmanager
from dataclasses import replace
import json
import os
from pathlib import Path
import socket
import struct
import threading
import time
from types import SimpleNamespace

import pytest

from src.agent.child_outcome import OutcomeClient
from src.agent.child_tools import ControlClient
from src.agent.managed_runner import BrokerClient, BrokerError
from src.polyphony.managed_client import AuthorityUnavailable
from src.worker.child_broker import ChildBroker, _ChildModelContext
from src.worker.child_journal import ChildJournal
from src.worker.child_outcomes import work_outcome
from src.worker.child_sessions import SESSION_PROTOCOL
import src.worker.child_supervisor as supervisor_module
from src.worker.child_supervisor import ChildSupervisor
from src.worker.child_types import canonical
from src.worker.lifecycle import LifecycleConflict
from src.worker.model_broker import BrokerDenied, ModelBroker, ModelPolicy
from tests.unit.test_child_authority_contract import context, policy
from tests.unit.test_child_outcome_socket import exchange
from tests.unit.test_child_supervisor import FixtureAuthority, FixtureDriver, FixtureLifecycle
from tests.unit.test_managed_agent import MESSAGES, TEST_TOKEN, message, provider, response


def eventually(predicate, seconds=3):
    until = time.monotonic() + seconds
    while time.monotonic() < until:
        value = predicate()
        if value:
            return value
        time.sleep(0.01)
    assert predicate(), "bounded fixture condition did not become true"


class SessionAuthorityFixture(FixtureAuthority):
    def call(self, operation, scope, attempt_id, **payload):
        result = super().call(operation, scope, attempt_id, **payload)
        if operation in {"grant", "permission", "turn"}:
            result = dict(result)
            result["remaining_seconds"] = min(
                result["binding"]["allocated_seconds"],
                max(0, self.root.monotonic_deadline - time.monotonic()),
            )
            result["launch_allowed"] = result["remaining_seconds"] > 0
        elif operation == "observe":
            manifest = json.loads(self.artifacts[(payload["child_id"], "manifest")])
            result["child"]["initial_outcome"] = manifest["work_outcome"] | {
                "artifacts": payload["artifacts"],
                "canonical_committed": True,
                "release_authorized": False,
            }
        return result


class SessionDriverFixture(FixtureDriver):
    """Explicit exec observations, with the actual launch cutoff retained."""

    def launch(self, root, child, cutoff):
        super().launch(root, child, cutoff)
        self.supervisor.journal.update(
            root.worker_id, child["child_id"], armed_deadline=cutoff
        )

    def final_capture(self, root, child, receipt):
        result = super().final_capture(root, child, receipt)
        binding = json.loads(child["grant_json"])["binding"]
        report = (
            None if child["outcome_report"] is None
            else json.loads(child["outcome_report"])
        )
        result["manifest"] = canonical({
            "work_outcome": work_outcome(binding, report),
        })
        return result


class HostSessionFixture:
    def __init__(self, path, endpoint):
        self.path = path
        self.root = replace(
            context(),
            monotonic_deadline=time.monotonic() + 60,
            boot_id=Path("/proc/sys/kernel/random/boot_id").read_text().strip(),
        )
        self.policy = replace(
            policy(), outcome_protocol="initial-v1", session_protocol=SESSION_PROTOCOL
        )
        self.key = (
            self.root.spec.deployment_id, self.root.spec.repository, self.root.spec.profile
        )
        self.models = {self.key: ModelPolicy(
            endpoint, "fixture", "env:MOCK_MODEL_TOKEN",
            max_calls=16, max_output_tokens=32, max_total_output_tokens=512,
            request_timeout_seconds=5,
        )}
        self.authority = SessionAuthorityFixture(self.root)
        self.lifecycle = FixtureLifecycle(self.root)
        self.descriptors = []
        self.open()

    def open(self):
        self.broker = ModelBroker(
            self.path / "models", self.models, lambda _: 50,
            peer_uids={self.key: os.getuid()},
        )
        directory = self.broker.prepare_worker(self.root.worker_id, self.root.spec)
        self.broker.bind_attempt(
            self.root.worker_id, self.root.spec, self.root.attempt_id, 50,
            deadline_monotonic=self.root.monotonic_deadline,
        )
        self.children = ChildSupervisor(
            self.path / "children", {self.key: self.policy}, None,
            self.lifecycle, SimpleNamespace(), self.broker, lambda _: 50, lambda _: True,
        )
        self.children.authority = self.authority
        self.children.driver = SessionDriverFixture(self.children)
        self.children.endpoints = ChildBroker(self.children, self.broker)
        self.broker.child_supervisor = self.children
        self.children.journal.prepare(self.root.worker_id, self.root.spec, self.policy)
        self.root = self.children.journal.bind(self.root)
        self.children.endpoints.prepare_root(self.root.worker_id, self.root.spec, directory)
        self.directory = directory
        self.control = ControlClient(self.socket_path(directory, "control.sock"), timeout_seconds=5)

    def socket_path(self, directory, name):
        descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
        self.descriptors.append(descriptor)
        return f"/proc/self/fd/{descriptor}/{name}"

    def child_socket(self, child_id, name):
        return self.socket_path(self.directory / "children" / child_id, name)

    def start(self):
        value = self.control.request(
            "session_start", request_id="original-start",
            instructions="Ask the parent to select a value.", seconds=20,
            max_turns=2, capabilities=["python"],
        )
        return value["session_id"], value["rounds"][0]["child_id"]

    def report_and_return(self, child_id):
        client = OutcomeClient(self.child_socket(child_id, "outcome.sock"))
        receipt = client.report("needs_clarification", "Which value is approved?")
        self.children.journal.update(
            self.root.worker_id, child_id, phase="exec_returned", exit_code=0
        )
        return client, receipt

    def queue(self, session_id):
        state = self.control.request("session_status", session_id=session_id)
        return self.control.request(
            "session_followup", request_id="original-followup",
            session_id=session_id, predecessor_digest=state["predecessor_digest"],
            instructions="Use the explicit approved value.", seconds=20, max_turns=2,
        )

    def rounds(self, session_id):
        return self.children.sessions.get(self.root, self.policy, session_id)["rounds"]

    def calls(self):
        with self.broker.connection() as db:
            return [dict(row) for row in db.execute("SELECT * FROM calls ORDER BY rowid")]

    def close(self):
        self.children.close()
        self.broker.close()
        for descriptor in self.descriptors:
            os.close(descriptor)
        self.descriptors.clear()


@contextmanager
def host_stack(tmp_path, monkeypatch, endpoint):
    monkeypatch.setenv("MOCK_MODEL_TOKEN", TEST_TOKEN)
    # A named socket peer fixture, not a new production option. The journal
    # retains real distinct policy UIDs; Docker tests use those actual UIDs.
    monkeypatch.setattr(
        _ChildModelContext, "peer_uid_for_worker",
        lambda self, child_id: (self._bound(child_id), os.getuid())[1],
    )
    stack = HostSessionFixture(tmp_path, endpoint)
    try:
        yield stack
    finally:
        stack.close()


def start_call(stack, child_id):
    results, errors = [], []
    client = BrokerClient(stack.child_socket(child_id, "model.sock"), timeout_seconds=5)

    def call():
        try:
            results.append(client.complete(MESSAGES, "original-child-call"))
        except BaseException as error:
            errors.append(error)

    caller = threading.Thread(target=call, name="cold-admitted-model-fixture")
    caller.start()
    return caller, results, errors


def grants(stack):
    return [payload for operation, payload in stack.authority.events if operation == "grant"]


@pytest.mark.parametrize("hold_at", ["provider", "after_admission"])
def test_followup_waits_for_admitted_call_and_original_socket_owner(
    tmp_path, monkeypatch, hold_at
):
    entered, release = threading.Event(), threading.Event()

    def held_provider(handler, requests):
        if hold_at == "provider":
            entered.set()
            assert release.wait(5)
        response(handler, message())

    with provider(held_provider) as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            if hold_at == "after_admission":
                original = stack.broker._complete_serial

                def pause_after_admission(worker_id, payload, child_id=None):
                    entered.set()
                    assert release.wait(5)
                    return original(worker_id, payload, child_id)

                monkeypatch.setattr(stack.broker, "_complete_serial", pause_after_admission)
            caller, results, errors = start_call(stack, first)
            pending = None
            try:
                assert entered.wait(3)
                assert caller.is_alive() and not release.is_set()
                original_endpoint = stack.children.endpoints.children[first]
                # Positively queue a second accepted request behind the active
                # handler. Closing admission must discard it without parsing or
                # reserving another model/canonical turn.
                pending = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                pending.settimeout(2)
                pending.connect(stack.child_socket(first, "model.sock"))
                body = json.dumps({
                    "schema_version": 1, "request_id": "not-yet-admitted",
                    "messages": MESSAGES,
                }).encode()
                pending.sendall(struct.pack("!I", len(body)) + body)

                def queued():
                    with original_endpoint.server._condition:
                        return len(original_endpoint.server._pending) == 1

                eventually(queued)
                _, retained = stack.report_and_return(first)
                before = stack.calls()
                assert len(before) == (1 if hold_at == "provider" else 0)
                if before:
                    assert before[0]["status"] == "reserved"
                value = stack.queue(sid)
                assert value["phase"] == "followup_queued"
                assert value["model_fence"] == "requested"
                assert original_endpoint.thread.is_alive()
                assert original_endpoint.stop_requested.is_set()
                with original_endpoint.server._condition:
                    assert not original_endpoint.server._pending
                try:
                    assert pending.recv(1) == b""
                except ConnectionResetError:
                    pass
                stack.children.reconcile(stack.root.worker_id)
                assert len(grants(stack)) == len(stack.authority.grants) == 1
                assert stack.calls() == before
                assert len(stack.children.driver.launches) == 1
                assert caller.is_alive() and not release.is_set()
                release.set()
                caller.join(5)
                assert not caller.is_alive() and not errors
                assert results[0]["role"] == "assistant"
                eventually(lambda: not original_endpoint.thread.is_alive())
                assert stack.calls()[0]["status"] == "complete"
                assert len(requests) == len(stack.calls()) == 1
                assert sum(event == "turn" for event, _ in stack.authority.events) == 1
                # A new request, including a retry, is rejected at the new-call
                # gate after closure. The already-admitted request above finished.
                for request_id in ("original-child-call", "fresh-after-closure"):
                    with pytest.raises(BrokerDenied, match="not_authorized"):
                        stack.broker.complete_child(stack.root.worker_id, first, {
                            "schema_version": 1, "request_id": request_id,
                            "messages": MESSAGES,
                        })
                assert len(requests) == len(stack.calls()) == 1
                gate = stack.broker.inference_locks[stack.root.worker_id]
                assert gate.acquire(blocking=False)
                try:
                    stack.children.reconcile(stack.root.worker_id)
                    assert stack.rounds(sid)[1]["state"] == "queued"
                    assert len(grants(stack)) == 1
                finally:
                    gate.release()
                original_authority_call = stack.authority.call
                delivery_locks = []

                def check_successor_delivery(operation, scope, attempt_id, **payload):
                    if operation == "grant":
                        # Network delivery must run under the original operation
                        # lock, after releasing the common inference effect gate.
                        operation_lock = stack.children._operation_lock(
                            stack.root.worker_id
                        )
                        operation_free = operation_lock.acquire(blocking=False)
                        if operation_free:
                            operation_lock.release()
                        model_free = gate.acquire(blocking=False)
                        if model_free:
                            gate.release()
                        delivery_locks.append((operation_free, model_free))
                        assert not operation_free and model_free
                    return original_authority_call(
                        operation, scope, attempt_id, **payload
                    )

                monkeypatch.setattr(stack.authority, "call", check_successor_delivery)
                stack.children.reconcile(stack.root.worker_id)
                assert delivery_locks == [(False, True)]
                rounds = stack.rounds(sid)
                assert rounds[0]["fence_established"] == 1
                assert rounds[1]["child_id"] != first
                assert len(grants(stack)) == len(stack.authority.grants) == 2
                assert len(stack.children.driver.launches) == 2
                assert len(requests) == len(stack.calls()) == 1
                assert rounds[1]["predecessor_value"]["work_outcome"]["report"] == retained["report"]
            finally:
                release.set()
                caller.join(5)
                if pending is not None:
                    pending.close()
                assert not caller.is_alive()


def test_restore_preserves_closed_model_and_original_outcome_replay(
    tmp_path, monkeypatch
):
    with provider() as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            client, receipt = stack.report_and_return(first)
            stack.queue(sid)
            endpoint_owner = stack.children.endpoints.children[first]
            eventually(lambda: not endpoint_owner.thread.is_alive())
            original_exec = stack.rounds(sid)[0]["child"]["exec_id"]
            retained = stack.rounds(sid)[1]["request_json"]
            stack.close()
            stack.open()
            stack.children.endpoints.restore(stack.root.worker_id)
            assert first not in stack.children.endpoints.children
            assert stack.children.endpoints.outcomes[first].thread.is_alive()
            assert not (stack.directory / "children" / first / "model.sock").exists()
            retried = exchange(stack.child_socket(first, "outcome.sock"), {
                "schema_version": 1, "request_id": client.request_key,
                "outcome": "needs_clarification", "summary": "Which value is approved?",
            })
            assert retried == receipt
            assert stack.rounds(sid)[1]["request_json"] == retained
            assert stack.rounds(sid)[0]["child"]["exec_id"] == original_exec
            assert not requests and not stack.calls()
            stack.children.reconcile(stack.root.worker_id)
            assert len(stack.authority.grants) == 2
            assert len(stack.children.driver.launches) == 1
            assert stack.rounds(sid)[0]["child"]["exec_id"] == original_exec
            assert not requests


def test_bounded_close_keeps_both_service_leases_until_active_handler_exits(
    tmp_path, monkeypatch
):
    entered, release = threading.Event(), threading.Event()

    def delayed(handler, requests):
        entered.set()
        assert release.wait(5)
        response(handler, message())

    with provider(delayed) as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            caller, _, errors = start_call(stack, first)
            try:
                assert entered.wait(3)
                stack.report_and_return(first)
                stack.queue(sid)
                child_lock = stack.children.journal.service_lock
                model_lock = stack.broker._service_lock
                stack.children.close()
                stack.broker.close()
                assert caller.is_alive() and not release.is_set()
                assert not child_lock.closed and not model_lock.closed
                with pytest.raises(ValueError, match="another child supervisor"):
                    ChildJournal(tmp_path / "children")
                with pytest.raises(ValueError, match="another"):
                    ModelBroker(
                        tmp_path / "models", stack.models, lambda _: 50,
                        peer_uids={stack.key: os.getuid()},
                    )
                assert len(grants(stack)) == 1 and len(requests) == 1
            finally:
                release.set()
                caller.join(5)
                assert not caller.is_alive()
            eventually(lambda: child_lock.closed and model_lock.closed)
            assert errors and all(isinstance(error, BrokerError) for error in errors)
            assert stack.calls()[0]["status"] == "complete"
            stack.open()
            stack.children.endpoints.restore(stack.root.worker_id)
            assert first not in stack.children.endpoints.children
            assert stack.rounds(sid)[1]["state"] == "queued"
            assert len(requests) == 1


@pytest.mark.parametrize("status", ["reserved", "uncertain", "child_authorizing"])
def test_unresolved_original_model_rows_block_successor_without_refund(
    tmp_path, monkeypatch, status
):
    with provider() as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            stack.report_and_return(first)
            stack.queue(sid)
            eventually(lambda: not stack.children.endpoints.children[first].thread.is_alive())
            with stack.broker.connection() as db:
                db.execute(
                    "INSERT INTO calls VALUES(?,?,?,?,?,?,?)",
                    (
                        stack.root.worker_id, stack.root.attempt_id,
                        "retained-original-call", "a" * 64, 32, status, None,
                    ),
                )
            before = stack.calls()
            stack.children.reconcile(stack.root.worker_id)
            result = stack.children.sessions.project(stack.root, stack.policy, sid)
            assert result["phase"] == "uncertain" and result["reason"] == "model_unresolved"
            assert stack.rounds(sid)[1]["state"] == "queued"
            assert stack.calls() == before and not requests
            assert len(grants(stack)) == len(stack.children.driver.launches) == 1
            stack.close()
            stack.open()
            stack.children.endpoints.restore(stack.root.worker_id)
            stack.children.reconcile(stack.root.worker_id)
            assert stack.calls() == before and not requests
            assert stack.children.sessions.project(
                stack.root, stack.policy, sid
            )["reason"] == "model_unresolved"
            assert len(stack.authority.grants) == 1


def test_actual_host_launch_uses_earlier_retained_predecessor_cutoff(
    tmp_path, monkeypatch
):
    with provider() as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            earlier = time.monotonic() + 10
            stack.children.journal.update(
                stack.root.worker_id, first, armed_deadline=earlier
            )
            stack.report_and_return(first)
            stack.queue(sid)
            eventually(lambda: not stack.children.endpoints.children[first].thread.is_alive())
            stack.children.reconcile(stack.root.worker_id)
            first_round, second = stack.rounds(sid)
            assert first_round["child"]["armed_deadline"] == earlier
            assert second["child"]["deadline"] > earlier + 5
            assert stack.root.monotonic_deadline > earlier + 20
            assert second["child"]["armed_deadline"] <= earlier
            assert stack.children.driver.launches[-1][1] <= earlier
            assert not requests and not stack.calls()


def test_lost_successor_grant_replays_after_close_when_original_interval_expired(
    tmp_path, monkeypatch
):
    with provider() as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            earlier = time.monotonic() + 10
            stack.children.journal.update(
                stack.root.worker_id, first, armed_deadline=earlier
            )
            stack.report_and_return(first)
            stack.queue(sid)
            eventually(lambda: not stack.children.endpoints.children[first].thread.is_alive())
            stack.authority.lose_grant = True
            with pytest.raises(AuthorityUnavailable, match="lost grant"):
                stack.children.reconcile(stack.root.worker_id)
            retained = stack.rounds(sid)[1]
            assert retained["state"] == "linked" and retained["child_id"] is None
            original_request = grants(stack)[-1]["request_key"]
            allocated = list(stack.authority.grants.values())[-1]["binding"]["child_id"]
            assert len(stack.authority.grants) == 2
            marker = len(stack.authority.events)
            monkeypatch.setattr(
                supervisor_module, "time",
                SimpleNamespace(monotonic=lambda: earlier + 1),
            )
            assert earlier + 1 < stack.root.monotonic_deadline
            stack.children.reconcile(stack.root.worker_id)
            later = stack.authority.events[marker:]
            assert later[0][0] == "close" and later[1][0] == "grant"
            assert later[1][1]["request_key"] == original_request
            second = stack.rounds(sid)[1]
            assert second["child_id"] == allocated
            assert second["child"]["exec_dispatched"] == 0
            assert len(stack.authority.grants) == 2
            assert len(stack.children.driver.launches) == 1
            assert not requests and not stack.calls()


def test_missing_session_mapping_blocks_finalization_before_capture_effects(
    tmp_path, monkeypatch
):
    with provider() as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            stack.report_and_return(first)
            with stack.children.journal.connection() as db:
                db.execute(
                    "DELETE FROM cold_rounds WHERE worker_id=? AND session_id=?",
                    (stack.root.worker_id, sid),
                )
            before = list(stack.authority.events)
            with pytest.raises(LifecycleConflict):
                stack.children.finalize(
                    stack.root.worker_id,
                    SimpleNamespace(
                        termination_confirmed=True, launch_fenced=True,
                        artifacts_captured=True,
                    ),
                )
            assert stack.authority.events == before
            assert not stack.children.driver.captures
            assert first in stack.lifecycle.active
            assert not requests and not stack.calls()


def test_accepted_request_paused_before_admission_observes_durable_closure(
    tmp_path, monkeypatch
):
    entered, release = threading.Event(), threading.Event()
    with provider() as (endpoint, requests):
        with host_stack(tmp_path, monkeypatch, endpoint) as stack:
            sid, first = stack.start()
            owner = stack.children.endpoints.children[first]
            original_admission = stack.children.model_admission_open

            def paused_admission(worker_id, child_id):
                # Pause only the actual accepted model handler, after its UID
                # and frame checks and after acquiring the common effect gate.
                # Control/outcome handlers still read the real durable flag.
                if threading.current_thread() is owner.server._worker:
                    assert worker_id == stack.root.worker_id and child_id == first
                    entered.set()
                    assert release.wait(5)
                return original_admission(worker_id, child_id)

            monkeypatch.setattr(
                stack.children, "model_admission_open", paused_admission
            )
            caller, results, errors = start_call(stack, first)
            try:
                assert entered.wait(3)
                gate = stack.broker.inference_locks[stack.root.worker_id]
                assert gate.locked()
                with owner.server._condition:
                    assert owner.server._active is not None
                assert caller.is_alive() and not release.is_set()
                assert not stack.calls() and not requests
                assert not any(
                    operation == "turn" for operation, _ in stack.authority.events
                )
                stack.report_and_return(first)
                queued = stack.queue(sid)
                assert queued["model_fence"] == "requested"
                assert stack.rounds(sid)[0]["model_closed"] == 1
                assert owner.thread.is_alive() and owner.stop_requested.is_set()
                stack.children.reconcile(stack.root.worker_id)
                assert len(grants(stack)) == len(stack.authority.grants) == 1
                assert not stack.calls() and not requests
                assert caller.is_alive() and not release.is_set()
                release.set()
                caller.join(5)
                assert not caller.is_alive() and not results
                assert len(errors) == 1 and isinstance(errors[0], BrokerError)
                assert "not_authorized" in str(errors[0])
                eventually(lambda: not owner.thread.is_alive())
                assert not stack.calls() and not requests
                assert not any(
                    operation == "turn" for operation, _ in stack.authority.events
                )
                stack.children.reconcile(stack.root.worker_id)
                first_round, second = stack.rounds(sid)
                assert first_round["fence_established"] == 1
                assert second["child_id"] != first
                assert len(grants(stack)) == len(stack.authority.grants) == 2
                assert len(stack.children.driver.launches) == 2
                assert not stack.calls() and not requests
            finally:
                release.set()
                caller.join(5)
                assert not caller.is_alive()
