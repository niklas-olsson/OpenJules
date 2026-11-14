"""Bounded adapter/controller fixtures, not a production connected transport."""
import copy
import json
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from src.polyphony.controller import SwarmResourceController
from src.polyphony.models import HostTelemetrySignal, SignalType, PolyphonyCohortConfig, WorkerContainerInfo
from src.polyphony.outbox import (McpOutboxBridge, InMemoryOutboxBridge, OutboxError,
                                 OutboxOutcome, MAX_TEXT_BYTES, MAX_SIGNALS)
from src.polyphony.provisioner import MockContainerProvisioner
from src.polyphony.registry import SwarmCohortRegistry


def signal(**updates):
    return HostTelemetrySignal(signal_id="original-signal", emitted_by_actor="actor", signal_type=SignalType.SCALE_UP,
                               requested_worker_delta=1, target_task_ids=["ordinary-task"], **updates)


def payload(rows=None):
    return {"success": True, "data": [signal().model_dump(mode="json")] if rows is None else rows,
            "managed_authority": False, "release_authorized": False}


def envelope(value, *, projection=False):
    text = json.dumps(value)
    return {"content": [{"type": "text", "text": text}], "isError": False,
            **({"structuredContent": {"result": text}} if projection else {})}


def bridge_with(value):
    return McpOutboxBridge("private-host-key", lambda name, arguments: value)


def controller(bridge=None, provisioner=None):
    return SwarmResourceController(
        PolyphonyCohortConfig(swarm_id="fixture", repo_url="https://example.invalid/repo", base_worker_count=0),
        bridge if bridge is not None else InMemoryOutboxBridge(),
        provisioner if provisioner is not None else MockContainerProvisioner())


@pytest.mark.parametrize("shape", ["text", "mapping", "projection", "sdk-like"])
def test_actual_json_text_shape_preserves_ids_and_sends_new_status(shape):
    calls = []
    def call(name, arguments):
        calls.append((name, arguments))
        value = payload() if name == "openjules_poll_outbox" else {"success": True, "message": "accepted"}
        if shape == "text": return json.dumps(value)
        result = envelope(value, projection=shape == "projection")
        if shape == "sdk-like":
            return SimpleNamespace(isError=False, content=[SimpleNamespace(type="text", text=json.dumps(value))], structuredContent=None)
        return result
    bridge = McpOutboxBridge("host-secret", call)
    rows = bridge.poll_pending_signals()
    assert rows[0].signal_id == "original-signal" and rows[0].target_task_ids == ["ordinary-task"]
    assert bridge.acknowledge_signal(rows[0].signal_id, "FULFILLED", "one action") is True
    assert calls == [
        ("openjules_poll_outbox", {"host_key": "host-secret", "status_filter": "PENDING"}),
        ("openjules_ack_signal", {"host_key": "host-secret", "signal_id": "original-signal", "new_status": "FULFILLED", "response_note": "one action"}),
    ]


def test_successful_empty_queue_is_distinct_from_unsupported_activity():
    call = Mock(return_value=envelope(payload([])))
    bridge = McpOutboxBridge("host-key", call)
    assert bridge.poll_pending_signals() == []
    with pytest.raises(OutboxError) as result:
        bridge.count_active_leases("worker")
    assert result.value.outcome is OutboxOutcome.UNSUPPORTED
    assert call.call_count == 1


@pytest.mark.parametrize("bad", [
    {}, {"signals": []}, {"success": True, "data": []},
    {"content": []}, {"content": [{"type": "image", "data": "secret"}]},
    {"content": [{"type": "text", "text": "{}"}, {"type": "text", "text": "{}"}]},
    {"content": [{"type": "text", "text": "not-json"}]},
    {"content": [{"type": "text", "text": "{}"}], "isError": True},
    {"content": [{"type": "text", "text": "{}"}], "structuredContent": {"success": True}},
    '{"success":true,"success":false}',
    '{"success":true,"data":[],"managed_authority":false,"release_authorized":NaN}',
    "x" * (MAX_TEXT_BYTES + 1),
])
def test_malformed_mixed_ambiguous_or_oversized_envelopes_are_unknown(bad):
    with pytest.raises(OutboxError) as result:
        bridge_with(bad).poll_pending_signals()
    assert result.value.outcome is OutboxOutcome.UNKNOWN
    assert str(result.value) == "invalid_host_signal_result"


@pytest.mark.parametrize("field,value", [
    ("data", {}), ("managed_authority", True), ("managed_authority", 0),
    ("release_authorized", None), ("success", "true"),
])
def test_poll_requires_exact_success_data_and_noncanonical_flags(field, value):
    body = payload(); body[field] = value
    with pytest.raises(OutboxError) as result:
        bridge_with(envelope(body)).poll_pending_signals()
    assert result.value.outcome is OutboxOutcome.UNKNOWN


@pytest.mark.parametrize("field,value", [
    ("signal_id", ""), ("signal_id", "line\nbreak"), ("emitted_by_actor", 1),
    ("requested_worker_delta", True), ("requested_worker_delta", "2"),
    ("target_task_ids", "[ordinary-task]"), ("target_task_ids", [1]),
    ("target_task_ids", ["same", "same"]), ("unsettled_cost_snapshot", True),
    ("created_at", -1), ("created_at", 10**200), ("host_status", "FULFILLED"),
    ("signal_type", {}), ("rationale", None),
])
def test_signal_fields_are_not_coerced_or_defaulted(field, value):
    body = payload(); body["data"][0][field] = value
    with pytest.raises(OutboxError) as result:
        bridge_with(envelope(body)).poll_pending_signals()
    assert result.value.outcome is OutboxOutcome.UNKNOWN


def test_duplicate_or_excessive_signal_batch_is_atomic_refusal():
    for rows in [[signal().model_dump(mode="json")] * 2, [{}] * (MAX_SIGNALS + 1)]:
        with pytest.raises(OutboxError):
            bridge_with(envelope(payload(rows))).poll_pending_signals()


@pytest.mark.parametrize("failure,outcome", [
    (TimeoutError("secret timeout detail"), OutboxOutcome.UNKNOWN),
    (ConnectionError("private endpoint"), OutboxOutcome.UNKNOWN),
    (NotImplementedError("private missing tool"), OutboxOutcome.UNSUPPORTED),
    (KeyError("private missing tool"), OutboxOutcome.UNSUPPORTED),
])
def test_transport_failures_have_safe_distinct_classifications(failure, outcome, caplog):
    bridge = McpOutboxBridge("private-host-key", Mock(side_effect=failure))
    for action in [bridge.poll_pending_signals, lambda: bridge.acknowledge_signal("original", "FULFILLED")]:
        with pytest.raises(OutboxError) as result: action()
        assert result.value.outcome is outcome
        assert "private" not in str(result.value) and "secret" not in str(result.value)
    assert "private" not in caplog.text and "secret" not in caplog.text


def test_producer_refusal_is_not_an_empty_queue_or_acknowledgement():
    bridge = bridge_with(envelope({"success": False, "error": "host secret must not be copied"}))
    for action in [bridge.poll_pending_signals, lambda: bridge.acknowledge_signal("original", "FULFILLED")]:
        with pytest.raises(OutboxError) as result: action()
        assert result.value.outcome is OutboxOutcome.REFUSED
        assert "secret" not in str(result.value)


def test_absent_or_incompatible_transport_does_not_open_sqlite_or_construct_docker(tmp_path):
    cfg = PolyphonyCohortConfig(swarm_id="missing", repo_url="fixture", liminal_db_path=str(tmp_path / "foreign.db"))
    with patch("sqlite3.connect", side_effect=AssertionError("foreign SQL")) as sql, \
         patch("src.polyphony.registry.DockerContainerProvisioner", side_effect=AssertionError("Docker before selection")) as docker:
        registry = SwarmCohortRegistry()
        for action in [lambda: registry.register_cohort(cfg), lambda: McpOutboxBridge("key"),
                       lambda: McpOutboxBridge("key", Mock(), db_path=cfg.liminal_db_path),
                       lambda: registry.register_cohort(cfg, InMemoryOutboxBridge())]:
            with pytest.raises(OutboxError) as result: action()
            assert result.value.outcome is OutboxOutcome.UNSUPPORTED
        sql.assert_not_called(); docker.assert_not_called()
    assert not (tmp_path / "foreign.db").exists()


@pytest.mark.parametrize("observation", [None, True, "0", -1, TimeoutError("private")])
def test_idle_drain_does_not_stop_or_acknowledge_unknown_activity(observation):
    bridge = InMemoryOutboxBridge(); provider = MockContainerProvisioner(); ctrl = controller(bridge, provider)
    provider.spawn_worker(ctrl.config, "idle-known", is_burst=True)
    provider.spawn_worker(ctrl.config, "unknown", is_burst=True)
    bridge.add_signal(HostTelemetrySignal(signal_id="drain", emitted_by_actor="actor", signal_type=SignalType.IDLE_DRAIN))
    original = bridge.count_active_leases
    bridge.set_active_leases("idle-known", 0)
    def activity(actor):
        if actor == "idle-known": return original(actor)
        if isinstance(observation, Exception): raise observation
        return observation
    bridge.count_active_leases = activity
    with patch.object(provider, "stop_worker", wraps=provider.stop_worker) as stop, \
         patch.object(bridge, "acknowledge_signal", wraps=bridge.acknowledge_signal) as ack:
        result = ctrl.reconcile_signals()
        assert result[0]["status"] in {"UNKNOWN", "UNSUPPORTED"}
        stop.assert_not_called(); ack.assert_not_called()
    assert ctrl.reconciliation_required is None


@pytest.mark.parametrize("ack", [False, None, TimeoutError("private ack"), OutboxError(OutboxOutcome.REFUSED, "producer_refused_host_signal")])
@pytest.mark.parametrize("action", ["spawn", "stop"])
def test_attempted_host_action_survives_failed_ack_and_repeated_poll(ack, action):
    bridge = InMemoryOutboxBridge(); provider = MockContainerProvisioner(); ctrl = controller(bridge, provider)
    if action == "stop":
        provider.spawn_worker(ctrl.config, "burst", is_burst=True); bridge.set_active_leases("burst", 0)
        item = HostTelemetrySignal(signal_id="original", emitted_by_actor="actor", signal_type=SignalType.IDLE_DRAIN)
    else: item = signal()
    bridge.add_signal(item)
    def acknowledge(*args):
        assert item.signal_id in ctrl._attempted_signals
        if isinstance(ack, Exception): raise ack
        return ack
    bridge.acknowledge_signal = acknowledge
    method = "spawn_worker" if action == "spawn" else "stop_worker"
    original = getattr(provider, method)
    def effect(*args, **kwargs):
        assert item.signal_id in ctrl._attempted_signals
        return original(*args, **kwargs)
    with patch.object(provider, method, side_effect=effect) as call:
        first = ctrl.reconcile_signals(); second = ctrl.reconcile_signals()
        assert first[0]["status"] == second[0]["status"] == "RECONCILIATION_REQUIRED"
        assert first[0]["managed_authority"] is False and first[0]["release_authorized"] is False
        assert call.call_count == 1
    assert item.host_status.value == "PENDING"


def test_action_timeout_latches_before_ack_and_blocks_health_bootstrap_or_replacement():
    bridge = InMemoryOutboxBridge(); provider = MockContainerProvisioner()
    registry = SwarmCohortRegistry(provider)
    cfg = PolyphonyCohortConfig(swarm_id="uncertain", repo_url="fixture", base_worker_count=0)
    ctrl = registry.register_cohort(cfg, bridge)
    bridge.add_signal(signal())
    with patch.object(provider, "spawn_worker", side_effect=TimeoutError("host secret")) as spawn, \
         patch.object(bridge, "acknowledge_signal") as ack:
        assert ctrl.reconcile_signals()[0]["status"] == "RECONCILIATION_REQUIRED"
        ctrl.reconcile_signals()
        assert spawn.call_count == 1; ack.assert_not_called()
        from src.polyphony.health import WorkerHealthMonitor
        for action in [ctrl.bootstrap_cohort, WorkerHealthMonitor(ctrl).check_and_heal,
                       lambda: registry.remove_cohort(cfg.swarm_id)]:
            with pytest.raises(OutboxError): action()
        with pytest.raises(ValueError, match="cohort_already_registered"):
            registry.register_cohort(cfg, bridge)
    assert registry.get_controller(cfg.swarm_id) is ctrl


@pytest.mark.parametrize("signal_type", [SignalType.SCALE_UP, SignalType.SPAWN_REVIEWER])
@pytest.mark.parametrize("returned", [None, False, WorkerContainerInfo(container_id="other-container", actor_id="other-actor")])
def test_spawn_requires_original_actor_confirmation_before_metering_or_ack(signal_type, returned):
    bridge = InMemoryOutboxBridge(); provider = MockContainerProvisioner(); ctrl = controller(bridge, provider)
    item = HostTelemetrySignal(signal_id="original-signal", emitted_by_actor="actor", signal_type=signal_type,
                               requested_worker_delta=1)
    bridge.add_signal(item)
    def effect(*args, **kwargs):
        assert item.signal_id in ctrl._attempted_signals
        return returned
    with patch.object(provider, "spawn_worker", side_effect=effect) as spawn, \
         patch.object(bridge, "acknowledge_signal") as ack:
        first = ctrl.reconcile_signals(); second = ctrl.reconcile_signals()
        assert first == second
        assert first[0]["status"] == "RECONCILIATION_REQUIRED"
        assert first[0]["reason"] == "worker_spawn_not_confirmed"
        assert ctrl.internal_metered_cost == 0
        assert item.host_status.value == "PENDING"
        assert spawn.call_count == 1
        ack.assert_not_called()


def test_successful_signal_replay_is_not_another_host_action_and_changed_id_pauses():
    bridge = InMemoryOutboxBridge(); ctrl = controller(bridge); item = signal()
    bridge.poll_pending_signals = lambda: [item]
    bridge.acknowledge_signal = lambda *args: True
    first = ctrl.reconcile_signals()[0]
    assert first["status"] == "FULFILLED"
    assert first["managed_authority"] is False and first["release_authorized"] is False
    assert ctrl.reconcile_signals()[0]["status"] == "ALREADY_ATTEMPTED"
    assert len(ctrl.provisioner.list_active_workers()) == 1
    item.target_task_ids = ["changed-target"]
    assert ctrl.reconcile_signals()[0]["status"] == "RECONCILIATION_REQUIRED"
    assert len(ctrl.provisioner.list_active_workers()) == 1


def test_full_correlation_capacity_stops_before_effect_without_evicting_history(monkeypatch):
    import src.polyphony.controller as module
    monkeypatch.setattr(module, "MAX_RETAINED_SIGNALS", 1)
    bridge = InMemoryOutboxBridge(); ctrl = controller(bridge)
    bridge.add_signal(signal()); ctrl.reconcile_signals()
    other = signal(); other.signal_id = "next-signal"; bridge.add_signal(other)
    assert ctrl.reconcile_signals()[0]["status"] == "RECONCILIATION_REQUIRED"
    assert list(ctrl._attempted_signals) == ["original-signal"]
    assert len(ctrl.provisioner.list_active_workers()) == 1


def test_ambiguous_bootstrap_response_retains_controller_and_actor_before_retry():
    provider = MockContainerProvisioner()
    registry = SwarmCohortRegistry(provider)
    cfg = PolyphonyCohortConfig(swarm_id="bootstrap-unknown", repo_url="fixture", base_worker_count=1)
    with patch.object(provider, "spawn_worker", return_value=None) as spawn:
        with pytest.raises(OutboxError, match="bootstrap_action_unknown"):
            registry.register_cohort(cfg, InMemoryOutboxBridge())
        ctrl = registry.get_controller(cfg.swarm_id)
        assert ctrl.reconciliation_required["actor_id"] == spawn.call_args.kwargs["actor_id"]
        with pytest.raises(OutboxError, match="cohort_reconciliation_required"):
            ctrl.bootstrap_cohort()
        assert spawn.call_count == 1
