"""Explicit local swarm components and CLI, with fixture workers.

Covers:
1. SwarmCohortRegistry & SwarmReconciliationDaemon background loop
2. WorkerHealthMonitor container liveness detection & self-healing
3. CLI swarm commands (start, status, drain)

The closed HTTP/WS boundary is covered by test_standalone_ingress.py.
"""

import asyncio
from unittest.mock import MagicMock, patch
import pytest

from src.cli import handle_swarm_cli
from src.polyphony import (
    InMemoryOutboxBridge,
    MockContainerProvisioner,
    PolyphonyCohortConfig,
    SignalType,
    SwarmResourceController,
)
from src.polyphony.health import WorkerHealthMonitor
# Explicit legacy components may construct their host runtime. These tests use
# fixture workers; the actual disabled app must never import this singleton.
with patch("docker.from_env"):
    from src.polyphony.daemon import SwarmReconciliationDaemon
    from src.polyphony.registry import SwarmCohortRegistry, cohort_registry


def test_swarm_cohort_registry_and_daemon():
    mock_prov = MockContainerProvisioner()
    registry = SwarmCohortRegistry(default_provisioner=mock_prov)

    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-reg-1",
        repo_url="https://github.com/org/repo.git",
        base_worker_count=2,
    )
    bridge = InMemoryOutboxBridge()
    ctrl = registry.register_cohort(cfg, outbox_bridge=bridge, bootstrap=True)

    assert registry.get_controller("swarm-reg-1") is ctrl
    assert len(mock_prov.list_active_workers()) == 2
    assert len(registry.list_cohorts()) == 1

    events_received = []

    def on_event(s_id, results):
        events_received.append((s_id, results))

    daemon = SwarmReconciliationDaemon(
        registry=registry,
        poll_interval=0.1,
        on_reconciliation_event=on_event,
    )

    # Queue a scale up signal
    from src.polyphony.models import HostTelemetrySignal
    bridge.add_signal(
        HostTelemetrySignal(
            signal_id="sig-daemon-1",
            emitted_by_actor="test",
            signal_type=SignalType.SCALE_UP,
            requested_worker_delta=1,
            rationale="Daemon test",
        )
    )

    res = daemon.run_one_pass()
    assert "swarm-reg-1" in res
    assert len(events_received) == 1
    assert len(mock_prov.list_active_workers()) == 3

    # Clean removal
    assert registry.remove_cohort("swarm-reg-1", drain_workers=True) is True
    assert len(mock_prov.list_active_workers()) == 0


def test_worker_health_monitor_self_healing():
    mock_prov = MockContainerProvisioner()
    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-health-1",
        repo_url="https://github.com/org/repo.git",
        base_worker_count=2,
    )
    bridge = InMemoryOutboxBridge()
    ctrl = SwarmResourceController(cfg, bridge, mock_prov)
    ctrl.bootstrap_cohort()

    workers = mock_prov.list_active_workers()
    assert len(workers) == 2
    crashed_id = workers[0].container_id

    # Liveness check returns false for crashed container
    monitor = WorkerHealthMonitor(ctrl, liveness_check=lambda cid: cid != crashed_id)
    heal_result = monitor.check_and_heal()

    assert heal_result["swarm_id"] == "swarm-health-1"
    assert len(heal_result["reaped_dead_workers"]) == 1
    assert len(heal_result["replenished_base_workers"]) == 1
    assert heal_result["current_total_active"] == 2




def test_cli_swarm_mutations_are_unavailable_before_registry_or_provisioning(capsys, monkeypatch):
    from types import SimpleNamespace
    effects = MagicMock(side_effect=AssertionError("unavailable CLI must not provision"))
    monkeypatch.setattr(cohort_registry, "register_cohort", effects)
    monkeypatch.setattr(cohort_registry, "get_controller", effects)
    for action in ["start", "drain"]:
        assert handle_swarm_cli(SimpleNamespace(swarm_action=action)) == 2
        assert "no qualified host-signal transport" in capsys.readouterr().out
    effects.assert_not_called()


def test_cli_status_describes_only_an_explicit_in_process_fixture(capsys):
    from types import SimpleNamespace
    cohort_registry._controllers.clear()
    provider = MockContainerProvisioner()
    config = PolyphonyCohortConfig(swarm_id="cli-fixture", repo_url="https://example.invalid/repo", base_worker_count=2)
    cohort_registry.register_cohort(config, outbox_bridge=InMemoryOutboxBridge(), provisioner=provider)
    try:
        assert handle_swarm_cli(SimpleNamespace(swarm_action="status", swarm_id="cli-fixture")) == 0
        text = capsys.readouterr().out
        assert "Polyphony Cohort Status: cli-fixture" in text and "Active Workers: 2" in text
    finally:
        cohort_registry.remove_cohort("cli-fixture")
