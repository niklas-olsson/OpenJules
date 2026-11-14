"""Unit and integration tests for Polyphony Swarm Resource Controller & Dynamic Cohort Scaler."""

import json
import os
import shutil
import tempfile
import time
from unittest.mock import MagicMock, patch
import pytest

from src.polyphony import (
    BaseOutboxBridge,
    DockerContainerProvisioner,
    HostSignalStatus,
    HostTelemetrySignal,
    InMemoryOutboxBridge,
    McpOutboxBridge,
    MockContainerProvisioner,
    PolyphonyCohortConfig,
    SignalType,
    SQLiteOutboxBridge,
    SwarmResourceController,
    WorkerBootstrapBuilder,
)
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import SandboxContext, SandboxManager


def test_key_separation_security_invariant():
    """Verify OpenJules bootstraps a cohort with separate SWARM_KEY (injected into workers)
    and OPENJULES_HOST_KEY (retained strictly by host)."""
    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-sec-01",
        repo_url="https://github.com/org/repo.git",
        swarm_key="swarm_secret_abc123",
        host_control_key="host_secret_xyz789",
    )

    prov = MockContainerProvisioner()
    ctrl = SwarmResourceController(config=cfg, outbox_bridge=InMemoryOutboxBridge(), provisioner=prov)
    spawned = ctrl.bootstrap_cohort()

    assert len(spawned) == 1
    worker_info = spawned[0]
    pkg = prov.injected_packages[worker_info.container_id]

    # Injected into worker
    assert pkg.env_vars["SWARM_KEY"] == "swarm_secret_abc123"
    assert pkg.env_vars["JULES_ACTOR_ID"] == worker_info.actor_id

    # Strictly absent from worker env & AGENTS.md
    assert "OPENJULES_HOST_KEY" not in pkg.env_vars
    assert "host_secret_xyz789" not in json.dumps(pkg.env_vars)
    assert "host_secret_xyz789" not in pkg.agents_md_content


def test_scale_up_burst_to_ceiling_and_rejection():
    """Verify SCALE_UP signal bursts a 6-worker cohort up to max_burst_workers (18)
    and rejects requests beyond the cap or budget ceiling."""
    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-scale-01",
        repo_url="https://github.com/org/repo.git",
        base_worker_count=6,
        max_burst_workers=18,
        max_host_budget=50.0,
        estimated_worker_cost=2.0,
    )
    bridge = InMemoryOutboxBridge()
    prov = MockContainerProvisioner()
    ctrl = SwarmResourceController(config=cfg, outbox_bridge=bridge, provisioner=prov)

    # 1. Bootstrap 6 base workers
    ctrl.bootstrap_cohort()
    assert len(prov.list_active_workers()) == 6

    # 2. Emit SCALE_UP requesting 12 more workers (6 + 12 = 18 max burst)
    sig_scale1 = HostTelemetrySignal(
        signal_id="sig-scale-1",
        emitted_by_actor="conductor-1",
        signal_type=SignalType.SCALE_UP,
        requested_worker_delta=12,
        target_task_ids=["task-1", "task-2"],
        unsettled_cost_snapshot=10.0,
        rationale="Decomposing tree into 12 subtasks",
    )
    bridge.add_signal(sig_scale1)
    results = ctrl.reconcile_signals()

    assert len(results) == 1
    assert results[0]["status"] == "FULFILLED"
    assert len(results[0]["spawned_workers"]) == 12
    assert len(prov.list_active_workers()) == 18
    assert sig_scale1.host_status == HostSignalStatus.FULFILLED

    # 3. Emit another SCALE_UP when already at max capacity (18/18) -> should reject
    sig_scale2 = HostTelemetrySignal(
        signal_id="sig-scale-2",
        emitted_by_actor="conductor-1",
        signal_type=SignalType.SCALE_UP,
        requested_worker_delta=4,
        unsettled_cost_snapshot=10.0,
        rationale="Need more burst workers",
    )
    bridge.add_signal(sig_scale2)
    results2 = ctrl.reconcile_signals()

    assert len(results2) == 1
    assert results2[0]["status"] == "REJECTED"
    assert "max burst capacity" in results2[0]["reason"]
    assert sig_scale2.host_status == HostSignalStatus.REJECTED
    assert len(prov.list_active_workers()) == 18


def test_scale_up_budget_ceiling_rejection():
    """Verify SCALE_UP rejection when effective burn + worker delta exceeds max_host_budget."""
    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-budget-01",
        repo_url="https://github.com/org/repo.git",
        base_worker_count=2,
        max_burst_workers=10,
        max_host_budget=20.0,
        estimated_worker_cost=5.0,
    )
    bridge = InMemoryOutboxBridge()
    prov = MockContainerProvisioner()
    ctrl = SwarmResourceController(config=cfg, outbox_bridge=bridge, provisioner=prov)
    ctrl.bootstrap_cohort()

    # Request 4 workers at $5 each = $20, but unsettled_cost_snapshot is already $15 (15 + 20 > 20)
    sig_budget = HostTelemetrySignal(
        signal_id="sig-budget-exceeded",
        emitted_by_actor="worker-1",
        signal_type=SignalType.SCALE_UP,
        requested_worker_delta=4,
        unsettled_cost_snapshot=15.0,
        rationale="Over budget test",
    )
    bridge.add_signal(sig_budget)
    results = ctrl.reconcile_signals()

    assert len(results) == 1
    assert results[0]["status"] == "REJECTED"
    assert "Budget ceiling exceeded" in results[0]["reason"]
    assert sig_budget.host_status == HostSignalStatus.REJECTED


def test_spawn_reviewer_resolves_solo_agent_gate():
    """Verify SPAWN_REVIEWER spawns a distinct actor_id reviewer container with role='reviewer'."""
    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-solo-01",
        repo_url="https://github.com/org/repo.git",
        base_worker_count=1,
    )
    bridge = InMemoryOutboxBridge()
    prov = MockContainerProvisioner()
    ctrl = SwarmResourceController(config=cfg, outbox_bridge=bridge, provisioner=prov)
    ctrl.bootstrap_cohort()

    solo_worker = prov.list_active_workers()[0]

    # Solo agent signals reviewer needed
    sig_rev = HostTelemetrySignal(
        signal_id="sig-rev-1",
        emitted_by_actor=solo_worker.actor_id,
        signal_type=SignalType.SPAWN_REVIEWER,
        target_task_ids=["task-candidate-99"],
        rationale="Candidate in INTEGRATING awaiting independent review",
    )
    bridge.add_signal(sig_rev)
    results = ctrl.reconcile_signals()

    assert len(results) == 1
    assert results[0]["status"] == "FULFILLED"
    reviewer_actor_id = results[0]["reviewer_actor_id"]
    assert reviewer_actor_id != solo_worker.actor_id
    assert reviewer_actor_id.startswith("jules-reviewer-")

    # Verify reviewer container attributes & bootstrap
    all_workers = prov.list_active_workers()
    assert len(all_workers) == 2
    reviewer_worker = [w for w in all_workers if w.actor_id == reviewer_actor_id][0]
    assert reviewer_worker.role == "reviewer"
    assert reviewer_worker.is_burst is True

    pkg = prov.injected_packages[reviewer_worker.container_id]
    assert pkg.env_vars["POLYPHONY_ROLE"] == "reviewer"
    assert "author_actor_id != reviewer_actor_id" in pkg.agents_md_content
    assert "record_review" in pkg.agents_md_content


def test_idle_drain_respects_active_leases():
    """Verify IDLE_DRAIN reaps burst containers cleanly without killing workers holding active leases."""
    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-drain-01",
        repo_url="https://github.com/org/repo.git",
        base_worker_count=1,
        max_burst_workers=5,
    )
    bridge = InMemoryOutboxBridge()
    prov = MockContainerProvisioner()
    ctrl = SwarmResourceController(config=cfg, outbox_bridge=bridge, provisioner=prov)

    # 1 base worker + 2 burst workers
    ctrl.bootstrap_cohort()
    w_burst1 = prov.spawn_worker(cfg, "jules-burst-1", is_burst=True)
    w_burst2 = prov.spawn_worker(cfg, "jules-burst-2", is_burst=True)

    assert len(prov.list_active_workers()) == 3

    # Mark w_burst1 as holding an active lease in Polyphony store
    bridge.set_active_leases("jules-burst-1", 1)
    bridge.set_active_leases("jules-burst-2", 0)

    # Signal idle drain
    sig_drain = HostTelemetrySignal(
        signal_id="sig-drain-1",
        emitted_by_actor="coordinator",
        signal_type=SignalType.IDLE_DRAIN,
        requested_worker_delta=2,
        rationale="Tasks completed, drain idle burst workers",
    )
    bridge.add_signal(sig_drain)
    results = ctrl.reconcile_signals()

    assert len(results) == 1
    assert results[0]["status"] == "FULFILLED"
    assert results[0]["drained_count"] == 1
    assert results[0]["reaped_workers"] == ["jules-burst-2"]

    # Active containers: base worker and burst-1 (held lease)
    active = prov.list_active_workers()
    active_actors = [w.actor_id for w in active]
    assert "jules-burst-1" in active_actors
    assert "jules-burst-2" not in active_actors


def test_escalate_triage_logging_and_webhook():
    """Verify ESCALATE_TRIAGE logs and surfaces webhook notification when configured."""
    cfg = PolyphonyCohortConfig(
        swarm_id="swarm-escalate-01",
        repo_url="https://github.com/org/repo.git",
        escalation_webhook_url="https://webhook.site/triage",
    )
    bridge = InMemoryOutboxBridge()
    prov = MockContainerProvisioner()
    ctrl = SwarmResourceController(config=cfg, outbox_bridge=bridge, provisioner=prov)

    sig_esc = HostTelemetrySignal(
        signal_id="sig-esc-1",
        emitted_by_actor="worker-stuck",
        signal_type=SignalType.ESCALATE_TRIAGE,
        target_task_ids=["task-conflict-10"],
        rationale="Task in HELD status due to 3-way merge conflict",
    )
    bridge.add_signal(sig_esc)

    with patch("urllib.request.urlopen") as mock_urlopen:
        mock_resp = MagicMock()
        mock_resp.status = 200
        mock_resp.__enter__.return_value = mock_resp
        mock_urlopen.return_value = mock_resp

        results = ctrl.reconcile_signals()

        assert len(results) == 1
        assert results[0]["status"] == "ACKNOWLEDGED"
        assert "HTTP status 200" in results[0]["response_note"]
        assert sig_esc.host_status == HostSignalStatus.ACKNOWLEDGED
        mock_urlopen.assert_called_once()


def test_sqlite_outbox_bridge_refuses_without_opening_existing_or_new_state(tmp_path):
    """A historical API name cannot initialize or bypass the producer's ledger."""
    from src.polyphony.outbox import OutboxError, OutboxOutcome
    original = tmp_path / "existing.sqlite3"
    original.write_bytes(b"retained producer-owned bytes")
    with patch("sqlite3.connect", side_effect=AssertionError("foreign SQLite opened")) as connect:
        for path in [original, tmp_path / "must-not-exist.sqlite3"]:
            with pytest.raises(OutboxError) as refusal:
                SQLiteOutboxBridge(str(path))
            assert refusal.value.outcome is OutboxOutcome.UNSUPPORTED
        connect.assert_not_called()
    assert original.read_bytes() == b"retained producer-owned bytes"
    assert not (tmp_path / "must-not-exist.sqlite3").exists()


def test_docker_container_provisioner_agents_md_injection():
    """Verify DockerContainerProvisioner injects AGENTS.md into workspace."""
    mock_sandbox_mgr = MagicMock(spec=SandboxManager)
    temp_dir = tempfile.mkdtemp(prefix="test_prov_ws_")

    try:
        mock_sandbox_mgr.spawn_sandbox.return_value = SandboxContext(
            container_id="docker-c-1",
            workspace_dir=temp_dir,
            repo_url="https://github.com/org/repo.git",
            branch="main",
            config=OpenJulesConfig(),
        )

        prov = DockerContainerProvisioner(sandbox_manager=mock_sandbox_mgr)
        cfg = PolyphonyCohortConfig(swarm_id="swarm-docker-1", repo_url="https://github.com/org/repo.git")

        worker = prov.spawn_worker(cfg, actor_id="jules-worker-test", role="worker")
        assert worker.container_id == "docker-c-1"

        agents_md_file = os.path.join(temp_dir, "AGENTS.md")
        assert os.path.exists(agents_md_file)
        with open(agents_md_file, "r", encoding="utf-8") as f:
            content = f.read()
        assert "jules-worker-test" in content
        assert "swarm-docker-1" in content
    finally:
        shutil.rmtree(temp_dir, ignore_errors=True)
