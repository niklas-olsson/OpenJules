"""Original standalone cohort custody under incomplete cleanup observations."""

from dataclasses import replace
from unittest.mock import Mock, call, patch

import pytest

from src.polyphony.controller import SwarmResourceController
from src.polyphony.health import WorkerHealthMonitor
from src.polyphony.models import HostTelemetrySignal, PolyphonyCohortConfig, SignalType
from src.polyphony.outbox import InMemoryOutboxBridge, OutboxError, OutboxOutcome
from src.polyphony.provisioner import DockerContainerProvisioner, MockContainerProvisioner
from src.polyphony.registry import SwarmCohortRegistry
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import CleanupResult, SandboxContext, SandboxManager
from src.worker import execution_context


COMPLETE = CleanupResult(
    termination_confirmed=True, artifact_capture_confirmed=True,
    container_removed=True, workspace_removed=True, execution_pending=False,
)


def docker_worker(tmp_path):
    manager = Mock(spec=SandboxManager)
    workspace = tmp_path / "original-workspace"
    workspace.mkdir()
    manager.spawn_sandbox.return_value = SandboxContext(
        container_id="original-container", workspace_dir=str(workspace),
        repo_url="fixture", branch="main", config=OpenJulesConfig(),
    )
    provider = DockerContainerProvisioner(manager)
    config = PolyphonyCohortConfig(swarm_id="original-cohort", repo_url="fixture")
    worker = provider.spawn_worker(config, "original-actor")
    return provider, manager, worker, config


@pytest.mark.parametrize("receipt", [
    replace(COMPLETE, termination_confirmed=False),
    replace(COMPLETE, execution_pending=True),
    replace(COMPLETE, artifact_capture_confirmed=False),
    replace(COMPLETE, container_removed=False),
    replace(COMPLETE, workspace_removed=False),
    replace(COMPLETE, termination_confirmed=1),
    replace(COMPLETE, execution_pending=0),
    replace(COMPLETE, artifact_capture_confirmed=1),
    replace(COMPLETE, container_removed=1),
    replace(COMPLETE, workspace_removed=1),
    CleanupResult(termination_confirmed=True, artifact_capture_confirmed=False,
                  reason="Durable artifact capture is unconfirmed; work retained"),
])
def test_incomplete_cleanup_retains_original_worker_and_exact_facts(tmp_path, receipt):
    provider, manager, worker, config = docker_worker(tmp_path)
    manager.cleanup_sandbox.return_value = receipt

    assert provider.stop_worker(worker.container_id) is False
    assert provider.get_worker(worker.container_id) is worker
    assert provider.list_active_workers(config.swarm_id) == [worker]
    assert provider.get_cleanup_result(worker.container_id) is receipt
    manager.cleanup_sandbox.assert_called_once_with(worker.container_id, worker.workspace_dir)


@pytest.mark.parametrize("response", [None, True, {"termination_confirmed": True}])
def test_malformed_cleanup_cannot_release_worker(tmp_path, response):
    provider, manager, worker, _ = docker_worker(tmp_path)
    manager.cleanup_sandbox.return_value = response
    assert provider.stop_worker(worker.container_id) is False
    assert provider.get_worker(worker.container_id) is worker
    assert provider.get_cleanup_result(worker.container_id) is None


def test_original_safety_cleanup_remains_available_after_controller_pause(tmp_path):
    provider, manager, worker, config = docker_worker(tmp_path)
    controller = SwarmResourceController(config, InMemoryOutboxBridge(), provider)
    pending = replace(COMPLETE, termination_confirmed=False, execution_pending=True)
    manager.cleanup_sandbox.side_effect = [pending, TimeoutError("private failure"), COMPLETE]

    with pytest.raises(OutboxError, match="worker_cleanup_not_confirmed"):
        controller.stop_worker(worker)
    retained = controller.reconciliation_required.copy()
    assert provider.get_cleanup_result(worker.container_id) is pending
    with pytest.raises(TimeoutError):
        provider.stop_worker(worker.container_id)
    assert provider.get_worker(worker.container_id) is worker
    assert provider.get_cleanup_result(worker.container_id) is pending
    assert provider.stop_worker(worker.container_id) is True
    assert provider.get_worker(worker.container_id) is None
    assert provider.get_cleanup_result(worker.container_id) is None
    assert manager.cleanup_sandbox.call_args_list == [
        call(worker.container_id, worker.workspace_dir),
    ] * 3
    assert controller.reconcile_signals() == [retained]
    assert controller.reconciliation_required == retained


def cohort(action):
    provider = MockContainerProvisioner()
    registry = SwarmCohortRegistry(provider)
    config = PolyphonyCohortConfig(
        swarm_id="original-cohort", repo_url="fixture",
        base_worker_count=2 if action == "health" else 0,
    )
    bridge = InMemoryOutboxBridge()
    controller = registry.register_cohort(config, bridge, bootstrap=False)
    workers = [provider.spawn_worker(config, actor, is_burst=action == "drain")
               for actor in ("first-actor", "second-actor")]
    for worker in workers:
        bridge.set_active_leases(worker.actor_id, 0)
    signal = HostTelemetrySignal(signal_id="original-drain", emitted_by_actor="fixture",
                                 signal_type=SignalType.IDLE_DRAIN, requested_worker_delta=2)
    bridge.add_signal(signal)
    return provider, registry, controller, bridge, workers, signal


def perform(action, registry, controller):
    if action == "drain":
        result = controller.reconcile_signals()
        assert result[0]["status"] == "RECONCILIATION_REQUIRED"
    else:
        with pytest.raises(OutboxError) as failure:
            if action == "health":
                WorkerHealthMonitor(controller, lambda _: False).check_and_heal()
            else:
                registry.remove_cohort(controller.config.swarm_id)
        assert failure.value.outcome is OutboxOutcome.UNKNOWN


@pytest.mark.parametrize("action", ["drain", "health", "removal"])
@pytest.mark.parametrize("outcome", [False, None, 1, TimeoutError("private stop details")])
def test_unconfirmed_stop_pauses_all_automatic_consumers_without_replacement(action, outcome):
    provider, registry, controller, bridge, workers, signal = cohort(action)
    with patch.object(provider, "stop_worker", side_effect=outcome if isinstance(outcome, Exception) else None,
                      return_value=outcome) as stop, \
         patch.object(provider, "spawn_worker") as spawn, \
         patch.object(bridge, "acknowledge_signal") as acknowledge:
        perform(action, registry, controller)
        retained = controller.reconciliation_required.copy()
        assert retained["reason"] == "worker_cleanup_not_confirmed"
        assert retained["actor_id"] == workers[0].actor_id
        assert retained["container_id"] == workers[0].container_id
        assert retained["managed_authority"] is retained["release_authorized"] is False
        assert controller.reconcile_signals() == [retained]
        for operation in [controller.bootstrap_cohort,
                          WorkerHealthMonitor(controller, lambda _: False).check_and_heal,
                          lambda: registry.remove_cohort(controller.config.swarm_id),
                          lambda: registry.remove_cohort(controller.config.swarm_id, drain_workers=False),
                          lambda: controller.stop_worker(workers[0])]:
            with pytest.raises(OutboxError, match="cohort_reconciliation_required"):
                operation()
        stop.assert_called_once_with(workers[0].container_id)
        spawn.assert_not_called()
        acknowledge.assert_not_called()
    assert registry.get_controller(controller.config.swarm_id) is controller
    assert provider.list_active_workers(controller.config.swarm_id) == workers
    assert signal.host_status.value == "PENDING"


@pytest.mark.parametrize("action", ["drain", "health", "removal"])
def test_partial_cleanup_keeps_remaining_worker_and_controller(action):
    provider, registry, controller, bridge, workers, _ = cohort(action)
    original_stop = provider.stop_worker

    def partial_stop(container_id):
        return original_stop(container_id) if container_id == workers[0].container_id else False

    with patch.object(provider, "stop_worker", side_effect=partial_stop) as stop, \
         patch.object(provider, "spawn_worker") as spawn, \
         patch.object(bridge, "acknowledge_signal") as acknowledge:
        perform(action, registry, controller)
        assert stop.call_args_list == [call(worker.container_id) for worker in workers]
        spawn.assert_not_called()
        acknowledge.assert_not_called()
    assert registry.get_controller(controller.config.swarm_id) is controller
    assert provider.list_active_workers(controller.config.swarm_id) == [workers[1]]
    assert controller.reconciliation_required["container_id"] == workers[1].container_id


def test_removal_without_drain_cannot_discard_worker_custody():
    provider, registry, controller, _, workers, _ = cohort("removal")
    with patch.object(provider, "stop_worker", wraps=provider.stop_worker) as stop:
        assert registry.remove_cohort(controller.config.swarm_id, drain_workers=False) is False
        stop.assert_not_called()
    assert registry.get_controller(controller.config.swarm_id) is controller
    assert controller.reconciliation_required is None
    for worker in workers:
        assert provider.stop_worker(worker.container_id) is True
    assert registry.remove_cohort(controller.config.swarm_id, drain_workers=False) is True
    assert registry.get_controller(controller.config.swarm_id) is None


def test_new_component_methods_refuse_managed_context_before_local_state(monkeypatch):
    controller = object.__new__(SwarmResourceController)
    provider = object.__new__(DockerContainerProvisioner)
    monkeypatch.setattr(execution_context, "_managed_process", True)
    for operation in (lambda: controller.stop_worker(None),
                      lambda: provider.get_cleanup_result("original-container")):
        with pytest.raises(execution_context.LegacyExecutionRefused):
            operation()
    assert vars(controller) == vars(provider) == {}
