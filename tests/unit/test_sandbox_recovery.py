"""Adversarial command deadlines and capture-before-cleanup behavior."""

import subprocess
import sys
import threading
import time
from pathlib import Path
from unittest.mock import MagicMock

import pytest
from docker.errors import DockerException, NotFound

from src.sandbox.config import OpenJulesConfig
from src.sandbox import docker_driver
from src.sandbox.docker_driver import (
    SandboxCleanupError,
    SandboxContext,
    SandboxExecutionUnknown,
    SandboxExecTimeout,
    SandboxLaunchUnknown,
    SandboxManager,
)


def runtime(*, max_pending_exchanges=16):
    client = MagicMock()
    container = MagicMock()
    container.id = "immutable-container"
    container.attrs = {"State": {"Running": False, "Restarting": False}}
    client.containers.get.return_value = container
    client.api.exec_create.return_value = {"Id": "exec-one"}
    client.api.exec_start.return_value = (b"useful output", b"")
    client.api.exec_inspect.return_value = {"Running": False, "ExitCode": 0}
    manager = SandboxManager(
        client, operation_timeout=0.1, max_pending_exchanges=max_pending_exchanges
    )
    return manager, client, container


@pytest.mark.parametrize(
    "outcome",
    [
        {"Running": False, "ExitCode": None},
        {"Running": True, "ExitCode": 0},
        {"ExitCode": 0},
        {"Running": False, "ExitCode": True},
    ],
)
def test_unconfirmed_exit_is_never_success(outcome):
    manager, client, container = runtime()
    client.api.exec_inspect.return_value = outcome
    with pytest.raises(SandboxExecutionUnknown):
        manager.exec_in_sandbox(container.id, "ignored fixture command")
    container.stop.assert_called_once()
    with pytest.raises(RuntimeError, match="requires reconciliation"):
        manager.exec_in_sandbox(container.id, "must not launch again")
    assert client.api.exec_create.call_count == 1


def test_deadline_stops_real_blocking_process_via_runtime_fixture():
    """Exercises a real process, but does not claim a real Docker integration."""
    manager, client, container = runtime()
    manager.operation_timeout = 2
    process = None

    def start(*args, **kwargs):
        nonlocal process
        process = subprocess.Popen(
            [sys.executable, "-c", "import time; time.sleep(30)"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        return process.communicate()

    def stop(**kwargs):
        if process is not None:
            process.terminate()
            process.wait(timeout=2)

    client.api.exec_start.side_effect = start
    container.stop.side_effect = stop
    try:
        with pytest.raises(SandboxExecTimeout) as exc:
            manager.exec_in_sandbox(container.id, "fixture", timeout=0.2)
        assert process is not None
        assert process.poll() is not None
        assert exc.value.termination_confirmed is True
    finally:
        if process is not None and process.poll() is None:
            process.kill()
            process.wait(timeout=2)


def test_late_create_response_cannot_start_after_deadline(tmp_path):
    manager, client, container = runtime()
    release = threading.Event()
    returned = threading.Event()

    def create(**kwargs):
        release.wait()
        returned.set()
        return {"Id": "late-exec"}

    client.api.exec_create.side_effect = create
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "patch.txt").write_text("keep this work")
    try:
        with pytest.raises(SandboxExecTimeout):
            manager.exec_in_sandbox(container.id, "fixture", timeout=0.02)
        result = manager.cleanup_sandbox(
            container.id, str(workspace), artifact_capture_confirmed=True
        )
        assert result.execution_pending is True
        assert result.workspace_removed is False
        container.remove.assert_not_called()
        assert (workspace / "patch.txt").read_text() == "keep this work"
    finally:
        release.set()
        assert returned.wait(1)
    # The delayed SDK response cannot turn an expired intent into a new start.
    deadline = time.monotonic() + 1
    while container.id in manager._active_executions and time.monotonic() < deadline:
        time.sleep(0.005)
    client.api.exec_start.assert_not_called()


def test_pending_exchange_cap_prevents_thread_growth():
    manager, client, container = runtime(max_pending_exchanges=1)
    release = threading.Event()
    client.api.exec_start.side_effect = lambda *a, **k: (release.wait(), b"")
    try:
        with pytest.raises(SandboxExecTimeout) as exc:
            manager.exec_in_sandbox(container.id, "fixture", timeout=0.02)
        assert exc.value.termination_confirmed is False
        # The unresolved request still occupies its slot. Repeated requests
        # cannot add blocking command or cancellation threads.
        for _ in range(5):
            with pytest.raises(RuntimeError, match="exchange limit"):
                manager.exec_in_sandbox(container.id, "retry", timeout=0.02)
        assert client.api.exec_create.call_count == 1
        container.stop.assert_not_called()
    finally:
        release.set()


def test_unknown_result_keeps_admission_closed_during_caller_handoff(monkeypatch):
    manager, client, container = runtime()
    client.api.exec_inspect.return_value = {"Running": False, "ExitCode": None}
    result_received = threading.Event()
    release_caller = threading.Event()
    failures = []
    original_queue = docker_driver.queue.Queue

    class PausedResultQueue(original_queue):
        def get(self, *args, **kwargs):
            result = super().get(*args, **kwargs)
            result_received.set()
            if not release_caller.wait(2):
                raise AssertionError("caller fixture was not released")
            return result

    monkeypatch.setattr(docker_driver.queue, "Queue", PausedResultQueue)

    def first_command():
        try:
            manager.exec_in_sandbox(container.id, "first fixture command", timeout=2)
        except BaseException as exc:
            failures.append(exc)

    caller = threading.Thread(target=first_command)
    caller.start()
    try:
        assert result_received.wait(1)
        with pytest.raises(RuntimeError, match="active or requires reconciliation"):
            manager.exec_in_sandbox(container.id, "must not race the first outcome")
        assert client.api.exec_create.call_count == 1
    finally:
        release_caller.set()
        caller.join(2)
    assert not caller.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], SandboxExecutionUnknown)


def test_cleanup_closes_admission_before_delayed_exec_create_returns(tmp_path):
    manager, client, container = runtime()
    create_entered = threading.Event()
    release_create = threading.Event()
    failures = []

    def create(**kwargs):
        create_entered.set()
        if not release_create.wait(2):
            raise AssertionError("create fixture was not released")
        return {"Id": "pending-exec"}

    def command():
        try:
            manager.exec_in_sandbox(container.id, "pending fixture command", timeout=2)
        except BaseException as exc:
            failures.append(exc)

    client.api.exec_create.side_effect = create
    caller = threading.Thread(target=command)
    caller.start()
    try:
        assert create_entered.wait(1)
        receipt = manager.cleanup_sandbox(container.id, str(tmp_path))
        assert receipt.execution_pending is True
        assert receipt.workspace_removed is False
    finally:
        release_create.set()
        caller.join(2)
    assert not caller.is_alive()
    assert len(failures) == 1
    assert isinstance(failures[0], SandboxExecutionUnknown)
    client.api.exec_start.assert_not_called()


def test_failed_stop_preserves_even_acknowledged_workspace(tmp_path):
    manager, client, container = runtime()
    container.stop.side_effect = DockerException("daemon unavailable")
    patch = tmp_path / "patch.txt"
    patch.write_text("valuable")
    result = manager.cleanup_sandbox(
        container.id, str(tmp_path), artifact_capture_confirmed=True
    )
    assert result.termination_confirmed is False
    assert patch.read_text() == "valuable"
    container.remove.assert_not_called()


def test_stop_reply_without_stopped_observation_preserves_work(tmp_path):
    manager, client, container = runtime()
    container.attrs["State"]["Running"] = True
    result = manager.cleanup_sandbox(
        container.id, str(tmp_path), artifact_capture_confirmed=True
    )
    assert result.termination_confirmed is False
    assert tmp_path.exists()
    container.remove.assert_not_called()


def test_capture_acknowledgement_is_required_before_destructive_cleanup(tmp_path):
    manager, client, container = runtime()
    result = manager.cleanup_sandbox(container.id, str(tmp_path))
    assert result.termination_confirmed is True
    assert result.artifact_capture_confirmed is False
    assert result.workspace_removed is False
    container.remove.assert_not_called()
    assert tmp_path.exists()

    result = manager.cleanup_sandbox(
        container.id, str(tmp_path), artifact_capture_confirmed=True
    )
    assert result.container_removed is True
    assert result.workspace_removed is True
    assert not tmp_path.exists()
    container.remove.assert_called_once_with(v=True)


def test_failed_remove_keeps_workspace_for_retry(tmp_path):
    manager, client, container = runtime()
    container.remove.side_effect = DockerException("remove response lost")
    result = manager.cleanup_sandbox(
        container.id, str(tmp_path), artifact_capture_confirmed=True
    )
    assert result.termination_confirmed is False
    assert result.container_removed is False
    assert result.workspace_removed is False
    assert tmp_path.exists()


def test_restart_observed_before_removal_revokes_termination_receipt(tmp_path):
    manager, client, container = runtime()

    def reload():
        container.attrs["State"]["Running"] = container.reload.call_count > 1

    container.reload.side_effect = reload
    result = manager.cleanup_sandbox(
        container.id, str(tmp_path), artifact_capture_confirmed=True
    )
    assert result.termination_confirmed is False
    assert result.container_removed is False
    assert result.workspace_removed is False
    container.remove.assert_not_called()
    assert tmp_path.exists()


def test_already_absent_container_still_requires_capture_ack(tmp_path):
    manager, client, container = runtime()
    client.containers.get.side_effect = NotFound("gone")
    result = manager.cleanup_sandbox(container.id, str(tmp_path))
    assert result.termination_confirmed is True
    assert result.container_removed is True
    assert result.workspace_removed is False
    assert tmp_path.exists()


def test_create_response_failure_does_not_delete_possibly_mounted_work(tmp_path):
    manager, client, container = runtime()
    client.containers.run.side_effect = DockerException("lost create reply")
    with pytest.raises(SandboxLaunchUnknown) as exc:
        manager.spawn_sandbox("https://example.invalid/repo", "main", OpenJulesConfig(), workspace_base_dir=str(tmp_path))
    assert Path(exc.value.workspace_dir).is_dir()


def test_failed_initialization_reports_retained_work_identifiers(tmp_path, caplog):
    manager, client, container = runtime()
    client.containers.run.return_value = container
    client.api.exec_inspect.return_value = {"Running": False, "ExitCode": 1}
    with pytest.raises(RuntimeError, match="Failed to clone repository"):
        manager.spawn_sandbox("https://example.invalid/repo", "main", OpenJulesConfig(), workspace_base_dir=str(tmp_path))
    retained = list(tmp_path.iterdir())
    assert len(retained) == 1
    assert retained[0].is_dir()
    assert "Failed sandbox initialization retained work" in caplog.text
    assert container.id in caplog.text
    assert str(retained[0]) in caplog.text


def test_context_cannot_report_clean_success_after_unknown_stop(tmp_path):
    manager, client, container = runtime()
    manager.spawn_sandbox = lambda **kw: SandboxContext(
        container.id, str(tmp_path), "repo", "main", OpenJulesConfig()
    )
    container.stop.side_effect = DockerException("unavailable")
    with pytest.raises(SandboxCleanupError):
        with manager.run_sandbox("repo", "main", OpenJulesConfig()) as context:
            pass
    assert context.cleanup_result.termination_confirmed is False
    assert tmp_path.exists()


def test_cleanup_does_not_mask_original_failure(tmp_path):
    manager, client, container = runtime()
    manager.spawn_sandbox = lambda **kw: SandboxContext(
        container.id, str(tmp_path), "repo", "main", OpenJulesConfig()
    )
    container.stop.side_effect = DockerException("unavailable")
    with pytest.raises(ValueError, match="original failure"):
        with manager.run_sandbox("repo", "main", OpenJulesConfig()) as context:
            raise ValueError("original failure")
    assert context.cleanup_result.termination_confirmed is False


def test_unexpected_cleanup_error_does_not_mask_original_failure(tmp_path):
    manager, client, container = runtime()
    manager.spawn_sandbox = lambda **kw: SandboxContext(
        container.id, str(tmp_path), "repo", "main", OpenJulesConfig()
    )

    def broken_cleanup(*args, **kwargs):
        raise RuntimeError("unexpected cleanup failure")

    manager.cleanup_sandbox = broken_cleanup
    with pytest.raises(ValueError, match="original task failure"):
        with manager.run_sandbox("repo", "main", OpenJulesConfig()) as context:
            raise ValueError("original task failure")
    assert context.cleanup_result.termination_confirmed is False
    assert context.cleanup_result.artifact_capture_confirmed is False
    assert context.cleanup_result.workspace_removed is False


@pytest.mark.parametrize("timeout", [None, True, 0, -1, float("nan"), float("inf")])
def test_invalid_timeout_fails_before_any_docker_operation(timeout):
    manager, client, container = runtime()
    with pytest.raises(ValueError):
        manager.exec_in_sandbox(container.id, "fixture", timeout=timeout)
    client.containers.get.assert_not_called()
