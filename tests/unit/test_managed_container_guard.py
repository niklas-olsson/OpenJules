"""Standalone legacy access must never mutate canonical-owned containers."""

import threading
from unittest.mock import MagicMock

import pytest
from docker.errors import DockerException

from src.agent.tools import AgentTools
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import SandboxManager
from src.worker import execution_context as context


@pytest.fixture(autouse=True)
def standalone_context(tmp_path, monkeypatch):
    monkeypatch.setattr(context.sys, "prefix", str(tmp_path / "standalone"))
    monkeypatch.setattr(context, "_managed_process", False)
    monkeypatch.setattr(context, "_selector_observed", False)


def runtime(labels=None):
    client = MagicMock()
    container = MagicMock()
    container.id = "immutable-container"
    container.attrs = {
        "Config": {"Labels": {} if labels is None else labels},
        "State": {"Running": False, "Restarting": False},
    }
    client.containers.get.return_value = container
    client.api.exec_create.return_value = {"Id": "exec-ordinary"}
    client.api.exec_start.return_value = (b"ordinary output", b"")
    client.api.exec_inspect.return_value = {"Running": False, "ExitCode": 0}
    manager = SandboxManager(client, operation_timeout=0.1)
    return manager, client, container


def assert_no_effects(manager, client, container, workspace):
    client.api.exec_create.assert_not_called()
    client.api.exec_start.assert_not_called()
    client.containers.run.assert_not_called()
    container.put_archive.assert_not_called()
    container.stop.assert_not_called()
    container.remove.assert_not_called()
    assert manager._quarantined == set()
    assert manager._active_executions == set()
    assert (workspace / "retained.txt").read_text() == "original"


@pytest.mark.parametrize("operation", ["exec", "read", "write", "stop", "cleanup"])
def test_managed_label_refusal_never_enters_unknown_execution_cleanup(tmp_path, operation):
    manager, client, container = runtime({"openjules.managed": "1"})
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "retained.txt").write_text("original")
    tools = AgentTools(manager, container.id)
    actions = {
        "exec": lambda: manager.exec_in_sandbox(container.id, "must not run"),
        "read": lambda: tools.read_file("retained.txt"),
        "write": lambda: tools.write_file("retained.txt", "must not write"),
        "stop": lambda: manager._stop(container.id),
        "cleanup": lambda: manager.cleanup_sandbox(
            container.id, str(workspace), artifact_capture_confirmed=True
        ),
    }
    with pytest.raises(context.LegacyExecutionRefused, match="^managed_container_requires_canonical_runtime$"):
        actions[operation]()
    client.containers.get.assert_called_once_with(container.id)
    assert_no_effects(manager, client, container, workspace)


@pytest.mark.parametrize("failure", ["alias", "missing_config", "missing_labels", "bad_labels", "unavailable"])
@pytest.mark.parametrize("operation", ["exec", "stop", "cleanup"])
def test_unknown_ownership_is_refused_before_any_mutation(tmp_path, failure, operation):
    manager, client, container = runtime()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "retained.txt").write_text("original")
    identity = container.id
    if failure == "alias":
        identity = "mutable-container-name"
    elif failure == "missing_config":
        del container.attrs["Config"]
    elif failure == "missing_labels":
        del container.attrs["Config"]["Labels"]
    elif failure == "bad_labels":
        container.attrs["Config"]["Labels"] = {"openjules.managed": 1}
    else:
        client.containers.get.side_effect = DockerException("private transport details")
    actions = {
        "exec": lambda: manager.exec_in_sandbox(identity, "must not run"),
        "stop": lambda: manager._stop(identity),
        "cleanup": lambda: manager.cleanup_sandbox(
            identity, str(workspace), artifact_capture_confirmed=True
        ),
    }
    with pytest.raises(context.LegacyExecutionRefused, match="^legacy_container_identity_unverified$"):
        actions[operation]()
    assert_no_effects(manager, client, container, workspace)


def test_late_ownership_lookup_never_becomes_a_late_execution(tmp_path):
    manager, client, container = runtime()
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "retained.txt").write_text("original")
    entered, release, returned = threading.Event(), threading.Event(), threading.Event()

    def delayed_lookup(_identity):
        entered.set()
        try:
            assert release.wait(2)
            return container
        finally:
            returned.set()

    client.containers.get.side_effect = delayed_lookup
    try:
        with pytest.raises(TimeoutError):
            manager.exec_in_sandbox(container.id, "must not run", timeout=0.02)
        assert entered.is_set()
        assert_no_effects(manager, client, container, workspace)
    finally:
        release.set()
        assert returned.wait(1)
    # The completed read may release its exchange slot, but has no dispatch
    # continuation in its own thread after the original caller timed out.
    assert_no_effects(manager, client, container, workspace)


def test_ordinary_container_exec_and_capture_gated_cleanup_remain_available(tmp_path):
    manager, client, container = runtime({"purpose": "ordinary"})
    client.containers.get.side_effect = [container, container]
    receipt = manager.exec_in_sandbox(container.id, "ordinary", timeout=1)
    assert receipt.exit_code == 0
    assert receipt.stdout == "ordinary output"
    assert client.api.exec_create.call_args.kwargs["container"] == container.id
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    result = manager.cleanup_sandbox(
        container.id, str(workspace), artifact_capture_confirmed=True
    )
    assert result.termination_confirmed and result.container_removed and result.workspace_removed
    # No later name lookup can substitute another target after the guard.
    assert client.containers.get.call_count == 2
    container.stop.assert_called_once_with(timeout=2)
    container.remove.assert_called_once_with(v=True)


def test_preconstructed_manager_refuses_managed_context_before_docker_or_tempfiles(
    tmp_path, monkeypatch
):
    manager, client, container = runtime()
    context.enter_managed_context()
    tempfiles = MagicMock(side_effect=AssertionError("must not create workspace"))
    monkeypatch.setattr("src.sandbox.docker_driver.tempfile.mkdtemp", tempfiles)
    actions = [
        lambda: manager.spawn_sandbox("repo", "main", OpenJulesConfig()),
        lambda: manager.exec_in_sandbox(container.id, "must not run"),
        lambda: manager._stop(container.id),
        lambda: manager.cleanup_sandbox(container.id, str(tmp_path), artifact_capture_confirmed=True),
        lambda: SandboxManager(client),
    ]
    for action in actions:
        with pytest.raises(context.LegacyExecutionRefused):
            action()
    assert client.mock_calls == []
    assert container.mock_calls == []
    assert manager._quarantined == set()
    tempfiles.assert_not_called()


@pytest.mark.parametrize("changed_at", [1, 2])
def test_reload_identity_mismatch_cannot_redirect_removal_or_confirm_release(
    tmp_path, changed_at
):
    manager, client, container = runtime()
    original_id = container.id
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    (workspace / "retained.txt").write_text("original")

    def reload():
        if container.reload.call_count == changed_at:
            container.id = "foreign-container"

    container.reload.side_effect = reload
    result = manager.cleanup_sandbox(
        original_id, str(workspace), artifact_capture_confirmed=True
    )
    # The ordinary stop was admitted under the original owned identity. A
    # later inconsistent inspection cannot authorize another target or release.
    container.stop.assert_called_once_with(timeout=2)
    container.remove.assert_not_called()
    assert not result.termination_confirmed and not result.workspace_removed
    assert (workspace / "retained.txt").read_text() == "original"
