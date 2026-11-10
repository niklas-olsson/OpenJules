"""Unit tests for Phase 1: Repository config and sandbox runtime."""

import os
from unittest.mock import MagicMock, patch
import pytest

from src.sandbox.config import OpenJulesConfig, load_config_from_file, load_config_from_yaml
from src.sandbox.docker_driver import ExecResult, SandboxContext, SandboxManager


def test_openjules_config_defaults():
    config = OpenJulesConfig()
    assert config.image == "python:3.11-slim"
    assert config.setup == []
    assert config.test_command == "pytest"
    assert config.env == {}
    assert config.timeout_seconds == 900


def test_load_config_from_yaml():
    yaml_content = """
    image: python:3.12-slim
    setup:
      - pip install -r requirements.txt
    test_command: pytest tests/
    env:
      TEST_ENV: "true"
    timeout_seconds: 600
    """
    config = load_config_from_yaml(yaml_content)
    assert config.image == "python:3.12-slim"
    assert config.setup == ["pip install -r requirements.txt"]
    assert config.test_command == "pytest tests/"
    assert config.env == {"TEST_ENV": "true"}
    assert config.timeout_seconds == 600


def test_load_config_from_yaml_empty_or_invalid():
    assert load_config_from_yaml("").image == "python:3.11-slim"
    assert load_config_from_yaml("invalid: [").image == "python:3.11-slim"


def test_load_config_from_file(tmp_path):
    conf_file = tmp_path / ".openjules.yaml"
    conf_file.write_text("image: node:20\ntest_command: npm test\n")
    config = load_config_from_file(conf_file)
    assert config.image == "node:20"
    assert config.test_command == "npm test"

    missing_config = load_config_from_file(tmp_path / "nonexistent.yaml")
    assert missing_config.image == "python:3.11-slim"


def test_inject_git_token():
    url = "https://github.com/org/repo.git"
    injected = SandboxManager._inject_git_token(url, "ghp_secret123")
    assert injected == "https://x-access-token:ghp_secret123@github.com/org/repo.git"

    # No token
    assert SandboxManager._inject_git_token(url, None) == url


def test_sandbox_manager_spawn_and_exec():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.id = "cont-12345"
    mock_container.attrs = {"State": {"Running": False, "Restarting": False}}
    mock_client.containers.run.return_value = mock_container
    mock_client.containers.get.return_value = mock_container

    mock_client.api.exec_create.return_value = {"Id": "exec-abc"}
    mock_client.api.exec_start.return_value = (b"Clone success\n", b"")
    mock_client.api.exec_inspect.return_value = {"ExitCode": 0, "Running": False}

    manager = SandboxManager(docker_client=mock_client)
    config = OpenJulesConfig(setup=["echo setting up"])

    context = manager.spawn_sandbox(
        repo_url="https://github.com/org/repo.git",
        branch="main",
        config=config,
        git_token="tok123",
    )

    assert context.container_id == "cont-12345"
    assert os.path.exists(context.workspace_dir)

    # Exec command test
    res = manager.exec_in_sandbox("cont-12345", "pytest")
    assert res.exit_code == 0
    assert "Clone success" in res.stdout

    # Cleanup
    manager.cleanup_sandbox(
        context.container_id, context.workspace_dir, artifact_capture_confirmed=True
    )
    assert not os.path.exists(context.workspace_dir)
    mock_container.stop.assert_called()
    mock_container.remove.assert_called_with(v=True)


def test_sandbox_context_manager_teardown():
    mock_client = MagicMock()
    mock_container = MagicMock()
    mock_container.id = "cont-ctx-123"
    mock_container.attrs = {"State": {"Running": False, "Restarting": False}}
    mock_client.containers.run.return_value = mock_container
    mock_client.containers.get.return_value = mock_container

    mock_client.api.exec_create.return_value = {"Id": "exec-id"}
    mock_client.api.exec_start.return_value = (b"OK", b"")
    mock_client.api.exec_inspect.return_value = {"ExitCode": 0, "Running": False}

    manager = SandboxManager(docker_client=mock_client)
    config = OpenJulesConfig()

    ws_dir = None
    with pytest.raises(ValueError):
        with manager.run_sandbox(
            repo_url="https://github.com/org/repo.git",
            branch="main",
            config=config,
        ) as ctx:
            ws_dir = ctx.workspace_dir
            assert os.path.exists(ws_dir)
            raise ValueError("Simulated task failure")

    assert ws_dir is not None
    assert os.path.exists(ws_dir)
    assert ctx.cleanup_result.termination_confirmed is True
    assert ctx.cleanup_result.artifact_capture_confirmed is False
    mock_container.remove.assert_not_called()
    # The retention assertion above is the behavior under test. Explicitly
    # acknowledge capture of this fixture's empty directory to release it.
    manager.cleanup_sandbox(ctx.container_id, ws_dir, artifact_capture_confirmed=True)
