"""Unit tests for the OpenJules CLI tool."""

from unittest.mock import MagicMock, patch
import pytest

from src.cli import inspect_polyphony, run_cli_task


def test_cli_polyphony_inspect(capsys):
    inspect_polyphony("owner/test-repo")
    captured = capsys.readouterr()
    assert "Keystone Polyphony Swarm for 'owner/test-repo'" in captured.out
    assert "Swarm Key (SHA-256):" in captured.out
    assert "Node ID:" in captured.out


def test_cli_run_task():
    with patch("src.worker.executor.TaskExecutor.execute_task", return_value=True) as mock_exec:
        exit_code = run_cli_task("Add unit tests for auth", "owner/test-repo", "main")
        assert exit_code == 0
        mock_exec.assert_called_once()
        payload = mock_exec.call_args[0][0]
        assert payload.issue_title == "Add unit tests for auth"
        assert payload.repo_full_name == "owner/test-repo"


def test_cli_run_task_failure():
    with patch("src.worker.executor.TaskExecutor.execute_task", return_value=False):
        exit_code = run_cli_task("Failing task", "owner/test-repo")
        assert exit_code == 1
