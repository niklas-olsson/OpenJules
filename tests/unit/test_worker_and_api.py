"""Unit and integration tests for Phase 4: API Webhook and Worker."""

import hashlib
import hmac
import json
from unittest.mock import MagicMock
import pytest
from fastapi.testclient import TestClient

from src.api.webhook import app, verify_github_signature
from src.sandbox.docker_driver import SandboxContext
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor


def test_verify_github_signature():
    secret = "mysecret123"
    body = b'{"hello": "world"}'
    valid_sig = "sha256=" + hmac.new(secret.encode("utf-8"), body, hashlib.sha256).hexdigest()

    assert verify_github_signature(body, valid_sig, secret) is True
    assert verify_github_signature(body, "sha256=invalid", secret) is False
    assert verify_github_signature(body, None, secret) is False
    assert verify_github_signature(body, valid_sig, "") is False


def test_health_check():
    client = TestClient(app)
    resp = client.get("/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"








def test_task_executor_run():
    mock_sandbox = MagicMock()
    mock_agent = MagicMock()
    mock_git = MagicMock()
    mock_gh = MagicMock()

    # Setup context manager for run_sandbox
    mock_ctx = MagicMock(spec=SandboxContext)
    mock_ctx.container_id = "cont-123"
    mock_ctx.workspace_dir = "/tmp/ws"
    mock_sandbox.run_sandbox.return_value.__enter__.return_value = mock_ctx
    mock_sandbox.exec_in_sandbox.return_value = MagicMock(exit_code=1, stdout="")

    # Mock agent engine
    mock_agent_res = MagicMock()
    mock_agent_res.success = True
    mock_agent_res.turns_taken = 2
    mock_agent.run.return_value = mock_agent_res

    # Mock git lifecycle
    mock_git.create_task_branch.return_value = "openjules/task-1-fix-test"
    mock_git.commit_changes.return_value = "c" * 40
    mock_git.push_branch.return_value = True
    mock_git.generate_pr_summary.return_value = MagicMock(
        summary="PR description", diff="some diff"
    )

    # Mock github client
    mock_repo = MagicMock()
    mock_issue = MagicMock()
    mock_pr = MagicMock(html_url="https://github.com/owner/repo/pull/1")
    mock_repo.get_issue.return_value = mock_issue
    mock_repo.create_pull.return_value = mock_pr
    mock_gh.get_repo.return_value = mock_repo

    executor = TaskExecutor(
        sandbox_manager=mock_sandbox,
        agent_engine=mock_agent,
        git_manager=mock_git,
        github_client=mock_gh,
    )

    payload = TaskPayload(
        issue_id=1,
        issue_title="Fix bug",
        issue_body="Bug description",
        repo_full_name="owner/repo",
        repo_clone_url="https://github.com/owner/repo.git",
    )

    result = executor.execute_task(payload)
    assert result is True
    mock_repo.create_pull.assert_called_once()
    mock_issue.create_comment.assert_called()
