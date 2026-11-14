"""Unit and integration tests for Radicle forge and multi-forge support."""

import json
from unittest.mock import MagicMock, patch
import pytest

from src.forge.base import ForgeProvider, ProposalResult
from src.forge.github import GitHubProvider
from src.forge.radicle import RadicleProvider
from src.sandbox.docker_driver import ExecResult, SandboxContext, SandboxManager
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor
from src.worker.radicle_poller import RadicleNodePoller


def test_radicle_provider_get_clone_url():
    rad = RadicleProvider()
    assert rad.get_clone_url("z4V1sJY123") == "rad:z4V1sJY123"
    assert rad.get_clone_url("rad:z4V1sJY123") == "rad:z4V1sJY123"


def test_radicle_provider_create_proposal_cli():
    mock_sandbox = MagicMock(spec=SandboxManager)
    mock_sandbox.exec_in_sandbox.return_value = ExecResult(
        stdout="rad:patch:abcd1234efgh\n",
        stderr="",
        exit_code=0,
    )

    rad = RadicleProvider(sandbox_manager=mock_sandbox)
    mock_context = MagicMock(spec=SandboxContext)
    mock_context.container_id = "cont-rad-1"

    prop = rad.create_proposal(
        repo_identifier="rad:z4V1sJY123",
        title="fix: radicle support",
        description="add radicle adapter",
        source_branch="openjules/task-1-fix",
        target_branch="master",
        context=mock_context,
    )

    assert prop.id == "rad:patch:abcd1234efgh"
    assert "rad:z4V1sJY123/patches/rad:patch:abcd1234efgh" in prop.url_or_id
    mock_sandbox.exec_in_sandbox.assert_called_once()


def test_radicle_poller_repository(monkeypatch):
    poller = RadicleNodePoller(
        node_url="http://mock-radicle:8080/api/v1",
        tracked_repos=["rad:z4V1sJY123"],
    )

    mock_issues = [
        {
            "id": "issue-001",
            "title": "Fix memory leak in node",
            "labels": ["openjules:run"],
            "thread": {"comments": [{"body": "Please fix the buffer overflow"}]},
        },
        {
            "id": "issue-002",
            "title": "Unrelated issue",
            "labels": ["question"],
        },
    ]

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = mock_issues

    with patch("httpx.Client.get", return_value=mock_resp):
        tasks = poller.poll_repository("rad:z4V1sJY123")
        assert len(tasks) == 1
        assert tasks[0].forge == "radicle"
        assert tasks[0].issue_id == "issue-001"
        assert tasks[0].issue_title == "Fix memory leak in node"
        assert tasks[0].issue_body == "Please fix the buffer overflow"

        # Subsequent poll should skip already processed issues
        second_poll = poller.poll_repository("rad:z4V1sJY123")
        assert len(second_poll) == 0




def test_task_executor_with_radicle_forge():
    mock_sandbox = MagicMock()
    mock_agent = MagicMock()
    mock_git = MagicMock()
    mock_rad_provider = MagicMock(spec=RadicleProvider)

    mock_ctx = MagicMock(spec=SandboxContext)
    mock_ctx.container_id = "cont-123"
    mock_ctx.workspace_dir = "/tmp/ws"
    mock_sandbox.run_sandbox.return_value.__enter__.return_value = mock_ctx
    mock_sandbox.exec_in_sandbox.return_value = MagicMock(exit_code=1, stdout="")

    mock_agent_res = MagicMock()
    mock_agent_res.success = True
    mock_agent_res.turns_taken = 3
    mock_agent.run.return_value = mock_agent_res

    mock_git.create_task_branch.return_value = "openjules/task-rad-1"
    mock_git.commit_changes.return_value = "d" * 40
    mock_git.push_branch.return_value = True
    mock_git.generate_pr_summary.return_value = MagicMock(
        summary="Radicle Patch summary", diff="some diff"
    )

    mock_rad_provider.create_proposal.return_value = ProposalResult(
        id="patch-123",
        url_or_id="rad:z4V1sJY123/patches/patch-123",
        title="fix: radicle bug",
        target_branch="master",
        source_branch="openjules/task-rad-1",
    )

    executor = TaskExecutor(
        sandbox_manager=mock_sandbox,
        agent_engine=mock_agent,
        git_manager=mock_git,
        radicle_provider=mock_rad_provider,
    )

    payload = TaskPayload(
        forge="radicle",
        issue_id="issue-99",
        issue_title="Fix Radicle protocol edge case",
        issue_body="Description of protocol bug",
        repo_full_name="rad:z4V1sJY123",
        repo_clone_url="rad:z4V1sJY123",
        default_branch="master",
    )

    result = executor.execute_task(payload)
    assert result is True
    mock_rad_provider.create_proposal.assert_called_once()
    mock_rad_provider.post_issue_comment.assert_called()
