"""Integration tests for Forge Providers and TaskExecutor interactions."""

from unittest.mock import MagicMock
import pytest

from src.agent.engine import AgentEngine, AgentResult
from src.forge.github import GitHubProvider
from src.forge.radicle import RadicleProvider
from src.git_manager.lifecycle import GitDiffSummary, GitLifecycleManager
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import ExecResult, SandboxContext, SandboxManager
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor

pytestmark = pytest.mark.integration


def test_executor_github_provider_integration():
    mock_sandbox = MagicMock(spec=SandboxManager)
    mock_agent = MagicMock(spec=AgentEngine)
    mock_git = MagicMock(spec=GitLifecycleManager)
    mock_gh_client = MagicMock()

    # Context setup
    ctx = SandboxContext("c-gh", "/tmp/ws", "https://github.com/o/r.git", "main", OpenJulesConfig())
    mock_sandbox.run_sandbox.return_value.__enter__.return_value = ctx
    mock_sandbox.exec_in_sandbox.return_value = ExecResult(stdout="", stderr="", exit_code=0)

    # Agent success
    mock_agent.run.return_value = AgentResult(
        success=True,
        turns_taken=2,
        verification_passed=True,
    )

    # Git
    mock_git.create_task_branch.return_value = "openjules/task-10-fix"
    mock_git.commit_changes.return_value = "1" * 40
    mock_git.push_branch.return_value = True
    mock_git.generate_pr_summary.return_value = GitDiffSummary(
        branch_name="openjules/task-10-fix",
        diff="+new code",
        summary="PR body",
    )

    # GitHub Mock
    mock_repo = MagicMock()
    mock_issue = MagicMock()
    mock_pr = MagicMock(html_url="https://github.com/owner/repo/pull/10")
    mock_repo.get_issue.return_value = mock_issue
    mock_repo.create_pull.return_value = mock_pr
    mock_gh_client.get_repo.return_value = mock_repo

    executor = TaskExecutor(
        sandbox_manager=mock_sandbox,
        agent_engine=mock_agent,
        git_manager=mock_git,
        github_client=mock_gh_client,
    )

    payload = TaskPayload(
        forge="github",
        issue_id=10,
        issue_title="Fix user auth timeout",
        issue_body="Auth tokens expire prematurely",
        repo_full_name="owner/repo",
        repo_clone_url="https://github.com/owner/repo.git",
    )

    success = executor.execute_task(payload)
    assert success is True
    mock_repo.create_pull.assert_called_once()
    mock_issue.create_comment.assert_called()


def test_executor_radicle_provider_does_not_translate_missing_patch_output_to_success():
    mock_sandbox = MagicMock(spec=SandboxManager)
    mock_agent = MagicMock(spec=AgentEngine)
    mock_git = MagicMock(spec=GitLifecycleManager)

    ctx = SandboxContext("c-rad", "/tmp/ws", "rad:z4V1sJY123", "master", OpenJulesConfig())
    mock_sandbox.run_sandbox.return_value.__enter__.return_value = ctx
    mock_sandbox.exec_in_sandbox.return_value = ExecResult(stdout="", stderr="", exit_code=0)

    mock_agent.run.return_value = AgentResult(success=True, turns_taken=3, verification_passed=True)

    mock_git.create_task_branch.return_value = "openjules/task-rad-20-fix"
    mock_git.commit_changes.return_value = "2" * 40
    mock_git.push_branch.return_value = True
    mock_git.generate_pr_summary.return_value = GitDiffSummary(
        branch_name="openjules/task-rad-20-fix",
        diff="+patch code",
        summary="Patch description",
    )

    rad_provider = RadicleProvider(sandbox_manager=mock_sandbox)

    executor = TaskExecutor(
        sandbox_manager=mock_sandbox,
        agent_engine=mock_agent,
        git_manager=mock_git,
        radicle_provider=rad_provider,
    )

    payload = TaskPayload(
        forge="radicle",
        issue_id="rad-iss-20",
        issue_title="P2P discovery fix",
        issue_body="DHT routing table refresh",
        repo_full_name="rad:z4V1sJY123",
        repo_clone_url="rad:z4V1sJY123",
        default_branch="master",
    )

    success = executor.execute_task(payload)
    assert success is False
    # Configuration inspection can run, but publication is not attempted.
    assert all("rad patch" not in call.args[1] for call in mock_sandbox.exec_in_sandbox.call_args_list)
