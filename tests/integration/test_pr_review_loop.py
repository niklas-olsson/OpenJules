"""Integration tests for PR review feedback iteration loop."""

from unittest.mock import MagicMock
import pytest

from src.agent.engine import AgentResult
from src.sandbox.docker_driver import SandboxContext
from src.worker.pr_reviewer import PRReviewHandler, ReviewComment

pytestmark = pytest.mark.integration


def test_pr_review_handler_address_feedback():
    mock_sandbox = MagicMock()
    mock_agent = MagicMock()
    mock_git = MagicMock()

    ctx = MagicMock(spec=SandboxContext)
    mock_sandbox.run_sandbox.return_value.__enter__.return_value = ctx
    mock_agent.run.return_value = AgentResult(success=True, turns_taken=2, verification_passed=True)
    mock_git.commit_changes.return_value = "c" * 40
    mock_git.push_branch.return_value = True

    handler = PRReviewHandler(
        sandbox_manager=mock_sandbox,
        agent_engine=mock_agent,
        git_manager=mock_git,
    )

    comments = [
        ReviewComment(id=1, body="Please handle None check on line 15", path="src/api.py", line=15, author="senior_dev")
    ]

    success = handler.address_review_feedback(
        repo_clone_url="https://github.com/org/repo.git",
        branch_name="openjules/task-12-feature",
        comments=comments,
    )

    assert success is True
    mock_agent.run.assert_called_once()
    mock_git.commit_changes.assert_called_once()
    mock_git.push_branch.assert_called_once()
