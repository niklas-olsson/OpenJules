"""Unqualified Radicle writes refuse; inspection and retained work remain distinct."""

from types import SimpleNamespace
from unittest.mock import MagicMock

import httpx
import pytest
from docker.errors import DockerException

from src.agent.engine import AgentResult
from src.forge.radicle import RadicleProvider, RadiclePublicationUnsupported
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import SandboxContext, SandboxManager
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor
from tests.unit.test_sandbox_recovery import runtime


def test_missing_context_never_returns_a_simulated_patch():
    with pytest.raises(RadiclePublicationUnsupported, match="radicle_patch_publication_unsupported"):
        RadicleProvider().create_proposal(
            "rad:fixture", "private title", "private description", "source", "target")


def test_comment_refuses_before_any_http_or_cli_attempt_without_logging_private_text(monkeypatch, caplog):
    client = MagicMock(side_effect=AssertionError("unqualified HTTP write"))
    monkeypatch.setattr("src.forge.radicle.httpx.Client", client)
    sandbox = MagicMock(spec=SandboxManager)
    provider = RadicleProvider(sandbox_manager=sandbox, rad_passphrase="fixture-private-passphrase")
    assert provider.post_issue_comment("rad:private-repository", "private-issue", "private comment body") is False
    client.assert_not_called()
    sandbox.exec_in_sandbox.assert_not_called()
    assert "radicle_comment_publication_unsupported" in caplog.text
    assert all(value not in caplog.text for value in (
        "private-repository", "private-issue", "private comment body", "fixture-private-passphrase"))


@pytest.mark.parametrize("response", ["issues", "refused", "malformed", "reply_lost"])
def test_existing_issue_inspection_keeps_its_single_read_and_safe_fallback(monkeypatch, response):
    requests = []
    issues = [{"id": "fixture-issue", "title": "Retained inspection"}]

    def handle(request):
        requests.append((request.method, str(request.url)))
        if response == "reply_lost":
            raise httpx.ReadTimeout("fixture read reply unavailable", request=request)
        if response == "issues":
            return httpx.Response(200, json=issues)
        if response == "refused":
            return httpx.Response(503, text="fixture unavailable")
        return httpx.Response(200, content=b"not JSON")

    client_type = httpx.Client
    monkeypatch.setattr("src.forge.radicle.httpx.Client", lambda **kw:
        client_type(transport=httpx.MockTransport(handle), **kw))
    monkeypatch.delenv("RADICLE_NODE_URL", raising=False)
    sandbox = MagicMock(spec=SandboxManager)
    provider = RadicleProvider(node_url="http://fixture.invalid/api/v1", sandbox_manager=sandbox)
    assert provider.fetch_open_issues("rad:fixture") == (issues if response == "issues" else [])
    assert requests == [("GET", "http://fixture.invalid/api/v1/projects/rad:fixture/issues")]
    sandbox.exec_in_sandbox.assert_not_called()


@pytest.mark.parametrize("cleanup_unknown", [False, True])
def test_executor_refused_publication_preserves_prior_work_and_never_reports_success(tmp_path, monkeypatch, cleanup_unknown):
    # Real SandboxManager lifecycle and cleanup, with controlled Docker replies.
    manager, docker_client, container = runtime()
    context = SandboxContext(container.id, str(tmp_path), "rad:fixture", "main", OpenJulesConfig())
    manager.spawn_sandbox = lambda **_: context
    docker_client.api.exec_start.return_value = (b"", b"")
    docker_client.api.exec_inspect.return_value = {"Running": False, "ExitCode": 1}
    if cleanup_unknown:
        container.stop.side_effect = DockerException("fixture stop reply unavailable")
    retained = tmp_path / "agent-work.txt"
    retained.write_text("uncaptured task work", encoding="utf-8")

    agent, git, polyphony_manager = MagicMock(), MagicMock(), MagicMock()
    agent.run.return_value = AgentResult(success=True, turns_taken=1, verification_passed=True)
    git.create_task_branch.return_value = "openjules/fixture-task"
    git.commit_changes.return_value = "a" * 40
    git.push_branch.return_value = True
    git.generate_pr_summary.return_value = SimpleNamespace(summary="private task summary")
    polyphony = polyphony_manager.get_or_create_client.return_value
    polyphony.acquire_baton.return_value = True

    provider = RadicleProvider(sandbox_manager=manager)
    provider.post_issue_comment = MagicMock(wraps=provider.post_issue_comment)
    provider.create_proposal = MagicMock(wraps=provider.create_proposal)
    http_client = MagicMock(side_effect=AssertionError("unqualified HTTP publication"))
    monkeypatch.setattr("src.forge.radicle.httpx.Client", http_client)
    executor = TaskExecutor(sandbox_manager=manager, agent_engine=agent, git_manager=git,
        github_provider=MagicMock(), radicle_provider=provider, polyphony_manager=polyphony_manager)
    executor.clarification_detector.evaluate_task = lambda **_: SimpleNamespace(is_ambiguous=False, questions=[])
    assert executor.post_issue_comment("radicle", "rad:fixture", "fixture-issue", "status") is False
    payload = TaskPayload(forge="radicle", issue_id="fixture-issue", issue_title="Fixture task",
        issue_body="Explicit fixture work", repo_full_name="rad:fixture", repo_clone_url="rad:fixture")

    assert executor.execute_task(payload, git_token="fixture-git-token") is False
    agent.run.assert_called_once()
    git.push_branch.assert_called_once()  # Earlier legacy effects are not undone by write refusal.
    provider.create_proposal.assert_called_once()
    http_client.assert_not_called()
    assert all("rad patch" not in str(call) for call in docker_client.api.exec_create.call_args_list)
    messages = [call.args[-1] for call in provider.post_issue_comment.call_args_list]
    assert any("radicle_patch_publication_unsupported" in message for message in messages)
    assert all("successfully opened" not in message and "rad-patch-" not in message for message in messages)
    statuses = [call.kwargs["status"] for call in polyphony.sync_task_backlog.call_args_list]
    assert statuses == ["in_progress", "error"]
    polyphony.release_all_batons.assert_called_once()
    polyphony.set_status.assert_called_once_with("idle")
    assert retained.read_text(encoding="utf-8") == "uncaptured task work"
    assert context.cleanup_result.termination_confirmed is not cleanup_unknown
    assert context.cleanup_result.artifact_capture_confirmed is False
    assert context.cleanup_result.workspace_removed is False
    container.remove.assert_not_called()
