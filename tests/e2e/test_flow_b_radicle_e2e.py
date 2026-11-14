"""Trusted local Radicle execution/poller flow with deterministic fixtures."""

import json
from unittest.mock import MagicMock, patch
import pytest

from src.agent.engine import AgentEngine
from src.forge.radicle import RadicleProvider
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import ExecResult, SandboxContext, SandboxManager
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor
from src.worker.radicle_poller import RadicleNodePoller

pytestmark = pytest.mark.e2e


def test_flow_b_radicle_full_lifecycle_e2e(tmp_path):
    ws_dir = str(tmp_path)
    mock_sandbox = MagicMock(spec=SandboxManager)

    ctx = SandboxContext("cont-flow-b", ws_dir, "rad:z4V1sJY123", "master", OpenJulesConfig(test_command="pytest"))
    mock_sandbox.run_sandbox.return_value.__enter__.return_value = ctx

    # Track executed commands inside sandbox
    executed_cmds = []

    def fake_exec(cid, cmd, timeout=120, workdir="/workspace", env=None):
        executed_cmds.append(cmd)
        if "rad patch open" in cmd:
            return ExecResult(stdout="rad:patch:789abcde\n", stderr="", exit_code=0)
        elif "git commit" in cmd:
            return ExecResult(stdout="commit ok\n" + ("b" * 40), stderr="", exit_code=0)
        elif "pytest" in cmd:
            return ExecResult(stdout="all tests green", stderr="", exit_code=0)
        return ExecResult(stdout="ok", stderr="", exit_code=0)

    mock_sandbox.exec_in_sandbox.side_effect = fake_exec

    # Mock LLM sequence: clarification check, Step A planning, Step B action, Step C experience distillation
    mock_llm = MagicMock()
    mock_llm.completion.side_effect = [
        # Clarification check
        MagicMock(choices=[MagicMock(message=MagicMock(content='{"is_ambiguous": false, "rationale": "Clear"}'))]),
        # Planning
        MagicMock(choices=[MagicMock(message=MagicMock(content='{"rationale":"P2P sync","target_files":["node.py"],"planned_tests":["pytest"],"action_steps":["edit"]}'))]),
        # Action completed
        MagicMock(choices=[MagicMock(message=MagicMock(content="TASK_COMPLETED", tool_calls=None))]),
        # Experience record
        MagicMock(choices=[MagicMock(message=MagicMock(content='{"problem_summary":"p2p","solution_pattern":"sync","discovered_rules":[]}'))]),
    ]

    rad_provider = RadicleProvider(sandbox_manager=mock_sandbox)
    executor = TaskExecutor(
        sandbox_manager=mock_sandbox,
        agent_engine=AgentEngine(mock_sandbox, llm_client=mock_llm),
        radicle_provider=rad_provider,
    )

    assert executor.execute_task(TaskPayload(
        forge="radicle", issue_id="rad-issue-77", issue_title="Fix gossip sync delay",
        issue_body="DHT announcements taking over 10s", repo_full_name="rad:z4V1sJY123",
        repo_clone_url="rad:z4V1sJY123", default_branch="master",
    )) is True
    assert any("rad patch open" in command for command in executed_cmds)

    # 2. Test RadicleNodePoller discovering and dispatching issues
    poller_resp = MagicMock()
    poller_resp.status_code = 200
    poller_resp.json.return_value = [
        {
            "id": "iss-poller-1",
            "title": "Automated poll issue",
            "labels": ["openjules:run"],
            "thread": {"comments": [{"body": "Fix routing bug"}]},
        }
    ]

    mock_dispatcher = MagicMock()
    poller = RadicleNodePoller(
        node_url="http://127.0.0.1:8080/api/v1",
        tracked_repos=["rad:z4V1sJY123"],
        dispatcher=mock_dispatcher,
    )

    with patch("httpx.Client.get", return_value=poller_resp):
        dispatched_tasks = poller.poll_all_repositories()
        assert len(dispatched_tasks) == 1
        assert dispatched_tasks[0].forge == "radicle"
        mock_dispatcher.dispatch.assert_called_once()
