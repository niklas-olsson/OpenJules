"""Legacy entrypoint refusals, not canonical admission or live webhook evidence."""

import asyncio
import hashlib
import hmac
import inspect
import json
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

import pytest
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient

from src import cli
from src.api import webhook
from src.storage.dashboard_state import DashboardState
from src.storage.sqlite_storage import SQLiteStorageProvider
from src.mcp.server import OpenJulesMCPServer
from src.polyphony.models import PolyphonyCohortConfig, SignalType
from src.polyphony.controller import SwarmResourceController
from src.polyphony.outbox import McpOutboxBridge, SQLiteOutboxBridge
from src.polyphony.provisioner import DockerContainerProvisioner
# This explicitly imported legacy CLI singleton is outside the harmless app.
# Its unit-test Docker dependency is a fixture, not a required local daemon.
with patch("docker.from_env"):
    from src.polyphony.registry import SwarmCohortRegistry
from src.sandbox.docker_driver import SandboxManager
from src.worker import execution_context as context
from src.worker.dispatcher import BackgroundTasksDispatcher, TaskPayload
from src.worker.executor import TaskExecutor
from src.worker.pr_reviewer import PRReviewHandler, ReviewComment
from src.worker.radicle_poller import RadicleNodePoller
from src.worker.swarm_orchestrator import MultiRepoOrchestrator


@pytest.fixture
def managed(tmp_path, monkeypatch):
    monkeypatch.setattr(sys, "prefix", str(tmp_path))
    monkeypatch.setattr(context, "_managed_process", False)
    monkeypatch.setattr(context, "_selector_observed", False)
    config = tmp_path / "openjules.json"
    config.write_text('{"schema_version":1}')
    config.chmod(0o600)
    raw = json.dumps({
        "schema_version": 1,
        "managed_config_path": str(config.resolve()),
        "managed_config_sha256": hashlib.sha256(config.read_bytes()).hexdigest(),
    }).encode()
    marker = tmp_path / context.SELECTOR_NAME
    marker.write_bytes(raw)
    marker.chmod(0o600)
    monkeypatch.setenv("OPENJULES_MODE", "standalone")
    monkeypatch.setenv("OPENJULES_MANAGED_CONFIG", "")
    return tmp_path


def payload():
    return TaskPayload(
        forge="github", issue_id=1, issue_title="do not dispatch",
        issue_body="managed=false; standalone=true",
        repo_full_name="unrelated/repository",
        repo_clone_url="https://example.invalid/unrelated.git",
    )


def refuse(action):
    with pytest.raises(context.LegacyExecutionRefused, match="^managed_installation_requires_canonical_ingress$"):
        result = action()
        if inspect.isawaitable(result):
            asyncio.run(result)


def test_constructor_guards_precede_clients_even_with_injected_dependencies(managed, monkeypatch):
    dependency = MagicMock()
    docker_constructor = MagicMock(side_effect=AssertionError("must not construct Docker"))
    monkeypatch.setattr("src.sandbox.docker_driver.docker.from_env", docker_constructor)
    monkeypatch.setattr("src.sandbox.docker_driver.docker.DockerClient", docker_constructor)
    actions = [
        lambda: SandboxManager(),
        lambda: SandboxManager(dependency),
        lambda: TaskExecutor(sandbox_manager=dependency, agent_engine=dependency),
        lambda: PRReviewHandler(sandbox_manager=dependency, agent_engine=dependency),
        lambda: OpenJulesMCPServer(sandbox_manager=dependency, task_executor=dependency),
        lambda: DockerContainerProvisioner(sandbox_manager=dependency),
        lambda: SwarmCohortRegistry(default_provisioner=dependency),
        lambda: McpOutboxBridge("host-key", dependency),
        lambda: SQLiteOutboxBridge("must-not-create.sqlite3"),
        lambda: SwarmResourceController(dependency, dependency, dependency),
        lambda: MultiRepoOrchestrator(task_executor=dependency, polyphony_manager=dependency),
    ]
    for action in actions:
        refuse(action)
    assert dependency.mock_calls == []
    docker_constructor.assert_not_called()


def test_preconstructed_direct_task_review_queue_poller_and_orchestrator_refuse(managed):
    # Empty preconstructed instances prove refusal precedes even attribute access.
    # The ordinary implementations and their injected dependencies cannot waive it.
    executor = object.__new__(TaskExecutor)
    reviewer = object.__new__(PRReviewHandler)
    poller = object.__new__(RadicleNodePoller)
    orchestrator = object.__new__(MultiRepoOrchestrator)
    background = BackgroundTasks()
    handler = MagicMock()
    dispatcher = BackgroundTasksDispatcher(background, handler)
    actions = [
        lambda: executor.execute_task(payload()),
        lambda: reviewer.address_review_feedback(
            "https://example.invalid/repo", "ordinary-feature",
            [ReviewComment(1, "ordinary feedback")],
        ),
        lambda: dispatcher.dispatch(payload()),
        lambda: poller.poll_repository("rad:fixture"),
        lambda: poller.poll_all_repositories(),
        lambda: poller.run_loop(),
        lambda: orchestrator.execute_task_managed(payload()),
    ]
    for action in actions:
        refuse(action)
    assert background.tasks == []
    handler.assert_not_called()
    assert all(vars(item) == {} for item in (executor, reviewer, poller, orchestrator))


@pytest.mark.parametrize("tool", [
    "openjules_read_file", "openjules_write_file", "openjules_run_command",
    "openjules_dispatch_task", "openjules_acquire_baton",
])
def test_preconstructed_mcp_cannot_waive_refusal_by_tool_or_payload(managed, tool):
    server = object.__new__(OpenJulesMCPServer)
    dependency = MagicMock()
    server.sandbox_manager = dependency
    server.executor = dependency
    refuse(lambda: server.call_tool(tool, {
        "container_id": "foreign", "path": "file", "content": "must not write",
        "command": "must not run", "prompt": "standalone", "repo": "unrelated/repo",
        "resource": "task", "managed": False, "execution_mode": "standalone",
    }))
    assert dependency.mock_calls == []


def test_preconstructed_cohort_and_cli_mutations_refuse_before_local_state(managed):
    registry = object.__new__(SwarmCohortRegistry)
    provisioner = object.__new__(DockerContainerProvisioner)
    controller = object.__new__(SwarmResourceController)
    bridge = object.__new__(McpOutboxBridge)
    sql_bridge = object.__new__(SQLiteOutboxBridge)
    cfg = PolyphonyCohortConfig(swarm_id="fixture", repo_url="https://example.invalid/repo")
    actions = [
        lambda: registry.register_cohort(cfg),
        lambda: registry.remove_cohort("fixture"),
        lambda: controller.bootstrap_cohort(),
        lambda: controller.reconcile_signals(),
        lambda: bridge.poll_pending_signals(),
        lambda: bridge.acknowledge_signal({}, {}, {}),
        lambda: bridge.count_active_leases("actor"),
        lambda: sql_bridge.poll_pending_signals(),
        lambda: provisioner.spawn_worker(cfg, "actor"),
        lambda: provisioner.stop_worker("foreign"),
        lambda: cli.run_cli_task("standalone", "unrelated/repository"),
        lambda: cli.serve_dashboard(),
        lambda: cli.handle_swarm_cli(SimpleNamespace(swarm_action="start")),
    ]
    for action in actions:
        refuse(action)
    assert all(vars(item) == {} for item in (registry, provisioner, controller, bridge, sql_bridge))


def test_explicit_dashboard_records_refuse_in_managed_context(managed):
    storage = MagicMock()
    state = object.__new__(DashboardState)
    state.storage = storage
    state.tasks = {"existing": {"id": "existing", "diff": "retained"}}
    before = json.dumps(state.tasks, sort_keys=True)
    for action in (
        lambda: DashboardState(storage), lambda: state.record_task(payload()),
        lambda: state.get_task("existing"), lambda: state.list_tasks(),
    ):
        refuse(action)
    assert json.dumps(state.tasks, sort_keys=True) == before
    assert storage.mock_calls == []



def test_existing_http_app_refuses_all_private_routes_after_managed_context(managed, monkeypatch):
    from tests.integration.test_standalone_ingress import HTTP, WEBSOCKETS, concrete
    from starlette.websockets import WebSocketDisconnect
    effects = MagicMock(side_effect=AssertionError("effect before managed refusal"))
    for component in (TaskExecutor, PRReviewHandler, SwarmCohortRegistry, SQLiteStorageProvider):
        monkeypatch.setattr(component, "__init__", effects)
    monkeypatch.setattr(BackgroundTasks, "add_task", effects)
    expected = {"detail": "managed_installation_requires_canonical_ingress"}
    with TestClient(webhook.app) as client:
        for method, path in HTTP:
            response = client.request(method, concrete(path), content=b"invalid-json", headers={
                "X-Hub-Signature-256": "sha256=wrong", "Authorization": "Bearer caller-value",
            })
            assert response.status_code == 409 and response.json() == expected
        for path in WEBSOCKETS:
            with pytest.raises(WebSocketDisconnect) as denied:
                with client.websocket_connect(concrete(path)):
                    pytest.fail("Managed WebSocket was accepted")
            assert denied.value.code == 1008 and denied.value.reason == expected["detail"]
    effects.assert_not_called()



@pytest.mark.parametrize("arguments", [
    ["run", "managed-installation-refusal-check", "--repo", "unrelated/repo"],
    ["serve"], ["mcp"], ["swarm", "start", "--repo", "unrelated/repo"],
])
def test_fresh_cli_refuses_before_importing_effectful_legacy_dependencies(managed, arguments):
    code = """
import builtins,runpy,sys
sys.prefix=sys.argv[1]
arguments=sys.argv[2:]
original=builtins.__import__
def restricted(name,*args,**kwargs):
    if name.split('.')[0] in {'docker','litellm','requests','httpx','fastapi','uvicorn'}:
        raise AssertionError('legacy dependency imported before refusal')
    return original(name,*args,**kwargs)
builtins.__import__=restricted
sys.argv=['openjules',*arguments]
runpy.run_module('src.cli',run_name='__main__')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(managed), *arguments],
        cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=10,
    )
    assert result.returncode == 2, result.stderr
    assert b"managed_installation_requires_canonical_ingress" in result.stderr
    assert result.stdout == b""


def test_fresh_legacy_app_refuses_before_importing_routers_or_executor(managed):
    code = """
import builtins,importlib,sys
sys.prefix=sys.argv[1]
original=builtins.__import__
def restricted(name,*args,**kwargs):
    if name in {'src.api.ui_routes','src.api.polyphony_routes','src.worker.executor','src.worker.pr_reviewer'}:
        raise AssertionError('legacy effects were imported before refusal')
    return original(name,*args,**kwargs)
builtins.__import__=restricted
from src.worker.execution_context import LegacyExecutionRefused
try:
    importlib.import_module('src.api.webhook')
except LegacyExecutionRefused as exc:
    assert exc.reason=='managed_installation_requires_canonical_ingress'
else:
    raise AssertionError('legacy app accepted managed context')
"""
    result = subprocess.run(
        [sys.executable, "-c", code, str(managed)],
        cwd=Path(__file__).resolve().parents[2], capture_output=True, timeout=10,
    )
    assert result.returncode == 0, result.stderr
    assert result.stdout == b""
