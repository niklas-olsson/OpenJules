"""OpenJules Model Context Protocol (MCP) server.

Exposes OpenJules sandbox tools, Polyphony batons, and task dispatching over the standard
Model Context Protocol for IDE extensions (Zed, VS Code Cline/Roo, Cursor).
"""

import json
import logging
from typing import Any, Dict, List, Optional

from src.agent.tools import AgentTools
from src.polyphony.client import PolyphonyClient
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import SandboxManager
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)


class OpenJulesMCPServer:
    """MCP interface exposing OpenJules capabilities."""

    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        task_executor: Optional[TaskExecutor] = None,
    ):
        require_legacy_execution()
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.executor = task_executor or TaskExecutor(sandbox_manager=self.sandbox_manager)

    def get_tool_list(self) -> List[Dict[str, Any]]:
        """Returns MCP tool definitions."""
        return [
            {
                "name": "openjules_read_file",
                "description": "Reads lines from a file in the active sandbox workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "container_id": {"type": "string"},
                        "path": {"type": "string"},
                        "offset": {"type": "integer", "default": 1},
                        "limit": {"type": "integer", "default": 200},
                    },
                    "required": ["container_id", "path"],
                },
            },
            {
                "name": "openjules_write_file",
                "description": "Writes content to a file inside the sandbox workspace.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "container_id": {"type": "string"},
                        "path": {"type": "string"},
                        "content": {"type": "string"},
                    },
                    "required": ["container_id", "path", "content"],
                },
            },
            {
                "name": "openjules_run_command",
                "description": "Executes a shell command inside the sandbox container.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "container_id": {"type": "string"},
                        "command": {"type": "string"},
                    },
                    "required": ["container_id", "command"],
                },
            },
            {
                "name": "openjules_acquire_baton",
                "description": "Acquires an exclusive Keystone Polyphony mutex baton.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "repo": {"type": "string"},
                        "resource": {"type": "string"},
                    },
                    "required": ["repo", "resource"],
                },
            },
            {
                "name": "openjules_dispatch_task",
                "description": "Dispatches an autonomous coding task through OpenJules.",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "prompt": {"type": "string"},
                        "repo": {"type": "string"},
                    },
                    "required": ["prompt", "repo"],
                },
            },
        ]

    def call_tool(self, tool_name: str, arguments: Dict[str, Any]) -> Dict[str, Any]:
        """Dispatches an MCP tool call to the underlying service."""
        require_legacy_execution()
        if tool_name == "openjules_read_file":
            tools = AgentTools(self.sandbox_manager, arguments["container_id"])
            out = tools.read_file(
                arguments["path"],
                offset=arguments.get("offset", 1),
                limit=arguments.get("limit", 200),
            )
            return {"content": [{"type": "text", "text": out}]}

        elif tool_name == "openjules_write_file":
            tools = AgentTools(self.sandbox_manager, arguments["container_id"])
            out = tools.write_file(arguments["path"], arguments["content"])
            return {"content": [{"type": "text", "text": out}]}

        elif tool_name == "openjules_run_command":
            tools = AgentTools(self.sandbox_manager, arguments["container_id"])
            out = tools.run_command(arguments["command"])
            return {"content": [{"type": "text", "text": out}]}

        elif tool_name == "openjules_acquire_baton":
            poly = self.executor.polyphony_manager.get_or_create_client(arguments["repo"])
            acquired = poly.acquire_baton(arguments["resource"])
            status = "ACQUIRED" if acquired else "DENIED"
            return {"content": [{"type": "text", "text": f"Baton {arguments['resource']}: {status}"}]}

        elif tool_name == "openjules_dispatch_task":
            payload = TaskPayload(
                forge="github",
                issue_id=9999,
                issue_title=arguments["prompt"][:80],
                issue_body=arguments["prompt"],
                repo_full_name=arguments["repo"],
                repo_clone_url=arguments["repo"] if arguments["repo"].startswith("http") else f"https://github.com/{arguments['repo']}.git",
            )
            success = self.executor.execute_task(payload)
            return {"content": [{"type": "text", "text": "Task succeeded" if success else "Task failed"}]}

        return {"error": f"Unknown tool: {tool_name}"}
