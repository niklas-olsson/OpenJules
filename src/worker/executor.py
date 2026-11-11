"""Task worker executor running the full OpenJules autonomous coding lifecycle across forges."""

import logging
import os
from typing import Any, Optional
from github import Github, Auth

from src.agent.clarification import TaskClarificationDetector
from src.agent.engine import AgentEngine
from src.forge.base import ForgeProvider, ProposalResult
from src.forge.github import GitHubProvider
from src.forge.radicle import RadicleProvider
from src.git_manager.lifecycle import GitLifecycleManager
from src.polyphony.manager import PolyphonySwarmManager
from src.sandbox.config import OpenJulesConfig, load_config_from_yaml
from src.sandbox.docker_driver import SandboxManager
from src.sandbox.self_healing import EnvironmentSelfHealer
from src.sandbox.test_bisection import TestBisectionManager
from src.worker.auth import get_app_installation_token
from src.worker.dispatcher import TaskPayload
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)


class TaskExecutor:
    """Executes an issue task from sandbox spawn through agent run, git push, and proposal opening."""

    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        agent_engine: Optional[AgentEngine] = None,
        git_manager: Optional[GitLifecycleManager] = None,
        github_client: Optional[Github] = None,
        radicle_provider: Optional[RadicleProvider] = None,
        polyphony_manager: Optional[PolyphonySwarmManager] = None,
    ):
        require_legacy_execution()
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.agent_engine = agent_engine or AgentEngine(self.sandbox_manager)
        self.git_manager = git_manager or GitLifecycleManager(self.sandbox_manager)
        self.github_provider = GitHubProvider(github_client=github_client)
        self.radicle_provider = radicle_provider or RadicleProvider(sandbox_manager=self.sandbox_manager)
        self.polyphony_manager = polyphony_manager or PolyphonySwarmManager()
        self.clarification_detector = TaskClarificationDetector(
            llm_client=getattr(self.agent_engine, "llm_client", None),
            model_name=getattr(self.agent_engine, "model_name", "gpt-4o"),
        )
        self.self_healer = EnvironmentSelfHealer(self.sandbox_manager)
        self.test_bisection = TestBisectionManager(self.sandbox_manager)

    def get_forge_provider(self, forge_type: str) -> ForgeProvider:
        """Retrieves provider for given forge type."""
        if forge_type.lower() == "radicle":
            return self.radicle_provider
        return self.github_provider

    def post_issue_comment(self, forge_type: str, repo_name: str, issue_id: int | str, message: str) -> None:
        """Posts a comment on the issue via the active forge provider."""
        provider = self.get_forge_provider(forge_type)
        provider.post_issue_comment(repo_name, issue_id, message)

    def execute_task(self, payload: TaskPayload, git_token: Optional[str] = None) -> bool:
        """Runs the complete autonomous agent lifecycle."""
        require_legacy_execution()
        forge = payload.forge.lower()
        provider = self.get_forge_provider(forge)

        logger.info(
            f"Starting task execution for {forge} issue #{payload.issue_id} in {payload.repo_full_name}"
        )
        self.post_issue_comment(
            forge,
            payload.repo_full_name,
            payload.issue_id,
            f"🚀 OpenJules received task ({forge}): **{payload.issue_title}**. Initializing sandbox...",
        )

        # Mint token dynamically via GitHub App JWT if credentials are present
        effective_token = git_token or os.environ.get("GITHUB_TOKEN")
        app_id = os.environ.get("GITHUB_APP_ID")
        app_key_path = os.environ.get("GITHUB_APP_PRIVATE_KEY_PATH")

        if not effective_token and app_id and app_key_path and payload.installation_id:
            effective_token = get_app_installation_token(
                app_id=app_id,
                private_key_or_path=app_key_path,
                installation_id=payload.installation_id,
            )

        initial_config = OpenJulesConfig()

        # Subscribe to repo-scoped Keystone Polyphony swarm
        polyphony = self.polyphony_manager.get_or_create_client(payload.repo_full_name)
        task_baton_key = f"task:{payload.issue_id}"

        # Acquire task baton to prevent concurrent duplicate runs on the same issue
        if not polyphony.acquire_baton(task_baton_key):
            self.post_issue_comment(
                forge,
                payload.repo_full_name,
                payload.issue_id,
                f"⏸️ Task #{payload.issue_id} is already in progress by another agent in the Polyphony swarm. Aborting duplicate run.",
            )
            return False

        polyphony.sync_task_backlog(payload.issue_id, payload.issue_title, status="in_progress")

        # Deep Planning Mode: Check if task needs clarification before executing
        clarification = self.clarification_detector.evaluate_task(
            title=payload.issue_title,
            description=payload.issue_body,
        )
        if clarification.is_ambiguous and clarification.questions:
            q_bullets = "\n".join(f"- {q}" for q in clarification.questions)
            self.post_issue_comment(
                forge,
                payload.repo_full_name,
                payload.issue_id,
                f"🤔 **[OpenJules Planning Clarification]**\n"
                f"{clarification.rationale}\n\n"
                f"Please clarify the following before execution proceeds:\n{q_bullets}",
            )
            # If completely empty body, pause execution awaiting user response
            if not payload.issue_body.strip():
                polyphony.release_all_batons()
                polyphony.set_status("awaiting_input")
                return True

        # Strict try...finally sandbox container & volume lifecycle
        try:
            with self.sandbox_manager.run_sandbox(
                repo_url=payload.repo_clone_url,
                branch=payload.default_branch,
                config=initial_config,
                git_token=effective_token,
            ) as context:
                # 1. Read .openjules.yaml if present in repository
                config_res = self.sandbox_manager.exec_in_sandbox(
                    context.container_id, "cat .openjules.yaml 2>/dev/null || cat .openjules.yml 2>/dev/null"
                )
                if config_res.exit_code == 0 and config_res.stdout.strip():
                    context.config = load_config_from_yaml(config_res.stdout)

                # 2. Create task branch
                branch_name = self.git_manager.create_task_branch(
                    context,
                    issue_id=payload.issue_id,
                    title=payload.issue_title,
                )

                # 3. Agent planning and execution loop
                task_instruction = f"Title: {payload.issue_title}\n\nDescription:\n{payload.issue_body}"

                def on_progress(msg: str):
                    self.post_issue_comment(forge, payload.repo_full_name, payload.issue_id, msg)
                    polyphony.share_thought(msg)

                agent_result = self.agent_engine.run(
                    context=context,
                    task_instruction=task_instruction,
                    on_progress=on_progress,
                    polyphony=polyphony,
                )

                if not agent_result.success:
                    self.post_issue_comment(
                        forge,
                        payload.repo_full_name,
                        payload.issue_id,
                        f"❌ Verification failed after {agent_result.turns_taken} turns. Automated tests did not pass cleanly.",
                    )
                    polyphony.sync_task_backlog(payload.issue_id, payload.issue_title, status="failed")
                    return False

                # 4. Commit changes
                commit_msg = f"fix: resolve #{payload.issue_id} - {payload.issue_title}"
                sha = self.git_manager.commit_changes(context, commit_msg)
                if not sha:
                    self.post_issue_comment(
                        forge,
                        payload.repo_full_name,
                        payload.issue_id,
                        "ℹ️ No file changes were detected to commit.",
                    )
                    polyphony.sync_task_backlog(payload.issue_id, payload.issue_title, status="done")
                    return True

                # 5. Push branch to remote / radicle storage
                self.git_manager.push_branch(context, branch_name)

                # 6. Generate summary and diff
                test_output = "Automated test suite verified green."
                diff_summary = self.git_manager.generate_pr_summary(
                    context,
                    issue_id=payload.issue_id,
                    issue_title=payload.issue_title,
                    branch_name=branch_name,
                    test_output=test_output,
                    base_branch=payload.default_branch,
                )

                # 7. Create Proposal (PR on GitHub, Patch on Radicle)
                proposal = provider.create_proposal(
                    repo_identifier=payload.repo_full_name,
                    title=f"fix: {payload.issue_title} (fixes #{payload.issue_id})",
                    description=diff_summary.summary,
                    source_branch=branch_name,
                    target_branch=payload.default_branch,
                    context=context,
                )

                proposal_kind = "Patch" if forge == "radicle" else "Pull Request"
                pr_msg = f"🎉 {proposal_kind} successfully opened: `{proposal.url_or_id}`"
                self.post_issue_comment(forge, payload.repo_full_name, payload.issue_id, pr_msg)
                polyphony.sync_task_backlog(payload.issue_id, payload.issue_title, status="done")
                return True

        except Exception as e:
            logger.exception(f"Fatal error executing task #{payload.issue_id}: {e}")
            self.post_issue_comment(
                forge,
                payload.repo_full_name,
                payload.issue_id,
                f"⚠️ Fatal error during execution: `{str(e)}`",
            )
            polyphony.sync_task_backlog(payload.issue_id, payload.issue_title, status="error")
            return False
        finally:
            # Guarantee strict baton release and swarm status reset on exit
            polyphony.release_all_batons()
            polyphony.set_status("idle")
