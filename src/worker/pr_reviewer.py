"""PR review feedback handler and iteration loop.

Processes reviewer comments on open Pull Requests or Radicle Patches, checks out the
existing branch, executes a fix loop with tests, and pushes an updated commit.
"""

import logging
import os
import re
from dataclasses import dataclass
from typing import List, Optional

from src.agent.engine import AgentEngine
from src.forge.github import GitHubProvider
from src.git_manager.lifecycle import GitLifecycleManager
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import SandboxManager
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)


class ReviewSourceRejected(ValueError):
    """A legacy feedback operation cannot act on this supplied source."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def require_legacy_review_source(branch_name, *source_texts):
    """Refuse current managed-publication signals; absence grants no authority.

    PublicationService appends a 64-hex operation to every slash-terminated
    PublicationPolicy prefix. This also covers custom managed branch prefixes.
    Public markers can only cause refusal, never authorize legacy execution.
    """
    if (
        not isinstance(branch_name, str)
        or not branch_name
        or any(
            value is not None and not isinstance(value, str) for value in source_texts
        )
    ):
        raise ReviewSourceRejected("invalid_legacy_review_source")
    if (
        "/" in branch_name
        and re.fullmatch(r"[0-9a-f]{64}", branch_name.rsplit("/", 1)[1])
    ) or any(
        value is not None and "<!-- openjules-publication:" in value
        for value in source_texts
    ):
        raise ReviewSourceRejected("managed_publication_requires_canonical_review")


@dataclass
class ReviewComment:
    """A reviewer comment on a PR diff or conversation."""

    id: str | int
    body: str
    path: Optional[str] = None
    line: Optional[int] = None
    author: str = ""


class PRReviewHandler:
    """Handles iteration on PRs based on reviewer feedback."""

    def __init__(
        self,
        sandbox_manager: Optional[SandboxManager] = None,
        agent_engine: Optional[AgentEngine] = None,
        git_manager: Optional[GitLifecycleManager] = None,
    ):
        require_legacy_execution()
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self.agent_engine = agent_engine or AgentEngine(self.sandbox_manager)
        self.git_manager = git_manager or GitLifecycleManager(self.sandbox_manager)

    def address_review_feedback(
        self,
        repo_clone_url: str,
        branch_name: str,
        comments: List[ReviewComment],
        git_token: Optional[str] = None,
        config: Optional[OpenJulesConfig] = None,
        *,
        source_body: Optional[str] = None,
    ) -> bool:
        """Checks out the existing branch, fixes the code based on comments, and pushes updates."""
        require_legacy_execution()
        if not isinstance(comments, (list, tuple)) or any(
            not isinstance(comment, ReviewComment) or not isinstance(comment.body, str)
            for comment in comments
        ):
            raise ReviewSourceRejected("invalid_legacy_review_source")
        require_legacy_review_source(
            branch_name, source_body, *(comment.body for comment in comments)
        )
        cfg = config or OpenJulesConfig()
        effective_token = git_token or os.environ.get("GITHUB_TOKEN")

        # Compile comments into actionable instruction
        comment_lines = []
        for c in comments:
            loc = f" on {c.path}:{c.line}" if c.path and c.line else ""
            comment_lines.append(f"- Reviewer {c.author}{loc}: \"{c.body}\"")

        prompt = (
            f"Reviewers provided feedback on branch `{branch_name}`:\n"
            + "\n".join(comment_lines)
            + "\n\nPlease modify the code to address this feedback, run the verification tests, and ensure all checks pass."
        )

        with self.sandbox_manager.run_sandbox(
            repo_url=repo_clone_url,
            branch=branch_name,
            config=cfg,
            git_token=effective_token,
        ) as context:
            # Run agent loop to address feedback
            res = self.agent_engine.run(
                context=context,
                task_instruction=prompt,
            )
            if not res.success:
                logger.warning("Agent failed to verify changes after addressing review feedback.")
                return False

            # Commit updates with conventional commit message
            commit_msg = "fix: address PR reviewer feedback"
            sha = self.git_manager.commit_changes(context, commit_msg)
            if sha:
                self.git_manager.push_branch(context, branch_name)
                logger.info(f"Pushed updated commit {sha} addressing review feedback to {branch_name}")
            return True
