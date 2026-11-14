"""GitHub Forge Provider implementation using PyGithub."""

import logging
import os
from typing import Any, Optional
from urllib.parse import urlparse, urlunparse
from github import Github, Auth

from src.forge.base import ForgeProvider, ProposalResult

logger = logging.getLogger(__name__)


class GitHubProvider(ForgeProvider):
    """Forge provider for GitHub via PyGithub."""

    def __init__(self, github_client: Optional[Github] = None, token: Optional[str] = None,
                 *, allow_environment_token: bool = True):
        self.token = token or (os.environ.get("GITHUB_TOKEN") if allow_environment_token else None)
        if github_client is not None:
            self.client = github_client
        elif self.token:
            self.client = Github(auth=Auth.Token(self.token))
        else:
            self.client = None

    @property
    def forge_type(self) -> str:
        return "github"

    def get_clone_url(self, repo_identifier: str, token: Optional[str] = None) -> str:
        tok = token or self.token
        if repo_identifier.startswith("http://") or repo_identifier.startswith("https://"):
            url = repo_identifier
        else:
            url = f"https://github.com/{repo_identifier}.git"

        if tok and url.startswith("https://"):
            parsed = urlparse(url)
            netloc = f"x-access-token:{tok}@{parsed.hostname}"
            if parsed.port:
                netloc += f":{parsed.port}"
            return urlunparse(
                (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
            )
        return url

    def post_issue_comment(self, repo_identifier: str, issue_id: str | int, comment: str) -> bool:
        if not self.client:
            logger.info(f"GitHub client not configured. Issue #{issue_id} update:\n{comment}")
            return False
        try:
            repo = self.client.get_repo(repo_identifier)
            issue = repo.get_issue(number=int(issue_id))
            issue.create_comment(f"🤖 **[OpenJules]** {comment}")
            return True
        except Exception as e:
            logger.warning(f"Failed to post comment to GitHub issue #{issue_id}: {e}")
            return False

    def create_proposal(
        self,
        repo_identifier: str,
        title: str,
        description: str,
        source_branch: str,
        target_branch: str,
        context: Optional[Any] = None,
    ) -> ProposalResult:
        if not self.client:
            logger.info(f"GitHub client not configured. Would open PR: {source_branch} -> {target_branch}")
            return ProposalResult(
                id="dry-run",
                url_or_id="https://github.com/" + repo_identifier + "/pull/dry-run",
                title=title,
                target_branch=target_branch,
                source_branch=source_branch,
            )
        repo = self.client.get_repo(repo_identifier)
        pr = repo.create_pull(
            title=title,
            body=description,
            head=source_branch,
            base=target_branch,
        )
        return ProposalResult(
            id=str(pr.number),
            url_or_id=pr.html_url,
            title=title,
            target_branch=target_branch,
            source_branch=source_branch,
        )
