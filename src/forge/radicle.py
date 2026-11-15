"""Legacy Radicle inspection with explicit refusal of unqualified writes."""

import logging
import os
from typing import Any, Dict, List, Optional
import httpx

from src.forge.base import ForgeProvider, ProposalResult
from src.sandbox.docker_driver import SandboxManager

logger = logging.getLogger(__name__)


class RadiclePublicationUnsupported(RuntimeError):
    """No Radicle patch publisher has been selected and qualified."""


class RadicleProvider(ForgeProvider):
    """Legacy repository/issue inspection; comment and patch writes refuse."""

    def __init__(
        self,
        node_url: str = "http://127.0.0.1:8080/api/v1",
        rad_passphrase: str = "",
        sandbox_manager: Optional[SandboxManager] = None,
    ):
        self.node_url = os.environ.get("RADICLE_NODE_URL", node_url).rstrip("/")
        self.rad_passphrase = os.environ.get("RAD_PASSPHRASE", rad_passphrase)
        self.sandbox_manager = sandbox_manager

    @property
    def forge_type(self) -> str:
        return "radicle"

    def get_clone_url(self, repo_identifier: str, token: Optional[str] = None) -> str:
        """Returns the Radicle repository identifier (e.g. rad:z4V1sJY...)."""
        if repo_identifier.startswith("rad:"):
            return repo_identifier
        return f"rad:{repo_identifier}"

    def post_issue_comment(self, repo_identifier: str, issue_id: str | int, comment: str) -> bool:
        """Return False before effects: no comment write contract is qualified.

        The old unauthenticated POST and logging fallback did not establish a
        published comment. Do not submit, retry, or log private comment text.
        """
        logger.warning("radicle_comment_publication_unsupported")
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
        """Refuse before CLI effects rather than invent a patch identity.

        No CLI revision, signing/remote profile or verifiable result contract
        is selected here. Trying a second command after an uncertain write
        could duplicate publication; neither fallback nor simulation is safe.
        """
        raise RadiclePublicationUnsupported("radicle_patch_publication_unsupported")

    def fetch_open_issues(self, repo_identifier: str) -> List[Dict[str, Any]]:
        """Queries Radicle Node HTTP API for issues."""
        rid = repo_identifier if repo_identifier.startswith("rad:") else f"rad:{repo_identifier}"
        try:
            url = f"{self.node_url}/projects/{rid}/issues"
            with httpx.Client(timeout=5.0) as client:
                res = client.get(url)
                if res.status_code == 200:
                    return res.json()
        except Exception as e:
            logger.warning(f"Failed to fetch Radicle issues for {rid}: {e}")
        return []
