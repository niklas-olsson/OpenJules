"""Background poller for self-hosted / local Radicle nodes."""

import asyncio
import logging
from typing import Callable, Dict, List, Optional, Set
import httpx

from src.worker.dispatcher import TaskDispatcher, TaskPayload
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)


class RadicleNodePoller:
    """Polls a local or self-hosted Radicle Node HTTP API for issues labeled 'openjules:run'."""

    def __init__(
        self,
        node_url: str = "http://127.0.0.1:8080/api/v1",
        poll_interval_seconds: int = 30,
        tracked_repos: Optional[List[str]] = None,
        dispatcher: Optional[TaskDispatcher] = None,
    ):
        self.node_url = node_url.rstrip("/")
        self.poll_interval = poll_interval_seconds
        self.tracked_repos: List[str] = tracked_repos or []
        self.dispatcher = dispatcher
        self._processed_issue_ids: Set[str] = set()
        self._running = False

    def poll_repository(self, rid: str) -> List[TaskPayload]:
        """Queries node API for issues on repository and converts labeled issues to TaskPayloads."""
        require_legacy_execution()
        clean_rid = rid if rid.startswith("rad:") else f"rad:{rid}"
        tasks: List[TaskPayload] = []
        try:
            url = f"{self.node_url}/projects/{clean_rid}/issues"
            with httpx.Client(timeout=10.0) as client:
                res = client.get(url)
                if res.status_code != 200:
                    return []
                issues = res.json()

            for issue in issues:
                issue_id = str(issue.get("id", ""))
                task_key = f"{clean_rid}:{issue_id}"
                if task_key in self._processed_issue_ids:
                    continue

                labels = issue.get("labels", [])
                # Trigger on openjules or openjules:run
                if any(l in ("openjules", "openjules:run") for l in labels) or any(
                    "openjules" in str(l) for l in labels
                ):
                    title = issue.get("title", f"Radicle Issue {issue_id}")
                    body = ""
                    # Radicle issue description is often in the first comment / thread
                    if issue.get("thread", {}).get("comments"):
                        body = issue["thread"]["comments"][0].get("body", "")
                    elif issue.get("body"):
                        body = issue["body"]

                    payload = TaskPayload(
                        forge="radicle",
                        issue_id=issue_id,
                        issue_title=title,
                        issue_body=body,
                        repo_full_name=clean_rid,
                        repo_clone_url=clean_rid,
                        default_branch="master",
                    )
                    tasks.append(payload)
                    self._processed_issue_ids.add(task_key)

        except Exception as e:
            logger.warning(f"Error polling Radicle repository {clean_rid}: {e}")

        return tasks

    def poll_all_repositories(self) -> List[TaskPayload]:
        """Polls all configured repositories and dispatches new tasks."""
        require_legacy_execution()
        all_tasks = []
        for rid in self.tracked_repos:
            tasks = self.poll_repository(rid)
            for t in tasks:
                all_tasks.append(t)
                if self.dispatcher:
                    self.dispatcher.dispatch(t)
        return all_tasks

    async def run_loop(self):
        """Asynchronous polling loop."""
        require_legacy_execution()
        self._running = True
        logger.info(f"Started Radicle Node poller on {self.node_url} (interval: {self.poll_interval}s)")
        while self._running:
            try:
                self.poll_all_repositories()
            except Exception as e:
                logger.error(f"Radicle poller loop encountered error: {e}")
            await asyncio.sleep(self.poll_interval)

    def stop(self):
        self._running = False
