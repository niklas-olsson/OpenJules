"""Multi-repository concurrent swarm orchestrator."""

import asyncio
import logging
from typing import Dict, List, Optional, Set
from pydantic import BaseModel, Field

from src.polyphony.manager import PolyphonySwarmManager
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)


class SwarmWorkerLimits(BaseModel):
    """Resource concurrency limits across multiple repositories."""

    max_global_workers: int = Field(default=8, description="Max concurrent agent containers across all repos.")
    max_workers_per_repo: int = Field(default=2, description="Max concurrent agent containers per repo.")


class MultiRepoOrchestrator:
    """Orchestrates concurrent worker pools across multiple GitHub repositories and Radicle projects."""

    def __init__(
        self,
        task_executor: Optional[TaskExecutor] = None,
        limits: Optional[SwarmWorkerLimits] = None,
        polyphony_manager: Optional[PolyphonySwarmManager] = None,
    ):
        require_legacy_execution()
        self.executor = task_executor or TaskExecutor()
        self.limits = limits or SwarmWorkerLimits()
        self.polyphony_manager = (
            polyphony_manager
            or getattr(self.executor, "polyphony_manager", None)
            or PolyphonySwarmManager()
        )

        # Concurrency tracking
        self.active_tasks: Dict[str, TaskPayload] = {}
        self.active_by_repo: Dict[str, Set[str]] = {}
        self._global_semaphore = asyncio.Semaphore(self.limits.max_global_workers)
        self._repo_semaphores: Dict[str, asyncio.Semaphore] = {}

    def _get_repo_semaphore(self, repo_identifier: str) -> asyncio.Semaphore:
        clean_id = repo_identifier.strip().lower()
        if clean_id not in self._repo_semaphores:
            self._repo_semaphores[clean_id] = asyncio.Semaphore(self.limits.max_workers_per_repo)
        return self._repo_semaphores[clean_id]

    def can_dispatch(self, repo_identifier: str) -> bool:
        """Checks if there is available worker capacity globally and for this repo."""
        clean_id = repo_identifier.strip().lower()
        active_in_repo = len(self.active_by_repo.get(clean_id, set()))
        if active_in_repo >= self.limits.max_workers_per_repo:
            return False
        if len(self.active_tasks) >= self.limits.max_global_workers:
            return False
        return True

    async def execute_task_managed(self, payload: TaskPayload) -> bool:
        """Executes a task under global and per-repository worker concurrency limits."""
        require_legacy_execution()
        repo_id = payload.repo_full_name.strip().lower()
        task_key = f"{repo_id}:{payload.issue_id}"
        repo_sem = self._get_repo_semaphore(repo_id)

        async with self._global_semaphore:
            async with repo_sem:
                # Track active task
                self.active_tasks[task_key] = payload
                if repo_id not in self.active_by_repo:
                    self.active_by_repo[repo_id] = set()
                self.active_by_repo[repo_id].add(task_key)

                logger.info(
                    f"Orchestrator dispatching {task_key} (Repo active: {len(self.active_by_repo[repo_id])}, Global active: {len(self.active_tasks)})"
                )

                try:
                    # Run execution loop
                    loop = asyncio.get_running_loop()
                    success = await loop.run_in_executor(None, self.executor.execute_task, payload)
                    return success
                finally:
                    # Cleanup tracking
                    self.active_tasks.pop(task_key, None)
                    if repo_id in self.active_by_repo:
                        self.active_by_repo[repo_id].discard(task_key)
                        if not self.active_by_repo[repo_id]:
                            del self.active_by_repo[repo_id]
                    logger.info(f"Orchestrator finished {task_key}")

    def get_orchestrator_status(self) -> dict:
        """Returns active multi-repo workload summary."""
        return {
            "global_active": len(self.active_tasks),
            "max_global_workers": self.limits.max_global_workers,
            "active_repositories": {
                repo: list(tasks) for repo, tasks in self.active_by_repo.items()
            },
        }
