"""Task dispatcher abstract interface and implementations."""

from abc import ABC, abstractmethod
from typing import Any, Callable, Optional
from pydantic import BaseModel, Field
from fastapi import BackgroundTasks

from src.worker.execution_context import require_legacy_execution


class TaskPayload(BaseModel):
    """Payload representing a task triggered by GitHub or Radicle."""

    forge: str = Field(default="github", description="Target forge: 'github' or 'radicle'")
    issue_id: int | str
    issue_title: str
    issue_body: str = ""
    repo_full_name: str  # e.g., 'owner/repo' or 'rad:z4V1sJY...'
    repo_clone_url: str
    default_branch: str = "main"
    installation_id: Optional[int] = None
    sender: str = ""


class TaskDispatcher(ABC):
    """Abstract interface for dispatching background agent tasks."""

    @abstractmethod
    def dispatch(self, task_payload: TaskPayload) -> Any:
        """Dispatches task payload for background execution."""
        pass


class BackgroundTasksDispatcher(TaskDispatcher):
    """FastAPI BackgroundTasks dispatcher implementation."""

    def __init__(self, background_tasks: BackgroundTasks, task_handler: Callable[[TaskPayload], Any]):
        self.background_tasks = background_tasks
        self.task_handler = task_handler

    def dispatch(self, task_payload: TaskPayload) -> Any:
        require_legacy_execution()
        self.background_tasks.add_task(self.task_handler, task_payload)
