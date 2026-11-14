"""Explicit host-owned dashboard records; not an HTTP admission path."""

import hashlib
import json

from src.worker.execution_context import require_legacy_execution


def task_id(payload):
    """Preserve the exact repository-qualified identity and historical keys."""
    identity = [
        "openjules.ui-task", 1, payload.forge, payload.repo_full_name,
        "issue", str(payload.issue_id),
    ]
    encoded = json.dumps(identity, ensure_ascii=True, separators=(",", ":")).encode("ascii")
    return "task_v1_" + hashlib.sha256(encoded).hexdigest()


class DashboardState:
    """Construct only for an explicit local host operation with its own store."""

    def __init__(self, storage_provider):
        require_legacy_execution()
        self.storage = storage_provider
        self.tasks = {}

    def record_task(self, payload):
        require_legacy_execution()
        identifier = task_id(payload)
        record = {
            "id": identifier, "forge": payload.forge, "issue_id": payload.issue_id,
            "issue_title": payload.issue_title, "issue_body": payload.issue_body,
            "repo": payload.repo_full_name, "status": "recorded",
            "thoughts": [{"origin": "OpenJules local records", "status": "recorded",
                          "content": f"Task #{payload.issue_id} recorded. No execution has started."}],
            "diff": "", "created_at": None,
        }
        self.tasks[identifier] = record
        self.storage.save_task(identifier, record)
        return identifier

    def list_tasks(self):
        require_legacy_execution()
        return self.storage.list_tasks() or list(self.tasks.values())

    def get_task(self, identifier):
        require_legacy_execution()
        if identifier in self.tasks:
            return self.tasks[identifier]
        stored = self.storage.get_task(identifier)
        if stored:
            self.tasks[identifier] = stored
        return stored
