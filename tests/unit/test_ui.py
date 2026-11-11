"""Unit and integration tests for 3-pane web interface endpoints."""

from unittest.mock import MagicMock, patch
import pytest
from fastapi.testclient import TestClient

from src.api.webhook import app
from src.worker.dispatcher import TaskPayload
from src.worker.executor import TaskExecutor


def test_serve_dashboard():
    client = TestClient(app)
    resp = client.get("/")
    assert resp.status_code == 200
    assert "OpenJules" in resp.text
    assert "three-pane-container" in resp.text
    assert "diff-command-palette" in resp.text


def test_ui_task_lifecycle_api():
    client = TestClient(app)

    with patch.object(TaskExecutor, "execute_task", return_value=True):
        payload = {
            "forge": "github",
            "issue_id": 501,
            "issue_title": "Fix division error in app",
            "issue_body": "Edge cases in division",
            "repo_full_name": "owner/repo",
            "repo_clone_url": "https://github.com/owner/repo.git",
            "default_branch": "main",
        }

        # 1. Dispatch task
        resp = client.post("/api/tasks", json=payload)
        assert resp.status_code == 200
        data = resp.json()
        assert data["status"] == "dispatched"
        tid = data["id"]

        # 2. List tasks
        resp_list = client.get("/api/tasks")
        assert resp_list.status_code == 200
        tasks = resp_list.json()["tasks"]
        assert any(t["issue_id"] == 501 for t in tasks)

        # 3. Get task details
        resp_det = client.get(f"/api/tasks/{tid}")
        assert resp_det.status_code == 200
        details = resp_det.json()
        assert details["issue_title"] == "Fix division error in app"

        # 4. Get diff
        resp_diff = client.get(f"/api/tasks/{tid}/diff")
        assert resp_diff.status_code == 200
        assert "diff" in resp_diff.json()

        # 5. Execute command palette actions
        resp_cmd = client.post(f"/api/tasks/{tid}/command", json={"command": "verify"})
        assert resp_cmd.status_code == 200
        assert "Verification" in resp_cmd.json()["result"]

        resp_cmd_commit = client.post(f"/api/tasks/{tid}/command", json={"command": "commit"})
        assert resp_cmd_commit.status_code == 200
        assert "committed" in resp_cmd_commit.json()["result"]


def test_polyphony_state_endpoint():
    client = TestClient(app)
    resp = client.get("/api/polyphony/state")
    assert resp.status_code == 200
    assert "batons" in resp.json()
