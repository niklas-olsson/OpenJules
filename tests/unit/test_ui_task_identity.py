"""Repository-qualified dashboard records with actual SQLite reopen/read checks."""

import sqlite3

import pytest
from fastapi import FastAPI
from fastapi.testclient import TestClient

from src.api import ui_routes
from src.storage.sqlite_storage import SQLiteStorageProvider
from src.worker.dispatcher import TaskPayload


def payload(repository, source_id=1, forge="github", body="original"):
    return TaskPayload(
        forge=forge,
        issue_id=source_id,
        issue_title="Source record",
        issue_body=body,
        repo_full_name=repository,
        repo_clone_url="https://example.invalid/source.git",
    )


@pytest.fixture
def dashboard(tmp_path, monkeypatch):
    path = tmp_path / "dashboard.sqlite3"
    monkeypatch.setattr(ui_routes, "tasks_db", {})
    monkeypatch.setattr(ui_routes, "storage_provider", SQLiteStorageProvider(str(path)))
    app = FastAPI()
    app.include_router(ui_routes.ui_router)
    with TestClient(app) as client:
        yield path, client


def stored_row(path, task_id):
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()


def test_repository_records_survive_reopen_without_rewriting_legacy_ids(
    dashboard, monkeypatch
):
    path, client = dashboard
    legacy = {
        "id": "github-1",
        "forge": "github",
        "repo": "owner/legacy",
        "issue_id": 1,
        "status": "completed",
        "issue_title": "Existing historical record",
        "thoughts": [{"content": "Retained original contribution"}],
        "diff": "retained legacy diff",
    }
    ui_routes.storage_provider.save_task(legacy["id"], legacy)
    original_legacy_row = stored_row(path, legacy["id"])

    first = payload("owner/repository-a", body="A")
    second = payload("owner/repository-b", body="B")
    first_id = ui_routes.record_ui_task(first)
    second_id = ui_routes.record_ui_task(second)
    assert len({first_id, second_id, legacy["id"]}) == 3

    updated = first.model_copy(update={"issue_body": "A updated"})
    assert ui_routes.record_ui_task(updated) == first_id

    # Discard every in-memory record and reopen the actual persistent provider.
    monkeypatch.setattr(ui_routes, "tasks_db", {})
    monkeypatch.setattr(ui_routes, "storage_provider", SQLiteStorageProvider(str(path)))
    for task_id, expected in (
        (first_id, ("owner/repository-a", "A updated")),
        (second_id, ("owner/repository-b", "B")),
    ):
        response = client.get(f"/api/tasks/{task_id}")
        assert response.status_code == 200
        assert (response.json()["repo"], response.json()["issue_body"]) == expected
    assert client.get("/api/tasks/github-1").json() == legacy

    # A later recording of the same source reuses its key after the reopen.
    assert ui_routes.record_ui_task(updated) == first_id
    response = client.get("/api/tasks")
    assert response.status_code == 200
    assert {record["id"] for record in response.json()["tasks"]} == {
        first_id, second_id, legacy["id"]
    }
    assert stored_row(path, legacy["id"]) == original_legacy_row
    assert ui_routes.storage_provider.get_task(second_id)["issue_body"] == "B"


@pytest.mark.parametrize(
    ("left", "right"),
    [
        (("github", "shared/source", "1"), ("radicle", "shared/source", "1")),
        (("radicle", "rad:AbCd", "source"), ("radicle", "rad:aBcD", "source")),
        (
            ("radicle", "rad:project", "part:issue:one"),
            ("radicle", "rad:project:issue:part", "one"),
        ),
        (("github", "owner/caf\u00e9", "1"), ("github", "owner/cafe\u0301", "1")),
    ],
)
def test_distinct_opaque_source_fields_never_share_dashboard_state(dashboard, left, right):
    _, client = dashboard
    left_id = ui_routes.record_ui_task(payload(left[1], left[2], left[0], "left"))
    right_id = ui_routes.record_ui_task(payload(right[1], right[2], right[0], "right"))
    assert left_id != right_id
    assert client.get(f"/api/tasks/{left_id}").json()["issue_body"] == "left"
    assert client.get(f"/api/tasks/{right_id}").json()["issue_body"] == "right"
    assert len(ui_routes.storage_provider.list_tasks()) == 2


def test_metadata_changes_do_not_change_the_existing_source_identity(dashboard):
    first = payload("owner/repository")
    task_id = ui_routes.record_ui_task(first)
    updated = first.model_copy(
        update={
            "issue_id": "1",
            "issue_title": "New title",
            "issue_body": "New description",
            "repo_clone_url": "https://example.invalid/updated.git",
            "default_branch": "other",
            "sender": "another-sender",
            "installation_id": 23,
        }
    )
    assert ui_routes.record_ui_task(updated) == task_id
    rows = ui_routes.storage_provider.list_tasks()
    assert len(rows) == 1
    assert rows[0]["issue_body"] == "New description"
