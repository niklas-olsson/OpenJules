"""Repository-qualified dashboard records with actual SQLite reopen/read checks."""

import sqlite3

import pytest

from src.storage.dashboard_state import DashboardState
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
def dashboard(tmp_path):
    path = tmp_path / "dashboard.sqlite3"
    return path, DashboardState(SQLiteStorageProvider(str(path)))


def stored_row(path, task_id):
    with sqlite3.connect(path) as connection:
        return connection.execute(
            "SELECT * FROM tasks WHERE task_id = ?", (task_id,)
        ).fetchone()


def test_repository_records_survive_reopen_without_rewriting_legacy_ids(dashboard):
    path, state = dashboard
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
    state.storage.save_task(legacy["id"], legacy)
    original_legacy_row = stored_row(path, legacy["id"])

    first = payload("owner/repository-a", body="A")
    second = payload("owner/repository-b", body="B")
    first_id = state.record_task(first)
    second_id = state.record_task(second)
    assert state.get_task(first_id)["status"] == "recorded"
    assert len({first_id, second_id, legacy["id"]}) == 3
    # Every key made by the old formatter contains its literal hyphen separator.
    assert all("-" not in task_id for task_id in (first_id, second_id))

    updated = first.model_copy(update={"issue_body": "A updated"})
    assert state.record_task(updated) == first_id

    # Discard every in-memory record and reopen the actual persistent provider.
    state = DashboardState(SQLiteStorageProvider(str(path)))
    for task_id, expected in (
        (first_id, ("owner/repository-a", "A updated")),
        (second_id, ("owner/repository-b", "B")),
    ):
        record = state.get_task(task_id)
        assert (record["repo"], record["issue_body"]) == expected
    assert state.get_task("github-1") == legacy

    # A later recording of the same source reuses its key after the reopen.
    assert state.record_task(updated) == first_id
    assert {record["id"] for record in state.list_tasks()} == {
        first_id, second_id, legacy["id"]
    }
    assert stored_row(path, legacy["id"]) == original_legacy_row
    assert state.storage.get_task(second_id)["issue_body"] == "B"


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
    _, state = dashboard
    left_id = state.record_task(payload(left[1], left[2], left[0], "left"))
    right_id = state.record_task(payload(right[1], right[2], right[0], "right"))
    assert left_id != right_id
    assert state.get_task(left_id)["issue_body"] == "left"
    assert state.get_task(right_id)["issue_body"] == "right"
    assert len(state.storage.list_tasks()) == 2


def test_metadata_changes_do_not_change_the_existing_source_identity(dashboard):
    _, state = dashboard
    first = payload("owner/repository")
    task_id = state.record_task(first)
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
    assert state.record_task(updated) == task_id
    rows = state.storage.list_tasks()
    assert len(rows) == 1
    assert rows[0]["issue_body"] == "New description"
