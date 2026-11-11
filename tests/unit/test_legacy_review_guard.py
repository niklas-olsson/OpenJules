"""Legacy routing/effect isolation; Docker and forge dependencies are fixtures."""

from copy import deepcopy
from dataclasses import replace
import hashlib
import hmac
import json
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock, patch

from fastapi import BackgroundTasks
from fastapi.testclient import TestClient
import pytest

from src.git_manager.lifecycle import GitLifecycleManager
from src.worker import pr_reviewer
from src.worker.pr_reviewer import (
    PRReviewHandler,
    ReviewComment,
    ReviewSourceRejected,
)
from src.worker.managed_publication import PublicationService
from tests.unit.test_managed_composition import final_case
from tests.unit.test_managed_publication import FixtureForge, FixtureReader

MISSING = object()
SECRET = "synthetic-legacy-review-webhook-secret"
MANAGED_REASON = "managed_publication_requires_canonical_review"
INVALID_REASON = "invalid_legacy_review_source"
EVENTS = ("pull_request_review_comment", "pull_request_review")


def payload(event, branch, source_body=MISSING):
    result = {
        "action": "created" if event == EVENTS[0] else "submitted",
        "repository": {"clone_url": "https://github.com/owner/project.git"},
        "pull_request": {"head": {"ref": branch}},
        "comment" if event == EVENTS[0] else "review": {
            "id": 71,
            "body": "Please handle this feedback /jules",
            "user": {"login": "reviewer"},
        },
    }
    if source_body is not MISSING:
        result["pull_request"]["body"] = source_body
    return result


@pytest.fixture
def route(tmp_path, monkeypatch):
    # The legacy app still initializes its components. Only that preflight is
    # replaced when this module is tested alone without a Docker daemon.
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv("DOCKER_HOST", raising=False)
    with patch("docker.from_env", return_value=MagicMock()):
        from src.api import webhook

    callback = Mock(return_value=True)
    monkeypatch.setattr(
        webhook,
        "pr_review_handler",
        SimpleNamespace(address_review_feedback=callback),
    )
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", SECRET)
    queued = []
    original = BackgroundTasks.add_task

    def track(self, function, *args, **kwargs):
        queued.append((function, args, kwargs))
        return original(self, function, *args, **kwargs)

    monkeypatch.setattr(BackgroundTasks, "add_task", track)
    with TestClient(webhook.app) as client:
        yield SimpleNamespace(client=client, callback=callback, queued=queued)


def post(route, event, document):
    raw = json.dumps(document).encode()
    signature = "sha256=" + hmac.new(SECRET.encode(), raw, hashlib.sha256).hexdigest()
    return route.client.post(
        "/api/webhook",
        content=raw,
        headers={
            "Content-Type": "application/json",
            "X-GitHub-Event": event,
            "X-Hub-Signature-256": signature,
        },
    )


@pytest.fixture
def guarded_handler(monkeypatch):
    # The contract is method-entry refusal, not effect-free legacy construction.
    handler = PRReviewHandler.__new__(PRReviewHandler)
    handler.sandbox_manager = Mock()
    handler.agent_engine = Mock()
    handler.git_manager = Mock()
    configuration = Mock(side_effect=AssertionError("configuration touched"))
    credential = Mock(side_effect=AssertionError("credential touched"))
    monkeypatch.setattr(pr_reviewer, "OpenJulesConfig", configuration)
    monkeypatch.setattr(
        pr_reviewer, "os", SimpleNamespace(environ=SimpleNamespace(get=credential))
    )
    return handler, configuration, credential


def refused_direct(guarded_handler, branch, *, source_body=None, comments=None):
    handler, configuration, credential = guarded_handler
    with pytest.raises(ReviewSourceRejected) as result:
        handler.address_review_feedback(
            "https://github.com/owner/project.git",
            branch,
            [ReviewComment(71, "ordinary feedback")] if comments is None else comments,
            source_body=source_body,
        )
    configuration.assert_not_called()
    credential.assert_not_called()
    assert handler.sandbox_manager.mock_calls == []
    assert handler.agent_engine.mock_calls == []
    assert handler.git_manager.mock_calls == []
    return result.value.reason


def test_actual_publisher_output_is_refused_across_routes_and_direct_calls(
    route, guarded_handler, tmp_path, monkeypatch
):
    monkeypatch.setenv("PUBLICATION_TEST_TOKEN", "synthetic-publication-token")
    for index, prefix in enumerate(
        ("openjules/managed/", "custom/", "openjules/task-12-custom/")
    ):
        directory = tmp_path / str(index)
        directory.mkdir()
        case = final_case(directory)
        reader, forge = FixtureReader(case), FixtureForge(case)
        # Actual validated policy and production run construct the operation,
        # branch and marker. Git composition is real; the forge is a fixture.
        reader.policy = forge.policy = replace(forge.policy, branch_prefix=prefix)
        service = PublicationService(
            reader, forge, case["source"], directory / "publication"
        )
        published = service.run(case["inputs"]["manifest"]["candidate_id"])
        assert published["status"] == "draft_published"
        branch = forge.proposal["head_branch"]
        assert branch.startswith(prefix)
        assert refused_direct(guarded_handler, branch) == MANAGED_REASON
        for event in EVENTS:
            # Erasing optional provenance does not bypass the immutable shape.
            for _ in range(2):
                response = post(route, event, payload(event, branch, None))
                assert response.status_code == 409
                assert response.json() == {"detail": MANAGED_REASON}
        assert (
            refused_direct(
                guarded_handler, "feature/ordinary", source_body=forge.marker
            )
            == MANAGED_REASON
        )
        for event in EVENTS:
            response = post(
                route, event, payload(event, "feature/ordinary", forge.marker)
            )
            assert response.status_code == 409
            assert response.json() == {"detail": MANAGED_REASON}
    assert not route.queued
    route.callback.assert_not_called()


@pytest.mark.parametrize("event", EVENTS)
def test_marker_in_feedback_also_refuses_without_echoing_text(
    route, guarded_handler, event
):
    text = "private-text /jules <!-- openjules-publication:malformed"
    document = payload(event, "feature/ordinary")
    document["comment" if event == EVENTS[0] else "review"]["body"] = text
    response = post(route, event, document)
    assert response.status_code == 409
    assert response.json() == {"detail": MANAGED_REASON}
    assert not route.queued
    route.callback.assert_not_called()
    assert (
        refused_direct(
            guarded_handler,
            "feature/ordinary",
            comments=[ReviewComment(71, text)],
        )
        == MANAGED_REASON
    )


@pytest.mark.parametrize("event", EVENTS)
def test_ordinary_generator_and_ad_hoc_branches_preserve_review_flow(route, event):
    sandbox = Mock()
    sandbox.exec_in_sandbox.return_value = SimpleNamespace(exit_code=0)
    manager = GitLifecycleManager(sandbox)
    context = SimpleNamespace(container_id="explicit-fixture")
    branches = [
        manager.create_task_branch(context, 1, "!!!"),
        manager.create_task_branch(context, 2, "a" * 29 + " beta"),
        manager.create_task_branch(context, 3, "Ordinary task"),
        "feature/ad-hoc-review",
        "a" * 64,  # No slash: not a current publication branch.
        "feature/" + "a" * 63,
        "feature/" + "a" * 65,
        "feature/" + "A" * 64,
    ]
    assert branches[0] == "openjules/task-1-"
    assert branches[1].endswith("a" * 29 + "-")
    for branch in branches:
        for source_body in (MISSING, None, "Ordinary description"):
            response = post(route, event, payload(event, branch, source_body))
            assert response.status_code == 200
            assert response.json() == {
                "status": "review_iteration_dispatched",
                "branch": branch,
                "comment_id": 71,
            }
            supplied = route.callback.call_args.kwargs
            assert supplied["branch_name"] == branch
            assert supplied["repo_clone_url"] == "https://github.com/owner/project.git"
            assert supplied["source_body"] == (
                None if source_body is MISSING else source_body
            )
            assert supplied["comments"] == [
                ReviewComment(
                    71, "Please handle this feedback /jules", author="reviewer"
                )
            ]
    assert len(route.queued) == route.callback.call_count == len(branches) * 3
    automatic = payload(event, branches[2], None)
    automatic["comment" if event == EVENTS[0] else "review"][
        "body"
    ] = "ordinary feedback"
    assert (
        post(route, event, automatic).json()["status"] == "review_iteration_dispatched"
    )


@pytest.mark.parametrize("event", EVENTS)
def test_malformed_review_values_are_bounded_refusals_before_queueing(route, event):
    name = "comment" if event == EVENTS[0] else "review"
    original = payload(event, "feature/ordinary")
    malformed = [[], None, "private-invalid", original | {"action": []}]
    for key in ("pull_request", name, "repository"):
        for value in (None, [], "private-invalid"):
            malformed.append(original | {key: value})
    for value in (None, [], "private-invalid"):
        malformed.append(original | {"pull_request": {"head": value}})
    for value in (None, [], 7, ""):
        malformed.append(original | {"pull_request": {"head": {"ref": value}}})
    for value in ([], {}, 7):
        malformed.append(
            original | {"pull_request": {"head": {"ref": "feature/x"}, "body": value}}
        )
    for key, value in (
        ("body", None),
        ("body", []),
        ("body", {}),
        ("body", 7),
        ("user", None),
        ("user", []),
        ("user", {"login": []}),
        ("id", {}),
        ("id", True),
        ("path", []),
        ("line", True),
    ):
        malformed.append(original | {name: original[name] | {key: value}})
    malformed.append(original | {"repository": {"clone_url": []}})
    missing_body = deepcopy(original)
    del missing_body[name]["body"]
    malformed.append(missing_body)
    for document in malformed:
        response = post(route, event, document)
        assert response.status_code == 400
        assert response.json() == {"detail": INVALID_REASON}
    assert not route.queued
    route.callback.assert_not_called()


@pytest.mark.parametrize(
    "branch,source_body,comments",
    [
        (None, None, [ReviewComment(1, "text")]),
        ([], None, [ReviewComment(1, "text")]),
        ("", None, [ReviewComment(1, "text")]),
        ("feature/x", {}, [ReviewComment(1, "text")]),
        ("feature/x", None, [ReviewComment(1, None)]),
        ("feature/x", None, [{"body": "text"}]),
        ("feature/x", None, "text"),
    ],
)
def test_direct_invalid_sources_do_not_read_configuration_or_credentials(
    guarded_handler, branch, source_body, comments
):
    assert (
        refused_direct(
            guarded_handler, branch, source_body=source_body, comments=comments
        )
        == INVALID_REASON
    )


def test_direct_ad_hoc_review_keeps_its_existing_effect_path():
    sandbox, agent, git = MagicMock(), Mock(), Mock()
    sandbox.run_sandbox.return_value.__enter__.return_value = "fixture-context"
    agent.run.return_value = SimpleNamespace(success=True)
    git.commit_changes.return_value = "c" * 40
    handler = PRReviewHandler(sandbox, agent, git)
    assert (
        handler.address_review_feedback(
            "https://github.com/owner/project.git",
            "feature/ad-hoc-review",
            [ReviewComment(71, "ordinary feedback")],
            git_token="synthetic-legacy-token",
            config=SimpleNamespace(),
        )
        is True
    )
    agent.run.assert_called_once()
    git.commit_changes.assert_called_once()
    git.push_branch.assert_called_once_with("fixture-context", "feature/ad-hoc-review")
