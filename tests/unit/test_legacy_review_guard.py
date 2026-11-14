"""Direct legacy review boundaries; HTTP refusal is owned by test_standalone_ingress."""
from dataclasses import replace
from types import SimpleNamespace
from unittest.mock import MagicMock, Mock

import pytest
from src.git_manager.lifecycle import GitLifecycleManager
from src.worker import pr_reviewer
from src.worker.pr_reviewer import PRReviewHandler, ReviewComment, ReviewSourceRejected
from src.worker.managed_publication import PublicationService
from tests.unit.test_managed_composition import final_case
from tests.unit.test_managed_publication import FixtureForge, FixtureReader

MANAGED_REASON = "managed_publication_requires_canonical_review"
INVALID_REASON = "invalid_legacy_review_source"


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


def test_actual_publisher_output_is_refused_by_direct_legacy_review(guarded_handler, tmp_path, monkeypatch):
    monkeypatch.setenv("PUBLICATION_TEST_TOKEN", "synthetic-publication-token")
    for index, prefix in enumerate(("openjules/managed/", "custom/", "openjules/task-12-custom/")):
        directory = tmp_path / str(index)
        directory.mkdir()
        case = final_case(directory)
        reader, forge = FixtureReader(case), FixtureForge(case)
        reader.policy = forge.policy = replace(forge.policy, branch_prefix=prefix)
        published = PublicationService(reader, forge, case["source"], directory / "publication").run(case["inputs"]["manifest"]["candidate_id"])
        assert published["status"] == "draft_published"
        branch = forge.proposal["head_branch"]
        assert branch.startswith(prefix)
        assert refused_direct(guarded_handler, branch) == MANAGED_REASON
        assert refused_direct(guarded_handler, "feature/ordinary", source_body=forge.marker) == MANAGED_REASON


def test_marker_in_direct_feedback_refuses_before_effects(guarded_handler):
    text = "private-text /jules <!-- openjules-publication:malformed"
    assert refused_direct(guarded_handler, "feature/ordinary", comments=[ReviewComment(71, text)]) == MANAGED_REASON


def test_ordinary_generator_and_ad_hoc_branches_remain_eligible_for_direct_review():
    sandbox = Mock()
    sandbox.exec_in_sandbox.return_value = SimpleNamespace(exit_code=0)
    manager = GitLifecycleManager(sandbox)
    context = SimpleNamespace(container_id="explicit-fixture")
    branches = [manager.create_task_branch(context, 1, "!!!"),
                manager.create_task_branch(context, 2, "a" * 29 + " beta"),
                manager.create_task_branch(context, 3, "Ordinary task"),
                "feature/ad-hoc-review", "a" * 64, "feature/" + "a" * 63,
                "feature/" + "a" * 65, "feature/" + "A" * 64]
    for branch in branches:
        for body in (None, "Ordinary description"):
            pr_reviewer.require_legacy_review_source(branch, body, "Ordinary feedback /jules")
