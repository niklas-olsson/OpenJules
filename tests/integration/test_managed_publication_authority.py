"""Canonical HTTP refusal and journal recovery at publication boundaries.

The shared fixture serves actual loopback HTTP and stores actual Git objects.
Canonical state and forge responses are named fixtures, not a live Polyphony
outage or GitHub publication. Reopening creates a new service object, not an OS
process. A successful read is not atomic with a later remote forge effect.
"""

from copy import deepcopy
import json

import pytest

from src.worker.managed_publication import PublicationError
from tests.integration.test_managed_publication import (
    AUTHORITY_TOKEN,
    FORGE_TOKEN,
    actual,  # noqa: F401
    git_bytes,
)


class SnapshotFailure:
    """Change only authenticated snapshot HTTP replies at an observed boundary."""

    def __init__(self, fixture, service, monkeypatch, first_failure):
        self.original = fixture.route
        self.scope = {
            "deployment_id": service.policy.deployment_id,
            "repository": service.policy.repository,
        }
        self.first_failure = first_failure
        self.snapshots = 0
        self.mode = "outage"
        self.refusals = []
        monkeypatch.setattr(fixture, "route", self.route)

    def route(self, method, path, query, headers, payload):
        if path.startswith("/managed/"):
            assert method == "GET"
            assert headers.get("Authorization") == "Bearer " + AUTHORITY_TOKEN
            assert all(query.get(key) == [value] for key, value in self.scope.items())
        if path == "/managed/snapshot":
            self.snapshots += 1
            if self.snapshots >= self.first_failure and self.mode is not None:
                self.refusals.append((self.snapshots, self.mode))
                if self.mode == "outage":
                    return 503, {"error": "untrusted-detail-" + AUTHORITY_TOKEN}, None
                status, value, effect = self.original(
                    method, path, query, headers, payload
                )
                assert status == 200 and effect is None
                assert self.mode in {"deployment", "repository", "schema"}
                changed = {
                    "deployment": {"deployment_id": "foreign-deployment"},
                    "repository": {"repository": "github:github.com/foreign/project"},
                    "schema": {"schema_version": True},
                }[self.mode]
                return 200, value | changed, None
        return self.original(method, path, query, headers, payload)


def forge_requests(fixture):
    return [
        request
        for request in fixture.requests
        if not request[1].startswith("/managed/")
    ]


def refs(fixture):
    return git_bytes(
        fixture.repository, "for-each-ref", "--format=%(refname) %(objectname)"
    )


def operation_state(service):
    paths = list(service.journal.root.glob("*/state.json"))
    assert len(paths) == 1
    raw = paths[0].read_bytes()
    state = json.loads(raw)
    assert paths[0].parent.name == state["operation"]
    return paths[0], raw, state


def assert_safe_result(result):
    encoded = json.dumps(result)
    assert AUTHORITY_TOKEN not in encoded and FORGE_TOKEN not in encoded
    assert "untrusted-detail-" not in encoded
    assert len(encoded.encode()) < 8192
    assert result["ready_for_review"] is False
    assert result["release_authorized"] is False


def recover_and_replay(case, fixture, service, fault, prefix, original=None):
    fault.mode = None
    candidate = case["inputs"]["manifest"]["candidate_id"]
    recovered = fixture.service(service.journal.root)
    result = recovered.run(candidate)
    assert result["status"] == "draft_published"
    assert_safe_result(result)
    path, raw, state = operation_state(recovered)
    assert state["inputs"] == case["inputs"]
    assert state["candidate_id"] == candidate
    assert state["child_order"] == [
        item["child_id"] for item in case["inputs"]["manifest"]["lineage"]
    ]
    if original is not None:
        for key in (
            "operation", "candidate_id", "child_order", "inputs",
            "policy_fingerprint", "limits", "branch", "identity",
        ):
            assert state[key] == original[key]
        if "composition" in original:
            assert state["composition"] == original["composition"]
        if original.get("objects_uploaded"):
            assert [
                effect for effect in fixture.effects
                if effect[0] in {"blob", "tree", "commit"}
            ] == [
                effect for effect in prefix
                if effect[0] in {"blob", "tree", "commit"}
            ]
    assert fixture.effects[:len(prefix)] == prefix
    assert sum(effect[0] == "branch" for effect in fixture.effects) == 1
    assert sum(effect[0] == "draft" for effect in fixture.effects) == 1
    assert len(fixture.proposals) == 1
    assert fixture.proposals[0]["draft"] is True
    assert result["proposal"]["head_sha"] == result["commit_sha"]
    assert result["proposal"]["base_sha"] == case["inputs"]["manifest"]["base"]
    assert fixture._ref(state["branch"]) == result["commit_sha"]
    commit = fixture._commit(result["commit_sha"])
    assert commit["tree"]["sha"] == result["tree_sha"]
    assert commit["parents"] == [{"sha": case["inputs"]["manifest"]["base"]}]
    assert AUTHORITY_TOKEN.encode() not in raw and FORGE_TOKEN.encode() not in raw

    effects = deepcopy(fixture.effects)
    original_refs = refs(fixture)
    replay = fixture.service(service.journal.root).run(candidate)
    assert replay == result
    assert fixture.effects == effects and refs(fixture) == original_refs
    assert path.read_bytes() == raw
    assert len(list(service.journal.root.glob("*/state.json"))) == 1
    assert not fixture.errors
    for method, route, query, headers, payload in fixture.requests:
        assert method in {"GET", "POST"}
        assert headers.get("Authorization") == "Bearer " + (
            AUTHORITY_TOKEN if route.startswith("/managed/") else FORGE_TOKEN
        )
        assert AUTHORITY_TOKEN not in json.dumps(query) + json.dumps(payload)
        assert FORGE_TOKEN not in json.dumps(query) + json.dumps(payload)
        assert not any(part in route for part in ("merge", "ready", "review"))


def test_initial_authority_refusal_creates_no_operation_or_forge_effect(
    actual, monkeypatch
):
    case, fixture, service = actual
    candidate = case["inputs"]["manifest"]["candidate_id"]
    fault = SnapshotFailure(fixture, service, monkeypatch, first_failure=1)
    original_refs = refs(fixture)
    for mode in ("outage", "outage", "deployment", "repository", "schema"):
        fault.mode = mode
        reopened = fixture.service(service.journal.root)
        with pytest.raises(PublicationError) as caught:
            reopened.run(candidate)
        expected = "canonical_unavailable" if mode == "outage" else "canonical_mismatch"
        assert caught.value.code == expected
        assert str(caught.value) == expected
        assert fault.refusals[-1] == (fault.snapshots, mode)
        assert not list(service.journal.root.glob("*/state.json"))
        assert not list(service.journal.root.glob("*/git"))
        assert not forge_requests(fixture) and not fixture.effects
        assert not fixture.proposals and refs(fixture) == original_refs
    assert fault.snapshots == 5
    recover_and_replay(case, fixture, service, fault, [])


@pytest.mark.parametrize(
    "snapshot_number,phase",
    [(2, "captured"), (3, "objects_uploaded"), (4, "branch_observed")],
)
def test_retained_publication_waits_for_fresh_valid_authority_after_reopen(
    actual, monkeypatch, snapshot_number, phase
):
    case, fixture, service = actual
    candidate = case["inputs"]["manifest"]["candidate_id"]
    fault = SnapshotFailure(
        fixture, service, monkeypatch, first_failure=snapshot_number
    )
    denied = service.run(candidate)
    assert denied["status"] == "unavailable"
    assert denied["reason"] == "canonical_unavailable"
    assert_safe_result(denied)
    assert fault.snapshots == snapshot_number
    path, raw, state = operation_state(service)
    assert state["phase"] == phase and state["operation"] == denied["operation"]
    assert state["inputs"] == case["inputs"]
    assert not state.get("pr_intent") and not state.get("proposal")

    prefix = deepcopy(fixture.effects)
    requests = deepcopy(forge_requests(fixture))
    original_refs = refs(fixture)
    if snapshot_number == 2:
        assert not prefix and not requests
        assert "composition" not in state and not (path.parent / "git").exists()
    else:
        assert state["objects_uploaded"] is True
        assert any(effect[0] == "blob" for effect in prefix)
        assert sum(effect[0] == "commit" for effect in prefix) == 1
        assert sum(effect[0] == "draft" for effect in prefix) == 0
        assert sum(effect[0] == "branch" for effect in prefix) == snapshot_number - 3
        if snapshot_number == 3:
            assert fixture._ref(state["branch"]) is None
        else:
            assert state["branch_intent"] is True
            assert fixture._ref(state["branch"]) == state["composition"]["commit_sha"]
    assert not fixture.proposals

    for mode in ("outage", "outage", "deployment", "repository", "schema"):
        fault.mode = mode
        reopened = fixture.service(service.journal.root)
        result = reopened.run(candidate)
        assert result["operation"] == state["operation"]
        assert result["status"] == ("unavailable" if mode == "outage" else "conflict")
        assert result["reason"] == (
            "canonical_unavailable" if mode == "outage" else "canonical_mismatch"
        )
        assert_safe_result(result)
        assert fault.refusals[-1] == (fault.snapshots, mode)
        assert path.read_bytes() == raw
        assert fixture.effects == prefix and forge_requests(fixture) == requests
        assert refs(fixture) == original_refs and not fixture.proposals
    recover_and_replay(case, fixture, service, fault, prefix, state)
