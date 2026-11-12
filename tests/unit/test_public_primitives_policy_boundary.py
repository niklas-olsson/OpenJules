"""Shared public primitives do not enable an unfinished managed child mode.

The raw configuration loader and ordinary model journal/lock are real. The
runtime constructor is an explicit stop fixture. These cases prove admission
and cleanup boundaries, not Docker, native transport or provider readiness.
"""

from contextlib import closing
from copy import deepcopy
import hashlib
import json
import sqlite3

import pytest

import src.worker.managed_service as service_module
from src.worker.model_broker import ModelBroker
from tests.unit.test_child_session_policy import (
    RuntimeBoundaryReached,
    SCOPE_KEY,
    assert_brokers_released,
    configuration,
    construction_boundary,  # noqa: F401
    load_file,
)


def public_document(tmp_path):
    """Representative generated shape; no public runtime is installed here."""
    approved = {
        "protocol": "managed-public-discussion-v1",
        "public_approved": True,
        "topic": "public-policy-boundary",
        "roles": [
            {
                "id": "proposer",
                "persona": "An independent proposer.",
                "slots": [{"id": "proposal", "instruction": "Propose a change."}],
            },
            {
                "id": "critic",
                "persona": "An independent critic.",
                "slots": [{"id": "criticism", "instruction": "You may decline."}],
            },
        ],
    }
    raw = json.dumps(
        approved, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode()
    return {
        **approved,
        "approval_sha256": hashlib.sha256(raw).hexdigest(),
        "host": {
            "python": str(tmp_path / "polyphony-python"),
            "cwd": str(tmp_path / "polyphony-source"),
            "revision": "1" * 40,
            "scope_key_file": str(tmp_path / "public-scope"),
            "scope_sha256": "2" * 64,
            "state_directory": str(tmp_path / "public-state"),
        },
    }


@pytest.mark.parametrize("mode", ["ordinary", "initial", "cold"])
def test_raw_public_policy_refuses_before_worker_effects_and_releases_broker(
    tmp_path, monkeypatch, construction_boundary, mode
):
    config = configuration(tmp_path)
    policy = config["children"][0]["policy"]
    if mode != "cold":
        policy.pop("session_protocol")
    if mode == "ordinary":
        policy.pop("outcome_protocol")
    policy["public_discussion"] = public_document(tmp_path)

    def unexpected_authority(*_args, **_kwargs):
        pytest.fail("configuration admission must not contact authority")

    async def unexpected_provider(*_args, **_kwargs):
        pytest.fail("configuration admission must not dispatch inference")

    monkeypatch.setattr(
        service_module.ManagedAuthorityClient, "request", unexpected_authority
    )
    monkeypatch.setattr(ModelBroker, "_forward", unexpected_provider)
    path, original_bytes, loaded, credentials = load_file(tmp_path, config)
    original_loaded = deepcopy(loaded)
    # Bind refusal to the unsupported field itself, not a later failure to
    # validate this fixture's intentionally uninstalled host references.
    with pytest.raises(
        TypeError, match="unexpected keyword argument 'public_discussion'"
    ):
        service_module.build_app(loaded, credentials)

    assert loaded == original_loaded
    assert path.read_bytes() == original_bytes
    assert construction_boundary.runtime_policies == []
    assert len(construction_boundary.brokers) == 1
    assert_brokers_released(construction_boundary)
    broker = construction_boundary.brokers[0]
    # Existing service construction may create its ordinary broker database.
    # It must not allocate a worker or reserve/dispatch a model call.
    with closing(sqlite3.connect(f"file:{broker.database}?mode=ro", uri=True)) as db:
        assert db.execute("SELECT COUNT(*) FROM workers").fetchone()[0] == 0
        assert db.execute("SELECT COUNT(*) FROM calls").fetchone()[0] == 0
    assert not (tmp_path / "public-state").exists()

    # Removing only the unsupported option reuses the same real journal/lock
    # and reaches the ordinary runtime boundary with the selected old mode.
    policy.pop("public_discussion")
    _, _, corrected, credentials = load_file(tmp_path, config)
    with pytest.raises(RuntimeBoundaryReached):
        service_module.build_app(corrected, credentials)
    assert len(construction_boundary.brokers) == 2
    assert len(construction_boundary.runtime_policies) == 1
    approved = construction_boundary.runtime_policies[0][SCOPE_KEY]
    assert approved.session_protocol == (
        "cold-clarification-v1" if mode == "cold" else None
    )
    assert approved.outcome_protocol == (
        None if mode == "ordinary" else "initial-v1"
    )
    assert "public_discussion" not in corrected["children"][0]["policy"]
    assert_brokers_released(construction_boundary)
