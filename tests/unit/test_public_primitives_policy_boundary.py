"""Malformed public policy is refused before managed worker effects.

The raw configuration loader and ordinary model journal/lock are real. The
runtime constructor is an explicit stop fixture. These cases prove admission
and cleanup boundaries, not Docker, native transport or provider readiness.
"""

from contextlib import closing
from copy import deepcopy
import sqlite3

import pytest

import src.worker.managed_service as service_module
from src.worker.managed_public_types import PROTOCOL, PublicPolicy
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
    """Valid current shape except for its unsupported protocol value."""
    return {
        "protocol": "managed-public-discussion-v1",
        "public_approved": True,
        "topic": "public-policy-boundary",
        "server": {
            "python": str(tmp_path / "polyphony-python"),
            "cwd": str(tmp_path / "polyphony-source"),
            "scope_key_file": str(tmp_path / "public-scope"),
            "scope_key_sha256": "2" * 64,
        },
        "personas": {"independent": "An independent public participant."},
        "instructions": {"proposal": "Discuss this approved public question."},
        "invitations": {},
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
    # Changing only the protocol yields a valid shape without reading host files.
    valid_shape = policy["public_discussion"] | {"protocol": PROTOCOL}
    assert PublicPolicy.parse(valid_shape).document == valid_shape

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
    # Bind refusal to the unsupported protocol, before public prerequisites or
    # validation of this fixture's intentionally uninstalled host references.
    with pytest.raises(ValueError, match="^invalid managed public discussion policy$"):
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

    # Removing only the malformed public option reuses the same real journal/lock
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
