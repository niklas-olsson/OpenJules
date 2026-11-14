"""The producer emits a closed diagnostic only for an explicitly typed refusal."""

import json
from pathlib import Path

import pytest

from src.worker.child_types import ChildCapabilities
from src.worker.lifecycle import CapabilityDiagnostic, RuntimeCapabilities


DIAGNOSTIC = CapabilityDiagnostic.CHILD_INITIAL_OUTCOME_UNSUPPORTED
VECTOR = json.loads(
    (Path(__file__).parents[1] / "fixtures/capability-diagnostic-v1.json").read_text()
)


def test_closed_diagnostic_and_subclass_fields_match_the_shared_vector():
    capability = ChildCapabilities(
        profile_supported=True,
        reason=VECTOR["responses"]["unsupported"]["reason"],
        diagnostic=DIAGNOSTIC,
    )
    payload = capability.as_response()
    assert payload["diagnostic"] == VECTOR["diagnostic"]
    assert type(payload["diagnostic"]["schema_version"]) is int
    assert type(payload["diagnostic"]["requirement"]["version"]) is int
    assert len(json.dumps(payload["diagnostic"]).encode()) <= 1024
    assert payload["children"] is False
    assert capability.usable is False
    # A caller cannot mutate another response's diagnostic through shared state.
    payload["diagnostic"]["requirement"]["version"] = 9
    assert capability.as_response()["diagnostic"] == VECTOR["diagnostic"]


@pytest.mark.parametrize("capability", [
    RuntimeCapabilities(True, True, True),
    RuntimeCapabilities(),
    RuntimeCapabilities(
        profile_supported=True,
        reason=VECTOR["responses"]["unsupported"]["reason"],
    ),
])
def test_unclassified_responses_omit_diagnostic_even_with_matching_prose(capability):
    assert "diagnostic" not in capability.as_response()


@pytest.mark.parametrize("fields", [
    {"diagnostic": VECTOR["diagnostic"]},
    {"diagnostic": "child_initial_outcome_unsupported"},
    {"managed_dispatch": True},
    {"repository_access": True},
    {"profile_supported": False},
    {"managed_dispatch": 0},
    {"repository_access": 0},
    {"profile_supported": 1},
])
def test_untyped_or_contradictory_diagnostics_cannot_be_constructed(fields):
    with pytest.raises(ValueError, match="invalid capability diagnostic"):
        RuntimeCapabilities(**{
            "profile_supported": True, "diagnostic": DIAGNOSTIC, **fields,
        })
