"""Capability attenuation and delegated grants for managed execution.

A primary lease holder sub-allocates a bounded slice of authority and budget
via capability attenuation. This terminology aligns with capability delegation
and FencedLedger lease invariants rather than POSIX process hierarchy baggage.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re
from typing import Any, Mapping

from src.polyphony.managed_client import AuthorityUnavailable

PROTOCOL = "bounded-children-v1"
WATCHDOG_UID = 65534
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
CHILD_ID = re.compile(r"child_[0-9a-f]{32}")
HASH = re.compile(r"[0-9a-f]{64}")

GRANT_FIELDS = {
    "child_id",
    "root_attempt_id",
    "parent_attempt_id",
    "task_id",
    "deployment_id",
    "repository",
    "runtime_principal",
    "worker_id",
    "profile",
    "profile_digest",
    "requirements_revision",
    "base",
    "launch_key",
    "allocated_seconds",
    "deadline",
    "max_turns",
    "capabilities",
    "instructions_digest",
    "grant_digest",
}


def canonical(value: Any) -> str:
    """Canonical JSON encoding matching Polyphony's immutable grant digest."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value: Any) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def text_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def finite(value: Any, minimum: float = 0, maximum: float = 86400) -> bool:
    return (
        type(value) in {int, float}
        and math.isfinite(value)
        and minimum < value <= maximum
    )


@dataclass(frozen=True)
class DelegatedGrantBinding:
    """Immutable capability binding parameters for a delegated grant."""

    child_id: str
    root_attempt_id: str
    parent_attempt_id: str
    task_id: str
    deployment_id: str
    repository: str
    runtime_principal: str
    worker_id: str
    profile: str
    profile_digest: str
    requirements_revision: int
    base: str
    launch_key: str
    allocated_seconds: float
    deadline: float
    max_turns: int
    capabilities: tuple[str, ...]
    instructions_digest: str
    grant_digest: str

    def to_dict(self) -> dict[str, Any]:
        data = asdict(self)
        data["capabilities"] = list(self.capabilities)
        return data

    @classmethod
    def from_dict(cls, data: Mapping[str, Any]) -> DelegatedGrantBinding:
        if not isinstance(data, Mapping) or set(data) != GRANT_FIELDS:
            raise AuthorityUnavailable("Canonical delegated grant binding is incomplete")
        return cls(
            child_id=data["child_id"],
            root_attempt_id=data["root_attempt_id"],
            parent_attempt_id=data["parent_attempt_id"],
            task_id=data["task_id"],
            deployment_id=data["deployment_id"],
            repository=data["repository"],
            runtime_principal=data["runtime_principal"],
            worker_id=data["worker_id"],
            profile=data["profile"],
            profile_digest=data["profile_digest"],
            requirements_revision=data["requirements_revision"],
            base=data["base"],
            launch_key=data["launch_key"],
            allocated_seconds=data["allocated_seconds"],
            deadline=data["deadline"],
            max_turns=data["max_turns"],
            capabilities=tuple(data["capabilities"]),
            instructions_digest=data["instructions_digest"],
            grant_digest=data["grant_digest"],
        )


@dataclass(frozen=True)
class DelegatedGrant:
    """A bounded capability sub-allocation (DelegatedGrant) from a primary lease holder.

    Represents capability attenuation: a primary lease holder sub-allocating a
    bounded slice of authority and budget.
    """

    binding: DelegatedGrantBinding
    instructions: str
    child_id: str
    launch_allowed: bool
    remaining_seconds: float
    reason: str
    raw_response: dict[str, Any]

    @property
    def grant_digest(self) -> str:
        return self.binding.grant_digest

    @property
    def instructions_digest(self) -> str:
        return self.binding.instructions_digest

    def to_dict(self) -> dict[str, Any]:
        return dict(self.raw_response)

    @classmethod
    def from_response(cls, response: dict[str, Any]) -> DelegatedGrant:
        binding_dict = response.get("binding") or {}
        binding = DelegatedGrantBinding.from_dict(binding_dict)
        return cls(
            binding=binding,
            instructions=response.get("instructions", ""),
            child_id=binding.child_id,
            launch_allowed=bool(response.get("launch_allowed")),
            remaining_seconds=float(response.get("remaining_seconds", 0.0)),
            reason=str(response.get("reason", "")),
            raw_response=dict(response),
        )


# Backward-compatible aliases
Subgrant = DelegatedGrant
SubLease = DelegatedGrant
