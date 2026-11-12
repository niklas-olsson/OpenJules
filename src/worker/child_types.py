"""Immutable policy and canonical bindings for one level of managed children.

Capability names describe one approved runner bundle. They are not a claim that
removing a model tool creates an operating-system privilege boundary.
"""

from __future__ import annotations

from dataclasses import asdict, dataclass
import hashlib
import json
import math
import re
from typing import Mapping

from src.polyphony.managed_client import AuthorityUnavailable, AuthorityUnsupported
from src.worker.lifecycle import RuntimeCapabilities, WorkerSpec

PROTOCOL = "bounded-children-v1"
WATCHDOG_UID = 65534
IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
CHILD_ID = re.compile(r"child_[0-9a-f]{32}")
HASH = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class ChildCapabilities(RuntimeCapabilities):
    children: bool = False


def canonical(value) -> str:
    # Polyphony's immutable grant digest uses the default ASCII escaping.
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False)


def digest(value) -> str:
    return hashlib.sha256(canonical(value).encode()).hexdigest()


def text_hash(value: str) -> str:
    return hashlib.sha256(value.encode()).hexdigest()


def finite(value, minimum=0, maximum=86400) -> bool:
    return (
        type(value) in {int, float}
        and math.isfinite(value)
        and minimum < value <= maximum
    )


def argv(value, name: str, *, empty=False) -> tuple[str, ...]:
    if (
        not isinstance(value, (list, tuple))
        or (not empty and not value)
        or len(value) > 128
    ):
        raise ValueError(f"invalid child {name}")
    if any(
        not isinstance(item, str) or not item or "\0" in item or len(item) > 4096
        for item in value
    ):
        raise ValueError(f"invalid child {name}")
    return tuple(value)


@dataclass(frozen=True)
class ChildPolicy:
    max_children: int
    max_child_seconds: float
    max_child_turns: int
    capabilities: tuple[str, ...]
    uid_start: int = 60000
    command: tuple[str, ...] = (
        "python3",
        "-I",
        "-S",
        "/opt/openjules/managed_runner.py",
    )
    verify_argv: tuple[str, ...] = ()
    max_result_bytes: int = 4_000_000
    outcome_protocol: str | None = None
    session_protocol: str | None = None

    def __post_init__(self):
        if type(self.max_children) is not int or not 1 <= self.max_children <= 64:
            raise ValueError("child lifetime count must be between one and 64")
        if not finite(self.max_child_seconds):
            raise ValueError("invalid maximum child duration")
        if (
            type(self.max_child_turns) is not int
            or not 1 <= self.max_child_turns <= 1000
        ):
            raise ValueError("invalid maximum child turns")
        values = self.capabilities
        if (
            not isinstance(values, (tuple, list))
            or len(values) > 100
            or any(
                not isinstance(value, str)
                or not value
                or "\0" in value
                or len(value.encode()) > 512
                for value in values
            )
            or len(set(values)) != len(values)
        ):
            raise ValueError("child capabilities must name a distinct approved bundle")
        object.__setattr__(self, "capabilities", tuple(sorted(values)))
        if (
            type(self.uid_start) is not int
            or not 1 <= self.uid_start <= 65535 - self.max_children + 1
        ):
            raise ValueError("child UID range must be nonzero and bounded")
        if WATCHDOG_UID in self.uids:
            raise ValueError("child UID range includes the protected watchdog")
        object.__setattr__(self, "command", argv(self.command, "command"))
        object.__setattr__(
            self,
            "verify_argv",
            argv(self.verify_argv, "verification command", empty=True),
        )
        if (
            type(self.max_result_bytes) is not int
            or not 1024 <= self.max_result_bytes <= 4_000_000
        ):
            raise ValueError("invalid child result bound")
        if self.outcome_protocol is not None and (
            self.outcome_protocol != "initial-v1"
            or self.command != type(self).__dataclass_fields__["command"].default
        ):
            raise ValueError(
                "child outcome protocol requires the approved managed runner"
            )

        if self.session_protocol is not None and (
            self.session_protocol != "cold-clarification-v1"
            or self.outcome_protocol != "initial-v1"
            or self.max_children < 2
        ):
            raise ValueError(
                "cold child sessions require initial-v1 and at least two lifetime slots"
            )

    @property
    def uids(self) -> range:
        return range(self.uid_start, self.uid_start + self.max_children)

    def validate_root(self, root_uid: int, root_seconds: float, reserved_uids=()):
        if any(uid in self.uids for uid in {0, root_uid, WATCHDOG_UID, *reserved_uids}):
            raise ValueError("child UID range overlaps a protected identity")
        if self.max_child_seconds > root_seconds:
            raise ValueError("child duration exceeds the root runtime limit")

    @property
    def fingerprint(self) -> str:
        values = asdict(self)
        if self.outcome_protocol is None:
            values.pop("outcome_protocol")
        if self.session_protocol is None:
            values.pop("session_protocol")
        return digest({"protocol": PROTOCOL, "watchdog_protocol": 1, **values})

    @property
    def canonical_policy(self) -> dict:
        return {
            "max_children": self.max_children,
            "max_child_seconds": self.max_child_seconds,
            "max_child_turns": self.max_child_turns,
            "child_capabilities": list(self.capabilities),
        }

    def validate_capabilities(self, response: dict):
        approved = response.get("child_policy")
        if (
            isinstance(approved, dict)
            and isinstance(approved.get("child_capabilities"), list)
            and all(isinstance(item, str) for item in approved["child_capabilities"])
        ):
            approved = approved | {
                "child_capabilities": sorted(approved["child_capabilities"])
            }
        if (
            response.get("child_grants") is not True
            or approved != self.canonical_policy
        ):
            raise AuthorityUnavailable(
                "Canonical child policy does not match the approved runtime"
            )
        if self.outcome_protocol is not None and (
            type(response.get("child_initial_outcome")) is not int
            or response["child_initial_outcome"] != 1
        ):
            version = response.get("child_initial_outcome")
            # This branch already refuses admission. Attribute unsupported only
            # to a well-typed matching policy, never Python's bool/int aliases.
            trusted_policy = (
                isinstance(approved, dict)
                and type(approved.get("max_children")) is int
                and type(approved.get("max_child_turns")) is int
                and finite(approved.get("max_child_seconds"))
            )
            unsupported_version = "child_initial_outcome" not in response or (
                type(version) is int and version > 0 and version != 1
            )
            if trusted_policy and unsupported_version:
                raise AuthorityUnsupported()
            raise AuthorityUnavailable(
                "Canonical child policy does not match the approved runtime"
            )

    def request(self, value: dict) -> dict:
        if not isinstance(value, dict) or set(value) != {
            "instructions",
            "seconds",
            "max_turns",
            "capabilities",
        }:
            raise ValueError("invalid child grant request fields")
        instructions = value["instructions"]
        if (
            not isinstance(instructions, str)
            or not instructions
            or "\0" in instructions
            or len(instructions.encode()) > 65536
        ):
            raise ValueError("child instructions must be bounded nonempty text")
        if not finite(value["seconds"], maximum=self.max_child_seconds):
            raise ValueError("child duration exceeds the approved bundle")
        if (
            type(value["max_turns"]) is not int
            or not 1 <= value["max_turns"] <= self.max_child_turns
        ):
            raise ValueError("child turns exceed the approved bundle")
        supplied = value["capabilities"]
        if (
            not isinstance(supplied, list)
            or any(not isinstance(item, str) for item in supplied)
            or sorted(supplied) != list(self.capabilities)
        ):
            raise ValueError(
                "only the exact approved child capability bundle is supported"
            )
        return {**value, "capabilities": list(self.capabilities)}


@dataclass(frozen=True)
class RootContext:
    worker_id: str
    spec: WorkerSpec
    attempt_id: str
    task_id: str
    runtime_principal: str
    profile_digest: str
    requirements_revision: int
    base: str
    deadline: float
    monotonic_deadline: float
    boot_id: str

    @classmethod
    def bind(
        cls,
        worker_id: str,
        spec: WorkerSpec,
        response: dict,
        monotonic_deadline: float,
        boot_id: str,
    ):
        binding = response.get("binding", {})
        attempt = response.get("attempt", {})
        expected = {
            "worker_id": worker_id,
            "deployment_id": spec.deployment_id,
            "repository": spec.repository,
            "profile": spec.profile,
        }
        if any(binding.get(key) != value for key, value in expected.items()) or (
            response.get("deployment_id") != spec.deployment_id
            or response.get("repository") != spec.repository
            or type(response.get("schema_version")) is not int
            or response["schema_version"] != 1
            or binding.get("attempt_id") != attempt.get("id")
            or not isinstance(attempt.get("task"), str)
            or not attempt["task"]
            or not isinstance(binding.get("attempt_id"), str)
            or not binding["attempt_id"]
            or not isinstance(binding.get("runtime_principal"), str)
            or not binding["runtime_principal"]
            or not isinstance(binding.get("profile_digest"), str)
            or not HASH.fullmatch(binding["profile_digest"])
            or not isinstance(binding.get("base"), str)
            or not re.fullmatch(r"[0-9a-f]{40}", binding["base"])
            or type(binding.get("requirements_revision")) is not int
            or binding["requirements_revision"] < 1
            or not finite(binding.get("deadline"), maximum=1e20)
            or not finite(monotonic_deadline, maximum=1e20)
            or not isinstance(boot_id, str)
            or not boot_id
        ):
            raise AuthorityUnavailable(
                "Root child context is not bound to this runtime attempt"
            )
        return cls(
            worker_id,
            spec,
            binding["attempt_id"],
            attempt["task"],
            binding["runtime_principal"],
            binding["profile_digest"],
            binding["requirements_revision"],
            binding["base"],
            binding["deadline"],
            monotonic_deadline,
            boot_id,
        )

    def to_dict(self):
        return asdict(self)

    @classmethod
    def from_dict(cls, value):
        return cls(**(value | {"spec": WorkerSpec(**value["spec"])}))


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


def verify_grant(
    response: dict,
    root: RootContext,
    policy: ChildPolicy,
    requested: Mapping | None = None,
    original: Mapping | None = None,
) -> dict:
    """Validate immutable canonical content even after permission was revoked."""
    if not isinstance(response, dict):
        raise AuthorityUnavailable("Canonical child response is not an object")
    binding = response.get("binding")
    child = response.get("child")
    if (
        not isinstance(binding, dict)
        or set(binding) != GRANT_FIELDS
        or not isinstance(child, dict)
    ):
        raise AuthorityUnavailable("Canonical child binding is incomplete")
    expected = {
        "deployment_id": root.spec.deployment_id,
        "repository": root.spec.repository,
        "root_attempt_id": root.attempt_id,
        "parent_attempt_id": root.attempt_id,
        "worker_id": root.worker_id,
        "task_id": root.task_id,
        "runtime_principal": root.runtime_principal,
        "profile": root.spec.profile,
        "profile_digest": root.profile_digest,
        "requirements_revision": root.requirements_revision,
        "base": root.base,
    }
    instructions = response.get("instructions")
    if (
        type(response.get("schema_version")) is not int
        or response["schema_version"] != 1
        or any(
            response.get(key) != expected[key]
            for key in ("deployment_id", "repository", "root_attempt_id")
        )
        or any(binding.get(key) != value for key, value in expected.items())
        or not isinstance(binding.get("child_id"), str)
        or not CHILD_ID.fullmatch(binding["child_id"])
        or binding["launch_key"] != "polyphony-child:" + binding["child_id"]
        or child.get("id") != binding["child_id"]
        or child.get("binding") != binding
        or not isinstance(instructions, str)
        or not instructions
        or len(instructions.encode()) > 65536
        or child.get("instructions") != instructions
        or binding["instructions_digest"] != text_hash(instructions)
        or binding["grant_digest"]
        != digest(
            {key: value for key, value in binding.items() if key != "grant_digest"}
        )
        or not finite(binding["allocated_seconds"], maximum=policy.max_child_seconds)
        or not finite(binding["deadline"], maximum=root.deadline)
        or type(binding["max_turns"]) is not int
        or not 1 <= binding["max_turns"] <= policy.max_child_turns
        or binding["capabilities"] != list(policy.capabilities)
        or type(response.get("launch_allowed")) is not bool
        or type(response.get("remaining_seconds")) not in {int, float}
        or not math.isfinite(response["remaining_seconds"])
        or not 0 <= response["remaining_seconds"] <= binding["allocated_seconds"]
    ):
        raise AuthorityUnavailable(
            "Canonical child grant does not match its immutable root"
        )
    if requested is not None and (
        instructions != requested["instructions"]
        or binding["allocated_seconds"] != requested["seconds"]
        or binding["max_turns"] != requested["max_turns"]
        or binding["capabilities"] != requested["capabilities"]
    ):
        raise AuthorityUnavailable("Canonical child grant changed the requested limits")
    if original is not None and (
        binding != original["binding"] or instructions != original["instructions"]
    ):
        raise AuthorityUnavailable(
            "Canonical child retry changed its immutable binding"
        )
    return response
