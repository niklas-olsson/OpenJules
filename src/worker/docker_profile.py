"""Pure immutable Docker profile; re-exported by docker_runtime for compatibility."""

from dataclasses import asdict, dataclass, field
import hashlib
import json
from pathlib import Path
import re
from typing import Mapping

from .lifecycle import WorkerScope

WATCHDOG_UID = 65534


def _json(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value):
    return hashlib.sha256(value.encode() if isinstance(value, str) else value).hexdigest()


_MODEL_ENV = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
}


@dataclass(frozen=True)
class DockerProfile:
    """Operator-owned immutable configuration, never supplied by a task."""

    name: str
    deployment_id: str
    repository: str
    source_path: str
    image: str
    command: tuple[str, ...]
    base_commit: str
    uid: int = 65532
    memory_bytes: int = 536870912
    cpu_quota: int = 100000
    pids_limit: int = 128
    max_seconds: int = 300
    max_archive_bytes: int = 16777216
    environment_refs: tuple[tuple[str, str], ...] | Mapping[str, str] = field(
        default_factory=tuple
    )

    def __post_init__(self) -> None:
        WorkerScope(self.deployment_id, self.repository)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.name):
            raise ValueError("invalid approved profile name")
        if not re.fullmatch(r"(?:sha256:|[^\s]+@sha256:)[0-9a-f]{64}", self.image):
            raise ValueError("profile image must use an immutable image ID or digest")
        if not re.fullmatch(r"[0-9a-f]{40}", self.base_commit):
            raise ValueError("base_commit must be a full Git SHA-1 commit ID")
        if (
            not isinstance(self.source_path, str)
            or not Path(self.source_path).is_absolute()
        ):
            raise ValueError("source_path must be an approved absolute path")
        if not isinstance(self.command, (list, tuple)):
            raise ValueError("command must be an argv list or tuple")
        object.__setattr__(self, "command", tuple(self.command))
        if not self.command or any(
            not isinstance(x, str) or not x or "\0" in x or len(x) > 4096
            for x in self.command
        ):
            raise ValueError("command must be a bounded nonempty argv")
        for name, minimum, maximum in (
            ("uid", 1, 65535),
            ("memory_bytes", 16777216, 1 << 40),
            ("cpu_quota", 1000, 1 << 31),
            ("pids_limit", 8, 65536),
            ("max_seconds", 1, 86400),
            ("max_archive_bytes", 1024, 1 << 30),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"invalid {name}")
        if self.uid == WATCHDOG_UID:
            raise ValueError("task uid must differ from the trusted watchdog uid")
        refs = (
            self.environment_refs.items()
            if isinstance(self.environment_refs, Mapping)
            else self.environment_refs
        )
        refs = tuple(sorted(refs))
        if len(dict(refs)) != len(refs):
            raise ValueError("duplicate environment reference")
        for name, reference in refs:
            if (
                name not in _MODEL_ENV
                or not isinstance(reference, str)
                or not re.fullmatch(r"env:[A-Z_][A-Z0-9_]*", reference)
            ):
                raise ValueError(
                    "only explicit model credential environment references are supported"
                )
        object.__setattr__(self, "environment_refs", refs)

    @property
    def scope(self) -> WorkerScope:
        return WorkerScope(self.deployment_id, self.repository)

    @property
    def fingerprint(self) -> str:
        return _digest(_json(asdict(self)))
