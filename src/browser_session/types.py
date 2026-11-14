"""Closed, bounded values at the standalone session's trusted adapter seam."""

from __future__ import annotations

from dataclasses import asdict, dataclass
import json
import ipaddress
import re
import time
from typing import Protocol
from urllib.parse import urlsplit


IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
RIGHTS = frozenset({"observe", "control", "stop"})
OUTCOMES = frozenset({"applied", "not_applied", "unknown"})
KEYS = frozenset({"enter", "tab", "escape", "backspace", "delete", "space",
                  "arrow_up", "arrow_down", "arrow_left", "arrow_right",
                  "home", "end", "page_up", "page_down", "select_all"})


class SessionDenied(ValueError):
    """A fixed public code, without supplied input or credentials."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class SessionUnavailable(RuntimeError):
    def __init__(self):
        super().__init__("session_state_unavailable")


class Clock(Protocol):
    def wall_ms(self) -> int: ...
    def monotonic(self) -> float: ...


class SystemClock:
    def wall_ms(self) -> int:
        return time.time_ns() // 1_000_000

    def monotonic(self) -> float:
        return time.monotonic()


def integer(value, minimum=0, maximum=2**53 - 1):
    if (type(value) is not int or not max(minimum, -(2**53 - 1)) <= value <= min(maximum, 2**53 - 1)):
        raise SessionDenied("invalid_integer")
    return value


def identifier(value):
    if type(value) is not str or not IDENTIFIER.fullmatch(value):
        raise SessionDenied("invalid_identity")
    return value


def text(value, maximum, *, empty=False):
    if (type(value) is not str or (not empty and not value) or "\0" in value
            or any(0xD800 <= ord(c) <= 0xDFFF for c in value)
            or len(value.encode("utf-8")) > maximum):
        raise SessionDenied("invalid_text")
    return value


def canonical(value):
    return json.dumps(value, ensure_ascii=True, sort_keys=True,
                      separators=(",", ":"), allow_nan=False)


def strict_json(raw):
    def pairs(items):
        result = {}
        for key, value in items:
            if key in result:
                raise SessionDenied("invalid_json")
            result[key] = value
        return result

    try:
        return json.loads(raw, object_pairs_hook=pairs,
                          parse_constant=lambda _: (_ for _ in ()).throw(SessionDenied("invalid_json")))
    except (ValueError, UnicodeError, RecursionError):
        raise SessionDenied("invalid_json") from None


def origin(value):
    text(value, 4096)
    if any(c.isspace() or ord(c) < 32 for c in value) or "\\" in value:
        raise SessionDenied("invalid_origin")
    try:
        parsed = urlsplit(value)
        port = parsed.port
        if (parsed.scheme not in {"http", "https"} or not parsed.hostname
                or parsed.username is not None or parsed.password is not None
                or "%" in parsed.netloc or not parsed.netloc.isascii()
                or parsed.netloc.endswith(":") or port == 0):
            raise ValueError()
        host = parsed.hostname.lower()
        if ":" in host:
            host = "[" + str(ipaddress.IPv6Address(host)) + "]"
        elif all(character in "0123456789." for character in host):
            host = str(ipaddress.IPv4Address(host))
        elif (len(host) > 253 or any(not re.fullmatch(r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", part)
                                    for part in host.split("."))):
            raise ValueError()
        if port is not None and port != {"http": 80, "https": 443}[parsed.scheme]:
            host += ":" + str(port)
        return parsed.scheme + "://" + host
    except ValueError:
        raise SessionDenied("invalid_origin") from None


@dataclass(frozen=True)
class Limits:
    semantic_actions: int = 20
    raw_inputs: int = 200
    raw_inputs_per_second: int = 20
    queue: int = 8
    operations: int = 256
    events: int = 1024
    grants: int = 16
    frame_bytes: int = 524288
    frame_age_ms: int = 2000
    frame_interval_ms: int = 100
    action_timeout_ms: int = 3000
    fence_timeout_ms: int = 3000
    stop_timeout_ms: int = 3000
    result_bytes: int = 16777216

    def validate(self):
        caps = {"semantic_actions": 20, "raw_inputs": 1000, "raw_inputs_per_second": 100,
                "queue": 16, "operations": 512, "events": 2048, "grants": 64,
                "frame_bytes": 1048576, "frame_age_ms": 5000, "frame_interval_ms": 1000,
                "action_timeout_ms": 10000, "fence_timeout_ms": 10000,
                "stop_timeout_ms": 10000, "result_bytes": 16777216}
        for key, maximum in caps.items():
            integer(getattr(self, key), 2 if key == "operations" else 1, maximum)
        if self.events < self.operations + 8:
            raise SessionDenied("event_budget_too_small")
        return self


@dataclass(frozen=True)
class SessionSpec:
    session_id: str
    context_id: str
    target_id: str
    document_id: str
    driver_actor_id: str
    owner_actor_id: str
    fixture_origins: tuple[str, str]
    observation_fields: tuple[str, ...]
    browser_expires_at_ms: int
    retention_expires_at_ms: int
    limits: Limits = Limits()

    def validate(self, now_ms):
        integer(now_ms)
        for key in ("session_id", "context_id", "target_id", "document_id", "driver_actor_id", "owner_actor_id"):
            identifier(getattr(self, key))
        if self.driver_actor_id == self.owner_actor_id:
            raise SessionDenied("actor_alias")
        if (type(self.fixture_origins) is not tuple or len(self.fixture_origins) != 2
                or len(set(self.fixture_origins)) != 2
                or any(origin(item) != item for item in self.fixture_origins)):
            raise SessionDenied("invalid_fixture_origins")
        if (type(self.observation_fields) is not tuple or len(self.observation_fields) > 16
                or tuple(sorted(set(self.observation_fields))) != self.observation_fields):
            raise SessionDenied("invalid_observation_fields")
        for field in self.observation_fields:
            identifier(field)
        integer(self.browser_expires_at_ms, now_ms + 1, now_ms + 300000)
        integer(self.retention_expires_at_ms, self.browser_expires_at_ms, now_ms + 86400000)
        self.limits.validate()
        return self

    def to_dict(self):
        return asdict(self)

    @classmethod
    def retained(cls, value):
        if type(value) is not dict or set(value) != set(cls.__dataclass_fields__):
            raise SessionUnavailable()
        try:
            return cls(**(value | {"fixture_origins": tuple(value["fixture_origins"]),
                "observation_fields": tuple(value["observation_fields"]), "limits": Limits(**value["limits"])}))
        except (TypeError, KeyError, ValueError):
            raise SessionUnavailable() from None


@dataclass(frozen=True)
class Authorization:
    actor_id: str
    session_id: str
    context_id: str
    target_id: str
    right: str
    expires_at_ms: int


@dataclass(frozen=True)
class Observation:
    session_id: str
    context_id: str
    target_id: str
    backend_epoch: str
    control_generation: int
    document_id: str
    sequence: int
    captured_at_ms: int
    width: int
    height: int
    projection_json: str
    jpeg: bytes


@dataclass(frozen=True)
class ActionTicket:
    session_id: str
    context_id: str
    target_id: str
    backend_epoch: str
    operation_id: str
    actor_id: str
    control_generation: int
    document_id: str
    document_generation: int
    action: str
    parameters_json: str
    deadline_monotonic: float


@dataclass(frozen=True)
class OperationOutcome:
    operation_id: str
    backend_epoch: str
    control_generation: int
    document_generation: int
    state: str  # applied, not_applied, unknown


@dataclass(frozen=True)
class FenceTicket:
    session_id: str
    context_id: str
    target_id: str
    backend_epoch: str
    operation_id: str
    control_generation: int
    inflight: tuple[ActionTicket, ...]
    deadline_monotonic: float


@dataclass(frozen=True)
class FenceReceipt:
    session_id: str
    backend_epoch: str
    operation_id: str
    control_generation: int
    quiescent: bool
    outcomes: tuple[OperationOutcome, ...]
    observation: Observation | None


@dataclass(frozen=True)
class StopTicket:
    session_id: str
    context_id: str
    target_id: str
    backend_epoch: str
    operation_id: str
    control_generation: int
    deadline_monotonic: float


@dataclass(frozen=True)
class StopReceipt:
    session_id: str
    backend_epoch: str
    operation_id: str
    control_generation: int
    state: str  # confirmed, pending, failed, unknown


class Adapter(Protocol):
    """Trusted non-bypassing connection owner, not a sandbox qualification.

    A real implementation must enforce ticket deadlines and confined egress,
    return exact original outcomes and retain custody of timed-out tasks. Core
    timeout cancellation never supplies quiescence or teardown evidence.
    """

    async def execute(self, ticket: ActionTicket) -> OperationOutcome: ...
    async def quiesce(self, ticket: FenceTicket) -> FenceReceipt: ...
    async def stop(self, ticket: StopTicket) -> StopReceipt: ...
