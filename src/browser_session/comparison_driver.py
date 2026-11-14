"""One bounded comparison through an already scoped in-process gateway.

This module has no browser, listener, dispatcher, credential issuer or durable
driver ledger. The trusted host supplies synchronous, non-preemptible callbacks
and keeps ownership of dispatch, lifetime supervision, capture and owner Stop.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from hashlib import sha256
import math
import re
import threading
from typing import Callable

from .types import Clock, canonical, identifier, integer, text


ALPHA_URL = "http://127.0.0.1:8765/alpha.html"
BETA_URL = "http://127.0.0.1:8766/beta.html"
CORRECTION = "Use express delivery for Alpha."
PHASES = ("alpha-to-beta", "beta-to-alpha", "corrected-alpha-to-beta")
_IDENTITY = {"session_id", "context_id", "target_id", "backend_epoch", "control_generation",
             "document_id", "document_generation"}
_VIEW = _IDENTITY | {"schema_version", "mode", "actor_id", "audit_available", "server_time_ms",
                     "frame_max_age_ms", "corrections", "results", "frame"}
_FRAME = {"session_id", "context_id", "target_id", "backend_epoch", "control_generation", "document_id",
          "sequence", "captured_at_ms", "width", "height", "projection", "jpeg_sha256",
          "observation_id", "jpeg_base64"}
_ACK = {"schema_version", "operation_id", "actor_id", "kind", "state", "control_generation", "audit_persisted"}
_FIELDS = {"fixture", "price", "delivery", "total", "next_url", "next_x", "next_y"}
_HASH = re.compile(r"[0-9a-f]{64}\Z")
_MODES = {"driver", "human", "quiescing", "fenced", "stopping", "stopped", "lost"}
_STATES = {"queued", "dispatched", "applied", "not_applied", "unknown"}
_CLAIM_LOCK = threading.Lock()
_process_claim = None  # One irreversible claim, with no production reset API.


class DriverDenied(ValueError):
    """A fixed diagnostic, never a callback's exception or supplied data."""

    def __init__(self, code):
        self.code = code
        super().__init__(code)


@dataclass(frozen=True, slots=True)
class OperationAbsent:
    """The host observed the core's authorized, exact operation_absent result."""


ABSENT = OperationAbsent()


@dataclass(frozen=True, slots=True)
class ComparisonPort:
    """Only closed public projections cross these already scoped callbacks.

    Bind actual observe/control grants outside the driver. Project a core
    operation through the existing public acknowledgement before returning it;
    the core's complete submit record contains private ticket data. Only an
    authorized exact ``operation_absent`` lookup may become ``ABSENT``. Every
    other exception or result remains a failure, never evidence of absence.

    These are synchronous in-process calls. A blocked callback is not cancelled
    or preempted by the driver. The host retains callback/process custody.
    """

    observe: Callable[[], dict] = field(repr=False)
    submit: Callable[[dict], dict] = field(repr=False)
    operation: Callable[[str], dict | OperationAbsent] = field(repr=False)

    def __post_init__(self):
        if not all(callable(value) for value in (self.observe, self.submit, self.operation)):
            raise DriverDenied("invalid_port")


@dataclass(frozen=True, slots=True)
class DriverLimits:
    steps: int = 1200
    port_calls: int = 2400
    step_interval_ms: int = 250
    clicks: int = 3
    result_bytes: int = 8192

    def validate(self):
        for name, maximum in (("steps", 1200), ("port_calls", 2400), ("clicks", 3), ("result_bytes", 8192)):
            integer(getattr(self, name), 1, maximum)
        integer(self.step_interval_ms, 250, 300000)


@dataclass(frozen=True, slots=True)
class DriverSpec:
    session_id: str
    context_id: str
    target_id: str
    backend_epoch: str
    driver_actor_id: str
    owner_actor_id: str
    started_at_ms: int
    expires_at_ms: int
    limits: DriverLimits = DriverLimits()

    def validate(self, now_ms):
        for name in ("session_id", "context_id", "target_id", "backend_epoch", "driver_actor_id", "owner_actor_id"):
            identifier(getattr(self, name))
        if self.driver_actor_id == self.owner_actor_id or type(self.limits) is not DriverLimits:
            raise DriverDenied("invalid_spec")
        integer(self.started_at_ms)
        integer(self.expires_at_ms, self.started_at_ms + 1, self.started_at_ms + 300000)
        integer(now_ms, self.started_at_ms, self.expires_at_ms - 1)
        self.limits.validate()

    def operation_ids(self):
        """No deadline, budget, generation, retry counter or caller run ID."""
        scope = {"session_id": self.session_id, "backend_epoch": self.backend_epoch,
                 "driver_actor_id": self.driver_actor_id}
        return tuple("compare." + sha256(canonical(scope | {"phase": phase}).encode("ascii")).hexdigest()
                     for phase in PHASES)


@dataclass(frozen=True, slots=True)
class DriverProgress:
    state: str
    phase: str
    reason: str | None
    steps: int
    port_calls: int
    clicks: int
    original_operation_id: str | None
    last_known_operation_state: str | None
    result: bytes | None = field(repr=False)


def _shape(value, fields):
    if type(value) is not dict or set(value) != fields:
        raise DriverDenied("invalid_projection")


def _version(value):
    if type(value) is not int or value != 1:
        raise DriverDenied("invalid_projection")


def _hash(value):
    if type(value) is not str or not _HASH.fullmatch(value):
        raise DriverDenied("invalid_projection")


def _acknowledgement(value, spec, key, generation=None):
    _shape(value, _ACK)
    _version(value["schema_version"])
    integer(value["control_generation"])
    if (value["operation_id"] != key or type(value["operation_id"]) is not str
            or value["actor_id"] != spec.driver_actor_id or type(value["actor_id"]) is not str
            or value["kind"] != "action" or type(value["kind"]) is not str
            or type(value["state"]) is not str or value["state"] not in _STATES
            or type(value["audit_persisted"]) is not bool
            or (generation is not None and value["control_generation"] != generation)):
        raise DriverDenied("invalid_acknowledgement")
    return {name: value[name] for name in _ACK}


def _observation(value, spec, now_ms):
    """Validate the existing HTTP observation projection, dropping JPEG data."""
    _shape(value, _VIEW)
    _version(value["schema_version"])
    for name in ("session_id", "context_id", "target_id", "backend_epoch"):
        if type(value[name]) is not str or value[name] != getattr(spec, name):
            raise DriverDenied("foreign_observation")
    identifier(value["document_id"])
    integer(value["control_generation"])
    integer(value["document_generation"])
    integer(value["server_time_ms"], 0, now_ms)
    integer(value["frame_max_age_ms"], 1, 5000)
    if (type(value["mode"]) is not str or value["mode"] not in _MODES
            or type(value["audit_available"]) is not bool):
        raise DriverDenied("invalid_projection")
    expected_actor = {"driver": spec.driver_actor_id, "human": spec.owner_actor_id}.get(value["mode"])
    if value["actor_id"] != expected_actor or (expected_actor is not None and type(value["actor_id"]) is not str):
        raise DriverDenied("foreign_actor")
    rows = value["corrections"]
    if type(rows) is not list or len(rows) > 20:
        raise DriverDenied("invalid_corrections")
    corrections, keys = [], set()
    for row in rows:
        _shape(row, {"operation_id", "actor_id", "text", "generation"})
        identifier(row["operation_id"])
        identifier(row["actor_id"])
        text(row["text"], 2048)
        integer(row["generation"], 0, value["control_generation"])
        if row["operation_id"] in keys or row["actor_id"] != spec.owner_actor_id:
            raise DriverDenied("ambiguous_correction")
        keys.add(row["operation_id"])
        corrections.append(dict(row))
    results = value["results"]
    if type(results) is not list or len(results) > 3:
        raise DriverDenied("invalid_projection")
    names = set()
    for row in results:
        _shape(row, {"name", "sha256", "bytes"})
        if type(row["name"]) is not str or row["name"] not in {"result.json", "events.json", "screenshot.jpg"} or row["name"] in names:
            raise DriverDenied("invalid_projection")
        names.add(row["name"])
        _hash(row["sha256"])
        integer(row["bytes"], 0, 16777216)
    view = {name: value[name] for name in _IDENTITY | {"mode", "actor_id", "audit_available", "server_time_ms", "frame_max_age_ms"}}
    view["corrections"], view["frame"] = corrections, None
    if value["frame"] is None:
        return view
    frame = value["frame"]
    _shape(frame, _FRAME)
    for name in ("session_id", "context_id", "target_id", "backend_epoch", "control_generation", "document_id"):
        if type(frame[name]) is not type(value[name]) or frame[name] != value[name]:
            raise DriverDenied("foreign_frame")
    integer(frame["sequence"], 1)
    integer(frame["captured_at_ms"], 0, value["server_time_ms"])
    integer(frame["width"], 1, 4096)
    integer(frame["height"], 1, 4096)
    _hash(frame["observation_id"])
    _hash(frame["jpeg_sha256"])
    text(frame["jpeg_base64"], 1398104)
    projection = frame["projection"]
    _shape(projection, {"url", "title", "fields"})
    text(projection["url"], 4096)
    text(projection["title"], 1024, empty=True)
    _shape(projection["fields"], _FIELDS)
    fields = projection["fields"]
    fixture = fields["fixture"]
    if type(fixture) is not str or fixture not in {"alpha", "beta"}:
        raise DriverDenied("invalid_fixture")
    expected_url, next_url, price, deliveries = ((ALPHA_URL, BETA_URL, 120, {5, 12}) if fixture == "alpha"
                                                else (BETA_URL, ALPHA_URL, 110, {8}))
    for name in ("price", "delivery", "total", "next_x", "next_y"):
        integer(fields[name])
    if (projection["url"] != expected_url or fields["next_url"] != next_url
            or type(fields["next_url"]) is not str or fields["price"] != price
            or fields["delivery"] not in deliveries or fields["price"] + fields["delivery"] != fields["total"]
            or fields["next_x"] >= frame["width"] or fields["next_y"] >= frame["height"]):
        raise DriverDenied("invalid_fixture_values")
    view["frame"] = {name: frame[name] for name in _FRAME - {"projection", "jpeg_base64"}}
    view["frame"]["projection"] = {"url": projection["url"], "title": projection["title"], "fields": dict(fields)}
    return view


def _latest_correction(view, generation):
    values = [row for row in view["corrections"] if row["generation"] == generation]
    return values[-1] if values else None


def _clock(clock):
    try:
        wall, mono = clock.wall_ms(), clock.monotonic()
        integer(wall)
        if type(mono) not in {int, float} or not math.isfinite(mono) or mono < 0:
            raise ValueError()
        return wall, mono
    except Exception:
        raise DriverDenied("invalid_clock") from None
