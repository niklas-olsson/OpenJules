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
    deadline_monotonic: float
    limits: DriverLimits = DriverLimits()

    def validate(self, now_ms, now_mono):
        for name in ("session_id", "context_id", "target_id", "backend_epoch", "driver_actor_id", "owner_actor_id"):
            identifier(getattr(self, name))
        if self.driver_actor_id == self.owner_actor_id or type(self.limits) is not DriverLimits:
            raise DriverDenied("invalid_spec")
        integer(self.started_at_ms)
        integer(self.expires_at_ms, self.started_at_ms + 1, self.started_at_ms + 300000)
        integer(now_ms, self.started_at_ms, self.expires_at_ms - 1)
        if (type(self.deadline_monotonic) not in {int, float} or not math.isfinite(self.deadline_monotonic)
                or not 0 < self.deadline_monotonic - now_mono <= 300):
            raise DriverDenied("invalid_original_deadline")
        self.limits.validate()

    def operation_ids(self):
        """No deadline, budget, generation, retry counter or caller run ID."""
        scope = {name: getattr(self, name) for name in
                 ("session_id", "context_id", "target_id", "backend_epoch", "driver_actor_id")}
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


_MISSING = object()


class ComparisonDriver:
    """Advance one fixed fixture comparison without owning its runtime.

    At most two port calls occur in an eligible step. Successive eligible steps
    are separated by at least 250 ms, including after a slow callback returns;
    this permits at most eight calls/second, not four. There is no sleep or
    scheduler. The original expiry and all counters survive every waiting phase.
    A callback can block beyond expiry, but its return cannot authorize another
    call or mutation. Any uncertain original remains available only by its key.
    """

    def __init__(self, spec: DriverSpec, port: ComparisonPort, clock: Clock):
        global _process_claim
        if type(spec) is not DriverSpec or type(port) is not ComparisonPort:
            raise DriverDenied("invalid_configuration")
        wall, mono = _clock(clock)
        try:
            spec.validate(wall, mono)
        except Exception:
            raise DriverDenied("invalid_spec") from None
        cutoff = spec.deadline_monotonic
        if not math.isfinite(cutoff) or cutoff <= mono:
            raise DriverDenied("invalid_clock")
        with _CLAIM_LOCK:
            if _process_claim is not None:
                raise DriverDenied("process_run_already_claimed")
            self._claim = _process_claim = object()
        self._spec, self._port, self._clock = spec, port, clock
        self._deadline, self._last_wall, self._last_mono = cutoff, wall, mono
        self._call_started = (wall, mono)
        self._next_step = mono
        self._lock = threading.Lock()
        self._state, self._phase, self._reason = "waiting", "preflight", None
        self._steps = self._calls = self._clicks = self._step_calls = self._preflight = 0
        self._ids = spec.operation_ids()
        self._prepared_key = None
        self._pending = None
        self._pending_state = None
        self._uncertain = False
        self._history = []
        self._quotes = {}
        self._generation = 0
        self._human_generation = None
        self._correction = None
        self._result = None
        self._last_progress = self._progress()

    @property
    def spec(self):
        return self._spec

    def _progress(self, reason=None):
        return DriverProgress(self._state, self._phase, self._reason if reason is None else reason,
            self._steps, self._calls, self._clicks,
            self._pending["request"]["operation_id"] if self._pending else None,
            self._pending_state, self._result)

    def _now(self):
        wall, mono = _clock(self._clock)
        if wall < self._last_wall or mono < self._last_mono:
            raise DriverDenied("clock_rollback")
        self._last_wall, self._last_mono = wall, mono
        if wall >= self.spec.expires_at_ms or mono >= self._deadline:
            raise DriverDenied("driver_expired")
        return wall, mono

    def _deny(self, reason):
        if self._state in {"completed", "expired", "refused"}:
            return
        if reason == "driver_expired":
            self._state = "expired"
        elif reason in {"clock_rollback", "invalid_clock", "step_budget", "port_budget", "claim_lost"}:
            self._state = "refused"
        elif self._pending is not None and reason != "operation_not_applied":
            self._uncertain = True
            self._state = "uncertain"
        else:
            self._state = "refused"
        self._reason = reason

    def _call(self, callback, *arguments):
        with _CLAIM_LOCK:
            if _process_claim is not self._claim:
                raise DriverDenied("claim_lost")
        self._call_started = self._now()
        if self._step_calls >= 2 or self._calls >= self.spec.limits.port_calls:
            raise DriverDenied("port_budget")
        self._step_calls += 1
        self._calls += 1  # Charge before entering a possibly failing callback.
        try:
            value = callback(*arguments)
        except Exception:
            self._deny("port_unavailable")
            try:
                self._now()
            except DriverDenied as error:
                self._deny(error.code)
            return _MISSING
        except BaseException:
            # Honor host interruption, but retain any possibly admitted original
            # before it escapes. Catching it outside cannot restore continuation.
            self._deny("port_interrupted")
            try:
                self._now()
            except DriverDenied as error:
                self._deny(error.code)
            except BaseException:
                self._deny("invalid_clock")
            raise
        try:
            self._now()
        except DriverDenied as error:
            # A late exact acknowledgement may still improve original facts.
            # Its caller may retain those facts, but cannot advance or do I/O.
            self._deny(error.code)
        return value

    def _live_return(self):
        return self._state not in {"expired", "refused", "uncertain"}

    def _read(self):
        value = self._call(self._port.observe)
        if value is _MISSING or not self._live_return():
            return None
        view = _observation(value, self.spec, self._last_wall)
        view["_read_started_monotonic"] = self._call_started[1]
        if not view["audit_available"]:
            raise DriverDenied("producer_audit_unavailable")
        if view["mode"] in {"fenced", "stopping", "stopped", "lost"}:
            raise DriverDenied("producer_unavailable")
        return view

    def _fresh_frame(self, view):
        wall, mono = self._now()
        frame = view["frame"]
        age = None if frame is None else max(wall - frame["captured_at_ms"],
            view["server_time_ms"] - frame["captured_at_ms"]
            + (mono - view["_read_started_monotonic"]) * 1000)
        if frame is None or age > view["frame_max_age_ms"]:
            self._reason = "fresh_observation_required"
            return None
        return frame

    def _driver_frame(self, view, fixture, delivery):
        if (view["mode"] != "driver" or view["actor_id"] != self.spec.driver_actor_id
                or view["control_generation"] != self._generation):
            raise DriverDenied("driver_control_required")
        frame = self._fresh_frame(view)
        if frame is None:
            return None
        fields = frame["projection"]["fields"]
        if fields["fixture"] != fixture or fields["delivery"] != delivery:
            raise DriverDenied("unexpected_fixture_state")
        return frame

    @staticmethod
    def _quote(view):
        frame, fields = view["frame"], view["frame"]["projection"]["fields"]
        return {"fixture": fields["fixture"], "price": fields["price"], "delivery": fields["delivery"],
            "total": fields["total"], "url": frame["projection"]["url"],
            "observation_id": frame["observation_id"], "document_id": view["document_id"],
            "document_generation": view["document_generation"], "control_generation": view["control_generation"],
            "sequence": frame["sequence"], "captured_at_ms": frame["captured_at_ms"]}

    def _probe(self, key):
        value = self._call(self._port.operation, key)
        if value is _MISSING or not self._live_return():
            return False
        if value is ABSENT:
            return True
        # A known retained row, including not_applied, makes this run used.
        _acknowledgement(value, self.spec, key)
        raise DriverDenied("original_run_already_used")

    def _prepare_link(self, index, fixture, delivery, destination):
        key = self._ids[index]
        if self._prepared_key != key:
            if self._probe(key):
                self._prepared_key = key
                self._reason = "original_key_absent"
            return
        view = self._read()
        if view is None:
            return
        frame = self._driver_frame(view, fixture, delivery)
        if frame is None:
            return
        if index == 2:
            self._check_correction(view)
            if view["control_generation"] != self._human_generation + 1:
                raise DriverDenied("handback_generation_required")
        if self._clicks >= self.spec.limits.clicks:
            raise DriverDenied("click_budget")
        fields = frame["projection"]["fields"]
        request = {name: view[name] for name in ("session_id", "context_id", "target_id", "control_generation",
                                               "document_id", "document_generation")}
        request.update(operation_id=key, observation_id=frame["observation_id"], action="click",
                       parameters={"x": fields["next_x"], "y": fields["next_y"], "button": "left"})
        quote = self._quote(view)
        if self._fresh_frame(view) is None:
            return  # Include parsing/use time, even when the wall clock freezes.
        self._pending = {"request": request, "index": index, "destination": destination,
                         "sequence": frame["sequence"], "captured_at_ms": frame["captured_at_ms"]}
        self._pending_state = "unconfirmed"
        self._clicks += 1
        # Retain the exact request before submit. The callback gets its own copy.
        self._quotes[("standard_alpha", "standard_beta", "corrected_alpha")[index]] = quote
        self._state, self._reason = "waiting", "original_submitted"
        value = self._call(self._port.submit, request | {"parameters": dict(request["parameters"])})
        if value is not _MISSING:
            self._remember(value)

    def _remember(self, value):
        request = self._pending["request"]
        ack = _acknowledgement(value, self.spec, request["operation_id"], request["control_generation"])
        previous, current = self._pending_state, ack["state"]
        if (previous in {"applied", "not_applied"} and current != previous
                or previous == "unknown" and current in {"queued", "dispatched"}):
            raise DriverDenied("contradictory_original_outcome")
        self._pending_state = current
        if not ack["audit_persisted"]:
            self._deny("original_audit_unavailable")
        elif current == "unknown":
            self._uncertain = True
            if self._state not in {"expired", "refused"}:
                self._state, self._reason = "uncertain", "original_outcome_unknown"
        elif current == "not_applied" and self._live_return():
            self._deny("operation_not_applied")

    def _pending_step(self):
        if self._pending_state != "applied" or self._uncertain:
            value = self._call(self._port.operation, self._pending["request"]["operation_id"])
            if value is _MISSING:
                return
            if value is ABSENT:
                self._deny("submitted_original_absent")
                return
            self._remember(value)
        if not self._live_return() or self._uncertain or self._pending_state != "applied":
            return
        view = self._read()
        if view is None:
            return
        request = self._pending["request"]
        if (view["mode"] != "driver" or view["control_generation"] != request["control_generation"]):
            raise DriverDenied("driver_control_required")
        frame = self._fresh_frame(view)
        if frame is None:
            return
        if view["document_generation"] <= request["document_generation"]:
            self._reason = "new_document_required"
            return
        if (view["document_id"] == request["document_id"] or frame["sequence"] <= self._pending["sequence"]
                or frame["captured_at_ms"] < self._pending["captured_at_ms"]):
            raise DriverDenied("invalid_document_transition")
        fixture = self._pending["destination"]
        self._driver_frame(view, fixture, 8 if fixture == "beta" else 5)
        index = self._pending["index"]
        quote = self._quote(view)
        if self._fresh_frame(view) is None:
            return
        original = {"phase": PHASES[index], "operation_id": request["operation_id"], "state": "applied"}
        if index == 2:
            self._check_correction(view)
            self._quotes["corrected_beta"] = quote
            if not self._finish(view, self._history + [original]):
                return  # Keep this applied original; only a new observation is needed.
        self._history.append(original)
        self._pending, self._pending_state, self._prepared_key = None, None, None
        if index == 0:
            self._quotes["standard_beta"] = quote
            self._phase, self._reason = "return_to_alpha", None
        elif index == 1:
            self._quotes["human_checkpoint"] = quote
            self._phase, self._reason = "await_human", "explicit_human_turn_required"

    def _check_correction(self, view):
        latest = _latest_correction(view, self._human_generation)
        if self._correction is None or latest != self._correction or latest["text"] != CORRECTION:
            raise DriverDenied("observed_correction_required")

    def _human_step(self):
        view = self._read()
        if view is None:
            return
        mode, generation = view["mode"], view["control_generation"]
        if mode == "quiescing":
            self._reason = "explicit_transfer_pending"
            return
        if mode == "human":
            if generation <= self._generation or (self._human_generation is not None and generation != self._human_generation):
                raise DriverDenied("unexpected_human_generation")
            self._human_generation = generation
            latest = _latest_correction(view, generation)
            self._correction = latest if latest is not None and latest["text"] == CORRECTION else None
            self._phase = "await_handback"
            self._reason = "explicit_handback_required" if self._correction else "declared_correction_required"
            return
        if self._human_generation is None:
            # Missing a brief human turn is not evidence that we observed it.
            self._reason = "explicit_human_turn_not_observed"
            return
        if mode != "driver" or generation != self._human_generation + 1:
            raise DriverDenied("handback_generation_required")
        self._check_correction(view)
        self._generation = generation
        frame = self._driver_frame(view, "alpha", 12)
        if frame is None:
            return
        checkpoint = self._quotes["human_checkpoint"]
        if frame["sequence"] <= checkpoint["sequence"] or frame["captured_at_ms"] < checkpoint["captured_at_ms"]:
            raise DriverDenied("post_handback_observation_required")
        self._phase, self._reason = "corrected_link", "fresh_handback_observed"

    def _finish(self, view, originals):
        standard = {name: self._quotes["standard_" + name] for name in ("alpha", "beta")}
        corrected = {name: self._quotes["corrected_" + name] for name in ("alpha", "beta")}
        if (corrected["alpha"]["control_generation"] != self._human_generation + 1
                or corrected["beta"]["control_generation"] != self._human_generation + 1
                or corrected["alpha"]["observation_id"] == corrected["beta"]["observation_id"]
                or corrected["beta"]["document_generation"] <= corrected["alpha"]["document_generation"]):
            raise DriverDenied("post_handback_observation_required")
        for pair in (standard, corrected):
            for quote in pair.values():
                if quote["price"] + quote["delivery"] != quote["total"]:
                    raise DriverDenied("comparison_equation_failed")
            pair["alpha_minus_beta"] = pair["alpha"]["total"] - pair["beta"]["total"]
            pair["lower_total_fixture"] = "beta" if pair["alpha_minus_beta"] > 0 else "alpha"
        self._now()
        result = {"schema_version": 1, "task": "alpha-beta-express-comparison",
            **{name: getattr(self.spec, name) for name in ("session_id", "context_id", "target_id", "backend_epoch", "driver_actor_id")},
            "historical_standard": standard, "after_explicit_handback": corrected,
            "owner_correction": dict(self._correction), "original_operations": originals}
        raw = (canonical(result) + "\n").encode("ascii")
        if len(raw) > self.spec.limits.result_bytes:
            raise DriverDenied("result_budget")
        if self._fresh_frame(view) is None:
            return False
        self._result, self._state, self._phase, self._reason = raw, "completed", "complete", None
        return True

    def step(self):
        if not self._lock.acquire(blocking=False):
            old = self._last_progress
            return DriverProgress(old.state, old.phase, "step_busy", old.steps, old.port_calls, old.clicks,
                                  old.original_operation_id, old.last_known_operation_state, old.result)
        eligible = False
        try:
            if self._state in {"completed", "expired", "refused"}:
                return self._progress()
            try:
                _, mono = self._now()
                if mono < self._next_step:
                    return self._progress("step_too_soon")
                if self._steps >= self.spec.limits.steps:
                    raise DriverDenied("step_budget")
                self._steps += 1
                self._step_calls = 0
                eligible = True
                if self._pending is not None:
                    self._pending_step()
                elif self._phase == "preflight":
                    while self._preflight < 3 and self._step_calls < 2:
                        if not self._probe(self._ids[self._preflight]):
                            break
                        self._preflight += 1
                    if self._preflight == 3 and self._live_return():
                        self._phase = "initial_link"
                elif self._phase == "initial_link":
                    self._prepare_link(0, "alpha", 5, "beta")
                elif self._phase == "return_to_alpha":
                    self._prepare_link(1, "beta", 8, "alpha")
                elif self._phase in {"await_human", "await_handback"}:
                    self._human_step()
                elif self._phase == "corrected_link":
                    self._prepare_link(2, "alpha", 12, "beta")
            except DriverDenied as error:
                self._deny(error.code)
            except Exception:
                self._deny("invalid_projection")
            except BaseException:
                # Cover interruption after callback return and during later
                # decoding/bookkeeping too. Original facts remain, never replay.
                if self._pending is not None:
                    self._uncertain = True
                    self._result = None
                    self._state, self._reason = "uncertain", "step_interrupted"
                else:
                    self._deny("step_interrupted")
                raise
            return self._progress()
        finally:
            if eligible:
                self._next_step = self._last_mono + self.spec.limits.step_interval_ms / 1000
            self._last_progress = self._progress()
            self._lock.release()
