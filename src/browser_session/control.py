"""Standalone execution interlock; no browser launcher, HTTP server or task policy.

The host owns the adapter and drives ``execute_next`` and ``supervise``. Adapter
timeouts preserve the original task, not an invented cancellation result.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
from dataclasses import asdict
import hashlib
import math
import secrets
import threading

from .store import SessionStore
from .types import (ActionTicket, Authorization, FenceReceipt, FenceTicket, KEYS,
                    Observation, OperationOutcome, OUTCOMES, RIGHTS, SessionDenied,
                    SessionSpec, SessionUnavailable, StopReceipt, StopTicket,
                    SystemClock, canonical, identifier, integer, origin, strict_json, text)


_STATE_FIELDS = {"schema_version", "spec", "created_at_ms", "backend_epoch",
    "control_generation", "document_id", "document_generation", "mode", "actor_id",
    "grants", "operations", "queue", "inflight", "semantic_count", "raw_count",
    "events", "corrections", "results"}
_ACTIVE = {"driver", "human"}
_TERMINAL = {"stopped", "lost"}


def _sha256(value):
    if type(value) is not str or len(value) != 64 or any(character not in "0123456789abcdef" for character in value):
        raise SessionDenied("invalid_identity")
    return value


def _parameters(action, parameters, origins, *, width=4096, height=4096):
    """One schema and server-derived charge for admission and retained records."""
    if type(action) is not str or type(parameters) is not dict:
        raise SessionDenied("invalid_action")
    if action == "navigate" and set(parameters) == {"url"}:
        if origin(parameters["url"]) not in origins:
            raise SessionDenied("outside_fixture_origin")
        return "semantic", 1
    if action == "correction" and set(parameters) == {"text"}:
        text(parameters["text"], 2048)
        return "semantic", 1
    if action == "click" and set(parameters) == {"x", "y", "button"}:
        integer(parameters["x"], 0, width - 1)
        integer(parameters["y"], 0, height - 1)
        if type(parameters["button"]) is not str or parameters["button"] not in {"left", "middle", "right"}:
            raise SessionDenied("invalid_action")
        return "raw", 1
    if action == "type" and set(parameters) == {"text"}:
        text(parameters["text"], 1024)
        return "raw", len(parameters["text"])
    if (action == "key" and set(parameters) == {"key"} and type(parameters["key"]) is str
            and parameters["key"] in KEYS):
        return "raw", 1
    raise SessionDenied("invalid_action")


def _action_request(request, spec):
    if (type(request) is not dict or set(request) != {"kind", "operation_id", "actor_id", "session_id",
            "context_id", "target_id", "control_generation", "document_id", "document_generation",
            "observation_id", "action", "parameters"} or request["kind"] != "action"):
        raise SessionDenied("invalid_action")
    for name in ("operation_id", "actor_id", "session_id", "context_id", "target_id", "document_id"):
        identifier(request[name])
    integer(request["control_generation"])
    integer(request["document_generation"])
    _sha256(request["observation_id"])
    if (request["session_id"] != spec.session_id or request["context_id"] != spec.context_id
            or request["target_id"] != spec.target_id
            or request["actor_id"] not in {spec.driver_actor_id, spec.owner_actor_id}):
        raise SessionDenied("input_fenced")
    return _parameters(request["action"], request["parameters"], spec.fixture_origins)


class SessionControl:
    """One locally locked session. Host methods are not browser-facing RPCs."""

    def __init__(self, store, state, adapter, clock):
        self.store, self._state, self.adapter, self.clock = store, state, adapter, clock
        self.spec = SessionSpec.retained(state["spec"])
        self._lock = threading.RLock()
        self._fault = False
        self._teardown_confirmed = False
        self._closed = False
        self._grant_deadlines = {}
        self._tasks = {}
        self._transition_task = None
        self._stop_task = None
        self._frame = None
        self._served = {}
        self._last_sequence = -1
        self._last_frame_mono = float("-inf")
        self._raw_times = []
        self._wall_floor = integer(clock.wall_ms())
        self._mono_floor = clock.monotonic()
        if type(self._mono_floor) not in {int, float} or not math.isfinite(self._mono_floor) or self._mono_floor < 0:
            raise SessionUnavailable()
        self._browser_deadline = self._mono_floor + max(0, self.spec.browser_expires_at_ms - self._wall_floor) / 1000
        self._retention_deadline = self._mono_floor + max(0, self.spec.retention_expires_at_ms - self._wall_floor) / 1000

    @classmethod
    def create(cls, directory, spec, adapter, clock=None):
        clock = clock or SystemClock()
        if type(spec) is not SessionSpec or adapter is None:
            raise SessionDenied("invalid_host_configuration")
        now = integer(clock.wall_ms())
        spec.validate(now)
        store = SessionStore(directory, create=True, maximum=spec.limits.result_bytes)
        state = {"schema_version": 1, "spec": spec.to_dict(), "created_at_ms": now,
            "backend_epoch": secrets.token_hex(16), "control_generation": 0,
            "document_id": spec.document_id, "document_generation": 0,
            "mode": "driver", "actor_id": spec.driver_actor_id, "grants": {},
            "operations": {}, "queue": [], "inflight": None, "semantic_count": 0,
            "raw_count": 0, "events": [], "corrections": [], "results": {}}
        try:
            control = cls(store, state, adapter, clock)
            control._event(state, "created")
            control._save(state)
            return control
        except Exception:
            store.close()
            raise

    @classmethod
    def reopen(cls, directory, clock=None):
        """Recover retained bytes only. A released file lock is not browser death."""
        clock = clock or SystemClock()
        store = SessionStore(directory)
        try:
            state = store.load()
            cls._validate_retained(state)
            control = cls(store, state, None, clock)
            for result in state["results"].values():
                store.read_result(result, control.spec.limits.result_bytes)
            state = deepcopy(state)
            for grant in state["grants"].values():
                grant["revoked"] = True
            for operation in state["operations"].values():
                if operation["state"] == "queued":
                    operation["state"] = "not_applied"
                elif operation["state"] == "dispatched":
                    operation["state"] = "unknown"
            state["queue"] = []
            state["inflight"] = None
            state["control_generation"] += 1
            state["mode"], state["actor_id"] = "lost", None
            # Existing sealed event bytes are immutable. Loss is also visible in
            # the current status, even if the bounded browser history is sealed.
            control._event(state, "ownership_lost", emergency=True)
            control._save(state)
            return control
        except Exception:
            store.close()
            raise SessionUnavailable() from None

    @staticmethod
    def _validate_retained(state):
        try:
            if (type(state) is not dict or set(state) != _STATE_FIELDS
                    or type(state["schema_version"]) is not int or state["schema_version"] != 1):
                raise SessionUnavailable()
            spec = SessionSpec.retained(state["spec"])
            spec.validate(integer(state["created_at_ms"]))
            identifier(state["backend_epoch"])
            identifier(state["document_id"])
            integer(state["control_generation"])
            integer(state["document_generation"])
            integer(state["semantic_count"], 0, spec.limits.semantic_actions)
            integer(state["raw_count"], 0, spec.limits.raw_inputs)
            if state["mode"] not in _ACTIVE | _TERMINAL | {"quiescing", "stopping", "fenced"}:
                raise SessionUnavailable()
            expected_actor = {"driver": spec.driver_actor_id, "human": spec.owner_actor_id}.get(state["mode"])
            if state["actor_id"] != expected_actor:
                raise SessionUnavailable()
            for name, maximum in (("operations", spec.limits.operations), ("grants", spec.limits.grants),
                                  ("results", 16)):
                if type(state[name]) is not dict or len(state[name]) > maximum:
                    raise SessionUnavailable()
            if not set(state["results"]) <= {"result.json", "screenshot.jpg", "events.json"}:
                raise SessionUnavailable()
            for name, maximum in (("events", spec.limits.events), ("queue", spec.limits.queue),
                                  ("corrections", spec.limits.semantic_actions)):
                if type(state[name]) is not list or len(state[name]) > maximum:
                    raise SessionUnavailable()
            for digest, grant in state["grants"].items():
                _sha256(digest)
                if (type(grant) is not dict or set(grant) != {"actor_id", "rights", "revoked"}
                        or type(grant["revoked"]) is not bool or type(grant["rights"]) is not dict
                        or not grant["rights"] or not set(grant["rights"]) <= RIGHTS):
                    raise SessionUnavailable()
                identifier(grant["actor_id"])
                if (("stop" in grant["rights"] and grant["actor_id"] != spec.owner_actor_id)
                        or ("control" in grant["rights"] and grant["actor_id"] not in {spec.owner_actor_id, spec.driver_actor_id})):
                    raise SessionUnavailable()
                for right, expiry in grant["rights"].items():
                    integer(expiry, state["created_at_ms"] + 1,
                            spec.browser_expires_at_ms if right == "control" else spec.retention_expires_at_ms)
            counts = {"semantic": 0, "raw": 0}
            for key, operation in state["operations"].items():
                identifier(key)
                if (type(operation) is not dict
                        or set(operation) != {"request", "state", "generation", "ticket", "audit_persisted"}
                        or type(operation["request"]) is not dict
                        or operation["request"].get("operation_id") != key
                        or operation["request"].get("kind") not in {"action", "takeover", "handback", "stop"}
                        or operation["state"] not in {"queued", "dispatched", "applied", "not_applied",
                            "unknown", "confirmed", "pending", "failed"}
                        or type(operation["audit_persisted"]) is not bool):
                    raise SessionUnavailable()
                integer(operation["generation"], 0, state["control_generation"])
                request, ticket = operation["request"], operation["ticket"]
                kind = request["kind"]
                if kind == "action":
                    budget, amount = _action_request(request, spec)
                    counts[budget] += amount
                    if (operation["generation"] != request["control_generation"]
                            or operation["state"] not in {"queued", "dispatched", "applied", "not_applied", "unknown"}
                            or type(ticket) is not dict or set(ticket) != set(ActionTicket.__dataclass_fields__) | {"grant_digest"}
                            or type(ticket["deadline_monotonic"]) is not float
                            or not math.isfinite(ticket["deadline_monotonic"]) or ticket["deadline_monotonic"] < 0
                            or (request["action"] == "correction" and request["actor_id"] != spec.owner_actor_id)):
                        raise SessionUnavailable()
                    expected = {name: request[name] for name in ("session_id", "context_id", "target_id", "operation_id",
                        "actor_id", "control_generation", "document_id", "document_generation", "action")}
                    expected.update(backend_epoch=state["backend_epoch"], parameters_json=canonical(request["parameters"]))
                    if any(type(ticket[name]) is not type(value) or ticket[name] != value for name, value in expected.items()):
                        raise SessionUnavailable()
                    integer(request["document_generation"], 0, state["document_generation"])
                    required_right = "control"
                elif kind in {"takeover", "handback"}:
                    if (set(request) != {"kind", "operation_id", "actor_id", "control_generation", "observation_id"}
                            or request["actor_id"] != spec.owner_actor_id
                            or type(ticket) is not dict or set(ticket) != {"grant_digest"}
                            or operation["state"] not in {"dispatched", "applied", "unknown"}):
                        raise SessionUnavailable()
                    integer(request["control_generation"])
                    if operation["generation"] != request["control_generation"] + 1:
                        raise SessionUnavailable()
                    if kind == "handback":
                        _sha256(request["observation_id"])
                    elif request["observation_id"] is not None:
                        raise SessionUnavailable()
                    required_right = "control"
                else:
                    if (set(request) != {"kind", "operation_id", "actor_id"} or request["actor_id"] != spec.owner_actor_id
                            or type(ticket) is not dict or set(ticket) != {"grant_digest"}
                            or operation["state"] not in {"dispatched", "confirmed", "pending", "failed", "unknown"}):
                        raise SessionUnavailable()
                    required_right = "stop"
                if key.startswith("host."):
                    if kind != "stop" or key != "host.browser-lifetime-expired" or ticket["grant_digest"] is not None:
                        raise SessionUnavailable()
                else:
                    digest = _sha256(ticket["grant_digest"])
                    grant = state["grants"].get(digest)
                    if grant is not None and (grant["actor_id"] != request["actor_id"] or required_right not in grant["rights"]):
                        raise SessionUnavailable()
            if counts != {"semantic": state["semantic_count"], "raw": state["raw_count"]}:
                raise SessionUnavailable()
            if (len(set(state["queue"])) != len(state["queue"])
                    or any(key not in state["operations"] or state["operations"][key]["state"] != "queued"
                           for key in state["queue"])
                    or set(state["queue"]) != {key for key, value in state["operations"].items() if value["state"] == "queued"}
                    or (state["inflight"] is not None and (state["inflight"] not in state["operations"]
                        or state["operations"][state["inflight"]]["request"]["kind"] != "action"
                        or state["operations"][state["inflight"]]["state"] == "queued"))):
                raise SessionUnavailable()
            for index, event in enumerate(state["events"]):
                if (type(event) is not dict or set(event) != {"sequence", "at_ms", "type", "operation_id", "actor_id"}
                        or type(event["sequence"]) is not int or event["sequence"] != index):
                    raise SessionUnavailable()
                integer(event["at_ms"])
                identifier(event["type"])
                if event["operation_id"] is not None:
                    identifier(event["operation_id"])
                    if event["operation_id"] not in state["operations"]:
                        raise SessionUnavailable()
                if event["actor_id"] is not None:
                    identifier(event["actor_id"])
                    if event["actor_id"] not in {spec.owner_actor_id, spec.driver_actor_id}:
                        raise SessionUnavailable()
            for correction in state["corrections"]:
                if (type(correction) is not dict or set(correction) != {"operation_id", "actor_id", "text", "generation"}
                        or correction["actor_id"] != spec.owner_actor_id
                        or correction["operation_id"] not in state["operations"]):
                    raise SessionUnavailable()
                text(correction["text"], 2048)
                integer(correction["generation"])
                operation = state["operations"][correction["operation_id"]]
                if (operation["request"].get("action") != "correction" or operation["state"] != "applied"
                        or operation["generation"] != correction["generation"]
                        or operation["request"]["parameters"]["text"] != correction["text"]):
                    raise SessionUnavailable()
        except (ValueError, TypeError, KeyError, AttributeError, OverflowError):
            raise SessionUnavailable() from None

    def _event(self, state, kind, operation_id=None, actor_id=None, *, emergency=False):
        if "events.json" in state["results"]:
            return
        maximum = self.spec.limits.events
        if len(state["events"]) >= maximum - (0 if emergency else 8):
            if emergency:
                return
            raise SessionDenied("event_budget_exhausted")
        state["events"].append({"sequence": len(state["events"]), "at_ms": integer(self.clock.wall_ms()),
            "type": kind, "operation_id": operation_id, "actor_id": actor_id})

    def _save(self, state):
        try:
            self.store.save(state)
        except SessionUnavailable:
            self._state = state
            self._fault = True
            self._state["mode"], self._state["actor_id"] = ("stopped" if self._teardown_confirmed else "fenced"), None
            self._state["control_generation"] += 1
            raise
        self._state = state

    def _clock(self, *, stop=False):
        now, mono = integer(self.clock.wall_ms()), self.clock.monotonic()
        if type(mono) not in {int, float} or not math.isfinite(mono) or mono < self._mono_floor:
            raise SessionDenied("clock_unavailable")
        if now < self._wall_floor and not stop:
            raise SessionDenied("clock_rollback")
        self._wall_floor, self._mono_floor = max(now, self._wall_floor), mono
        return max(now, self._wall_floor), mono

    def _live(self):
        if self._closed or self._fault:
            raise SessionUnavailable()
        now, mono = self._clock()
        if (self.adapter is None or self._state["mode"] in _TERMINAL
                or now >= self.spec.browser_expires_at_ms or mono >= self._browser_deadline):
            raise SessionDenied("browser_unavailable")
        return now, mono

    @staticmethod
    def _digest(token):
        if type(token) is not str or not 32 <= len(token) <= 128 or not token.isascii():
            raise SessionDenied("unauthorized")
        return hashlib.sha256(token.encode()).hexdigest()

    def issue_grant(self, actor_id, rights):
        """Trusted host only. Pairing can bind a grant but cannot call this."""
        with self._lock:
            if self._closed or self._fault:
                raise SessionUnavailable()
            now, mono = self._clock()
            identifier(actor_id)
            if type(rights) is not dict or not rights or not set(rights) <= RIGHTS:
                raise SessionDenied("invalid_rights")
            if self._state["mode"] in _TERMINAL and set(rights) != {"observe"}:
                raise SessionDenied("retained_read_only")
            if "stop" in rights and actor_id != self.spec.owner_actor_id:
                raise SessionDenied("owner_stop_only")
            if "control" in rights and actor_id not in {self.spec.owner_actor_id, self.spec.driver_actor_id}:
                raise SessionDenied("unknown_controller")
            for right, expiry in rights.items():
                maximum = self.spec.browser_expires_at_ms if right == "control" else self.spec.retention_expires_at_ms
                integer(expiry, now + 1, maximum)
            state = deepcopy(self._state)
            state["grants"] = {key: grant for key, grant in state["grants"].items()
                if not grant["revoked"] and any(now < expiry for expiry in grant["rights"].values())}
            if len(state["grants"]) >= self.spec.limits.grants:
                raise SessionDenied("grant_budget_exhausted")
            for _ in range(3):
                token = secrets.token_urlsafe(32)
                digest = self._digest(token)
                if digest not in state["grants"] and not any(
                    value["ticket"] is not None and value["ticket"].get("grant_digest") == digest
                    for value in state["operations"].values()):
                    break
            else:
                raise SessionDenied("entropy_unavailable")
            state["grants"][digest] = {"actor_id": actor_id, "rights": dict(rights), "revoked": False}
            self._save(state)
            self._grant_deadlines = {key: value for key, value in self._grant_deadlines.items() if key in state["grants"]}
            self._grant_deadlines[digest] = {right: mono + (expiry - now) / 1000 for right, expiry in rights.items()}
            return token

    def _authorized(self, digest, right):
        if type(right) is not str or right not in RIGHTS or self._closed:
            raise SessionDenied("unauthorized")
        now, mono = self._clock(stop=right == "stop")
        grant = self._state["grants"].get(digest)
        deadline = self._grant_deadlines.get(digest, {}).get(right)
        if (grant is None or grant["revoked"] or deadline is None or right not in grant["rights"]
                or now >= grant["rights"][right] or mono >= deadline
                or now >= self.spec.retention_expires_at_ms or mono >= self._retention_deadline
                or (self._state["mode"] == "lost" and right != "observe")
                or (self._state["mode"] == "stopped" and right == "control")):
            raise SessionDenied("unauthorized")
        if self._fault and right != "stop":
            raise SessionUnavailable()
        return Authorization(grant["actor_id"], self.spec.session_id, self.spec.context_id,
                             self.spec.target_id, right, grant["rights"][right])

    def authorize(self, token, right):
        with self._lock:
            return self._authorized(self._digest(token), right)

    def revoke(self, token):
        with self._lock:
            if self._fault or self._closed:
                raise SessionUnavailable()
            state = deepcopy(self._state)
            grant = state["grants"].get(self._digest(token))
            if grant is not None:
                grant["revoked"] = True
                self._save(state)

    def identity(self):
        """Trusted adapter metadata. This grants no browser admission."""
        with self._lock:
            return {"session_id": self.spec.session_id, "context_id": self.spec.context_id,
                "target_id": self.spec.target_id, "backend_epoch": self._state["backend_epoch"],
                "control_generation": self._state["control_generation"],
                "document_id": self._state["document_id"], "document_generation": self._state["document_generation"]}

    def _validated_frame(self, observation, *, generation=None, throttle=True):
        if type(observation) is not Observation:
            raise SessionDenied("invalid_observation")
        now, mono = self._clock()
        generation = self._state["control_generation"] if generation is None else generation
        integer(observation.control_generation)
        if (type(observation.session_id) is not str or type(observation.context_id) is not str
                or type(observation.target_id) is not str or type(observation.backend_epoch) is not str
                or observation.session_id != self.spec.session_id or observation.context_id != self.spec.context_id
                or observation.target_id != self.spec.target_id or observation.backend_epoch != self._state["backend_epoch"]
                or observation.control_generation != generation):
            raise SessionDenied("stale_observation")
        identifier(observation.document_id)
        integer(observation.sequence, self._last_sequence + 1)
        integer(observation.captured_at_ms, max(0, now - self.spec.limits.frame_age_ms), now)
        integer(observation.width, 1, 4096)
        integer(observation.height, 1, 4096)
        if (type(observation.jpeg) is not bytes or not 4 <= len(observation.jpeg) <= self.spec.limits.frame_bytes
                or not observation.jpeg.startswith(b"\xff\xd8") or not observation.jpeg.endswith(b"\xff\xd9")):
            raise SessionDenied("invalid_frame")
        text(observation.projection_json, 16384)
        projection = strict_json(observation.projection_json)
        if type(projection) is not dict or set(projection) != {"url", "title", "fields"}:
            raise SessionDenied("invalid_projection")
        if origin(projection["url"]) not in self.spec.fixture_origins:
            raise SessionDenied("outside_fixture_origin")
        text(projection["title"], 1024, empty=True)
        if type(projection["fields"]) is not dict or not set(projection["fields"]) <= set(self.spec.observation_fields):
            raise SessionDenied("invalid_projection")
        for value in projection["fields"].values():
            if value is not None and type(value) not in {str, bool, int}:
                raise SessionDenied("invalid_projection")
            if type(value) is str:
                text(value, 2048, empty=True)
            if type(value) is int:
                integer(value, -(2**53 - 1))
        if throttle and mono - self._last_frame_mono < self.spec.limits.frame_interval_ms / 1000:
            raise SessionDenied("frame_rate_exceeded")
        metadata = asdict(observation)
        metadata.pop("jpeg")
        metadata["projection"] = projection
        metadata.pop("projection_json")
        metadata["jpeg_sha256"] = hashlib.sha256(observation.jpeg).hexdigest()
        metadata["observation_id"] = hashlib.sha256(canonical(metadata).encode()).hexdigest()
        return metadata, mono

    def _install_frame(self, observation, metadata, mono):
        self._last_sequence = observation.sequence
        self._last_frame_mono = mono
        self._frame = (metadata, observation.jpeg)
        self._served.clear()

    def publish_observation(self, observation):
        """Trusted adapter push. Exactly one latest frame, with no observer queues."""
        with self._lock:
            self._live()
            if self._state["mode"] not in _ACTIVE:
                raise SessionDenied("input_fenced")
            metadata, mono = self._validated_frame(observation)
            if observation.document_id != self._state["document_id"]:
                state = deepcopy(self._state)
                state["document_id"] = observation.document_id
                state["document_generation"] += 1
                self._save(state)
            self._install_frame(observation, metadata, mono)

    def observe(self, token):
        with self._lock:
            auth = self.authorize(token, "observe")
            frame = None
            if (self._frame is not None and self._state["mode"] not in _TERMINAL
                    and self._frame[0]["control_generation"] == self._state["control_generation"]):
                now, mono = self._clock()
                if (now - self._frame[0]["captured_at_ms"] <= self.spec.limits.frame_age_ms
                        and mono - self._last_frame_mono <= self.spec.limits.frame_age_ms / 1000):
                    frame = deepcopy(self._frame[0]) | {"jpeg": self._frame[1]}
                    self._served[auth.actor_id] = frame["observation_id"]
            return self.identity() | {"mode": self._state["mode"], "actor_id": self._state["actor_id"],
                "frame": frame, "corrections": deepcopy(self._state["corrections"]),
                "audit_available": not self._fault, "results": deepcopy(self._state["results"])}

    def _fresh(self, actor, observation_id):
        if (self._frame is None or self._served.get(actor) != observation_id
                or self._frame[0]["observation_id"] != observation_id
                or self._frame[0]["control_generation"] != self._state["control_generation"]
                or self._frame[0]["document_id"] != self._state["document_id"]):
            raise SessionDenied("fresh_observation_required")
        now, mono = self._clock()
        if (now - self._frame[0]["captured_at_ms"] > self.spec.limits.frame_age_ms
                or mono - self._last_frame_mono > self.spec.limits.frame_age_ms / 1000):
            raise SessionDenied("stale_observation")

    def _original(self, operation_id, request):
        identifier(operation_id)
        if operation_id.startswith("host."):
            raise SessionDenied("reserved_operation_identity")
        original = self._state["operations"].get(operation_id)
        if original is not None:
            if original["request"] != request:
                raise SessionDenied("operation_conflict")
            return deepcopy(original)
        if len(self._state["operations"]) >= self.spec.limits.operations - 2:
            raise SessionDenied("operation_budget_exhausted")
        return None

    def submit(self, token, *, operation_id, session_id, context_id, target_id,
               control_generation, document_id, document_generation, observation_id,
               action, parameters):
        with self._lock:
            auth = self.authorize(token, "control")
            # Validate exact types before comparing with an original request;
            # Python's bool/int and float/int equality is not contract equality.
            _parameters(action, parameters, self.spec.fixture_origins)
            request = {"kind": "action", "operation_id": operation_id, "actor_id": auth.actor_id,
                "session_id": session_id, "context_id": context_id, "target_id": target_id,
                "control_generation": control_generation, "document_id": document_id,
                "document_generation": document_generation, "observation_id": observation_id,
                "action": action, "parameters": deepcopy(parameters)}
            _action_request(request, self.spec)
            original = self._original(operation_id, request)
            if original is not None:
                return original
            _, mono = self._live()
            if (self._state["mode"] not in _ACTIVE or auth.actor_id != self._state["actor_id"]
                    or session_id != self.spec.session_id or context_id != self.spec.context_id
                    or target_id != self.spec.target_id or control_generation != self._state["control_generation"]
                    or document_id != self._state["document_id"] or document_generation != self._state["document_generation"]):
                raise SessionDenied("input_fenced")
            integer(control_generation)
            integer(document_generation)
            self._fresh(auth.actor_id, observation_id)
            budget, amount = _parameters(action, parameters, self.spec.fixture_origins,
                                         width=self._frame[0]["width"], height=self._frame[0]["height"])
            if action == "correction" and self._state["mode"] != "human":
                raise SessionDenied("human_correction_only")
            if len(self._state["queue"]) >= self.spec.limits.queue:
                raise SessionDenied("queue_full")
            self._raw_times = [stamp for stamp in self._raw_times if mono - stamp < 1]
            if (self._state[budget + "_count"] + amount > getattr(self.spec.limits, budget + ("_actions" if budget == "semantic" else "_inputs"))
                    or (budget == "raw" and len(self._raw_times) + amount > self.spec.limits.raw_inputs_per_second)):
                raise SessionDenied("action_budget_exhausted")
            state = deepcopy(self._state)
            state[budget + "_count"] += amount
            digest = self._digest(token)
            deadline = min(mono + self.spec.limits.action_timeout_ms / 1000,
                self._grant_deadlines[digest]["control"], self._browser_deadline,
                self._last_frame_mono + self.spec.limits.frame_age_ms / 1000,
                mono + (self._frame[0]["captured_at_ms"] + self.spec.limits.frame_age_ms - self.clock.wall_ms()) / 1000)
            ticket = asdict(ActionTicket(session_id, context_id, target_id, state["backend_epoch"],
                operation_id, auth.actor_id, control_generation, document_id, document_generation,
                action, canonical(parameters), deadline))
            # The digest is an authorization reference, never the bearer secret.
            ticket["grant_digest"] = digest
            state["operations"][operation_id] = {"request": request, "state": "queued",
                "generation": control_generation, "ticket": ticket, "audit_persisted": True}
            state["queue"].append(operation_id)
            self._event(state, "queued", operation_id, auth.actor_id)
            self._save(state)
            if budget == "raw":
                self._raw_times.extend([mono] * amount)
            return deepcopy(state["operations"][operation_id])

    @staticmethod
    def _ticket(record):
        return ActionTicket(**{key: value for key, value in record["ticket"].items() if key != "grant_digest"})

    @staticmethod
    def _outcome_matches(ticket, outcome):
        return (type(outcome) is OperationOutcome and type(outcome.operation_id) is str
            and type(outcome.backend_epoch) is str and type(outcome.control_generation) is int
            and type(outcome.document_generation) is int and type(outcome.state) is str
            and outcome.operation_id == ticket.operation_id and outcome.backend_epoch == ticket.backend_epoch
            and outcome.control_generation == ticket.control_generation
            and outcome.document_generation == ticket.document_generation and outcome.state in OUTCOMES)

    def _action_ready(self, ticket, record):
        _, mono = self._live()
        auth = self._authorized(record["ticket"]["grant_digest"], "control")
        self._fresh(auth.actor_id, record["request"]["observation_id"])
        if (self._state["mode"] not in _ACTIVE or auth.actor_id != self._state["actor_id"]
                or ticket.control_generation != self._state["control_generation"]
                or ticket.document_generation != self._state["document_generation"]
                or ticket.document_id != self._state["document_id"] or mono >= ticket.deadline_monotonic):
            raise SessionDenied("input_fenced")

    async def _invoke_action(self, ticket):
        with self._lock:
            record = self._state["operations"][ticket.operation_id]
            try:
                self._action_ready(ticket, record)
                if record["state"] != "dispatched" or self._state["inflight"] != ticket.operation_id:
                    raise SessionDenied("input_fenced")
            except (SessionDenied, SessionUnavailable):
                # This wrapper has not invoked the adapter. Original intent
                # can be retired without claiming cancellation of native work.
                return OperationOutcome(ticket.operation_id, ticket.backend_epoch, ticket.control_generation,
                                        ticket.document_generation, "not_applied")
            # No await separates the final authorization from invocation. The
            # adapter must enforce this original deadline across its own awaits.
            pending = self.adapter.execute(ticket)
        return await pending

    @staticmethod
    def _scheduled(coroutine):
        try:
            return asyncio.create_task(coroutine)
        except Exception:
            # This is our own not-yet-started wrapper, not an adapter task whose
            # cancellation could be confused with quiescence.
            coroutine.close()
            return None

    async def execute_next(self):
        with self._lock:
            _, mono = self._live()
            if self._state["mode"] not in _ACTIVE or self._state["inflight"] is not None:
                raise SessionDenied("input_fenced")
            if not self._state["queue"]:
                return None
            state = deepcopy(self._state)
            key = state["queue"].pop(0)
            record = state["operations"][key]
            ticket = self._ticket(record)
            try:
                self._action_ready(ticket, record)
            except SessionDenied:
                record["state"] = "not_applied"
                self._event(state, "not_applied", key, ticket.actor_id)
                self._save(state)
                return deepcopy(record)
            if ticket.action == "correction":
                record["state"] = "applied"
                state["corrections"].append({"operation_id": key, "actor_id": ticket.actor_id,
                    "text": strict_json(ticket.parameters_json)["text"], "generation": ticket.control_generation})
                self._event(state, "correction", key, ticket.actor_id)
                self._save(state)
                return deepcopy(record)
            record["state"] = "dispatched"
            state["inflight"] = key
            self._event(state, "dispatched", key, ticket.actor_id)
            self._save(state)
            task = self._scheduled(self._invoke_action(ticket))
            if task is None:
                self._finish_action(ticket, None)
                return deepcopy(self._state["operations"][key])
            self._tasks[key] = task
            task.add_done_callback(lambda done: self._action_done(ticket, done))
        try:
            done, _ = await asyncio.wait({task}, timeout=max(0, ticket.deadline_monotonic - self.clock.monotonic()))
            if not done:
                self._finish_action(ticket, None)
        except asyncio.CancelledError:
            self._finish_action(ticket, None)
            raise
        with self._lock:
            return deepcopy(self._state["operations"][key])

    def _action_done(self, ticket, task):
        try:
            outcome = task.result()
        except BaseException:
            outcome = None
        self._finish_action(ticket, outcome)

    def _finish_action(self, ticket, outcome):
        with self._lock:
            if self._closed or self._state["mode"] in _TERMINAL:
                return
            state = deepcopy(self._state)
            record = state["operations"][ticket.operation_id]
            if record["state"] not in {"dispatched", "unknown"}:
                return
            result = outcome.state if self._outcome_matches(ticket, outcome) else "unknown"
            if record["state"] == result:
                return
            record["state"] = result
            if result != "unknown" and state["inflight"] == ticket.operation_id:
                state["inflight"] = None
            expired = self.clock.monotonic() >= ticket.deadline_monotonic
            if ((result == "unknown" or expired) and state["mode"] in _ACTIVE
                    and state["control_generation"] == ticket.control_generation):
                state["control_generation"] += 1
                state["mode"], state["actor_id"] = "fenced", None
            self._event(state, result, ticket.operation_id, ticket.actor_id, emergency=True)
            try:
                self._save(state)
            except SessionUnavailable:
                record["audit_persisted"] = False

    def operation(self, token, operation_id):
        with self._lock:
            self.authorize(token, "observe")
            identifier(operation_id)
            record = self._state["operations"].get(operation_id)
            if record is None:
                raise SessionDenied("operation_absent")
            result = deepcopy(record)
            # Adapter deadlines and grant references are private interlock data.
            result.pop("ticket")
            return result

    async def takeover(self, token, operation_id, *, control_generation):
        return await self._transfer(token, operation_id, control_generation, "takeover", None)

    async def handback(self, token, operation_id, *, control_generation, observation_id):
        return await self._transfer(token, operation_id, control_generation, "handback", observation_id)

    async def _transfer(self, token, operation_id, generation, kind, observation_id):
        with self._lock:
            auth = self.authorize(token, "control")
            integer(generation)
            if kind == "handback":
                _sha256(observation_id)
            request = {"kind": kind, "operation_id": operation_id, "actor_id": auth.actor_id,
                       "control_generation": generation, "observation_id": observation_id}
            original = self._original(operation_id, request)
            if original is not None:
                return original
            _, mono = self._live()
            if (auth.actor_id != self.spec.owner_actor_id or generation != self._state["control_generation"]
                    or self._state["mode"] == "stopping"
                    or (self._transition_task is not None and not self._transition_task.done())):
                raise SessionDenied("input_fenced")
            if kind == "handback":
                if self._state["mode"] != "human":
                    raise SessionDenied("human_control_required")
                self._fresh(auth.actor_id, observation_id)
            elif self._state["mode"] == "human":
                raise SessionDenied("already_human")
            state = deepcopy(self._state)
            state["control_generation"] += 1
            state["mode"], state["actor_id"] = "quiescing", None
            self._cancel_queue(state)
            inflight = () if state["inflight"] is None else (self._ticket(state["operations"][state["inflight"]]),)
            ticket = FenceTicket(self.spec.session_id, self.spec.context_id, self.spec.target_id,
                state["backend_epoch"], operation_id, state["control_generation"], inflight,
                min(mono + self.spec.limits.fence_timeout_ms / 1000,
                    self._grant_deadlines[self._digest(token)]["control"], self._browser_deadline))
            state["operations"][operation_id] = {"request": request, "state": "dispatched",
                "generation": state["control_generation"], "ticket": {"grant_digest": self._digest(token)}, "audit_persisted": True}
            self._event(state, "quiescing", operation_id, auth.actor_id)
            self._save(state)
            self._frame, self._served = None, {}
            task = self._scheduled(self._invoke_fence(ticket))
            if task is None:
                return self._complete_transfer(ticket, kind, None)
            self._transition_task = task
        try:
            done, _ = await asyncio.wait({task}, timeout=max(0, ticket.deadline_monotonic - self.clock.monotonic()))
            receipt = task.result() if done else None
        except asyncio.CancelledError:
            self._complete_transfer(ticket, kind, None)
            task.add_done_callback(lambda done: self._late_fence(ticket, done))
            raise
        except Exception:
            receipt = None
        result = self._complete_transfer(ticket, kind, receipt)
        if not task.done():
            task.add_done_callback(lambda done: self._late_fence(ticket, done))
        return result

    async def _invoke_fence(self, ticket):
        with self._lock:
            self._live()
            record = self._state["operations"][ticket.operation_id]
            self._authorized(record["ticket"]["grant_digest"], "control")
            if (self._state["mode"] != "quiescing" or self._state["control_generation"] != ticket.control_generation
                    or self.clock.monotonic() >= ticket.deadline_monotonic):
                return None
            pending = self.adapter.quiesce(ticket)
        return await pending

    def _late_fence(self, ticket, task):
        # Late evidence may improve original operations, never complete transfer.
        try:
            receipt = task.result()
        except BaseException:
            return
        if self._fence_matches(ticket, receipt):
            for original, outcome in zip(ticket.inflight, receipt.outcomes):
                self._finish_action(original, outcome)

    def _fence_matches(self, ticket, receipt):
        return (type(receipt) is FenceReceipt and type(receipt.session_id) is str
            and type(receipt.backend_epoch) is str and type(receipt.operation_id) is str
            and type(receipt.control_generation) is int and receipt.session_id == ticket.session_id
            and receipt.backend_epoch == ticket.backend_epoch and receipt.operation_id == ticket.operation_id
            and receipt.control_generation == ticket.control_generation and type(receipt.quiescent) is bool
            and type(receipt.outcomes) is tuple and len(receipt.outcomes) == len(ticket.inflight)
            and all(self._outcome_matches(original, outcome) for original, outcome in zip(ticket.inflight, receipt.outcomes)))

    def _complete_transfer(self, ticket, kind, receipt):
        with self._lock:
            record = self._state["operations"][ticket.operation_id]
            if (self._closed or self._fault or self._state["mode"] != "quiescing"
                    or self._state["control_generation"] != ticket.control_generation):
                return deepcopy(record)
            state = deepcopy(self._state)
            record = state["operations"][ticket.operation_id]
            valid = self._fence_matches(ticket, receipt)
            if valid and any(state["operations"][original.operation_id]["state"] not in
                    {"dispatched", "unknown", outcome.state} for original, outcome in zip(ticket.inflight, receipt.outcomes)):
                valid = False
            if valid:
                for original, outcome in zip(ticket.inflight, receipt.outcomes):
                    state["operations"][original.operation_id]["state"] = outcome.state
            confirmed = valid and receipt.quiescent and all(value.state != "unknown" for value in receipt.outcomes)
            metadata = None
            if confirmed:
                try:
                    self._live()
                    self._authorized(record["ticket"]["grant_digest"], "control")
                    metadata, mono = self._validated_frame(receipt.observation, throttle=False)
                    if self.clock.monotonic() > ticket.deadline_monotonic:
                        raise SessionDenied("late_quiescence")
                except SessionDenied:
                    confirmed = False
            if confirmed:
                state["mode"] = "human" if kind == "takeover" else "driver"
                state["actor_id"] = self.spec.owner_actor_id if kind == "takeover" else self.spec.driver_actor_id
                state["inflight"] = None
                if receipt.observation.document_id != state["document_id"]:
                    state["document_id"] = receipt.observation.document_id
                    state["document_generation"] += 1
                record["state"] = "applied"
                self._event(state, state["mode"], ticket.operation_id, state["actor_id"])
            else:
                state["mode"], state["actor_id"] = "fenced", None
                record["state"] = "unknown"
                self._event(state, "unknown", ticket.operation_id, emergency=True)
            self._save(state)
            if confirmed:
                self._install_frame(receipt.observation, metadata, mono)
            return deepcopy(record)

    @staticmethod
    def _cancel_queue(state):
        for key in state["queue"]:
            state["operations"][key]["state"] = "not_applied"
        state["queue"] = []

    async def stop(self, token, operation_id):
        with self._lock:
            auth = self.authorize(token, "stop")
            return_request = {"kind": "stop", "operation_id": identifier(operation_id), "actor_id": auth.actor_id}
            if operation_id.startswith("host."):
                raise SessionDenied("reserved_operation_identity")
        return await self._stop_owned(return_request, grant_digest=self._digest(token))

    async def _stop_owned(self, request, *, grant_digest=None):
        with self._lock:
            key = request["operation_id"]
            original = self._state["operations"].get(key)
            if original is not None:
                if original["request"] != request:
                    raise SessionDenied("operation_conflict")
                return deepcopy(original)
            if (self._closed or self.adapter is None or self._teardown_confirmed or self._state["mode"] in _TERMINAL
                    or (self._stop_task is not None and not self._stop_task.done())):
                raise SessionDenied("stop_unavailable")
            if len(self._state["operations"]) >= self.spec.limits.operations:
                raise SessionDenied("operation_budget_exhausted")
            _, mono = self._clock(stop=True)
            state = deepcopy(self._state)
            state["control_generation"] += 1
            state["mode"], state["actor_id"] = "stopping", None
            self._cancel_queue(state)
            ticket = StopTicket(self.spec.session_id, self.spec.context_id, self.spec.target_id,
                state["backend_epoch"], key, state["control_generation"],
                min(mono + self.spec.limits.stop_timeout_ms / 1000,
                    self._grant_deadlines[grant_digest]["stop"] if grant_digest else float("inf")))
            state["operations"][key] = {"request": request, "state": "dispatched",
                "generation": state["control_generation"], "ticket": {"grant_digest": grant_digest}, "audit_persisted": True}
            self._event(state, "stop_requested", key, request["actor_id"], emergency=True)
            try:
                self._save(state)
            except SessionUnavailable:
                # Custody survives a failed audit write. This is the one action
                # allowed from cached owner authority, without claiming durability.
                state["operations"][key]["audit_persisted"] = False
            self._frame, self._served = None, {}
            task = self._scheduled(self._invoke_stop(ticket))
            if task is None:
                self._finish_stop(ticket, None)
                return deepcopy(self._state["operations"][key])
            self._stop_task = task
            task.add_done_callback(lambda done: self._stop_done(ticket, done))
        try:
            done, _ = await asyncio.wait({task}, timeout=max(0, ticket.deadline_monotonic - self.clock.monotonic()))
            if not done:
                self._finish_stop(ticket, None)
        except asyncio.CancelledError:
            self._finish_stop(ticket, None)
            raise
        with self._lock:
            return deepcopy(self._state["operations"][key])

    async def _invoke_stop(self, ticket):
        with self._lock:
            if self._closed or self.clock.monotonic() >= ticket.deadline_monotonic:
                return None
            digest = self._state["operations"][ticket.operation_id]["ticket"]["grant_digest"]
            if digest is not None:
                self._authorized(digest, "stop")
            pending = self.adapter.stop(ticket)
        return await pending

    def _stop_done(self, ticket, task):
        try:
            receipt = task.result()
        except BaseException:
            receipt = None
        self._finish_stop(ticket, receipt)

    def _finish_stop(self, ticket, receipt):
        with self._lock:
            if self._closed:
                return
            state = deepcopy(self._state)
            record = state["operations"][ticket.operation_id]
            if record["state"] == "confirmed" or self._teardown_confirmed:
                return
            valid = (type(receipt) is StopReceipt and type(receipt.session_id) is str
                and type(receipt.backend_epoch) is str and type(receipt.operation_id) is str
                and type(receipt.control_generation) is int and type(receipt.state) is str
                and receipt.session_id == ticket.session_id
                and receipt.backend_epoch == ticket.backend_epoch and receipt.operation_id == ticket.operation_id
                and receipt.control_generation == ticket.control_generation
                and receipt.state in {"confirmed", "pending", "failed", "unknown"})
            result = receipt.state if valid else "unknown"
            if result == "confirmed":
                self._teardown_confirmed = True
            record["state"] = result
            if result == "confirmed" or state["control_generation"] == ticket.control_generation:
                state["mode"], state["actor_id"] = ("stopped" if result == "confirmed" else "fenced"), None
            self._event(state, "stop_" + result, ticket.operation_id, emergency=True)
            try:
                self._save(state)
                if result == "confirmed":
                    self._seal_events()
            except SessionUnavailable:
                record["audit_persisted"] = False

    def retain_result(self, name, content):
        """Trusted host capture, never a Stop or browser input permission."""
        with self._lock:
            if self._closed or self._fault:
                raise SessionUnavailable()
            now, mono = self._clock()
            if (now >= self.spec.retention_expires_at_ms or mono >= self._retention_deadline
                    or self._state["mode"] in _TERMINAL):
                raise SessionDenied("retained_read_only")
            if (type(name) is not str or name not in {"result.json", "screenshot.jpg"}
                    or type(content) is not bytes or len(content) > self.spec.limits.result_bytes):
                raise SessionDenied("invalid_result")
            if name == "result.json":
                if type(strict_json(content)) is not dict:
                    raise SessionDenied("invalid_result")
            elif not content.startswith(b"\xff\xd8") or not content.endswith(b"\xff\xd9"):
                raise SessionDenied("invalid_result")
            self._retain(name, content)

    def _retain(self, name, content):
        existing = self._state["results"].get(name)
        if existing is not None:
            if self.store.read_result(existing, self.spec.limits.result_bytes) != content:
                raise SessionDenied("result_conflict")
            return
        try:
            result = self.store.retain(content, self.spec.limits.result_bytes)
            state = deepcopy(self._state)
            state["results"][name] = result
            self._save(state)
        except SessionUnavailable:
            self._fault = True
            raise

    def _seal_events(self):
        content = (canonical({"schema_version": 1, "session_id": self.spec.session_id,
            "events": self._state["events"]}) + "\n").encode()
        self._retain("events.json", content)

    def read_result(self, token, name):
        with self._lock:
            self.authorize(token, "observe")
            result = self._state["results"].get(name)
            if result is None:
                raise SessionDenied("result_absent")
            return self.store.read_result(result, self.spec.limits.result_bytes)

    async def supervise(self):
        """Host must run once independently of clients, until expiry or Stop.

        This task does not launch or acquire a browser. External process loss is
        LOST on reopen; a real host must separately supervise its native owner.
        """
        while True:
            with self._lock:
                if self._closed or self.adapter is None or self._state["mode"] in _TERMINAL:
                    return
                now, mono = self._clock(stop=True)
                remaining = min((self.spec.browser_expires_at_ms - now) / 1000,
                                self._browser_deadline - mono)
            if remaining <= 0:
                await self._stop_owned({"kind": "stop", "operation_id": "host.browser-lifetime-expired",
                                        "actor_id": self.spec.owner_actor_id})
                return
            await asyncio.sleep(min(remaining, 0.1))

    def close(self):
        """Release local custody without inferring native teardown or cancellation."""
        with self._lock:
            if self._closed:
                return
            self._closed = True
            self._frame, self._served = None, {}
            self.store.close()
