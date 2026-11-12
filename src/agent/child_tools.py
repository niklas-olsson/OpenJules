"""Bounded child controls for the trusted image's root runner.

The host authenticates the root UID on a separate control socket. These tools
never supply an actor, command, image, provider or credential. Child runners
keep the ordinary completion protocol and do not import this extension.
"""

from __future__ import annotations

import hashlib
import json
import math
import re
import socket
import struct
import threading
import time
from uuid import uuid4

MAX_REQUEST_BYTES = 131072
MAX_RESPONSE_BYTES = 524288
MAX_RESULT_BYTES = 65536
MAX_ARTIFACT_BYTES = 4_000_000
_IDENTIFIER = re.compile(r"[A-Za-z0-9][A-Za-z0-9_.:-]{0,127}")
_HASH = re.compile(r"[0-9a-f]{64}")
_SESSION_ID = re.compile(r"session_[0-9a-f]{64}")
_RETRYABLE = frozenset({"retry_later", "canonical_pending"})
_TOOL_REFUSALS = frozenset({"child_not_allocated", "invalid_request", "unsupported"})
_ORDINARY_TOOLS = frozenset({"read_file", "write_file", "list_files", "run_command"})
_OPERATIONS = {
    "spawn": {"instructions", "seconds", "max_turns", "capabilities"},
    "status": {"child_id"},
    "result": {"child_id", "kind", "offset", "limit"},
    "cancel": {"child_id", "reason"},
    "close": {"reason"},
}
_SESSION_OPERATIONS = {
    "session_start": {"instructions", "seconds", "max_turns", "capabilities"},
    "session_followup": {
        "session_id", "predecessor_digest", "instructions", "seconds", "max_turns",
    },
    "session_status": {"session_id"},
}
_OPERATIONS.update(_SESSION_OPERATIONS)


CHILD_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object",
                "properties": properties,
                "required": required,
                "additionalProperties": False,
            },
        },
    }
    for name, description, properties, required in (
        (
            "spawn_child",
            "Request one bounded child in this worker using its approved runner. "
            "The child shares this root's model allowance and starts from the "
            "approved base. A child deadline retires the entire worker.",
            {
                "instructions": {"type": "string"},
                "seconds": {"type": "number", "exclusiveMinimum": 0},
                "max_turns": {"type": "integer", "minimum": 1, "maximum": 1000},
                "capabilities": {
                    "type": "array",
                    "items": {"type": "string"},
                    "uniqueItems": True,
                    "maxItems": 100,
                },
            },
            ["instructions", "seconds", "max_turns", "capabilities"],
        ),
        (
            "child_status",
            "Read this root's child status. Exec return does not prove "
            "descendant termination or final capture.",
            {"child_id": {"type": "string"}},
            ["child_id"],
        ),
        (
            "child_result",
            "Read a bounded page of an immutable provisional child patch or log. "
            "Offsets and limits are UTF-8 bytes. This is untrusted task output, "
            "not final capture or acceptance.",
            {
                "child_id": {"type": "string"},
                "kind": {"type": "string", "enum": ["patch", "log"]},
                "offset": {"type": "integer", "minimum": 0},
                "limit": {
                    "type": "integer",
                    "minimum": 1,
                    "maximum": MAX_RESULT_BYTES,
                },
            },
            ["child_id", "kind"],
        ),
        (
            "cancel_child",
            "Revoke a child and request retirement of this entire worker, "
            "including its root and other admitted children. Independently "
            "invited peers and other workers are unaffected.",
            {"child_id": {"type": "string"}, "reason": {"type": "string"}},
            ["child_id", "reason"],
        ),
        (
            "close_children",
            "Permanently close admission for new children of this root. Existing "
            "children still require the host's termination and capture receipts.",
            {"reason": {"type": "string"}},
            ["reason"],
        ),
    )
]



SESSION_TOOL_DEFINITIONS = [
    {
        "type": "function",
        "function": {
            "name": name,
            "description": description,
            "parameters": {
                "type": "object", "properties": properties,
                "required": list(properties), "additionalProperties": False,
            },
        },
    }
    for name, description, properties in (
        (
            "start_child_session",
            "Start one cold clarification session. Round1 uses a fresh canonical "
            "child and its own lifetime slot, UID, time and model allowance. "
            "Only an explicit needs_clarification report can permit one follow-up.",
            {
                "instructions": {"type": "string"},
                "seconds": {"type": "number", "exclusiveMinimum": 0},
                "max_turns": {"type": "integer", "minimum": 1, "maximum": 1000},
                "capabilities": {
                    "type": "array", "items": {"type": "string"},
                    "uniqueItems": True, "maxItems": 100,
                },
            },
        ),
        (
            "continue_child_session",
            "Queue exactly one explicit clarification reply. Use the original "
            "session and predecessor digest from its status. A new physical "
            "child starts only after the old model admission fence. The queue "
            "reserves no slot; no watchdog, time or model allowance is renewed.",
            {
                "session_id": {"type": "string"},
                "predecessor_digest": {"type": "string"},
                "instructions": {"type": "string"},
                "seconds": {"type": "number", "exclusiveMinimum": 0},
                "max_turns": {"type": "integer", "minimum": 1, "maximum": 1000},
            },
        ),
        (
            "child_session_status",
            "Observe the original cold session and each separate child. "
            "Reports and provisional evidence are not verification or release. "
            "Observation cannot queue, allocate or infer another round.",
            {"session_id": {"type": "string"}},
        ),
    )
]

class ControlError(RuntimeError):
    """A bounded refusal or uncertain control outcome, without server details."""

    def __init__(self, code: str, request_id: str | None = None):
        self.code = code
        self.request_id = request_id
        super().__init__("child control unavailable: " + code)


def _json(value) -> bytes:
    return json.dumps(
        value,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=False,
        allow_nan=False,
    ).encode("utf-8")


def _pairs(pairs):
    value = {}
    for key, item in pairs:
        if key in value:
            raise ValueError("duplicate response field")
        value[key] = item
    return value


def _invalid_constant(_value):
    raise ValueError("nonfinite response number")


def _identifier(value):
    return isinstance(value, str) and _IDENTIFIER.fullmatch(value) is not None


def _text(value, maximum):
    return (
        isinstance(value, str)
        and bool(value.strip())
        and "\0" not in value
        and len(value.encode("utf-8")) <= maximum
    )


def _validate(operation: str, fields: dict) -> None:
    if (
        not isinstance(operation, str)
        or operation not in _OPERATIONS
        or set(fields) != _OPERATIONS[operation]
    ):
        raise ValueError("unsupported control operation or fields")
    if "child_id" in fields and not _identifier(fields["child_id"]):
        raise ValueError("invalid child identifier")
    if "reason" in fields and not _text(fields["reason"], 512):
        raise ValueError("invalid control reason")
    if operation == "spawn":
        capabilities = fields["capabilities"]
        seconds = fields["seconds"]
        if (
            not _text(fields["instructions"], 65536)
            or type(seconds) not in {int, float}
            or not math.isfinite(seconds)
            or not 0 < seconds <= 86400
            or type(fields["max_turns"]) is not int
            or not 1 <= fields["max_turns"] <= 1000
            or not isinstance(capabilities, list)
            or len(capabilities) > 100
            or any(not _text(item, 512) for item in capabilities)
            or len(set(capabilities)) != len(capabilities)
        ):
            raise ValueError("invalid bounded child request")
    if operation in _SESSION_OPERATIONS:
        if "session_id" in fields and (
            not isinstance(fields["session_id"], str)
            or not _SESSION_ID.fullmatch(fields["session_id"])
        ):
            raise ValueError("invalid cold-session identity")
        if operation != "session_status":
            seconds = fields["seconds"]
            if (
                not _text(fields["instructions"], 16384)
                or type(seconds) not in {int, float}
                or not 0 < seconds <= 86400
                or not math.isfinite(float(seconds))
                or type(fields["max_turns"]) is not int
                or not 1 <= fields["max_turns"] <= 1000
            ):
                raise ValueError("invalid cold-session request")
        if operation == "session_start":
            capabilities = fields["capabilities"]
            if (
                not isinstance(capabilities, list) or len(capabilities) > 100
                or any(not _text(item, 512) for item in capabilities)
                or len(set(capabilities)) != len(capabilities)
            ):
                raise ValueError("invalid session capabilities")
        if operation == "session_followup" and (
            not isinstance(fields["predecessor_digest"], str)
            or not _HASH.fullmatch(fields["predecessor_digest"])
        ):
            raise ValueError("invalid predecessor digest")
    if operation == "result" and (
        not isinstance(fields["kind"], str)
        or fields["kind"] not in {"patch", "log"}
        or type(fields["offset"]) is not int
        or not 0 <= fields["offset"] <= MAX_ARTIFACT_BYTES
        or type(fields["limit"]) is not int
        or not 1 <= fields["limit"] <= MAX_RESULT_BYTES
    ):
        raise ValueError("invalid result page")


def _receive(connection, size: int, deadline: float) -> bytes:
    content = bytearray()
    while len(content) < size:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("control deadline elapsed")
        connection.settimeout(remaining)
        part = connection.recv(min(65536, size - len(content)))
        if not part:
            raise ControlError("uncertain")
        content.extend(part)
    return bytes(content)


class ControlClient:
    """One original deadline and payload for each explicit request identity.

    Only explicit busy or unresolved canonical-grant responses are retried.
    A broken connection or malformed reply does not authorize a new request.
    The host retains the durable grant intent and is the recovery authority.
    """

    def __init__(
        self,
        socket_path: str,
        *,
        timeout_seconds: float = 30,
        max_response_bytes: int = MAX_RESPONSE_BYTES,
        retry_delay_seconds: float = 0.05,
    ):
        if (
            not isinstance(socket_path, str)
            or not socket_path.startswith("/")
            or "\0" in socket_path
            or type(timeout_seconds) not in {int, float}
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 120
            or type(max_response_bytes) is not int
            or not 1 <= max_response_bytes <= MAX_RESPONSE_BYTES
            or type(retry_delay_seconds) not in {int, float}
            or not math.isfinite(retry_delay_seconds)
            or not 0 < retry_delay_seconds <= 1
        ):
            raise ValueError("invalid bounded control transport")
        self.socket_path = socket_path
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes
        self.retry_delay_seconds = retry_delay_seconds
        self._guard = threading.Lock()
        self._requests = {}
        self._snapshots = {}
        self._sessions = {}

    def request(self, operation: str, request_id: str | None = None, **fields):
        entered = time.monotonic()
        _validate(operation, fields)
        request_id = uuid4().hex if request_id is None else request_id
        if not _identifier(request_id):
            raise ValueError("invalid control request identity")
        payload = _json(
            {
                "schema_version": 1,
                "request_id": request_id,
                "operation": operation,
                **fields,
            }
        )
        if len(payload) > MAX_REQUEST_BYTES:
            raise ValueError("control request exceeds its bound")
        # Freeze all fields before the first connection. A caller mutating a
        # supplied list while a retry waits cannot change the dispatched body.
        frozen = json.loads(payload)
        digest = hashlib.sha256(payload).hexdigest()
        with self._guard:
            prior = self._requests.get(request_id)
            if prior is not None and prior[0] != digest:
                raise ControlError("conflict", request_id)
            if prior is None:
                if len(self._requests) >= 16384:
                    raise ControlError("request_limit", request_id)
                prior = (digest, entered + self.timeout_seconds)
                self._requests[request_id] = prior
            deadline = prior[1]
        frame = struct.pack("!I", len(payload)) + payload
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ControlError("deadline_exceeded", request_id)
            try:
                with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
                    connection.settimeout(remaining)
                    connection.connect(self.socket_path)
                    remaining = deadline - time.monotonic()
                    if remaining <= 0:
                        raise TimeoutError("control deadline elapsed")
                    connection.settimeout(remaining)
                    connection.sendall(frame)
                    length = struct.unpack("!I", _receive(connection, 4, deadline))[0]
                    if not 1 <= length <= self.max_response_bytes:
                        raise ControlError("invalid_response", request_id)
                    response = json.loads(
                        _receive(connection, length, deadline),
                        object_pairs_hook=_pairs,
                        parse_constant=_invalid_constant,
                    )
            except ControlError as exc:
                if exc.request_id is None:
                    exc.request_id = request_id
                raise
            except (OSError, ValueError, TimeoutError):
                raise ControlError("uncertain", request_id) from None
            if time.monotonic() >= deadline:
                raise ControlError("deadline_exceeded", request_id)
            if (
                not isinstance(response, dict)
                or type(response.get("schema_version")) is not int
                or response["schema_version"] != 1
                or response.get("request_id") != request_id
                or type(response.get("ok")) is not bool
            ):
                raise ControlError("invalid_response", request_id)
            if response["ok"]:
                try:
                    self._validate_response(operation, frozen, response)
                except (ValueError, TypeError, OverflowError, RecursionError):
                    raise ControlError("invalid_response", request_id) from None
                return response
            code = response.get("error")
            if not isinstance(code, str) or not re.fullmatch(r"[a-z_]{1,64}", code):
                raise ControlError("invalid_response", request_id)
            if code not in _RETRYABLE:
                raise ControlError(code, request_id)
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise ControlError("deadline_exceeded", request_id)
            time.sleep(min(self.retry_delay_seconds, remaining))

    def _validate_response(self, operation, request, response):
        request_id = request["request_id"]
        if operation in _SESSION_OPERATIONS:
            self._validate_session_response(operation, request, response)
            return
        if "child_id" in request and response.get("child_id") != request["child_id"]:
            raise ControlError("invalid_response", request_id)
        if operation == "spawn":
            capabilities = response.get("capabilities")
            deadline = response.get("deadline")
            if (
                not _identifier(response.get("child_id"))
                or not _text(response.get("state"), 128)
                or type(deadline) not in {int, float}
                or not math.isfinite(deadline)
                or deadline <= 0
                or not isinstance(capabilities, list)
                or any(not isinstance(item, str) for item in capabilities)
                or sorted(capabilities) != sorted(request["capabilities"])
            ):
                raise ControlError("invalid_response", request_id)
        if operation == "status" and not _text(response.get("state"), 128):
            raise ControlError("invalid_response", request_id)
        if operation != "result":
            return
        content = response.get("content")
        content_hash = response.get("content_sha256")
        artifact_hash = response.get("artifact_sha256")
        total = response.get("total_bytes")
        if (
            response.get("final") is not False
            or type(response.get("offset")) is not int
            or response["offset"] != request["offset"]
            or ("kind" in response and response["kind"] != request["kind"])
            or not isinstance(content, str)
            or not isinstance(content_hash, str)
            or not _HASH.fullmatch(content_hash)
            or not isinstance(artifact_hash, str)
            or not _HASH.fullmatch(artifact_hash)
            or type(total) is not int
            or not 0 <= total <= MAX_ARTIFACT_BYTES
        ):
            raise ControlError("invalid_response", request_id)
        try:
            encoded = content.encode("utf-8")
        except UnicodeError:
            raise ControlError("invalid_response", request_id) from None
        if (
            len(encoded) > request["limit"]
            or request["offset"] + len(encoded) > total
            or (request["offset"] < total and not encoded)
            or hashlib.sha256(encoded).hexdigest() != content_hash
            or (
                request["offset"] == 0
                and len(encoded) == total
                and content_hash != artifact_hash
            )
        ):
            raise ControlError("invalid_response", request_id)
        snapshot = (artifact_hash, total)
        key = (request["child_id"], request["kind"])
        with self._guard:
            previous = self._snapshots.setdefault(key, snapshot)
            if previous != snapshot:
                raise ControlError("conflict", request_id)


    def _validate_session_response(self, operation, request, response):
        def require(condition):
            if not condition:
                raise ControlError("invalid_response", request["request_id"])

        def hashed(value):
            return isinstance(value, str) and _HASH.fullmatch(value) is not None

        def digest(value):
            encoded = json.dumps(
                value, sort_keys=True, separators=(",", ":"), allow_nan=False
            ).encode("utf-8")
            return hashlib.sha256(encoded).hexdigest()

        fields = {
            "schema_version", "request_id", "ok", "protocol", "session_id",
            "root_attempt_id", "phase", "reason", "predecessor_digest",
            "followup_request_id", "model_fence", "logical_outcome",
            "all_child_receipts_final", "canonical_session", "release_authorized",
            "rounds",
        }
        reasons = {
            None, "awaiting_exec_return", "awaiting_model_fence", "awaiting_canonical",
            "child_not_allocated", "lifetime_limit", "round_limit", "admission_closed",
            "expired", "invalid_predecessor", "model_unresolved", "launch_uncertain",
            "runtime_failed", "capture_unresolved",
        }
        outcomes = {"completed", "declined", "needs_clarification", "failed"}
        require(
            set(response) == fields
            and response["protocol"] == "cold-clarification-v1"
            and isinstance(response["session_id"], str)
            and _SESSION_ID.fullmatch(response["session_id"])
            and _identifier(response["root_attempt_id"])
            and isinstance(response["phase"], str)
            and response["phase"] in {
                "round1", "awaiting_followup", "followup_queued", "round2", "closed", "uncertain",
            }
            and (response["reason"] is None or isinstance(response["reason"], str))
            and response["reason"] in reasons
            and response["model_fence"] in {"open", "requested", "established"}
            and (
                response["logical_outcome"] is None
                or isinstance(response["logical_outcome"], str)
            )
            and response["logical_outcome"] in outcomes | {
                None, "unreported", "refused", "cancelled", "expired",
            }
            and type(response["all_child_receipts_final"]) is bool
            and response["canonical_session"] is False
            and response["release_authorized"] is False
            and (
                response["predecessor_digest"] is None
                or hashed(response["predecessor_digest"])
            )
            and (
                response["followup_request_id"] is None
                or _identifier(response["followup_request_id"])
            )
            and isinstance(response["rounds"], list)
            and 1 <= len(response["rounds"]) <= 2
        )
        if "session_id" in request:
            require(response["session_id"] == request["session_id"])
        round_fields = {
            "logical_round", "request_id", "child_id", "grant_digest",
            "instructions_digest", "exec_id", "runtime_state", "exit_code",
            "initial_outcome", "evidence", "artifacts",
        }
        outcome_fields = {
            "schema_version", "work_turn_id", "ordinal", "child_id", "root_attempt_id",
            "parent_attempt_id", "task_id", "requirements_revision", "grant_digest",
            "instructions_digest", "source", "report", "canonical_committed",
            "release_authorized",
        }
        identities = []
        for ordinal, row in enumerate(response["rounds"], 1):
            require(
                isinstance(row, dict) and set(row) == round_fields
                and type(row["logical_round"]) is int and row["logical_round"] == ordinal
                and _identifier(row["request_id"])
                and hashed(row["instructions_digest"])
                and (row["exec_id"] is None or _identifier(row["exec_id"]))
                and (row["exit_code"] is None or type(row["exit_code"]) is int)
                and isinstance(row["evidence"], str)
                and row["evidence"] in {"pending", "provisional", "canonical_child_final"}
            )
            identities.append({
                name: row[name] for name in (
                    "request_id", "instructions_digest", "child_id", "grant_digest", "exec_id"
                )
            })
            if row["child_id"] is None:
                require(
                    row["grant_digest"] is None and row["exec_id"] is None
                    and row["runtime_state"] is None and row["exit_code"] is None
                    and row["initial_outcome"] is None and row["evidence"] == "pending"
                    and row["artifacts"] is None
                )
                continue
            require(
                isinstance(row["child_id"], str)
                and re.fullmatch(r"child_[0-9a-f]{32}", row["child_id"])
                and hashed(row["grant_digest"])
                and isinstance(row["runtime_state"], str)
                and row["runtime_state"] in {
                    "granted", "admitted", "preparing", "arming", "armed", "creating",
                    "created", "dispatching", "running", "exec_returned", "uncertain",
                    "captured", "completed",
                }
            )
            final = row["evidence"] == "canonical_child_final"
            outcome = row["initial_outcome"]
            require(
                isinstance(outcome, dict)
                and set(outcome) == outcome_fields | ({"artifacts"} if final else set())
                and type(outcome["schema_version"]) is int and outcome["schema_version"] == 1
                and type(outcome["ordinal"]) is int and outcome["ordinal"] == 1
                and outcome["child_id"] == row["child_id"]
                and outcome["root_attempt_id"] == response["root_attempt_id"]
                and outcome["parent_attempt_id"] == response["root_attempt_id"]
                and _identifier(outcome["task_id"])
                and type(outcome["requirements_revision"]) is int
                and outcome["requirements_revision"] >= 1
                and outcome["grant_digest"] == row["grant_digest"]
                and outcome["instructions_digest"] == row["instructions_digest"]
                and outcome["work_turn_id"] == digest([
                    "polyphony-child-work-v1", row["child_id"], row["grant_digest"], 1,
                ])
                and outcome["canonical_committed"] is final
                and outcome["release_authorized"] is False
            )
            report = outcome["report"]
            if report is None:
                require(outcome["source"] == "unreported")
            else:
                require(
                    isinstance(report, dict)
                    and set(report) == {"request_key", "outcome", "summary", "payload_digest"}
                    and _identifier(report["request_key"])
                    and isinstance(report["outcome"], str) and report["outcome"] in outcomes
                    and isinstance(report["summary"], str) and "\0" not in report["summary"]
                    and len(report["summary"].encode("utf-8")) <= 8192
                    and report["payload_digest"] == digest({
                        name: report[name] for name in ("request_key", "outcome", "summary")
                    })
                    and outcome["source"] == "child_report_via_bound_runtime"
                )
            if final:
                require(
                    row["runtime_state"] == "completed"
                    and isinstance(row["artifacts"], dict)
                    and set(row["artifacts"]) == {"patch", "log", "manifest"}
                    and all(hashed(value) for value in row["artifacts"].values())
                    and outcome["artifacts"] == row["artifacts"]
                )
            else:
                require(row["evidence"] == "provisional" and row["artifacts"] is None)
            identities[-1].update(
                outcome_binding=digest({
                    name: outcome[name] for name in (
                        "schema_version", "work_turn_id", "ordinal", "child_id",
                        "root_attempt_id", "parent_attempt_id", "task_id",
                        "requirements_revision", "grant_digest", "instructions_digest",
                    )
                }),
                report=None if report is None else digest(report),
                artifacts=None if row["artifacts"] is None else digest(row["artifacts"]),
            )
        task_bindings = {
            (row["initial_outcome"]["task_id"], row["initial_outcome"]["requirements_revision"])
            for row in response["rounds"] if row["initial_outcome"] is not None
        }
        require(len(task_bindings) <= 1)
        child_ids = [
            row["child_id"] for row in response["rounds"] if row["child_id"] is not None
        ]
        require(
            len(set(child_ids)) == len(child_ids)
            and len({row["request_id"] for row in response["rounds"]})
            == len(response["rounds"])
        )
        if (
            len(response["rounds"]) == 2
            and response["rounds"][1]["child_id"] is not None
        ):
            require(response["model_fence"] == "established")
        if response["all_child_receipts_final"]:
            require(
                response["phase"] in {"closed", "uncertain"}
                and all(
                    row["child_id"] is None or row["evidence"] == "canonical_child_final"
                    for row in response["rounds"]
                )
            )
        first = response["rounds"][0]
        if operation == "session_start":
            require(first["request_id"] == request["request_id"])
        if len(response["rounds"]) == 1:
            require(response["followup_request_id"] is None and response["model_fence"] == "open")
        else:
            require(
                response["followup_request_id"] == response["rounds"][1]["request_id"]
                and response["model_fence"] != "open"
            )
        if operation == "session_followup":
            require(
                len(response["rounds"]) == 2
                and response["followup_request_id"] == request["request_id"]
                and response["predecessor_digest"] == request["predecessor_digest"]
            )
        if response["predecessor_digest"] is not None:
            original = first["initial_outcome"]
            require(
                first["exec_id"] is not None
                and isinstance(original, dict)
                and isinstance(original["report"], dict)
                and original["report"]["outcome"] == "needs_clarification"
            )
            provisional = {
                key: value for key, value in original.items() if key != "artifacts"
            } | {"canonical_committed": False, "release_authorized": False}
            require(response["predecessor_digest"] == digest({
                "exec_id": first["exec_id"], "work_outcome": provisional,
            }))
        with self._guard:
            old = self._sessions.get(response["session_id"])
            current = {
                "root": response["root_attempt_id"], "rounds": identities,
                "predecessor": response["predecessor_digest"],
                "followup": response["followup_request_id"],
                "fence": {"open": 0, "requested": 1, "established": 2}[response["model_fence"]],
                "final": response["all_child_receipts_final"],
                "closure": (
                    (response["phase"], response["logical_outcome"])
                    if response["phase"] in {"closed", "uncertain"} else None
                ),
            }
            if old is not None:
                require(
                    old["root"] == current["root"]
                    and len(old["rounds"]) <= len(current["rounds"])
                    and current["fence"] >= old["fence"]
                    and (not old["final"] or current["final"])
                    and (old["closure"] is None or old["closure"] == current["closure"])
                )
                for key in ("predecessor", "followup"):
                    require(old[key] is None or old[key] == current[key])
                for prior, observed in zip(old["rounds"], current["rounds"]):
                    require(all(
                        value is None or observed.get(key) == value
                        for key, value in prior.items()
                    ))
            elif len(self._sessions) >= 64:
                raise ControlError("request_limit", request["request_id"])
            self._sessions[response["session_id"]] = current


class RootTools:
    """Expose root controls while preserving the ordinary LocalTools boundary."""

    def __init__(self, ordinary, control: ControlClient):
        self.ordinary = ordinary
        self.control = control
        self._close_request_id = uuid4().hex
        self._closed = False

    def run_command(self, argv):
        return self.ordinary.run_command(argv)

    def close(self):
        if self._closed:
            return
        self.control.request(
            "close", request_id=self._close_request_id, reason="root runner ended"
        )
        self._closed = True

    def call(self, name: str, arguments: dict) -> str:
        if not isinstance(name, str):
            return "Tool error: unsupported tool or arguments"
        if name in _ORDINARY_TOOLS:
            return self.ordinary.call(name, arguments)
        operations = {
            "spawn_child": "spawn",
            "child_status": "status",
            "child_result": "result",
            "cancel_child": "cancel",
            "close_children": "close",
            "start_child_session": "session_start",
            "continue_child_session": "session_followup",
            "child_session_status": "session_status",
        }
        if name not in operations or not isinstance(arguments, dict):
            return "Tool error: unsupported tool or arguments"
        operation = operations[name]
        if self._closed and operation in {"spawn", "session_start", "session_followup"}:
            return "Tool error: child admission is closed"
        fields = dict(arguments)
        if operation == "result":
            fields.setdefault("offset", 0)
            fields.setdefault("limit", 16384)
        try:
            # Do not let a tool argument bind ControlClient.request's own
            # request_id parameter. Only the client creates delivery keys.
            _validate(operation, fields)
            response = self.control.request(operation, **fields)
        except (ValueError, TypeError):
            return "Tool error: invalid bounded child arguments"
        except ControlError as exc:
            if exc.code in _TOOL_REFUSALS:
                return _json({"ok": False, "error": exc.code}).decode()
            # Do not feed an unknown spawn outcome back to a model that could
            # invent another request key. The root wrapper closes admission.
            raise
        if operation == "close":
            self._closed = True
        return _json(response).decode("utf-8")
