"""Explicit experimental host-signal adapters, separate from managed authority.

The MCP caller is an injected, bounded transport seam. There is no production
connector or direct-SQL compatibility path. InMemoryOutboxBridge is a fixture.
"""
from __future__ import annotations

from abc import ABC, abstractmethod
from enum import Enum
import json
import math
import time
from typing import Any, Callable, Dict, List, Optional

from src.polyphony.models import HostSignalStatus, HostTelemetrySignal, SignalType
from src.worker.execution_context import require_legacy_execution

MAX_TEXT_BYTES = 64 * 1024
MAX_SIGNALS = 128
MAX_TARGETS = 64
MAX_ID_CHARS = 256
MAX_NOTE_CHARS = 4096


class OutboxOutcome(str, Enum):
    REFUSED = "REFUSED"
    UNSUPPORTED = "UNSUPPORTED"
    UNKNOWN = "UNKNOWN"


class OutboxError(RuntimeError):
    """A local safe classification, never a remote error body or credential."""

    def __init__(self, outcome: OutboxOutcome, code: str):
        self.outcome = outcome
        self.code = code
        super().__init__(code)


def unsupported(code="host_signal_transport_unsupported"):
    return OutboxError(OutboxOutcome.UNSUPPORTED, code)


def _invalid():
    return OutboxError(OutboxOutcome.UNKNOWN, "invalid_host_signal_result")


def _member(value, name, default=None):
    return value.get(name, default) if isinstance(value, dict) else getattr(value, name, default)


def _unique(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ValueError("duplicate JSON member")
        result[key] = value
    return result


def _decode(result: Any) -> dict:
    """Accept one bounded JSON text result and its identical SDK projection.

    The pinned producer returns a JSON string. FastMCP also projects that same
    string as structuredContent.result. Mixed/different projections are refused.
    Direct result dictionaries and empty/multiple/non-text blocks are not data.
    """
    try:
        if isinstance(result, str):
            text = result
        else:
            content = _member(result, "content")
            is_error = _member(result, "isError", False)
            if type(is_error) is not bool or is_error or not isinstance(content, list) or len(content) != 1:
                raise ValueError("ambiguous MCP result")
            item = content[0]
            if _member(item, "type") != "text":
                raise ValueError("non-text MCP result")
            text = _member(item, "text")
            projection = _member(result, "structuredContent")
            if projection is not None and projection != {"result": text}:
                raise ValueError("different structured result")
        if not isinstance(text, str) or len(text) > MAX_TEXT_BYTES or len(text.encode("utf-8")) > MAX_TEXT_BYTES:
            raise ValueError("unbounded MCP text")
        payload = json.loads(text, object_pairs_hook=_unique,
                             parse_constant=lambda _: (_ for _ in ()).throw(ValueError("nonfinite JSON")))
        if not isinstance(payload, dict) or type(payload.get("success")) is not bool:
            raise ValueError("missing explicit success")
        if payload["success"] is False:
            if not set(payload) <= {"success", "error", "reason", "message"}:
                raise ValueError("mixed refusal and data")
            raise OutboxError(OutboxOutcome.REFUSED, "producer_refused_host_signal")
        return payload
    except OutboxError:
        raise
    except (ValueError, TypeError, UnicodeError, RecursionError):
        raise _invalid() from None


def _text(value, maximum, *, empty=False):
    if not isinstance(value, str) or not (empty or value) or len(value) > maximum:
        return False
    try:
        value.encode("utf-8")
    except UnicodeError:
        return False
    return not any(ord(char) < 32 for char in value if char not in "\n\t")


def _identifier(value):
    return _text(value, MAX_ID_CHARS) and not any(char.isspace() for char in value)


def _signal(row):
    fields = {"signal_id", "emitted_by_actor", "signal_type", "requested_worker_delta",
              "target_task_ids", "unsettled_cost_snapshot", "rationale", "host_status",
              "host_response_note", "created_at", "updated_at"}
    if not isinstance(row, dict) or set(row) != fields:
        raise _invalid()
    for name in ("signal_id", "emitted_by_actor"):
        if not _identifier(row[name]):
            raise _invalid()
    for name in ("rationale", "host_response_note"):
        if not _text(row[name], MAX_NOTE_CHARS, empty=True):
            raise _invalid()
    targets = row["target_task_ids"]
    if (not isinstance(targets, list) or len(targets) > MAX_TARGETS
            or any(not _identifier(value) for value in targets)
            or len(set(targets)) != len(targets)):
        raise _invalid()
    if type(row["requested_worker_delta"]) is not int or abs(row["requested_worker_delta"]) > 2**31 - 1:
        raise _invalid()
    for name in ("unsettled_cost_snapshot", "created_at", "updated_at"):
        value = row[name]
        if type(value) not in (int, float) or value < 0 or value > 1e100 or not math.isfinite(value):
            raise _invalid()
    if (row["host_status"] != "PENDING" or not isinstance(row["signal_type"], str)
            or row["signal_type"] not in {item.value for item in SignalType}):
        raise _invalid()
    return HostTelemetrySignal(**row)


class BaseOutboxBridge(ABC):
    """Success returns data; refused/unsupported/unknown observations raise safely."""

    def ensure_available(self) -> None:
        """An explicit fixture or injected adapter may implement this boundary."""

    @abstractmethod
    def poll_pending_signals(self) -> List[HostTelemetrySignal]:
        pass

    @abstractmethod
    def acknowledge_signal(self, signal_id: str, new_status: HostSignalStatus | str,
                           response_note: str = "") -> bool:
        pass

    @abstractmethod
    def count_active_leases(self, actor_id: str, now: Optional[float] = None) -> Optional[int]:
        """An absent observation is None or a classified failure, never idle zero."""


class SQLiteOutboxBridge(BaseOutboxBridge):
    """Refused historical API; foreign-table access is not a supported transport."""

    def __init__(self, db_path: str):
        require_legacy_execution()
        raise unsupported("direct_sql_host_signals_unsupported")

    def ensure_available(self):
        require_legacy_execution()
        raise unsupported("direct_sql_host_signals_unsupported")

    def poll_pending_signals(self):
        self.ensure_available()

    def acknowledge_signal(self, signal_id, new_status, response_note=""):
        self.ensure_available()

    def count_active_leases(self, actor_id, now=None):
        self.ensure_available()


class McpOutboxBridge(BaseOutboxBridge):
    """Decode the actual producer contract through an explicitly supplied caller.

    The caller must bound its own transport lifetime and received envelope before
    returning. This seam does not implement a connected production transport.
    """

    def __init__(self, host_control_key: str,
                 mcp_caller: Optional[Callable[[str, Dict[str, Any]], Any]] = None,
                 db_path: Optional[str] = None):
        require_legacy_execution()
        if db_path is not None:
            raise unsupported("direct_sql_host_signals_unsupported")
        if not isinstance(host_control_key, str) or not host_control_key or len(host_control_key) > 4096:
            raise unsupported("host_signal_key_unconfigured")
        self.host_control_key = host_control_key
        self.mcp_caller = mcp_caller
        self.ensure_available()

    def ensure_available(self):
        require_legacy_execution()
        if not callable(self.mcp_caller):
            raise unsupported()

    def _call(self, name, arguments):
        self.ensure_available()
        try:
            result = self.mcp_caller(name, {"host_key": self.host_control_key, **arguments})
        except (NotImplementedError, KeyError):
            raise unsupported("host_signal_tool_unsupported") from None
        except Exception:
            raise OutboxError(OutboxOutcome.UNKNOWN, "host_signal_transport_unknown") from None
        return _decode(result)

    def poll_pending_signals(self):
        result = self._call("openjules_poll_outbox", {"status_filter": "PENDING"})
        if (set(result) != {"success", "data", "managed_authority", "release_authorized"}
                or result["managed_authority"] is not False or result["release_authorized"] is not False
                or not isinstance(result["data"], list) or len(result["data"]) > MAX_SIGNALS):
            raise _invalid()
        signals = [_signal(row) for row in result["data"]]
        if len({signal.signal_id for signal in signals}) != len(signals):
            raise _invalid()
        return signals

    def acknowledge_signal(self, signal_id, new_status, response_note=""):
        require_legacy_execution()
        status = new_status.value if isinstance(new_status, HostSignalStatus) else new_status
        if (not _identifier(signal_id) or not isinstance(status, str)
                or status not in {"ACKNOWLEDGED", "FULFILLED", "REJECTED"}
                or not _text(response_note, MAX_NOTE_CHARS, empty=True)):
            raise _invalid()
        result = self._call("openjules_ack_signal", {
            "signal_id": signal_id, "new_status": status, "response_note": response_note,
        })
        if not set(result) <= {"success", "message"}:
            raise _invalid()
        return True

    def count_active_leases(self, actor_id, now=None):
        self.ensure_available()
        # The producer has no such tool. A successful empty poll proves no idle
        # worker state, so do not invent a call or manufacture a zero result.
        raise unsupported("worker_activity_observation_unsupported")


class InMemoryOutboxBridge(BaseOutboxBridge):
    """Explicit deterministic fixture, never a production transport fallback."""

    def __init__(self):
        self.signals: Dict[str, HostTelemetrySignal] = {}
        self.active_leases: Dict[str, int] = {}

    def add_signal(self, signal: HostTelemetrySignal) -> None:
        self.signals[signal.signal_id] = signal

    def set_active_leases(self, actor_id: str, count: int) -> None:
        if type(count) is not int or count < 0:
            raise ValueError("invalid fixture activity")
        self.active_leases[actor_id] = count

    def poll_pending_signals(self):
        return [signal for signal in sorted(self.signals.values(), key=lambda item: item.created_at)
                if signal.host_status == HostSignalStatus.PENDING]

    def acknowledge_signal(self, signal_id, new_status, response_note=""):
        if signal_id not in self.signals:
            return False
        signal = self.signals[signal_id]
        signal.host_status = HostSignalStatus(new_status)
        signal.host_response_note = response_note
        signal.updated_at = time.time()
        return True

    def count_active_leases(self, actor_id, now=None):
        return self.active_leases.get(actor_id)
