"""Owned, bounded MCP client for the NEW public-conversation profile.

The approved host interpreter and checkout are executable trust. Public messages
cannot choose them. No ordinary Polyphony server fallback or task callback exists.
"""

from __future__ import annotations

from contextlib import asynccontextmanager
from dataclasses import dataclass
from datetime import timedelta
import os
from pathlib import Path
import signal
import subprocess
import time

import anyio
from mcp import ClientSession
from mcp.shared.message import SessionMessage
from mcp.types import Implementation, JSONRPCMessage

from ..worker.discussion_types import (
    CHILD_ENVIRONMENT, CLEANUP_SECONDS, CONTEXT_LIMIT, ConversationLaunch,
    Deadline, DiscussionError, Policy,
    FRAME_LIMIT, RPC_SECONDS, STARTUP_SECONDS, STDERR_LIMIT, TOOLS, WIRE_LIMIT,
    absolute_path, boot_id, canonical, fields, integer, strict_json, text,
    validate_history, validate_status,
)


PROBE = (
    "import sys;sys.dont_write_bytecode=True;"
    "import json,pathlib;"
    "print(json.dumps({'schema_version':1,"
    "'resolved_executable':str(pathlib.Path(sys.executable).resolve(strict=True)),"
    "'prefix':str(pathlib.Path(sys.prefix).resolve(strict=True))},"
    "sort_keys=True,separators=(',',':')))"
)
ARGUMENTS = {
    "conversation_status": ({}, set()),
    "conversation_start": (
        {"topic": "string", "request_key": "nullable:string"}, {"topic"}
    ),
    "conversation_join": (
        {"topic": "string", "decision": "string", "message": "string",
         "request_key": "nullable:string"}, {"topic"}
    ),
    "conversation_say": (
        {"topic": "string", "message": "string", "request_key": "nullable:string",
         "reply_to": "nullable:string", "kind": "string",
         "target": "nullable:string", "references": "nullable:references"},
        {"topic", "message"},
    ),
    "conversation_history": (
        {"topic": "string", "after": "integer", "limit": "integer",
         "stream_id": "nullable:string"}, {"topic"}
    ),
    "conversation_watch": (
        {"topic": "string", "after": "integer", "limit": "integer",
         "stream_id": "nullable:string", "timeout": "number"}, {"topic"}
    ),
}


def _invalid():
    raise DiscussionError("transport_invalid")


def _metadata(value):
    if value is not None:
        _invalid()


def _property(spec):
    fields(spec, set(), {
        "type", "anyOf", "title", "description", "default", "items",
        "additionalProperties",
    }, code="unsupported_profile")
    for label in ("title", "description"):
        if label in spec:
            text(spec[label], FRAME_LIMIT, code="unsupported_profile")
    if "anyOf" in spec:
        if (
            "type" in spec or "items" in spec or "additionalProperties" in spec
            or not isinstance(spec["anyOf"], list) or len(spec["anyOf"]) != 2
        ):
            raise DiscussionError("unsupported_profile")
        options = [_property(item) for item in spec["anyOf"]]
        if options.count("null") != 1:
            raise DiscussionError("unsupported_profile")
        other = next(item for item in options if item != "null")
        if other.startswith("nullable:"):
            raise DiscussionError("unsupported_profile")
        return "nullable:" + other
    kind = spec.get("type")
    if not isinstance(kind, str):
        raise DiscussionError("unsupported_profile")
    if kind in {"string", "integer", "number", "null"}:
        if "items" in spec or "additionalProperties" in spec:
            raise DiscussionError("unsupported_profile")
        return kind
    if kind == "array" and "additionalProperties" not in spec:
        item = spec.get("items")
        fields(item, {"type", "additionalProperties"}, {"title", "description"},
               code="unsupported_profile")
        if item["type"] != "object" or _property(item["additionalProperties"]) != "string":
            raise DiscussionError("unsupported_profile")
        return "references"
    raise DiscussionError("unsupported_profile")


def _tools(result):
    fields(result, {"tools"}, {"nextCursor", "_meta"}, code="unsupported_profile")
    if result.get("nextCursor") is not None:
        raise DiscussionError("unsupported_profile")
    _metadata(result.get("_meta"))
    if not isinstance(result["tools"], list) or len(result["tools"]) != len(TOOLS):
        raise DiscussionError("unsupported_profile")
    seen = set()
    for tool in result["tools"]:
        fields(tool, {"name", "inputSchema"}, {
            "title", "description", "outputSchema", "execution", "annotations",
            "icons", "_meta",
        }, code="unsupported_profile")
        name = tool["name"]
        if not isinstance(name, str) or name not in TOOLS or name in seen:
            raise DiscussionError("unsupported_profile")
        seen.add(name)
        if tool.get("outputSchema") is not None:
            raise DiscussionError("unsupported_profile")
        for label in ("title", "description"):
            if tool.get(label) is not None:
                text(tool[label], FRAME_LIMIT, code="unsupported_profile")
        for label in ("icons", "annotations", "_meta"):
            _metadata(tool.get(label))
        execution = tool.get("execution")
        if execution is not None:
            fields(execution, set(), {"taskSupport"}, code="unsupported_profile")
            if execution.get("taskSupport") not in (None, "forbidden"):
                raise DiscussionError("unsupported_profile")
        schema = tool["inputSchema"]
        fields(schema, {"type", "properties"}, {
            "required", "additionalProperties", "title", "description",
        }, code="unsupported_profile")
        expected, required = ARGUMENTS[name]
        actual_required = schema.get("required", [])
        if (
            schema["type"] != "object"
            or not isinstance(schema["properties"], dict)
            or set(schema["properties"]) != set(expected)
            or not isinstance(actual_required, list)
            or any(not isinstance(item, str) for item in actual_required)
            or len(actual_required) != len(set(actual_required))
            or set(actual_required) != required
        ):
            raise DiscussionError("unsupported_profile")
        if "additionalProperties" in schema and type(schema["additionalProperties"]) is not bool:
            raise DiscussionError("unsupported_profile")
        for key, value in schema["properties"].items():
            if _property(value) != expected[key]:
                raise DiscussionError("unsupported_profile")


def _initialize(result):
    fields(result, {"protocolVersion", "capabilities", "serverInfo"}, {
        "instructions", "_meta",
    }, code="unsupported_profile")
    text(result["protocolVersion"], 32, nonempty=True, code="unsupported_profile")
    _metadata(result.get("_meta"))
    if result.get("instructions") is not None:
        text(result["instructions"], FRAME_LIMIT, code="unsupported_profile")
    # Instructions are never used as model context.
    caps = result["capabilities"]
    fields(caps, {"tools"}, {
        "experimental", "logging", "prompts", "resources", "completions", "tasks",
    }, code="unsupported_profile")
    if any(value is not None for key, value in caps.items() if key != "tools"):
        raise DiscussionError("unsupported_profile")
    fields(caps["tools"], set(), {"listChanged"}, code="unsupported_profile")
    changed = caps["tools"].get("listChanged")
    if changed is not None and changed is not False:
        raise DiscussionError("unsupported_profile")
    info = result["serverInfo"]
    fields(info, {"name", "version"}, {"title"}, code="unsupported_profile")
    for value in info.values():
        text(value, 256, nonempty=True, code="unsupported_profile")


def _application(result):
    fields(result, {"content"}, {"isError", "structuredContent", "_meta"},
           code="transport_invalid")
    if result.get("isError", False) is not False:
        raise DiscussionError("transport_unavailable")
    _metadata(result.get("structuredContent"))
    _metadata(result.get("_meta"))
    if not isinstance(result["content"], list) or len(result["content"]) != 1:
        _invalid()
    item = result["content"][0]
    fields(item, {"type", "text"}, {"annotations", "_meta"}, code="transport_invalid")
    if item["type"] != "text":
        _invalid()
    _metadata(item.get("annotations"))
    _metadata(item.get("_meta"))
    text(item["text"], FRAME_LIMIT, nonempty=True, code="transport_invalid")
    return strict_json(item["text"].encode("utf-8"), FRAME_LIMIT, "transport_invalid")


@dataclass(frozen=True)
class CleanupResult:
    attempted_processes: int
    cleaned_processes: int
    active_processes: int
    failed: bool

    @property
    def confirmed(self):
        return (
            not self.failed and self.active_processes == 0
            and self.cleaned_processes == self.attempted_processes
        )


class CleanupObserver:
    """Inspect aggregate cleanup after the owned context exits, even on error.

    The observer owns no process and cannot signal or adopt one. Only the
    existing owner reports positive close completion. Failed or interrupted
    cleanup is sticky across every probe/profile lifetime observed here.
    """

    def __init__(self):
        self._attempted = 0
        self._cleaned = 0
        self._active = 0
        self._failed = False

    @property
    def result(self):
        return CleanupResult(
            self._attempted, self._cleaned, self._active, self._failed,
        )

    def _begin(self):
        self._attempted += 1
        self._active += 1

    def _finish(self, confirmed):
        self._active -= 1
        if confirmed:
            self._cleaned += 1
        else:
            self._failed = True


class ProcessLifecycleObserver:
    """Trusted local durability hooks; never an owner or signalling interface.

    before_start returns a caller-owned ticket before Popen. Only copied scalar
    identity facts reach started/finished; no process handle is exposed. Hook
    errors fail the operation without skipping the existing owner's cleanup.
    A missing identity or negative cleanup remains unresolved, not a safe retry.
    """

    def before_start(self, stage, argv, cwd, environment, deadline):
        raise NotImplementedError

    def started(self, ticket, identity):
        raise NotImplementedError

    def finished(self, ticket, identity, confirmed):
        raise NotImplementedError


def _observe(function, *arguments):
    try:
        return function(*arguments)
    except DiscussionError:
        raise
    except Exception:
        raise DiscussionError("state_conflict") from None


class _OwnedProcess:
    """Retain the leader PID until all group signals have been delivered."""

    def __init__(self, argv, cwd):
        if os.name != "posix" or not hasattr(os, "WNOWAIT"):
            raise DiscussionError("transport_unavailable")
        self.process = subprocess.Popen(
            argv, cwd=cwd, env=dict(CHILD_ENVIRONMENT),
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            start_new_session=True, close_fds=True, bufsize=0,
        )
        self.closed = False
        self.cleanup_confirmed = False

    def identity(self):
        # The leader is still owned and unreaped, even if it already exited.
        # Preserve the original PID until the existing group cleanup finishes.
        try:
            with open("/proc/" + str(self.process.pid) + "/stat", "rb") as handle:
                raw = handle.read(4097)
            if len(raw) > 4096:
                raise ValueError("bounded process identity unavailable")
            prefix, tail = raw.rsplit(b")", 1)
            values = tail.split()
            pid = int(prefix.split(b"(", 1)[0])
            pgid, session, starttime = int(values[2]), int(values[3]), int(values[19])
            if pid != self.process.pid or pgid != pid or session != pid or starttime <= 0:
                raise ValueError("owned process identity changed")
            return {"pid": pid, "starttime": starttime, "pgid": pgid, "boot_id": boot_id()}
        except Exception:
            raise DiscussionError("transport_unavailable") from None

    def configure(self):
        for handle in (self.process.stdin, self.process.stdout, self.process.stderr):
            os.set_blocking(handle.fileno(), False)

    def exit_info(self):
        # poll()/communicate()/wait() would reap an exited leader and lose the
        # stable group identity while a descendant still owns a pipe.
        return os.waitid(
            os.P_PID, self.process.pid, os.WEXITED | os.WNOHANG | os.WNOWAIT
        )

    def exited(self):
        return self.exit_info() is not None

    def _signal(self, signum):
        try:
            os.killpg(self.process.pid, signum)
        except ProcessLookupError:
            pass

    def _live_group(self, cutoff):
        """Observe termination, not waitpid ownership of grandchildren."""
        try:
            entries = os.scandir("/proc")
            with entries:
                for entry in entries:
                    if time.monotonic() >= cutoff:
                        raise DiscussionError("process_cleanup_failed")
                    if not entry.name.isdecimal():
                        continue
                    try:
                        with open(entry.path + "/stat", "rb") as handle:
                            raw = handle.read(4097)
                    except FileNotFoundError:
                        continue
                    if len(raw) > 4096:
                        raise DiscussionError("process_cleanup_failed")
                    tail = raw.rsplit(b")", 1)[1].split()
                    if int(tail[2]) == self.process.pid and tail[0] not in {b"Z", b"X"}:
                        return True
            return False
        except DiscussionError:
            raise
        except Exception:
            raise DiscussionError("process_cleanup_failed") from None

    async def close(self, cutoff=None):
        if self.closed:
            return
        cutoff = min(
            time.monotonic() + CLEANUP_SECONDS,
            cutoff if cutoff is not None else float("inf"),
        )
        failure = None
        # Let the trusted service see EOF, then require bounded termination.
        try:
            if self.process.stdin is not None:
                self.process.stdin.close()
            self._signal(signal.SIGTERM)
            graceful = min(cutoff, time.monotonic() + 0.5)
            while time.monotonic() < graceful:
                if self.exited() and not self._live_group(cutoff):
                    break
                await anyio.sleep(0.01)
        except Exception:
            failure = DiscussionError("process_cleanup_failed")
        try:
            # Always signal the original group, including an exited leader
            # whose inherited descendants still hold stdout/stderr open.
            self._signal(signal.SIGKILL)
            while not self.exited() or self._live_group(cutoff):
                if time.monotonic() >= cutoff:
                    raise DiscussionError("process_cleanup_failed")
                await anyio.sleep(0.01)
        except Exception:
            failure = DiscussionError("process_cleanup_failed")
        finally:
            # No group signals occur after this reap.
            try:
                self.process.wait(timeout=max(0.001, cutoff - time.monotonic()))
            except Exception:
                failure = DiscussionError("process_cleanup_failed")
            for handle in (self.process.stdin, self.process.stdout, self.process.stderr):
                try:
                    if handle is not None:
                        handle.close()
                except Exception:
                    failure = DiscussionError("process_cleanup_failed")
            self.closed = True
        if failure is not None:
            raise failure
        self.cleanup_confirmed = True


async def _read(handle, maximum=4096):
    while True:
        try:
            return os.read(handle.fileno(), maximum)
        except BlockingIOError:
            await anyio.wait_readable(handle.fileno())


async def _write(handle, raw):
    view = memoryview(raw)
    while view:
        try:
            size = os.write(handle.fileno(), view)
            if size <= 0:
                raise DiscussionError("transport_unavailable")
            view = view[size:]
        except BlockingIOError:
            await anyio.wait_writable(handle.fileno())


@asynccontextmanager
async def _owned(argv, cwd, *, deadline=None, cleanup=None, lifecycle=None, stage=None):
    process = None
    primary = None
    cleanup_error = None
    confirmed = False
    ticket = None
    observed_intent = False
    identity = None
    if cleanup is not None:
        cleanup._begin()
    try:
        if lifecycle is not None:
            if stage not in {"probe", "server"} or deadline is None:
                raise DiscussionError("invalid_policy")
            ticket = _observe(
                lifecycle.before_start, stage, tuple(argv), cwd, dict(CHILD_ENVIRONMENT), deadline,
            )
            observed_intent = True
            deadline.remaining()
        process = _OwnedProcess(argv, cwd)
        if lifecycle is not None:
            identity = process.identity()
            _observe(lifecycle.started, ticket, dict(identity))
        process.configure()
        yield process
    except BaseException as error:
        primary = error
        raise
    finally:
        try:
            if process is not None:
                with anyio.CancelScope(shield=True):
                    try:
                        cutoff = None if deadline is None else (
                            deadline.monotonic_cutoff + CLEANUP_SECONDS
                        )
                        await process.close(cutoff)
                        if not process.cleanup_confirmed:
                            raise DiscussionError("process_cleanup_failed")
                        confirmed = True
                    except BaseException as error:
                        cleanup_error = error
                        if primary is not None:
                            primary.add_note("owned discussion process cleanup failed")
                        elif not isinstance(error, Exception):
                            # Cleanup cancellation/interruption is not an
                            # ordinary transport error. Without an earlier
                            # primary, preserve that original control flow.
                            raise
                        else:
                            raise DiscussionError("process_cleanup_failed") from None
        finally:
            try:
                if lifecycle is not None and observed_intent:
                    try:
                        _observe(
                            lifecycle.finished, ticket,
                            None if identity is None else dict(identity), confirmed,
                        )
                    except BaseException:
                        earlier = primary if primary is not None else cleanup_error
                        if earlier is not None:
                            earlier.add_note("owned discussion lifecycle acknowledgement failed")
                        else:
                            raise
            finally:
                if cleanup is not None:
                    cleanup._finish(confirmed)


async def probe_interpreter(launch, startup, *, cleanup=None, lifecycle=None):
    launch.check_binding()
    raw = bytearray()
    stderr_bytes = 0

    async def output(process):
        while True:
            chunk = await _read(process.process.stdout, min(4096, 4097 - len(raw)))
            if not chunk:
                return
            raw.extend(chunk)
            if len(raw) > 4096:
                _invalid()

    async def errors(process):
        nonlocal stderr_bytes
        while True:
            chunk = await _read(process.process.stderr)
            if not chunk:
                return
            stderr_bytes += len(chunk)
            if stderr_bytes > STDERR_LIMIT:
                _invalid()

    with anyio.fail_after(startup.remaining()):
        async with _owned(
            [launch.python, "-I", "-c", PROBE], launch.cwd,
            deadline=startup, cleanup=cleanup, lifecycle=lifecycle, stage="probe",
        ) as process:
            process.process.stdin.close()
            async with anyio.create_task_group() as group:
                group.start_soon(output, process)
                group.start_soon(errors, process)
            if not process.exited():
                while not process.exited():
                    await anyio.sleep(0.01)
            info = process.exit_info()
            if info.si_code != os.CLD_EXITED or info.si_status != 0:
                raise DiscussionError("unsupported_profile")
            result = strict_json(raw, 4096, "unsupported_profile")
            fields(result, {"schema_version", "resolved_executable", "prefix"},
                   code="unsupported_profile")
            integer(result["schema_version"], 1, 1, "unsupported_profile")
            resolved = absolute_path(
                result["resolved_executable"], executable=True, code="unsupported_profile"
            )
            prefix = absolute_path(result["prefix"], code="unsupported_profile")
            launch_path = Path(launch.python)
            if (
                str(resolved) != str(launch_path.resolve(strict=True))
                or not prefix.is_dir()
            ):
                raise DiscussionError("unsupported_profile")
            return {
                "schema_version": 1, "launch_path": str(launch_path),
                "resolved_executable": str(resolved), "prefix": str(prefix),
            }


class _Wire:
    def __init__(self):
        self.total = 0
        self.stderr_bytes = 0
        self.pending = {}
        self.failure = None

    def charge(self, count):
        self.total += count
        if self.total > WIRE_LIMIT:
            _invalid()

    def outgoing(self, value):
        if value.get("jsonrpc") != "2.0":
            _invalid()
        if value.get("method") == "notifications/initialized":
            fields(value, {"jsonrpc", "method"}, {"params"}, code="transport_invalid")
            if value.get("params") not in (None, {}):
                _invalid()
            return
        fields(value, {"jsonrpc", "method", "id"}, {"params"}, code="transport_invalid")
        request_id = value["id"]
        if type(request_id) is not int or request_id < 0 or self.pending:
            _invalid()
        method = value["method"]
        if method not in {"initialize", "tools/list", "tools/call"}:
            _invalid()
        params = value.get("params")
        if method == "tools/list" and params not in (None, {}):
            _invalid()
        if method == "tools/call":
            fields(params, {"name", "arguments"}, code="transport_invalid")
            if (
                not isinstance(params["name"], str) or params["name"] not in TOOLS
                or not isinstance(params["arguments"], dict)
            ):
                _invalid()
        if method == "initialize":
            fields(params, {"protocolVersion", "capabilities", "clientInfo"},
                   code="transport_invalid")
            if params["capabilities"] != {}:
                _invalid()
        self.pending[request_id] = method

    def incoming(self, value):
        fields(value, {"jsonrpc", "id"}, {"result", "error"}, code="transport_invalid")
        request_id = value["id"]
        if (
            value["jsonrpc"] != "2.0" or type(request_id) is not int
            or request_id not in self.pending
            or ("result" in value) == ("error" in value)
        ):
            _invalid()
        method = self.pending.pop(request_id)
        if "error" in value:
            # Do not forward untrusted diagnostic strings into SDK logging.
            raise DiscussionError("transport_unavailable")
        result = value["result"]
        if method == "initialize":
            _initialize(result)
        elif method == "tools/list":
            _tools(result)
        else:
            _application(result)
        return SessionMessage(JSONRPCMessage.model_validate(value))


@asynccontextmanager
async def _transport(launch, deadline, *, cleanup=None, lifecycle=None):
    deadline.remaining()
    launch.check_binding()
    wire = _Wire()
    incoming, receive = anyio.create_memory_object_stream(1)
    send, outgoing = anyio.create_memory_object_stream(1)

    async def reader(process):
        buffer = bytearray()
        while True:
            chunk = await _read(
                process.process.stdout, min(4096, FRAME_LIMIT + 1 - len(buffer))
            )
            if not chunk:
                # EOF is not a successful tool result, even without a partial line.
                raise DiscussionError("transport_unavailable")
            wire.charge(len(chunk))
            buffer.extend(chunk)
            while b"\n" in buffer:
                line, _, remainder = buffer.partition(b"\n")
                buffer = bytearray(remainder)
                if not line or len(line) + 1 > FRAME_LIMIT:
                    _invalid()
                value = strict_json(line, FRAME_LIMIT, "transport_invalid")
                await incoming.send(wire.incoming(value))
            if len(buffer) >= FRAME_LIMIT:
                _invalid()

    async def writer(process):
        async for message in outgoing:
            value = message.message.model_dump(mode="json", by_alias=True, exclude_none=True)
            wire.outgoing(value)
            raw = canonical(value) + b"\n"
            if len(raw) > FRAME_LIMIT:
                _invalid()
            wire.charge(len(raw))
            await _write(process.process.stdin, raw)

    async def errors(process):
        while True:
            chunk = await _read(process.process.stderr)
            if not chunk:
                return
            wire.stderr_bytes += len(chunk)
            if wire.stderr_bytes > STDERR_LIMIT:
                _invalid()

    async def bounded(function, process):
        try:
            with anyio.fail_after(deadline.remaining()):
                await function(process)
        except BaseException as error:
            if isinstance(error, DiscussionError):
                wire.failure = error.code
            elif not isinstance(error, anyio.get_cancelled_exc_class()):
                wire.failure = "transport_unavailable"
            raise

    async with _owned(
        [launch.python, "-m", "src.liminal_bridge.conversation_server",
         "--config", launch.config],
        launch.cwd, deadline=deadline, cleanup=cleanup, lifecycle=lifecycle, stage="server",
    ) as process:
        try:
            async with incoming, receive, send, outgoing:
                async with anyio.create_task_group() as group:
                    group.start_soon(bounded, reader, process)
                    group.start_soon(bounded, writer, process)
                    group.start_soon(bounded, errors, process)
                    try:
                        yield receive, send, wire, process
                    finally:
                        group.cancel_scope.cancel()
        except DiscussionError:
            raise
        except BaseExceptionGroup:
            raise DiscussionError(wire.failure or "transport_unavailable") from None


class ConversationClient:
    def __init__(self, session, launch, deadline, wire, interpreter):
        self.session = session
        self.launch = launch
        self.deadline = deadline
        self.wire = wire
        self.interpreter = interpreter
        self.status = None

    async def _call(self, name, arguments, *, seconds=RPC_SECONDS):
        if self.wire.failure is not None:
            raise DiscussionError(self.wire.failure)
        timeout = min(seconds, self.deadline.remaining())
        try:
            with anyio.fail_after(timeout):
                result = await self.session.call_tool(
                    name, arguments, read_timeout_seconds=timedelta(seconds=timeout)
                )
            # The raw response was checked before entering the SDK. Validate
            # the retained text again without promoting any metadata to input.
            value = _application(
                result.model_dump(mode="json", by_alias=True, exclude_none=True)
            )
        except DiscussionError:
            raise
        except Exception:
            raise DiscussionError(self.wire.failure or "transport_unavailable") from None
        if self.wire.failure is not None:
            raise DiscussionError(self.wire.failure)
        return value

    async def check_status(self, expected=None):
        value = validate_status(
            await self._call("conversation_status", {}),
            self.launch.topic,
        )
        if expected is not None and canonical(value) != canonical(expected):
            raise DiscussionError("state_conflict")
        if self.status is not None and canonical(value) != canonical(self.status):
            raise DiscussionError("state_conflict")
        self.status = value
        return value

    async def history(self, after=0, *, stream_id=None, watch=0):
        integer(after, 0, (1 << 63) - 1, "invalid_context")
        if self.status is None:
            raise DiscussionError("state_conflict")
        if stream_id is not None and stream_id != self.status["stream_id"]:
            raise DiscussionError("state_conflict")
        if after > 0 and stream_id is None:
            raise DiscussionError("invalid_context")
        arguments = {
            "topic": self.status["topic"], "after": after, "limit": 100,
            "stream_id": self.status["stream_id"],
        }
        if watch:
            integer(watch, 1, 30, "invalid_context")
            remaining = self.deadline.remaining()
            wait = min(watch, max(0, remaining - 5))
            if wait <= 0:
                raise DiscussionError("expired")
            arguments["timeout"] = wait
            result = await self._call(
                "conversation_watch", arguments, seconds=min(remaining, wait + 5)
            )
        else:
            result = await self._call("conversation_history", arguments)
        return validate_history(result, self.status, after)

    async def selected_context(self, turn):
        if self.status is None:
            raise DiscussionError("state_conflict")
        requested = set(turn.document["selected_message_ids"])
        original_after = turn.document["context_after"]
        after = original_after
        selected = []
        seen = set()
        used = 0
        gaps = []
        if turn.document["stream_id"] not in {None, self.status["stream_id"]}:
            raise DiscussionError("state_conflict")
        # Even an empty selection gets one bounded history observation so a
        # stale requested cursor cannot be silently repaired.
        for _ in range(8):
            page = await self.history(
                after, stream_id=self.status["stream_id"] if after else turn.document["stream_id"]
            )
            if page["gap"] is not None:
                raise DiscussionError("invalid_context")
            gaps.append(page["peer_gaps"])
            for item in page["messages"]:
                identifier = item["record"]["message_id"]
                if identifier in requested:
                    if identifier in seen:
                        raise DiscussionError("invalid_context")
                    selected.append(item)
                    seen.add(identifier)
                    used += len(canonical(item["record"]))
                    if used > CONTEXT_LIMIT:
                        raise DiscussionError("invalid_context")
            next_cursor = page["next_cursor"]
            if seen == requested:
                return {
                    "status": self.status, "messages": selected, "peer_gaps": gaps,
                    "context_after": original_after, "next_cursor": next_cursor,
                }
            if not page["has_more"] or next_cursor <= after:
                raise DiscussionError("invalid_context")
            after = next_cursor
        raise DiscussionError("invalid_context")

    async def say(self, intent):
        if self.status is None:
            raise DiscussionError("state_conflict")
        # Routing and immutable optional fields are host-derived, never selected
        # by provider JSON. The journal independently binds the complete intent.
        return await self._call("conversation_say", {
            "topic": intent["topic"], "message": intent["content"],
            "request_key": intent["request_key"], "reply_to": intent["reply_to"],
            "kind": intent["kind"], "target": intent["target"],
            "references": intent["references"],
        })


@asynccontextmanager
async def connect(policy, deadline, *, expected_status=None, expected_interpreter=None,
                  cleanup=None, lifecycle=None):
    """Connect through a validated launch; optional cleanup survives any exit.

    Pass a CleanupObserver created before entry to inspect both owned lifetimes
    after this context finishes. A transport/application error and a positive
    cleanup result are independent facts. Optional trusted lifecycle hooks can
    retain a start intent and exact owned identity without gaining ownership.
    """
    launch = policy.launch if isinstance(policy, Policy) else policy
    if not isinstance(launch, ConversationLaunch):
        raise DiscussionError("invalid_policy")
    if cleanup is None:
        cleanup = CleanupObserver()
    elif not isinstance(cleanup, CleanupObserver):
        raise DiscussionError("invalid_policy")
    if lifecycle is not None and not isinstance(lifecycle, ProcessLifecycleObserver):
        raise DiscussionError("invalid_policy")
    startup = Deadline(
        min(time.time() + STARTUP_SECONDS, deadline.expires_at),
        min(time.monotonic() + STARTUP_SECONDS, deadline.monotonic_cutoff),
    )
    trusted_body_error = None
    try:
        interpreter = await probe_interpreter(launch, startup, cleanup=cleanup, lifecycle=lifecycle)
        if (
            expected_interpreter is not None
            and canonical(interpreter) != canonical(expected_interpreter)
        ):
            raise DiscussionError("state_conflict")
        startup.remaining()
        async with _transport(launch, deadline, cleanup=cleanup, lifecycle=lifecycle) as (
            receive, send, wire, process,
        ):
            async with ClientSession(
                receive, send, read_timeout_seconds=timedelta(seconds=RPC_SECONDS),
                client_info=Implementation(name="openjules-public-discussion", version="1"),
            ) as session:
                try:
                    with anyio.fail_after(startup.remaining()):
                        await session.initialize()
                        # Cache only the raw-validated six tools before status.
                        await session.list_tools()
                        client = ConversationClient(session, launch, deadline, wire, interpreter)
                        await client.check_status(expected_status)
                    yield client
                except (DiscussionError, KeyboardInterrupt, SystemExit) as error:
                    # Capture our explicit fixed error before SDK task-group
                    # exit can wrap it. Never select an arbitrary remote/group
                    # exception or parse its text into a trusted reason.
                    trusted_body_error = error
                    raise
    except BaseException as error:
        if trusted_body_error is not None:
            if error is not trusted_body_error and getattr(error, "__notes__", None):
                trusted_body_error.add_note("owned discussion context cleanup also failed")
            raise trusted_body_error
        if isinstance(error, (DiscussionError, KeyboardInterrupt, SystemExit)):
            raise
        if isinstance(error, anyio.get_cancelled_exc_class()):
            raise
        raise DiscussionError("transport_unavailable") from None
