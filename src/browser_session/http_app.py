"""Bounded same-origin HTTP application for an already owned session interlock.

This ASGI component binds no listener and starts no browser, dispatcher or
lifetime supervisor. The trusted host owns those independent tasks and supplies
``notify_pending`` solely to wake its existing dispatcher after durable submit.
An ASGI server must supply the actual HTTPS scheme and raw header pairs with
proxy-header inference disabled. A fixture's HTTPS scope is not TLS evidence.
There is no grant, browser-create, reconnect, or backend-handle route.
"""

from __future__ import annotations

import asyncio
import base64
from dataclasses import dataclass
import hashlib
from importlib.resources import files
import math
import threading

from .pairing import HEADER_NAME, SECURITY_HEADERS, PairingBroker, PairingDenied, RequestContext, _origin
from .types import SessionDenied, canonical, identifier, integer, strict_json


ASSETS = {"/": ("index.html", "text/html; charset=utf-8"),
          "/client/app.js": ("app.js", "text/javascript; charset=utf-8"),
          "/client/style.css": ("style.css", "text/css; charset=utf-8")}
RESULTS = {"result.json": "application/json", "events.json": "application/json", "screenshot.jpg": "image/jpeg"}
ACK_STATES = frozenset({"queued", "dispatched", "applied", "not_applied", "unknown", "confirmed", "pending", "failed"})
IDENTITY_FIELDS = ("session_id", "context_id", "target_id", "backend_epoch", "control_generation", "document_id", "document_generation")
ACTION_FIELDS = frozenset({"operation_id", "session_id", "context_id", "target_id", "control_generation",
                          "document_id", "document_generation", "observation_id", "action", "parameters"})


@dataclass(frozen=True)
class HTTPBounds:
    """Finite admitted application work; network-server custody is host-owned."""

    body_bytes: int = 16384
    response_bytes: int = 2097152
    ordinary_requests: int = 4096
    ordinary_response_bytes: int = 134217728
    ordinary_concurrency: int = 4
    owner_stop_requests: int = 4
    owner_stop_response_bytes: int = 65536
    owner_read_requests: int = 28
    owner_read_response_bytes: int = 196608
    request_seconds: float = 15.0
    body_seconds: float = 1.0
    send_seconds: float = 3.0

    def __post_init__(self):
        caps = {"body_bytes": 16384, "response_bytes": 2097152, "ordinary_requests": 4096,
                "ordinary_response_bytes": 134217728, "ordinary_concurrency": 4,
                "owner_stop_requests": 4, "owner_stop_response_bytes": 65536,
                "owner_read_requests": 28, "owner_read_response_bytes": 196608}
        for name, cap in caps.items():
            if type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= cap:
                raise ValueError("invalid HTTP bounds")
        for name, cap in (("request_seconds", 15), ("body_seconds", 1), ("send_seconds", 3)):
            value = getattr(self, name)
            if type(value) not in {int, float} or not math.isfinite(value) or not 0 < value <= cap:
                raise ValueError("invalid HTTP bounds")


class _Denied(Exception):
    def __init__(self, status, code):
        self.status, self.code = status, code


class _Disconnected(Exception):
    pass


def _json(value):
    return canonical(value).encode("ascii")


def _ack(record):
    """Never serialize the private ticket, grant digest, request or deadlines."""
    try:
        request = record["request"]
        operation_id, actor_id = identifier(request["operation_id"]), identifier(request["actor_id"])
        kind, state = request["kind"], record["state"]
        generation = integer(record["generation"])
        if kind not in {"action", "takeover", "handback", "stop"} or state not in ACK_STATES or type(record["audit_persisted"]) is not bool:
            raise ValueError()
        return {"schema_version": 1, "operation_id": operation_id, "actor_id": actor_id,
                "kind": kind, "state": state, "control_generation": generation,
                "audit_persisted": record["audit_persisted"]}
    except (KeyError, TypeError, ValueError):
        raise _Denied(503, "operation_projection_unavailable") from None


def _authorization(value):
    return {"actor_id": value.actor_id, "session_id": value.session_id, "context_id": value.context_id,
            "target_id": value.target_id, "binding_right": value.right, "binding_expires_at_ms": value.expires_at_ms}


class SessionHTTP:
    """An injected application, never an actor-facing host or browser object.

    The host keeps ``core.supervise()`` and a single dispatcher alive independently
    of this application. ``notify_pending()`` must only signal that dispatcher and
    return promptly. Failure to signal preserves the original queued intent.
    Startup, client reload, disconnect and ASGI shutdown do not acquire, resume
    or terminate native custody. Explicit owner Stop remains the core's action.
    """

    def __init__(self, core, pairing: PairingBroker, origin: str, *, notify_pending, bounds=HTTPBounds()):
        if type(pairing) is not PairingBroker or type(bounds) is not HTTPBounds or not callable(notify_pending):
            raise ValueError("invalid HTTP composition")
        self._origin, self._host = _origin(origin)
        self._core, self._pairing, self._notify, self._bounds = core, pairing, notify_pending, bounds
        self._lock = threading.Lock()
        self._active = self._stop_active = self._requests = self._stop_requests = 0
        self._bytes = self._stop_bytes = 0
        self._owner_read_active = self._owner_read_requests = self._owner_read_bytes = 0
        self._assets = {}
        for route, (name, content_type) in ASSETS.items():
            raw = files("src.browser_session").joinpath("client", name).read_bytes()
            if len(raw) > 65536:
                raise ValueError("oversized client asset")
            self._assets[route] = (raw, content_type)

    def _context(self, scope):
        method, path = scope.get("method"), scope.get("path")
        if (scope.get("scheme") != "https" or method not in {"GET", "POST"}
                or type(path) is not str or len(path) > 512 or not path.isascii()
                or not path.startswith("/") or "?" in path or "#" in path
                or scope.get("query_string", b"") != b""
                or scope.get("raw_path", path.encode()) != path.encode()):
            raise _Denied(400, "invalid_secure_request")
        raw = scope.get("headers")
        if type(raw) not in {list, tuple} or len(raw) > 64:
            raise _Denied(400, "invalid_headers")
        headers, selected, size = [], {}, 0
        for pair in raw:
            if type(pair) not in {list, tuple} or len(pair) != 2 or any(type(item) is not bytes for item in pair):
                raise _Denied(400, "invalid_headers")
            try:
                name, value = (item.decode("ascii") for item in pair)
            except UnicodeError:
                raise _Denied(400, "invalid_headers") from None
            size += len(name) + len(value)
            if (not HEADER_NAME.fullmatch(name) or len(name) > 128 or len(value) > 4096 or size > 16384
                    or any(ord(character) < 32 or ord(character) > 126 for character in value)):
                raise _Denied(400, "invalid_headers")
            lower = name.lower()
            if lower in SECURITY_HEADERS | {"content-length", "content-type", "transfer-encoding"}:
                if lower in selected:
                    raise _Denied(400, "duplicate_security_header")
                selected[lower] = value
            headers.append((name, value))
        if selected.get("host") != self._host or selected.get("origin", self._origin) != self._origin:
            raise _Denied(403, "origin_or_host_denied")
        if "transfer-encoding" in selected:
            raise _Denied(400, "unsupported_body_framing")
        length = selected.get("content-length", "0")
        if (not length.isascii() or not length.isdecimal() or len(length) > 6
                or str(int(length)) != length or int(length) > self._bounds.body_bytes
                or (method == "GET" and int(length) != 0)
                or (method == "POST" and ("content-length" not in selected or selected.get("content-type") != "application/json"))):
            raise _Denied(400, "invalid_body_bounds")
        return RequestContext(method, path, True, tuple(headers)), int(length)

    async def _body(self, receive, length, deadline):
        value = bytearray()
        async with asyncio.timeout_at(min(deadline, asyncio.get_running_loop().time() + self._bounds.body_seconds)):
            for _ in range(128):
                event = await receive()
                if event.get("type") == "http.disconnect":
                    raise _Disconnected()
                if event.get("type") != "http.request" or type(event.get("body", b"")) is not bytes:
                    raise _Denied(400, "invalid_body")
                value.extend(event.get("body", b""))
                if len(value) > length or len(value) > self._bounds.body_bytes:
                    raise _Denied(400, "invalid_body_bounds")
                more = event.get("more_body", False)
                if type(more) is not bool:
                    raise _Denied(400, "invalid_body")
                if not more:
                    break
            else:
                raise _Denied(400, "body_chunk_budget")
        if len(value) != length:
            raise _Denied(400, "incomplete_body")
        return bytes(value)

    @staticmethod
    def _object(raw, keys):
        value = strict_json(raw)
        if type(value) is not dict or set(value) != set(keys):
            raise _Denied(400, "invalid_request_shape")
        return value

    def _session(self, request, state):
        view = self._pairing.session(request)
        if view.authorization.right == "stop":
            self._charge_owner("owner_read")
            state["response_lane"] = "owner_read"
        rights = {}
        for right in ("observe", "control", "stop"):
            try:
                auth = self._pairing.authorize_request(request, right=right, method="GET", path="/session")
                rights[right] = {"available": True, "expires_at_ms": auth.authorization.expires_at_ms}
            except PairingDenied:
                rights[right] = {"available": False, "expires_at_ms": None}
        return {"schema_version": 1, **_authorization(view.authorization), "csrf_token": view.csrf_token,
                "cookie_expires_at_ms": view.expires_at_ms, "rights": rights}

    def _observation(self, token):
        view = self._core.observe(token)
        value = {name: view[name] for name in IDENTITY_FIELDS}
        value.update(schema_version=1, mode=view["mode"], actor_id=view["actor_id"], audit_available=view["audit_available"],
                     server_time_ms=self._core.clock.wall_ms(), frame_max_age_ms=self._core.spec.limits.frame_age_ms,
                     corrections=[{name: row[name] for name in ("operation_id", "actor_id", "text", "generation")}
                                  for row in view["corrections"]],
                     results=[{"name": name, "sha256": row["sha256"], "bytes": row["bytes"]}
                              for name, row in sorted(view["results"].items()) if name in RESULTS], frame=None)
        if view["frame"] is not None:
            frame = view["frame"]
            value["frame"] = {name: frame[name] for name in
                ("session_id", "context_id", "target_id", "backend_epoch", "control_generation", "document_id",
                 "sequence", "captured_at_ms", "width", "height", "projection", "jpeg_sha256", "observation_id")}
            value["frame"]["jpeg_base64"] = base64.b64encode(frame["jpeg"]).decode("ascii")
        return value

    def _charge_owner(self, lane):
        with self._lock:
            if lane == "stop":
                if self._stop_requests >= self._bounds.owner_stop_requests:
                    raise _Denied(429, "owner_stop_request_budget")
                self._stop_requests += 1
            else:
                if self._owner_read_requests >= self._bounds.owner_read_requests:
                    raise _Denied(429, "owner_read_request_budget")
                self._owner_read_requests += 1

    def _lane(self, request):
        """Only a current authenticated purpose may reserve owner capacity.

        This is an admission precheck, not a lease. The actual route rechecks
        the original right again after bounded body receipt. Polling/reload
        has a different slot and allowance from the Stop mutation itself.
        """
        try:
            if request.method == "POST" and request.path == "/stop":
                self._pairing.authorize_request(request, right="stop", method="POST", path="/stop")
                return "stop"
            if request.method == "GET" and request.path.startswith("/stop-operations/"):
                self._pairing.authorize_request(request, right="stop", method="GET", path=request.path)
                return "owner_read"
            if request.method == "GET" and request.path == "/session" and self._pairing.session(request).authorization.right == "stop":
                return "owner_read"
        except PairingDenied:
            pass
        return "ordinary"

    async def _route(self, request, raw, state):
        path, method = request.path, request.method
        if method == "GET" and path in self._assets:
            content, content_type = self._assets[path]
            return 200, content, content_type, []
        if path == "/pair" and method == "POST":
            reply = self._pairing.redeem(request, raw)
            return 200, _json({"schema_version": 1, **_authorization(reply.authorization),
                "csrf_token": reply.csrf_token, "cookie_expires_at_ms": reply.expires_at_ms}), "application/json", [("set-cookie", reply.set_cookie)]
        if path == "/session" and method == "GET":
            return 200, _json(self._session(request, state)), "application/json", []
        if path == "/observation" and method == "GET":
            auth = self._pairing.authorize_request(request, right="observe", method=method, path=path)
            return 200, _json(self._observation(auth.grant_token)), "application/json", []
        if method == "GET" and path.startswith("/results/") and path[9:] in RESULTS:
            auth = self._pairing.authorize_request(request, right="observe", method=method, path=path)
            content = self._core.read_result(auth.grant_token, path[9:])
            return 200, content, RESULTS[path[9:]], [("x-content-sha256", hashlib.sha256(content).hexdigest())]
        if method == "GET" and (path.startswith("/operations/") or path.startswith("/stop-operations/")):
            stop = path.startswith("/stop-operations/")
            key = identifier(path[len("/stop-operations/") if stop else len("/operations/"):])
            auth = self._pairing.authorize_request(request, right="stop" if stop else "observe", method=method, path=path)
            if stop:
                self._charge_owner("owner_read")
                state["response_lane"] = "owner_read"
            record = self._core.stop_operation(auth.grant_token, key) if stop else self._core.operation(auth.grant_token, key)
            return 200, _json(_ack(record)), "application/json", []
        if method != "POST" or path not in {"/actions", "/takeover", "/handback", "/stop"}:
            raise _Denied(404, "route_unavailable")
        auth = self._pairing.authorize_request(request, right="stop" if path == "/stop" else "control", method=method, path=path)
        if path == "/stop":
            self._charge_owner("stop")
            state["response_lane"] = "stop"
        fields = ACTION_FIELDS if path == "/actions" else {"operation_id"}
        if path in {"/takeover", "/handback"}:
            fields = fields | {"control_generation"}
        if path == "/handback":
            fields = fields | {"observation_id"}
        value = self._object(raw, fields)
        state["operation_id"] = identifier(value["operation_id"])
        state["effect_requested"] = True
        if path == "/actions":
            record = self._core.submit(auth.grant_token, **value)
            notice = "not_needed"
            if record["state"] == "queued":
                try:
                    self._notify()
                    notice = "sent"
                except Exception:
                    # The durable original intent remains. Never replay it
                    # under another key or call the browser from this route.
                    notice = "unknown"
            return 202, _json(_ack(record) | {"dispatch_notice": notice}), "application/json", []
        if path == "/takeover":
            record = await self._core.takeover(auth.grant_token, **value)
        elif path == "/handback":
            record = await self._core.handback(auth.grant_token, **value)
        else:
            record = await self._core.stop(auth.grant_token, **value)
        return 200, _json(_ack(record)), "application/json", []

    async def _send(self, send, status, body, content_type, extra, *, lane, deadline):
        maximum = 16777216 if any(key == "x-content-sha256" for key, _ in extra) else self._bounds.response_bytes
        if len(body) > maximum:
            status, body, content_type, extra = 503, _json({"error": "response_bounds"}), "application/json", []
        with self._lock:
            used = {"stop": self._stop_bytes, "owner_read": self._owner_read_bytes, "ordinary": self._bytes}[lane]
            cap = {"stop": self._bounds.owner_stop_response_bytes, "owner_read": self._bounds.owner_read_response_bytes,
                   "ordinary": self._bounds.ordinary_response_bytes}[lane]
            if used + len(body) > cap:
                status, body, extra = 429, b"", []
            if lane == "stop":
                self._stop_bytes += len(body)
            elif lane == "owner_read":
                self._owner_read_bytes += len(body)
            else:
                self._bytes += len(body)
        headers = [("content-type", content_type), ("content-length", str(len(body))), ("cache-control", "no-store"),
            ("referrer-policy", "no-referrer"), ("x-content-type-options", "nosniff"), ("x-frame-options", "DENY"),
            ("cross-origin-resource-policy", "same-origin"), ("cross-origin-opener-policy", "same-origin"),
            ("content-security-policy", "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' blob:; connect-src 'self'; base-uri 'none'; form-action 'self'; frame-ancestors 'none'")]
        end = min(deadline, asyncio.get_running_loop().time() + self._bounds.send_seconds)
        if asyncio.get_running_loop().time() >= end:
            raise TimeoutError()
        async with asyncio.timeout_at(end):
            await send({"type": "http.response.start", "status": status,
                        "headers": [(key.encode("ascii"), value.encode("ascii")) for key, value in headers + extra]})
            if asyncio.get_running_loop().time() >= end:
                raise TimeoutError()
            await send({"type": "http.response.body", "body": body})
            if asyncio.get_running_loop().time() >= end:
                raise TimeoutError()

    async def __call__(self, scope, receive, send):
        if scope.get("type") == "lifespan":
            # Application lifecycle does not own or infer browser lifetime.
            while True:
                event = await receive()
                if event["type"] == "lifespan.startup":
                    await send({"type": "lifespan.startup.complete"})
                elif event["type"] == "lifespan.shutdown":
                    await send({"type": "lifespan.shutdown.complete"})
                    return
        if scope.get("type") == "websocket":
            await send({"type": "websocket.close", "code": 1008})
            return
        if scope.get("type") != "http":
            raise _Denied(400, "unsupported_transport")
        lane = "ordinary"
        acquired = False
        state = {"response_lane": "ordinary", "operation_id": None, "effect_requested": False}
        deadline = asyncio.get_running_loop().time() + self._bounds.request_seconds
        try:
            try:
                request, length = self._context(scope)
                lane = self._lane(request)
                with self._lock:
                    if lane == "stop":
                        if self._stop_active >= 1:
                            raise _Denied(429, "owner_stop_request_busy")
                        self._stop_active += 1
                    elif lane == "owner_read":
                        if self._owner_read_active >= 1:
                            raise _Denied(429, "owner_read_request_busy")
                        self._owner_read_active += 1
                    else:
                        if self._active >= self._bounds.ordinary_concurrency or self._requests >= self._bounds.ordinary_requests:
                            raise _Denied(429, "ordinary_request_budget")
                        self._active += 1
                        self._requests += 1
                    acquired = True
                async with asyncio.timeout_at(deadline):
                    raw = await self._body(receive, length, deadline)
                    status, body, content_type, extra = await self._route(request, raw, state)
                    if asyncio.get_running_loop().time() >= deadline:
                        raise TimeoutError()
            except _Disconnected:
                return
            except _Denied as error:
                status, body, content_type, extra = error.status, _json({"error": error.code}), "application/json", []
            except (PairingDenied, SessionDenied):
                status, body, content_type, extra = 403, _json({"error": "authority_or_state_denied"}), "application/json", []
            except Exception:
                payload = {"error": "operation_outcome_unknown" if state["effect_requested"] else "session_unavailable"}
                if state["operation_id"] is not None:
                    payload["operation_id"] = state["operation_id"]
                status, body, content_type, extra = 503, _json(payload), "application/json", []
            try:
                await self._send(send, status, body, content_type, extra, lane=state["response_lane"], deadline=deadline)
            except (ConnectionError, OSError, TimeoutError):
                # A lost reply leaves the original core operation available by key.
                pass
        finally:
            if acquired:
                with self._lock:
                    if lane == "stop":
                        self._stop_active -= 1
                    elif lane == "owner_read":
                        self._owner_read_active -= 1
                    else:
                        self._active -= 1
