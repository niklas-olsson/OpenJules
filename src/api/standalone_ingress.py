"""Fail-closed outer gate for default status and explicitly selected ingress.

The default selector remains status-only. Only a host-built configured app can
pass the explicitly supported routes to their authenticated policy adapter.
This module imports no execution or storage client.
"""

import os
import re

from fastapi import HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse

from src.worker.execution_context import LegacyExecutionRefused, require_legacy_execution

UNAVAILABLE = "standalone_ingress_unavailable"
POLICY_INVALID = "standalone_ingress_policy_invalid"
POLICY_UNSUPPORTED = "standalone_ingress_policy_unsupported"
POLICY_ENV = "OPENJULES_INGRESS_POLICY"
PUBLIC_HTTP_PATHS = frozenset({"/", "/health", "/static/standalone.css"})


def ingress_failure(status_code, code, receipt=None):
    """Closed configured-ingress projection without private submitted input."""
    status = "conflict" if status_code == 409 else "unsupported" if status_code == 404 else "unknown" if status_code == 503 else "refused"
    result = {
        "schema_version": 1, "protocol": "standalone-ingress-v1",
        "operation_id": None, "status": status, "dispatch_state": None,
        "managed_authority": False, "release_authorized": False, "code": code,
    }
    if receipt is not None:
        for name in ("operation_id", "dispatch_state", "result"):
            if name in receipt:
                result[name] = receipt[name]
    return result


def policy_status():
    """Classify the selector without reading a policy file or accepting grants."""
    selector = os.environ.get(POLICY_ENV)
    if selector is None:
        state, reason = "missing", UNAVAILABLE
    elif not selector.strip() or len(selector) > 4096 or "\x00" in selector:
        state, reason = "invalid", POLICY_INVALID
    else:
        state, reason = "unsupported", POLICY_UNSUPPORTED
    return {"state": "disabled", "policy": state, "reason": reason}


def refusal_reason(app):
    return getattr(app.state, "standalone_ingress", {}).get("reason", UNAVAILABLE)


def refuse_http(request: Request):
    """Also protects refusal-only routers mounted independently of the app."""
    try:
        require_legacy_execution()
    except LegacyExecutionRefused as exc:
        raise HTTPException(status_code=409, detail=exc.reason) from None
    raise HTTPException(status_code=503, detail=refusal_reason(request.app))


async def refuse_websocket(websocket: WebSocket):
    # Closing before accept refuses the upgrade and creates no subscription.
    try:
        require_legacy_execution()
        reason = refusal_reason(websocket.app)
    except LegacyExecutionRefused as exc:
        reason = exc.reason
    await websocket.close(code=1008, reason=reason)


class StandaloneIngressGate:
    """Admit only the exact harmless public files and health methods."""

    def __init__(self, app, reason=UNAVAILABLE, *, configured=False):
        self.app, self.reason = app, reason
        self.configured = configured

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        supported = self.configured and (
            (scope.get("method") == "POST" and scope.get("path") in {"/api/tasks", "/api/webhook"})
            or (scope.get("method") == "GET" and re.fullmatch(
                r"/api/ingress/receipts/[A-Za-z0-9_-]{1,128}", scope.get("path", "")) is not None)
            or (scope.get("method") == "GET" and re.fullmatch(
                r"/api/tasks/[A-Za-z0-9_-]{1,128}", scope.get("path", "")) is not None)
        )
        if kind == "http" and (
            scope["method"] not in {"GET", "HEAD"}
            or scope["path"] not in PUBLIC_HTTP_PATHS
        ):
            try:
                require_legacy_execution()
                status, reason = 503, self.reason
            except LegacyExecutionRefused as exc:
                status, reason = 409, exc.reason
                supported = False
            if supported:
                await self.app(scope, receive, send)
                return
            # Never receive/parse the body or enter a legacy router/callback.
            if self.configured:
                status = 404 if status == 503 else status
                content = ingress_failure(status, reason)
            else:
                content = {"detail": reason}
            response = JSONResponse(status_code=status, content=content,
                                    headers={"Cache-Control": "no-store"})
            await response(scope, receive, send)
            return
        if kind == "websocket":
            try:
                require_legacy_execution()
                reason = self.reason
            except LegacyExecutionRefused as exc:
                reason = exc.reason
            await send({"type": "websocket.close", "code": 1008, "reason": reason})
            return
        await self.app(scope, receive, send)
