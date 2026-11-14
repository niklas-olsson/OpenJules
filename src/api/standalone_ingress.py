"""Disabled standalone ingress until an authenticated policy adapter is qualified.

No policy value, credential, origin or caller-supplied flag enables an operation
in this intermediate delivery. This module imports no execution/storage client.
"""

import os

from fastapi import HTTPException, Request, WebSocket
from fastapi.responses import JSONResponse

from src.worker.execution_context import LegacyExecutionRefused, require_legacy_execution

UNAVAILABLE = "standalone_ingress_unavailable"
POLICY_INVALID = "standalone_ingress_policy_invalid"
POLICY_UNSUPPORTED = "standalone_ingress_policy_unsupported"
POLICY_ENV = "OPENJULES_INGRESS_POLICY"
PUBLIC_HTTP_PATHS = frozenset({"/", "/health", "/static/standalone.css"})


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

    def __init__(self, app, reason=UNAVAILABLE):
        self.app, self.reason = app, reason

    async def __call__(self, scope, receive, send):
        kind = scope["type"]
        if kind == "http" and (
            scope["method"] not in {"GET", "HEAD"}
            or scope["path"] not in PUBLIC_HTTP_PATHS
        ):
            try:
                require_legacy_execution()
                status, reason = 503, self.reason
            except LegacyExecutionRefused as exc:
                status, reason = 409, exc.reason
            # Never receive/parse the body or enter a legacy router/callback.
            response = JSONResponse(status_code=status, content={"detail": reason})
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
