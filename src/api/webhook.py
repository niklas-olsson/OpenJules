"""Harmless standalone status service; all private/effectful ingress is disabled."""

import hashlib
import hmac
from pathlib import Path
from typing import Optional

from fastapi import FastAPI
from fastapi.responses import FileResponse

from src.worker.execution_context import require_legacy_execution

# Preserve managed-interpreter refusal before even the safe router imports.
require_legacy_execution()

from src.api.standalone_ingress import StandaloneIngressGate, policy_status, refuse_http
from src.api.polyphony_routes import polyphony_router
from src.api.ui_routes import ui_router
from src.api.ws import ws_router


def verify_github_signature(payload_body: bytes, signature_header: Optional[str], secret: str) -> bool:
    """Pure HMAC check retained for future adapters; it grants no admission."""
    if not secret or not signature_header:
        return False
    parts = signature_header.split("=", 1)
    if len(parts) != 2 or parts[0] != "sha256":
        return False
    expected = hmac.new(secret.encode("utf-8"), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected, parts[1])


def create_app():
    require_legacy_execution()
    status = policy_status()
    app = FastAPI(
        title="OpenJules standalone status", version="0.3.0",
        description="Health/static service; task and cohort ingress unavailable.",
        docs_url=None, redoc_url=None, openapi_url=None,
    )
    app.state.standalone_ingress = status
    app.add_middleware(StandaloneIngressGate, reason=status["reason"])
    app.include_router(ui_router)
    app.include_router(ws_router)
    app.include_router(polyphony_router)
    app.add_api_route("/api/webhook", refuse_http, methods=["POST"])
    app.add_api_route("/api/radicle/webhook", refuse_http, methods=["POST"])

    static_dir = Path(__file__).resolve().parents[1] / "ui" / "static"
    headers = {
        "Cache-Control": "no-store", "X-Content-Type-Options": "nosniff",
        "Content-Security-Policy": "default-src 'none'; style-src 'self'; base-uri 'none'; form-action 'none'; frame-ancestors 'none'",
    }

    @app.api_route("/", methods=["GET", "HEAD"])
    def dashboard():
        return FileResponse(static_dir / "standalone.html", headers=headers)

    @app.api_route("/static/standalone.css", methods=["GET", "HEAD"])
    def stylesheet():
        return FileResponse(static_dir / "standalone.css", media_type="text/css", headers=headers)

    @app.api_route("/health", methods=["GET", "HEAD"])
    def health():
        return {"status": "ok", "service": "openjules", "standalone_ingress": dict(status)}

    return app


app = create_app()
