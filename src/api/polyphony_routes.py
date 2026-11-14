"""Unavailable standalone cohort ingress; no provisioner or registry imports."""

from fastapi import APIRouter
from src.worker.execution_context import require_legacy_execution
from src.api.standalone_ingress import refuse_http, refuse_websocket

require_legacy_execution()
polyphony_router = APIRouter(prefix="/api/polyphony", tags=["polyphony"])
for path, methods in (
    ("/cohorts", ["GET", "POST"]),
    ("/cohorts/{swarm_id}", ["GET", "DELETE"]),
    ("/cohorts/{swarm_id}/signal", ["POST"]),
):
    polyphony_router.add_api_route(path, refuse_http, methods=methods)
polyphony_router.add_api_websocket_route("/ws/{swarm_id}", refuse_websocket)
