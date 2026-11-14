"""Unavailable standalone task/private-read routes; no storage construction."""

from fastapi import APIRouter
from src.worker.execution_context import require_legacy_execution
from src.api.standalone_ingress import refuse_http

require_legacy_execution()
ui_router = APIRouter()

for path, methods in (
    ("/api/tasks", ["GET", "POST"]),
    ("/api/tasks/{task_id}", ["GET"]),
    ("/api/tasks/{task_id}/diff", ["GET"]),
    ("/api/tasks/{task_id}/comments", ["POST"]),
    ("/api/tasks/{task_id}/command", ["POST"]),
    ("/api/polyphony/state", ["GET"]),
):
    ui_router.add_api_route(path, refuse_http, methods=methods)
