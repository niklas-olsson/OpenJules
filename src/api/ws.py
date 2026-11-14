"""Standalone WebSocket upgrades are unavailable, with no subscriptions."""

from fastapi import APIRouter
from src.worker.execution_context import require_legacy_execution
from src.api.standalone_ingress import refuse_websocket

require_legacy_execution()
ws_router = APIRouter()
ws_router.add_api_websocket_route("/ws/tasks/{task_id}", refuse_websocket)
