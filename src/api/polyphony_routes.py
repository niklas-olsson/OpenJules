"""REST and WebSocket endpoints for Polyphony Swarm Cohort Management."""

import json
import logging
from typing import Any, Dict, List, Optional
from fastapi import APIRouter, HTTPException, WebSocket, WebSocketDisconnect
from pydantic import BaseModel, Field

from src.worker.execution_context import require_legacy_execution

require_legacy_execution()

from src.polyphony.models import (
    HostSignalStatus,
    HostTelemetrySignal,
    PolyphonyCohortConfig,
    SignalType,
)
from src.polyphony.registry import cohort_registry

logger = logging.getLogger(__name__)

polyphony_router = APIRouter(prefix="/api/polyphony", tags=["polyphony"])


class SignalTriggerRequest(BaseModel):
    signal_type: SignalType
    requested_worker_delta: int = 1
    target_task_ids: List[str] = Field(default_factory=list)
    unsettled_cost_snapshot: float = 0.0
    rationale: str = ""
    actor_id: str = "operator"


class CohortStatusResponse(BaseModel):
    swarm_id: str
    repo_url: str
    base_worker_count: int
    max_burst_workers: int
    max_host_budget: float
    internal_metered_cost: float
    active_worker_count: int
    base_workers: List[Dict[str, Any]]
    burst_workers: List[Dict[str, Any]]


# Simple connection manager for swarm WebSocket telemetry
class SwarmWebSocketManager:
    def __init__(self):
        self.active_connections: Dict[str, List[WebSocket]] = {}

    async def connect(self, swarm_id: str, websocket: WebSocket):
        await websocket.accept()
        if swarm_id not in self.active_connections:
            self.active_connections[swarm_id] = []
        self.active_connections[swarm_id].append(websocket)

    def disconnect(self, swarm_id: str, websocket: WebSocket):
        if swarm_id in self.active_connections:
            self.active_connections[swarm_id].remove(websocket)
            if not self.active_connections[swarm_id]:
                del self.active_connections[swarm_id]

    async def broadcast(self, swarm_id: str, data: Dict[str, Any]):
        if swarm_id in self.active_connections:
            for connection in list(self.active_connections[swarm_id]):
                try:
                    await connection.send_text(json.dumps(data))
                except Exception:
                    pass


swarm_ws_manager = SwarmWebSocketManager()


@polyphony_router.post("/cohorts", response_model=Dict[str, Any])
def create_cohort(config: PolyphonyCohortConfig):
    """Registers and bootstraps a managed Polyphony swarm cohort."""
    require_legacy_execution()
    if cohort_registry.get_controller(config.swarm_id):
        raise HTTPException(status_code=400, detail=f"Cohort '{config.swarm_id}' already exists")

    controller = cohort_registry.register_cohort(config, bootstrap=True)
    active = controller.provisioner.list_active_workers(swarm_id=config.swarm_id)
    return {
        "status": "created",
        "swarm_id": config.swarm_id,
        "base_workers_spawned": len(active),
    }


@polyphony_router.get("/cohorts", response_model=List[Dict[str, Any]])
def list_cohorts():
    """Lists all active cohorts."""
    cohorts = []
    for ctrl in cohort_registry.list_cohorts():
        active = ctrl.provisioner.list_active_workers(swarm_id=ctrl.config.swarm_id)
        cohorts.append({
            "swarm_id": ctrl.config.swarm_id,
            "repo_url": ctrl.config.repo_url,
            "base_worker_count": ctrl.config.base_worker_count,
            "max_burst_workers": ctrl.config.max_burst_workers,
            "active_worker_count": len(active),
            "internal_metered_cost": ctrl.internal_metered_cost,
        })
    return cohorts


@polyphony_router.get("/cohorts/{swarm_id}", response_model=CohortStatusResponse)
def get_cohort(swarm_id: str):
    """Inspects detailed status of a specific cohort."""
    ctrl = cohort_registry.get_controller(swarm_id)
    if not ctrl:
        raise HTTPException(status_code=404, detail="Cohort not found")

    active = ctrl.provisioner.list_active_workers(swarm_id=swarm_id)
    base_workers = [
        {"container_id": w.container_id, "actor_id": w.actor_id, "role": w.role}
        for w in active if not w.is_burst
    ]
    burst_workers = [
        {"container_id": w.container_id, "actor_id": w.actor_id, "role": w.role, "targets": w.target_task_ids}
        for w in active if w.is_burst
    ]

    return CohortStatusResponse(
        swarm_id=swarm_id,
        repo_url=ctrl.config.repo_url,
        base_worker_count=ctrl.config.base_worker_count,
        max_burst_workers=ctrl.config.max_burst_workers,
        max_host_budget=ctrl.config.max_host_budget,
        internal_metered_cost=ctrl.internal_metered_cost,
        active_worker_count=len(active),
        base_workers=base_workers,
        burst_workers=burst_workers,
    )


@polyphony_router.post("/cohorts/{swarm_id}/signal")
async def trigger_signal(swarm_id: str, req: SignalTriggerRequest):
    """Injects a signal and executes immediate reconciliation."""
    require_legacy_execution()
    ctrl = cohort_registry.get_controller(swarm_id)
    if not ctrl:
        raise HTTPException(status_code=404, detail="Cohort not found")

    import uuid, time
    sig = HostTelemetrySignal(
        signal_id=f"sig-{uuid.uuid4().hex[:8]}",
        emitted_by_actor=req.actor_id,
        signal_type=req.signal_type,
        requested_worker_delta=req.requested_worker_delta,
        target_task_ids=req.target_task_ids,
        unsettled_cost_snapshot=req.unsettled_cost_snapshot,
        rationale=req.rationale,
    )

    if hasattr(ctrl.outbox_bridge, "emit_signal"):
        ctrl.outbox_bridge.emit_signal(sig)
    elif hasattr(ctrl.outbox_bridge, "add_signal"):
        ctrl.outbox_bridge.add_signal(sig)

    results = ctrl.reconcile_signals()

    # Broadcast event to WebSocket
    await swarm_ws_manager.broadcast(swarm_id, {
        "event": "signal_reconciled",
        "signal": sig.model_dump(),
        "results": results,
    })

    return {"status": "reconciled", "signal_id": sig.signal_id, "results": results}


@polyphony_router.delete("/cohorts/{swarm_id}")
def delete_cohort(swarm_id: str):
    """Drains and terminates a cohort."""
    require_legacy_execution()
    success = cohort_registry.remove_cohort(swarm_id, drain_workers=True)
    if not success:
        raise HTTPException(status_code=404, detail="Cohort not found")
    return {"status": "deleted", "swarm_id": swarm_id}


@polyphony_router.websocket("/ws/{swarm_id}")
async def polyphony_websocket(websocket: WebSocket, swarm_id: str):
    """Real-time telemetry stream for a managed swarm."""
    await swarm_ws_manager.connect(swarm_id, websocket)
    try:
        while True:
            # Keepalive / ping
            await websocket.receive_text()
    except WebSocketDisconnect:
        swarm_ws_manager.disconnect(swarm_id, websocket)
