"""Data models and configuration for Polyphony Swarm Resource Controller."""

from enum import Enum
import secrets
import time
from typing import Any, Dict, List, Optional
from pydantic import BaseModel, Field


class SignalType(str, Enum):
    SCALE_UP = "SCALE_UP"
    SPAWN_REVIEWER = "SPAWN_REVIEWER"
    IDLE_DRAIN = "IDLE_DRAIN"
    ESCALATE_TRIAGE = "ESCALATE_TRIAGE"


class HostSignalStatus(str, Enum):
    PENDING = "PENDING"
    ACKNOWLEDGED = "ACKNOWLEDGED"
    FULFILLED = "FULFILLED"
    REJECTED = "REJECTED"


class PolyphonyCohortConfig(BaseModel):
    """Configuration for an experimental standalone Polyphony swarm cohort."""

    swarm_id: str = Field(description="Unique cohort identifier")
    repo_url: str = Field(description="Target repository clone URL or path")
    workspace_path: str = Field(default="/workspace", description="Base workspace path")
    baseline_sha: Optional[str] = Field(default=None, description="Baseline git commit SHA")

    base_worker_count: int = Field(default=1, ge=0, description="Base baseline cohort size (e.g., 1 to 6)")
    max_burst_workers: int = Field(default=18, ge=1, description="Hard ceiling for dynamic scaling (e.g., 18 for 6x3)")
    max_host_budget: float = Field(default=100.0, ge=0.0, description="Maximum aggregate budget/cost ceiling allowed")
    estimated_worker_cost: float = Field(default=1.0, ge=0.0, description="Estimated marginal cost per spawned worker")

    swarm_key: str = Field(
        default_factory=lambda: secrets.token_hex(32),
        description="Shared secret key injected into cohort worker containers",
    )
    host_control_key: str = Field(
        default_factory=lambda: secrets.token_hex(32),
        description="Secret key retained strictly on OpenJules host controller (never injected into workers)",
    )

    escalation_webhook_url: Optional[str] = Field(
        default=None,
        description="Optional webhook URL to receive notifications when ESCALATE_TRIAGE is triggered",
    )
    liminal_db_path: Optional[str] = Field(
        default=None,
        description="Unsupported historical compatibility field; direct foreign SQLite transport is refused",
    )


class HostTelemetrySignal(BaseModel):
    """Signal emitted from Polyphony swarm to the OpenJules host resource controller."""

    signal_id: str
    emitted_by_actor: str
    signal_type: SignalType
    requested_worker_delta: int = 0
    target_task_ids: List[str] = Field(default_factory=list)
    unsettled_cost_snapshot: float = 0.0
    rationale: str = ""
    host_status: HostSignalStatus = HostSignalStatus.PENDING
    host_response_note: str = ""
    created_at: float = Field(default_factory=time.time)
    updated_at: float = Field(default_factory=time.time)


class WorkerContainerInfo(BaseModel):
    """State tracking for an active worker container provisioned by OpenJules."""

    container_id: str
    actor_id: str
    role: str = "worker"  # e.g. "worker", "reviewer"
    target_task_ids: List[str] = Field(default_factory=list)
    spawned_at: float = Field(default_factory=time.time)
    workspace_dir: Optional[str] = None
    is_burst: bool = False
    metadata: Dict[str, Any] = Field(default_factory=dict)
