"""Polyphony Swarm Resource Controller and dynamic cohort scaling loop.

OpenJules acts as the external Resource & Execution Host:
- Reconciles signals from Polyphony's host_signal_outbox
- Manages dynamic cohort scaling: SCALE_UP, SPAWN_REVIEWER, IDLE_DRAIN, ESCALATE_TRIAGE
- Enforces hardware/budget quotas and two-key security boundary
"""

import json
import hashlib
import logging
import threading
import uuid
from typing import Any, Dict, List, Optional
import urllib.request
import urllib.error

from src.polyphony.models import (
    HostSignalStatus,
    HostTelemetrySignal,
    PolyphonyCohortConfig,
    SignalType,
    WorkerContainerInfo,
)
from src.polyphony.outbox import BaseOutboxBridge, OutboxError, OutboxOutcome, unsupported
from src.polyphony.provisioner import ContainerProvisionerProtocol
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)
MAX_RETAINED_SIGNALS = 4096


def _experimental(result):
    """Host resource observations never convey canonical or release authority."""
    return {**result, "managed_authority": False, "release_authorized": False}


class SwarmResourceController:
    """Host-side controller reconciling Polyphony swarm signals with container resources."""

    def __init__(
        self,
        config: PolyphonyCohortConfig,
        outbox_bridge: BaseOutboxBridge,
        provisioner: ContainerProvisionerProtocol,
    ):
        require_legacy_execution()
        if outbox_bridge is None:
            raise unsupported()
        if config.liminal_db_path is not None:
            raise unsupported("direct_sql_host_signals_unsupported")
        outbox_bridge.ensure_available()
        self.config = config
        self.outbox_bridge = outbox_bridge
        self.provisioner = provisioner
        self.internal_metered_cost: float = 0.0
        self._attempted_signals: Dict[str, Dict[str, Any]] = {}
        self.reconciliation_required: Optional[Dict[str, Any]] = None
        self._loop_lock = threading.Lock()

    def require_unpaused(self) -> None:
        require_legacy_execution()
        if self.reconciliation_required is not None:
            raise OutboxError(OutboxOutcome.UNKNOWN, "cohort_reconciliation_required")
        self.outbox_bridge.ensure_available()

    @staticmethod
    def _fingerprint(signal):
        # Status timestamps may change after acknowledgement; only the original
        # advice identity/payload binds the attempted host action.
        data = signal.model_dump(mode="json", exclude={"host_status", "host_response_note", "updated_at"})
        return hashlib.sha256(json.dumps(data, sort_keys=True, separators=(",", ":")).encode()).hexdigest()

    def _mark_attempt(self, signal, *, acknowledgement=False):
        if signal.signal_id not in self._attempted_signals:
            if len(self._attempted_signals) >= MAX_RETAINED_SIGNALS:
                self.reconciliation_required = _experimental({
                    "status": "RECONCILIATION_REQUIRED", "signal_id": signal.signal_id,
                    "reason": "attempted_signal_capacity_reached", "outcome": "UNKNOWN",
                })
                raise OutboxError(OutboxOutcome.UNKNOWN, "attempted_signal_capacity_reached")
            self._attempted_signals[signal.signal_id] = {
                "fingerprint": self._fingerprint(signal), "host_action_attempts": 0,
                "acknowledgement_attempted": False,
            }
        record = self._attempted_signals[signal.signal_id]
        if acknowledgement:
            record["acknowledgement_attempted"] = True
        else:
            record["host_action_attempts"] += 1

    def _acknowledge(self, signal, status, note):
        self._mark_attempt(signal, acknowledgement=True)
        if self.outbox_bridge.acknowledge_signal(signal.signal_id, status, note) is not True:
            raise OutboxError(OutboxOutcome.REFUSED, "host_signal_acknowledgement_refused")

    def _failure(self, error, signal=None):
        result = _experimental({"status": error.outcome.value, "outcome": error.outcome.value, "reason": error.code})
        if signal is not None:
            result["signal_id"] = signal.signal_id
        if self.reconciliation_required is not None or (signal is not None and signal.signal_id in self._attempted_signals):
            result["status"] = "RECONCILIATION_REQUIRED"
            self.reconciliation_required = result.copy()
        return result

    def bootstrap_cohort(self) -> List[WorkerContainerInfo]:
        """Spawns the initial base cohort workers up to base_worker_count."""
        self.require_unpaused()
        active = self.provisioner.list_active_workers(swarm_id=self.config.swarm_id)
        current_count = len(active)
        needed = self.config.base_worker_count - current_count

        spawned = []
        for _ in range(max(0, needed)):
            actor_id = f"jules-worker-{uuid.uuid4().hex[:8]}"
            try:
                worker = self.provisioner.spawn_worker(
                    config=self.config, actor_id=actor_id, role="worker",
                    target_task_ids=[], is_burst=False,
                )
                if not isinstance(worker, WorkerContainerInfo) or worker.actor_id != actor_id:
                    raise ValueError("bootstrap response did not preserve the attempted actor")
            except Exception:
                self.reconciliation_required = _experimental({
                    "status": "RECONCILIATION_REQUIRED", "reason": "bootstrap_action_unknown",
                    "outcome": "UNKNOWN", "actor_id": actor_id,
                })
                raise OutboxError(OutboxOutcome.UNKNOWN, "bootstrap_action_unknown") from None
            spawned.append(worker)
            self.internal_metered_cost += self.config.estimated_worker_cost
            logger.info(f"Bootstrapped base worker {actor_id} (container {worker.container_id})")

        return spawned

    def reconcile_signals(self) -> List[Dict[str, Any]]:
        """Executes one pass of the reconciliation loop over pending outbox signals."""
        require_legacy_execution()
        if self.reconciliation_required is not None:
            return [self.reconciliation_required.copy()]
        if not self._loop_lock.acquire(blocking=False):
            return [_experimental({"status": "UNKNOWN", "outcome": "UNKNOWN", "reason": "reconciliation_in_progress"})]
        try:
            try:
                self.outbox_bridge.ensure_available()
                signals = self.outbox_bridge.poll_pending_signals()
            except OutboxError as error:
                return [self._failure(error)]
            except Exception:
                return [self._failure(OutboxError(OutboxOutcome.UNKNOWN, "host_signal_poll_unknown"))]
            results = []
            for signal in signals:
                previous = self._attempted_signals.get(signal.signal_id)
                if previous is not None:
                    if previous["fingerprint"] != self._fingerprint(signal):
                        results.append(self._failure(OutboxError(OutboxOutcome.UNKNOWN, "attempted_signal_changed"), signal))
                        break
                    results.append(_experimental({"signal_id": signal.signal_id, "status": "ALREADY_ATTEMPTED",
                                                  "reason": "host_action_not_repeated"}))
                    continue
                try:
                    results.append(_experimental(self._handle_signal(signal)))
                except OutboxError as error:
                    results.append(self._failure(error, signal))
                except Exception:
                    results.append(self._failure(OutboxError(OutboxOutcome.UNKNOWN, "host_signal_action_unknown"), signal))
                if self.reconciliation_required is not None:
                    break
            return results
        finally:
            self._loop_lock.release()

    def _handle_signal(self, signal: HostTelemetrySignal) -> Dict[str, Any]:
        if signal.signal_type == SignalType.SCALE_UP:
            return self._handle_scale_up(signal)
        elif signal.signal_type == SignalType.SPAWN_REVIEWER:
            return self._handle_spawn_reviewer(signal)
        elif signal.signal_type == SignalType.IDLE_DRAIN:
            return self._handle_idle_drain(signal)
        elif signal.signal_type == SignalType.ESCALATE_TRIAGE:
            return self._handle_escalate_triage(signal)
        else:
            self._acknowledge(
                signal,
                HostSignalStatus.REJECTED,
                f"Unknown signal type: {signal.signal_type}",
            )
            return {"signal_id": signal.signal_id, "status": "REJECTED", "reason": "Unknown signal"}

    def _handle_scale_up(self, signal: HostTelemetrySignal) -> Dict[str, Any]:
        active_workers = self.provisioner.list_active_workers(swarm_id=self.config.swarm_id)
        current_active = len(active_workers)

        # Composite accounting: Effective Burn = max(signal.unsettled_cost_snapshot, controller.internal_metered_cost)
        effective_burn = max(signal.unsettled_cost_snapshot, self.internal_metered_cost)

        # Calculate allowable delta capped by max_burst_workers
        available_slots = self.config.max_burst_workers - current_active
        allowed_delta = min(signal.requested_worker_delta, available_slots)

        if allowed_delta <= 0:
            reason = f"Cohort at or above max burst capacity ({current_active}/{self.config.max_burst_workers})"
            self._acknowledge(signal, HostSignalStatus.REJECTED, reason)
            return {"signal_id": signal.signal_id, "status": "REJECTED", "reason": reason}

        # Check projected budget with allowed_delta
        projected_cost = effective_burn + (allowed_delta * self.config.estimated_worker_cost)
        if projected_cost > self.config.max_host_budget:
            reason = (
                f"Budget ceiling exceeded: projected {projected_cost:.2f} > max {self.config.max_host_budget:.2f} "
                f"(effective burn: {effective_burn:.2f})"
            )
            self._acknowledge(signal, HostSignalStatus.REJECTED, reason)
            return {"signal_id": signal.signal_id, "status": "REJECTED", "reason": reason}

        # Spawn allowed_delta workers
        spawned = []
        for _ in range(allowed_delta):
            actor_id = f"jules-worker-{uuid.uuid4().hex[:8]}"
            self._mark_attempt(signal)
            worker = self.provisioner.spawn_worker(
                config=self.config,
                actor_id=actor_id,
                role="worker",
                target_task_ids=signal.target_task_ids,
                is_burst=True,
            )
            if not isinstance(worker, WorkerContainerInfo) or worker.actor_id != actor_id:
                raise OutboxError(OutboxOutcome.UNKNOWN, "worker_spawn_not_confirmed")
            spawned.append(worker)
            self.internal_metered_cost += self.config.estimated_worker_cost

        note = f"Spawned {len(spawned)} burst workers (total active: {current_active + len(spawned)})"
        self._acknowledge(signal, HostSignalStatus.FULFILLED, note)
        return {
            "signal_id": signal.signal_id,
            "status": "FULFILLED",
            "spawned_workers": [w.actor_id for w in spawned],
        }

    def _handle_spawn_reviewer(self, signal: HostTelemetrySignal) -> Dict[str, Any]:
        # Always spawn 1 ephemeral reviewer container with distinct actor_id
        reviewer_actor_id = f"jules-reviewer-{uuid.uuid4().hex[:8]}"
        self._mark_attempt(signal)
        worker = self.provisioner.spawn_worker(
            config=self.config,
            actor_id=reviewer_actor_id,
            role="reviewer",
            target_task_ids=signal.target_task_ids,
            is_burst=True,
        )
        if not isinstance(worker, WorkerContainerInfo) or worker.actor_id != reviewer_actor_id:
            raise OutboxError(OutboxOutcome.UNKNOWN, "worker_spawn_not_confirmed")
        self.internal_metered_cost += self.config.estimated_worker_cost
        note = f"Spawned ephemeral reviewer {reviewer_actor_id} for target tasks {signal.target_task_ids}"
        self._acknowledge(signal, HostSignalStatus.FULFILLED, note)
        return {
            "signal_id": signal.signal_id,
            "status": "FULFILLED",
            "reviewer_actor_id": reviewer_actor_id,
        }

    def _handle_idle_drain(self, signal: HostTelemetrySignal) -> Dict[str, Any]:
        active_workers = self.provisioner.list_active_workers(swarm_id=self.config.swarm_id)
        burst_workers = [w for w in active_workers if w.is_burst]

        # Determine target number of workers to keep
        # If all tasks are accepted or requested delta drains down to base_worker_count
        # Sort burst workers by spawn time (oldest or newest, FIFO)
        drained_count = 0
        reaped_workers = []

        # Observe the entire candidate set before any stop. A missing or failed
        # observation is neither idle nor permission to acknowledge a drain.
        activity = {}
        for worker in burst_workers:
            try:
                count = self.outbox_bridge.count_active_leases(worker.actor_id)
            except OutboxError:
                raise
            except Exception:
                raise OutboxError(OutboxOutcome.UNKNOWN, "worker_activity_observation_unknown") from None
            if count is None:
                raise unsupported("worker_activity_observation_unsupported")
            if type(count) is not int or count < 0:
                raise OutboxError(OutboxOutcome.UNKNOWN, "worker_activity_observation_unknown")
            activity[worker.actor_id] = count

        for worker in burst_workers:
            # Active lease guard: check Polyphony store for active leases
            active_leases = activity[worker.actor_id]
            if active_leases > 0:
                logger.info(f"Skipping drain for {worker.actor_id} because it holds {active_leases} active lease(s)")
                continue

            # Ensure we don't drain below base_worker_count unless requested delta specifies total drain
            current_total = len(self.provisioner.list_active_workers(swarm_id=self.config.swarm_id))
            if current_total <= self.config.base_worker_count and signal.requested_worker_delta <= 0:
                break

            self._mark_attempt(signal)
            success = self.provisioner.stop_worker(worker.container_id)
            if success is True:
                drained_count += 1
                reaped_workers.append(worker.actor_id)
                if signal.requested_worker_delta > 0 and drained_count >= signal.requested_worker_delta:
                    break
            else:
                raise OutboxError(OutboxOutcome.UNKNOWN, "worker_stop_not_confirmed")

        note = f"Reaped {drained_count} idle burst workers: {reaped_workers}"
        self._acknowledge(signal, HostSignalStatus.FULFILLED, note)
        return {
            "signal_id": signal.signal_id,
            "status": "FULFILLED",
            "drained_count": drained_count,
            "reaped_workers": reaped_workers,
        }

    def _handle_escalate_triage(self, signal: HostTelemetrySignal) -> Dict[str, Any]:
        logger.error(
            f"Swarm escalation triggered for swarm {self.config.swarm_id} by {signal.emitted_by_actor}: "
            f"{signal.rationale} (targets: {signal.target_task_ids})",
            extra={
                "swarm_id": self.config.swarm_id,
                "signal_id": signal.signal_id,
                "emitted_by": signal.emitted_by_actor,
                "target_task_ids": signal.target_task_ids,
                "rationale": signal.rationale,
            },
        )

        response_note = "Escalation logged to operator"
        if self.config.escalation_webhook_url:
            webhook_payload = json.dumps({
                "swarm_id": self.config.swarm_id,
                "signal_id": signal.signal_id,
                "actor_id": signal.emitted_by_actor,
                "targets": signal.target_task_ids,
                "rationale": signal.rationale,
            }).encode("utf-8")

            req = urllib.request.Request(
                self.config.escalation_webhook_url,
                data=webhook_payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            try:
                self._mark_attempt(signal)
                with urllib.request.urlopen(req, timeout=5) as resp:
                    response_note = f"Escalation webhook dispatched, HTTP status {resp.status}"
            except OutboxError:
                raise
            except Exception:
                raise OutboxError(OutboxOutcome.UNKNOWN, "escalation_delivery_unknown") from None

        self._acknowledge(signal, HostSignalStatus.ACKNOWLEDGED, response_note)
        return {
            "signal_id": signal.signal_id,
            "status": "ACKNOWLEDGED",
            "response_note": response_note,
        }
