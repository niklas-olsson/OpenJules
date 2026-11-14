"""Worker health checker and self-healing manager for Polyphony swarms.

Monitors active worker sandboxes, detects dead/crashed containers, cleans up orphaned state,
and respawns base workers to maintain cohort resilience.
"""

import logging
import time
from typing import Callable, Dict, List, Optional

from src.polyphony.controller import SwarmResourceController
from src.polyphony.models import WorkerContainerInfo

logger = logging.getLogger(__name__)


class WorkerHealthMonitor:
    """Monitors worker container liveness and triggers self-healing for dropped base workers."""

    def __init__(
        self,
        controller: SwarmResourceController,
        liveness_check: Optional[Callable[[str], bool]] = None,
    ):
        self.controller = controller
        # Optional external liveness probe (e.g. docker container inspect status == 'running')
        self.liveness_check = liveness_check

    def check_and_heal(self) -> Dict[str, any]:
        """Inspects all workers for the cohort, reaps dead containers, and replenishes base workers."""
        self.controller.require_unpaused()
        swarm_id = self.controller.config.swarm_id
        active = self.controller.provisioner.list_active_workers(swarm_id=swarm_id)

        dead_workers: List[WorkerContainerInfo] = []
        healthy_workers: List[WorkerContainerInfo] = []

        for worker in active:
            is_healthy = True
            if self.liveness_check:
                try:
                    is_healthy = self.liveness_check(worker.container_id)
                except Exception as e:
                    logger.warning(f"Liveness probe failed for {worker.container_id}: {e}")
                    is_healthy = False

            if is_healthy:
                healthy_workers.append(worker)
            else:
                dead_workers.append(worker)

        # Reap dead workers
        reaped_ids = []
        for dead in dead_workers:
            logger.warning(
                f"Worker {dead.actor_id} (container {dead.container_id}) failed liveness check. Reaping..."
            )
            self.controller.provisioner.stop_worker(dead.container_id)
            reaped_ids.append(dead.actor_id)

        # Respawn base workers if healthy count is below base_worker_count
        healthy_base_count = len([w for w in healthy_workers if not w.is_burst])
        needed_base = max(0, self.controller.config.base_worker_count - healthy_base_count)

        replenished = []
        for _ in range(needed_base):
            new_worker = self.controller.provisioner.spawn_worker(
                config=self.controller.config,
                actor_id=f"jules-healed-{int(time.time()*1000)%1000000}",
                role="worker",
                is_burst=False,
            )
            replenished.append(new_worker.actor_id)
            self.controller.internal_metered_cost += self.controller.config.estimated_worker_cost
            logger.info(f"Replenished base worker: {new_worker.actor_id}")

        return {
            "swarm_id": swarm_id,
            "reaped_dead_workers": reaped_ids,
            "replenished_base_workers": replenished,
            "current_total_active": len(self.controller.provisioner.list_active_workers(swarm_id=swarm_id)),
        }
