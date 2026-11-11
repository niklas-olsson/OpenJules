"""In-memory registry managing active Polyphony swarm cohorts."""

import logging
from typing import Dict, List, Optional

from src.polyphony.controller import SwarmResourceController
from src.polyphony.models import PolyphonyCohortConfig
from src.polyphony.outbox import BaseOutboxBridge, SQLiteOutboxBridge
from src.polyphony.provisioner import ContainerProvisionerProtocol, DockerContainerProvisioner
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)


class SwarmCohortRegistry:
    """Registry managing active Polyphony cohort controllers across the OpenJules service."""

    def __init__(self, default_provisioner: Optional[ContainerProvisionerProtocol] = None):
        require_legacy_execution()
        self.default_provisioner = default_provisioner or DockerContainerProvisioner()
        self._controllers: Dict[str, SwarmResourceController] = {}

    def register_cohort(
        self,
        config: PolyphonyCohortConfig,
        outbox_bridge: Optional[BaseOutboxBridge] = None,
        provisioner: Optional[ContainerProvisionerProtocol] = None,
        bootstrap: bool = True,
    ) -> SwarmResourceController:
        """Registers a new cohort and optionally bootstraps its base worker pool."""
        require_legacy_execution()
        bridge = outbox_bridge or SQLiteOutboxBridge(config.liminal_db_path or f"/tmp/polyphony_{config.swarm_id}.db")
        prov = provisioner or self.default_provisioner

        controller = SwarmResourceController(
            config=config,
            outbox_bridge=bridge,
            provisioner=prov,
        )
        if bootstrap:
            controller.bootstrap_cohort()

        self._controllers[config.swarm_id] = controller
        logger.info(f"Registered cohort {config.swarm_id} (base workers: {config.base_worker_count})")
        return controller

    def get_controller(self, swarm_id: str) -> Optional[SwarmResourceController]:
        return self._controllers.get(swarm_id)

    def list_cohorts(self) -> List[SwarmResourceController]:
        return list(self._controllers.values())

    def remove_cohort(self, swarm_id: str, drain_workers: bool = True) -> bool:
        require_legacy_execution()
        if swarm_id in self._controllers:
            ctrl = self._controllers[swarm_id]
            if drain_workers:
                for w in ctrl.provisioner.list_active_workers(swarm_id=swarm_id):
                    ctrl.provisioner.stop_worker(w.container_id)
            del self._controllers[swarm_id]
            return True
        return False


# Global singleton registry instance
cohort_registry = SwarmCohortRegistry()
