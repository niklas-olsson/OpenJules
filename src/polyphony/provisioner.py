"""Container provisioner protocol and adapters for Polyphony Swarm workers.

Abstracts the container runtime so the SwarmResourceController can spawn, monitor, and
terminate workers via Docker/local Sandboxes or deterministic Mock Provisioners.
"""

from abc import ABC, abstractmethod
import logging
import os
import shutil
import tempfile
import time
import uuid
from typing import Dict, List, Optional

from src.polyphony.bootstrap import WorkerBootstrapBuilder, WorkerBootstrapPackage
from src.polyphony.models import PolyphonyCohortConfig, WorkerContainerInfo
from src.sandbox.config import OpenJulesConfig
from src.sandbox.docker_driver import SandboxManager
from src.worker.execution_context import require_legacy_execution

logger = logging.getLogger(__name__)


class ContainerProvisionerProtocol(ABC):
    """Protocol for managing cohort worker sandboxes/containers."""

    @abstractmethod
    def spawn_worker(
        self,
        config: PolyphonyCohortConfig,
        actor_id: str,
        role: str = "worker",
        target_task_ids: Optional[List[str]] = None,
        is_burst: bool = False,
    ) -> WorkerContainerInfo:
        """Spawns an isolated worker container pre-seeded with bootstrap configuration."""
        pass

    @abstractmethod
    def stop_worker(self, container_id: str) -> bool:
        """Gracefully stops and reaps a worker container."""
        pass

    @abstractmethod
    def list_active_workers(self, swarm_id: Optional[str] = None) -> List[WorkerContainerInfo]:
        """Lists currently active worker containers managed by the provisioner."""
        pass

    @abstractmethod
    def get_worker(self, container_id: str) -> Optional[WorkerContainerInfo]:
        """Retrieves details of a specific container."""
        pass


class DockerContainerProvisioner(ContainerProvisionerProtocol):
    """Production provisioner backed by Docker SandboxManager."""

    def __init__(self, sandbox_manager: Optional[SandboxManager] = None):
        require_legacy_execution()
        self.sandbox_manager = sandbox_manager or SandboxManager()
        self._workers: Dict[str, WorkerContainerInfo] = {}

    def spawn_worker(
        self,
        config: PolyphonyCohortConfig,
        actor_id: str,
        role: str = "worker",
        target_task_ids: Optional[List[str]] = None,
        is_burst: bool = False,
    ) -> WorkerContainerInfo:
        require_legacy_execution()
        bootstrap_pkg = WorkerBootstrapBuilder.build(
            config=config,
            actor_id=actor_id,
            role=role,
            target_task_ids=target_task_ids,
        )

        # Build sandbox config with injected environment
        sb_config = OpenJulesConfig(
            env=bootstrap_pkg.env_vars,
        )

        ctx = self.sandbox_manager.spawn_sandbox(
            repo_url=config.repo_url,
            branch=config.baseline_sha or "main",
            config=sb_config,
        )

        # Inject AGENTS.md directly into the workspace root
        agents_md_path = os.path.join(ctx.workspace_dir, "AGENTS.md")
        try:
            with open(agents_md_path, "w", encoding="utf-8") as f:
                f.write(bootstrap_pkg.agents_md_content)
        except Exception as e:
            logger.warning(f"Could not write AGENTS.md to {agents_md_path}: {e}")

        info = WorkerContainerInfo(
            container_id=ctx.container_id,
            actor_id=actor_id,
            role=role,
            target_task_ids=target_task_ids or [],
            spawned_at=time.time(),
            workspace_dir=ctx.workspace_dir,
            is_burst=is_burst,
            metadata={"swarm_id": config.swarm_id},
        )
        self._workers[info.container_id] = info
        return info

    def stop_worker(self, container_id: str) -> bool:
        require_legacy_execution()
        if container_id in self._workers:
            info = self._workers[container_id]
            self.sandbox_manager.cleanup_sandbox(container_id, info.workspace_dir)
            del self._workers[container_id]
            return True
        return False

    def list_active_workers(self, swarm_id: Optional[str] = None) -> List[WorkerContainerInfo]:
        workers = list(self._workers.values())
        if swarm_id:
            workers = [w for w in workers if w.metadata.get("swarm_id") == swarm_id]
        return workers

    def get_worker(self, container_id: str) -> Optional[WorkerContainerInfo]:
        return self._workers.get(container_id)


class MockContainerProvisioner(ContainerProvisionerProtocol):
    """Deterministic in-memory provisioner for fast unit tests."""

    def __init__(self):
        self._workers: Dict[str, WorkerContainerInfo] = {}
        self.spawn_history: List[WorkerContainerInfo] = []
        self.stopped_containers: List[str] = []
        self.injected_packages: Dict[str, WorkerBootstrapPackage] = {}

    def spawn_worker(
        self,
        config: PolyphonyCohortConfig,
        actor_id: str,
        role: str = "worker",
        target_task_ids: Optional[List[str]] = None,
        is_burst: bool = False,
    ) -> WorkerContainerInfo:
        pkg = WorkerBootstrapBuilder.build(
            config=config,
            actor_id=actor_id,
            role=role,
            target_task_ids=target_task_ids,
        )
        container_id = f"mock-container-{uuid.uuid4().hex[:8]}"
        self.injected_packages[container_id] = pkg

        info = WorkerContainerInfo(
            container_id=container_id,
            actor_id=actor_id,
            role=role,
            target_task_ids=target_task_ids or [],
            spawned_at=time.time(),
            workspace_dir=f"/tmp/mock_ws_{container_id}",
            is_burst=is_burst,
            metadata={"swarm_id": config.swarm_id},
        )
        self._workers[container_id] = info
        self.spawn_history.append(info)
        return info

    def stop_worker(self, container_id: str) -> bool:
        if container_id in self._workers:
            self.stopped_containers.append(container_id)
            del self._workers[container_id]
            return True
        return False

    def list_active_workers(self, swarm_id: Optional[str] = None) -> List[WorkerContainerInfo]:
        workers = list(self._workers.values())
        if swarm_id:
            workers = [w for w in workers if w.metadata.get("swarm_id") == swarm_id]
        return workers

    def get_worker(self, container_id: str) -> Optional[WorkerContainerInfo]:
        return self._workers.get(container_id)
