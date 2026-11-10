"""Docker sandbox runtime and container management for OpenJules."""

import logging
import math
import os
import queue
import shutil
import tempfile
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass
from typing import Any, Callable, Dict, Generator, Optional
from urllib.parse import urlparse, urlunparse

import docker
from docker.errors import NotFound

from src.sandbox.config import OpenJulesConfig

logger = logging.getLogger(__name__)


@dataclass
class ExecResult:
    """Result of command execution within a container."""

    stdout: str
    stderr: str
    exit_code: int


@dataclass(frozen=True)
class CleanupResult:
    """Observed cleanup facts; a stop request is not a termination receipt."""

    termination_confirmed: bool
    artifact_capture_confirmed: bool
    container_removed: bool = False
    workspace_removed: bool = False
    execution_pending: bool = False
    reason: str = ""


class SandboxExecutionUnknown(RuntimeError):
    """Execution has no confirmed result and must not be retried blindly."""

    def __init__(self, message: str, container_id: str, termination_confirmed: bool = False):
        super().__init__(message)
        self.container_id = container_id
        self.termination_confirmed = termination_confirmed


class SandboxExecTimeout(SandboxExecutionUnknown, TimeoutError):
    """The command deadline expired; termination may still be unknown."""


class SandboxCleanupError(RuntimeError):
    """A context cannot report a clean stop while execution is unresolved."""

    def __init__(self, result: CleanupResult):
        super().__init__(result.reason)
        self.result = result


class SandboxLaunchUnknown(RuntimeError):
    """A failed create response is not proof that Docker created nothing."""

    def __init__(self, workspace_dir: str):
        super().__init__("Sandbox creation is unresolved; workspace retained for recovery")
        self.workspace_dir = workspace_dir


class _ExchangeUnavailable(RuntimeError):
    pass


class _CallDeadline(TimeoutError):
    pass


@dataclass
class SandboxContext:
    """Context information for an active sandbox container."""

    container_id: str
    workspace_dir: str
    repo_url: str
    branch: str
    config: OpenJulesConfig
    # Only a trusted caller that saved the work durably may set this flag.
    # The existing executor has no capture receipt, so it retains work by default.
    artifact_capture_confirmed: bool = False
    cleanup_result: Optional[CleanupResult] = None


class SandboxManager:
    """Bounds Docker exchanges and preserves work until capture is acknowledged."""

    def __init__(
        self,
        docker_client: Optional[docker.DockerClient] = None,
        *,
        operation_timeout: float = 5.0,
        max_pending_exchanges: int = 16,
    ):
        if (
            isinstance(operation_timeout, bool)
            or not isinstance(operation_timeout, (int, float))
            or not math.isfinite(operation_timeout)
            or operation_timeout <= 0
        ):
            raise ValueError("operation_timeout must be positive and finite")
        if type(max_pending_exchanges) is not int or max_pending_exchanges < 1:
            raise ValueError("max_pending_exchanges must be a positive integer")
        self.operation_timeout = operation_timeout
        self._exchange_slots = threading.BoundedSemaphore(max_pending_exchanges)
        self._state_lock = threading.Lock()
        self._active_executions: set[str] = set()
        self._quarantined: set[str] = set()
        if docker_client is not None:
            self.client = docker_client
        else:
            docker_host = os.environ.get("DOCKER_HOST")
            if docker_host:
                self.client = docker.DockerClient(base_url=docker_host)
            else:
                self.client = docker.from_env()

    def _bounded_call(
        self,
        operation: Callable[[], Any],
        deadline: float,
        *,
        execution: Optional[str] = None,
    ) -> Any:
        """Wait for a bounded exchange without blocking on a hung SDK thread.

        Docker requests can outlive a client timeout. Slots remain occupied until
        those requests actually return; they are never refunded by a timeout.
        """
        if time.monotonic() >= deadline:
            raise _CallDeadline("Docker operation deadline expired")
        if not self._exchange_slots.acquire(blocking=False):
            raise _ExchangeUnavailable("Pending Docker exchange limit reached")
        if execution is not None:
            with self._state_lock:
                if execution in self._quarantined or execution in self._active_executions:
                    self._exchange_slots.release()
                    raise _ExchangeUnavailable("Sandbox is active or requires reconciliation")
                self._active_executions.add(execution)
        result: queue.Queue = queue.Queue(maxsize=1)
        caller_finished = threading.Event()
        exchange_finished = threading.Event()
        execution_released = False

        def release_execution():
            # Keep admission closed until both the SDK exchange and its caller
            # have handled the outcome. Otherwise a second command could start
            # between an unknown result and the caller quarantining the sandbox.
            nonlocal execution_released
            if execution is not None:
                with self._state_lock:
                    if not execution_released and caller_finished.is_set() and exchange_finished.is_set():
                        execution_released = True
                        self._active_executions.discard(execution)

        def run():
            try:
                if time.monotonic() >= deadline:
                    raise _CallDeadline("Docker operation deadline expired")
                outcome = (True, operation())
            except BaseException as exc:
                outcome = (False, exc)
            finally:
                exchange_finished.set()
                release_execution()
                self._exchange_slots.release()
            result.put(outcome)

        # A daemon avoids interpreter shutdown waiting forever for a broken
        # Docker connection. The cap above prevents an unbounded thread leak.
        thread = threading.Thread(target=run, daemon=True, name="openjules-docker")
        try:
            thread.start()
        except BaseException:
            if execution is not None:
                with self._state_lock:
                    self._active_executions.discard(execution)
            self._exchange_slots.release()
            raise
        try:
            try:
                succeeded, value = result.get(timeout=max(0.0, deadline - time.monotonic()))
            except queue.Empty:
                raise _CallDeadline("Docker operation deadline expired") from None
            if time.monotonic() > deadline:
                raise _CallDeadline("Docker operation deadline expired")
            if not succeeded:
                raise value
            return value
        except BaseException:
            if execution is not None:
                with self._state_lock:
                    self._quarantined.add(execution)
            raise
        finally:
            caller_finished.set()
            release_execution()

    @staticmethod
    def _stopped(container) -> bool:
        container.reload()
        state = container.attrs.get("State", {})
        return (
            state.get("Running") is False
            and state.get("Restarting") is not True
            and state.get("Paused") is not True
        )

    def _stop(self, container_id: str) -> tuple[bool, bool]:
        """Return (termination confirmed, container already absent)."""
        def stop():
            try:
                container = self.client.containers.get(container_id)
                if container.id != container_id:
                    raise ValueError("An immutable container ID is required")
                container.stop(timeout=2)
                return self._stopped(container), False
            except NotFound:
                return True, True

        return self._bounded_call(stop, time.monotonic() + self.operation_timeout)

    @staticmethod
    def _inject_git_token(repo_url: str, git_token: Optional[str]) -> str:
        """Inject GitHub token into HTTPS repo URL if provided."""
        if not git_token or not repo_url.startswith("https://"):
            return repo_url
        parsed = urlparse(repo_url)
        # format: https://x-access-token:<token>@github.com/...
        netloc = f"x-access-token:{git_token}@{parsed.hostname}"
        if parsed.port:
            netloc += f":{parsed.port}"
        return urlunparse(
            (parsed.scheme, netloc, parsed.path, parsed.params, parsed.query, parsed.fragment)
        )

    def spawn_sandbox(
        self,
        repo_url: str,
        branch: str,
        config: OpenJulesConfig,
        git_token: Optional[str] = None,
        workspace_base_dir: Optional[str] = None,
    ) -> SandboxContext:
        """Provisions a container with resource constraints, mounts workspace, and clones repo.

        Resource constraints: mem_limit="4g", nano_cpus=2000000000 (2 CPUs).
        """
        temp_dir = tempfile.mkdtemp(prefix="openjules_ws_", dir=workspace_base_dir)

        # Build environment dictionary
        env = dict(config.env)
        env["DEBIAN_FRONTEND"] = "noninteractive"
        env["PYTHONUNBUFFERED"] = "1"

        try:
            # Mount host temp_dir to /workspace inside container
            volumes = {
                temp_dir: {
                    "bind": "/workspace",
                    "mode": "rw",
                }
            }

            container = self.client.containers.run(
                image=config.image,
                command="tail -f /dev/null",  # Keep container running
                detach=True,
                volumes=volumes,
                working_dir="/workspace",
                mem_limit="4g",
                nano_cpus=2000000000,
                environment=env,
                network_mode="bridge",
            )
            container_id = container.id

            context = SandboxContext(
                container_id=container_id,
                workspace_dir=temp_dir,
                repo_url=repo_url,
                branch=branch,
                config=config,
            )

            # Clone the repository
            auth_repo_url = self._inject_git_token(repo_url, git_token)
            clone_cmd = f"git clone --branch {branch} --depth 1 {auth_repo_url} /workspace"
            res = self.exec_in_sandbox(container_id, clone_cmd, timeout=config.timeout_seconds)
            if res.exit_code != 0:
                # If branch didn't exist or single-branch failed, try full clone or fallback
                fallback_cmd = f"git clone {auth_repo_url} /workspace"
                res_fallback = self.exec_in_sandbox(
                    container_id, fallback_cmd, timeout=config.timeout_seconds
                )
                if res_fallback.exit_code != 0:
                    raise RuntimeError(
                        f"Failed to clone repository: {res.stderr or res_fallback.stderr}"
                    )
                # Check out the branch or create it if missing
                self.exec_in_sandbox(
                    container_id,
                    f"git checkout {branch} 2>/dev/null || git checkout -b {branch}",
                    timeout=30,
                )

            # Execute setup commands defined in .openjules.yaml
            for setup_cmd in config.setup:
                setup_res = self.exec_in_sandbox(
                    container_id, setup_cmd, timeout=config.timeout_seconds
                )
                if setup_res.exit_code != 0:
                    logger.warning(
                        f"Setup command '{setup_cmd}' failed with code {setup_res.exit_code}: {setup_res.stderr}"
                    )

            return context

        except Exception:
            # A failed create reply may hide a live container using this mount.
            # A confirmed stop also does not prove that useful work was saved.
            if "container" in locals():
                result = self.cleanup_sandbox(container.id, temp_dir)
                logger.warning(
                    "Failed sandbox initialization retained work: container_id=%s workspace_dir=%s reason=%s",
                    container.id,
                    temp_dir,
                    result.reason,
                )
            else:
                raise SandboxLaunchUnknown(temp_dir) from None
            raise

    def exec_in_sandbox(
        self,
        container_id: str,
        cmd: str,
        timeout: int = 120,
        workdir: str = "/workspace",
        env: Optional[Dict[str, str]] = None,
    ) -> ExecResult:
        """Bound command execution and reject unconfirmed exit as a success.

        Timeout stops the whole sandbox to include descendants. A Docker outage
        may prevent confirmation; in that case the exception remains explicit
        and further commands on this sandbox are denied.
        """
        if isinstance(timeout, bool) or not isinstance(timeout, (int, float)):
            raise ValueError("timeout must be a positive finite number")
        if not math.isfinite(timeout) or timeout <= 0:
            raise ValueError("timeout must be a positive finite number")
        deadline = time.monotonic() + timeout

        def check_dispatch():
            if time.monotonic() >= deadline:
                raise _CallDeadline("Docker operation deadline expired")
            with self._state_lock:
                if container_id in self._quarantined:
                    raise SandboxExecutionUnknown("Sandbox command admission is closed", container_id)

        def execute():
            container = self.client.containers.get(container_id)
            if container.id != container_id:
                raise ValueError("An immutable container ID is required")
            check_dispatch()
            exec_instance = self.client.api.exec_create(
                container=container_id,
                cmd=["/bin/sh", "-c", cmd],
                workdir=workdir,
                environment=env,
                stdout=True,
                stderr=True,
            )
            # A delayed create must not start a fresh process after its approved
            # deadline or after cleanup closed admission while it was pending.
            check_dispatch()
            output = self.client.api.exec_start(exec_instance["Id"], stream=False, demux=True)
            if time.monotonic() >= deadline:
                raise _CallDeadline("Docker operation deadline expired")
            inspected = self.client.api.exec_inspect(exec_instance["Id"])
            if inspected.get("Running") is not False or type(inspected.get("ExitCode")) is not int:
                raise SandboxExecutionUnknown("Docker did not confirm command exit", container_id)
            return output, inspected["ExitCode"]

        try:
            output_stream, exit_code = self._bounded_call(execute, deadline, execution=container_id)
        except _ExchangeUnavailable:
            # No new exchange was started. Do not create extra stop threads on
            # each retry of an already quarantined or pending sandbox.
            raise
        except BaseException as exc:
            with self._state_lock:
                self._quarantined.add(container_id)
            termination_confirmed = False
            try:
                termination_confirmed, _ = self._stop(container_id)
            except Exception:
                pass
            if not isinstance(exc, Exception):
                raise
            error = SandboxExecTimeout if isinstance(exc, _CallDeadline) else SandboxExecutionUnknown
            message = (
                "Sandbox command timed out; further execution requires reconciliation"
                if error is SandboxExecTimeout
                else "Sandbox command outcome is unknown; further execution requires reconciliation"
            )
            raise error(message, container_id, termination_confirmed) from None

        stdout_bytes, stderr_bytes = (b"", b"")
        if isinstance(output_stream, tuple):
            stdout_bytes, stderr_bytes = output_stream
        elif isinstance(output_stream, bytes):
            stdout_bytes = output_stream

        stdout_str = stdout_bytes.decode("utf-8", errors="replace") if stdout_bytes else ""
        stderr_str = stderr_bytes.decode("utf-8", errors="replace") if stderr_bytes else ""
        return ExecResult(
            stdout=stdout_str,
            stderr=stderr_str,
            exit_code=exit_code,
        )

    def cleanup_sandbox(
        self,
        container_id: str,
        workspace_dir: Optional[str] = None,
        *,
        artifact_capture_confirmed: bool = False,
    ) -> CleanupResult:
        """Stop first; retain the container and workspace until work is captured.

        The capture flag is a trusted caller acknowledgement of durable storage,
        not something inferred from a successful command or a model's answer.
        """
        if type(artifact_capture_confirmed) is not bool:
            raise ValueError("artifact_capture_confirmed must be a boolean")
        with self._state_lock:
            # Cleanup is terminal for this sandbox, even if the stop response
            # or a previously started exec exchange arrives later.
            self._quarantined.add(container_id)
        try:
            stopped, removed = self._stop(container_id)
        except Exception:
            stopped, removed = False, False
        with self._state_lock:
            pending = container_id in self._active_executions
        if not stopped or pending:
            return CleanupResult(
                termination_confirmed=stopped,
                artifact_capture_confirmed=artifact_capture_confirmed,
                container_removed=removed,
                execution_pending=pending,
                reason="Termination or Docker execution remains unresolved; work retained",
            )
        if not artifact_capture_confirmed:
            return CleanupResult(
                termination_confirmed=True,
                artifact_capture_confirmed=False,
                container_removed=removed,
                reason="Durable artifact capture is unconfirmed; container and workspace retained",
            )

        if not removed:
            def remove():
                try:
                    container = self.client.containers.get(container_id)
                    if container.id != container_id or not self._stopped(container):
                        return False
                    # Never force deletion across a state race. Docker rejects
                    # ordinary removal if a container has become active again.
                    container.remove(v=True)
                    return True
                except NotFound:
                    return True

            try:
                removed = self._bounded_call(remove, time.monotonic() + self.operation_timeout)
            except Exception:
                removed = False
        if not removed:
            return CleanupResult(
                # A second observation may have found the container active
                # again, or the removal reply may be lost. Do not retain the
                # earlier stopped observation as a current release receipt.
                termination_confirmed=False,
                artifact_capture_confirmed=True,
                reason="Container removal is unconfirmed; workspace retained",
            )
        workspace_removed = not workspace_dir or not os.path.lexists(workspace_dir)
        if workspace_dir and not workspace_removed:
            try:
                shutil.rmtree(workspace_dir)
                workspace_removed = True
            except OSError:
                pass
        return CleanupResult(
            termination_confirmed=True,
            artifact_capture_confirmed=True,
            container_removed=True,
            workspace_removed=workspace_removed,
            reason="Cleanup confirmed" if workspace_removed else "Workspace removal failed; retry is safe",
        )

    @contextmanager
    def run_sandbox(
        self,
        repo_url: str,
        branch: str,
        config: OpenJulesConfig,
        git_token: Optional[str] = None,
        workspace_base_dir: Optional[str] = None,
    ) -> Generator[SandboxContext, None, None]:
        """Stop on exit and expose cleanup facts; preserve uncaptured work."""
        context = self.spawn_sandbox(
            repo_url=repo_url,
            branch=branch,
            config=config,
            git_token=git_token,
            workspace_base_dir=workspace_base_dir,
        )
        body_failed = False
        try:
            yield context
        except BaseException:
            body_failed = True
            raise
        finally:
            try:
                context.cleanup_result = self.cleanup_sandbox(
                    context.container_id,
                    context.workspace_dir,
                    artifact_capture_confirmed=context.artifact_capture_confirmed,
                )
            except Exception:
                if not body_failed:
                    raise
                # Even an unexpected cleanup implementation or argument failure
                # must not replace the task's original failure.
                context.cleanup_result = CleanupResult(
                    termination_confirmed=False,
                    artifact_capture_confirmed=False,
                    execution_pending=True,
                    reason="Cleanup failed unexpectedly; termination and capture are unconfirmed",
                )
            if not context.cleanup_result.workspace_removed:
                logger.warning(
                    "Sandbox work retained: container_id=%s workspace_dir=%s reason=%s",
                    context.container_id,
                    context.workspace_dir,
                    context.cleanup_result.reason,
                )
            if not body_failed and (
                not context.cleanup_result.termination_confirmed or context.cleanup_result.execution_pending
            ):
                raise SandboxCleanupError(context.cleanup_result)
