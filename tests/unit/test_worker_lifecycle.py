"""Adversarial contract tests, including a real subprocess runtime fixture.

The fixture is not a production coding worker or Polyphony integration proof.
"""

from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict, replace
from pathlib import Path
import subprocess
import sys
from tempfile import TemporaryDirectory
from threading import Event, Lock
import unittest

from src.worker.lifecycle import (
    LifecycleConflict,
    RuntimeCapabilities,
    RuntimeObservation,
    RuntimeUnavailable,
    WorkerLifecycle,
    WorkerNotFound,
    WorkerScope,
    WorkerSpec,
)


class ContractRuntime:
    """Explicit deterministic fixture, never a default production backend."""

    def __init__(self):
        self.results = {}
        self.launches = 0
        self.stops = 0
        self.available = True
        self.lose_launch_response = False
        self.crash_before_launch = False
        self.lock = Lock()

    def capabilities(self, scope, profile):
        return RuntimeCapabilities(
            self.available, profile == "fixture", self.available, "Contract fixture"
        )

    def ensure(self, worker_id, spec):
        with self.lock:
            if worker_id in self.results:
                return self.results[worker_id]
            if self.crash_before_launch:
                raise SystemExit("injected supervisor crash")
            self.launches += 1
            result = RuntimeObservation("ready", runtime_id="runtime-" + worker_id)
            self.results[worker_id] = result
        if self.lose_launch_response:
            raise ConnectionError("injected lost response")
        return result

    def observe(self, worker_id, spec, runtime_id):
        return self.results.get(
            worker_id, RuntimeObservation("unknown", reason="Fixture cannot prove launch outcome")
        )

    def drain(self, worker_id, spec, runtime_id):
        with self.lock:
            if worker_id not in self.results:
                self.results[worker_id] = RuntimeObservation(
                    "stopped", not_started=True, launch_fenced=True,
                    termination_confirmed=True, artifacts_captured=True,
                )
            return self.results[worker_id]

    def stop(self, worker_id, spec, runtime_id):
        with self.lock:
            previous = self.results.get(worker_id)
            if previous and previous.state == "stopped" and previous.launch_fenced:
                return previous
            self.stops += 1
            result = RuntimeObservation(
                "stopped", runtime_id=runtime_id, not_started=runtime_id is None,
                termination_confirmed=True, artifacts_captured=True, launch_fenced=True,
            )
            self.results[worker_id] = result
            return result


class SubprocessFixture(ContractRuntime):
    """Real process lifecycle and captured output, without a coding provider."""

    def __init__(self, root):
        super().__init__()
        self.root = Path(root)
        self.processes = {}

    def ensure(self, worker_id, spec):
        if worker_id in self.results:
            return self.results[worker_id]
        self.launches += 1
        process = subprocess.Popen(
            [sys.executable, "-u", "-c", "print('fixture-work'); input()"],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        self.processes[worker_id] = process
        # Synchronize fixture startup without claiming authority readiness from PID.
        output = process.stdout.readline()
        (self.root / (worker_id + ".started")).write_text(output)
        observation = RuntimeObservation("ready", runtime_id=f"fixture-{worker_id}-{process.pid}")
        self.results[worker_id] = observation
        return observation

    def stop(self, worker_id, spec, runtime_id):
        if self.results[worker_id].state == "stopped":
            return self.results[worker_id]
        self.stops += 1
        process = self.processes[worker_id]
        if self.results[worker_id].runtime_id != runtime_id:
            raise AssertionError("fixture would signal a different incarnation")
        process.terminate()
        stdout, stderr = process.communicate(timeout=5)
        artifact = (self.root / (worker_id + ".started")).read_text() + stdout + stderr
        (self.root / (worker_id + ".artifact")).write_text(artifact)
        observation = RuntimeObservation(
            "stopped", runtime_id=runtime_id,
            termination_confirmed=process.poll() is not None, artifacts_captured=True,
            launch_fenced=True,
        )
        self.results[worker_id] = observation
        return observation

    def close(self):
        for process in self.processes.values():
            if process.poll() is None:
                process.kill()
            process.communicate(timeout=5)


class LifecycleTests(unittest.TestCase):
    def setUp(self):
        self.directory = TemporaryDirectory()
        self.database = Path(self.directory.name) / "runtime.sqlite"
        self.runtime = ContractRuntime()
        self.service = WorkerLifecycle(self.database, self.runtime)
        self.scope = WorkerScope("deployment-a", "github:github.com/example/repo")
        self.spec = WorkerSpec(
            self.scope.deployment_id, self.scope.repository, "slot-0", 1, "launch-0", "fixture"
        )

    def tearDown(self):
        self.directory.cleanup()

    def test_concurrent_duplicate_ensure_has_one_incarnation(self):
        other = WorkerLifecycle(self.database, self.runtime)
        with ThreadPoolExecutor(max_workers=2) as pool:
            results = list(pool.map(lambda service: service.ensure_worker(self.spec), [self.service, other]))
        self.assertEqual(results[0]["worker_id"], results[1]["worker_id"])
        self.assertEqual(self.runtime.launches, 1)
        with self.assertRaises(LifecycleConflict):
            self.service.ensure_worker(replace(self.spec, profile="different"))
        with self.assertRaises(LifecycleConflict):
            self.service.ensure_worker(replace(self.spec, launch_key="different"))

    def test_lost_response_recovers_same_launch_after_reopen(self):
        self.runtime.lose_launch_response = True
        first = self.service.ensure_worker(self.spec)
        self.assertEqual(first["state"], "unknown")
        reopened = WorkerLifecycle(self.database, self.runtime)
        found = reopened.discover_workers(self.scope, self.spec.launch_key)
        self.assertEqual(len(found), 1)
        self.assertEqual(found[0]["worker_id"], first["worker_id"])
        self.assertEqual(found[0]["state"], "ready")
        self.assertEqual(reopened.ensure_worker(self.spec)["worker_id"], first["worker_id"])
        self.assertEqual(self.runtime.launches, 1)

    def test_crash_before_dispatch_resumes_same_incarnation_after_reopen(self):
        self.runtime.crash_before_launch = True
        with self.assertRaises(SystemExit):
            self.service.ensure_worker(self.spec)
        reopened = WorkerLifecycle(self.database, self.runtime)
        held = reopened.discover_workers(self.scope)[0]
        self.assertEqual(held["state"], "unknown")
        self.assertEqual(self.runtime.launches, 0)
        with self.assertRaises(LifecycleConflict):
            self.service.ensure_worker(replace(self.spec, generation=2, launch_key="new-launch"))
        self.runtime.crash_before_launch = False
        recovered = reopened.ensure_worker(self.spec)
        self.assertEqual(recovered["worker_id"], held["worker_id"])
        self.assertEqual(recovered["state"], "ready")
        self.assertEqual(self.runtime.launches, 1)

    def test_stop_cannot_release_while_ensure_is_still_dispatching(self):
        entered, release = Event(), Event()
        original_ensure = self.runtime.ensure

        def delayed_ensure(worker_id, spec):
            entered.set()
            if not release.wait(5):
                raise RuntimeError("test synchronization timeout")
            return original_ensure(worker_id, spec)

        self.runtime.ensure = delayed_ensure
        other = WorkerLifecycle(self.database, self.runtime)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.service.ensure_worker, self.spec)
            self.assertTrue(entered.wait(5))
            try:
                worker = other.discover_workers(self.scope)[0]["worker_id"]
                stopped = other.stop_worker(self.scope, worker, "stop")
                self.assertEqual(stopped["state"], "unknown")
                self.assertFalse(stopped["admission_open"])
                self.assertFalse(stopped["termination_confirmed"])
                self.assertEqual(self.runtime.stops, 0)
                with self.assertRaises(LifecycleConflict):
                    other.ensure_worker(replace(self.spec, generation=2, launch_key="next"))
            finally:
                release.set()
            self.assertEqual(future.result()["state"], "draining")
        terminal = other.stop_worker(self.scope, worker, "stop")
        self.assertEqual(terminal["state"], "stopped")
        self.assertEqual(self.runtime.stops, 1)
        self.assertEqual(self.service.ensure_worker(self.spec)["state"], "stopped")
        self.assertEqual(self.runtime.launches, 1)
        self.assertNotEqual(
            other.ensure_worker(replace(self.spec, generation=2, launch_key="next"))["worker_id"],
            worker,
        )

    def test_pending_control_resumes_after_crash_before_dispatch(self):
        for action in ("drain", "stop"):
            with self.subTest(action=action):
                spec = replace(self.spec, slot_id=action, launch_key="launch-" + action)
                worker = self.service.ensure_worker(spec)["worker_id"]
                original = getattr(self.runtime, action)

                def crash_before_effect(*args):
                    raise SystemExit("injected crash after intent commit")

                setattr(self.runtime, action, crash_before_effect)
                command = getattr(self.service, action + "_worker")
                with self.assertRaises(SystemExit):
                    command(self.scope, worker, action)
                self.assertFalse(self.service.observe_worker(self.scope, worker)["admission_open"])
                setattr(self.runtime, action, original)
                reopened = WorkerLifecycle(self.database, self.runtime)
                recovered = getattr(reopened, action + "_worker")(self.scope, worker, action)
                self.assertEqual(recovered["state"], "draining" if action == "drain" else "stopped")
                self.assertFalse(recovered["admission_open"])

    def test_stale_observation_cannot_race_a_newer_control_receipt(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        original_observe = self.runtime.observe
        captured, release = Event(), Event()

        def stale_observe(*args):
            observation = original_observe(*args)
            captured.set()
            if not release.wait(5):
                raise RuntimeError("test synchronization timeout")
            return observation

        self.runtime.observe = stale_observe
        other = WorkerLifecycle(self.database, self.runtime)
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.service.observe_worker, self.scope, worker)
            self.assertTrue(captured.wait(5))
            try:
                pending = other.stop_worker(self.scope, worker, "stop")
                self.assertEqual(pending["state"], "draining")
                self.assertFalse(pending["admission_open"])
                self.assertEqual(self.runtime.stops, 0)
            finally:
                release.set()
            self.assertEqual(future.result()["state"], "draining")
        self.runtime.observe = original_observe
        self.assertEqual(other.stop_worker(self.scope, worker, "stop")["state"], "stopped")
        self.assertEqual(self.service.observe_worker(self.scope, worker)["state"], "stopped")

    def test_terminal_absence_requires_a_durable_launch_fence(self):
        self.runtime.crash_before_launch = True
        with self.assertRaises(SystemExit):
            self.service.ensure_worker(self.spec)
        worker = self.service.discover_workers(self.scope)[0]["worker_id"]
        self.runtime.results[worker] = RuntimeObservation(
            "stopped", not_started=True,
            termination_confirmed=True, artifacts_captured=True,
        )
        observed = self.service.observe_worker(self.scope, worker)
        self.assertEqual(observed["state"], "unknown")
        with self.assertRaises(LifecycleConflict):
            self.service.ensure_worker(replace(self.spec, generation=2, launch_key="next"))
        terminal = self.service.stop_worker(self.scope, worker, "stop")
        self.assertEqual(terminal["state"], "stopped")
        self.runtime.crash_before_launch = False
        self.assertEqual(self.service.ensure_worker(self.spec)["state"], "stopped")
        self.assertEqual(self.runtime.launches, 0)

    def test_runtime_lock_is_shared_with_another_process_and_released_on_death(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        program = (
            "import sys\n"
            "from src.worker.lifecycle import WorkerLifecycle\n"
            "service = WorkerLifecycle(sys.argv[1])\n"
            "with service._runtime_lock(sys.argv[2]) as acquired:\n"
            "    print('locked' if acquired else 'busy', flush=True)\n"
            "    input()\n"
        )
        supervisor = subprocess.Popen(
            [sys.executable, "-u", "-c", program, str(self.database), worker],
            stdin=subprocess.PIPE, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
            text=True,
        )
        try:
            self.assertEqual(supervisor.stdout.readline().strip(), "locked")
            pending = self.service.stop_worker(self.scope, worker, "stop")
            self.assertEqual(pending["state"], "draining")
            self.assertEqual(self.runtime.stops, 0)
            supervisor.kill()
            supervisor.communicate(timeout=5)
            reopened = WorkerLifecycle(self.database, self.runtime)
            self.assertEqual(reopened.stop_worker(self.scope, worker, "stop")["state"], "stopped")
            self.assertEqual(self.runtime.stops, 1)
        finally:
            if supervisor.poll() is None:
                supervisor.kill()
            supervisor.communicate(timeout=5)

    def test_deployments_and_repositories_never_share_discovery_or_control(self):
        first = self.service.ensure_worker(self.spec)
        foreign = WorkerScope("deployment-b", self.scope.repository)
        self.assertEqual(self.service.discover_workers(foreign), [])
        with self.assertRaises(WorkerNotFound):
            self.service.stop_worker(foreign, first["worker_id"], "stop")
        second = self.service.ensure_worker(replace(self.spec, deployment_id="deployment-b"))
        self.assertNotEqual(first["worker_id"], second["worker_id"])
        another_repo = WorkerScope(self.scope.deployment_id, "github:github.com/example/other")
        self.assertEqual(self.service.discover_workers(another_repo), [])

    def test_unknown_child_capture_blocks_stop_and_replacement(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        self.service.begin_execution(self.scope, worker, "root")
        self.service.begin_execution(self.scope, worker, "child", parent_id="root")
        self.assertEqual(self.service.observe_worker(self.scope, worker)["state"], "busy")
        self.service.record_execution_end(
            self.scope, worker, "root", termination_confirmed=True, artifacts_captured=True
        )
        stopped = self.service.stop_worker(self.scope, worker, "stop-1")
        self.assertEqual(stopped["state"], "unknown")
        self.assertEqual(stopped["active_executions"], ["child"])
        with self.assertRaises(LifecycleConflict):
            self.service.ensure_worker(replace(self.spec, generation=2, launch_key="new"))
        self.service.record_execution_end(
            self.scope, worker, "child", termination_confirmed=True, artifacts_captured=False
        )
        self.assertEqual(self.service.observe_worker(self.scope, worker)["state"], "unknown")
        self.service.record_execution_end(
            self.scope, worker, "child", termination_confirmed=True, artifacts_captured=True
        )
        terminal = self.service.observe_worker(self.scope, worker)
        self.assertEqual(terminal["state"], "stopped")
        next_worker = self.service.ensure_worker(replace(self.spec, generation=2, launch_key="new"))
        self.assertNotEqual(next_worker["worker_id"], worker)

    def test_drain_is_durable_and_denies_new_root_or_children(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        self.service.begin_execution(self.scope, worker, "root")
        drain_entered, permit_return = Event(), Event()

        def blocking_drain(worker_id, spec, runtime_id):
            drain_entered.set()
            if not permit_return.wait(5):
                raise RuntimeError("test synchronization timeout")
            return self.runtime.observe(worker_id, spec, runtime_id)

        self.runtime.drain = blocking_drain
        with ThreadPoolExecutor(max_workers=1) as pool:
            future = pool.submit(self.service.drain_worker, self.scope, worker, "drain")
            self.assertTrue(drain_entered.wait(5))
            try:
                with self.assertRaises(LifecycleConflict):
                    self.service.begin_execution(self.scope, worker, "child", parent_id="root")
            finally:
                permit_return.set()
            self.assertEqual(future.result()["state"], "draining")
        reopened = WorkerLifecycle(self.database, self.runtime)
        self.assertFalse(reopened.observe_worker(self.scope, worker)["admission_open"])
        with self.assertRaises(LifecycleConflict):
            reopened.begin_execution(self.scope, worker, "new-root")

    def test_mismatched_runtime_identity_cannot_confirm_death(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        self.runtime.results[worker] = RuntimeObservation(
            "stopped", "different-incarnation", termination_confirmed=True, artifacts_captured=True
        )
        observed = self.service.observe_worker(self.scope, worker)
        self.assertEqual(observed["state"], "unknown")
        self.assertFalse(observed["termination_confirmed"])
        self.runtime.results[worker] = RuntimeObservation(
            "stopped", termination_confirmed=True, artifacts_captured=True
        )
        self.assertEqual(self.service.observe_worker(self.scope, worker)["state"], "unknown")

    def test_runtime_incarnation_cannot_be_shared_or_reused_by_another_worker(self):
        first = self.service.ensure_worker(self.spec)["worker_id"]
        original_ensure = self.runtime.ensure

        def duplicated_handle(worker_id, spec):
            original_ensure(worker_id, spec)
            result = RuntimeObservation("ready", runtime_id="runtime-" + first)
            self.runtime.results[worker_id] = result
            return result

        self.runtime.ensure = duplicated_handle
        foreign_scope = WorkerScope("deployment-b", "github:github.com/example/other")
        second_spec = replace(
            self.spec, deployment_id=foreign_scope.deployment_id,
            repository=foreign_scope.repository,
        )
        second = self.service.ensure_worker(second_spec)
        self.assertEqual(second["state"], "unknown")
        self.assertFalse(second["admission_open"])
        self.assertFalse(second["termination_confirmed"])
        with self.service._transaction() as connection:
            self.assertIsNone(self.service._get(connection, foreign_scope, second["worker_id"])["runtime_id"])
        with self.assertRaises(LifecycleConflict):
            self.service.begin_execution(foreign_scope, second["worker_id"], "root")
        self.assertEqual(self.service.observe_worker(self.scope, first)["state"], "ready")
        self.assertEqual(self.service.stop_worker(self.scope, first, "stop")["state"], "stopped")
        # An immutable incarnation cannot be recycled after its owner stops.
        self.assertEqual(
            self.service.observe_worker(foreign_scope, second["worker_id"])["state"],
            "unknown",
        )

    def test_missing_capabilities_fail_closed_without_launch(self):
        unavailable = WorkerLifecycle(Path(self.directory.name) / "unavailable.sqlite")
        self.assertFalse(unavailable.capabilities(self.scope, "fixture")["managed_dispatch"])
        with self.assertRaises(RuntimeUnavailable):
            unavailable.ensure_worker(self.spec)
        self.assertEqual(unavailable.discover_workers(self.scope), [])
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        self.runtime.available = False
        observed = self.service.observe_worker(self.scope, worker)
        self.assertEqual(observed["state"], "unknown")
        self.assertFalse(observed["admission_open"])

    def test_control_retries_do_not_signal_terminal_runtime_again(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        self.service.stop_worker(self.scope, worker, "stop")
        reopened = WorkerLifecycle(self.database, self.runtime)
        self.assertEqual(reopened.stop_worker(self.scope, worker, "stop")["state"], "stopped")
        self.assertEqual(reopened.stop_worker(self.scope, worker, "another-stop")["state"], "stopped")
        self.assertEqual(self.runtime.stops, 1)
        with self.assertRaises(LifecycleConflict):
            reopened.drain_worker(self.scope, worker, "stop")

    def test_stop_response_loss_is_reconciled_without_another_signal(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        original_stop = self.runtime.stop

        def stop_then_lose_response(*args):
            original_stop(*args)
            raise ConnectionError("injected lost stop response")

        self.runtime.stop = stop_then_lose_response
        first = self.service.stop_worker(self.scope, worker, "stop")
        self.assertEqual(first["state"], "unknown")
        recovered = WorkerLifecycle(self.database, self.runtime)
        self.assertEqual(recovered.stop_worker(self.scope, worker, "stop")["state"], "stopped")
        self.assertEqual(self.runtime.stops, 1)

    def test_terminated_runtime_with_failed_capture_keeps_reservation(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        self.runtime.results[worker] = RuntimeObservation(
            "stopped", "runtime-" + worker,
            termination_confirmed=True, artifacts_captured=False, launch_fenced=True,
        )
        observed = self.service.observe_worker(self.scope, worker)
        self.assertEqual(observed["state"], "unknown")
        self.assertFalse(observed["artifacts_captured"])
        with self.assertRaises(LifecycleConflict):
            self.service.ensure_worker(replace(self.spec, generation=2, launch_key="replacement"))

    def test_execution_admission_does_not_allow_duplicate_root_or_recursive_child(self):
        worker = self.service.ensure_worker(self.spec)["worker_id"]
        self.service.begin_execution(self.scope, worker, "root")
        self.service.begin_execution(self.scope, worker, "child", parent_id="root")
        for execution_id, parent_id in [("second-root", None), ("root", None), ("grandchild", "child")]:
            with self.assertRaises(LifecycleConflict):
                self.service.begin_execution(self.scope, worker, execution_id, parent_id)

    def test_admission_cannot_use_cached_readiness_during_runtime_observation(self):
        other = WorkerLifecycle(self.database, self.runtime)
        for execution_id, parent_id in (("root", None), ("child", "parent")):
            with self.subTest(execution=execution_id):
                spec = replace(self.spec, slot_id=execution_id, launch_key="launch-" + execution_id)
                worker = self.service.ensure_worker(spec)["worker_id"]
                if parent_id:
                    self.service.begin_execution(self.scope, worker, parent_id)
                prior_executions = [parent_id] if parent_id else []
                with other._runtime_lock(worker) as acquired:
                    self.assertTrue(acquired)
                    self.runtime.available = False
                    # Observation may return the last snapshot while the other
                    # process is reconciling, but that is not fresh admission.
                    cached = self.service.observe_worker(self.scope, worker)
                    self.assertTrue(cached["admission_open"])
                    with self.assertRaises(LifecycleConflict):
                        self.service.begin_execution(self.scope, worker, execution_id, parent_id)
                    self.assertEqual(
                        self.service.observe_worker(self.scope, worker)["active_executions"],
                        prior_executions,
                    )
                # The retry must refresh rather than trust the cached ready row.
                with self.assertRaises(LifecycleConflict):
                    self.service.begin_execution(self.scope, worker, execution_id, parent_id)
                self.runtime.available = True
                self.service.begin_execution(self.scope, worker, execution_id, parent_id)

    def test_generation_and_version_are_strict(self):
        for fields in (
            {"generation": True}, {"generation": 0}, {"generation": 1 << 63},
            {"schema_version": True}, {"schema_version": 2},
        ):
            with self.assertRaises(ValueError):
                WorkerSpec(**(asdict(self.spec) | fields))

    def test_real_subprocess_reopens_drains_captures_and_stops_once(self):
        runtime = SubprocessFixture(self.directory.name)
        service = WorkerLifecycle(self.database, runtime)
        try:
            worker = service.ensure_worker(self.spec)["worker_id"]
            process = runtime.processes[worker]
            self.assertIsNone(process.poll())
            reopened = WorkerLifecycle(self.database, runtime)
            self.assertEqual(reopened.ensure_worker(self.spec)["worker_id"], worker)
            self.assertEqual(runtime.launches, 1)
            self.assertEqual(reopened.drain_worker(self.scope, worker, "drain")["state"], "draining")
            stopped = reopened.stop_worker(self.scope, worker, "stop")
            self.assertEqual(stopped["state"], "stopped")
            self.assertTrue(stopped["termination_confirmed"])
            self.assertTrue(stopped["artifacts_captured"])
            self.assertIsNotNone(process.poll())
            self.assertIn("fixture-work", (Path(self.directory.name) / (worker + ".artifact")).read_text())
            reopened.stop_worker(self.scope, worker, "stop")
            self.assertEqual(runtime.stops, 1)
        finally:
            runtime.close()


if __name__ == "__main__":
    unittest.main()
