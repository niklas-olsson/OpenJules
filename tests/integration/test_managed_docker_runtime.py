"""Real Docker qualification; opt in explicitly, then missing Docker is failure.

OPENJULES_MANAGED_DOCKER_TESTS=1 python -m pytest tests/integration/test_managed_docker_runtime.py
An optional OPENJULES_MANAGED_IMAGE_ID avoids rebuilding the Python+Git fixture.
This exercises real processes and containment, not model inference or Polyphony.
"""

from dataclasses import asdict
import json
import io
import multiprocessing
import os
from pathlib import Path
import subprocess
import tarfile
import time
from uuid import uuid4

import docker
import pytest

from src.worker.docker_runtime import DockerProfile, ManagedDockerRuntime
from src.worker.lifecycle import RuntimeCapabilities, WorkerSpec

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OPENJULES_MANAGED_DOCKER_TESTS") != "1",
        reason="real managed Docker qualification requires explicit opt-in",
    ),
]


def ready(scope, profile):
    # This fixture verifies the driver only. Combined CI uses the real authority.
    return RuntimeCapabilities(True, True, True, "driver qualification fixture")


@pytest.fixture(scope="module")
def engine():
    client = docker.from_env(timeout=30)
    client.ping()  # Opt-in means unavailable Docker fails, never silently skips.
    image = os.environ.get("OPENJULES_MANAGED_IMAGE_ID")
    if image:
        image = client.images.get(image)
    else:
        image, _ = client.images.build(
            path=str(Path(__file__).parents[1] / "fixtures"),
            dockerfile="Dockerfile.managed-runtime",
            rm=True,
            forcerm=True,
        )
    yield client, image.id
    client.close()


@pytest.fixture
def provisioned(tmp_path, engine):
    client, image = engine
    source = tmp_path / "source"
    source.mkdir(mode=0o755)
    (source / "initial.txt").write_text("base\n")
    subprocess.run(["git", "init", "-q", str(source)], check=True)
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    subprocess.run(
        [
            "git",
            "-C",
            str(source),
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-qm",
            "base",
        ],
        check=True,
    )
    base = subprocess.check_output(
        ["git", "-C", str(source), "rev-parse", "HEAD"], text=True
    ).strip()
    profile = DockerProfile(
        "qualified-v1",
        "docker-test",
        "github:github.com/test/managed",
        str(source),
        image,
        (
            "python3",
            "-I",
            "-c",
            "from pathlib import Path; Path('result.txt').write_text('implemented\\n'); print('real code change')",
        ),
        base,
    )
    runtime = ManagedDockerRuntime(tmp_path / "runtime", [profile], ready, client)
    spec = WorkerSpec(
        profile.deployment_id, profile.repository, "slot", 1, "launch", profile.name
    )
    worker = uuid4().hex
    yield runtime, profile, spec, worker, client
    # Test-owned resources only; production runtime never removes its fences.
    try:
        client.containers.get(runtime._name(worker)).remove(force=True)
    except docker.errors.NotFound:
        pass
    try:
        client.volumes.get(
            "openjules-work-"
            + __import__("hashlib").sha256(worker.encode()).hexdigest()[:40]
        ).remove()
    except docker.errors.NotFound:
        pass


def test_real_git_change_capture_and_stopped_incarnation(provisioned):
    runtime, profile, spec, worker, client = provisioned
    assert runtime.ensure(worker, spec).state == "ready"
    receipt = runtime.execute_attempt(
        worker, spec, "attempt-real", "make the approved change", 20
    )
    assert (
        receipt.termination_confirmed
        and receipt.launch_fenced
        and receipt.artifacts_captured
    )
    assert receipt.exit_code == 0, receipt.log
    assert "+implemented" in receipt.patch
    assert "real code change" in receipt.log
    assert Path(receipt.capture_path).is_file()
    assert json.loads(receipt.manifest)["patch_present"]
    assert (
        runtime.execute_attempt(
            worker, spec, "attempt-real", "make the approved change", 1
        )
        == receipt
    )
    container = client.containers.get(runtime._name(worker))
    assert container.attrs["State"]["Running"] is False
    assert container.attrs["HostConfig"]["NetworkMode"] == "none"
    assert container.attrs["HostConfig"]["ReadonlyRootfs"] is True
    assert container.attrs["HostConfig"]["Privileged"] is False
    assert container.attrs["Config"]["User"] == "65534:65534"
    assert not any(
        mount["Destination"] == "/var/run/docker.sock"
        for mount in container.attrs["Mounts"]
    )


def test_real_stopped_idle_worker_is_captured_and_released(provisioned):
    runtime, profile, spec, worker, client = provisioned
    assert runtime.ensure(worker, spec).state == "ready"
    container = client.containers.get(runtime._name(worker))
    container.kill()
    container.wait(timeout=10)
    assert runtime.observe(worker, spec, "docker:" + container.id).state == "unknown"
    recovered = runtime.recover_idle(worker, spec)
    assert (
        recovered.termination_confirmed
        and recovered.launch_fenced
        and recovered.artifacts_captured
    )
    assert runtime.observe(worker, spec, "docker:" + container.id).state == "stopped"


def _execute_in_supervisor(state_directory, profile_data, spec_data, worker):
    client = docker.from_env(timeout=5)
    runtime = ManagedDockerRuntime(
        state_directory, [DockerProfile(**profile_data)], ready, client
    )
    runtime.execute_attempt(
        worker, WorkerSpec(**spec_data), "attempt-deadline", "bounded work", 5
    )


def test_watchdog_survives_supervisor_death_and_task_cannot_signal_it(provisioned):
    runtime, original, spec, worker, client = provisioned
    # Use a distinct immutable approved profile before the worker is created.
    from dataclasses import replace

    code = """import os,signal,time
from pathlib import Path
assert os.getuid()==65532
assert os.getgid()==65532
assert not Path('/var/run/docker.sock').exists()
try:
    os.kill(1,signal.SIGKILL)
except PermissionError:
    pass
else:
    raise AssertionError('task could signal trusted watchdog')
try:
    Path('/control/deadline').write_text('999999999999')
except PermissionError:
    pass
else:
    raise AssertionError('task could extend deadline')
Path('boundary-verified.txt').write_text('watchdog protected')
print('BOUNDARY_VERIFIED',flush=True)
time.sleep(60)
"""
    profile = replace(
        original, name="watchdog-v1", command=("python3", "-I", "-c", code)
    )
    spec = replace(spec, profile=profile.name)
    runtime = ManagedDockerRuntime(runtime.root, [profile], ready, client)
    assert runtime.ensure(worker, spec).state == "ready"
    process = multiprocessing.get_context("spawn").Process(
        target=_execute_in_supervisor,
        args=(runtime.root, asdict(profile), asdict(spec), worker),
    )
    process.start()
    try:
        deadline = time.monotonic() + 4
        dispatched = False
        container = client.containers.get(runtime._name(worker))
        while time.monotonic() < deadline:
            attempt = runtime._attempt(worker)
            if attempt and attempt["exec_dispatched"]:
                try:
                    chunks, _ = container.get_archive("/workspace/run/output.log")
                    content = b"".join(chunks)
                    with tarfile.open(
                        fileobj=io.BytesIO(content), mode="r:"
                    ) as log_archive:
                        log = log_archive.extractfile(
                            log_archive.getmembers()[0]
                        ).read()
                    if b"BOUNDARY_VERIFIED" in log:
                        dispatched = True
                        break
                except docker.errors.NotFound:
                    pass
            time.sleep(0.05)
        assert (
            dispatched
        ), "supervisor did not dispatch within the qualification interval"
        process.kill()
        process.join(timeout=3)
        assert not process.is_alive()
        end = time.monotonic() + 8
        while time.monotonic() < end:
            container.reload()
            if not container.attrs["State"]["Running"]:
                break
            time.sleep(0.1)
        assert not container.attrs["State"][
            "Running"
        ], "watchdog did not terminate the worker without its supervisor"
        receipt = runtime.inspect_attempt(worker, spec, "attempt-deadline")
        assert (
            receipt.termination_confirmed
            and receipt.artifacts_captured
            and receipt.launch_fenced
        )
        assert "BOUNDARY_VERIFIED" in receipt.log, receipt.log
    finally:
        if process.is_alive():
            process.kill()
        process.join(timeout=3)


def test_legacy_raw_access_cannot_stop_or_modify_a_real_managed_container(
    provisioned, tmp_path
):
    from src.agent.tools import AgentTools
    from src.sandbox.docker_driver import SandboxManager
    from src.worker.execution_context import LegacyExecutionRefused

    runtime, profile, spec, worker, client = provisioned
    assert runtime.ensure(worker, spec).state == "ready"
    container = client.containers.get(runtime._name(worker))
    assert container.attrs["Config"]["Labels"]["openjules.managed"] == "1"
    assert container.attrs["State"]["Running"] is True
    original_id = container.id
    workspace = tmp_path / "retained-legacy-path"
    workspace.mkdir()
    (workspace / "canary").write_text("preserved")
    legacy = SandboxManager(client)
    actions = [
        lambda: legacy.exec_in_sandbox(original_id, "printf forbidden"),
        lambda: AgentTools(legacy, original_id).write_file("initial.txt", "forbidden"),
        lambda: legacy._stop(original_id),
        lambda: legacy.cleanup_sandbox(
            original_id, str(workspace), artifact_capture_confirmed=True
        ),
    ]
    for action in actions:
        with pytest.raises(LegacyExecutionRefused, match="^managed_container_requires_canonical_runtime$"):
            action()
        container.reload()
        assert container.id == original_id and container.attrs["State"]["Running"] is True
    assert legacy._quarantined == legacy._active_executions == set()
    assert (workspace / "canary").read_text() == "preserved"

    # Actual canonical-runtime execution remains available after every refusal.
    # This tests a running idle worker, not a new live authority or model turn.
    receipt = runtime.execute_attempt(
        worker, spec, "attempt-after-legacy-refusal", "make the approved change", 20
    )
    assert receipt.exit_code == 0
    assert receipt.termination_confirmed and receipt.launch_fenced and receipt.artifacts_captured
    assert "+implemented" in receipt.patch and "forbidden" not in receipt.patch
    assert "real code change" in receipt.log
