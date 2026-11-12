"""Real networkless-container and model-socket qualification, with a fake model.

This checks the agent image and Unix-socket boundary, not canonical authority.
Enable OPENJULES_MANAGED_DOCKER_TESTS=1; unavailable Docker then fails.
"""

import json
import os
from pathlib import Path
import shutil
from uuid import uuid4

import docker
import pytest

from src.worker.lifecycle import WorkerSpec
from src.worker.model_broker import ModelBroker, ModelPolicy
from tests.unit.test_managed_agent import message, provider, response

pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OPENJULES_MANAGED_DOCKER_TESTS") != "1",
        reason="real managed Docker qualification requires explicit opt-in",
    ),
]


@pytest.fixture(scope="module")
def agent_image(tmp_path_factory):
    client = docker.from_env(timeout=30)
    client.ping()
    # A daemon with user-namespace remapping requires separately qualified host
    # UID bindings. It must not be silently treated as the rootful baseline.
    if any(
        "rootless" in option or "userns" in option
        for option in client.info().get("SecurityOptions", [])
    ):
        pytest.fail(
            "this qualification requires the documented local rootful Docker topology"
        )
    configured = os.environ.get("OPENJULES_MANAGED_AGENT_IMAGE_ID")
    if configured:
        image = client.images.get(configured)
        if image.id != configured:
            pytest.fail(
                "OPENJULES_MANAGED_AGENT_IMAGE_ID must be the exact immutable image ID"
            )
    else:
        repository = Path(__file__).parents[2]
        build = tmp_path_factory.mktemp("agent-image")
        (build / "src/agent").mkdir(parents=True)
        for name in (
            "managed_runner.py",
            "managed_root_runner.py",
            "child_tools.py",
            "public_tools.py",
            "child_outcome.py",
        ):
            shutil.copyfile(repository / "src/agent" / name, build / "src/agent" / name)
        shutil.copyfile(
            repository / "docker/Dockerfile.managed-agent", build / "Dockerfile"
        )
        image, _ = client.images.build(
            path=str(build),
            rm=True,
            forcerm=True,
            buildargs={
                "PYTHON_BASE": os.environ.get(
                    "OPENJULES_AGENT_PYTHON_BASE", "python:3.12-slim"
                )
            },
        )
    yield client, image.id
    client.close()


def test_readonly_agent_uses_checked_stdlib_caches_without_source_compilation(
    agent_image,
):
    """Fresh imports must consume valid build caches, without a timing oracle."""
    client, image = agent_image
    program = r'''import importlib.machinery,os,sys
assert os.getuid()==os.getgid()==65532
assert os.environ.get('PYTHONDONTWRITEBYTECODE')=='1'
assert sys.dont_write_bytecode and sys.flags.optimize==0
targets=('json','subprocess','tempfile','http.client','urllib.request','unittest')
assert all(name not in sys.modules for name in targets)
def reject_source_compilation(*args,**kwargs):
    raise AssertionError('stdlib import fell back to source compilation')
importlib.machinery.SourceFileLoader.source_to_code=reject_source_compilation
for name in targets:
    __import__(name)
    module=sys.modules[name]
    cache=module.__cached__
    with open(cache,'rb') as stream:
        header=stream.read(16)
    assert len(header)==16 and int.from_bytes(header[4:8],'little')==3
    metadata=os.stat(cache)
    assert metadata.st_uid==0 and metadata.st_mode&0o777==0o644
    assert os.access(cache,os.R_OK) and not os.access(cache,os.W_OK)
assert not os.path.exists('/opt/openjules/__pycache__')
print('checked-stdlib-cache-imports-verified')
'''
    container = None
    try:
        container = client.containers.run(
            image,
            ["python3", "-I", "-S", "-B", "-c", program],
            detach=True,
            user="65532:65532",
            working_dir="/",
            network_mode="none",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            privileged=False,
            mem_limit=268435456,
            memswap_limit=268435456,
            pids_limit=64,
            nano_cpus=1_000_000_000,
            tmpfs={"/tmp": "rw,nosuid,nodev,noexec,size=16777216"},
            environment={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        result = container.wait(timeout=30)
        output = container.logs().decode(errors="replace")
        assert result["StatusCode"] == 0, output
        assert output.strip() == "checked-stdlib-cache-imports-verified"
        container.reload()
        assert container.attrs["Config"]["User"] == "65532:65532"
        assert container.attrs["HostConfig"]["ReadonlyRootfs"] is True
        assert container.attrs["HostConfig"]["NetworkMode"] == "none"
        assert container.attrs["HostConfig"]["Privileged"] is False
        assert not any(
            mount["Type"] in {"bind", "volume"}
            for mount in container.attrs["Mounts"]
        )
    finally:
        if container is not None:
            container.remove(force=True)  # This test owns this exact ID.


def test_networkless_container_runs_agent_over_own_broker_socket(
    tmp_path, monkeypatch, agent_image
):
    client, image = agent_image
    task_uid = 65532
    worker_id, attempt_id = uuid4().hex, uuid4().hex
    spec = WorkerSpec(
        "agent-qualification",
        "github:github.com/fixture/agent",
        "slot",
        1,
        "launch",
        "agent-v1",
    )
    key = (spec.deployment_id, spec.repository, spec.profile)
    workspace = tmp_path / "workspace"
    workspace.mkdir()
    workspace.chmod(0o777)  # Test-owned shared data, never service state.
    answer = workspace / "answer.txt"
    answer.write_text("old\n")
    answer.chmod(0o666)
    monkeypatch.setenv(
        "MODEL_BROKER_FIXTURE_TOKEN", "test-provider-token-never-in-container"
    )
    sequence = [
        message("read_file", path="answer.txt"),
        message("write_file", path="answer.txt", content="implemented\n"),
        message("finish", summary="Edited the qualified fixture"),
    ]

    def model(handler, requests):
        response(handler, sequence[len(requests) - 1])

    checked_bindings = []

    def permission(binding):
        # Fixture only. Production must call the actual scoped authority.
        assert binding.worker_id == worker_id and binding.attempt_id == attempt_id
        assert binding.spec == spec
        checked_bindings.append(binding)
        return 30

    with provider(model) as (endpoint, requests):
        broker = ModelBroker(
            tmp_path / "private-broker",
            {
                key: ModelPolicy(
                    endpoint,
                    "deterministic-fixture",
                    "env:MODEL_BROKER_FIXTURE_TOKEN",
                    request_timeout_seconds=5,
                )
            },
            permission,
            peer_uids={key: task_uid},
        )
        container = None
        try:
            directory = broker.prepare_worker(worker_id, spec)
            broker.bind_attempt(worker_id, spec, attempt_id, 30)
            verification = [
                "python3",
                "-I",
                "-c",
                "import os,pathlib; assert os.getuid()==65532; "
                "assert pathlib.Path('answer.txt').read_text()=='implemented\\n'; "
                "assert not pathlib.Path('/var/run/docker.sock').exists(); "
                "assert not any(k in os.environ for k in ['MODEL_BROKER_FIXTURE_TOKEN', 'POLYPHONY_RUNTIME_TOKEN', 'OPENJULES_WORKER_TOKEN'])",
            ]
            runner = [
                "python3",
                "-I",
                "-S",
                "/opt/openjules/managed_runner.py",
                "--socket",
                "/run/openjules-model/model.sock",
                "--max-turns",
                "5",
                "--verify-json",
                json.dumps(verification),
            ]
            # This fixed test wrapper supplies stdin without a shell. The
            # managed runtime supplies the same approved-input channel itself.
            wrapper = [
                "python3",
                "-I",
                "-c",
                "import json,subprocess,sys; raise SystemExit(subprocess.run(json.loads(sys.argv[1]), input=b'Change old to implemented and finish.').returncode)",
                json.dumps(runner),
            ]
            container = client.containers.run(
                image,
                wrapper,
                detach=True,
                user=f"{task_uid}:{task_uid}",
                working_dir="/workspace",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                privileged=False,
                mem_limit=268435456,
                memswap_limit=268435456,
                pids_limit=64,
                nano_cpus=1_000_000_000,
                volumes={
                    str(workspace): {"bind": "/workspace", "mode": "rw"},
                    str(directory): {"bind": "/run/openjules-model", "mode": "ro"},
                },
                tmpfs={"/tmp": "rw,nosuid,nodev,noexec,size=16777216"},
                environment={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
            result = container.wait(timeout=30)
            output = container.logs().decode(errors="replace")
            assert result["StatusCode"] == 0, output
            assert '"event": "configured_verification"' in output
            assert answer.read_text() == "implemented\n"
            assert len(requests) == 3
            assert checked_bindings
            assert all(
                request["authorization"]
                == "Bearer test-provider-token-never-in-container"
                for request in requests
            )
            assert "test-provider-token-never-in-container" not in output
            container.reload()
            assert container.attrs["HostConfig"]["NetworkMode"] == "none"
            mounts = container.attrs["Mounts"]
            assert (
                next(m for m in mounts if m["Destination"] == "/run/openjules-model")[
                    "RW"
                ]
                is False
            )
            assert not any(m["Destination"] == "/var/run/docker.sock" for m in mounts)
        finally:
            if container is not None:
                container.remove(force=True)  # This test owns this exact ID.
            broker.close()
