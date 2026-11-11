"""Actual Unix peer denial while an authorized provider request remains held.

The model provider and canonical permission callback are explicit fixtures.
The socket, SQLite reservation, approved container image and distinct kernel
peer UID are real. This is not a live provider or Polyphony qualification.
"""

import json
import os
import sys
import threading

import pytest

from src.agent.managed_runner import BrokerClient
from src.worker.model_broker import ModelBroker, ModelPolicy
from tests.integration.test_managed_agent_container import agent_image  # noqa: F401
from tests.unit.test_managed_agent import (
    ATTEMPT,
    MESSAGES,
    SCOPE_KEY,
    SPEC,
    TEST_TOKEN,
    WORKER,
    message,
    provider,
    response,
)


pytestmark = [
    pytest.mark.integration,
    pytest.mark.skipif(
        os.environ.get("OPENJULES_MANAGED_DOCKER_TESTS") != "1",
        reason="real managed Docker qualification requires explicit opt-in",
    ),
]


DENIAL_PROBE = r"""
import json, os, socket, struct, sys

uid = int(sys.argv[1])
assert os.getuid() == uid
print(json.dumps({"peer_uid": os.getuid()}), flush=True)
with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as connection:
    connection.settimeout(5)
    connection.connect("/run/openjules-model/model.sock")
    # A different UID must receive a denial without supplying any body.
    def exact(size):
        data = bytearray()
        while len(data) < size:
            part = connection.recv(size - len(data))
            assert part, "denial response closed before its complete frame"
            data.extend(part)
        return bytes(data)

    length = struct.unpack("!I", exact(4))[0]
    assert 1 <= length <= 1024
    result = json.loads(exact(length))
    assert result == {
        "schema_version": 1,
        "request_id": "invalid",
        "ok": False,
        "error": "not_authorized",
    }
print("UNAUTHORIZED_DENIAL_RECEIVED", flush=True)
"""


def _retained(broker):
    with broker.connection() as db:
        return {
            "workers": [
                dict(row)
                for row in db.execute("SELECT * FROM workers ORDER BY worker_id")
            ],
            "calls": [
                dict(row)
                for row in db.execute(
                    "SELECT * FROM calls ORDER BY worker_id,attempt_id,request_id"
                )
            ],
        }


def test_wrong_uid_is_denied_before_a_held_authorized_provider_reply(
    tmp_path, monkeypatch, agent_image
):
    docker_client, image = agent_image
    unauthorized_uid = 60001 if os.getuid() != 60001 else 60000
    entered = threading.Event()
    release = threading.Event()
    finished = threading.Event()
    provider_errors = []
    permission_checks = []
    result = {}
    monkeypatch.setenv("MOCK_MODEL_TOKEN", TEST_TOKEN)

    def permission(binding):
        assert binding.worker_id == WORKER and binding.attempt_id == ATTEMPT
        assert binding.spec == SPEC
        permission_checks.append(binding)
        return 60

    def held_provider(handler, requests):
        try:
            assert len(requests) == 1
            assert requests[0]["authorization"] == "Bearer " + TEST_TOKEN
            assert requests[0]["body"]["messages"] == MESSAGES
            entered.set()
            assert release.wait(20), "test did not release its held provider request"
            response(handler, message())
        except BaseException as error:
            provider_errors.append(type(error).__name__)
            raise

    with provider(held_provider) as (endpoint, requests):
        broker = ModelBroker(
            tmp_path / "private-models",
            {SCOPE_KEY: ModelPolicy(endpoint, "held-fixture", "env:MOCK_MODEL_TOKEN")},
            permission,
            peer_uids={SCOPE_KEY: os.getuid()},
        )
        container = None
        descriptor = None
        caller = None
        try:
            directory = broker.prepare_worker(WORKER, SPEC)
            broker.bind_attempt(WORKER, SPEC, ATTEMPT, 60)
            descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
            client = BrokerClient(
                f"/proc/self/fd/{descriptor}/model.sock", timeout_seconds=30
            )
            # Start the test-owned container before holding the provider call.
            # It receives only the socket mount and no provider credentials.
            container = docker_client.containers.run(
                image,
                ["python3", "-I", "-S", "-c", "import time; time.sleep(60)"],
                detach=True,
                user=f"{unauthorized_uid}:{unauthorized_uid}",
                network_mode="none",
                read_only=True,
                cap_drop=["ALL"],
                security_opt=["no-new-privileges:true"],
                privileged=False,
                mem_limit=134217728,
                memswap_limit=134217728,
                pids_limit=16,
                nano_cpus=1_000_000_000,
                volumes={
                    str(directory): {"bind": "/run/openjules-model", "mode": "ro"}
                },
                environment={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
            )
            container.reload()
            assert container.attrs["State"]["Running"] is True
            assert container.attrs["HostConfig"]["NetworkMode"] == "none"
            assert container.attrs["Config"]["User"] == (
                f"{unauthorized_uid}:{unauthorized_uid}"
            )
            assert container.attrs["Mounts"][0]["Destination"] == "/run/openjules-model"
            assert container.attrs["Mounts"][0]["RW"] is False

            def authorized_call():
                try:
                    result["reply"] = client.complete(MESSAGES, "held-authorized")
                except BaseException as error:
                    result["error"] = error
                finally:
                    finished.set()

            caller = threading.Thread(target=authorized_call, daemon=True)
            caller.start()
            assert entered.wait(5), "authorized request never reached the provider"
            assert not finished.is_set() and not release.is_set()
            before = _retained(broker)
            assert len(before["workers"]) == len(before["calls"]) == len(requests) == 1
            call = before["calls"][0]
            assert call["request_id"] == "held-authorized"
            assert call["status"] == "reserved"
            assert call["reserved_tokens"] == 2048 and call["response"] is None
            checked = list(permission_checks)

            denial = container.exec_run(
                ["python3", "-I", "-S", "-c", DENIAL_PROBE, str(unauthorized_uid)]
            )
            output = denial.output.decode("utf-8", errors="replace")
            assert denial.exit_code == 0, output
            assert output.splitlines() == [
                json.dumps({"peer_uid": unauthorized_uid}),
                "UNAUTHORIZED_DENIAL_RECEIVED",
            ]
            assert not release.is_set() and not finished.is_set()
            assert caller.is_alive() and not provider_errors
            assert len(requests) == 1
            assert _retained(broker) == before
            assert permission_checks == checked

            release.set()
            assert finished.wait(5), "authorized reply did not finish after release"
            caller.join(1)
            assert not caller.is_alive()
            assert "error" not in result, type(result.get("error")).__name__
            assert result["reply"] == message()
            after = _retained(broker)
            assert len(after["calls"]) == len(requests) == 1
            assert after["calls"][0]["status"] == "complete"
            assert after["calls"][0]["reserved_tokens"] == 2048
            assert not provider_errors
        finally:
            original_error = sys.exc_info()[1]
            cleanup_errors = []
            release.set()
            if caller is not None:
                caller.join(10)
                if caller.is_alive():
                    cleanup_errors.append("authorized caller did not stop")
            try:
                if container is not None:
                    container.remove(force=True)
            except Exception:
                cleanup_errors.append("owned container removal failed")
            try:
                broker.close()
            except Exception:
                cleanup_errors.append("broker close failed")
            if descriptor is not None:
                os.close(descriptor)
            if cleanup_errors:
                detail = "; ".join(cleanup_errors)
                if original_error is not None:
                    original_error.add_note(detail)
                else:
                    pytest.fail(detail)
