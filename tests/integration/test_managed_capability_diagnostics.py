"""Scoped capability diagnostics through real HTTP and the composed managed app.

Git, SQLite, the dispatcher, model/child journals and local socket probes are real.
FakeDocker supplies image, daemon and UID-topology preflight only. No container,
historical Polyphony process, inference provider or forge operation runs here.
"""

from contextlib import asynccontextmanager, contextmanager
from dataclasses import asdict
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
from pathlib import Path
import sqlite3
import threading
from urllib.parse import parse_qs, urlsplit

import httpx
import pytest

from src.worker.child_types import ChildPolicy
from src.worker.managed_service import build_app
from tests.unit.test_managed_docker_runtime import setup_runtime  # noqa: F401

pytestmark = pytest.mark.integration
AUTHORITY_TOKEN = "diagnostic-authority-fixture-token-" * 2
MODEL_TOKEN = "diagnostic-model-fixture-token-" * 2
WORKER_TOKEN = "diagnostic-worker-fixture-token-" * 2
UNSUPPORTED = "Canonical managed authority is unsupported: child_initial_outcome=1"
UNAVAILABLE = "Canonical managed authority is unavailable"


@contextmanager
def authority_server(supported):
    state = {"status": 200, "payload": supported, "requests": []}

    class Handler(BaseHTTPRequestHandler):
        def reply(self):
            state["requests"].append(
                (self.command, self.path, self.headers.get("Authorization"))
            )
            if (
                self.command == "GET"
                and urlsplit(self.path).path == "/managed/capabilities"
                and self.headers.get("Authorization") == "Bearer " + AUTHORITY_TOKEN
            ):
                status, payload = state["status"], state["payload"]
            else:
                status, payload = 500, {"error": "unexpected fixture request"}
            body = json.dumps(payload).encode()
            self.send_response(status)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        do_GET = do_POST = reply

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}", state
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)


@asynccontextmanager
async def composed_service(tmp_path, monkeypatch, runtime_fixture, outcome_protocol):
    _, docker_fixture, profile, spec = runtime_fixture
    # Explicit named Docker preflight fixture, not an actual daemon or UID proof.
    docker_fixture.info = lambda: {"SecurityOptions": []}
    child_policy = ChildPolicy(1, 1, 1, ("python",), outcome_protocol=outcome_protocol)
    policy = asdict(child_policy)
    assert policy.pop("session_protocol") is None
    if outcome_protocol is None:
        policy.pop("outcome_protocol")
    supported = {
        "schema_version": 1,
        "deployment_id": spec.deployment_id,
        "repository": spec.repository,
        "service": "keystone-polyphony",
        "protocol": "managed-runtime-v1",
        "profile": spec.profile,
        "base": profile.base_commit,
        "managed_dispatch": True,
        "external_root": True,
        "profile_supported": True,
        "child_grants": True,
        "child_policy": child_policy.canonical_policy,
        "child_initial_outcome": 1,
    }
    monkeypatch.setenv("DIAGNOSTIC_AUTHORITY_TOKEN", AUTHORITY_TOKEN)
    monkeypatch.setenv("DIAGNOSTIC_MODEL_TOKEN", MODEL_TOKEN)

    def no_fallback(*_args, **_kwargs):
        raise AssertionError("readiness attempted a legacy or real Docker client")

    monkeypatch.setattr("docker.DockerClient", no_fallback)
    monkeypatch.setattr("docker.from_env", no_fallback)
    monkeypatch.setattr("src.polyphony.client.PolyphonyClient.__init__", no_fallback)
    monkeypatch.setattr(
        "src.polyphony.manager.PolyphonySwarmManager.__init__", no_fallback
    )
    with authority_server(supported) as (endpoint, authority):
        binding = {
            "deployment_id": spec.deployment_id,
            "repository": spec.repository,
            "profile": spec.profile,
        }
        config = {
            "schema_version": 1,
            "state_directory": str(tmp_path / "service"),
            "lifecycle_database": str(tmp_path / "lifecycle.sqlite3"),
            "authority": {
                "endpoint": endpoint,
                "token_ref": "env:DIAGNOSTIC_AUTHORITY_TOKEN",
            },
            "profiles": [asdict(profile)],
            "models": [
                binding | {
                    "policy": {
                        "endpoint": endpoint + "/v1/chat/completions",
                        "model": "diagnostic-no-inference-fixture",
                        "token_ref": "env:DIAGNOSTIC_MODEL_TOKEN",
                    }
                }
            ],
            "children": [binding | {"policy": policy}],
            "poll_interval_seconds": 0.1,
        }
        app = build_app(config, {WORKER_TOKEN: [spec.scope]})
        app.state.worker_lifecycle.runtime._client = docker_fixture
        async with app.router.lifespan_context(app):
            async with httpx.AsyncClient(
                transport=httpx.ASGITransport(app=app),
                base_url="http://managed-diagnostic",
                headers={"Authorization": "Bearer " + WORKER_TOKEN},
                trust_env=False,
            ) as client:
                yield app, client, authority, supported, spec, docker_fixture


def retained_state(app, docker_fixture):
    lifecycle = app.state.worker_lifecycle
    databases = {
        "lifecycle": (
            lifecycle.database,
            ("managed_workers", "worker_operations", "worker_executions"),
        ),
        "runtime": (lifecycle.runtime.database, ("workers", "attempts")),
        "dispatcher": (app.state.managed_dispatcher.journal.database, ("deliveries",)),
        "model": (app.state.model_broker.database, ("workers", "calls")),
        "children": (
            app.state.child_supervisor.journal.path,
            ("workers", "intents", "children"),
        ),
    }
    retained = {}
    for name, (path, tables) in databases.items():
        uri = Path(path).resolve().as_uri() + "?mode=ro"
        with sqlite3.connect(uri, uri=True) as db:
            for table in tables:
                assert db.execute("SELECT COUNT(*) FROM " + table).fetchone()[0] == 0
            retained[name] = tuple(db.iterdump())
    assert docker_fixture.created == docker_fixture.executed == 0
    assert docker_fixture.all_containers == docker_fixture.all_volumes == {}
    return retained


def assert_scoped_requests(authority, spec):
    assert authority["requests"]
    for method, target, token in authority["requests"]:
        url = urlsplit(target)
        assert method == "GET" and url.path == "/managed/capabilities"
        assert token == "Bearer " + AUTHORITY_TOKEN
        assert parse_qs(url.query) == {
            "deployment_id": [spec.deployment_id],
            "repository": [spec.repository],
            "profile": [spec.profile],
        }


async def capability(client, spec):
    response = await client.get(
        "/api/workers/capabilities",
        params=asdict(spec.scope) | {"profile": spec.profile},
    )
    assert response.status_code == 200
    payload = response.json()
    assert payload["schema_version"] == 1
    assert payload["deployment_id"] == spec.deployment_id
    assert payload["repository"] == spec.repository
    assert payload["profile"] == spec.profile
    return payload


@pytest.mark.asyncio
async def test_valid_unsupported_capability_is_distinct_from_untrusted_or_unavailable(
    tmp_path, monkeypatch, setup_runtime
):
    async with composed_service(
        tmp_path, monkeypatch, setup_runtime, "initial-v1"
    ) as (app, client, authority, supported, spec, docker_fixture):
        ready = await capability(client, spec)
        assert ready["managed_dispatch"] is ready["repository_access"] is True
        before = retained_state(app, docker_fixture)
        missing = {
            key: value for key, value in supported.items()
            if key != "child_initial_outcome"
        }
        cases = [
            (200, missing, UNSUPPORTED),
            (200, supported | {"child_initial_outcome": 2}, UNSUPPORTED),
            (503, {"error": "untrusted-private-authority-details"}, UNAVAILABLE),
            (200, missing | {"deployment_id": "foreign-deployment"}, UNAVAILABLE),
            (
                200,
                missing | {"repository": "github:github.com/foreign/repo"},
                UNAVAILABLE,
            ),
            (200, missing | {"schema_version": True}, UNAVAILABLE),
            (200, missing | {"base": "0" * 40}, UNAVAILABLE),
            (200, missing | {"protocol": "unsupported-root-protocol"}, UNAVAILABLE),
            (200, missing | {"child_grants": False}, UNAVAILABLE),
            (200, missing | {"child_policy": {}}, UNAVAILABLE),
            (200, [], UNAVAILABLE),
        ]
        cases.extend(
            (200, supported | {"child_initial_outcome": value}, UNAVAILABLE)
            for value in (None, True, False, "1", 0, -1)
        )
        # Every configured number is1, so True would compare equal under the
        # old plain-dict policy comparison. It must not justify attribution.
        cases.extend(
            (
                200,
                missing | {
                    "child_policy": supported["child_policy"] | {field: True}
                },
                UNAVAILABLE,
            )
            for field in ("max_children", "max_child_turns", "max_child_seconds")
        )
        for status, payload, reason in cases:
            authority.update(status=status, payload=payload)
            blocked = await capability(client, spec)
            assert blocked["profile_supported"] is True
            assert blocked["managed_dispatch"] is blocked["repository_access"] is False
            assert blocked["reason"] == reason
            for _ in range(2):
                ensured = await client.post("/api/workers/ensure", json=asdict(spec))
                assert ensured.status_code == 503
                assert ensured.json() == {
                    "detail": "Managed runtime preflight is not ready"
                }
            assert retained_state(app, docker_fixture) == before

        authority.update(status=200, payload=supported)
        restored = await capability(client, spec)
        assert restored == ready
        assert retained_state(app, docker_fixture) == before
        # Each capability observation and ensure retry made its own HTTP read.
        assert len(authority["requests"]) == 2 + 3 * len(cases)
        assert_scoped_requests(authority, spec)


@pytest.mark.asyncio
async def test_omitted_outcome_profile_keeps_existing_capability_behavior(
    tmp_path, monkeypatch, setup_runtime
):
    async with composed_service(
        tmp_path, monkeypatch, setup_runtime, None
    ) as (app, client, authority, supported, spec, docker_fixture):
        ready = await capability(client, spec)
        assert ready["managed_dispatch"] is ready["repository_access"] is True
        before = retained_state(app, docker_fixture)
        without_outcome = {
            key: value for key, value in supported.items()
            if key != "child_initial_outcome"
        }
        for payload in (
            without_outcome,
            supported | {"child_initial_outcome": 2},
            supported | {"child_initial_outcome": True},
        ):
            authority["payload"] = payload
            assert await capability(client, spec) == ready
            assert retained_state(app, docker_fixture) == before
        assert len(authority["requests"]) == 4
        assert_scoped_requests(authority, spec)
