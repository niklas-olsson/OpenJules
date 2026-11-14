"""Actual disabled app boundaries; no model, forge or Docker qualification."""

import asyncio
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
from unittest.mock import Mock

from fastapi import FastAPI
from fastapi.routing import APIRoute, APIWebSocketRoute
from fastapi.testclient import TestClient
import pytest
from starlette.websockets import WebSocketDisconnect
import yaml

from src import cli
from src.api import polyphony_routes, ui_routes, ws
from src.api.standalone_ingress import POLICY_ENV, UNAVAILABLE, POLICY_INVALID, POLICY_UNSUPPORTED
from src.api.webhook import create_app

ROOT = Path(__file__).resolve().parents[2]
HTTP = (
    ("POST", "/api/webhook"), ("POST", "/api/radicle/webhook"),
    ("GET", "/api/tasks"), ("POST", "/api/tasks"),
    ("GET", "/api/tasks/{task_id}"), ("GET", "/api/tasks/{task_id}/diff"),
    ("POST", "/api/tasks/{task_id}/comments"), ("POST", "/api/tasks/{task_id}/command"),
    ("GET", "/api/polyphony/state"), ("GET", "/api/polyphony/cohorts"),
    ("POST", "/api/polyphony/cohorts"), ("GET", "/api/polyphony/cohorts/{swarm_id}"),
    ("DELETE", "/api/polyphony/cohorts/{swarm_id}"),
    ("POST", "/api/polyphony/cohorts/{swarm_id}/signal"),
)
WEBSOCKETS = ("/ws/tasks/{task_id}", "/api/polyphony/ws/{swarm_id}")


def concrete(path):
    return path.replace("{task_id}", "prior-private-task").replace("{swarm_id}", "prior-private-cohort")


@pytest.mark.parametrize("selector,state,reason", [
    (None, "missing", UNAVAILABLE), ("", "invalid", POLICY_INVALID),
    (" ", "invalid", POLICY_INVALID), ("x" * 4097, "invalid", POLICY_INVALID),
    ("prior-work.sqlite3", "unsupported", POLICY_UNSUPPORTED),
    ('{"schema_version":1,"approved":true}', "unsupported", POLICY_UNSUPPORTED),
    ("/absent/policy.json", "unsupported", POLICY_UNSUPPORTED),
])
def test_fresh_application_never_constructs_or_dispatches_effects(tmp_path, selector, state, reason):
    # Existing real SQLite bytes are preserved without reading its private rows.
    with sqlite3.connect(tmp_path / "prior-work.sqlite3") as connection:
        connection.execute("CREATE TABLE prior (value TEXT)")
        connection.execute("INSERT INTO prior VALUES ('retained private contribution')")
    env = {"PATH": os.environ.get("PATH", ""), "PYTHONDONTWRITEBYTECODE": "1"}
    if selector is not None:
        env[POLICY_ENV] = selector
    cases = [(method, concrete(path)) for method, path in HTTP]
    result = subprocess.run([
        sys.executable, str(ROOT / "tests/fixtures/standalone_ingress_probe.py"), str(ROOT), json.dumps(cases),
    ], cwd=tmp_path, env=env, capture_output=True, text=True, timeout=15)
    assert result.returncode == 0, result.stderr
    receipt = json.loads(result.stdout)
    assert receipt["policy"] == state
    assert receipt["http_refusals"] == 14 and receipt["websocket_refusals"] == 2
    assert receipt["prior_data_unchanged"] and set(receipt["effects"].values()) == {0}


def test_inventory_covers_every_route_and_only_fixed_harmless_files(monkeypatch):
    monkeypatch.delenv(POLICY_ENV, raising=False)
    app = create_app()
    def entries(routes):
        for route in routes:
            # FastAPI may retain included routers rather than flattening them.
            included = getattr(route, "original_router", None)
            if included is not None:
                yield from entries(included.routes)
            else:
                yield route
    routes = list(entries(app.routes))
    actual_http = {(method, route.path) for route in routes if isinstance(route, APIRoute)
                   for method in route.methods if route.path.startswith("/api/")}
    assert actual_http == set(HTTP)
    assert {route.path for route in routes if isinstance(route, APIWebSocketRoute)} == set(WEBSOCKETS)
    with TestClient(app) as client:
        for path in ("/", "/health", "/static/standalone.css"):
            assert client.get(path).status_code == 200
        page = client.get("/")
        assert "Task and cohort operations are unavailable" in page.text
        assert "<script" not in page.text and "<form" not in page.text and "<input" not in page.text
        assert "default-src 'none'" in page.headers["Content-Security-Policy"]
        for path in ("/static/index.html", "/static/app.js", "/docs", "/openapi.json", "/api/unknown"):
            assert client.get(path).json() == {"detail": UNAVAILABLE}


def test_independently_mounted_routers_cannot_bypass_refusal():
    app = FastAPI()
    for router in (ui_routes.ui_router, polyphony_routes.polyphony_router, ws.ws_router):
        app.include_router(router)
    with TestClient(app) as client:
        for method, path in HTTP[2:]:
            response = client.request(method, concrete(path), content=b"not-json")
            assert response.status_code == 503 and response.json() == {"detail": UNAVAILABLE}
        for path in WEBSOCKETS:
            with pytest.raises(WebSocketDisconnect) as refused:
                with client.websocket_connect(concrete(path)):
                    pytest.fail("Upgrade accepted")
            assert refused.value.code == 1008


def test_outer_gate_never_reads_body_or_calls_an_added_route(monkeypatch):
    monkeypatch.delenv(POLICY_ENV, raising=False)
    app = create_app()
    entered = Mock(side_effect=AssertionError("Added route bypassed ingress"))
    app.add_api_route("/api/future-adapter", entered, methods=["POST"])
    received = []

    async def receive():
        raise AssertionError("Unadmitted request body was consumed")

    async def send(message):
        received.append(message)

    scope = {"type": "http", "asgi": {"version": "3.0"}, "http_version": "1.1", "scheme": "http",
             "server": ("127.0.0.1", 8000), "client": ("127.0.0.1", 1), "root_path": "",
             "method": "POST", "path": "/api/future-adapter", "raw_path": b"/api/future-adapter",
             "query_string": b"token=caller-value", "headers": [(b"content-length", b"999999999"),
             (b"authorization", b"Bearer a"), (b"authorization", b"Bearer b")]}
    asyncio.run(app(scope, receive, send))
    assert received[0]["status"] == 503
    assert json.loads(received[-1]["body"]) == {"detail": UNAVAILABLE}
    entered.assert_not_called()


@pytest.mark.parametrize("event", ["issues", "issue_comment", "pull_request_review", "pull_request_review_comment", "push"])
def test_even_valid_hmac_does_not_admit_legacy_events(monkeypatch, event):
    monkeypatch.delenv(POLICY_ENV, raising=False)
    monkeypatch.setenv("GITHUB_WEBHOOK_SECRET", "fixture-secret")
    raw = b'{"action":"created","approved":true,"installation":{"id":123}}'
    signature = "sha256=" + hmac.new(b"fixture-secret", raw, hashlib.sha256).hexdigest()
    with TestClient(create_app()) as client:
        response = client.post("/api/webhook", content=raw, headers={
            "X-GitHub-Event": event, "X-GitHub-Delivery": "changed-key", "X-Hub-Signature-256": signature,
            "Authorization": "Bearer caller-token", "Origin": "https://proxy.invalid", "X-Forwarded-Proto": "https",
        })
    assert response.status_code == 503 and response.json() == {"detail": UNAVAILABLE}


def test_direct_serve_and_compose_host_bindings_are_literal_loopback(monkeypatch):
    run = Mock()
    monkeypatch.setattr("uvicorn.run", run)
    cli.serve_dashboard()
    assert run.call_args.kwargs["host"] == "127.0.0.1"
    cli.serve_dashboard("::1")
    assert run.call_args.kwargs["host"] == "::1"
    for host in ("0.0.0.0", "localhost", "::", "example.invalid"):
        with pytest.raises(ValueError, match="standalone_serve_requires_literal_loopback"):
            cli.serve_dashboard(host)
    assert run.call_count == 2
    compose = yaml.safe_load((ROOT / "docker-compose.yml").read_text())
    assert compose["services"]["openjules"]["ports"] == ["127.0.0.1:8000:8000"]
    assert "depends_on" not in compose["services"]["openjules"]
    assert "environment" not in compose["services"]["openjules"]
    assert "volumes" not in compose["services"]["openjules"]
    assert compose["services"]["dind"]["profiles"] == ["legacy-runtime"]
    assert {name for name, service in compose["services"].items() if not service.get("profiles")} == {"openjules"}
    image = (ROOT / "Dockerfile").read_text()
    assert '"--host", "0.0.0.0"' in image
    assert "ENV DOCKER_HOST" not in image and "ENV RADICLE_NODE_URL" not in image


def test_direct_trusted_cli_task_path_remains_explicit(monkeypatch):
    from src.worker import executor
    factory = Mock()
    factory.return_value.execute_task.return_value = True
    monkeypatch.setattr(executor, "TaskExecutor", factory)
    assert cli.run_cli_task("Explicit trusted command", "owner/repository") == 0
    request = factory.return_value.execute_task.call_args.args[0]
    assert request.repo_full_name == "owner/repository"
    factory.assert_called_once_with()
