"""Real HTTP/HMAC/SQLite admission with controlled legacy task dependencies."""

import asyncio
from contextlib import closing
from copy import deepcopy
import hashlib
import hmac
import json
import os
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time
from types import SimpleNamespace

from fastapi.testclient import TestClient
import httpx
import pytest

from src.api.ingress_policy import IngressError, load_policy
from src.api.webhook import create_app
from src.storage.ingress_receipts import ReceiptStore, enroll_policy
from tests.unit.ingress_core_support import TASK, activation_document, host_fixture, write_private


def configured(tmp_path, monkeypatch, *, adapter=None, mutate=None):
    policy, path, environment, document, _activation = host_fixture(tmp_path, mutate=mutate)
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    calls = []
    if adapter is None:
        def adapter(original):
            calls.append(original)
            return True
    app = create_app(policy_path=str(path), task_adapter=adapter)
    return app, path, document, environment, calls


def local_client(app, **kwargs):
    return TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 34567), **kwargs)


def operator_headers(key="original-key"):
    return {"Authorization": "Bearer test-operator-value", "Idempotency-Key": key}


def task_payload(**changes):
    return {"schema_version": 1, "binding_id": "repo", **TASK, **changes}


def issue_event(**changes):
    return {
        "action": "opened", "repository": {"id": 123, "full_name": "fixture/repo"},
        "sender": {"id": 456},
        "issue": {"id": 10007, "number": 7, "title": TASK["issue_title"],
                  "body": TASK["issue_body"], "labels": [{"name": "openjules:run"}]},
        **changes,
    }


def signed(value, **headers):
    body = json.dumps(value, separators=(",", ":")).encode()
    signature = "sha256=" + hmac.new(b"test-hmac-value", body, hashlib.sha256).hexdigest()
    return body, {"Content-Type": "application/json", "X-Hub-Signature-256": signature,
                  "X-GitHub-Event": "issues", "X-GitHub-Delivery": "unsigned-original", **headers}


def rows(path):
    document = json.loads(path.read_text())
    with sqlite3.connect(f"file:{document['receipt_store']['path']}?mode=ro", uri=True) as connection:
        return connection.execute("SELECT operation_id,state,code FROM receipts ORDER BY operation_id").fetchall()


def until(predicate):
    deadline = time.monotonic() + 5
    while time.monotonic() < deadline:
        result = predicate()
        if result:
            return result
        time.sleep(0.01)
    raise AssertionError("bounded fixture condition did not become observable")


def observed(client, operation):
    def read():
        response = client.get(f"/api/ingress/receipts/{operation}", headers=operator_headers())
        assert response.status_code == 200, response.text
        value = response.json()
        return value if value["dispatch_state"] in {"returned", "reconciliation_required", "refused_before_effect"} else None
    return until(read)


def test_operator_replay_lost_response_retained_result_and_static_page(tmp_path, monkeypatch):
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    with local_client(app) as client:
        client.post("/api/tasks", headers=operator_headers(), json=task_payload())  # response deliberately discarded
        repeated = client.post("/api/tasks", headers=operator_headers(), json=task_payload())
        assert repeated.status_code == 202
        operation = repeated.json()["operation_id"]
        result = observed(client, operation)
        assert result["result"] == {"handler_return": True}
        assert result["managed_authority"] is result["release_authorized"] is False
        assert len(calls) == 1 and calls[0]["operation_id"] == operation
        assert set(result) == {"schema_version", "protocol", "operation_id", "status", "dispatch_state",
                               "managed_authority", "release_authorized", "code", "result"}
        assert "Private synthetic input" not in json.dumps(result)
        conflict = client.post("/api/tasks", headers=operator_headers(), json=task_payload(issue_body="changed"))
        assert conflict.status_code == 409 and conflict.json()["operation_id"] == operation
        fresh_key = client.post("/api/tasks", headers=operator_headers("new-key"), json=task_payload())
        assert fresh_key.status_code == 409 and fresh_key.json()["code"] == "target_action_fenced"
        page = client.get("/")
        assert "static status page" in page.text
        assert all(tag not in page.text for tag in ("<form", "<input", "<script"))
        assert "test-operator-value" not in page.text and "Private synthetic input" not in page.text
        for method, url in (("GET", "/api/tasks"), ("GET", "/api/tasks/private"),
                            ("POST", "/api/polyphony/cohorts"), ("POST", "/api/radicle/webhook"),
                            ("OPTIONS", "/api/tasks"), ("POST", "/api/tasks/private/command")):
            response = client.request(method, url, headers=operator_headers(), content=b"private")
            assert response.status_code == 404 and response.json()["operation_id"] is None
    assert len(rows(path)) == 1
    # Reopening the enrolled original store never schedules old work.
    with local_client(create_app(policy_path=str(path), task_adapter=lambda _: pytest.fail("replayed"))) as client:
        assert observed(client, operation)["result"] == {"handler_return": True}
        assert client.post("/api/tasks", headers=operator_headers(), json=task_payload()).json()["operation_id"] == operation


def test_hmac_initial_number_identity_ignores_unsigned_delivery_and_vendor_metadata(tmp_path, monkeypatch):
    app, _path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    with local_client(app) as client:
        first_body, headers = signed(issue_event())
        first = client.post("/api/webhook", content=first_body, headers=headers)
        assert first.status_code == 202, first.text
        operation = first.json()["operation_id"]
        second_event = issue_event(action="labeled", arbitrary_vendor_metadata={"version": 12})
        second_event["issue"]["id"] = 999999  # global issue id is not the initial source key
        body, headers = signed(second_event, **{"X-GitHub-Delivery": "different"})
        repeated = client.post("/api/webhook", content=body, headers=headers)
        assert repeated.status_code == 202 and repeated.json()["operation_id"] == operation
        observed(client, operation)
        assert len(calls) == 1 and calls[0]["source_id"] == 7
        assert calls[0]["source_kind"] == "github_issue_initial"
        # Header substitution cannot reinterpret this signed issue as a review.
        body, headers = signed(issue_event(), **{"X-GitHub-Event": "pull_request_review"})
        assert client.post("/api/webhook", content=body, headers=headers).status_code == 404
        assert len(calls) == 1


def test_issue_comment_uses_allowlisted_author_original_comment_id_and_explicit_trigger(tmp_path, monkeypatch):
    app, _path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    event = issue_event(action="created", comment={"id": 8001, "user": {"id": 789}, "body": "/jules run\nKeep the original task."})
    event["sender"] = {"id": 999}  # comment author, not caller-style sender text, is authoritative here
    with local_client(app) as client:
        body, headers = signed(event, **{"X-GitHub-Event": "issue_comment"})
        response = client.post("/api/webhook", content=body, headers=headers)
        assert response.status_code == 202, response.text
        observed(client, response.json()["operation_id"])
        assert calls[0]["actor_id"] == 789 and calls[0]["source_id"] == 8001
        assert "Keep the original task." in calls[0]["task"]["issue_body"]
        headers["X-GitHub-Delivery"] = "changed"
        assert client.post("/api/webhook", content=body, headers=headers).json()["operation_id"] == response.json()["operation_id"]
        assert len(calls) == 1


@pytest.mark.parametrize("change", ["actor", "name", "case", "repository_id", "number_bool", "review", "review_comment", "pr", "wrong_event", "bad_signature", "no_label"])
def test_signed_source_refusals_have_no_admission_or_adapter_effects(tmp_path, monkeypatch, change):
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    event = issue_event()
    if change == "actor": event["sender"]["id"] = 999
    elif change == "name": event["repository"]["full_name"] = "other/repo"
    elif change == "case": event["repository"]["full_name"] = "Fixture/repo"
    elif change == "repository_id": event["repository"]["id"] = 999
    elif change == "number_bool": event["issue"]["number"] = True
    elif change == "review": event["review"] = {"id": 8001}
    elif change == "review_comment": event["review_comment"] = {"id": 8001}
    elif change == "pr": event["issue"]["pull_request"] = {"url": "https://api.github.com/pulls/7"}
    elif change == "no_label": event["issue"]["labels"] = []
    body, headers = signed(event)
    if change == "wrong_event": headers["X-GitHub-Event"] = "issue_comment"
    elif change == "bad_signature": headers["X-Hub-Signature-256"] = "sha256=" + "0" * 64
    with local_client(app) as client:
        response = client.post("/api/webhook", content=body, headers=headers)
        assert response.status_code in {401, 403, 404, 422}
        assert response.json()["operation_id"] is None
        assert rows(path) == [] and calls == []


@pytest.mark.parametrize("header", ["Host", "Origin", "Authorization", "Idempotency-Key", "X-Hub-Signature-256", "X-GitHub-Event", "X-GitHub-Delivery", "Content-Length"])
def test_raw_duplicate_security_headers_refuse_even_identical_values(tmp_path, monkeypatch, header):
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    body, headers = signed(issue_event())
    webhook = header.startswith("X-")
    if not webhook:
        body = json.dumps(task_payload()).encode()
        headers = {**operator_headers(), "Content-Type": "application/json"}
    headers.update({"Host": "127.0.0.1:8000", "Origin": "http://127.0.0.1:8000", "Content-Length": str(len(body))})
    duplicate = headers[header]
    raw_headers = list(headers.items()) + [(header.lower(), duplicate)]
    with local_client(app) as client:
        response = client.post("/api/webhook" if webhook else "/api/tasks", headers=raw_headers, content=body)
        assert response.status_code == 422, response.text
        assert response.json()["code"] == "ingress_headers_ambiguous"
        assert rows(path) == [] and calls == []


@pytest.mark.parametrize("change", ["anonymous", "cookie", "query", "origin", "null_origin", "host", "forwarded", "unknown_field", "schema_bool", "version", "issue_bool", "oversize", "duplicate_json"])
def test_operator_refusals_preserve_empty_original_store(tmp_path, monkeypatch, change):
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    headers = {**operator_headers(), "Content-Type": "application/json"}
    payload, url = task_payload(), "/api/tasks"
    if change == "anonymous": headers.pop("Authorization")
    elif change == "cookie":
        headers.pop("Authorization")
        headers["Cookie"] = "Authorization=Bearer test-operator-value"
    elif change == "query": url += "?token=test-operator-value"
    elif change == "origin": headers["Origin"] = "https://unapproved.example"
    elif change == "null_origin": headers["Origin"] = "null"
    elif change == "host": headers["Host"] = "unapproved.example"
    elif change == "forwarded": headers["X-Forwarded-Proto"] = "https"
    elif change == "unknown_field": payload["installation_id"] = 999
    elif change == "schema_bool": payload["schema_version"] = True
    elif change == "version": payload["schema_version"] = 2
    elif change == "issue_bool": payload["issue_id"] = True
    raw = json.dumps(payload).encode()
    if change == "oversize": raw = b" " * (1024 * 1024 + 1)
    elif change == "duplicate_json": raw = b'{"schema_version":1,"schema_version":1}'
    with local_client(app) as client:
        response = client.post(url, headers=headers, content=raw)
        assert response.status_code in {401, 403, 413, 422}
        assert response.json()["operation_id"] is response.json()["dispatch_state"] is None
        assert rows(path) == [] and calls == []


@pytest.mark.asyncio
async def test_anonymous_configured_request_never_receives_body_or_registers_callback(tmp_path, monkeypatch):
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    received, sent = [], []
    async def receive():
        received.append(True)
        raise AssertionError("unauthenticated body was read")
    async def send(message):
        sent.append(message)
    scope = {"type": "http", "method": "POST", "path": "/api/tasks", "raw_path": b"/api/tasks",
             "root_path": "", "query_string": b"", "http_version": "1.1", "scheme": "http",
             "headers": [(b"host", b"127.0.0.1:8000"), (b"content-type", b"application/json")],
             "client": ("127.0.0.1", 34567), "server": ("127.0.0.1", 8000)}
    async with app.router.lifespan_context(app):
        await app(scope, receive, send)
    assert sent[0]["status"] == 401
    assert received == [] and calls == [] and rows(path) == []


def test_queue_registration_failure_retains_unknown_original_without_retry(tmp_path, monkeypatch):
    from src.api.ingress_http import CallbackQueue
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    def fail(_coroutine):
        raise RuntimeError("private sentinel must not appear in response")
    monkeypatch.setattr(CallbackQueue, "_schedule", staticmethod(fail))
    with local_client(app) as client:
        response = client.post("/api/tasks", headers=operator_headers(), json=task_payload())
        assert response.status_code == 503
        operation = response.json()["operation_id"]
        assert response.json()["dispatch_state"] == "reconciliation_required"
        assert "private sentinel" not in response.text
        retry = client.post("/api/tasks", headers=operator_headers(), json=task_payload())
        assert retry.status_code == 202 and retry.json()["operation_id"] == operation
        assert observed(client, operation)["dispatch_state"] == "reconciliation_required"
        assert calls == []
    assert len(rows(path)) == 1


def test_queued_callback_rechecks_observed_credential_rotation_before_adapter_entry(tmp_path, monkeypatch):
    import src.api.ingress_http as ingress_http
    monkeypatch.setattr(ingress_http, "CONCURRENT_CALLBACKS", 1)
    entered, release, calls = threading.Event(), threading.Event(), []
    def adapter(original):
        calls.append(original["task"]["issue_id"])
        entered.set()
        assert release.wait(5)
        return True
    app, path, _document, _environment, _unused = configured(tmp_path, monkeypatch, adapter=adapter)
    try:
        with local_client(app) as client:
            assert client.post("/api/tasks", headers=operator_headers(), json=task_payload()).status_code == 202
            assert entered.wait(5)
            queued = client.post("/api/tasks", headers=operator_headers("queued"), json=task_payload(issue_id=8))
            assert queued.status_code == 202
            monkeypatch.setenv("OPENJULES_INGRESS_BEARER_OPERATOR", "rotated-operator-value")
            assert client.get("/api/ingress/receipts/" + queued.json()["operation_id"], headers=operator_headers()).status_code == 503
            release.set()
            until(lambda: any(row[1:] == ("refused_before_effect", "callback_authority_revoked") for row in rows(path)))
            assert calls == [7]
    finally:
        release.set()


def test_stopped_policy_cannot_reassign_binding_or_read_old_receipt_through_alias(tmp_path, monkeypatch):
    app, path, document, environment, _calls = configured(tmp_path, monkeypatch)
    with local_client(app) as client:
        operation = client.post("/api/tasks", headers=operator_headers(), json=task_payload()).json()["operation_id"]
        observed(client, operation)
    changed = deepcopy(document)
    changed["policy_id"] = "policy-2"
    changed["bindings"][0].update(repository="other/repo", repository_id=999, clone_url="https://github.com/other/repo.git")
    write_private(path, changed)
    replacement = load_policy(path)
    declaration = write_private(tmp_path / "new-activation.json", activation_document(replacement, declaration_id="activation-2", repositories=["github:999"]))
    with pytest.raises(IngressError, match="binding_identity_conflict"):
        enroll_policy(replacement, declaration)
    alias = deepcopy(document)
    alias["policy_id"] = "policy-3"
    alias_binding = deepcopy(alias["bindings"][0])
    alias_binding["binding_id"] = "alias"
    alias["bindings"].append(alias_binding)
    alias["principals"].append({"principal_id": "other-reader", "authentication": {"kind": "bearer", "secret_ref": "env:OPENJULES_INGRESS_BEARER_OTHER"},
                                "grants": [{"binding_id": "alias", "operations": ["task.start", "receipt.read"]}]})
    monkeypatch.setenv("OPENJULES_INGRESS_BEARER_OTHER", "test-other-value")
    write_private(path, alias)
    enroll_policy(load_policy(path))
    with local_client(create_app(policy_path=str(path), task_adapter=lambda _: pytest.fail("alias replayed"))) as client:
        hidden = client.get(f"/api/ingress/receipts/{operation}", headers={"Authorization": "Bearer test-other-value"})
        assert hidden.status_code == 404 and hidden.json()["operation_id"] is None
        conflict = client.post("/api/tasks", headers={"Authorization": "Bearer test-other-value", "Idempotency-Key": "alias-new"},
                               json=task_payload(binding_id="alias"))
        assert conflict.status_code == 409 and conflict.json()["operation_id"] is None
        assert observed(client, operation)["result"] == {"handler_return": True}


def test_explicit_remote_policy_supports_isolated_http_backend_without_forwarded_trust(tmp_path, monkeypatch):
    def remote(document):
        document["mode"] = "remote"
        document["transport"]["external_origin"] = "https://approved.example"
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch, mutate=remote)
    with TestClient(app, base_url="http://approved.example", client=("10.2.3.4", 54321)) as client:
        headers = {**operator_headers(), "Origin": "https://approved.example"}
        response = client.post("/api/tasks", headers=headers, json=task_payload())
        assert response.status_code == 202
        observed(client, response.json()["operation_id"])
        forwarded = client.post("/api/tasks", headers={**headers, "X-Forwarded-Proto": "https"}, json=task_payload())
        assert forwarded.status_code == 403
        assert len(calls) == 1
    assert len(rows(path)) == 1


def test_queue_saturation_does_not_hide_original_receipts_or_create_new_rows(tmp_path, monkeypatch):
    import src.api.ingress_http as ingress_http
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    with local_client(app) as client:
        operation = client.post("/api/tasks", headers=operator_headers(), json=task_payload()).json()["operation_id"]
        observed(client, operation)
        monkeypatch.setattr(ingress_http, "MAX_CALLBACKS", 0)
        replay = client.post("/api/tasks", headers=operator_headers(), json=task_payload())
        assert replay.status_code == 202 and replay.json()["operation_id"] == operation
        conflict = client.post("/api/tasks", headers=operator_headers("other-key"), json=task_payload())
        assert conflict.status_code == 409 and conflict.json()["operation_id"] == operation
        unavailable = client.post("/api/tasks", headers=operator_headers("new-target"), json=task_payload(issue_id=8))
        assert unavailable.status_code == 503 and unavailable.json()["operation_id"] is None
        assert len(rows(path)) == 1 and len(calls) == 1


def test_execution_epoch_refusal_does_not_hide_original_authenticated_http_replay(tmp_path, monkeypatch):
    class Adapter:
        changed = False
        calls = 0
        def validate_epoch(self):
            if self.changed:
                raise IngressError("execution_credentials_changed", 503)
        def __call__(self, _original):
            self.calls += 1
            return True
    adapter = Adapter()
    app, path, _document, _environment, _calls = configured(tmp_path, monkeypatch, adapter=adapter)
    with local_client(app) as client:
        operation = client.post("/api/tasks", headers=operator_headers(), json=task_payload()).json()["operation_id"]
        original = observed(client, operation)
        adapter.changed = True
        replay = client.post("/api/tasks", headers=operator_headers(), json=task_payload())
        assert replay.status_code == 202 and replay.json() == original
        assert client.post("/api/tasks", headers=operator_headers("new-target"), json=task_payload(issue_id=8)).status_code == 503
        assert observed(client, operation) == original
        assert adapter.calls == 1 and len(rows(path)) == 1


@pytest.mark.parametrize("field,secret,escaped", [
    ("issue_title", "test-operator-value", False),
    ("issue_body", "test-hmac-value", False),
    ("Idempotency-Key", "test-operator-value", False),
    ("issue_body", "test-operator-value", True),
])
def test_literal_ingress_secrets_never_enter_admitted_inputs(tmp_path, monkeypatch, field, secret, escaped):
    app, path, _document, _environment, calls = configured(tmp_path, monkeypatch)
    payload, headers = task_payload(), {**operator_headers(), "Content-Type": "application/json"}
    if field == "Idempotency-Key":
        headers[field] = "original-" + secret
    else:
        payload[field] = "literal " + secret + " inside admitted text"
    raw = json.dumps(payload).encode()
    if escaped:
        encoded = "".join("\\u%04x" % ord(character) for character in secret).encode()
        raw = raw.replace(secret.encode(), encoded)
        assert secret.encode() not in raw
    with local_client(app) as client:
        unauthenticated = client.post("/api/tasks", headers={**headers, "Authorization": "Bearer wrong-value"}, content=raw)
        assert unauthenticated.status_code == 401
        refused = client.post("/api/tasks", headers=headers, content=raw)
        assert refused.status_code == 422 and refused.json()["code"] == "ingress_secret_in_input"
        assert refused.json()["operation_id"] is refused.json()["dispatch_state"] is None
        assert secret not in refused.text
        assert rows(path) == [] and calls == []


@pytest.mark.asyncio
async def test_shutdown_revokes_unentered_callback_and_keeps_lock_until_native_thread_ends(tmp_path, monkeypatch):
    import src.api.ingress_http as ingress_http
    monkeypatch.setattr(ingress_http, "CONCURRENT_CALLBACKS", 1)
    observers = []
    original_wrap = ingress_http.wrap_future
    def track_native_future(native):
        observer = original_wrap(native)
        observers.append(observer)
        return observer
    monkeypatch.setattr(ingress_http, "wrap_future", track_native_future)
    entered, release, effects = threading.Event(), threading.Event(), []
    def adapter(original):
        effects.append(original["task"]["issue_id"])
        entered.set()
        assert release.wait(5)
        return True
    app, path, _document, _environment, _calls = configured(tmp_path, monkeypatch, adapter=adapter)
    lifetime = app.router.lifespan_context(app)
    await lifetime.__aenter__()
    shutdown = None
    try:
        transport = httpx.ASGITransport(app=app, client=("127.0.0.1", 12345))
        async with httpx.AsyncClient(transport=transport, base_url="http://127.0.0.1:8000") as client:
            first = await client.post("/api/tasks", headers=operator_headers(), json=task_payload())
            assert first.status_code == 202
            assert await asyncio.to_thread(entered.wait, 5)
            first_job = next(iter(app.state.ingress_callbacks.jobs))
            queued = await client.post("/api/tasks", headers=operator_headers("queued"), json=task_payload(issue_id=8))
            assert queued.status_code == 202
            # Cancellation of the event-loop wrapper must not shorten native
            # thread ownership or acknowledge task cancellation.
            observers[0].cancel()  # A cancelled asyncio Future is not native completion.
            first_job.cancel()
            shutdown = asyncio.create_task(lifetime.__aexit__(None, None, None))
            await asyncio.sleep(0.02)
            assert not shutdown.done()
            with pytest.raises(IngressError, match="receipt_store_owned"):
                ReceiptStore(load_policy(path))
            release.set()
            await asyncio.wait_for(shutdown, 5)
            assert effects == [7]
            assert any(row[1] == "refused_before_effect" for row in rows(path))
            with ReceiptStore(load_policy(path)):
                pass
    finally:
        release.set()
        if shutdown is None:
            await lifetime.__aexit__(None, None, None)
        elif not shutdown.done():
            await asyncio.wait_for(shutdown, 5)


def test_process_crash_after_actual_http_callback_fence_reopens_unknown_without_dispatch(tmp_path, monkeypatch):
    _app, path, _document, _environment, _calls = configured(tmp_path, monkeypatch)
    code = """
import json,os,sys,time
from fastapi.testclient import TestClient
from src.api.webhook import create_app
def interrupted(original):
    os._exit(21)
app=create_app(policy_path=sys.argv[1],task_adapter=interrupted)
with TestClient(app,base_url='http://127.0.0.1:8000',client=('127.0.0.1',34567)) as client:
    client.post('/api/tasks',headers={'Authorization':'Bearer test-operator-value','Idempotency-Key':'original-key'},json=json.loads(sys.argv[2]))
    time.sleep(5)
raise AssertionError('callback did not start')
"""
    result = subprocess.run([sys.executable, "-c", code, str(path), json.dumps(task_payload())],
                            cwd=Path(__file__).resolve().parents[2], env=dict(os.environ),
                            capture_output=True, text=True, timeout=10)
    assert result.returncode == 21, result.stderr
    with local_client(create_app(policy_path=str(path), task_adapter=lambda _: pytest.fail("crash replayed"))) as client:
        replay = client.post("/api/tasks", headers=operator_headers(), json=task_payload())
        assert replay.status_code == 202 and replay.json()["dispatch_state"] == "reconciliation_required"
        assert observed(client, replay.json()["operation_id"])["status"] == "unknown"
    assert len(rows(path)) == 1


def test_actual_selected_app_adapter_effects_all_follow_persisted_callback_claim(tmp_path, monkeypatch):
    from src.api.ingress_adapter import GitHubTaskAdapter
    def app_binding(document):
        document["bindings"][0]["installation_id"] = 99
    _app, path, _document, _environment, _calls = configured(tmp_path, monkeypatch, mutate=app_binding)
    key = tmp_path / "app-key.pem"
    key.write_text("synthetic-app-key-material")
    key.chmod(0o600)
    effects = []
    policy = load_policy(path)
    def effect(name):
        # This independent committed-row observer must not hold a competing
        # SQLite read lock while the real owner commits its next transition.
        with actual_app.state.ingress_store._mutex:
            with closing(sqlite3.connect(f"file:{policy.store_path}?mode=ro", uri=True)) as connection:
                row = connection.execute("SELECT state,callback_entered FROM receipts").fetchone()
        assert row == ("may_have_started", 1)
        effects.append(name)
    def mint(**kwargs):
        effect("mint")
        assert kwargs["installation_id"] == 99 and kwargs["safe_errors"] is True
        assert kwargs["private_key_is_content"] is True
        return "selected-installation-token"
    class Client:
        def get_repo(self, name):
            effect("repository")
            assert name == "fixture/repo"
            def get_issue(*, number):
                effect("issue")
                return SimpleNamespace(number=number, pull_request=None)
            return SimpleNamespace(id=123, full_name="fixture/repo", get_issue=get_issue)
        def close(self):
            effects.append("close")
    client = Client()
    def clients(token):
        effect("client")
        assert token == "selected-installation-token"
        return client
    def providers(**kwargs):
        effect("provider")
        assert kwargs == {"github_client": client, "token": "selected-installation-token", "allow_environment_token": False}
        return "selected-provider"
    def executors(**kwargs):
        effect("executor")
        assert kwargs == {"github_provider": "selected-provider"}
        def execute(payload, *, git_token):
            effect("execute")
            assert git_token == "selected-installation-token" and payload.installation_id is None
            assert "test-operator-value" not in payload.model_dump_json()
            return True
        return SimpleNamespace(execute_task=execute)
    adapter = GitHubTaskAdapter(bindings=policy.bindings.values(),
                                environ={"GITHUB_TOKEN": "must-not-be-used", "GITHUB_APP_ID": "42", "GITHUB_APP_PRIVATE_KEY_PATH": str(key)},
                                separation_validator=policy.assert_execution_separation,
                                app_token_factory=mint, client_factory=clients, provider_factory=providers,
                                executor_factory=executors)
    assert effects == []
    actual_app = create_app(policy_path=str(path), task_adapter=adapter)
    with local_client(actual_app) as client_http:
        assert client_http.post("/api/tasks", json=task_payload()).status_code == 401
        assert effects == [] and rows(path) == []
        response = client_http.post("/api/tasks", headers=operator_headers(), json=task_payload())
        assert response.status_code == 202
        assert observed(client_http, response.json()["operation_id"])["result"] == {"handler_return": True}
    assert effects == ["mint", "client", "repository", "issue", "provider", "executor", "execute", "close"]
