"""Scoped original task observations through the real HTTP app and journal."""

from copy import deepcopy
import json
import os
import shutil
import sqlite3
import subprocess
import sys

import pytest

from src.api.ingress_policy import IngressError, canonical_json, digest_json, load_policy
from src.api.webhook import create_app
from src.storage.ingress_receipts import ReceiptStore, TASK_READ_LIMIT, enroll_policy
from tests.integration.test_positive_ingress import (
    configured, local_client, observed, operator_headers, task_payload,
)
from tests.unit.ingress_core_support import TASK, host_fixture, reserve, write_private
from tests.unit.review_ingress_support import host as review_host, normalized


def allow_read(document):
    document["principals"][0]["grants"][0]["operations"].append("task.read")


def completed(policy, **changes):
    with ReceiptStore(policy) as store:
        receipt = reserve(store, **changes)
        ticket = store.fence(receipt["operation_id"], "operator")
        invocation = store.begin_callback(ticket)
        assert store.claim_callback(invocation)
        store.finish(invocation, handler_return=True)
        store.callback_quiesced(invocation)
    return receipt["operation_id"]


def readonly(path, environment, document, *, grants=None):
    document["policy_id"] += "-read"
    document["principals"] = [document["principals"][0]]
    document["principals"][0]["grants"] = grants if grants is not None else [
        {"binding_id": "repo", "operations": ["task.read"]}]
    write_private(path, document)
    policy = load_policy(path, environment)
    enroll_policy(policy)
    return policy


def app_at(path, environment, monkeypatch, **options):
    for name, value in environment.items():
        monkeypatch.setenv(name, value)
    return create_app(policy_path=str(path), **options)


def assert_closed_task(value, operation, task=TASK):
    assert set(value) == {"schema_version", "protocol", "observation", "operation_id", "binding_id",
                          "repository", "task", "receipt", "managed_authority", "release_authorized"}
    assert value["schema_version"] == 1 and value["protocol"] == "standalone-ingress-v1"
    assert value["observation"] == "retained_dispatch"
    assert value["operation_id"] == value["receipt"]["operation_id"] == operation
    assert value["binding_id"] == "repo"
    assert value["repository"] == {"forge": "github", "repository": "fixture/repo", "repository_id": 123}
    assert value["task"] == task
    assert value["managed_authority"] is value["release_authorized"] is False
    assert set(value["receipt"]) <= {"schema_version", "protocol", "operation_id", "status", "dispatch_state",
                                    "managed_authority", "release_authorized", "code", "result"}
    assert len(canonical_json(value).encode()) <= TASK_READ_LIMIT


def test_actual_admission_and_task_polling_do_not_redispatch_or_publish_private_html(tmp_path, monkeypatch):
    app, path, _, environment, calls = configured(tmp_path, monkeypatch, mutate=allow_read)
    task = {**TASK, "issue_body": "Private text <script>alert('inert task data')</script>"}
    with local_client(app) as client:
        accepted = client.post("/api/tasks", headers=operator_headers(), json=task_payload(**task))
        operation = accepted.json()["operation_id"]
        receipt = observed(client, operation)
        original_store = app.state.ingress_store.policy.store_path.read_bytes()
        for _ in range(3):
            response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
            assert response.status_code == 200, response.text
            assert_closed_task(response.json(), operation, task)
            assert response.json()["receipt"] == receipt
            assert response.headers["cache-control"] == "no-store"
            assert response.headers["x-content-type-options"] == "nosniff"
            assert response.headers["content-type"] == "application/json"
            assert all(secret not in response.text for secret in environment.values())
            assert str(path.parent) not in response.text and "clone_url" not in response.text
        assert app.state.ingress_store.policy.store_path.read_bytes() == original_store
        assert len(calls) == 1
        page = client.get("/").text
        assert task["issue_body"] not in page and "<script" not in page


def test_read_only_reopen_needs_no_execution_credentials_or_effectful_adapter(tmp_path, monkeypatch):
    import src.api.ingress_http as ingress_http
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    policy = readonly(path, environment, document)
    calls = []

    def forbidden(*_, **__):
        calls.append(True)
        raise AssertionError("private read entered an effectful boundary")

    monkeypatch.setattr(ingress_http, "GitHubTaskAdapter", forbidden)
    monkeypatch.setattr(ingress_http, "ReviewCredentialSnapshot", forbidden)
    monkeypatch.setattr(ingress_http.CallbackQueue, "submit", forbidden)
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        before = policy.store_path.read_bytes()
        result = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert result.status_code == 200, result.text
        assert_closed_task(result.json(), operation)
        assert result.json()["receipt"]["result"] == {"handler_return": True}
        assert policy.store_path.read_bytes() == before
        assert client.get(f"/api/ingress/receipts/{operation}", headers=operator_headers()).status_code == 404
        assert client.post("/api/tasks", headers=operator_headers(), json=task_payload()).status_code == 403
        assert calls == []


def test_stopped_service_reenrollment_can_remove_the_original_submitter(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    document["principals"][0]["principal_id"] = "reader"
    readonly(path, environment, document)
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert response.status_code == 200
        assert_closed_task(response.json(), operation)


def test_execution_epoch_changes_and_closed_admission_do_not_revoke_task_observation(tmp_path, monkeypatch):
    policy, path, environment, _, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    calls = []

    class Adapter:
        revoked = False

        def validate_epoch(self):
            calls.append("validate")
            if self.revoked:
                raise IngressError("execution_credentials_changed", 503)

        def __call__(self, _):
            pytest.fail("task observation dispatched an adapter")

    adapter = Adapter()
    app = app_at(path, environment, monkeypatch, task_adapter=adapter)
    with local_client(app) as client:
        adapter.revoked = True
        app.state.ingress_store.close_admission()
        before = list(calls)
        response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert response.status_code == 200
        assert_closed_task(response.json(), operation)
        assert calls == before


@pytest.mark.parametrize("grant", ["task.start", "receipt.read"])
def test_other_task_permissions_do_not_implicitly_grant_private_details(tmp_path, monkeypatch, grant):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    readonly(path, environment, document, grants=[{"binding_id": "repo", "operations": [grant]}])
    app = app_at(path, environment, monkeypatch, task_adapter=lambda _: pytest.fail("dispatch"))
    with local_client(app) as client:
        hidden = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        absent = client.get("/api/tasks/absent", headers=operator_headers())
        assert hidden.status_code == absent.status_code == 404
        assert hidden.json() == absent.json()
        assert hidden.json()["code"] == "task_not_found"


def test_ungranted_corrupt_task_is_hidden_before_private_data_is_parsed(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    readonly(path, environment, document, grants=[])
    with sqlite3.connect(policy.store_path) as connection:
        connection.execute("UPDATE receipts SET normalized_input='not json' WHERE operation_id=?", (operation,))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        hidden = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        absent = client.get("/api/tasks/absent", headers=operator_headers())
        assert hidden.status_code == absent.status_code == 404
        assert hidden.json() == absent.json()


@pytest.mark.parametrize("scope", ["different_repository", "new_binding_alias", "revoked_grant"])
def test_reopened_policy_keeps_original_repository_binding_and_current_scope(tmp_path, monkeypatch, scope):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    if scope == "revoked_grant":
        grants = []
    else:
        alternate = deepcopy(document["bindings"][0])
        alternate["binding_id"] = "alternate"
        if scope == "different_repository":
            alternate.update(repository="fixture/other", repository_id=987,
                             clone_url="https://github.com/fixture/other.git")
            # Enroll the separate original repository before the read-only epoch.
            document["bindings"].append(alternate)
            document["policy_id"] = "policy-expanded"
            write_private(path, document)
            expanded = load_policy(path, environment)
            from tests.unit.ingress_core_support import activation_document
            activation = write_private(tmp_path / "expanded.json", activation_document(expanded,
                declaration_id="activation-expanded", repositories=["github:987"]))
            enroll_policy(expanded, activation)
        else:
            document["bindings"].append(alternate)
        grants = [{"binding_id": "alternate", "operations": ["task.read"]}]
    readonly(path, environment, document, grants=grants)
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        hidden = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        absent = client.get("/api/tasks/absent", headers=operator_headers())
        assert hidden.status_code == absent.status_code == 404
        assert hidden.json() == absent.json()
        assert TASK["issue_body"] not in hidden.text and "fixture/repo" not in hidden.text


def test_task_read_cannot_disclose_a_review_even_under_the_same_binding(tmp_path, monkeypatch):
    policy, path, environment, document, _, _, credentials = review_host(tmp_path, mutate=allow_read)
    with ReceiptStore(policy, review_credentials=credentials) as store:
        binding, review, actor = normalized(policy)
        review_id = store.reserve_review("webhook", binding.binding_id, review, actor)["operation_id"]
    readonly(path, environment, document)
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        review_response = client.get(f"/api/tasks/{review_id}", headers=operator_headers())
        absent = client.get("/api/tasks/absent", headers=operator_headers())
        assert review_response.status_code == 404 and review_response.json() == absent.json()
        assert "Original PR" not in review_response.text


@pytest.mark.parametrize("change", ["credential", "policy"])
def test_live_epoch_invalidation_closes_reads_and_restoration_does_not_reopen(tmp_path, monkeypatch, change):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    readonly(path, environment, document)
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        assert client.get(f"/api/tasks/{operation}", headers=operator_headers()).status_code == 200
        original = path.read_bytes()
        if change == "credential":
            monkeypatch.setenv("OPENJULES_INGRESS_BEARER_OPERATOR", "rotated-test-credential")
        else:
            changed = deepcopy(document)
            changed["principals"][0]["grants"] = []
            write_private(path, changed)
        denied = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert denied.status_code == 503 and TASK["issue_body"] not in denied.text
        monkeypatch.setenv("OPENJULES_INGRESS_BEARER_OPERATOR", environment["OPENJULES_INGRESS_BEARER_OPERATOR"])
        path.write_bytes(original)
        latched = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert latched.status_code == 503 and latched.json()["code"] == "policy_epoch_revoked"
    # A new, explicitly restarted owner can use the unchanged enrolled policy.
    with local_client(app_at(path, environment, monkeypatch)) as client:
        assert client.get(f"/api/tasks/{operation}", headers=operator_headers()).status_code == 200


def test_process_interruption_is_read_as_original_unknown_without_dispatch(tmp_path, monkeypatch):
    _, path, environment, _, _ = host_fixture(tmp_path, mutate=allow_read)
    program = """
import os,sys
from src.api.ingress_policy import load_policy
from src.storage.ingress_receipts import ReceiptStore
from tests.unit.ingress_core_support import reserve
s=ReceiptStore(load_policy(sys.argv[1]))
r=reserve(s);s.fence(r['operation_id'],'operator')
print(r['operation_id'],flush=True)
os._exit(0)
"""
    child = subprocess.run([sys.executable, "-c", program, str(path)], env={**os.environ, **environment},
                           capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    operation = child.stdout.strip()
    calls = []
    app = app_at(path, environment, monkeypatch, task_adapter=lambda original: calls.append(original))
    with local_client(app) as client:
        result = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert result.status_code == 200
        assert_closed_task(result.json(), operation)
        assert result.json()["receipt"]["dispatch_state"] == "reconciliation_required"
        assert result.json()["receipt"]["code"] == "owner_interrupted"
        assert result.json()["receipt"]["status"] == "unknown"
        replay = client.post("/api/tasks", headers=operator_headers("key-1"), json=task_payload())
        assert replay.status_code == 202 and replay.json()["operation_id"] == operation
        assert calls == []


@pytest.mark.parametrize("column,value", [
    ("normalized_input", '{"private_corrupt_value":"do not disclose"}'),
    ("normalized_input", " " * (TASK_READ_LIMIT + 1)),
    ("repository_key", "github:987"),
    ("target_key", "github:123:issue:8:task.start"),
    ("target_key", b"not text"),
    ("request_sha256", "0" * 64),
    ("result_json", '{"private_corrupt_value":"do not disclose"}'),
])
def test_corrupt_original_data_is_unavailable_without_partial_projection(tmp_path, monkeypatch, column, value):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        connection.execute(f"UPDATE receipts SET {column}=? WHERE operation_id=?", (value, operation))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert response.status_code == 503
        assert response.json()["code"] == "task_state_invalid"
        assert response.json()["operation_id"] is None and "task" not in response.json()
        assert "do not disclose" not in response.text and TASK["issue_body"] not in response.text


def test_rehashed_binding_input_cannot_replace_the_original_binding(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        normalized_input = json.loads(connection.execute(
            "SELECT normalized_input FROM receipts WHERE operation_id=?", (operation,)).fetchone()[0])
        normalized_input["binding"]["clone_url"] = "https://github.com/fixture/other.git"
        connection.execute("UPDATE receipts SET normalized_input=?,request_sha256=? WHERE operation_id=?",
                           (canonical_json(normalized_input), digest_json(normalized_input), operation))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert response.status_code == 503 and response.json()["code"] == "task_state_invalid"
        assert TASK["issue_body"] not in response.text and "fixture/other" not in response.text


def test_rotated_ingress_secret_matching_retained_text_is_never_projected(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    secret = "next-epoch-secret-value"
    operation = completed(policy, task={**TASK, "issue_body": secret})
    environment["OPENJULES_INGRESS_BEARER_OPERATOR"] = secret
    readonly(path, environment, document)
    headers = {**operator_headers(), "Authorization": f"Bearer {secret}"}
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(f"/api/tasks/{operation}", headers=headers)
        assert response.status_code == 503 and response.json()["code"] == "task_state_invalid"
        assert secret not in response.text


@pytest.mark.parametrize("missing", [True, False])
def test_missing_or_replaced_live_journal_is_unavailable_never_empty(tmp_path, monkeypatch, missing):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    readonly(path, environment, document)
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        if missing:
            policy.store_path.unlink()
        else:
            replacement = tmp_path / "replacement.sqlite"
            shutil.copyfile(policy.store_path, replacement)
            replacement.chmod(0o600)
            os.replace(replacement, policy.store_path)
        response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert response.status_code == 503 and TASK["issue_body"] not in response.text
        app.state.ingress_store.close()  # No callbacks; release only this fixture's original lock.
    with pytest.raises(IngressError):
        ReceiptStore(load_policy(path, environment))
    assert policy.store_path.exists() is not missing


@pytest.mark.parametrize("change", ["anonymous", "cookie", "query", "host", "origin", "null_origin", "duplicate_auth", "forwarded"])
def test_task_detail_uses_the_same_transport_and_authentication_gate(tmp_path, monkeypatch, change):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    operation = completed(policy)
    readonly(path, environment, document)
    headers, url = operator_headers(), f"/api/tasks/{operation}"
    if change == "anonymous": headers.pop("Authorization")
    elif change == "cookie":
        headers.pop("Authorization")
        headers["Cookie"] = "Authorization=Bearer test-operator-value"
    elif change == "query": url += "?token=test-operator-value"
    elif change == "host": headers["Host"] = "other.example"
    elif change == "origin": headers["Origin"] = "https://other.example"
    elif change == "null_origin": headers["Origin"] = "null"
    elif change == "duplicate_auth": headers = list(headers.items()) + [("Authorization", "Bearer test-operator-value")]
    elif change == "forwarded": headers["X-Forwarded-Proto"] = "https"
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(url, headers=headers)
        assert response.status_code in {401, 403, 422}
        assert response.json()["operation_id"] is None and TASK["issue_body"] not in response.text


@pytest.mark.parametrize("character", ["b", "\U0001f331"])
def test_maximum_native_task_fields_have_one_bounded_json_projection(tmp_path, monkeypatch, character):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    width = len(character.encode("utf-8"))
    task = {"issue_id": 7, "issue_title": character * (1024 // width), "issue_body": character * (262144 // width)}
    operation = completed(policy, task=task)
    readonly(path, environment, document)
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert response.status_code == 200
        assert_closed_task(response.json(), operation, task)
        assert len(response.content) <= TASK_READ_LIMIT


@pytest.mark.parametrize("count,expected", [(174650, 200), (174660, 503)])
def test_response_ceiling_counts_json_escapes_not_only_stored_or_native_text(tmp_path, monkeypatch, count, expected):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=allow_read)
    task = {**TASK, "issue_body": "\x01" * count}
    operation = completed(policy, task=task)
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        retained = connection.execute("SELECT normalized_input FROM receipts WHERE operation_id=?", (operation,)).fetchone()[0]
        assert len(retained.encode("utf-8")) < TASK_READ_LIMIT
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(f"/api/tasks/{operation}", headers=operator_headers())
        assert response.status_code == expected
        assert len(response.content) <= TASK_READ_LIMIT
        if expected == 200:
            assert_closed_task(response.json(), operation, task)
        else:
            assert response.json()["code"] == "task_state_invalid" and "task" not in response.json()
