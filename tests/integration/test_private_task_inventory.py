"""Bounded discovery of original admissions through real ASGI and SQLite paths."""

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
from src.storage import ingress_receipts as receipts
from src.storage.ingress_receipts import ReceiptStore
from tests.integration.test_positive_ingress import (
    configured, local_client, observed, operator_headers, task_payload,
)
from tests.integration.test_private_task_reads import (
    allow_read, app_at, completed, readonly,
)
from tests.unit.ingress_core_support import TASK, host_fixture, reserve, write_private
from tests.unit.review_ingress_support import host as review_host, normalized


def retained(policy, count=1, *, body=TASK["issue_body"]):
    with ReceiptStore(policy) as store:
        return [reserve(store, key=f"key-{index}", task={
            **TASK, "issue_id": index + 1, "issue_body": body,
        })["operation_id"] for index in range(count)]


def assert_inventory(response, operations):
    assert response.status_code == 200, response.text
    assert response.headers["cache-control"] == "no-store"
    assert response.headers["x-content-type-options"] == "nosniff"
    value = response.json()
    assert set(value) == {"schema_version", "protocol", "observation", "tasks",
                          "managed_authority", "release_authorized"}
    assert value["schema_version"] == 1 and value["protocol"] == "standalone-ingress-v1"
    assert value["observation"] == "retained_dispatch_inventory"
    assert value["managed_authority"] is value["release_authorized"] is False
    assert [item["operation_id"] for item in value["tasks"]] == sorted(operations)
    for item in value["tasks"]:
        assert set(item) == {"operation_id", "binding_id", "repository", "task", "receipt"}
        assert set(item["task"]) == {"issue_id", "issue_title"}
        assert set(item["repository"]) == {"forge", "repository", "repository_id"}
        assert item["operation_id"] == item["receipt"]["operation_id"]
        assert item["receipt"]["managed_authority"] is item["receipt"]["release_authorized"] is False
    assert len(response.content) <= receipts.TASK_READ_LIMIT
    return value["tasks"]


def assert_refused(response, code="task_inventory_unavailable"):
    assert response.status_code == 503, response.text
    assert response.json()["code"] == code
    assert response.json()["operation_id"] is None
    assert "tasks" not in response.json() and "task" not in response.json()
    assert TASK["issue_title"] not in response.text
    assert TASK["issue_body"] not in response.text
    assert "private-corruption" not in response.text


def extra_bindings(document):
    allow_read(document)
    for name in ("alias", "foreign"):
        binding = {**document["bindings"][0], "binding_id": name}
        if name == "foreign":
            binding.update(repository="fixture/other", repository_id=987,
                           clone_url="https://github.com/fixture/other.git")
        document["bindings"].append(binding)
        document["principals"][0]["grants"].append({
            "binding_id": name, "operations": ["task.start"],
        })


def test_actual_admissions_are_discoverable_without_dispatch_or_body_disclosure(tmp_path, monkeypatch):
    app, path, _, _, calls = configured(tmp_path, monkeypatch, mutate=allow_read)
    title = "<script>untrusted & text</script>\n\"quoted\""
    with local_client(app) as client:
        operations = []
        for issue in (7, 8):
            reply = client.post("/api/tasks", headers=operator_headers(str(issue)),
                                json=task_payload(issue_id=issue, issue_title=title))
            assert reply.status_code == 202
            operations.append(reply.json()["operation_id"])
            observed(client, operations[-1])
        store_path = app.state.ingress_store.policy.store_path
        before = store_path.read_bytes()
        entries = assert_inventory(client.get("/api/tasks", headers=operator_headers()), operations)
        assert [entry["task"]["issue_title"] for entry in entries] == [title, title]
        for item in entries:
            individual = client.get(f"/api/tasks/{item['operation_id']}", headers=operator_headers()).json()
            assert item["receipt"] == individual["receipt"]
            assert item["task"] == {key: individual["task"][key] for key in ("issue_id", "issue_title")}
        assert store_path.read_bytes() == before
        assert len(calls) == 2
        assert TASK["issue_body"] not in canonical_json(entries)
        assert title not in client.get("/").text


def test_observation_only_reenrollment_discovers_originals_after_submitter_removal(tmp_path, monkeypatch):
    import src.api.ingress_http as ingress_http
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    document["principals"][0]["principal_id"] = "reader"
    policy = readonly(path, environment, document)

    def forbidden(*_, **__):
        pytest.fail("inventory entered an execution/queue/credential boundary")

    monkeypatch.setattr(ingress_http, "GitHubTaskAdapter", forbidden)
    monkeypatch.setattr(ingress_http, "ReviewCredentialSnapshot", forbidden)
    monkeypatch.setattr(ingress_http.CallbackQueue, "submit", forbidden)
    with local_client(app_at(path, environment, monkeypatch)) as client:
        before = policy.store_path.read_bytes()
        entries = assert_inventory(client.get("/api/tasks", headers=operator_headers()), [operation])
        assert entries[0]["receipt"]["result"] == {"handler_return": True}
        assert policy.store_path.read_bytes() == before
        assert client.post("/api/tasks", headers=operator_headers(), json=task_payload()).status_code == 403
        assert client.get(f"/api/ingress/receipts/{operation}", headers=operator_headers()).status_code == 404


@pytest.mark.parametrize("grant", ["task.start", "receipt.read", None])
def test_other_grants_and_known_identifiers_do_not_authorize_inventory(tmp_path, monkeypatch, grant):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    readonly(path, environment, document, grants=[] if grant is None else [
        {"binding_id": "repo", "operations": [grant]}])
    with local_client(app_at(path, environment, monkeypatch, task_adapter=lambda _: pytest.fail("effect"))) as client:
        response = client.get("/api/tasks", headers={**operator_headers(), "Idempotency-Key": operation})
        assert response.status_code == 403 and response.json()["code"] == "scope_denied"
        assert operation not in response.text and TASK["issue_title"] not in response.text


def test_exact_binding_scope_excludes_alias_and_foreign_corrupt_rows_before_decode(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=extra_bindings)
    with ReceiptStore(policy) as store:
        original = reserve(store, key="one")["operation_id"]
        others = [reserve(store, key=name, binding_id=name,
                          task={**TASK, "issue_id": index})["operation_id"]
                  for index, name in enumerate(("alias", "foreign"), 8)]
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        connection.executemany("UPDATE receipts SET normalized_input='private-corruption',result_json='private-corruption' WHERE operation_id=?",
                               [(operation,) for operation in others])
    with local_client(app_at(path, environment, monkeypatch)) as client:
        entries = assert_inventory(client.get("/api/tasks", headers=operator_headers()), [original])
        assert entries[0]["binding_id"] == "repo"
        assert "fixture/other" not in canonical_json(entries)


def test_multiple_current_binding_grants_select_only_their_original_rows(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=extra_bindings)
    operations = {name: completed(policy, key=name, binding_id=name,
                                 task={**TASK, "issue_id": index})
                  for index, name in enumerate(("repo", "alias", "foreign"), 1)}
    readonly(path, environment, document, grants=[
        {"binding_id": name, "operations": ["task.read"]} for name in ("repo", "foreign")])
    with local_client(app_at(path, environment, monkeypatch)) as client:
        entries = assert_inventory(client.get("/api/tasks", headers=operator_headers()),
                                   [operations["repo"], operations["foreign"]])
        assert {item["binding_id"] for item in entries} == {"repo", "foreign"}
        assert {item["repository"]["repository_id"] for item in entries} == {123, 987}


def test_known_review_rows_are_not_decoded_or_counted_as_tasks(tmp_path, monkeypatch):
    policy, path, environment, document, _, _, credentials = review_host(tmp_path, mutate=allow_read)
    with ReceiptStore(policy, review_credentials=credentials) as store:
        binding, review, actor = normalized(policy)
        operation = store.reserve_review("webhook", binding.binding_id, review, actor)["operation_id"]
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        connection.execute("UPDATE receipts SET normalized_input='private-corruption',result_json='private-corruption' WHERE operation_id=?",
                           (operation,))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        assert_inventory(client.get("/api/tasks", headers=operator_headers()), [])


@pytest.mark.parametrize("change", ["credential", "policy"])
def test_inventory_obeys_latched_ingress_epoch_revocation(tmp_path, monkeypatch, change):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    readonly(path, environment, document)
    with local_client(app_at(path, environment, monkeypatch)) as client:
        assert_inventory(client.get("/api/tasks", headers=operator_headers()), [operation])
        original = path.read_bytes()
        if change == "credential":
            monkeypatch.setenv("OPENJULES_INGRESS_BEARER_OPERATOR", "replacement-value")
        else:
            changed = deepcopy(document)
            changed["principals"][0]["grants"] = []
            write_private(path, changed)
        assert client.get("/api/tasks", headers=operator_headers()).status_code == 503
        path.write_bytes(original)
        monkeypatch.setenv("OPENJULES_INGRESS_BEARER_OPERATOR", environment["OPENJULES_INGRESS_BEARER_OPERATOR"])
        assert_refused(client.get("/api/tasks", headers=operator_headers()), "policy_epoch_revoked")


def test_interrupted_original_operation_is_listed_as_unknown_without_redispatch(tmp_path, monkeypatch):
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
    child = subprocess.run([sys.executable, "-c", program, str(path)],
                           env={**os.environ, **environment}, capture_output=True, text=True, timeout=10)
    assert child.returncode == 0, child.stderr
    operation = child.stdout.strip()
    with local_client(app_at(path, environment, monkeypatch, task_adapter=lambda _: pytest.fail("redispatch"))) as client:
        entry, = assert_inventory(client.get("/api/tasks", headers=operator_headers()), [operation])
        assert entry["receipt"]["dispatch_state"] == "reconciliation_required"
        assert entry["receipt"]["status"] == "unknown"
        assert entry["receipt"]["code"] == "owner_interrupted"


@pytest.mark.parametrize("column,value", [
    ("normalized_input", "private-corruption"),
    ("normalized_input", b"{}"),
    ("normalized_input", " " * (receipts.TASK_READ_LIMIT + 1)),
    ("request_sha256", "0" * 64),
    ("repository_key", "github:987"),
    ("target_key", "github:123:issue:999:task.start"),
    ("target_key", "private-corruption"),
    ("target_key", b"github:123:issue:1:task.start"),
    ("operation_id", "private-corruption / identifier"),
    ("result_json", '{"private-corruption":true}'),
    ("state", "private-corruption"),
    ("code", "private-corruption"),
])
def test_invalid_selected_admission_refuses_whole_inventory(tmp_path, monkeypatch, column, value):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operations = retained(policy, 2)
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        connection.execute(f"UPDATE receipts SET {column}=? WHERE operation_id=?", (value, operations[0]))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        assert_refused(client.get("/api/tasks", headers=operator_headers()), "task_state_invalid")


def test_rehashed_original_binding_is_still_validated(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        original = json.loads(connection.execute("SELECT normalized_input FROM receipts WHERE operation_id=?", (operation,)).fetchone()[0])
        original["binding"]["clone_url"] = "https://github.com/fixture/private-corruption.git"
        connection.execute("UPDATE receipts SET normalized_input=?,request_sha256=? WHERE operation_id=?",
                           (canonical_json(original), digest_json(original), operation))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        assert_refused(client.get("/api/tasks", headers=operator_headers()), "task_state_invalid")


def test_current_ingress_secret_in_omitted_body_still_refuses_projection(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    secret = "replacement-ingress-credential"
    completed(policy, task={**TASK, "issue_body": secret})
    environment["OPENJULES_INGRESS_BEARER_OPERATOR"] = secret
    readonly(path, environment, document)
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get("/api/tasks", headers={"Authorization": f"Bearer {secret}"})
        assert_refused(response, "task_state_invalid")
        assert secret not in response.text


@pytest.mark.parametrize("missing", [True, False])
def test_missing_or_replaced_original_history_is_not_an_empty_inventory(tmp_path, monkeypatch, missing):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    retained(policy)
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
        response = client.get("/api/tasks", headers=operator_headers())
        assert response.status_code == 503 and "tasks" not in response.json()
        app.state.ingress_store.close()


@pytest.mark.parametrize("change", ["anonymous", "query", "host", "origin", "forwarded"])
def test_inventory_retains_exact_authentication_and_transport_boundary(tmp_path, monkeypatch, change):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    retained(policy)
    readonly(path, environment, document)
    headers, url = operator_headers(), "/api/tasks"
    if change == "anonymous": headers.pop("Authorization")
    elif change == "query": url += "?token=test-operator-value"
    elif change == "host": headers["Host"] = "other.example"
    elif change == "origin": headers["Origin"] = "https://other.example"
    elif change == "forwarded": headers["X-Forwarded-Proto"] = "https"
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get(url, headers=headers)
        assert response.status_code in {401, 403, 422}
        assert "tasks" not in response.json() and "test-operator-value" not in response.text
    with local_client(create_app()) as client:
        assert client.get("/api/tasks", headers=operator_headers()).status_code == 503


@pytest.mark.parametrize("count", [32, 33])
def test_record_bound_is_complete_or_refused_without_truncation(tmp_path, monkeypatch, count):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operations = retained(policy, count)
    readonly(path, environment, document)
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get("/api/tasks", headers=operator_headers())
        if count == 32:
            assert_inventory(response, operations)
        else:
            assert_refused(response)


@pytest.mark.parametrize("count", [31, 32])
def test_aggregate_selected_input_includes_metadata_before_decoding(tmp_path, monkeypatch, count):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operations = retained(policy, count, body="b" * 262_144)
    readonly(path, environment, document)
    if count == 32:
        # The native bodies alone reach 8 MiB; their original binding/digest/receipt
        # metadata exceeds it. No selected row may be privately decoded first.
        monkeypatch.setattr(receipts, "_task_projection", lambda *a, **k: pytest.fail("decoded over-cap input"))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        response = client.get("/api/tasks", headers=operator_headers())
        assert_inventory(response, operations) if count == 31 else assert_refused(response)


def test_aggregate_allowance_also_counts_retained_dispatch_result_bytes(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operations = [completed(policy, key=str(index), task={**TASK, "issue_id": index + 1})
                  for index in range(9)]
    readonly(path, environment, document)
    # Valid closed JSON with large retained whitespace is still selected input.
    result = " " * (receipts.TASK_READ_LIMIT - 1024) + '{"handler_return":true}'
    with sqlite3.connect(policy.store_path) as connection:
        connection.executemany("UPDATE receipts SET result_json=? WHERE operation_id=?",
                               [(result, operation) for operation in operations])
    monkeypatch.setattr(receipts, "_task_projection", lambda *a, **k: pytest.fail("decoded over-cap receipt data"))
    with local_client(app_at(path, environment, monkeypatch)) as client:
        assert_refused(client.get("/api/tasks", headers=operator_headers()))


def test_whole_response_guard_and_sqlite_length_limit_restore_after_refusal(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operations = retained(policy, 2)
    readonly(path, environment, document)
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        store = app.state.ingress_store
        connection = store._owner.connection
        old_length = connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        result = client.get("/api/tasks", headers=operator_headers())
        assert_inventory(result, operations)
        # Shorten only this fixture's output ceiling: each original input and
        # individual projection fits, but the complete collection does not.
        with monkeypatch.context() as patch:
            patch.setattr(receipts, "TASK_READ_LIMIT", 900)
            assert_refused(client.get("/api/tasks", headers=operator_headers()))
        assert not connection.in_transaction
        assert connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == old_length
        assert client.get(f"/api/tasks/{operations[0]}", headers=operator_headers()).status_code == 200


def test_actual_scan_budget_refuses_and_restores_the_same_owned_connection(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path, mutate=extra_bindings)
    operation = completed(policy)
    foreign = completed(policy, key="foreign", binding_id="foreign")
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        # Bounded synthetic retained foreign history stresses the real unindexed
        # scan. These fixtures are never decoded or claimed as new admissions.
        connection.execute("""WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<50000)
            INSERT INTO receipts(operation_id,source_key,request_sha256,policy_id,policy_digest,
                principal_id,binding_id,repository_key,target_key,normalized_input,created_at,state,code)
            SELECT printf('scan%08d',x),printf('scan-source%08d',x),request_sha256,policy_id,policy_digest,
                principal_id,binding_id,repository_key,target_key,normalized_input,created_at,state,code
            FROM receipts,n WHERE operation_id=?""", (foreign,))
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        connection = app.state.ingress_store._owner.connection
        old_length = connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        before = policy.store_path.read_bytes()
        assert_refused(client.get("/api/tasks", headers=operator_headers()))
        assert not connection.in_transaction
        assert connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == old_length
        assert client.get(f"/api/tasks/{operation}", headers=operator_headers()).status_code == 200
        # A later query exceeding the inventory allowance proves its exhausted
        # progress handler was removed, independently of a short point lookup.
        assert connection.execute("WITH RECURSIVE n(x) AS (VALUES(1) UNION ALL SELECT x+1 FROM n WHERE x<20000) SELECT sum(x) FROM n").fetchone()[0] == 200010000
        assert policy.store_path.read_bytes() == before


def test_oversized_sqlite_cell_refuses_before_projection_and_restores_limit(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operations = retained(policy, 2)
    readonly(path, environment, document)
    with sqlite3.connect(policy.store_path) as connection:
        connection.execute("UPDATE receipts SET result_json=? WHERE operation_id=?",
                           ("private-corruption" * 150000, operations[0]))
    app = app_at(path, environment, monkeypatch)
    with local_client(app) as client:
        connection = app.state.ingress_store._owner.connection
        old_length = connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        assert_refused(client.get("/api/tasks", headers=operator_headers()))
        assert not connection.in_transaction
        assert connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == old_length
        assert client.get(f"/api/tasks/{operations[1]}", headers=operator_headers()).status_code == 200


def test_control_exception_restores_query_limits_before_original_rollback(tmp_path, monkeypatch):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    operation = completed(policy)
    policy = readonly(path, environment, document)
    original = KeyboardInterrupt()
    with ReceiptStore(policy) as store:
        connection = store._owner.connection
        old_length = connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH)
        with monkeypatch.context() as patch:
            def interrupt(*_, **__):
                raise original
            patch.setattr(receipts, "_task_projection", interrupt)
            with pytest.raises(KeyboardInterrupt) as raised:
                store.list_tasks("operator")
            assert raised.value is original
        assert not connection.in_transaction
        assert connection.getlimit(sqlite3.SQLITE_LIMIT_LENGTH) == old_length
        assert store.read_task(operation, "operator")["operation_id"] == operation
