from concurrent.futures import ThreadPoolExecutor
import copy
import json
import os
from pathlib import Path
import shutil
import sqlite3
import subprocess
import sys
import threading

import pytest

from src.api.ingress_policy import IngressError, canonical_json, digest_json, load_policy
from src.storage.ingress_receipts import ReceiptStore, enroll_policy, initialize_store
from tests.unit.ingress_core_support import (
    TASK, activation_document, host_fixture, reserve, write_private,
)


def assert_code(expected, function, *args, **kwargs):
    with pytest.raises(IngressError) as error:
        function(*args, **kwargs)
    assert error.value.code == expected
    return error.value


def test_initialization_is_create_only_and_normal_start_never_creates(tmp_path):
    policy, _, _, _, _ = host_fixture(tmp_path, enrolled=False)
    original = policy.store_path.read_bytes()
    assert_code("receipt_store_exists", initialize_store, policy.store_path)
    assert policy.store_path.read_bytes() == original
    assert_code("policy_not_enrolled", ReceiptStore, policy)
    os.unlink(policy.store_path)
    assert_code("receipt_store_unavailable", ReceiptStore, policy)
    assert not policy.store_path.exists()


@pytest.mark.parametrize("assertion", ["existing_resolved_scope", "unknown", "", True])
def test_first_enrollment_needs_attributable_fresh_scope(tmp_path, assertion):
    policy, _, _, _, declaration_path = host_fixture(tmp_path, enrolled=False)
    assert_code("fresh_activation_required", enroll_policy, policy)
    write_private(declaration_path, activation_document(policy, assertion=assertion))
    assert_code("invalid_activation", enroll_policy, policy, declaration_path)
    with sqlite3.connect(policy.store_path) as connection:
        assert connection.execute("SELECT count(*) FROM activations").fetchone()[0] == 0


def test_activation_records_provenance_once_and_no_credentials(tmp_path):
    policy, _, environment, _, activation = host_fixture(tmp_path)
    assert_code("activation_already_recorded", enroll_policy, policy, activation)
    assert enroll_policy(policy)["enrolled"] is True
    with sqlite3.connect(policy.store_path) as connection:
        row = connection.execute("SELECT operator,os_uid,journal_id,policy_digest,assertion FROM activations").fetchone()
    assert row == ("fixture-maintainer", os.getuid(), policy.journal_id, policy.digest, "fresh_isolated_scope")
    data = policy.store_path.read_bytes()
    assert all(value.encode() not in data for value in environment.values())
    assert b"OPENJULES_INGRESS_BEARER_OPERATOR" not in data


def test_owner_flock_blocks_an_independent_process_and_enrollment(tmp_path):
    policy, path, environment, _, _ = host_fixture(tmp_path)
    with ReceiptStore(policy):
        assert_code("receipt_store_owned", enroll_policy, policy)
        code = """
import json,sys
from src.api.ingress_policy import IngressError,load_policy
from src.storage.ingress_receipts import ReceiptStore
try:
    ReceiptStore(load_policy(sys.argv[1]))
except IngressError as error:
    print(error.code)
else:
    raise AssertionError('second owner admitted')
"""
        result = subprocess.run([sys.executable, "-c", code, str(path)], env={**os.environ, **environment}, capture_output=True, text=True, timeout=10)
        assert result.returncode == 0, result.stderr
        assert result.stdout.strip() == "receipt_store_owned"
    with ReceiptStore(policy):
        pass


@pytest.mark.parametrize("handler_return", [True, False])
def test_same_key_observes_original_and_return_does_not_release_target(tmp_path, handler_return):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        admitted = reserve(store)
        operation = admitted["operation_id"]
        assert reserve(store) == admitted
        assert_code("source_identity_conflict", reserve, store, task={**TASK, "issue_body": "changed input"})
        ticket = store.fence(operation, "operator")
        assert store.fence(operation, "operator") is None
        invocation = store.begin_callback(ticket)
        private = store.claim_callback(invocation)
        assert private["operation_id"] == operation
        assert private["binding"]["repository_id"] == 123
        duplicate = store.begin_callback(ticket)
        assert store.claim_callback(duplicate) is None
        store.callback_quiesced(duplicate)
        assert_code("callbacks_active", store.close)
        observed = store.finish(invocation, handler_return=handler_return)
        assert observed["status"] == "observed"
        assert observed["result"] == {"handler_return": handler_return}
        assert observed["release_authorized"] is False
        assert reserve(store) == observed
        assert_code("target_action_fenced", reserve, store, key="new-key")
        tail_duplicate = store.begin_callback(ticket)
        assert store.claim_callback(tail_duplicate) is None
        store.callback_quiesced(tail_duplicate)
        assert_code("callbacks_active", store.close)
        store.callback_quiesced(invocation)


def test_post_boundary_refusal_is_observed_and_retains_fence(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        ticket = store.fence(receipt["operation_id"], "operator")
        invocation = store.begin_callback(ticket)
        assert store.claim_callback(invocation)
        observed = store.finish(invocation, handler_return=None, code="pull_request_unsupported")
        assert observed["dispatch_state"] == "returned"
        assert "result" not in observed
        assert_code("target_action_fenced", reserve, store, key="new-key")
        store.callback_quiesced(invocation)


def test_github_initial_identity_and_cross_ingress_target_fence(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        args = {"principal_id": "webhook", "binding_id": "repo", "source_kind": "github_issue_initial",
                "source_id": 7, "request_key": None, "actor_id": 456, "task": TASK}
        receipt = store.reserve(**args)
        # The unsigned delivery/header is deliberately absent from the API.
        assert store.reserve(**args)["operation_id"] == receipt["operation_id"]
        assert_code("source_identity_conflict", store.reserve, **{**args, "actor_id": 789})
        assert_code("target_action_fenced", reserve, store)
        assert_code("target_action_fenced", store.reserve, **{**args, "source_kind": "github_issue_comment", "source_id": 8001})


def test_original_fence_survives_binding_principal_and_policy_aliases(tmp_path):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        ticket = store.fence(receipt["operation_id"], "operator")
        store.registration_failed(ticket)
        store.callback_quiesced(ticket)
    document["policy_id"] = "policy-2"
    binding = copy.deepcopy(document["bindings"][0])
    binding["binding_id"] = "repo-alias"
    document["bindings"].append(binding)
    principal = copy.deepcopy(document["principals"][0])
    principal["principal_id"] = "operator-alias"
    principal["authentication"]["secret_ref"] = "env:OPENJULES_INGRESS_BEARER_OTHER"
    principal["grants"][0]["binding_id"] = "repo-alias"
    document["principals"].append(principal)
    environment["OPENJULES_INGRESS_BEARER_OTHER"] = "other-operator-value"
    write_private(path, document)
    changed = load_policy(path, environment)
    enroll_policy(changed)
    with ReceiptStore(changed) as store:
        assert_code("target_action_fenced", reserve, store, key="different", binding_id="repo-alias", principal_id="operator-alias")
        retained = store.read(receipt["operation_id"], "operator")
        assert retained["dispatch_state"] == "reconciliation_required"
        assert_code("receipt_not_found", store.read, receipt["operation_id"], "operator-alias")


def test_policy_identity_cannot_be_reused_or_binding_identity_redefined(tmp_path):
    _, path, environment, document, _ = host_fixture(tmp_path)
    document["principals"][0]["grants"][0]["operations"] = ["receipt.read"]
    write_private(path, document)
    assert_code("policy_identity_conflict", enroll_policy, load_policy(path, environment))
    document["policy_id"] = "policy-2"
    document["bindings"][0]["default_branch"] = "another"
    write_private(path, document)
    assert_code("binding_identity_conflict", enroll_policy, load_policy(path, environment))


def test_scope_expansion_requires_its_own_fresh_declaration(tmp_path):
    _, path, environment, document, _ = host_fixture(tmp_path)
    document["policy_id"] = "policy-2"
    another = copy.deepcopy(document["bindings"][0])
    another.update(binding_id="another", repository_id=124, repository="fixture/another", clone_url="https://github.com/fixture/another.git")
    document["bindings"].append(another)
    write_private(path, document)
    policy = load_policy(path, environment)
    assert_code("fresh_activation_required", enroll_policy, policy)
    declaration = write_private(tmp_path / "additional.json", activation_document(policy, declaration_id="activation-2", repositories=["github:124"]))
    enroll_policy(policy, declaration)
    with sqlite3.connect(policy.store_path) as connection:
        assert connection.execute("SELECT count(*) FROM activations").fetchone()[0] == 2


@pytest.mark.parametrize("change", ["policy", "secret", "ambient_alias"])
def test_queued_callback_rechecks_current_policy_and_credentials(tmp_path, change):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    store = ReceiptStore(policy)
    receipt = reserve(store)
    ticket = store.fence(receipt["operation_id"], "operator")
    invocation = store.begin_callback(ticket)
    if change == "policy":
        original = copy.deepcopy(document)
        document["principals"][0]["grants"][0]["operations"] = ["receipt.read"]
        write_private(path, document)
    elif change == "secret":
        environment["OPENJULES_INGRESS_BEARER_OPERATOR"] = "rotated"
    else:
        environment["PROVIDER_SPECIFIC_API_KEY"] = environment["OPENJULES_INGRESS_BEARER_OPERATOR"]
    assert store.claim_callback(invocation) is None
    assert_code("callbacks_active", store.close)
    store.callback_quiesced(invocation)
    if change == "policy":
        write_private(path, original)
    elif change == "secret":
        environment["OPENJULES_INGRESS_BEARER_OPERATOR"] = "test-operator-value"
    else:
        del environment["PROVIDER_SPECIFIC_API_KEY"]
    assert_code("policy_epoch_revoked", store.read, receipt["operation_id"], "operator")
    store.close_admission()
    store.close()
    renewed_policy = load_policy(path, environment)
    with ReceiptStore(renewed_policy) as reopened:
        assert reopened.read(receipt["operation_id"], "operator")["dispatch_state"] == "refused_before_effect"
        assert reserve(reopened, key="safe-new-key")["operation_id"] != receipt["operation_id"]


def test_shutdown_retains_owner_lock_until_queued_callback_quiesces(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    store = ReceiptStore(policy)
    receipt = reserve(store)
    ticket = store.fence(receipt["operation_id"], "operator")
    store.close_admission()
    assert_code("callbacks_active", store.close)
    assert_code("receipt_store_owned", ReceiptStore, policy)
    invocation = store.begin_callback(ticket)
    assert store.claim_callback(invocation) is None
    assert_code("callbacks_active", store.close)
    store.callback_quiesced(invocation)
    store.close()
    with ReceiptStore(policy) as reopened:
        assert reopened.read(receipt["operation_id"], "operator")["dispatch_state"] == "refused_before_effect"
        assert reserve(reopened, key="new-key")["status"] == "admitted"


def test_parallel_callbacks_enter_once_and_keep_custody_through_actual_return(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    store = ReceiptStore(policy)
    ticket = store.fence(reserve(store)["operation_id"], "operator")
    barrier = threading.Barrier(8)
    def claim():
        invocation = store.begin_callback(ticket)
        barrier.wait(timeout=5)
        result = store.claim_callback(invocation)
        if result is None:
            store.callback_quiesced(invocation)
        return invocation, result
    with ThreadPoolExecutor(max_workers=8) as pool:
        results = list(pool.map(lambda _: claim(), range(8)))
    assert sum(result is not None for _, result in results) == 1
    owner_invocation = next(invocation for invocation, result in results if result is not None)
    store.close_admission()
    assert_code("callbacks_active", store.close)
    assert_code("receipt_store_owned", ReceiptStore, policy)
    # A queue exception after entry must not discard that live callback owner.
    store.registration_failed(ticket)
    store.callback_quiesced(ticket)
    assert_code("callbacks_active", store.close)
    store.finish(owner_invocation, handler_return=True)
    assert_code("callbacks_active", store.close)
    store.callback_quiesced(owner_invocation)
    store.close()


@pytest.mark.parametrize("entered", [False, True])
def test_process_crash_preserves_original_operation_and_never_reschedules(tmp_path, entered):
    policy, path, environment, _, _ = host_fixture(tmp_path)
    code = """
import json,os,sys
from src.api.ingress_policy import load_policy
from src.storage.ingress_receipts import ReceiptStore
from tests.unit.ingress_core_support import reserve
store = ReceiptStore(load_policy(sys.argv[1]))
receipt = reserve(store)
ticket = store.fence(receipt['operation_id'], 'operator')
if sys.argv[2] == 'entered':
    assert store.claim_callback(store.begin_callback(ticket))
print(receipt['operation_id'], flush=True)
os._exit(17)
"""
    result = subprocess.run([sys.executable, "-c", code, str(path), "entered" if entered else "queued"], env={**os.environ, **environment}, capture_output=True, text=True, timeout=10)
    assert result.returncode == 17, result.stderr
    operation = result.stdout.strip()
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        assert receipt["operation_id"] == operation
        assert receipt["dispatch_state"] == "reconciliation_required"
        assert store.fence(operation, "operator") is None
        assert_code("target_action_fenced", reserve, store, key="new-key")


def test_receipt_projection_is_scoped_closed_and_has_no_private_inputs(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        result = store.read(receipt["operation_id"], "operator")
        assert set(result) == {"schema_version", "protocol", "operation_id", "status", "dispatch_state", "managed_authority", "release_authorized", "code"}
        assert TASK["issue_body"] not in json.dumps(result)
        assert "fixture/repo" not in json.dumps(result)
        assert_code("receipt_not_found", store.read, receipt["operation_id"], "webhook")
        assert_code("receipt_not_found", store.read, "absent", "operator")


@pytest.mark.parametrize("replace", ["store", "lock"])
def test_byte_identical_replacement_is_not_the_original_owned_store(tmp_path, replace):
    policy, *_ = host_fixture(tmp_path)
    path = policy.store_path if replace == "store" else Path(str(policy.store_path) + ".lock")
    backup = tmp_path / "replacement"
    shutil.copyfile(path, backup)
    backup.chmod(0o600)
    with ReceiptStore(policy) as store:
        os.replace(backup, path)
        assert_code("receipt_store_replaced", reserve, store)
        # Even a replacement lock with byte-identical metadata cannot admit a
        # second process/owner while the original inode remains locked.
        assert_code("receipt_store_owned" if replace == "store" else "receipt_store_replaced", ReceiptStore, policy)
        # __exit__ cannot mutate an untrusted replacement. Close this idle owner.
        store.close()
    assert_code("receipt_store_replaced", ReceiptStore, policy)


def test_lost_dispatch_registration_is_unknown_and_cannot_enter_later(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        ticket = store.fence(receipt["operation_id"], "operator")
        observed = store.registration_failed(ticket)
        assert observed["status"] == "unknown"
        invocation = store.begin_callback(ticket)
        assert store.claim_callback(invocation) is None
        store.callback_quiesced(invocation)
        assert reserve(store)["operation_id"] == receipt["operation_id"]
        assert_code("target_action_fenced", reserve, store, key="new-key")


def test_execution_epoch_validator_refuses_before_entire_adapter_boundary(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    revoked = False
    def validate():
        if revoked:
            raise IngressError("execution_credentials_changed", 503)
    with ReceiptStore(policy, epoch_validator=validate) as store:
        ticket = store.fence(reserve(store)["operation_id"], "operator")
        invocation = store.begin_callback(ticket)
        revoked = True
        assert store.claim_callback(invocation) is None
        store.callback_quiesced(invocation)
        assert store.read(ticket.operation_id, "operator")["dispatch_state"] == "refused_before_effect"


def test_conflicts_preserve_only_scoped_original_receipt(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        error = assert_code("source_identity_conflict", reserve, store, task={**TASK, "issue_body": "different"})
        assert error.receipt == receipt
        error = assert_code("target_action_fenced", reserve, store, key="other")
        assert error.receipt == receipt
        error = assert_code("target_action_fenced", store.reserve, principal_id="webhook", binding_id="repo",
                            source_kind="github_issue_initial", source_id=7, actor_id=456, request_key=None, task=TASK)
        assert error.receipt is None


def test_saturation_keeps_original_replay_available_without_new_admission(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        ticket = store.fence(receipt["operation_id"], "operator")
        store.registration_failed(ticket)
        store.callback_quiesced(ticket)
        original = reserve(store, allow_new=False)
        assert original["operation_id"] == receipt["operation_id"]
        assert original["dispatch_state"] == "reconciliation_required"
        assert_code("source_identity_conflict", reserve, store, allow_new=False, task={**TASK, "issue_body": "changed"})
        assert_code("ingress_callbacks_unavailable", reserve, store, key="new-target", allow_new=False,
                    task={**TASK, "issue_id": 8})
        with sqlite3.connect(policy.store_path) as connection:
            assert connection.execute("SELECT count(*) FROM receipts").fetchone()[0] == 1


def test_execution_rotation_and_closed_admission_preserve_original_observation(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    revoked = False
    def validate():
        if revoked:
            raise IngressError("execution_credentials_changed", 503)
    with ReceiptStore(policy, epoch_validator=validate) as store:
        ticket = store.fence(reserve(store)["operation_id"], "operator")
        invocation = store.begin_callback(ticket)
        store.claim_callback(invocation)
        observed = store.finish(invocation, handler_return=True)
        store.callback_quiesced(invocation)
        pending = reserve(store, key="pending", task={**TASK, "issue_id": 8})
        revoked = True
        assert reserve(store) == observed
        assert reserve(store, key="pending", task={**TASK, "issue_id": 8}) == pending
        failure = assert_code("execution_credentials_changed", store.fence, pending["operation_id"], "operator")
        assert failure.receipt == pending
        assert_code("execution_credentials_changed", reserve, store, key="new", task={**TASK, "issue_id": 9})
        store.close_admission()
        assert reserve(store) == observed
        refused = reserve(store, key="pending", task={**TASK, "issue_id": 8})
        assert refused["operation_id"] == pending["operation_id"]
        assert refused["dispatch_state"] == "refused_before_effect"
        assert_code("admission_closed", reserve, store, key="new", task={**TASK, "issue_id": 9})


def test_original_observation_never_uses_revoked_ingress_authentication(tmp_path):
    policy, _, environment, _, _ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        environment["OPENJULES_INGRESS_BEARER_OPERATOR"] = "rotated-ingress-auth"
        failure = assert_code("credentials_changed", reserve, store)
        assert failure.receipt is None
        assert_code("policy_epoch_revoked", store.read, receipt["operation_id"], "operator")


@pytest.mark.parametrize("field", ["issue_title", "issue_body", "request_key"])
@pytest.mark.parametrize("secret_name", ["OPENJULES_INGRESS_BEARER_OPERATOR", "OPENJULES_INGRESS_HMAC_WEBHOOK"])
def test_literal_ingress_credentials_never_enter_new_receipts(tmp_path, field, secret_name):
    policy, _, environment, _, _ = host_fixture(tmp_path)
    secret = environment[secret_name]
    changes = {"key": "prefix-" + secret + "-suffix"} if field == "request_key" else {"task": {**TASK, field: "prefix " + secret + " suffix"}}
    with ReceiptStore(policy) as store:
        failure = assert_code("ingress_secret_in_input", reserve, store, **changes)
        assert failure.status == 422 and failure.receipt is None
        assert secret not in str(failure) and field not in str(failure)
        with sqlite3.connect(policy.store_path) as connection:
            assert connection.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
            assert connection.execute("SELECT count(*) FROM target_fences").fetchone()[0] == 0
        assert secret.encode() not in policy.store_path.read_bytes()
        # Refusal does not consume the legitimate original request key/target.
        assert reserve(store)["dispatch_state"] == "reserved"


def test_literal_ingress_value_in_approved_binding_is_not_admitted(tmp_path):
    policy, *_ = host_fixture(tmp_path, mutate=lambda document: document["bindings"][0].update(default_branch="test-hmac-value"))
    with ReceiptStore(policy) as store:
        assert_code("ingress_secret_in_input", reserve, store)
        with sqlite3.connect(policy.store_path) as connection:
            assert connection.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0


def test_callback_rechecks_literal_secret_boundary_even_for_checksum_consistent_input(tmp_path):
    policy, _, environment, _, _ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        receipt = reserve(store)
        ticket = store.fence(receipt["operation_id"], "operator")
        # Controlled private-journal corruption gives the callback a matching
        # checksum but disallowed input. No external adapter receives this tree.
        with sqlite3.connect(policy.store_path) as connection:
            raw = connection.execute("SELECT normalized_input FROM receipts").fetchone()[0]
            normalized = json.loads(raw)
            normalized["task"]["issue_body"] = environment["OPENJULES_INGRESS_HMAC_WEBHOOK"]
            connection.execute("UPDATE receipts SET normalized_input=?,request_sha256=?", (canonical_json(normalized), digest_json(normalized)))
        invocation = store.begin_callback(ticket)
        assert store.claim_callback(invocation) is None
        store.callback_quiesced(invocation)
        observed = store.read(ticket.operation_id, "operator")
        assert observed["dispatch_state"] == "refused_before_effect"
        assert "test-hmac-value" not in json.dumps(observed)


def test_unobserved_callback_exit_retains_unknown_and_custody_until_ack(tmp_path):
    policy, *_ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        ticket = store.fence(reserve(store)["operation_id"], "operator")
        invocation = store.begin_callback(ticket)
        assert store.claim_callback(invocation)
        # A wrapper's finally must remain sufficient after a producer exception
        # interrupted any explicit finish/unknown observation.
        store.callback_quiesced(invocation)
        assert store.read(ticket.operation_id, "operator")["status"] == "unknown"
        assert_code("target_action_fenced", reserve, store, key="other")


def test_stopped_service_empty_grant_revocation_preserves_receipts(tmp_path):
    policy, path, environment, document, _ = host_fixture(tmp_path)
    with ReceiptStore(policy) as store:
        ticket = store.fence(reserve(store)["operation_id"], "operator")
        store.registration_failed(ticket)
        store.callback_quiesced(ticket)
    document["policy_id"] = "policy-revoked"
    document["principals"][0]["grants"] = []
    write_private(path, document)
    updated = load_policy(path, environment)
    enroll_policy(updated)
    with ReceiptStore(updated) as store:
        assert_code("scope_denied", reserve, store)
        assert_code("receipt_not_found", store.read, ticket.operation_id, "operator")
    with sqlite3.connect(policy.store_path) as connection:
        assert connection.execute("SELECT operation_id FROM target_fences").fetchone()[0] == ticket.operation_id


def test_forked_process_cannot_inherit_owner_authority(tmp_path):
    policy, path, environment, _, _ = host_fixture(tmp_path)
    script = """
import os,sys
from src.api.ingress_policy import IngressError,load_policy
from src.storage.ingress_receipts import ReceiptStore
from tests.unit.ingress_core_support import reserve
store = ReceiptStore(load_policy(sys.argv[1]))
child = os.fork()
if child == 0:
    try: reserve(store)
    except IngressError as error: os._exit(0 if error.code == 'owner_process_changed' else 12)
    os._exit(13)
_, status = os.waitpid(child,0)
assert os.waitstatus_to_exitcode(status) == 0
store.close()
"""
    result = subprocess.run([sys.executable, "-c", script, str(path)], env={**os.environ, **environment}, capture_output=True, text=True, timeout=10)
    assert result.returncode == 0, result.stderr
    with sqlite3.connect(policy.store_path) as connection:
        assert connection.execute("SELECT count(*) FROM receipts").fetchone()[0] == 0
