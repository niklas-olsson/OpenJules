from dataclasses import replace
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from src.polyphony.child_client import ChildAuthorityClient, ChildRejected
from src.polyphony.managed_client import AuthorityUnavailable, ManagedAuthorityClient
from src.worker.child_journal import ChildJournal
from src.worker.child_types import (
    ChildPolicy,
    DelegatedGrant,
    DelegatedGrantBinding,
    RootContext,
    Subgrant,
    SubLease,
    digest,
    text_hash,
    verify_delegated_grant,
    verify_grant,
)
from src.worker.lifecycle import LifecycleConflict, WorkerSpec


def policy():
    return ChildPolicy(2, 20, 3, ("python",))


def context():
    return RootContext(
        "a" * 32,
        WorkerSpec(
            "deployment",
            "github:github.com/owner/repo",
            "slot",
            1,
            "launch",
            "child-profile",
        ),
        "attempt_root",
        "task_root",
        "runtime",
        "b" * 64,
        1,
        "c" * 40,
        2000000000,
        1000,
        "boot-one",
    )


def request():
    return {
        "instructions": "Change the file.",
        "seconds": 10,
        "max_turns": 2,
        "capabilities": ["python"],
    }


def grant(root=None, payload=None, child_id="child_" + "d" * 32):
    root, payload = root or context(), payload or request()
    binding = {
        "child_id": child_id,
        "root_attempt_id": root.attempt_id,
        "parent_attempt_id": root.attempt_id,
        "task_id": root.task_id,
        "deployment_id": root.spec.deployment_id,
        "repository": root.spec.repository,
        "runtime_principal": root.runtime_principal,
        "worker_id": root.worker_id,
        "profile": root.spec.profile,
        "profile_digest": root.profile_digest,
        "requirements_revision": root.requirements_revision,
        "base": root.base,
        "launch_key": "polyphony-child:" + child_id,
        "allocated_seconds": payload["seconds"],
        "deadline": root.deadline - 5,
        "max_turns": payload["max_turns"],
        "capabilities": payload["capabilities"],
        "instructions_digest": text_hash(payload["instructions"]),
    }
    binding["grant_digest"] = digest(binding)
    child = {
        "id": child_id,
        "binding": binding,
        "instructions": payload["instructions"],
        "state": "unknown",
        "termination_confirmed": False,
        "turns_allocated": 0,
    }
    return {
        "schema_version": 1,
        "deployment_id": root.spec.deployment_id,
        "repository": root.spec.repository,
        "root_attempt_id": root.attempt_id,
        "child": child,
        "binding": binding,
        "instructions": payload["instructions"],
        "launch_allowed": True,
        "remaining_seconds": 9,
        "reason": "allowed",
    }


def test_policy_uid_and_exact_capability_boundary():
    p = policy()
    p.validate_root(65532, 60)
    assert p.request(request()) == request()
    p.validate_capabilities({"child_grants": True, "child_policy": p.canonical_policy})
    for bad in (replace(p, uid_start=65531), replace(p, max_child_seconds=80)):
        with pytest.raises(ValueError):
            bad.validate_root(65532, 60)
    with pytest.raises(ValueError):
        replace(p, uid_start=0)
    with pytest.raises(ValueError):
        replace(p, uid_start=65534)
    with pytest.raises(ValueError):
        p.request(request() | {"capabilities": []})
    with pytest.raises(ValueError):
        p.request(request() | {"command": ["sh"]})
    with pytest.raises(AuthorityUnavailable):
        p.validate_capabilities(
            {
                "child_grants": True,
                "child_policy": p.canonical_policy | {"max_children": 3},
            }
        )


def test_delegated_grant_capability_attenuation():
    root, p, response = context(), policy(), grant()
    delegated = verify_delegated_grant(response, root, p, request())
    assert isinstance(delegated, DelegatedGrant)
    assert isinstance(delegated, Subgrant)
    assert isinstance(delegated, SubLease)
    assert isinstance(delegated.binding, DelegatedGrantBinding)
    assert delegated.child_id == response["binding"]["child_id"]
    assert delegated.grant_digest == response["binding"]["grant_digest"]
    assert delegated.instructions_digest == response["binding"]["instructions_digest"]
    assert delegated.instructions == response["instructions"]
    assert delegated.launch_allowed is True
    assert delegated.remaining_seconds == 9
    assert delegated.reason == "allowed"
    assert delegated.binding.to_dict() == response["binding"]
    assert delegated.to_dict() == response


def test_immutable_grant_replay_after_revocation():
    root, p, response = context(), policy(), grant()
    assert verify_grant(response, root, p, request()) == response
    denied = response | {
        "launch_allowed": False,
        "remaining_seconds": 0,
        "reason": "revoked",
    }
    assert (
        verify_grant(denied, root, p, request(), response)["binding"]
        == response["binding"]
    )
    for field, value in (
        ("worker_id", "other"),
        ("repository", "foreign"),
        ("parent_attempt_id", "child_bad"),
        ("requirements_revision", 2),
        ("deadline", root.deadline + 1),
        ("capabilities", []),
    ):
        changed = json.loads(json.dumps(response))
        changed["binding"][field] = value
        changed["binding"]["grant_digest"] = digest(
            {
                key: item
                for key, item in changed["binding"].items()
                if key != "grant_digest"
            }
        )
        changed["child"]["binding"] = changed["binding"]
        with pytest.raises(AuthorityUnavailable):
            verify_grant(changed, root, p, request(), response)


def test_delivery_journal_never_reallocates_after_close_or_restart(tmp_path):
    root, p = context(), policy()
    journal = ChildJournal(tmp_path / "journal")
    journal.prepare(root.worker_id, root.spec, p)
    journal.bind(root)
    first = journal.reserve(root.worker_id, "request-one", request(), p)
    with pytest.raises(LifecycleConflict):
        journal.reserve(
            root.worker_id, "request-one", request() | {"instructions": "changed"}, p
        )
    row = journal.grant(root.worker_id, "request-one", grant(), 900, root.boot_id, p)
    journal.update(
        root.worker_id,
        row["child_id"],
        exec_id="exec-one",
        exec_dispatched=1,
        phase="dispatching",
    )
    journal.close_admission(root.worker_id, "drain")
    assert (
        journal.reserve(root.worker_id, "request-one", request(), p)["delivery_key"]
        == first["delivery_key"]
    )
    with pytest.raises(LifecycleConflict):
        journal.reserve(root.worker_id, "request-two", request(), p)
    journal.close()
    journal = ChildJournal(tmp_path / "journal")
    try:
        journal.prepare(root.worker_id, root.spec, p)
        recovered = journal.child(root.worker_id, row["child_id"])
        assert recovered["uid"] == p.uid_start and recovered["exec_id"] == "exec-one"
        assert recovered["exec_dispatched"] == 1
        retry = journal.grant(
            root.worker_id, "request-one", grant(), 999, root.boot_id, p
        )
        assert retry["deadline"] == 900
        for changes in ({"exec_id": "another"}, {"exec_dispatched": 0}):
            with pytest.raises(LifecycleConflict):
                journal.update(root.worker_id, row["child_id"], **changes)
    finally:
        journal.close()


def test_unknown_intents_hold_slots_but_proven_rejection_does_not(tmp_path):
    root, p = context(), policy()
    journal = ChildJournal(tmp_path / "journal")
    try:
        journal.prepare(root.worker_id, root.spec, p)
        journal.bind(root)
        journal.reserve(root.worker_id, "one", request(), p)
        journal.reserve(root.worker_id, "two", request(), p)
        with pytest.raises(LifecycleConflict):
            journal.reserve(root.worker_id, "three", request(), p)
        journal.reject(root.worker_id, "one")
        journal.reserve(root.worker_id, "three", request(), p)
        bound = journal.grant(root.worker_id, "two", grant(), 900, root.boot_id, p)
        with pytest.raises(LifecycleConflict):
            journal.child("other-worker", bound["child_id"])
    finally:
        journal.close()


def test_child_http_transport_requires_precise_unallocated_code(monkeypatch):
    responses = [
        (409, {"code": "child_not_allocated"}),
        (409, {"code": "conflict"}),
        (200, grant()),
    ]
    observed = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            payload = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
            observed.append((self.path, self.headers.get("Authorization"), payload))
            status, value = responses.pop(0)
            raw = json.dumps(value).encode()
            self.send_response(status)
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

        def log_message(self, *args):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    monkeypatch.setenv("TEST_CHILD_AUTHORITY_TOKEN", "t" * 48)
    root = context()
    client = ChildAuthorityClient(
        ManagedAuthorityClient(
            f"http://127.0.0.1:{server.server_port}", "env:TEST_CHILD_AUTHORITY_TOKEN"
        )
    )
    try:
        for expected in (True, False):
            with pytest.raises(ChildRejected) as caught:
                client.call(
                    "grant",
                    root.spec.scope,
                    root.attempt_id,
                    request_key="key",
                    **request(),
                )
            assert caught.value.child_not_allocated is expected
        response = client.call(
            "grant", root.spec.scope, root.attempt_id, request_key="key", **request()
        )
        assert response["binding"] == grant()["binding"]
        assert all(
            path == "/managed/children/grant" and token == "Bearer " + "t" * 48
            for path, token, _ in observed
        )
        assert all(item[2]["attempt_id"] == root.attempt_id for item in observed)
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
