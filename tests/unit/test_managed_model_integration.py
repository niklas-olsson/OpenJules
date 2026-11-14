"""Model integration contracts with real journals and HTTP, explicit runtime fixtures.

The no-listener and Docker fixtures are not isolation evidence. Real socket and
managed Docker qualification live in their separate mandatory test modules.
"""

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import asdict, replace
import json
import os
from types import SimpleNamespace

import pytest

from src.polyphony.managed_client import AuthorityUnavailable
from src.worker.docker_runtime import (
    DockerProfile,
    ExecutionReceipt,
    ManagedDockerRuntime,
)
from src.worker.lifecycle import WorkerLifecycle
import src.worker.managed_dispatch as dispatch_module
from src.worker.managed_dispatch import ManagedDispatcher
import src.worker.managed_service as service_module
import src.worker.model_broker as broker_module
from src.worker.model_broker import BrokerDenied, ModelBroker, ModelPolicy
from tests.unit.test_managed_agent import _NoListener, provider
from tests.unit.test_managed_dispatch import Authority, BASE, Runtime, SPEC
from tests.unit.test_managed_docker_runtime import IMAGE, setup_runtime  # noqa: F401

TOKEN_REFERENCE = "env:MODEL_INTEGRATION_FIXTURE_TOKEN"
TOKEN_VALUE = "fixture-model-token-only-on-host"
SCOPE_KEY = (SPEC.deployment_id, SPEC.repository, SPEC.profile)


class FixtureAuthority(Authority):
    """Deterministic supervisor protocol fixture, never actual Polyphony proof."""

    def __init__(self):
        super().__init__()
        self.permission_checks = 0
        self.permission_mutator = None
        self.requirements = "Change answer.txt from old to implemented and verify it."

    def call(self, operation, scope, **data):
        result = deepcopy(super().call(operation, scope, **data))
        if operation in {"claim", "permission"}:
            result["requirements"] = self.requirements
            result["binding"].update(
                runtime_principal="fixture-runtime",
                profile_digest="c" * 64,
                requirements_revision=1,
            )
        if operation == "permission":
            self.permission_checks += 1
            if self.permission_mutator is not None:
                self.permission_mutator(result)
        return result


class HoldingRuntime(Runtime):
    """Explicit execution fixture leaving the real lifecycle admission active."""

    def __init__(self):
        super().__init__()
        self.last_cutoff = None

    def execute_attempt(
        self, worker_id, spec, attempt_id, text, seconds, *, deadline_monotonic=None
    ):
        if attempt_id not in self.executions:
            self.executions[attempt_id] = text
            self.launches += 1
        self.last_cutoff = deadline_monotonic
        return ExecutionReceipt("running", reason="held execution fixture")


def model_payload(request_id="one"):
    return {
        "schema_version": 1,
        "request_id": request_id,
        "messages": [{"role": "user", "content": "Inspect the fixture repository"}],
    }


@contextmanager
def admitted_model_stack(tmp_path, monkeypatch, endpoint, *, admit=True):
    monkeypatch.setenv(TOKEN_REFERENCE[4:], TOKEN_VALUE)
    monkeypatch.setattr(broker_module, "_Endpoint", _NoListener)
    runtime, authority = HoldingRuntime(), FixtureAuthority()
    lifecycle = WorkerLifecycle(tmp_path / "lifecycle.db", runtime)
    profile = SimpleNamespace(
        name=SPEC.profile,
        deployment_id=SPEC.deployment_id,
        repository=SPEC.repository,
        base_commit=BASE,
        max_seconds=60,
    )
    dispatcher = None
    broker = ModelBroker(
        tmp_path / "models",
        {SCOPE_KEY: ModelPolicy(endpoint, "fixture-model", TOKEN_REFERENCE)},
        lambda binding: dispatcher.model_permission(binding),
        peer_uids={SCOPE_KEY: os.getuid()},
    )
    try:
        dispatcher = ManagedDispatcher(
            lifecycle,
            runtime,
            authority,
            [profile],
            tmp_path / "dispatch",
            model_broker=broker,
        )
        worker = lifecycle.ensure_worker(SPEC)
        if admit:
            dispatcher.tick_worker(worker)
            assert dispatcher.journal.get(worker["worker_id"])["phase"] == "dispatching"
        yield SimpleNamespace(
            runtime=runtime,
            authority=authority,
            lifecycle=lifecycle,
            dispatcher=dispatcher,
            broker=broker,
            worker=worker,
            profile=profile,
        )
    finally:
        broker.close()


@pytest.mark.parametrize(
    "field,value",
    [
        ("worker_id", "f" * 32),
        ("attempt_id", "f" * 32),
        ("repository", "github:github.com/foreign/repository"),
        ("profile", "different-profile"),
        ("profile_digest", "d" * 64),
        ("requirements", "Changed instructions"),
    ],
)
def test_inference_rechecks_the_original_canonical_binding(
    tmp_path, monkeypatch, field, value
):
    with provider() as (endpoint, requests):
        with admitted_model_stack(tmp_path, monkeypatch, endpoint) as stack:
            worker_id = stack.worker["worker_id"]
            first = stack.broker.complete(worker_id, model_payload())
            assert first["ok"] and len(requests) == 1

            def change_permission(reply):
                target = reply if field == "requirements" else reply["binding"]
                target[field] = value

            stack.authority.permission_mutator = change_permission
            # Cached output is protected by the same current permission gate.
            for request_id in ("one", "fresh-request"):
                with pytest.raises(BrokerDenied, match="not_authorized"):
                    stack.broker.complete(worker_id, model_payload(request_id))
            assert len(requests) == 1


@pytest.mark.parametrize(
    "denial", ["not_admitted", "cancelling", "stopped", "revoked", "outage"]
)
def test_inference_requires_admitted_delivery_and_current_authority(
    tmp_path, monkeypatch, denial
):
    with provider() as (endpoint, requests):
        with admitted_model_stack(tmp_path, monkeypatch, endpoint) as stack:
            if denial in {"not_admitted", "cancelling"}:
                stack.dispatcher.journal.update(
                    stack.worker["worker_id"],
                    phase="bound" if denial == "not_admitted" else "cancelling",
                )
            elif denial == "stopped":
                stack.dispatcher.stop()
            elif denial == "revoked":
                stack.authority.allowed = False
            else:

                def unavailable(_reply):
                    raise AuthorityUnavailable("fixture authority outage")

                stack.authority.permission_mutator = unavailable
            with pytest.raises(BrokerDenied, match="not_authorized"):
                stack.broker.complete(stack.worker["worker_id"], model_payload())
            assert not requests


@pytest.mark.parametrize("action", ["revoke", "close", "cancel_delivery"])
def test_permission_reply_cannot_outlive_local_revocation_before_provider_dispatch(
    tmp_path, monkeypatch, action
):
    with provider() as (endpoint, requests):
        with admitted_model_stack(tmp_path, monkeypatch, endpoint) as stack:
            worker_id = stack.worker["worker_id"]
            changed = []

            def revoke_while_permission_reply_is_pending(_reply):
                with stack.broker.connection() as db:
                    reserved = db.execute(
                        "SELECT 1 FROM calls WHERE status='reserved'"
                    ).fetchone()
                if reserved is None:
                    return
                changed.append(action)
                if action == "revoke":
                    stack.broker.revoke_attempt(worker_id, "b" * 32)
                elif action == "close":
                    stack.broker.close()
                else:
                    stack.dispatcher.journal.update(worker_id, phase="cancelling")

            stack.authority.permission_mutator = (
                revoke_while_permission_reply_is_pending
            )
            with pytest.raises(BrokerDenied, match="not_authorized"):
                stack.broker.complete(worker_id, model_payload())
            assert changed
            assert not requests, "a new provider request escaped after local revocation"
            with stack.broker.connection() as db:
                assert db.execute(
                    "SELECT status,reserved_tokens FROM calls"
                ).fetchone()[:] == ("uncertain", 2048)


def test_model_and_runtime_share_cutoff_before_authority_and_admission_delays(
    tmp_path, monkeypatch
):
    clock = [100.0]
    timer = SimpleNamespace(monotonic=lambda: clock[0])
    monkeypatch.setattr(dispatch_module, "time", timer)
    monkeypatch.setattr(broker_module, "time", timer)
    with admitted_model_stack(
        tmp_path, monkeypatch, "http://127.0.0.1:8001/v1/chat/completions", admit=False
    ) as stack:

        def delayed_permission(_reply):
            clock[0] += 3

        stack.authority.permission_mutator = delayed_permission
        admit = stack.lifecycle.begin_execution

        def delayed_admission(*args, **kwargs):
            result = admit(*args, **kwargs)
            clock[0] += 5
            return result

        prepare = stack.broker.prepare_worker

        def delayed_socket(*args, **kwargs):
            result = prepare(*args, **kwargs)
            clock[0] += 2
            return result

        monkeypatch.setattr(stack.lifecycle, "begin_execution", delayed_admission)
        monkeypatch.setattr(stack.broker, "prepare_worker", delayed_socket)
        stack.dispatcher.tick_worker(stack.worker)
        assert clock[0] == 110
        assert stack.runtime.last_cutoff == 130
        with stack.broker.connection() as db:
            row = db.execute("SELECT deadline FROM workers").fetchone()
            assert row["deadline"] == 130
        # A later generous canonical reply cannot extend the broker's binding.
        stack.broker.bind_attempt(stack.worker["worker_id"], SPEC, "b" * 32, 60)
        with stack.broker.connection() as db:
            assert db.execute("SELECT deadline FROM workers").fetchone()[0] == 130


def test_lost_capture_reply_reconciles_after_model_revocation_without_new_inference(
    tmp_path, monkeypatch
):
    with provider() as (endpoint, requests):
        with admitted_model_stack(
            tmp_path, monkeypatch, endpoint, admit=False
        ) as stack:
            worker_id = stack.worker["worker_id"]

            def finish_once(wid, spec, attempt_id, text, seconds, **_kwargs):
                assert wid == worker_id and spec == SPEC
                assert not stack.runtime.executions
                stack.broker.complete(wid, model_payload())
                stack.runtime.executions[attempt_id] = text
                stack.runtime.launches += 1
                stack.runtime.finished = True
                return stack.runtime.receipt()

            monkeypatch.setattr(stack.runtime, "execute_attempt", finish_once)
            stack.authority.lose_capture = True
            with pytest.raises(AuthorityUnavailable, match="capture reply lost"):
                stack.dispatcher.tick_worker(stack.worker)
            with stack.broker.connection() as db:
                assert db.execute("SELECT revoked FROM workers").fetchone()[0] == 1
            assert not stack.authority.terminals
            observed = stack.lifecycle.observe_worker(SPEC.scope, worker_id)
            assert observed["active_executions"] == ["b" * 32]
            stack.dispatcher.tick_worker(observed)
            assert stack.runtime.launches == len(requests) == 1
            assert len(stack.authority.claims) == len(stack.authority.candidates) == 1
            assert stack.dispatcher.journal.get(worker_id)["phase"] == "completed"
            assert (
                stack.lifecycle.observe_worker(SPEC.scope, worker_id)[
                    "active_executions"
                ]
                == []
            )


def service_config(tmp_path, *, environment_refs=None):
    profile = DockerProfile(
        SPEC.profile,
        SPEC.deployment_id,
        SPEC.repository,
        str(tmp_path / "source"),
        IMAGE,
        ("python3", "-I", "-c", "pass"),
        BASE,
        environment_refs=environment_refs or (),
    )
    config = {
        "schema_version": 1,
        "state_directory": str(tmp_path / "service"),
        "lifecycle_database": str(tmp_path / "service-lifecycle.db"),
        "credentials_file": str(tmp_path / "explicit-worker-credentials.json"),
        "authority": {
            "endpoint": "http://127.0.0.1:8002",
            "token_ref": "env:MODEL_AUTHORITY_FIXTURE_TOKEN",
        },
        "profiles": [asdict(profile)],
        "models": [
            {
                "deployment_id": SPEC.deployment_id,
                "repository": SPEC.repository,
                "profile": SPEC.profile,
                "policy": {
                    "endpoint": "http://127.0.0.1:8001/v1/chat/completions",
                    "model": "fixture-model",
                    "token_ref": TOKEN_REFERENCE,
                },
            }
        ],
    }
    return config, {"fixture-worker-token-" * 2: [SPEC.scope]}


def test_service_and_runtime_reject_guest_credential_injection(tmp_path):
    config, credentials = service_config(
        tmp_path, environment_refs={"OPENAI_API_KEY": TOKEN_REFERENCE}
    )
    with pytest.raises(ValueError, match="model_guest_credentials"):
        service_module.build_app(config, credentials)
    policy = ModelPolicy(
        "http://127.0.0.1:8001/v1/chat/completions", "fixture", TOKEN_REFERENCE
    )
    broker = ModelBroker(tmp_path / "models", {SCOPE_KEY: policy}, lambda _: 0)
    try:
        with pytest.raises(ValueError, match="cannot inject guest credentials"):
            ManagedDockerRuntime(
                tmp_path / "runtime",
                [DockerProfile(**config["profiles"][0])],
                lambda *_: None,
                model_broker=broker,
            )
    finally:
        broker.close()


@pytest.mark.parametrize("token", [None, " ", "invalid token", TOKEN_VALUE])
def test_service_readiness_matches_broker_credential_validation(
    tmp_path, monkeypatch, token
):
    # Transport and authority are explicit fixtures. Actual sockets are tested
    # elsewhere; this isolates the service's configuration/readiness decision.
    monkeypatch.setattr(ModelBroker, "check_ready", lambda _self: None)
    monkeypatch.setattr(
        "src.polyphony.managed_client.ManagedAuthorityClient.capabilities", lambda *_: {}
    )
    if token is None:
        monkeypatch.delenv(TOKEN_REFERENCE[4:], raising=False)
    else:
        monkeypatch.setenv(TOKEN_REFERENCE[4:], token)
    config, credentials = service_config(tmp_path)
    app = service_module.build_app(config, credentials)
    try:
        app.state.managed_dispatcher.running.set()
        result = app.state.worker_lifecycle.runtime.readiness(SPEC.scope, SPEC.profile)
        assert result.usable is (token == TOKEN_VALUE)
    finally:
        app.state.model_broker.close()


def test_failed_service_construction_releases_broker_ownership(tmp_path, monkeypatch):
    retained = []

    class RetainedBroker(ModelBroker):
        def __init__(self, *args, **kwargs):
            super().__init__(*args, **kwargs)
            retained.append(self)

        def check_ready(self):
            pass  # Explicit transport fixture; no Unix socket proof here.

    def failed_runtime(*_args, **_kwargs):
        raise ValueError("fixture runtime construction failure")

    monkeypatch.setattr(broker_module, "ModelBroker", RetainedBroker)
    monkeypatch.setattr(ManagedDockerRuntime, "__init__", failed_runtime)
    config, credentials = service_config(tmp_path)
    with pytest.raises(ValueError, match="fixture runtime construction failure"):
        service_module.build_app(config, credentials)
    try:
        assert len(retained) == 1
        assert retained[0].closed
        assert retained[0]._service_lock.closed
    finally:
        for broker in retained:
            broker.close()


def test_runtime_recovery_preserves_original_model_deadline_and_budget(
    tmp_path, monkeypatch, setup_runtime
):
    original, docker_fixture, profile, spec = setup_runtime
    monkeypatch.setattr(broker_module, "_Endpoint", _NoListener)
    monkeypatch.setenv(TOKEN_REFERENCE[4:], TOKEN_VALUE)
    key = (spec.deployment_id, spec.repository, spec.profile)
    authority = FixtureAuthority()
    dispatcher = None
    with provider() as (endpoint, requests):
        policy = ModelPolicy(endpoint, "fixture-model", TOKEN_REFERENCE, max_calls=1)
        broker = ModelBroker(
            tmp_path / "models",
            {key: policy},
            lambda binding: dispatcher.model_permission(binding),
        )
        try:
            runtime = ManagedDockerRuntime(
                original.root,
                [profile],
                original.readiness,
                docker_fixture,
                model_broker=broker,
            )
            lifecycle = WorkerLifecycle(tmp_path / "lifecycle.db", runtime)
            dispatcher = ManagedDispatcher(
                lifecycle,
                runtime,
                authority,
                [profile],
                tmp_path / "dispatch",
                model_broker=broker,
            )
            worker = lifecycle.ensure_worker(spec)
            wid = worker["worker_id"]
            delivery = dispatcher.journal.reserve(worker, "task-1")
            binding = authority.call(
                "claim",
                spec.scope,
                worker_id=wid,
                profile=spec.profile,
                task_id="task-1",
                request_key=delivery["request_key"],
                base=profile.base_commit,
            )
            lifecycle.begin_execution(spec.scope, wid, "b" * 32)
            dispatcher.journal.update(
                wid, phase="dispatching", binding=json.dumps(binding)
            )
            broker.bind_attempt(wid, spec, "b" * 32, 20)
            result = broker.complete(wid, model_payload())
            with broker.connection() as db:
                deadline = db.execute(
                    "SELECT deadline FROM workers WHERE worker_id=?", (wid,)
                ).fetchone()[0]
            # An orphan broker row does not become an owned worker on restart.
            broker.prepare_worker("f" * 32, replace(spec, slot_id="orphan"))
            broker.close()
            broker = ModelBroker(
                tmp_path / "models",
                {key: policy},
                lambda model_binding: dispatcher.model_permission(model_binding),
            )
            runtime = ManagedDockerRuntime(
                original.root,
                [profile],
                original.readiness,
                docker_fixture,
                model_broker=broker,
            )
            lifecycle = WorkerLifecycle(tmp_path / "lifecycle.db", runtime)
            dispatcher = ManagedDispatcher(
                lifecycle,
                runtime,
                authority,
                [profile],
                tmp_path / "dispatch",
                model_broker=broker,
            )
            runtime.restore_model_endpoints()
            assert set(broker.endpoints) == {wid}
            broker.bind_attempt(wid, spec, "b" * 32, 60)
            assert broker.complete(wid, model_payload()) == result
            with pytest.raises(BrokerDenied, match="budget_exhausted"):
                broker.complete(wid, model_payload("new-call"))
            with broker.connection() as db:
                assert (
                    db.execute(
                        "SELECT deadline FROM workers WHERE worker_id=?", (wid,)
                    ).fetchone()[0]
                    == deadline
                )
                assert db.execute(
                    "SELECT COUNT(*),SUM(reserved_tokens) FROM calls"
                ).fetchone()[:] == (1, 2048)
            assert len(requests) == 1
            assert docker_fixture.created == 1
            assert docker_fixture.executed == 0
            assert (
                runtime._labels(wid, spec)["openjules.model_policy"]
                == broker.policy_digests[key]
            )
            # Losing the broker journal must not silently mint a fresh budget
            # for a container whose creation was already dispatched.
            with broker.connection() as db:
                db.execute("DELETE FROM workers WHERE worker_id=?", (wid,))
            with pytest.raises(ValueError, match="model recovery journal is missing"):
                runtime.restore_model_endpoints()
        finally:
            broker.close()
