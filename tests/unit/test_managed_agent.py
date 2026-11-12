"""Real journal/HTTP logic tests with an explicit no-listener fixture."""

from contextlib import contextmanager
from dataclasses import replace
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import socket
import struct
import sys
import threading
import time
from types import SimpleNamespace

import pytest

import src.worker.model_broker as model_broker
from src.agent.managed_runner import BrokerClient, BrokerError, LocalTools, run_agent
from src.worker.lifecycle import WorkerSpec
from src.worker.model_broker import BrokerDenied, ModelBroker, ModelPolicy

WORKER = "a" * 32
ATTEMPT = "b" * 32
SPEC = WorkerSpec(
    "installation",
    "github:github.com/example/project",
    "slot-1",
    1,
    "launch-1",
    "coding",
)
SCOPE_KEY = (SPEC.deployment_id, SPEC.repository, SPEC.profile)
MESSAGES = [{"role": "user", "content": "Inspect the repository"}]
TEST_TOKEN = "mock-provider-credential-only"


def message(tool="finish", **arguments):
    return {
        "role": "assistant",
        "content": None,
        "tool_calls": [
            {
                "id": "call-fixture",
                "type": "function",
                "function": {
                    "name": tool,
                    "arguments": json.dumps(arguments or {"summary": "Done"}),
                },
            }
        ],
    }


@contextmanager
def provider(callback=None):
    requests = []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            length = int(self.headers["Content-Length"])
            body = json.loads(self.rfile.read(length))
            requests.append(
                {
                    "path": self.path,
                    "authorization": self.headers.get("Authorization"),
                    "body": body,
                }
            )
            if callback:
                callback(self, requests)
            else:
                response(self, message())

        def log_message(self, *_):
            pass

    http = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=http.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{http.server_port}/v1/chat/completions", requests
    finally:
        http.shutdown()
        http.server_close()
        thread.join(2)


def response(handler, assistant):
    body = json.dumps({"choices": [{"message": assistant}]}).encode()
    handler.send_response(200)
    handler.send_header("Content-Type", "application/json")
    handler.send_header("Content-Length", str(len(body)))
    handler.end_headers()
    handler.wfile.write(body)


class _NoListener:
    """Unit fixture only: exercise real journal/HTTP without a local socket."""

    def __init__(self, *_):
        self.thread = self
        self.stop_requested = threading.Event()

    def is_alive(self):
        return True

    def stop(self):
        self.stop_requested.set()
        self.is_alive = lambda: False

    def join(self, *_):
        pass


class _DirectClient:
    def __init__(self, broker):
        self.broker = broker

    def complete(self, messages, request_id=None):
        from uuid import uuid4

        try:
            result = self.broker.complete(
                WORKER,
                {
                    "schema_version": 1,
                    "request_id": request_id or uuid4().hex,
                    "messages": messages,
                },
            )
        except BrokerDenied as exc:
            raise BrokerError(exc.code) from None
        return result["message"]


@contextmanager
def broker_client(
    tmp_path, monkeypatch, endpoint, *, permission=lambda _: 60, policy=None, uds=False
):
    monkeypatch.setenv("MOCK_MODEL_TOKEN", TEST_TOKEN)
    policy = policy or ModelPolicy(endpoint, "fixture-model", "env:MOCK_MODEL_TOKEN")
    with monkeypatch.context() as local_patch:
        if not uds:
            local_patch.setattr(model_broker, "_Endpoint", _NoListener)
        broker = ModelBroker(
            tmp_path / "private",
            {SCOPE_KEY: policy},
            permission,
            peer_uids={SCOPE_KEY: os.getuid()},
        )
        descriptor = None
        try:
            directory = broker.prepare_worker(WORKER, SPEC)
            broker.bind_attempt(WORKER, SPEC, ATTEMPT, 60)
            if uds:
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                client = BrokerClient(
                    f"/proc/self/fd/{descriptor}/model.sock", timeout_seconds=2
                )
            else:
                client = _DirectClient(broker)
            yield broker, client, policy
        finally:
            if descriptor is not None:
                os.close(descriptor)
            broker.close()


def test_model_http_forwards_only_server_owned_configuration(tmp_path, monkeypatch):
    with provider() as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint) as (broker, client, _):
            answer = client.complete(MESSAGES, "first")
            assert answer["tool_calls"][0]["function"]["name"] == "finish"
            assert TEST_TOKEN not in json.dumps(answer)
            assert len(requests) == 1
            assert requests[0]["authorization"] == "Bearer " + TEST_TOKEN
            assert requests[0]["body"]["model"] == "fixture-model"
            assert requests[0]["body"]["max_tokens"] == 2048
            assert requests[0]["body"]["stream"] is False
            assert requests[0]["path"] == "/v1/chat/completions"
            assert (tmp_path / "private").stat().st_mode & 0o777 == 0o700
            assert (tmp_path / "private" / WORKER).stat().st_mode & 0o777 == 0o711


def test_completed_retry_reuses_response_and_changed_retry_conflicts(
    tmp_path, monkeypatch
):
    with provider() as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint) as (broker, client, _):
            first = client.complete(MESSAGES, "same")
            assert client.complete(MESSAGES, "same") == first
            with pytest.raises(BrokerError, match="conflict"):
                client.complete([{"role": "user", "content": "different"}], "same")
            assert len(requests) == 1
            with broker.connection() as db:
                assert db.execute(
                    "SELECT COUNT(*),SUM(reserved_tokens) FROM calls"
                ).fetchone()[:] == (1, 2048)


def test_uncertain_provider_reply_is_not_replayed_even_with_new_request_key(
    tmp_path, monkeypatch
):
    def lose_reply(handler, requests):
        handler.send_response(200)
        handler.send_header("Content-Length", "500")
        handler.end_headers()
        handler.wfile.write(b'{"choices":')
        handler.wfile.flush()
        handler.close_connection = True

    with provider(lose_reply) as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint) as (broker, client, _):
            with pytest.raises(BrokerError, match="uncertain"):
                client.complete(MESSAGES, "lost")
            for key in ["lost", "another"]:
                with pytest.raises(BrokerError, match="uncertain"):
                    client.complete(MESSAGES, key)
            assert len(requests) == 1
            with broker.connection() as db:
                assert db.execute(
                    "SELECT status,reserved_tokens FROM calls"
                ).fetchone()[:] == ("uncertain", 2048)


def test_durable_token_budget_is_reserved_before_calls(tmp_path, monkeypatch):
    with provider() as (endpoint, requests):
        policy = ModelPolicy(
            endpoint,
            "fixture-model",
            "env:MOCK_MODEL_TOKEN",
            max_calls=10,
            max_output_tokens=8,
            max_total_output_tokens=10,
        )
        with broker_client(tmp_path, monkeypatch, endpoint, policy=policy) as (
            _,
            client,
            _,
        ):
            client.complete(MESSAGES, "one")
            client.complete(MESSAGES, "two")
            with pytest.raises(BrokerError, match="budget_exhausted"):
                client.complete(MESSAGES, "three")
            assert [r["body"]["max_tokens"] for r in requests] == [8, 2]


def test_current_canonical_permission_is_required_before_every_call(
    tmp_path, monkeypatch
):
    permitted = [True]
    with provider() as (endpoint, requests):
        with broker_client(
            tmp_path,
            monkeypatch,
            endpoint,
            permission=lambda _: 60 if permitted[0] else 0,
        ) as (_, client, _):
            client.complete(MESSAGES, "before")
            permitted[0] = False
            for key in ["before", "after"]:
                with pytest.raises(BrokerError, match="not_authorized"):
                    client.complete(MESSAGES, key)
            assert len(requests) == 1


def test_permission_is_rechecked_after_durable_budget_reservation(
    tmp_path, monkeypatch
):
    checks = []

    def permission(_):
        checks.append(True)
        return 60 if len(checks) == 1 else 0

    with provider() as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint, permission=permission) as (
            broker,
            client,
            _,
        ):
            with pytest.raises(BrokerError, match="not_authorized"):
                client.complete(MESSAGES, "revoked-before-forward")
            assert len(checks) == 2
            assert not requests
            with broker.connection() as db:
                assert db.execute(
                    "SELECT status,reserved_tokens FROM calls"
                ).fetchone()[:] == ("uncertain", 2048)


def test_guest_cannot_select_provider_or_other_attempt(tmp_path, monkeypatch):
    with provider() as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint) as (broker, _, _):
            for extra in [
                {"model": "expensive"},
                {"endpoint": "https://other.invalid"},
                {"attempt_id": "foreign"},
                {"token_ref": "env:SECRET"},
                {"max_tokens": 999999},
            ]:
                with pytest.raises(BrokerDenied, match="invalid_request"):
                    broker.complete(
                        WORKER,
                        {
                            "schema_version": 1,
                            "request_id": "forged",
                            "messages": MESSAGES,
                            **extra,
                        },
                    )
            assert not requests


def test_restart_preserves_deadline_budget_and_response(tmp_path, monkeypatch):
    monkeypatch.setenv("MOCK_MODEL_TOKEN", TEST_TOKEN)
    monkeypatch.setattr(model_broker, "_Endpoint", _NoListener)
    with provider() as (endpoint, requests):
        policy = ModelPolicy(
            endpoint, "fixture-model", "env:MOCK_MODEL_TOKEN", max_calls=1
        )
        root = tmp_path / "private"
        broker = ModelBroker(root, {SCOPE_KEY: policy}, lambda _: 100)
        broker.prepare_worker(WORKER, SPEC)
        broker.bind_attempt(WORKER, SPEC, ATTEMPT, 20)
        payload = {"schema_version": 1, "request_id": "one", "messages": MESSAGES}
        result = broker.complete(WORKER, payload)
        with broker.connection() as db:
            deadline = db.execute("SELECT deadline FROM workers").fetchone()[0]
        broker.close()
        recovered = ModelBroker(root, {SCOPE_KEY: policy}, lambda _: 100)
        try:
            recovered.prepare_worker(WORKER, SPEC)
            recovered.bind_attempt(WORKER, SPEC, ATTEMPT, 100)
            assert recovered.complete(WORKER, payload) == result
            with recovered.connection() as db:
                assert (
                    db.execute("SELECT deadline FROM workers").fetchone()[0] == deadline
                )
            with pytest.raises(BrokerDenied, match="budget_exhausted"):
                recovered.complete(WORKER, payload | {"request_id": "two"})
            assert len(requests) == 1
        finally:
            recovered.close()


def test_new_boot_and_changed_worker_binding_fail_closed(tmp_path, monkeypatch):
    with provider() as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint) as (broker, client, _):
            with pytest.raises(ValueError, match="binding changed"):
                broker.prepare_worker(WORKER, replace(SPEC, slot_id="other-slot"))
            with pytest.raises(BrokerDenied, match="not_authorized"):
                broker.prepare_worker(
                    WORKER, replace(SPEC, repository="github:github.com/other/repo")
                )
            with broker.connection() as db:
                db.execute("UPDATE workers SET boot_id='previous-boot'")
            with pytest.raises(BrokerError, match="not_authorized"):
                client.complete(MESSAGES, "after-reboot")
            assert not requests


def test_revoke_prevents_rebinding_attempt(tmp_path, monkeypatch):
    with provider() as (endpoint, _):
        with broker_client(tmp_path, monkeypatch, endpoint) as (broker, _, _):
            broker.revoke_attempt(WORKER, ATTEMPT)
            with pytest.raises(BrokerDenied, match="not_authorized"):
                broker.bind_attempt(WORKER, SPEC, ATTEMPT, 60)


@pytest.mark.parametrize("original_cutoff,expected", [(None, 110), (108, 108)])
def test_binding_time_never_extends_cutoff_across_preparation(
    tmp_path, monkeypatch, original_cutoff, expected
):
    clock = [100]
    monkeypatch.setattr(
        model_broker, "time", SimpleNamespace(monotonic=lambda: clock[0])
    )
    monkeypatch.setattr(model_broker, "_Endpoint", _NoListener)
    policy = ModelPolicy(
        "http://127.0.0.1:8001/v1/chat/completions", "model", "env:MOCK_MODEL_TOKEN"
    )
    broker = ModelBroker(tmp_path / "broker", {SCOPE_KEY: policy}, lambda _: 30)
    prepare = broker.prepare_worker

    def slow_prepare(worker_id, spec):
        directory = prepare(worker_id, spec)
        clock[0] += 5
        return directory

    monkeypatch.setattr(broker, "prepare_worker", slow_prepare)
    try:
        broker.bind_attempt(
            WORKER, SPEC, ATTEMPT, 10, deadline_monotonic=original_cutoff
        )
        with broker.connection() as db:
            assert db.execute("SELECT deadline FROM workers").fetchone()[0] == expected
        clock[0] = 106
        with pytest.raises(BrokerDenied, match="not_authorized"):
            broker.bind_attempt(WORKER, SPEC, ATTEMPT, 60)
        with broker.connection() as db:
            assert db.execute("SELECT deadline FROM workers").fetchone()[0] == expected
    finally:
        broker.close()


def test_model_policy_is_immutable_even_before_any_worker_exists(tmp_path):
    policy = ModelPolicy(
        "http://127.0.0.1:8001/v1/chat/completions", "model-a", "env:MOCK_MODEL_TOKEN"
    )
    state = tmp_path / "broker"
    broker = ModelBroker(state, {SCOPE_KEY: policy}, lambda _: 30)
    broker.close()
    with pytest.raises(ValueError, match="new profile name"):
        ModelBroker(state, {SCOPE_KEY: replace(policy, model="model-b")}, lambda _: 30)
    with pytest.raises(ValueError, match="new profile name"):
        ModelBroker(
            state, {SCOPE_KEY: policy}, lambda _: 30, peer_uids={SCOPE_KEY: 12345}
        )
    # Failed construction must release the service lock and must not replace
    # the existing policy fingerprint.
    recovered = ModelBroker(state, {SCOPE_KEY: policy}, lambda _: 30)
    recovered.close()
    new_key = (SPEC.deployment_id, SPEC.repository, "coding-v2")
    replacement = ModelBroker(
        state,
        {SCOPE_KEY: policy, new_key: replace(policy, model="model-b")},
        lambda _: 30,
    )
    replacement.close()


def test_readiness_fails_when_local_unix_transport_is_unavailable(
    tmp_path, monkeypatch
):
    policy = ModelPolicy(
        "http://127.0.0.1:8001/v1/chat/completions", "model", "env:MOCK_MODEL_TOKEN"
    )
    broker = ModelBroker(tmp_path / "broker", {SCOPE_KEY: policy}, lambda _: 30)

    def blocked_socket(*_args, **_kwargs):
        raise PermissionError("fixture: Unix sockets unavailable")

    monkeypatch.setattr(model_broker.socket, "socket", blocked_socket)
    try:
        with pytest.raises(BrokerDenied, match="model_transport_unavailable"):
            broker.check_ready()
        assert not list(broker.root.glob("probe-*"))
    finally:
        broker.close()


def test_bounded_agent_edits_and_verifies_through_real_model_protocol(
    tmp_path, monkeypatch
):
    repository = tmp_path / "repo"
    repository.mkdir()
    (repository / "AGENTS.md").write_text("Change only answer.txt.\n")
    (repository / "answer.txt").write_text("old\n")
    scripted = [
        message("read_file", path="answer.txt"),
        message("write_file", path="answer.txt", content="new\n"),
        message(
            "run_command",
            argv=[sys.executable, "-c", "assert open('answer.txt').read() == 'new\\n'"],
        ),
        message("finish", summary="Changed and tested answer.txt"),
    ]

    def answer(handler, requests):
        response(handler, scripted[len(requests) - 1])

    with provider(answer) as (endpoint, requests):
        with broker_client(tmp_path, monkeypatch, endpoint) as (_, client, _):
            exit_code = run_agent(
                client,
                LocalTools(repository),
                "Change old to new and verify.",
                verify_argv=[
                    sys.executable,
                    "-c",
                    "assert open('answer.txt').read() == 'new\\n'",
                ],
            )
            assert exit_code == 0
            assert (repository / "answer.txt").read_text() == "new\n"
            assert len(requests) == 4
            assert TEST_TOKEN not in json.dumps([r["body"] for r in requests])
            assert any(m["role"] == "tool" for m in requests[-1]["body"]["messages"])


def test_local_tools_bound_output_time_and_paths(tmp_path):
    tools = LocalTools(tmp_path, command_seconds=0.2, output_bytes=128)
    with pytest.raises(ValueError):
        tools.read_file("../outside")
    overflow = json.loads(tools.run_command([sys.executable, "-c", "print('x'*10000)"]))
    assert overflow["state"] == "output_limit"
    assert len(overflow["output"]) == 128
    started = time.monotonic()
    timed = json.loads(
        tools.run_command([sys.executable, "-c", "import time;time.sleep(10)"])
    )
    assert timed["state"] == "timed_out"
    assert time.monotonic() - started < 2


@pytest.mark.parametrize(
    "endpoint",
    [
        "http://public.example/v1/chat/completions",
        "https://secret@provider.example/v1/chat/completions",
        "https://provider.example/v1/chat/completions?api_key=secret",
    ],
)
def test_unsafe_model_endpoints_rejected(endpoint):
    with pytest.raises(ValueError):
        ModelPolicy(endpoint, "model", "env:MODEL_TOKEN")


def test_public_guest_composes_existing_loop_and_ordinary_verification(tmp_path):
    from src.agent.public_tools import PublicClient, PublicTools
    from tests.unit.test_public_tools import actor, history, server, success

    (tmp_path / "AGENTS.md").write_text("Use the existing verification command.\n")
    script = [
        message("public_read", after=0, stream_id=None, watch_seconds=0),
        message("finish", summary="Public observation and ordinary work complete."),
    ]
    seen = []

    def complete(messages):
        seen.append(json.loads(json.dumps(messages)))
        assert len(seen) <= len(script), "public observation added an inference"
        return script[len(seen) - 1]

    with server(lambda request, _: success(request, history(actor()))) as fixture:
        tools = PublicTools(LocalTools(tmp_path), PublicClient(fixture.path, role="child"))
        code = run_agent(
            SimpleNamespace(complete=complete), tools, "Read the approved public history.",
            max_turns=2,
            verify_argv=[sys.executable, "-c", "open('verified.txt','w').write('checked')"],
        )
        assert code == 0
        assert (tmp_path / "verified.txt").read_text() == "checked"
        assert len(seen) == 2
        assert [r["operation"] for r in fixture.requests] == ["public_read"]
        observed = [m for m in seen[1] if m["role"] == "tool"]
        assert len(observed) == 1
        assert json.loads(observed[0]["content"])["execution_authorized"] is False


@pytest.mark.parametrize("code", ["provider_uncertain", "publication_uncertain"])
def test_public_child_main_stops_on_effect_uncertainty_without_new_model_call(
    tmp_path, monkeypatch, capsys, code
):
    import io
    from src.agent import managed_runner as child_runner
    from src.agent import public_tools as public
    from tests.unit.test_public_tools import SLOT, refusal, server

    monkeypatch.chdir(tmp_path)
    (tmp_path / "AGENTS.md").write_text("Only approved operations.\n")
    calls, constructors = [], []
    actual_client = public.PublicClient

    def create_client(path, **kwargs):
        constructors.append((path, kwargs))
        return actual_client(path, **kwargs)

    def complete(messages):
        calls.append(json.loads(json.dumps(messages)))
        assert len(calls) == 1, "an uncertain public effect reached another model call"
        return message("public_pull", slot_id=SLOT)

    monkeypatch.setattr(public, "PublicClient", create_client)
    monkeypatch.setattr(child_runner, "BrokerClient", lambda _path: SimpleNamespace(complete=complete))
    monkeypatch.setattr(child_runner.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"Approved public pull")))
    with server(lambda request, _: refusal(request, code)) as fixture:
        monkeypatch.setattr(child_runner.sys, "argv", [
            "managed_runner.py", "--socket", "/fixture-model.sock",
            "--public-socket", fixture.path, "--max-turns", "3",
        ])
        with pytest.raises(SystemExit) as stopped:
            child_runner.main()
        assert stopped.value.code == 4
        assert constructors == [(fixture.path, {"role": "child"})]
        assert len(calls) == len(fixture.requests) == 1
        assert fixture.requests[0]["operation"] == "public_pull"
    events = [json.loads(line) for line in capsys.readouterr().out.splitlines()]
    assert [event["event"] for event in events] == ["agent_failed"]


def test_child_main_omission_never_constructs_public_tools(tmp_path, monkeypatch):
    import io
    from src.agent import managed_runner as child_runner
    from src.agent import public_tools as public

    def forbidden(*_args, **_kwargs):
        pytest.fail("ordinary child unexpectedly constructed public transport")

    monkeypatch.chdir(tmp_path)
    (tmp_path / "AGENTS.md").write_text("Ordinary child profile.\n")
    monkeypatch.setattr(public, "PublicClient", forbidden)
    monkeypatch.setattr(public, "PublicTools", forbidden)
    calls = []

    def complete(messages):
        calls.append(json.loads(json.dumps(messages)))
        return message("finish", summary="Ordinary completion.")

    monkeypatch.setattr(child_runner, "BrokerClient", lambda _path: SimpleNamespace(complete=complete))
    monkeypatch.setattr(child_runner.sys, "stdin", SimpleNamespace(buffer=io.BytesIO(b"Ordinary task")))
    monkeypatch.setattr(child_runner.sys, "argv", [
        "managed_runner.py", "--socket", "/fixture-model.sock", "--max-turns", "1",
    ])
    with pytest.raises(SystemExit) as stopped:
        child_runner.main()
    assert stopped.value.code == 0
    assert len(calls) == 1


def test_public_composition_preserves_sole_terminal_outcome_rule(tmp_path):
    from src.agent.public_tools import PublicClient, PublicTools
    from tests.unit.test_public_tools import SLOT, server

    (tmp_path / "AGENTS.md").write_text("Terminal outcome must remain a sole tool call.\n")
    mixed = message("public_pull", slot_id=SLOT)
    terminal = message("report_outcome", outcome="declined", summary="Explicit private decline.")
    mixed["tool_calls"].append({**terminal["tool_calls"][0], "id": "second-call"})
    script = [mixed, terminal]
    histories, reports = [], []

    def complete(messages):
        histories.append(json.loads(json.dumps(messages)))
        assert len(histories) <= 2
        return script[len(histories) - 1]

    with server(lambda *_: pytest.fail("mixed terminal response dispatched a public effect")) as fixture:
        code = run_agent(
            SimpleNamespace(complete=complete),
            PublicTools(LocalTools(tmp_path), PublicClient(fixture.path, role="child")),
            "Retain the existing private outcome semantics.", max_turns=2,
            outcome_client=SimpleNamespace(report=lambda *values: reports.append(values)),
            verify_argv=[sys.executable, "-c", "open('unexpected-verification','w').write('bad')"],
        )
        assert code == 0
        assert fixture.requests == []
        assert reports == [("declined", "Explicit private decline.")]
        assert len(histories) == 2
        assert len([
            item for item in histories[1] if item["role"] == "tool"
            and "terminal child outcome must be the only call" in item["content"]
        ]) == 2
        assert not (tmp_path / "unexpected-verification").exists()
