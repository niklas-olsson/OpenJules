"""Real HTTP and SDK/stdio fixtures for the noncoding discussion participant.

The named conversation fixture is not the restricted Polyphony implementation.
These tests prove component behavior, not live public delivery or model quality.
"""

from __future__ import annotations

import asyncio
from contextlib import closing, contextmanager
from copy import deepcopy
from http.server import BaseHTTPRequestHandler, HTTPServer
import json
import os
import signal
from pathlib import Path
import sqlite3
import subprocess
import sys
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from src.polyphony import conversation_client as transport
from src.worker import discussion_types as types
from src.worker import public_discussion as participant
from src.worker.discussion_journal import DiscussionJournal
from src.worker.discussion_types import (
    CHILD_ENVIRONMENT, DiscussionError, Policy, canonical, validate_receipt,
)
from tests.unit.test_conversation_client import (
    application_requests, install_fixture, server_requests, signed_item,
)
from tests.unit.test_discussion_journal import (
    fixture_context, fixture_policy, fixture_status, fixture_turn, prepared,
    private_json,
)


TOKEN = "private-discussion-provider-canary"


def provider_reply(output=None):
    return canonical({
        "choices": [{
            "index": 0, "finish_reason": "stop",
            "message": {
                "role": "assistant",
                "content": canonical(output or {
                    "kind": "message", "content": "One public contribution.",
                }).decode("utf-8"),
            },
        }],
    })


def retained_state(policy):
    database = policy.state / "discussion.sqlite3"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        metadata = json.loads(connection.execute(
            "SELECT data FROM metadata WHERE slot=1"
        ).fetchone()[0])
        turns = {
            key: json.loads(data)
            for key, data in connection.execute("SELECT request_key,data FROM turns")
        }
    return metadata, turns


def public_posts(policy):
    database = Path(policy.a_config["state_directory"]) / "fixture-posts.sqlite3"
    with closing(sqlite3.connect(database.as_uri() + "?mode=ro", uri=True)) as connection:
        return [
            {"key": key, "intent": json.loads(intent), "record": json.loads(record)}
            for key, intent, record in connection.execute(
                "SELECT key,intent,record FROM posts ORDER BY key"
            )
        ]


class ProviderFixture:
    def __init__(self):
        self.guard = threading.Lock()
        self.requests = []
        self.errors = []
        self.entered = threading.Event()
        self.release = threading.Event()
        self.release.set()
        self.body = provider_reply()
        self.truncated_http = False
        self.on_request = None
        fixture = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def do_POST(self):
                self.connection.settimeout(2)
                try:
                    length = int(self.headers["Content-Length"])
                    if not 0 < length <= 524288:
                        raise ValueError("fixture request size")
                    raw = self.rfile.read(length)
                    if len(raw) != length:
                        raise ValueError("fixture incomplete request")
                    payload = json.loads(raw)
                    observation = (
                        fixture.on_request(payload) if fixture.on_request else None
                    )
                    with fixture.guard:
                        fixture.requests.append({
                            "path": self.path, "headers": dict(self.headers),
                            "body": payload, "observation": observation,
                        })
                    fixture.entered.set()
                    if not fixture.release.wait(timeout=5):
                        fixture.errors.append("fixture_hold_timeout")
                    body = fixture.body
                    self.send_response(200)
                    self.send_header(
                        "Content-Length",
                        str(len(body) + (16 if fixture.truncated_http else 0)),
                    )
                    self.end_headers()
                    self.wfile.write(body)
                    self.wfile.flush()
                    self.close_connection = True
                except (BrokenPipeError, ConnectionResetError):
                    # The actual client may time out or cancel the held request.
                    self.close_connection = True
                except Exception as error:
                    fixture.errors.append(type(error).__name__)
                    self.close_connection = True

        self.server = HTTPServer(("127.0.0.1", 0), Handler)
        self.owner = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.owner.start()
        self.endpoint = (
            f"http://127.0.0.1:{self.server.server_port}/v1/chat/completions"
        )

    def observations(self):
        with self.guard:
            return deepcopy(self.requests)

    def close(self, primary=None):
        failures = []
        self.release.set()
        for operation in (self.server.shutdown, self.server.server_close):
            try:
                operation()
            except Exception:
                failures.append("provider fixture shutdown failed")
        self.owner.join(timeout=3)
        if self.owner.is_alive():
            failures.append("provider fixture thread remains")
        failures.extend(self.errors)
        if failures:
            if primary is not None:
                primary.add_note("provider fixture cleanup: " + ", ".join(failures))
            else:
                raise AssertionError(", ".join(failures))


@contextmanager
def provider_fixture():
    provider = ProviderFixture()
    primary = None
    try:
        yield provider
    except BaseException as error:
        primary = error
        raise
    finally:
        provider.close(primary)


def configured(
    tmp_path, monkeypatch, provider, *, mode="normal", timeout=2, records=None,
):
    policy, _, status = fixture_policy(tmp_path, endpoint=provider.endpoint)
    document = deepcopy(policy.document)
    document["provider"]["request_timeout_seconds"] = timeout
    private_json(policy.path, document)
    policy = Policy.load(policy.path)
    install_fixture(policy, mode=mode, records=records)
    monkeypatch.setenv("DISCUSSION_FIXTURE_TOKEN", TOKEN)
    assert asyncio.run(participant.initialize(policy))["state"] == "initialized"
    assert provider.observations() == []
    return policy, status


def request_file(tmp_path, turn):
    return private_json(tmp_path / (turn.key + ".json"), turn.document)


def observe_reservation(provider, policy, key):
    def inspect(payload):
        metadata, turns = retained_state(policy)
        value = turns[key]
        return {
            "state": value["state"], "reserved_tokens": value["reserved_tokens"],
            "provider_request": value["provider_request"],
            "calls": metadata["calls"], "tokens": metadata["tokens"],
        }

    provider.on_request = inspect


def say_calls(policy):
    return [
        item for item in application_requests(policy)
        if item["name"] == "conversation_say"
    ]


@pytest.mark.parametrize("kind", ["message", "decline", "leave"])
def test_real_http_reservation_precedes_signed_publication_and_same_key_replay(
    tmp_path, monkeypatch, kind,
):
    with provider_fixture() as provider:
        provider.body = provider_reply({"kind": kind, "content": "A public choice."})
        policy, status = configured(tmp_path, monkeypatch, provider)
        monkeypatch.setenv("UNRELATED_SECRET", "private-host-canary")
        monkeypatch.setenv("HTTPS_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
        monkeypatch.setenv("NO_PROXY", "")
        turn = fixture_turn()
        path = request_file(tmp_path, turn)
        observe_reservation(provider, policy, turn.key)

        result = asyncio.run(participant.turn(policy, path))
        assert result["state"] == "complete" and result["reason"] is None
        assert result["execution_authorized"] is False
        calls = provider.observations()
        assert len(calls) == 1
        call = calls[0]
        assert call["path"] == "/v1/chat/completions"
        assert call["headers"]["Authorization"] == "Bearer " + TOKEN
        assert call["headers"]["Accept-Encoding"] == "identity"
        assert set(call["body"]) == {"model", "messages", "stream", "max_tokens"}
        assert call["body"]["stream"] is False
        assert call["body"]["max_tokens"] == 1024
        assert [message["role"] for message in call["body"]["messages"]] == [
            "system", "user",
        ]
        assert TOKEN not in canonical(call["body"]).decode()
        assert call["observation"] == {
            "state": "reserved", "reserved_tokens": 1024,
            "provider_request": call["body"], "calls": 1, "tokens": 1024,
        }

        posts = public_posts(policy)
        assert len(posts) == 1 and posts[0]["key"] == turn.key
        assert posts[0]["intent"]["kind"] == kind
        assert posts[0]["intent"]["target"] is None
        assert posts[0]["intent"]["references"] == []
        assert result["receipt"]["record"] == posts[0]["record"]
        validate_receipt(result["receipt"], status, posts[0]["intent"])
        state = Path(policy.a_config["state_directory"])
        assert json.loads((state / "environment.json").read_bytes()) == CHILD_ENVIRONMENT
        assert TOKEN not in canonical(server_requests(policy)).decode()
        assert "private-host-canary" not in canonical(server_requests(policy)).decode()
        assert len(say_calls(policy)) == 1

        before_rpc = server_requests(policy)
        monkeypatch.delenv("DISCUSSION_FIXTURE_TOKEN")
        assert asyncio.run(participant.turn(policy, path)) == result
        assert server_requests(policy) == before_rpc
        assert len(provider.observations()) == 1
        assert public_posts(policy) == posts
        with DiscussionJournal(policy, read_only=True) as journal:
            assert journal.status()["calls_reserved"] == 1
            assert journal.status()["tokens_reserved"] == 1024


def test_init_and_observation_are_passive_without_inference_or_publication(
    tmp_path, monkeypatch,
):
    with provider_fixture() as provider:
        policy, status = configured(tmp_path, monkeypatch, provider)
        observed = asyncio.run(participant.observe(policy))
        assert observed["status"] == status
        assert observed["history"]["messages"] == []
        assert provider.observations() == []
        assert public_posts(policy) == []
        assert {
            item["name"] for item in application_requests(policy)
        } == {"conversation_status", "conversation_history"}
        with DiscussionJournal(policy, read_only=True) as journal:
            retained = journal.status()
            assert retained["calls_reserved"] == retained["tokens_reserved"] == 0
            assert retained["turns"] == {}


@pytest.mark.parametrize("case,state", [
    ("malformed_json", "rejected"),
    ("tool_call", "rejected"),
    ("truncated_completion", "rejected"),
    ("escaped_unicode", "rejected"),
    ("secret_output", "rejected"),
    ("truncated_http", "provider_uncertain"),
])
def test_invalid_or_incomplete_provider_output_is_charged_without_publication(
    tmp_path, monkeypatch, case, state,
):
    with provider_fixture() as provider:
        if case == "malformed_json":
            provider.body = b'{"choices":'
        elif case == "tool_call":
            response = json.loads(provider.body)
            response["choices"][0]["message"]["tool_calls"] = [{
                "id": "unexpected-tool", "type": "function",
                "function": {"name": "execute_command", "arguments": "{}"},
            }]
            provider.body = canonical(response)
        elif case == "truncated_completion":
            response = json.loads(provider.body)
            response["choices"][0]["finish_reason"] = "length"
            provider.body = canonical(response)
        elif case == "escaped_unicode":
            output = {"kind": "message", "content": "\u0800" * 2700}
            assert len(output["content"].encode("utf-8")) == 8100
            provider.body = provider_reply(output)
            # Provider JSON/output validation succeeds; the later signed-record
            # size check must still refuse its much larger ASCII representation.
            assert participant._provider_output(provider.body) == output
        elif case == "secret_output":
            provider.body = provider_reply({"kind": "message", "content": TOKEN})
        else:
            provider.truncated_http = True

        policy, _ = configured(tmp_path, monkeypatch, provider)
        turn = fixture_turn()
        path = request_file(tmp_path, turn)
        observe_reservation(provider, policy, turn.key)
        result = asyncio.run(participant.turn(policy, path))
        assert result["state"] == state
        assert result["reason"] == (
            "provider_uncertain" if state == "provider_uncertain"
            else "provider_rejected"
        )
        assert result["receipt"] is None
        assert result["execution_authorized"] is False
        calls = provider.observations()
        assert len(calls) == 1
        assert calls[0]["observation"]["state"] == "reserved"
        assert calls[0]["observation"]["calls"] == 1
        assert calls[0]["observation"]["tokens"] == 1024
        assert calls[0]["observation"]["provider_request"] == calls[0]["body"]
        assert public_posts(policy) == [] and say_calls(policy) == []
        metadata, turns = retained_state(policy)
        assert metadata["calls"] == 1 and metadata["tokens"] == 1024
        assert turns[turn.key]["response"] is None
        assert turns[turn.key]["intent"] is None
        before_rpc = server_requests(policy)
        monkeypatch.delenv("DISCUSSION_FIXTURE_TOKEN")
        assert asyncio.run(participant.turn(policy, path)) == result
        assert server_requests(policy) == before_rpc
        assert len(provider.observations()) == 1


@pytest.mark.parametrize("mode", ["timeout", "cancel", "profile_change"])
def test_provider_interruption_stays_charged_and_blocks_new_keys_after_reopen(
    tmp_path, monkeypatch, mode,
):
    with provider_fixture() as provider:
        fixture_mode = "notify_during_provider" if mode == "profile_change" else "normal"
        policy, _ = configured(
            tmp_path, monkeypatch, provider, mode=fixture_mode,
            timeout=1 if mode == "timeout" else 10,
        )
        turn = fixture_turn()
        path = request_file(tmp_path, turn)
        provider.release.clear()
        observed_notifications = []
        original_incoming = transport._Wire.incoming

        def incoming(wire, value):
            if value.get("method") == "notifications/tools/list_changed":
                observed_notifications.append(deepcopy(value))
            return original_incoming(wire, value)

        if mode == "profile_change":
            monkeypatch.setattr(transport._Wire, "incoming", incoming)
            state = Path(policy.a_config["state_directory"])

            def entered(payload):
                metadata, turns = retained_state(policy)
                private_json(state / "provider-entered.flag", {"entered": True})
                return {
                    "state": turns[turn.key]["state"], "calls": metadata["calls"],
                    "tokens": metadata["tokens"],
                }

            provider.on_request = entered
        else:
            observe_reservation(provider, policy, turn.key)

        if mode == "cancel":
            async def cancel_after_entry():
                task = asyncio.create_task(participant.turn(policy, path))
                primary = None
                try:
                    assert await asyncio.to_thread(provider.entered.wait, 3)
                    task.cancel()
                    with pytest.raises(asyncio.CancelledError):
                        await asyncio.wait_for(task, timeout=8)
                except BaseException as error:
                    primary = error
                    raise
                finally:
                    provider.release.set()
                    if not task.done():
                        task.cancel()
                        try:
                            await asyncio.wait_for(task, timeout=8)
                        except asyncio.CancelledError:
                            pass
                        except BaseException:
                            if primary is None:
                                raise
                            primary.add_note("discussion task cleanup also failed")

            asyncio.run(cancel_after_entry())
        else:
            result = asyncio.run(participant.turn(policy, path))
            assert result["state"] == "provider_uncertain"
            assert result["reason"] == "provider_uncertain"

        assert provider.entered.is_set()
        calls = provider.observations()
        assert len(calls) == 1
        assert calls[0]["observation"]["state"] == "reserved"
        assert calls[0]["observation"]["calls"] == 1
        if mode == "profile_change":
            assert len(observed_notifications) == 1
            assert not provider.release.is_set()
        # A late server reply cannot clear the durable uncertainty fence.
        provider.release.set()
        with DiscussionJournal(policy) as reopened:
            assert reopened.get(turn.key)["state"] == "provider_uncertain"
            retained = reopened.status()
            assert retained["provider_uncertain"] is True
            assert retained["calls_reserved"] == 1
            assert retained["tokens_reserved"] == 1024
        before_rpc = server_requests(policy)
        repeat = asyncio.run(participant.turn(policy, path))
        assert repeat["state"] == "provider_uncertain"
        extra = request_file(tmp_path, fixture_turn("after-uncertainty"))
        with pytest.raises(DiscussionError, match="^provider_uncertain$"):
            asyncio.run(participant.turn(policy, extra))
        assert server_requests(policy) == before_rpc
        assert len(provider.observations()) == 1
        metadata, turns = retained_state(policy)
        assert set(turns) == {turn.key}
        assert metadata["calls"] == 1 and metadata["tokens"] == 1024
        assert metadata["provider_uncertain"] is True
        assert public_posts(policy) == [] and say_calls(policy) == []


def test_lost_say_ack_recovers_original_record_under_later_provider_hold(
    tmp_path, monkeypatch,
):
    with provider_fixture() as provider:
        policy, status = configured(
            tmp_path, monkeypatch, provider, mode="lost_ack_once", timeout=1,
        )
        first = fixture_turn("first-post")
        first_path = request_file(tmp_path, first)
        observe_reservation(provider, policy, first.key)
        lost = asyncio.run(participant.turn(policy, first_path))
        assert lost["state"] == "publication_uncertain"
        assert lost["receipt"] is None
        posts = public_posts(policy)
        assert len(posts) == 1 and posts[0]["key"] == first.key
        original = retained_state(policy)[1][first.key]
        assert original["intent"] == posts[0]["intent"]

        second = fixture_turn("later-provider")
        second_path = request_file(tmp_path, second)
        observe_reservation(provider, policy, second.key)
        provider.entered.clear()
        provider.release.clear()
        uncertain = asyncio.run(participant.turn(policy, second_path))
        assert provider.entered.is_set()
        assert uncertain["state"] == "provider_uncertain"
        assert len(provider.observations()) == 2
        provider.release.set()
        monkeypatch.delenv("DISCUSSION_FIXTURE_TOKEN")
        recovered = asyncio.run(participant.turn(policy, first_path))
        assert recovered["state"] == "complete" and recovered["reason"] is None
        assert recovered["receipt"]["record"] == posts[0]["record"]
        validate_receipt(recovered["receipt"], status, original["intent"])
        assert public_posts(policy) == posts
        assert len(provider.observations()) == 2
        calls = say_calls(policy)
        assert len(calls) == 2 and calls[0] == calls[1]
        with DiscussionJournal(policy, read_only=True) as read:
            assert read.status()["provider_uncertain"] is True
            assert read.status()["calls_reserved"] == 2
            assert read.status()["tokens_reserved"] == 2048
            assert read.get(first.key)["provider_request"] == original["provider_request"]
            assert read.get(first.key)["expires_at"] == original["expires_at"]
            assert read.get(first.key)["monotonic_cutoff"] == original["monotonic_cutoff"]
            assert read.receipt(first.key)["receipt"] == recovered["receipt"]
        before_rpc = server_requests(policy)
        assert asyncio.run(participant.turn(policy, first_path)) == recovered
        assert server_requests(policy) == before_rpc
        assert len(provider.observations()) == 2


def test_forged_publication_ack_is_not_retained_and_valid_replay_needs_no_provider(
    tmp_path, monkeypatch,
):
    with provider_fixture() as provider:
        policy, status = configured(tmp_path, monkeypatch, provider, mode="bad_receipt")
        turn = fixture_turn()
        path = request_file(tmp_path, turn)
        observe_reservation(provider, policy, turn.key)
        invalid = asyncio.run(participant.turn(policy, path))
        assert invalid["state"] == "publication_uncertain"
        assert invalid["receipt"] is None
        posts = public_posts(policy)
        assert len(posts) == 1
        with DiscussionJournal(policy, read_only=True) as read:
            assert read.get(turn.key)["receipt"] is None
        install_fixture(policy, mode="normal")
        monkeypatch.delenv("DISCUSSION_FIXTURE_TOKEN")
        result = asyncio.run(participant.turn(policy, path))
        assert result["state"] == "complete"
        assert result["receipt"]["record"] == posts[0]["record"]
        validate_receipt(result["receipt"], status, posts[0]["intent"])
        assert public_posts(policy) == posts
        assert len(provider.observations()) == 1
        assert len(say_calls(policy)) == 2


def test_expired_original_turn_opens_no_new_rpc_or_provider_and_keeps_its_binding(
    tmp_path, monkeypatch,
):
    with provider_fixture() as provider:
        policy, _ = configured(tmp_path, monkeypatch, provider)
        turn = fixture_turn(expires_at=time.time() + 20)
        path = request_file(tmp_path, turn)
        with DiscussionJournal(policy) as journal:
            original = journal.prepare(turn)
        before_rpc = server_requests(policy)
        before = retained_state(policy)
        monkeypatch.setattr(types.time, "time", lambda: original["expires_at"] + 1)
        monkeypatch.setattr(
            types.time, "monotonic", lambda: original["monotonic_cutoff"] + 1,
        )
        result = asyncio.run(participant.turn(policy, path))
        assert result["state"] == "prepared" and result["reason"] == "expired"
        assert result["reserved_tokens"] == 0
        assert retained_state(policy) == before
        assert server_requests(policy) == before_rpc
        assert provider.observations() == []
        assert public_posts(policy) == []
        with DiscussionJournal(policy, read_only=True) as read:
            assert read.deadline.remaining() > 0
            assert read.get(turn.key) == original


def run_local_cli(policy, *arguments):
    command = [
        sys.executable, "-m", "src.worker.public_discussion",
        "--config", str(policy.path), *arguments,
    ]
    process = subprocess.Popen(
        command, cwd=Path(__file__).resolve().parents[2],
        stdout=subprocess.PIPE, stderr=subprocess.PIPE, start_new_session=True,
    )
    primary = None
    try:
        stdout, stderr = process.communicate(timeout=10)
        assert process.returncode == 0 and stderr == b""
        return json.loads(stdout)
    except BaseException as error:
        primary = error
        raise
    finally:
        # Do not poll/reap an exited leader before stopping its still-owned
        # process group if an inherited pipe prevented communicate completing.
        if process.returncode is None:
            try:
                os.killpg(process.pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
            try:
                process.communicate(timeout=3)
            except BaseException:
                if primary is None:
                    raise
                primary.add_note("local CLI cleanup also failed")
        if process.stdout is not None:
            process.stdout.close()
        if process.stderr is not None:
            process.stderr.close()


def test_fresh_cli_status_receipt_and_completed_turn_are_local_without_token(
    tmp_path, monkeypatch,
):
    with provider_fixture() as provider:
        policy, _ = configured(tmp_path, monkeypatch, provider)
        turn = fixture_turn()
        path = request_file(tmp_path, turn)
        result = asyncio.run(participant.turn(policy, path))
        assert result["state"] == "complete"
        before_rpc = server_requests(policy)
        before_posts = public_posts(policy)
        monkeypatch.delenv("DISCUSSION_FIXTURE_TOKEN")
        receipt = run_local_cli(policy, "receipt", turn.key)
        assert receipt["state"] == "complete"
        assert receipt["receipt"] == result["receipt"]
        status = run_local_cli(policy, "status")
        assert status["calls_reserved"] == 1 and status["tokens_reserved"] == 1024
        assert run_local_cli(policy, "turn", "--request", str(path)) == result
        assert server_requests(policy) == before_rpc
        assert public_posts(policy) == before_posts
        assert len(provider.observations()) == 1


def test_host_selected_peer_context_and_reply_are_frozen_through_actual_io(
    tmp_path, monkeypatch,
):
    peer_key = Ed25519PrivateKey.from_private_bytes(b"\x35" * 32)
    unselected = signed_item(2, "UNSELECTED-PUBLIC-CANARY")
    selected = signed_item(
        8, "A signed peer asks for a public reply.", signing_key=peer_key,
    )
    local_status = fixture_status()
    assert selected["record"]["body"]["author"] != local_status["author"]
    assert selected["record"]["body"]["public_key"] != local_status["public_key"]
    with provider_fixture() as provider:
        provider.body = provider_reply({
            "kind": "message", "content": "A bounded reply to the selected peer.",
        })
        policy, status = configured(
            tmp_path, monkeypatch, provider, records=[unselected, selected],
        )
        selected_id = selected["record"]["message_id"]
        turn = fixture_turn(
            "selected-reply", instruction="Reply only to the host-selected peer.",
            selected_message_ids=[selected_id], reply_to=selected_id,
        )
        path = request_file(tmp_path, turn)
        observe_reservation(provider, policy, turn.key)
        result = asyncio.run(participant.turn(policy, path))
        assert result["state"] == "complete" and result["reason"] is None
        calls = provider.observations()
        assert len(calls) == 1
        body = calls[0]["body"]
        assert calls[0]["observation"]["provider_request"] == body
        assert calls[0]["observation"]["state"] == "reserved"
        assert set(body) == {"model", "messages", "stream", "max_tokens"}
        user_input = json.loads(body["messages"][1]["content"])
        assert user_input["instruction"] == turn.document["instruction"]
        context = user_input["public_context"]
        assert context["status"] == status
        assert context["messages"] == [selected]
        assert context["context_after"] == 0 and context["next_cursor"] == 9
        assert "UNSELECTED-PUBLIC-CANARY" not in canonical(body).decode()
        assert selected_id in canonical(body).decode()
        metadata, turns = retained_state(policy)
        assert metadata["calls"] == 1 and metadata["tokens"] == 1024
        assert turns[turn.key]["context"] == context
        assert turns[turn.key]["provider_request"] == body
        posts = public_posts(policy)
        assert len(posts) == 1
        assert posts[0]["intent"]["reply_to"] == selected_id
        assert posts[0]["intent"]["target"] is None
        assert posts[0]["intent"]["references"] == []
        assert posts[0]["record"]["body"]["author"] == status["author"]
        assert posts[0]["record"]["body"]["public_key"] == status["public_key"]
        assert result["receipt"]["record"] == posts[0]["record"]
        validate_receipt(result["receipt"], status, posts[0]["intent"])
        assert say_calls(policy)[0]["arguments"]["reply_to"] == selected_id
        assert len(say_calls(policy)) == 1
        assert result["execution_authorized"] is False
