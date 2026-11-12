"""Real Unix framing and independent public projection fixtures.

The guest checks hashes and correlation. These tests do not attest socket UID,
canonical grants, provider reservation or host Ed25519 verification.
"""

import copy
import hashlib
import json
from pathlib import Path
import struct
import subprocess
import sys
import time
from types import SimpleNamespace

from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from src.agent import public_tools as public
from tests.unit.test_child_tools import server


CHILD = "child_" + "a" * 32
OTHER_CHILD = "child_" + "b" * 32
SLOT = "1" * 64
SECOND_SLOT = "2" * 64
TOPIC = "approved-public-topic"
SWARM = "c" * 64
EXPIRES = 2_000_000_000.0
FIXED_DECLINE = "I decline this offered public discussion turn."


def canonical(value):
    return json.dumps(
        value, sort_keys=True, separators=(",", ":"), allow_nan=False
    ).encode("utf-8")


def digest(value):
    return hashlib.sha256(canonical(value)).hexdigest()


def signing_key(seed):
    return Ed25519PrivateKey.from_private_bytes(bytes([seed]) * 32)


def actor(role="child", child_id=CHILD, *, seed=11, bound=True, closed=False, topic=TOPIC):
    if role == "root":
        child_id = None
    key = signing_key(seed).public_key().public_bytes(
        serialization.Encoding.Raw, serialization.PublicFormat.Raw
    ).hex()
    status = {
        "schema_version": 1, "profile": "polyphony-public-conversation",
        "topic": topic, "swarm_id": SWARM,
        "session_id": digest(["polyphony-public-conversation-v1", SWARM, topic]),
        "author": hashlib.sha256(bytes.fromhex(key)).hexdigest()[:16],
        "public_key": key, "stream_id": f"{seed:032x}", "visibility": "public",
        "execution_authorized": False,
    }
    return {
        "role": role, "child_id": child_id,
        "binding_digest": digest([role, child_id, seed]) if bound else None,
        "status": status if bound else None, "admission_closed": closed,
    }


def record(who, key, *, kind="message", content="An explicit public contribution.",
           reply_to=None, target=None, seed=11, references=()):
    status = who["status"]
    body = {
        "schema_version": 1, "swarm_id": status["swarm_id"],
        "session_id": status["session_id"], "topic": status["topic"],
        "kind": kind, "content": content, "reply_to": reply_to,
        "target": target, "references": copy.deepcopy(list(references)), "request_key": key,
        "visibility": "public", "author": status["author"],
        "public_key": status["public_key"], "timestamp": 1_700_000_000.0,
    }
    return {
        "message_id": digest(body), "body": body,
        "signature": signing_key(seed).sign(canonical(body)).hex(),
    }


def acknowledgement(item):
    body = item["body"]
    return {
        "schema_version": 1, "message_id": item["message_id"],
        "session_id": body["session_id"], "author": body["author"],
        "stored": True, "visibility": "public", "delivery": "submitted",
        "execution_authorized": False, "record": item,
    }


def slot(*, who=None, identifier=SLOT, activation="mpub1:activation",
         state="offered", selected=None, reply_to=None, model=True, seed=11):
    who = copy.deepcopy(who if who is not None else actor())
    selection = [] if selected is None else list(selected)
    value = {
        "slot_id": identifier, "actor": who,
        "activation_request_id": activation,
        "persona_key": "approved-persona", "instruction_key": "approved-instruction",
        "selected_message_ids": selection, "reply_to": reply_to,
        "expires_at": EXPIRES, "state": state, "reason": None,
        "context_digest": "3" * 64 if state != "offered" and model else None,
        "model_call_digest": "4" * 64 if state not in {"offered", "context_frozen"} and model else None,
        "publication_request_key": "oj-public:" + identifier, "receipt": None,
    }
    if state in {"published", "declined", "left"}:
        kind = {"published": "message", "declined": "decline", "left": "leave"}[state]
        value["receipt"] = acknowledgement(record(
            who, value["publication_request_key"], kind=kind,
            content=FIXED_DECLINE if state == "declined" and not model else "Public \u00e9cho.",
            reply_to=reply_to, seed=seed,
        ))
    return value


def slot_result(value):
    return {"slot": value, "execution_authorized": False}


def pending(who=None, slots=()):
    return {
        "actor": copy.deepcopy(who if who is not None else actor()),
        "slots": copy.deepcopy(list(slots)), "execution_authorized": False,
    }


def history(who, records=(), *, after=0, cursors=None, gap=None):
    positions = list(cursors) if cursors is not None else list(range(after + 1, after + len(records) + 1))
    status = who["status"]
    return {
        "actor": copy.deepcopy(who),
        "history": {
            "schema_version": 1, "session_id": status["session_id"],
            "topic": status["topic"], "stream_id": status["stream_id"],
            "messages": [
                {"cursor": cursor, "record": copy.deepcopy(item), "reply_state": "none"}
                for cursor, item in zip(positions, records)
            ],
            "next_cursor": positions[-1] if positions else (0 if gap else after),
            "has_more": False, "gap": gap, "peer_gaps": {"count": 0, "items": []},
        },
        "execution_authorized": False,
    }


def success(request, result):
    return {"schema_version": 1, "request_id": request["request_id"], "ok": True,
            "result": copy.deepcopy(result)}


def refusal(request, code):
    return {"schema_version": 1, "request_id": request["request_id"], "ok": False,
            "error": code}


def frame(raw):
    return struct.pack("!I", len(raw)) + raw


def selection():
    return {
        "persona_key": "approved-persona", "instruction_key": "approved-instruction",
        "selected_message_ids": [], "reply_to": None,
    }


def test_role_tool_definitions_are_exact_and_never_expose_request_or_identity_fields():
    expected = {
        "root": {"public_activate", "public_turn", "public_status", "public_read", "public_invite"},
        "child": {"public_pull", "public_decline", "public_pending", "public_status", "public_read"},
    }
    for role, definitions in [
        ("root", public.ROOT_PUBLIC_TOOL_DEFINITIONS),
        ("child", public.CHILD_PUBLIC_TOOL_DEFINITIONS),
    ]:
        assert {d["function"]["name"] for d in definitions} == expected[role]
        for definition in definitions:
            fields = definition["function"]["parameters"]
            assert set(fields["required"]) == set(fields["properties"])
            assert fields["additionalProperties"] is False
            assert not {"request_id", "role", "body", "content", "token", "endpoint"} & set(fields["properties"])
    assert "public_pull" not in expected["root"]
    assert "public_turn" not in expected["child"]


@pytest.mark.parametrize("role,operation", [
    ("root", "public_activate"), ("root", "public_turn"), ("root", "public_status"),
    ("root", "public_read"), ("root", "public_invite"),
    ("child", "public_pull"), ("child", "public_decline"), ("child", "public_pending"),
    ("child", "public_status"), ("child", "public_read"),
])
def test_all_enabled_operations_use_actual_framed_transport_and_result_shape(role, operation):
    fields = {}
    if operation in {"public_activate", "public_turn"}:
        fields = selection()
        if operation == "public_activate":
            fields["child_id"] = CHILD
    elif operation in {"public_pull", "public_decline", "public_status"}:
        fields = {"slot_id": SLOT}
    elif operation == "public_read":
        fields = {"after": 0, "stream_id": None, "watch_seconds": 0}
    elif operation == "public_invite":
        fields = {"invitation_key": "approved-invite"}

    def reply(request, _number):
        if operation == "public_pending":
            result = pending()
        elif operation == "public_read":
            result = history(actor(role))
        elif operation == "public_invite":
            who = actor("root")
            key = "oj-public-invite:" + digest([
                who["status"]["author"], fields["invitation_key"], request["request_id"],
            ])
            result = {
                "actor": who, "invitation_key": fields["invitation_key"],
                "publication_request_key": key, "state": "published", "reason": None,
                "receipt": acknowledgement(record(who, key, kind="invite", target="f" * 16)),
                "execution_authorized": False,
            }
        else:
            who = actor("root") if operation == "public_turn" else actor()
            state = (
                "declined" if operation == "public_decline" else
                "published" if operation in {"public_pull", "public_turn"} else "offered"
            )
            value = slot(
                who=who, state=state, model=operation != "public_decline",
                activation=request["request_id"] if operation in {"public_activate", "public_turn"} else "mpub1:activation",
            )
            result = slot_result(value)
        return success(request, result)

    with server(reply) as fixture:
        result = public.PublicClient(fixture.path, role=role).request(
            operation, request_id="mpub1:explicit", **fields
        )
        assert result["execution_authorized"] is False
        assert "ok" not in result and "result" not in result
        assert len(fixture.requests) == 1
        assert fixture.requests[0] == {
            "schema_version": 1, "request_id": "mpub1:explicit", "operation": operation,
            **fields,
        }


@pytest.mark.parametrize("role,operation,fields", [
    ("root", "public_pull", {"slot_id": SLOT}),
    ("root", "public_pending", {}),
    ("child", "public_turn", selection()),
    ("child", "public_activate", {"child_id": CHILD, **selection()}),
    ("child", "stop_peer", {"pid": 1}),
    ("child", "public_status", {"slot_id": SLOT, "body": "unapproved"}),
    ("root", "public_turn", {**selection(), "selected_message_ids": [SLOT, SLOT]}),
    ("root", "public_turn", {**selection(), "reply_to": SLOT}),
    ("root", "public_turn", {**selection(), "persona_key": "\ud800"}),
    ("child", "public_read", {"after": True, "stream_id": None, "watch_seconds": 0}),
    ("child", "public_read", {"after": 1, "stream_id": None, "watch_seconds": 0}),
    ("child", "public_read", {"after": 1 << 2048, "stream_id": None, "watch_seconds": 0}),
    ("child", "public_read", {"after": 0, "stream_id": None, "watch_seconds": 10.0}),
    ("root", "public_invite", {"invitation_key": "approved-invite", "target": "f" * 16}),
])
def test_invalid_or_wrong_role_requests_have_zero_socket_effects(role, operation, fields):
    with server(lambda *_: pytest.fail("invalid request reached socket")) as fixture:
        client = public.PublicClient(fixture.path, role=role)
        with pytest.raises(public.PublicError) as error:
            client.request(operation, request_id="mpub1:invalid", **fields)
        assert error.value.code == "invalid_request"
        assert fixture.requests == []
        assert client._requests == {}


@pytest.mark.parametrize("keyword,value", [
    ("timeout_seconds", True), ("timeout_seconds", 0), ("timeout_seconds", 46),
    ("timeout_seconds", 1 << 2048), ("timeout_seconds", float("nan")),
    ("timeout_seconds", float("inf")), ("max_response_bytes", True),
    ("max_response_bytes", 262145), ("retry_delay_seconds", 1 << 2048),
    ("retry_delay_seconds", float("nan")), ("role", []),
])
def test_constructor_rejects_invalid_numeric_types_before_transport(keyword, value):
    options = {"role": "child", keyword: value}
    with pytest.raises(ValueError, match="invalid bounded public client configuration"):
        public.PublicClient("/unused.sock", **options)


def test_retry_freezes_original_key_payload_and_no_changed_key_adoption():
    fields = selection()
    fields["selected_message_ids"] = [SLOT]
    fields["reply_to"] = SLOT

    def reply(request, number):
        if number < 3:
            fields["selected_message_ids"].append(SECOND_SLOT)
            return refusal(request, "retry_later" if number == 1 else "canonical_pending")
        return success(request, slot_result(slot(
            activation=request["request_id"], selected=[SLOT], reply_to=SLOT,
        )))

    with server(reply) as fixture:
        client = public.PublicClient(fixture.path, role="root", retry_delay_seconds=0)
        answer = client.request("public_activate", request_id="mpub1:owned",
                                child_id=CHILD, **fields)
        assert len(fixture.requests) == 3
        assert len(set(fixture.raw_requests)) == 1
        assert fixture.requests[0]["selected_message_ids"] == [SLOT]
        answer["slot"]["persona_key"] = "caller-mutated"
        with pytest.raises(public.PublicError) as error:
            client.request("public_activate", request_id="mpub1:owned",
                           child_id=CHILD, **selection())
        assert error.value.code == "conflict"
        assert len(fixture.requests) == 3


def test_explicit_key_keeps_original_deadline_but_fresh_observation_is_possible():
    with server(lambda request, _: success(request, pending())) as fixture:
        client = public.PublicClient(fixture.path, role="child", timeout_seconds=0.04)
        client.request("public_pending", request_id="mpub1:original")
        original = client._requests["mpub1:original"]["deadline"]
        time.sleep(0.06)
        with pytest.raises(public.PublicError) as error:
            client.request("public_pending", request_id="mpub1:original")
        assert error.value.code == "transport_unavailable"
        assert client._requests["mpub1:original"]["deadline"] == original
        assert len(fixture.requests) == 1
        assert client.request("public_pending", request_id="mpub1:fresh")["slots"] == []
        assert len(fixture.requests) == 2


@pytest.mark.parametrize("code", [
    "provider_uncertain", "publication_uncertain", "transport_unavailable", "state_conflict",
])
def test_ambiguous_public_refusal_is_fatal_and_does_not_create_another_key(code):
    with server(lambda request, _: refusal(request, code)) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        ordinary = SimpleNamespace(call=lambda *_: pytest.fail("ordinary tool unexpectedly ran"))
        with pytest.raises(public.PublicError) as error:
            public.PublicTools(ordinary, client).call("public_pending", {})
        assert error.value.code == code
        assert error.value.request_id == fixture.requests[0]["request_id"]
        assert len(fixture.requests) == 1


@pytest.mark.parametrize("code", [
    "invalid_request", "not_authorized", "conflict", "request_limit",
    "slot_limit", "transcript_limit", "expired", "actor_left", "context_unavailable",
])
def test_conclusive_refusal_is_bounded_and_no_additional_rpc(code):
    with server(lambda request, _: refusal(request, code)) as fixture:
        tools = public.PublicTools(object(), public.PublicClient(fixture.path, role="child"))
        assert json.loads(tools.call("public_pending", {})) == {"ok": False, "error": code}
        assert len(fixture.requests) == 1


@pytest.mark.parametrize("case,expected", [
    ("eof", "transport_unavailable"), ("partial", "transport_unavailable"),
    ("oversized", "protocol_invalid"), ("zero", "protocol_invalid"),
    ("invalid_json", "protocol_invalid"), ("duplicate", "protocol_invalid"),
    ("schema_bool", "protocol_invalid"), ("ok_integer", "protocol_invalid"),
    ("wrong_key", "protocol_invalid"), ("extra_envelope", "protocol_invalid"),
    ("unknown_error", "protocol_invalid"), ("error_list", "protocol_invalid"),
    ("surrogate_topic", "protocol_invalid"), ("huge_expiry", "protocol_invalid"),
])
def test_untrusted_wire_errors_are_fixed_and_never_retried(case, expected):
    def reply(request, _number):
        if case == "eof":
            return None
        if case == "partial":
            return struct.pack("!I", 20) + b"{}"
        if case == "oversized":
            return struct.pack("!I", 262145)
        if case == "zero":
            return struct.pack("!I", 0)
        if case == "invalid_json":
            return frame(b"{")
        if case == "duplicate":
            return frame(b'{"schema_version":1,"schema_version":1}')
        response = success(request, slot_result(slot()))
        if case == "schema_bool":
            response["schema_version"] = True
        elif case == "ok_integer":
            response["ok"] = 1
        elif case == "wrong_key":
            response["request_id"] = "mpub1:other"
        elif case == "extra_envelope":
            response["private_field"] = "DO_NOT_ECHO_THIS"
        elif case in {"unknown_error", "error_list"}:
            response = refusal(request, "DO_NOT_ECHO_THIS" if case == "unknown_error" else [])
        elif case == "surrogate_topic":
            response["result"]["slot"]["actor"]["status"]["topic"] = "\ud800"
        elif case == "huge_expiry":
            response["result"]["slot"]["expires_at"] = 1 << 2048
        return response

    with server(reply) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        with pytest.raises(public.PublicError) as error:
            client.request("public_status", request_id="mpub1:original", slot_id=SLOT)
        assert error.value.code == expected
        assert error.value.request_id == "mpub1:original"
        assert "DO_NOT_ECHO_THIS" not in str(error.value)
        assert len(fixture.requests) == 1
        assert client._actors == {} and client._slots == {}


def test_known_retry_deadline_has_one_key_and_no_timeout_fallback():
    with server(lambda request, _: refusal(request, "canonical_pending")) as fixture:
        client = public.PublicClient(
            fixture.path, role="child", timeout_seconds=0.08, retry_delay_seconds=0.02
        )
        with pytest.raises(public.PublicError) as error:
            client.request("public_pending", request_id="mpub1:retry")
        assert error.value.code == "transport_unavailable"
        assert fixture.requests
        assert {r["request_id"] for r in fixture.requests} == {"mpub1:retry"}
        assert len(set(fixture.raw_requests)) == 1
        assert len(fixture.requests) <= 5


@pytest.mark.parametrize("role", ["root", "child"])
@pytest.mark.parametrize("code", [
    "canonical_pending", "retry_later", "publication_uncertain", "expired",
])
def test_only_conclusive_host_expiry_can_resume_agent_loop(
    role, code, monkeypatch, tmp_path,
):
    """Exercise the actual client, tool adapter and agent with framed fixtures."""
    from src.agent import managed_runner

    clock = [100.0]
    requests, raw_requests, histories = [], [], []

    class Connection:
        def __enter__(self):
            return self

        def __exit__(self, *_):
            pass

        def settimeout(self, seconds):
            assert 0 < seconds <= 0.15 + 1e-10

        def connect(self, path):
            assert path == "/fixture/public.sock"

        def sendall(self, value):
            assert struct.unpack("!I", value[:4])[0] == len(value[4:])
            request = json.loads(value[4:])
            requests.append(request)
            raw_requests.append(value)
            self.reply = frame(canonical(refusal(request, code)))

        def recv(self, size):
            value, self.reply = self.reply[:size], self.reply[size:]
            return value

    operation = "public_turn" if role == "root" else "public_pull"
    fields = selection() if role == "root" else {"slot_id": SLOT}

    def complete(messages):
        histories.append(copy.deepcopy(messages))
        if len(histories) == 1:
            name, arguments = operation, fields
        else:
            assert len(histories) == 2
            name, arguments = "finish", {"summary": "Conclusive host refusal received."}
        return {"role": "assistant", "content": None, "tool_calls": [{
            "id": f"call-{len(histories)}", "type": "function",
            "function": {"name": name, "arguments": json.dumps(arguments)},
        }]}

    monkeypatch.setattr(public, "time", SimpleNamespace(
        monotonic=lambda: clock[0],
        sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    ))
    monkeypatch.setattr(public, "socket", SimpleNamespace(
        AF_UNIX=1, SOCK_STREAM=1, socket=lambda *_: Connection(),
    ))
    client = public.PublicClient(
        "/fixture/public.sock", role=role, timeout_seconds=0.15,
        retry_delay_seconds=0.1,
    )
    adapter = public.PublicTools(managed_runner.LocalTools(tmp_path), client)

    def run():
        return managed_runner.run_agent(
            SimpleNamespace(complete=complete), adapter,
            "Approved public contribution fixture.", max_turns=2,
        )

    if code == "expired":
        assert run() == 0
        assert len(histories) == 2
        assert [json.loads(message["content"]) for message in histories[-1]
                if message["role"] == "tool"] == [{"ok": False, "error": "expired"}]
        assert len(requests) == 1
    else:
        expected = "publication_uncertain" if code == "publication_uncertain" else "transport_unavailable"
        with pytest.raises(public.PublicError) as error:
            run()
        assert error.value.code == expected
        assert error.value.request_id == requests[0]["request_id"]
        assert len(histories) == 1
        assert all(message["role"] != "tool" for message in histories[0])
        assert len(requests) == (1 if code == "publication_uncertain" else 2)

    assert len(client._requests) == 1
    assert len(set(raw_requests)) == 1
    key = requests[0]["request_id"]
    assert requests[0]["operation"] == operation
    assert client._requests[key]["deadline"] == pytest.approx(100.15)
    if code in {"canonical_pending", "retry_later"}:
        assert clock[0] == pytest.approx(100.15)
        # Re-entry keeps the original cutoff and cannot dispatch another RPC.
        with pytest.raises(public.PublicError) as error:
            client.request(operation, request_id=key, **fields)
        assert error.value.code == "transport_unavailable"
        assert error.value.request_id == key
        assert len(requests) == 2
        assert client._requests[key]["deadline"] == pytest.approx(100.15)


@pytest.mark.parametrize("case", [
    "top_message", "top_author", "top_session", "stored_integer", "execution",
    "body_change", "foreign_scope", "foreign_author", "signature_shape",
    "bool_timestamp", "lone_surrogate", "unicode_envelope_overflow",
])
def test_original_receipt_hash_scope_and_duplicate_fields_are_checked(case):
    value = slot(state="published")
    receipt = value["receipt"]
    body = receipt["record"]["body"]
    if case == "top_message":
        receipt["message_id"] = "0" * 64
    elif case == "top_author":
        receipt["author"] = "0" * 16
    elif case == "top_session":
        receipt["session_id"] = "0" * 64
    elif case == "stored_integer":
        receipt["stored"] = 1
    elif case == "execution":
        receipt["execution_authorized"] = True
    elif case == "body_change":
        body["content"] = "changed without original hash"
    elif case == "foreign_scope":
        who = actor(topic="foreign-topic")
        value["receipt"] = acknowledgement(record(who, value["publication_request_key"]))
    elif case == "foreign_author":
        who = actor(seed=12)
        value["receipt"] = acknowledgement(record(who, value["publication_request_key"], seed=12))
    elif case == "signature_shape":
        receipt["record"]["signature"] = "g" * 128
    elif case == "bool_timestamp":
        body["timestamp"] = True
        receipt["record"]["message_id"] = receipt["message_id"] = digest(body)
    elif case in {"lone_surrogate", "unicode_envelope_overflow"}:
        body["content"] = "\ud800" if case == "lone_surrogate" else "\U0001f642" * 2048
        receipt["record"]["message_id"] = receipt["message_id"] = digest(body)
    with server(lambda request, _: success(request, slot_result(value))) as fixture:
        with pytest.raises(public.PublicError) as error:
            public.PublicClient(fixture.path, role="child").request("public_status", slot_id=SLOT)
        assert error.value.code == "protocol_invalid"


def test_valid_original_unicode_receipt_is_returned_without_reserializing_body():
    value = slot(state="published")
    original = copy.deepcopy(value["receipt"])
    signing_key(11).public_key().verify(
        bytes.fromhex(original["record"]["signature"]),
        canonical(original["record"]["body"]),
    )  # Fixture signature control; not a claim about guest verification.
    with server(lambda request, _: success(request, slot_result(value))) as fixture:
        answer = public.PublicClient(fixture.path, role="child").request("public_status", slot_id=SLOT)
        assert answer["slot"]["receipt"] == original
        assert answer["slot"]["receipt"]["record"]["body"]["content"] == "Public \u00e9cho."


@pytest.mark.parametrize("case", [
    "child", "binding", "coherent_author", "stream", "erase_binding", "reopen_actor",
])
def test_actor_identity_and_public_leave_cannot_be_replaced_by_a_new_read_key(case):
    first = slot(who=actor(closed=case == "reopen_actor"))
    second = copy.deepcopy(first)
    who = second["actor"]
    if case == "child":
        who["child_id"] = OTHER_CHILD
    elif case == "binding":
        who["binding_digest"] = "f" * 64
    elif case == "coherent_author":
        second["actor"] = actor(seed=12)
    elif case == "stream":
        who["status"]["stream_id"] = "e" * 32
    elif case == "erase_binding":
        who["status"] = who["binding_digest"] = None
    else:
        who["admission_closed"] = False
    with server(lambda request, n: success(request, slot_result(first if n == 1 else second))) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        client.request("public_status", request_id="mpub1:first", slot_id=SLOT)
        with pytest.raises(public.PublicError) as error:
            client.request("public_status", request_id="mpub1:second", slot_id=SLOT)
        assert error.value.code == "protocol_invalid"


def test_atomic_late_binding_and_invalid_response_do_not_poison_client_state():
    unbound = slot(who=actor(bound=False))
    bound = slot()
    invalid = slot(who=actor(child_id=OTHER_CHILD, seed=12))
    invalid["slot_id"] = SECOND_SLOT
    with server(lambda request, n: success(request, slot_result(
        invalid if n == 1 else unbound if n == 2 else bound
    ))) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        with pytest.raises(public.PublicError):
            client.request("public_status", slot_id=SLOT)
        assert client._actors == {} and client._slots == {}
        assert client.request("public_status", slot_id=SLOT)["slot"]["actor"]["status"] is None
        assert client.request("public_status", slot_id=SLOT)["slot"]["actor"] == actor()


@pytest.mark.parametrize("case", ["missing", "reordered", "duplicate"])
def test_complete_lifetime_pending_projection_is_retained_across_request_keys(case):
    one, two = slot(), slot(identifier=SECOND_SLOT, activation="mpub1:second")
    bad = [] if case == "missing" else [two, one] if case == "reordered" else [one, one]
    with server(lambda request, n: success(request, pending(slots=[one, two] if n == 1 else bad))) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        assert len(client.request("public_pending", request_id="mpub1:first")["slots"]) == 2
        with pytest.raises(public.PublicError) as error:
            client.request("public_pending", request_id="mpub1:new-key")
        assert error.value.code == "protocol_invalid"


@pytest.mark.parametrize("case", [
    "expiry", "activation", "persona", "instruction", "selection",
    "context", "model", "coherent_receipt", "terminal_reopen",
])
def test_retained_slot_and_original_receipt_cannot_be_coherently_rewritten(case):
    first = slot(state="published")
    second = copy.deepcopy(first)
    if case == "expiry":
        second["expires_at"] += 1
    elif case == "activation":
        second["activation_request_id"] = "mpub1:replacement"
    elif case == "persona":
        second["persona_key"] = "replacement"
    elif case == "instruction":
        second["instruction_key"] = "replacement"
    elif case == "selection":
        second["selected_message_ids"] = [SECOND_SLOT]
    elif case in {"context", "model"}:
        second[case + "_digest" if case == "context" else "model_call_digest"] = "e" * 64
    elif case == "coherent_receipt":
        second["receipt"] = acknowledgement(record(
            second["actor"], second["publication_request_key"], content="Coherently replaced."
        ))
    else:
        second["state"] = "offered"
        second["receipt"] = None
    with server(lambda request, n: success(request, slot_result(first if n == 1 else second))) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        client.request("public_status", slot_id=SLOT)
        with pytest.raises(public.PublicError) as error:
            client.request("public_status", slot_id=SLOT)
        assert error.value.code == "protocol_invalid"


def test_valid_terminal_history_survives_actor_leave_without_reopening_admission():
    first = slot(state="published")
    closed = copy.deepcopy(first)
    closed["actor"]["admission_closed"] = True
    leaving = slot(who=actor(closed=True), identifier=SECOND_SLOT,
                   activation="mpub1:leave", state="left")
    with server(lambda request, n: success(request, slot_result(
        first if n == 1 else closed if n == 2 else leaving
    ))) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        before = client.request("public_status", slot_id=SLOT)
        after = client.request("public_status", slot_id=SLOT)
        final = client.request("public_status", slot_id=SECOND_SLOT)
        assert before["slot"]["receipt"] == after["slot"]["receipt"]
        assert final["slot"]["actor"]["admission_closed"] is True
        assert final["slot"]["receipt"]["record"]["body"]["kind"] == "leave"


@pytest.mark.parametrize("case", ["missing_receipt", "wrong_kind", "leave_open", "nonterminal_receipt"])
def test_terminal_receipt_kind_and_closure_are_consistent(case):
    value = slot(state="published")
    if case == "missing_receipt":
        value["receipt"] = None
    elif case == "wrong_kind":
        value["receipt"] = acknowledgement(record(actor(), value["publication_request_key"], kind="decline"))
    elif case == "leave_open":
        value = slot(state="left")
    else:
        value["state"] = "uncertain"
    with server(lambda request, _: success(request, slot_result(value))) as fixture:
        with pytest.raises(public.PublicError):
            public.PublicClient(fixture.path, role="child").request("public_status", slot_id=SLOT)


def test_sparse_peer_history_is_public_data_and_stream_gap_is_not_repaired():
    who, peer = actor(), actor(seed=12)
    original = record(peer, "peer-message", seed=12)
    page = history(who, [original], after=2, cursors=[9])
    gap = history(who, gap="local history stream changed or cursor is ahead")
    with server(lambda request, n: success(request, page if n == 1 else gap)) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        answer = client.request("public_read", after=2, stream_id=who["status"]["stream_id"], watch_seconds=0)
        assert answer["history"]["messages"][0]["record"] == original
        assert answer["history"]["next_cursor"] == 9
        refused_gap = client.request("public_read", after=0, stream_id="f" * 32, watch_seconds=0)
        assert refused_gap["history"]["gap"] == "local history stream changed or cursor is ahead"
        assert len(fixture.requests) == 2


@pytest.mark.parametrize("case", ["foreign_topic", "bad_hash", "duplicate_record", "descending_cursor", "page_bytes", "changed_replay"])
def test_history_checks_original_records_page_budget_and_same_key_snapshot(case):
    who = actor()
    items = [record(who, "one", content="x" * 8000),
             record(who, "two", content="y" * 8000)]
    good = history(who, items, cursors=[3, 8])
    bad = copy.deepcopy(good)
    if case == "foreign_topic":
        bad["history"]["messages"][0]["record"] = record(actor(topic="foreign"), "foreign")
    elif case == "bad_hash":
        bad["history"]["messages"][0]["record"]["body"]["content"] = "tampered"
    elif case == "duplicate_record":
        bad["history"]["messages"][1]["record"] = copy.deepcopy(items[0])
    elif case == "descending_cursor":
        bad["history"]["messages"][1]["cursor"] = 2
    elif case == "page_bytes":
        third = record(who, "three", content="z" * 8000)
        bad = history(who, items + [third], cursors=[3, 8, 11])
    else:
        bad = history(who, [record(who, "different")], cursors=[12])
    with server(lambda request, n: success(request, good if n == 1 else bad)) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        fields = {"after": 0, "stream_id": None, "watch_seconds": 0}
        assert len(client.request("public_read", request_id="mpub1:read", **fields)["history"]["messages"]) == 2
        with pytest.raises(public.PublicError):
            client.request("public_read", request_id="mpub1:read" if case == "changed_replay" else "mpub1:other", **fields)


def test_request_capacity_has_no_reset_and_existing_original_keys_still_work():
    with server(lambda request, _: success(request, pending())) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        for index in range(128):
            client.request("public_pending", request_id=f"mpub1:key-{index}")
        with pytest.raises(public.PublicError) as error:
            client.request("public_pending", request_id="mpub1:over-cap")
        assert error.value.code == "request_limit"
        assert len(fixture.requests) == 128 and len(client._requests) == 128
        client.request("public_pending", request_id="mpub1:key-0")
        assert len(fixture.requests) == 129 and len(client._requests) == 128


def test_wrapper_delegates_ordinary_operations_but_model_cannot_supply_wire_key():
    calls = []
    ordinary = SimpleNamespace(
        call=lambda name, arguments: calls.append((name, arguments)) or "ordinary",
        run_command=lambda argv: calls.append(("verify", argv)) or "verified",
    )
    class Client:
        role = "child"
        def request(self, *_args, **_kwargs):
            pytest.fail("model-selected key reached transport")
    wrapped = public.PublicTools(ordinary, Client())
    assert wrapped.call("read_file", {"path": "AGENTS.md"}) == "ordinary"
    assert wrapped.run_command(["python3", "-V"]) == "verified"
    assert json.loads(wrapped.call("public_pending", {"request_id": "mpub1:model"})) == {
        "ok": False, "error": "invalid_request",
    }
    assert calls == [("read_file", {"path": "AGENTS.md"}), ("verify", ["python3", "-V"])]


def test_trusted_guest_module_imports_under_isolated_stdlib_python(tmp_path):
    (tmp_path / "public_tools.py").write_text("raise RuntimeError('repository module loaded')\n")
    script = (
        "import json,runpy,sys;"
        "m=runpy.run_path(sys.argv[1]);"
        "assert not any(n=='mcp' or n.startswith('cryptography') or n.startswith('src.worker') for n in sys.modules);"
        "print(json.dumps([d['function']['name'] for d in m['ROOT_PUBLIC_TOOL_DEFINITIONS']]))"
    )
    result = subprocess.run(
        [sys.executable, "-I", "-S", "-c", script, str(Path(public.__file__).resolve())],
        cwd=tmp_path, input="", text=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
        timeout=5, check=False,
    )
    assert result.returncode == 0, result.stderr
    assert json.loads(result.stdout) == [
        "public_activate", "public_turn", "public_status", "public_read", "public_invite",
    ]


@pytest.mark.parametrize("connect_seconds", [4.0, 6.0])
def test_connect_and_send_share_one_original_absolute_deadline(monkeypatch, connect_seconds):
    # Deterministic transport timing control. Other cases use actual Unix sockets.
    clock = [100.0]
    sent, timeouts = [], []
    response = frame(json.dumps({
        "schema_version": 1, "request_id": "mpub1:timing", "ok": True,
        "result": pending(),
    }).encode())
    class Connection:
        def __init__(self):
            self.buffer = response
        def __enter__(self):
            return self
        def __exit__(self, *_args):
            pass
        def settimeout(self, seconds):
            timeouts.append(seconds)
        def connect(self, _path):
            clock[0] += connect_seconds
        def sendall(self, payload):
            sent.append((payload, timeouts[-1], clock[0]))
        def recv(self, size):
            result, self.buffer = self.buffer[:size], self.buffer[size:]
            return result
    monkeypatch.setattr(public, "time", SimpleNamespace(
        monotonic=lambda: clock[0], sleep=lambda seconds: clock.__setitem__(0, clock[0] + seconds),
    ))
    monkeypatch.setattr(public.socket, "socket", lambda *_args, **_kwargs: Connection())
    client = public.PublicClient("/fixed.sock", role="child", timeout_seconds=5)
    if connect_seconds > 5:
        with pytest.raises(public.PublicError) as error:
            client.request("public_pending", request_id="mpub1:timing")
        assert error.value.code == "transport_unavailable"
        assert sent == []
    else:
        assert client.request("public_pending", request_id="mpub1:timing")["slots"] == []
        assert len(sent) == 1
        assert sent[0][1] == pytest.approx(1.0)
        assert sent[0][2] + sent[0][1] == pytest.approx(105.0)
    assert client._requests["mpub1:timing"]["deadline"] == 105.0


@pytest.mark.parametrize("terminal", ["published", "declined", "left"])
def test_original_leave_intent_survives_uncertainty_and_pending_recovery(terminal):
    who = actor(closed=True)
    original = slot(who=who, state="leave_pending")
    uncertain = slot(who=who, state="uncertain")
    uncertain["reason"] = "publication_uncertain"
    recovering = slot(who=who, state="publication_pending")
    final = slot(who=who, state=terminal)
    values = [original, uncertain, recovering, final]

    # Each terminal receipt is independently coherent. A message/decline is
    # valid for another slot, but cannot replace this previously observed leave.
    receipt = final["receipt"]
    signing_key(11).public_key().verify(
        bytes.fromhex(receipt["record"]["signature"]),
        canonical(receipt["record"]["body"]),
    )
    with server(lambda request, n: success(request, slot_result(values[n - 1]))) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        for index in range(3):
            client.request("public_status", request_id=f"mpub1:phase-{index}", slot_id=SLOT)
        if terminal == "left":
            answer = client.request("public_status", request_id="mpub1:final", slot_id=SLOT)
            assert answer["slot"]["receipt"] == receipt
        else:
            with pytest.raises(public.PublicError) as error:
                client.request("public_status", request_id="mpub1:final", slot_id=SLOT)
            assert error.value.code == "protocol_invalid"
        assert client._leave_slots == {SLOT}
    if terminal != "left":
        with server(lambda request, _: success(request, slot_result(final))) as fixture:
            fresh = public.PublicClient(fixture.path, role="child")
            assert fresh.request("public_status", slot_id=SLOT)["slot"]["receipt"] == receipt


@pytest.mark.parametrize("operation", ["public_status", "public_invite"])
def test_managed_receipts_require_empty_references_but_history_preserves_public_data(operation):
    who = actor("root") if operation == "public_invite" else actor()
    fields = {"invitation_key": "approved-invite"} if operation == "public_invite" else {"slot_id": SLOT}
    key = (
        "oj-public-invite:" + digest([who["status"]["author"], "approved-invite", "mpub1:receipt"])
        if operation == "public_invite" else "oj-public:" + SLOT
    )
    kwargs = {"kind": "invite", "target": "f" * 16} if operation == "public_invite" else {}
    original = record(who, key, **kwargs)
    changed = record(who, key, references=[{"kind": "child", "id": CHILD}], **kwargs)
    signing_key(11).public_key().verify(bytes.fromhex(changed["signature"]), canonical(changed["body"]))
    assert changed["message_id"] == digest(changed["body"])

    def result(item):
        if operation == "public_invite":
            return {
                "actor": who, "invitation_key": "approved-invite",
                "publication_request_key": key, "state": "published", "reason": None,
                "receipt": acknowledgement(item), "execution_authorized": False,
            }
        value = slot(state="published")
        value["receipt"] = acknowledgement(item)
        return slot_result(value)

    with server(lambda request, n: success(request, result(changed if n == 1 else original))) as fixture:
        with pytest.raises(public.PublicError) as error:
            public.PublicClient(fixture.path, role=who["role"]).request(
                operation, request_id="mpub1:receipt", **fields
            )
        assert error.value.code == "protocol_invalid"
        assert error.value.request_id == "mpub1:receipt"
        assert len(fixture.requests) == 1
        # A fresh valid receipt is still accepted on the same actual transport.
        answer = public.PublicClient(fixture.path, role=who["role"]).request(
            operation, request_id="mpub1:receipt", **fields
        )
        assert answer == result(original)
    # Typed references remain public history data, never execution permission.
    with server(lambda request, _: success(request, history(who, [changed]))) as fixture:
        answer = public.PublicClient(fixture.path, role=who["role"]).request(
            "public_read", after=0, stream_id=None, watch_seconds=0
        )
        assert answer["history"]["messages"][0]["record"] == changed


@pytest.mark.parametrize("fault", ["message", "leave", "changed_text", "model_charge"])
def test_explicit_decline_cannot_be_replaced_by_a_different_valid_signed_decision(fault):
    good = slot(state="declined", model=False)
    if fault == "message":
        bad = slot(state="published")
    elif fault == "leave":
        bad = slot(who=actor(closed=True), state="left")
    elif fault == "model_charge":
        bad = slot(state="declined", model=True)
        bad["receipt"] = copy.deepcopy(good["receipt"])
    else:
        bad = copy.deepcopy(good)
        bad["receipt"] = acknowledgement(record(
            bad["actor"], bad["publication_request_key"], kind="decline",
            content="A different public refusal chosen elsewhere.",
        ))
    item = bad["receipt"]["record"]
    signing_key(11).public_key().verify(bytes.fromhex(item["signature"]), canonical(item["body"]))
    assert item["message_id"] == digest(item["body"])
    with server(lambda request, n: success(request, slot_result(bad if n == 1 else good))) as fixture:
        client = public.PublicClient(fixture.path, role="child")
        with pytest.raises(public.PublicError) as error:
            client.request("public_decline", request_id="mpub1:decline", slot_id=SLOT)
        assert error.value.code == "protocol_invalid"
        assert error.value.request_id == "mpub1:decline"
        assert len(fixture.requests) == 1
        assert client._actors == {} and client._slots == {}
        answer = public.PublicClient(fixture.path, role="child").request(
            "public_decline", request_id="mpub1:decline", slot_id=SLOT
        )
        assert answer == slot_result(good)
        assert answer["slot"]["model_call_digest"] is None
        assert answer["slot"]["receipt"]["record"]["body"]["content"] == FIXED_DECLINE
    # These are well-formed observations. Only fixed no-model decline rejects them.
    with server(lambda request, _: success(request, slot_result(bad))) as fixture:
        assert public.PublicClient(fixture.path, role="child").request(
            "public_status", slot_id=SLOT
        ) == slot_result(bad)


@pytest.mark.parametrize("operation", ["public_turn", "public_pull", "public_decline", "public_invite"])
@pytest.mark.parametrize("state", ["publication_pending", "uncertain", "refused"])
def test_effect_success_cannot_hide_pending_uncertainty_or_refusal(operation, state):
    role = "root" if operation in {"public_turn", "public_invite"} else "child"
    fields = (
        selection() if operation == "public_turn" else
        {"invitation_key": "approved-invite"} if operation == "public_invite" else
        {"slot_id": SLOT}
    )

    def respond(request, _number):
        who = actor(role)
        if operation == "public_invite":
            key = "oj-public-invite:" + digest([
                who["status"]["author"], "approved-invite", request["request_id"],
            ])
            value = {
                "actor": who, "invitation_key": "approved-invite",
                "publication_request_key": key, "state": state, "reason": None,
                "receipt": None, "execution_authorized": False,
            }
        else:
            value = slot_result(slot(
                who=who, state=state, model=operation != "public_decline",
                activation=request["request_id"] if operation == "public_turn" else "mpub1:activation",
            ))
        return success(request, value)

    with server(respond) as fixture:
        client = public.PublicClient(fixture.path, role=role)
        ordinary = SimpleNamespace(call=lambda *_: pytest.fail("ordinary fallback ran"))
        with pytest.raises(public.PublicError) as error:
            public.PublicTools(ordinary, client).call(operation, fields)
        assert error.value.code == "protocol_invalid"
        assert error.value.request_id == fixture.requests[0]["request_id"]
        assert len(fixture.requests) == 1
        assert client._actors == {} and client._slots == {}
    if operation != "public_invite":
        # Intermediate/uncertain state remains observable through a fresh read.
        observed = slot(who=actor(role), state=state, model=operation != "public_decline")
        with server(lambda request, _: success(request, slot_result(observed))) as fixture:
            assert public.PublicClient(fixture.path, role=role).request(
                "public_status", slot_id=SLOT
            ) == slot_result(observed)


@pytest.mark.parametrize("operation", ["public_turn", "public_pull"])
@pytest.mark.parametrize("state", ["published", "declined", "left"])
def test_model_selected_terminal_effect_kinds_remain_valid(operation, state):
    role = "root" if operation == "public_turn" else "child"
    fields = selection() if operation == "public_turn" else {"slot_id": SLOT}

    def respond(request, _number):
        value = slot(
            who=actor(role, closed=state == "left"), state=state,
            activation=request["request_id"] if operation == "public_turn" else "mpub1:activation",
        )
        return success(request, slot_result(value))

    with server(respond) as fixture:
        answer = public.PublicClient(fixture.path, role=role).request(operation, **fields)
        assert answer["slot"]["state"] == state
        assert answer["slot"]["model_call_digest"] is not None
        assert answer["slot"]["receipt"]["record"]["body"]["kind"] == {
            "published": "message", "declined": "decline", "left": "leave",
        }[state]
        assert len(fixture.requests) == 1
