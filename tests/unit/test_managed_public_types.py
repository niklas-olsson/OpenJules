"""Pure managed-public boundaries; no enabled host, provider or peer is claimed."""

from copy import deepcopy
from dataclasses import asdict
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from src.worker.child_types import ChildPolicy
from src.worker import managed_public_types as public
from tests.unit.test_child_authority_contract import policy as ordinary_policy


def public_document(tmp_path):
    scope = tmp_path / "scope.key"
    scope.write_bytes(b"private-scope-canary\n")
    scope.chmod(0o600)
    return {
        "protocol": public.PROTOCOL, "public_approved": True,
        "topic": "  explicit public topic  ",
        "server": {
            "python": sys.executable, "cwd": str(tmp_path),
            "scope_key_file": str(scope),
            "scope_key_sha256": hashlib.sha256(scope.read_bytes()).hexdigest(),
        },
        "personas": {"independent": "  Offer independent public reasoning.  "},
        "instructions": {"proposal": "Discuss only this approved public question."},
        "invitations": {
            "peer": {"target": "0123456789abcdef", "content": "An optional public invitation."},
        },
    }


def root_command():
    return [
        "python3", "-I", "-S", "/opt/openjules/managed_root_runner.py",
        "--socket", "/run/openjules-model/model.sock",
        "--control-socket", "/run/openjules-model/control.sock",
        "--public-socket", "/run/openjules-model/public.sock",
    ]


def completion(output):
    return json.dumps({
        "choices": [{"message": {"role": "assistant", "content": json.dumps(output)},
                     "finish_reason": "stop"}],
    }).encode()


def test_dormant_helpers_do_not_enable_actual_child_policy_or_change_omission(tmp_path):
    original = ordinary_policy()
    before = asdict(original), original.fingerprint, original.canonical_policy
    block = public_document(tmp_path)
    parsed = public.PublicPolicy.parse(block)
    assert parsed.document == block
    with pytest.raises(TypeError, match="public_discussion"):
        ChildPolicy(**(asdict(original) | {"public_discussion": block}))
    assert (asdict(original), original.fingerprint, original.canonical_policy) == before
    assert "public_discussion" not in asdict(original)


def test_public_policy_is_an_immutable_copy_and_uses_original_ascii_bytes(tmp_path):
    source = public_document(tmp_path)
    source["topic"] = " "
    source["instructions"]["proposal"] = "Public \u754c reasoning."
    untouched = deepcopy(source)
    approved = public.PublicPolicy.parse(source)
    assert approved.encoded == json.dumps(
        untouched, sort_keys=True, separators=(",", ":"), allow_nan=False,
    ).encode()
    assert b"\\u754c" in approved.encoded
    source["instructions"]["proposal"] = "unapproved later change"
    source["server"]["scope_key_sha256"] = "0" * 64
    projection = approved.document
    projection["personas"].clear()
    assert approved.document == untouched
    assert approved.fingerprint == hashlib.sha256(approved.encoded).hexdigest()


@pytest.mark.parametrize("fault", [
    "null", "true_alias", "protocol", "cold_extra", "empty_topic", "topic_control",
    "topic_surrogate", "empty_personas", "bad_key", "blank_text", "too_many_instructions",
    "extra_invitation", "target", "missing_hash", "null_bootstrap", "bootstrap_host",
    "bootstrap_boolean", "bootstrap_huge",
])
def test_invalid_policy_shapes_fail_before_any_host_binding(tmp_path, fault):
    value = public_document(tmp_path)
    if fault == "null":
        value = None
    elif fault == "true_alias":
        value["public_approved"] = 1
    elif fault == "protocol":
        value["protocol"] = "managed-public-discussion-v1"
    elif fault == "cold_extra":
        value["session_protocol"] = "cold-clarification-v1"
    elif fault == "empty_topic":
        value["topic"] = ""
    elif fault == "topic_control":
        value["topic"] = "public\nhidden"
    elif fault == "topic_surrogate":
        value["topic"] = "\ud800"
    elif fault == "empty_personas":
        value["personas"] = {}
    elif fault == "bad_key":
        value["personas"] = {"not an approved key": "public"}
    elif fault == "blank_text":
        value["instructions"] = {"proposal": " \t "}
    elif fault == "too_many_instructions":
        value["instructions"] = {str(n): "public" for n in range(9)}
    elif fault == "extra_invitation":
        value["invitations"]["peer"]["permission"] = "execute"
    elif fault == "target":
        value["invitations"]["peer"]["target"] = "A" * 16
    elif fault == "missing_hash":
        value["server"].pop("scope_key_sha256")
    else:
        value["server"]["bootstrap"] = (
            None if fault == "null_bootstrap" else
            {"host": "localhost", "port": 41001} if fault == "bootstrap_host" else
            {"host": "127.0.0.1", "port": True if fault == "bootstrap_boolean" else 10 ** 1000}
        )
    with pytest.raises(ValueError, match="invalid managed public discussion policy"):
        public.PublicPolicy.parse(value)


def test_ascii_expansion_is_bounded_separately_from_utf8_text(tmp_path):
    value = public_document(tmp_path)
    value["personas"] = {str(n): "\u754c" * 1365 for n in range(3)}
    value["instructions"] = {str(n): "\u754c" * 1365 for n in range(8)}
    assert all(len(text.encode()) == 4095 for text in value["instructions"].values())
    assert len(json.dumps(value, ensure_ascii=False, separators=(",", ":")).encode()) < 65536
    assert len(json.dumps(value, ensure_ascii=True, separators=(",", ":")).encode()) > 65536
    with pytest.raises(ValueError):
        public.PublicPolicy.parse(value)
    value["personas"] = {"one": "public"}
    value["instructions"] = {"one": "\u754c" * 1365}
    assert len(public.PublicPolicy.parse(value).encoded) < 65536


@pytest.mark.parametrize("value", [True, None, float("nan"), float("inf"), 10 ** 1000, -1, "\ud800"])
def test_direct_numeric_calls_have_fixed_errors_without_conversion_leaks(value):
    with pytest.raises(public.ManagedPublicError) as caught:
        public.finite(value, 0, 120)
    assert caught.value.code == "invalid_request"
    assert str(caught.value) == "invalid_request"
    with pytest.raises(public.ManagedPublicError):
        public.integer(value, 1, 1000)


@pytest.mark.parametrize("raw", [
    '{"schema_version":1,"schema_version":1}', '{"x":NaN}', '{"x":1e999}',
    '{"x":"\ud800"}', "[" + "0" + "]", "",
])
def test_raw_json_ambiguity_and_invalid_scalar_shape_are_fixed(raw):
    # A lone surrogate in a Python string cannot enter a bounded UTF-8 record.
    with pytest.raises(public.ManagedPublicError) as caught:
        public.object_value(raw)
    assert caught.value.code == "invalid_request"
    assert str(caught.value) == "invalid_request"
    assert public.object_value('{"x":1}') == {"x": 1}


def test_retained_json_must_have_exact_original_canonical_bytes():
    with pytest.raises(public.ManagedPublicError, match="state_conflict"):
        public.object_value('{ "x" : 1 }', code="state_conflict", retained=True)
    assert public.object_value('{"x":1}', retained=True) == {"x": 1}


def test_root_command_only_accepts_fixed_roles_and_bounded_optional_pairs():
    command = root_command()
    public.validate_root_command(command)
    public.validate_root_command(command + [
        "--max-turns", "1000", "--control-timeout-seconds", "120",
        "--verify-json", json.dumps(["python3", "-m", "unittest"]),
    ])
    for changed in (
        command[:-2], command + ["--public-socket", command[-1]],
        command + ["--max-turns", "1001"], command + ["--max-turns", "+2"],
        command + ["--control-timeout-seconds", "nan"],
        command + ["--control-timeout-seconds", "1e999"],
        command + ["--verify-json", json.dumps(["x"] * 129)],
        command + ["--verify-json", '["a\\u0000b"]'],
        ["python3", "unapproved.py"],
    ):
        with pytest.raises(ValueError):
            public.validate_root_command(changed)
    public.validate_root_command(command + ["--verify-json", "[]"])


def test_scope_binding_checks_original_bytes_and_symlinked_interpreter_separately(tmp_path):
    document = public_document(tmp_path)
    link = tmp_path / "trusted-python"
    link.symlink_to(sys.executable)
    document["server"]["python"] = str(link)
    approved = public.PublicPolicy.parse(document)
    binding = approved.check_server()
    assert binding["launch_path"] == str(link)
    assert binding["resolved_executable"] == str(Path(sys.executable).resolve())
    assert binding["scope"]["sha256"] == hashlib.sha256(b"private-scope-canary\n").hexdigest()
    assert "private-scope-canary" not in json.dumps(binding)
    scope = Path(document["server"]["scope_key_file"])
    scope.write_bytes(b"x" * 4096)
    document["server"]["scope_key_sha256"] = hashlib.sha256(scope.read_bytes()).hexdigest()
    assert public.read_scope(document["server"])["sha256"] == document["server"]["scope_key_sha256"]


@pytest.mark.parametrize("fault", ["parent_link", "leaf_link", "double_slash", "hardlink", "mode", "wrong_owner", "changed", "fifo"])
def test_private_scope_refuses_unsafe_original_paths(tmp_path, monkeypatch, fault):
    document = public_document(tmp_path)
    scope = Path(document["server"]["scope_key_file"])
    alias = tmp_path / "alias"
    if fault == "parent_link":
        alias.symlink_to(tmp_path, target_is_directory=True)
        document["server"]["scope_key_file"] = str(alias / scope.name)
    elif fault == "leaf_link":
        alias.symlink_to(scope)
        document["server"]["scope_key_file"] = str(alias)
    elif fault == "double_slash":
        document["server"]["scope_key_file"] = "/" + str(scope)
    elif fault == "hardlink":
        os.link(scope, alias)
    elif fault == "mode":
        scope.chmod(0o644)
    elif fault == "wrong_owner":
        monkeypatch.setattr(public.os, "geteuid", lambda: scope.stat().st_uid + 1)
    elif fault == "changed":
        scope.write_bytes(b"unapproved-scope")
    else:
        scope.unlink()
        os.mkfifo(scope, 0o600)
    if fault == "fifo":
        program = (
            "import json,sys\n"
            "from src.worker.managed_public_types import read_scope,ManagedPublicError\n"
            "try: read_scope(json.loads(sys.argv[1]))\n"
            "except ManagedPublicError: raise SystemExit(0)\n"
            "raise SystemExit(9)\n"
        )
        result = subprocess.run(
            [sys.executable, "-c", program, json.dumps(document["server"])],
            stdin=subprocess.DEVNULL, capture_output=True, timeout=3, check=False,
        )
        assert result.returncode == 0 and result.stdout == result.stderr == b""
    else:
        with pytest.raises(public.ManagedPublicError) as caught:
            public.read_scope(document["server"])
        assert str(caught.value) == "state_conflict"


@pytest.mark.parametrize("replace_parent", [False, True])
def test_descriptor_leaf_and_parent_swap_never_return_replaced_binding(tmp_path, monkeypatch, replace_parent):
    directory = tmp_path / "original"
    directory.mkdir()
    document = public_document(directory)
    scope = Path(document["server"]["scope_key_file"])
    real_open = os.open
    changed = []
    retained = tmp_path / "retained"

    def swap(path, *args, **kwargs):
        if str(path) == scope.name and not changed:
            changed.append(True)
            if replace_parent:
                directory.rename(retained)
                directory.symlink_to(retained, target_is_directory=True)
            else:
                scope.rename(directory / "old-scope")
                scope.write_bytes(b"private-scope-canary\n")
                scope.chmod(0o600)
        return real_open(path, *args, **kwargs)

    with monkeypatch.context() as patch:
        patch.setattr(public.os, "open", swap)
        with pytest.raises(public.ManagedPublicError, match="state_conflict"):
            public.read_scope(document["server"])
    assert changed == [True]
    if replace_parent:
        assert scope.read_bytes() == b"private-scope-canary\n"
        directory.unlink()
        retained.rename(directory)
    assert public.read_scope(document["server"])["sha256"] == document["server"]["scope_key_sha256"]


def test_public_payload_uses_only_approved_projection_and_shared_completion_parser(tmp_path):
    document = public_document(tmp_path)
    approved = public.PublicPolicy.parse(document)
    messages = public.public_messages(approved, "independent", "proposal", [])
    assert [value["role"] for value in messages] == ["system", "user"]
    assert messages[0]["content"].endswith("\n\n" + document["personas"]["independent"])
    assert json.loads(messages[1]["content"]) == {
        "instruction": document["instructions"]["proposal"], "public_context": [],
    }
    raw = public.canonical(messages)
    for private in (b"private-scope-canary", document["server"]["scope_key_file"].encode(), b"scope_key_sha256"):
        assert private not in raw
    expected = {"kind": "decline", "content": "An independent public refusal."}
    assert public.public_output(completion(expected), "private-model-token") == expected
    assert approved.document == document


@pytest.mark.parametrize("fault", ["tools", "truncated", "extra_output", "raw_text", "token_echo", "duplicate", "invalid_kind"])
def test_invalid_or_credential_bearing_provider_output_is_fixed_uncertainty(fault):
    token = "private-provider-token-canary"
    output = {"kind": "message", "content": "Approved public content."}
    value = json.loads(completion(output))
    if fault == "tools":
        value["choices"][0]["message"]["tool_calls"] = [{"id": "untrusted"}]
    elif fault == "truncated":
        value["choices"][0]["finish_reason"] = "length"
    elif fault == "extra_output":
        value["choices"][0]["message"]["content"] = json.dumps(output | {"private": token})
    elif fault == "raw_text":
        value["choices"][0]["message"]["content"] = "not an output object"
    elif fault == "token_echo":
        value["choices"][0]["message"]["content"] = json.dumps(output | {"content": token})
    elif fault == "duplicate":
        value["choices"][0]["message"]["content"] = '{"kind":"leave","kind":"message","content":"x"}'
    else:
        value["choices"][0]["message"]["content"] = json.dumps(output | {"kind": "execute"})
    with pytest.raises(public.ManagedPublicError) as caught:
        public.public_output(json.dumps(value).encode(), token)
    assert caught.value.code == "provider_uncertain"
    assert token not in str(caught.value)
