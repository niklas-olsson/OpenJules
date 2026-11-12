"""Real private files/SQLite/crypto and HTTP compatibility fixtures.

These are component fixtures. They do not run the missing restricted Polyphony
profile or make a live-provider, installed-conversation or power-loss claim.
"""

from __future__ import annotations

import asyncio
from copy import deepcopy
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import sqlite3
import stat
import subprocess
import sys
import threading
import time

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from src.worker import discussion_journal as journal_module
from src.worker import discussion_types as types
from src.worker.discussion_journal import DiscussionJournal
from src.worker.discussion_types import (
    Deadline, DiscussionError, Policy, Turn, canonical, digest, publication_intent,
)
from src.worker.model_broker import BrokerDenied, ModelBroker, ModelPolicy, TOOL_DEFINITIONS


PRIVATE_KEY = Ed25519PrivateKey.from_private_bytes(b"\x17" * 32)


def private_json(path, value):
    path.write_bytes(canonical(value) + b"\n")
    path.chmod(0o600)
    return path


def fixture_status(topic="fixture-public-topic"):
    public = PRIVATE_KEY.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()
    swarm = hashlib.sha256(b"fixture-public-scope").hexdigest()
    return {
        "schema_version": 1, "profile": "polyphony-public-conversation",
        "topic": topic, "swarm_id": swarm,
        "session_id": hashlib.sha256(canonical([
            "polyphony-public-conversation-v1", swarm, topic,
        ])).hexdigest(),
        "author": hashlib.sha256(bytes.fromhex(public)).hexdigest()[:16],
        "public_key": public, "stream_id": "a" * 32,
        "visibility": "public", "execution_authorized": False,
    }


def fixture_policy(tmp_path, *, limits=None, endpoint=None):
    checkout = tmp_path / "approved-checkout"
    checkout.mkdir(mode=0o700)
    scope = tmp_path / "scope"
    scope.write_text("fixture-public-scope", encoding="utf-8")
    scope.chmod(0o600)
    a_config = private_json(tmp_path / "conversation.json", {
        "schema_version": 1, "topic": "fixture-public-topic",
        "scope_key_file": str(scope), "state_directory": str(tmp_path / "a-state"),
    })
    path = private_json(tmp_path / "participant.json", {
        "schema_version": 1, "public_approved": True,
        "topic": "fixture-public-topic", "persona": "A fixture public participant.",
        "provider": {
            "endpoint": endpoint or "http://127.0.0.1:9/v1/chat/completions",
            "model": "fixture/model", "token_ref": "env:DISCUSSION_FIXTURE_TOKEN",
        },
        "server": {
            "python": sys.executable, "cwd": str(checkout), "config": str(a_config),
        },
        "state_directory": str(tmp_path / "b-state"),
        "limits": limits or {},
    })
    policy = Policy.load(path)
    interpreter = {
        "schema_version": 1, "launch_path": sys.executable,
        "resolved_executable": str(Path(sys.executable).resolve()),
        "prefix": str(Path(sys.prefix).resolve()),
    }
    return policy, interpreter, fixture_status()


def fixture_turn(key="turn-1", **changes):
    value = {
        "schema_version": 1, "request_key": key, "expires_at": time.time() + 120,
        "instruction": "Contribute one bounded public thought.",
        "selected_message_ids": [], "context_after": 0, "stream_id": None,
    }
    value.update(changes)
    return Turn.parse(canonical(value) + b"\n")


def fixture_context(status):
    return {
        "status": status, "messages": [], "peer_gaps": [],
        "context_after": 0, "next_cursor": 0,
    }


def signed_record(status, intent, *, timestamp=1234.5):
    body = {
        **intent, "schema_version": 1, "author": status["author"],
        "public_key": status["public_key"], "timestamp": timestamp,
    }
    encoded = canonical(body)
    return {
        "message_id": hashlib.sha256(encoded).hexdigest(),
        "body": body, "signature": PRIVATE_KEY.sign(encoded).hex(),
    }


def fixture_receipt(status, intent):
    record = signed_record(status, intent)
    return {
        "schema_version": 1, "message_id": record["message_id"],
        "session_id": status["session_id"], "author": status["author"],
        "stored": True, "visibility": "public", "delivery": "submitted",
        "execution_authorized": False, "record": record,
    }


def initialized(tmp_path, **kwargs):
    policy, interpreter, status = fixture_policy(tmp_path, **kwargs)
    result = DiscussionJournal.initialize(policy, interpreter, status)
    assert result["state"] == "initialized"
    return policy, interpreter, status


def prepared(journal, status, turn=None):
    turn = turn or fixture_turn()
    journal.prepare(turn)
    journal.freeze_context(turn.key, fixture_context(status))
    return turn


def run_owned_child(argv, *, cwd=None, timeout=10):
    child = subprocess.Popen(
        argv, cwd=cwd, stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = child.communicate(timeout=timeout)
        return child.returncode, stdout, stderr
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
        if child.stdout is not None:
            child.stdout.close()
        if child.stderr is not None:
            child.stderr.close()


def test_explicit_init_persists_parent_before_any_usable_state(tmp_path, monkeypatch):
    policy, interpreter, status = fixture_policy(tmp_path)
    calls = []
    real_sync = os.fsync

    def sync(fd):
        path = Path(os.readlink(f"/proc/self/fd/{fd}"))
        if stat.S_ISDIR(os.fstat(fd).st_mode):
            calls.append(path)
            if path == tmp_path:
                assert policy.state.is_dir()
                assert list(policy.state.iterdir()) == []
        return real_sync(fd)

    monkeypatch.setattr(journal_module.os, "fsync", sync)
    DiscussionJournal.initialize(policy, interpreter, status)
    assert calls == [tmp_path, policy.state]
    with DiscussionJournal(policy) as journal:
        assert journal.status()["calls_reserved"] == 0
    with pytest.raises(DiscussionError, match="already_initialized"):
        DiscussionJournal.initialize(policy, interpreter, status)


def test_parent_sync_failure_leaves_refused_partial_leaf(tmp_path, monkeypatch):
    policy, interpreter, status = fixture_policy(tmp_path)
    real_sync = os.fsync

    def sync(fd):
        if Path(os.readlink(f"/proc/self/fd/{fd}")) == tmp_path:
            raise OSError("injected parent sync failure")
        return real_sync(fd)

    monkeypatch.setattr(journal_module.os, "fsync", sync)
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal.initialize(policy, interpreter, status)
    assert policy.state.is_dir() and list(policy.state.iterdir()) == []
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)
    with pytest.raises(DiscussionError, match="already_initialized"):
        DiscussionJournal.initialize(policy, interpreter, status)


@pytest.mark.parametrize("missing", ["owner.lock", "binding.json", "discussion.sqlite3"])
def test_missing_completed_file_never_becomes_new_allowance(tmp_path, missing):
    policy, interpreter, status = initialized(tmp_path)
    (policy.state / missing).unlink()
    retained = {p.name: p.read_bytes() for p in policy.state.iterdir()}
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)
    with pytest.raises(DiscussionError, match="already_initialized"):
        DiscussionJournal.initialize(policy, interpreter, status)
    assert {p.name: p.read_bytes() for p in policy.state.iterdir()} == retained


@pytest.mark.parametrize("suffix", ["-wal", "-shm"])
def test_unexpected_wal_files_are_not_an_adoption_path(tmp_path, suffix):
    policy, _, _ = initialized(tmp_path)
    path = policy.state / ("discussion.sqlite3" + suffix)
    path.write_bytes(b"unexpected")
    path.chmod(0o600)
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)
    assert path.read_bytes() == b"unexpected"


def test_private_modes_links_and_inspection_errors_refuse(tmp_path, monkeypatch):
    policy, _, _ = initialized(tmp_path)
    database = policy.state / "discussion.sqlite3"
    original = database.read_bytes()
    database.chmod(0o644)
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)
    database.chmod(0o600)
    replacement = policy.state / "replacement"
    database.rename(replacement)
    database.symlink_to(replacement)
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)
    database.unlink()
    replacement.rename(database)
    real_lstat = Path.lstat

    def broken(path, *args, **kwargs):
        if path == policy.state / "discussion.sqlite3-wal":
            raise PermissionError("injected unknown presence")
        return real_lstat(path, *args, **kwargs)

    monkeypatch.setattr(Path, "lstat", broken)
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)
    assert database.read_bytes() == original


def test_owner_lock_and_replaced_database_identity_are_retained(tmp_path):
    policy, _, _ = initialized(tmp_path)
    with DiscussionJournal(policy):
        with pytest.raises(DiscussionError, match="state_conflict"):
            DiscussionJournal(policy)
    database = policy.state / "discussion.sqlite3"
    retained = database.read_bytes()
    replacement = policy.state / "new-database"
    replacement.write_bytes(retained)
    replacement.chmod(0o600)
    replacement.replace(database)
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)


def test_policy_whitespace_change_and_changed_same_key_do_not_renew(tmp_path):
    policy, _, status = initialized(tmp_path)
    turn = fixture_turn()
    with DiscussionJournal(policy) as journal:
        before = journal.prepare(turn)
        changed = dict(turn.document, expires_at=turn.document["expires_at"] + 1)
        with pytest.raises(DiscussionError, match="state_conflict"):
            journal.prepare(Turn.parse(canonical(changed)))
        assert journal.get(turn.key) == before
        assert journal.prepare(turn) == before
    policy.path.write_bytes(policy.path.read_bytes() + b" ")
    changed_policy = Policy.load(policy.path)
    with pytest.raises(DiscussionError, match="state_conflict"):
        DiscussionJournal(changed_policy)


def test_prepared_key_limit_survives_reopen_without_charging_allowance(
    tmp_path, monkeypatch,
):
    policy, _, _ = initialized(tmp_path)

    def unexpected_request(*args, **kwargs):
        pytest.fail("preparing a key must not construct a provider request")

    monkeypatch.setattr(journal_module, "provider_request", unexpected_request)
    turns = [fixture_turn(f"prepared-{index:03d}") for index in range(128)]
    overflow = fixture_turn("prepared-overflow")
    with DiscussionJournal(policy) as journal:
        retained = [journal.prepare(turn) for turn in turns]
        before = journal.status()
        assert before["turns"] == {"prepared": 128}
        assert before["calls_reserved"] == before["tokens_reserved"] == 0
        assert before["provider_uncertain"] is False
        assert all(value["provider_request"] is None for value in retained)
        assert all(value["reserved_tokens"] == 0 for value in retained)
        with pytest.raises(DiscussionError, match="^journal_full$"):
            journal.prepare(overflow)
        assert journal.get(overflow.key) is None
        assert journal.prepare(turns[0]) == retained[0]
        assert journal.prepare(turns[-1]) == retained[-1]
        assert journal.status() == before

    with DiscussionJournal(policy) as reopened:
        assert reopened.status() == before
        assert [reopened.get(turn.key) for turn in turns] == retained
        with pytest.raises(DiscussionError, match="^journal_full$"):
            reopened.prepare(overflow)
        assert reopened.get(overflow.key) is None
        assert reopened.prepare(turns[0]) == retained[0]
        assert reopened.status() == before


def test_outstanding_reservation_blocks_prepared_and_new_keys_same_owner(tmp_path):
    policy, _, status = initialized(tmp_path)
    with DiscussionJournal(policy) as journal:
        one = prepared(journal, status, fixture_turn("one"))
        two = prepared(journal, status, fixture_turn("two"))
        first = journal.reserve(one.key)
        assert first["reserved_tokens"] == 1024
        with pytest.raises(DiscussionError, match="provider_uncertain"):
            journal.reserve(two.key)
        with pytest.raises(DiscussionError, match="provider_uncertain"):
            journal.prepare(fixture_turn("three"))
        assert journal.status()["calls_reserved"] == 1
        assert journal.get(two.key)["reserved_tokens"] == 0


def test_known_terminal_rejection_retains_exact_total_and_partial_final_charge(tmp_path):
    policy, _, status = initialized(tmp_path, limits={
        "max_calls": 3, "max_output_tokens": 32, "max_total_output_tokens": 40,
    })
    with DiscussionJournal(policy) as journal:
        for key, tokens in (("one", 32), ("two", 8)):
            turn = prepared(journal, status, fixture_turn(key))
            assert journal.reserve(key)["reserved_tokens"] == tokens
            journal.provider_failed(key, uncertain=False)
        third = prepared(journal, status, fixture_turn("three"))
        with pytest.raises(DiscussionError, match="budget_exhausted"):
            journal.reserve(third.key)
        assert journal.status()["tokens_reserved"] == 40
    with DiscussionJournal(policy) as reopened:
        assert reopened.status()["calls_reserved"] == 2
        assert reopened.status()["tokens_reserved"] == 40
        assert reopened.status()["provider_uncertain"] is False


def test_crashed_process_reservation_is_sticky_across_new_keys(tmp_path):
    policy, _, status = initialized(tmp_path)
    turn = fixture_turn()
    path = private_json(tmp_path / "turn.json", turn.document)
    code = """
import os,sys
from src.worker.discussion_types import Policy,Turn,read_private_bytes
from src.worker.discussion_journal import DiscussionJournal
p=Policy.load(sys.argv[1]); t=Turn.parse(read_private_bytes(sys.argv[2]))
j=DiscussionJournal(p); j.prepare(t)
j.freeze_context(t.key, {'status':j.binding['status'],'messages':[],
'peer_gaps':[],'context_after':0,'next_cursor':0})
j.reserve(t.key); os._exit(23)
"""
    code_value, stdout, stderr = run_owned_child(
        [sys.executable, "-c", code, str(policy.path), str(path)],
        cwd=Path(__file__).resolve().parents[2],
    )
    assert code_value == 23 and stdout == b"" and stderr == b""
    with DiscussionJournal(policy, read_only=True) as read:
        assert read.receipt(turn.key)["state"] == "provider_uncertain"
        assert read.status()["provider_uncertain"] is True
    with DiscussionJournal(policy) as reopened:
        assert reopened.get(turn.key)["state"] == "provider_uncertain"
        assert reopened.status()["tokens_reserved"] == 1024
        with pytest.raises(DiscussionError, match="provider_uncertain"):
            reopened.prepare(fixture_turn("new-key"))


def test_real_hot_rollback_does_not_refund_committed_reservation(tmp_path):
    policy, _, status = initialized(tmp_path)
    with DiscussionJournal(policy) as journal:
        turn = prepared(journal, status)
        journal.reserve(turn.key)
    code = """
import os,sqlite3,sys
db=sqlite3.connect(sys.argv[1],isolation_level=None)
db.execute('PRAGMA cache_size=1')
db.execute('BEGIN IMMEDIATE')
db.execute('UPDATE metadata SET data=? WHERE slot=1', ('x'*300000,))
os._exit(27)
"""
    code_value, stdout, stderr = run_owned_child(
        [sys.executable, "-c", code, str(policy.state / "discussion.sqlite3")],
    )
    assert code_value == 27 and stdout == b"" and stderr == b""
    rollback = policy.state / "discussion.sqlite3-journal"
    assert rollback.exists() and rollback.stat().st_size > 512
    with DiscussionJournal(policy) as reopened:
        assert reopened.get(turn.key)["state"] == "provider_uncertain"
        assert reopened.status()["calls_reserved"] == 1
        assert reopened.status()["tokens_reserved"] == 1024
        assert not rollback.exists()


def test_retained_impossible_per_call_charge_fails_even_with_consistent_hashes(tmp_path):
    policy, _, status = initialized(tmp_path, limits={
        "max_calls": 8, "max_output_tokens": 32, "max_total_output_tokens": 8192,
    })
    with DiscussionJournal(policy) as journal:
        turn = prepared(journal, status)
        value = journal.reserve(turn.key)
    value["reserved_tokens"] = 64
    value["provider_request"]["max_tokens"] = 64
    value["provider_request_hash"] = digest(value["provider_request"])
    db = sqlite3.connect(policy.state / "discussion.sqlite3")
    meta = json.loads(db.execute("SELECT data FROM metadata").fetchone()[0])
    meta["tokens"] = 64
    db.execute("UPDATE metadata SET data=?", (canonical(meta).decode(),))
    db.execute("UPDATE turns SET data=?", (canonical(value).decode(),))
    db.commit()
    db.close()
    with pytest.raises(DiscussionError, match="private_state_invalid"):
        DiscussionJournal(policy)


def test_old_validated_response_can_publish_under_later_provider_hold(tmp_path):
    policy, _, status = initialized(tmp_path)
    with DiscussionJournal(policy) as journal:
        one = prepared(journal, status, fixture_turn("one"))
        journal.reserve(one.key)
        response = journal.provider_result(one.key, {"kind": "message", "content": "Public."})
        two = prepared(journal, status, fixture_turn("two"))
        journal.reserve(two.key)
        journal.provider_failed(two.key, uncertain=True)
    with DiscussionJournal(policy) as reopened:
        assert reopened.status()["provider_uncertain"] is True
        publishing = reopened.begin_publication(one.key, status)
        assert publishing["intent"] == response["intent"]
        ack = fixture_receipt(status, response["intent"])
        reopened.publication_result(one.key, ack)
        assert reopened.receipt(one.key)["receipt"] == ack
        assert reopened.status()["calls_reserved"] == 2
        with pytest.raises(DiscussionError, match="provider_uncertain"):
            reopened.prepare(fixture_turn("three"))


def test_same_boot_wall_rollback_cannot_renew_retained_monotonic_expiry(
    tmp_path, monkeypatch,
):
    policy, _, status = initialized(tmp_path)
    clock = {"wall": time.time(), "monotonic": time.monotonic()}
    monkeypatch.setattr(types.time, "time", lambda: clock["wall"])
    monkeypatch.setattr(types.time, "monotonic", lambda: clock["monotonic"])
    expires_at = clock["wall"] + 20
    waiting = fixture_turn("waiting", expires_at=expires_at)
    responding = fixture_turn("responding", expires_at=expires_at)
    with DiscussionJournal(policy) as journal:
        prepared(journal, status, waiting)
        prepared(journal, status, responding)
        journal.reserve(responding.key)
        journal.provider_result(
            responding.key, {"kind": "message", "content": "Retain this response."},
        )
        originals = {turn.key: journal.get(turn.key) for turn in (waiting, responding)}
        before = journal.status()

    cutoff = originals[waiting.key]["monotonic_cutoff"]
    assert originals[responding.key]["monotonic_cutoff"] == cutoff
    clock["wall"] -= 30
    clock["monotonic"] = cutoff + 1

    # Reopening starts a fresh command-observation budget. The old turn's
    # monotonic cutoff, not the command deadline or rolled-back wall clock,
    # must refuse both provider dispatch and publication.
    with DiscussionJournal(policy) as reopened:
        assert reopened.deadline.remaining() > 0
        assert time.time() < expires_at
        assert types.boot_id() == originals[waiting.key]["boot_id"]
        with pytest.raises(DiscussionError, match="^expired$"):
            reopened.freeze_context(waiting.key, fixture_context(status))
        with pytest.raises(DiscussionError, match="^expired$"):
            reopened.reserve(waiting.key)
        with pytest.raises(DiscussionError, match="^expired$"):
            reopened.begin_publication(responding.key, status)
        for turn in (waiting, responding):
            assert reopened.get(turn.key) == originals[turn.key]
            assert reopened.prepare(turn) == originals[turn.key]
        assert reopened.status() == before

        fresh = prepared(reopened, status, fixture_turn("fresh-after-rollback"))
        assert reopened.get(fresh.key)["context"] == fixture_context(status)
        assert reopened.get(fresh.key)["monotonic_cutoff"] > cutoff
        assert reopened.status()["calls_reserved"] == 1
        assert reopened.status()["tokens_reserved"] == 1024

    with DiscussionJournal(policy, read_only=True) as read:
        assert read.get(waiting.key) == originals[waiting.key]
        assert read.get(responding.key) == originals[responding.key]
        assert read.status()["calls_reserved"] == 1
        assert read.status()["tokens_reserved"] == 1024


def test_post_dispatch_local_results_persist_after_original_expiry(tmp_path, monkeypatch):
    policy, _, status = initialized(tmp_path)
    with DiscussionJournal(policy) as journal:
        turn = prepared(journal, status)
        reserved = journal.reserve(turn.key)
        monkeypatch.setattr(types.time, "time", lambda: reserved["expires_at"] + 1)
        monkeypatch.setattr(types.time, "monotonic", lambda: reserved["monotonic_cutoff"] + 1)
        value = journal.provider_result(turn.key, {"kind": "message", "content": "Retain only."})
        assert value["state"] == "response"
        with pytest.raises(DiscussionError, match="expired"):
            journal.begin_publication(turn.key, status)
        assert journal.receipt(turn.key)["state"] == "response"


def test_signed_ack_after_dispatch_expiry_remains_readable_without_renewal(tmp_path, monkeypatch):
    policy, _, status = initialized(tmp_path)
    with DiscussionJournal(policy) as journal:
        turn = prepared(journal, status)
        journal.reserve(turn.key)
        value = journal.provider_result(turn.key, {"kind": "leave", "content": "Goodbye."})
        journal.begin_publication(turn.key, status)
        ack = fixture_receipt(status, value["intent"])
        monkeypatch.setattr(types.time, "time", lambda: value["expires_at"] + 1)
        monkeypatch.setattr(types.time, "monotonic", lambda: value["monotonic_cutoff"] + 1)
        assert journal.publication_result(turn.key, ack)["state"] == "complete"
    with DiscussionJournal(policy, read_only=True) as reopened:
        assert reopened.receipt(turn.key)["receipt"] == ack


def test_failed_say_reopens_original_intent_and_rejects_forged_ack(tmp_path):
    policy, _, status = initialized(tmp_path)
    with DiscussionJournal(policy) as journal:
        turn = prepared(journal, status)
        journal.reserve(turn.key)
        value = journal.provider_result(turn.key, {"kind": "decline", "content": "Decline."})
        journal.begin_publication(turn.key, status)
    with DiscussionJournal(policy) as reopened:
        assert reopened.get(turn.key)["state"] == "publication_uncertain"
        assert reopened.begin_publication(turn.key, status)["intent"] == value["intent"]
        forged = fixture_receipt(status, value["intent"])
        forged["record"]["signature"] = "0" * 128
        with pytest.raises(DiscussionError, match="invalid_receipt"):
            reopened.publication_result(turn.key, forged)
        assert reopened.get(turn.key)["receipt"] is None
        ack = fixture_receipt(status, value["intent"])
        reopened.publication_result(turn.key, ack)
    with DiscussionJournal(policy) as replay:
        assert replay.receipt(turn.key)["receipt"] == ack
        assert replay.status()["calls_reserved"] == 1


def test_unicode_output_that_cannot_fit_signed_record_is_charged_terminal(tmp_path):
    policy, _, status = initialized(tmp_path)
    content = "\u0800" * 2700
    assert len(content.encode("utf-8")) <= 8192
    with DiscussionJournal(policy) as journal:
        turn = prepared(journal, status)
        journal.reserve(turn.key)
        result = journal.provider_result(turn.key, {"kind": "message", "content": content})
        assert result["state"] == "rejected"
        assert result["response"] is None and result["intent"] is None
        assert journal.status()["calls_reserved"] == 1
        assert journal.prepare(turn) == result
        with pytest.raises(DiscussionError, match="state_conflict"):
            journal.begin_publication(turn.key, status)
    with DiscussionJournal(policy) as replay:
        assert replay.receipt(turn.key)["state"] == "rejected"
        assert replay.status()["tokens_reserved"] == 1024


@pytest.mark.parametrize("field", ["expires_at", "request_timeout_seconds"])
def test_bounded_json_huge_integer_returns_fixed_error(tmp_path, field):
    policy, _, _ = fixture_policy(tmp_path)
    huge = 10 ** 400
    if field == "expires_at":
        raw = canonical(dict(fixture_turn().document, expires_at=huge))
        assert len(raw) < 65536
        with pytest.raises(DiscussionError, match="invalid_turn"):
            Turn.parse(raw)
    else:
        document = deepcopy(policy.document)
        document["provider"][field] = huge
        private_json(policy.path, document)
        with pytest.raises(DiscussionError, match="invalid_policy"):
            Policy.load(policy.path)


def test_private_fifo_rejection_returns_without_open_block(tmp_path):
    fifo = tmp_path / "fifo"
    os.mkfifo(fifo, 0o600)
    code = """
import sys
from src.worker.discussion_types import DiscussionError,read_private_bytes
try: read_private_bytes(sys.argv[1])
except DiscussionError as error:
    assert str(error)=='invalid_policy'; sys.exit(0)
raise SystemExit(3)
"""
    child = subprocess.Popen(
        [sys.executable, "-c", code, str(fifo)],
        cwd=Path(__file__).resolve().parents[2], stdout=subprocess.PIPE, stderr=subprocess.PIPE,
    )
    try:
        stdout, stderr = child.communicate(timeout=3)
    finally:
        if child.poll() is None:
            child.kill()
            child.wait(timeout=3)
    assert child.returncode == 0 and stdout == b"" and stderr == b""


def test_original_managed_http_caller_keeps_body_headers_and_error_classes(monkeypatch):
    requests = []
    scenario = {"kind": "ok"}
    tool = {
        "id": "call_fixture", "type": "function",
        "function": {"name": TOOL_DEFINITIONS[0]["function"]["name"], "arguments": "{}"},
    }
    normal = {"choices": [{"message": {
        "role": "assistant", "content": "Original managed response.", "tool_calls": [tool],
    }}]}

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_POST(self):
            body = self.rfile.read(int(self.headers["Content-Length"]))
            requests.append((self.path, dict(self.headers), json.loads(body)))
            kind = scenario["kind"]
            if kind == "disconnect":
                self.connection.shutdown(2)
                self.connection.close()
                return
            status = 302 if kind == "redirect" else 503 if kind == "status" else 200
            raw = b'{"choices":[],"choices":[]}' if kind == "duplicate" else canonical(normal)
            if kind == "size":
                raw = b"x" * 2048
            self.send_response(status)
            if kind == "redirect":
                self.send_header("Location", "/should-not-follow")
            if kind == "encoding":
                self.send_header("Content-Encoding", "gzip")
            self.send_header("Content-Length", str(len(raw)))
            self.end_headers()
            self.wfile.write(raw)

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    owner = threading.Thread(target=server.serve_forever, daemon=True)
    owner.start()
    monkeypatch.setenv("DISCUSSION_FIXTURE_TOKEN", "private-managed-fixture-token")
    monkeypatch.setenv("HTTP_PROXY", "http://127.0.0.1:1")
    policy = ModelPolicy(
        endpoint=f"http://127.0.0.1:{server.server_port}/v1/chat/completions",
        model="fixture/model", token_ref="env:DISCUSSION_FIXTURE_TOKEN",
        max_response_bytes=1024, request_timeout_seconds=2,
    )
    messages = [{"role": "user", "content": "Keep the original managed contract."}]
    try:
        result = asyncio.run(ModelBroker._forward(
            None, policy, messages, 17, time.monotonic() + 3,
        ))
        assert result == normal["choices"][0]["message"]
        path, headers, body = requests[0]
        assert path == "/v1/chat/completions"
        assert headers["Authorization"] == "Bearer private-managed-fixture-token"
        assert headers["Accept-Encoding"] == "identity"
        assert body == {
            "model": "fixture/model", "messages": messages,
            "tools": TOOL_DEFINITIONS, "tool_choice": "auto",
            "stream": False, "max_tokens": 17,
        }
        for kind, expected in [
            ("status", "provider_unavailable"), ("encoding", "provider_unavailable"),
            ("size", "provider_unavailable"), ("redirect", "provider_unavailable"),
            ("disconnect", "uncertain"), ("duplicate", "uncertain"),
        ]:
            scenario["kind"] = kind
            before = len(requests)
            with pytest.raises(BrokerDenied, match=expected):
                asyncio.run(ModelBroker._forward(
                    None, policy, messages, 17, time.monotonic() + 3,
                ))
            assert len(requests) == before + 1
    finally:
        server.shutdown()
        server.server_close()
        owner.join(timeout=3)
        assert not owner.is_alive()
