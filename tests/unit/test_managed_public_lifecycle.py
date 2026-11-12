"""Real owned stdio lifetimes with a named local durability observer.

The MCP server is the existing explicit fixture, not installed Polyphony A.
SQLite event rows prove callback ordering and rollback/error boundaries; they
do not stand in for the later managed-worker ownership and capture integration.
"""

import asyncio
from contextlib import closing
from copy import deepcopy
import json
import os
from pathlib import Path
import signal
import sqlite3

import pytest

from src.polyphony import conversation_client as transport
from src.worker.discussion_types import (
    CHILD_ENVIRONMENT, Deadline, DiscussionError, boot_id, canonical,
)
from tests.unit.test_conversation_client import install_fixture, short_deadline
from tests.unit.test_discussion_journal import fixture_policy


class RecordingObserver(transport.ProcessLifecycleObserver):
    def __init__(self, path, *, fault=None):
        self.path = path
        self.fault = fault
        with closing(sqlite3.connect(path)) as db:
            db.execute("CREATE TABLE events (position INTEGER PRIMARY KEY, data TEXT NOT NULL)")
            db.commit()
        path.chmod(0o600)

    def events(self):
        with closing(sqlite3.connect(self.path)) as db:
            return [json.loads(row[0]) for row in db.execute("SELECT data FROM events ORDER BY position")]

    def write(self, event):
        with closing(sqlite3.connect(self.path)) as db:
            db.execute("INSERT INTO events(data) VALUES (?)", (canonical(event).decode(),))
            db.commit()

    def fail(self, operation, stage):
        if self.fault == (operation, stage):
            raise RuntimeError("private-lifecycle-diagnostic-canary")

    def before_start(self, stage, argv, cwd, environment, deadline):
        assert isinstance(argv, tuple)
        assert environment == CHILD_ENVIRONMENT
        assert deadline.remaining() > 0
        ticket = stage + ":" + str(len(self.events()))
        self.write({
            "event": "before", "ticket": ticket, "stage": stage,
            "argv": list(argv), "cwd": cwd, "environment": deepcopy(environment),
            "expires_at": deadline.expires_at, "monotonic_cutoff": deadline.monotonic_cutoff,
        })
        self.fail("before", stage)
        # The observer cannot change the actual child's exact environment.
        environment["OBSERVER_CANNOT_INJECT"] = "private-observer-canary"
        return ticket

    def started(self, ticket, identity):
        before = next(row for row in self.events() if row["ticket"] == ticket)
        raw = Path("/proc/" + str(identity["pid"]) + "/stat").read_bytes()
        values = raw.rsplit(b")", 1)[1].split()
        assert identity["starttime"] == int(values[19])
        assert identity["pgid"] == int(values[2]) == identity["pid"]
        assert identity["boot_id"] == boot_id()
        self.write({
            "event": "started", "ticket": ticket, "stage": before["stage"],
            "identity": deepcopy(identity),
        })
        self.fail("started", before["stage"])
        # started receives only a copy, not the owner's retained identity.
        identity["starttime"] = 0

    def finished(self, ticket, identity, confirmed):
        rows = [row for row in self.events() if row["ticket"] == ticket]
        before = rows[0]
        started = next((row for row in rows if row["event"] == "started"), None)
        if started is not None:
            assert identity == started["identity"]
        if confirmed:
            assert identity is not None
            with pytest.raises(ChildProcessError):
                os.waitpid(identity["pid"], os.WNOHANG)
        self.write({
            "event": "finished", "ticket": ticket, "stage": before["stage"],
            "identity": deepcopy(identity), "confirmed": confirmed,
        })
        self.fail("finished", before["stage"])


def dispatch_spy(monkeypatch, observer):
    original = transport.subprocess.Popen
    calls = []

    def popen(argv, *args, **kwargs):
        # An independent SQLite connection observes a committed intent BEFORE
        # the only actual Popen, without manufacturing an owner or fake process.
        rows = observer.events()
        assert rows[-1]["event"] == "before"
        assert rows[-1]["argv"] == list(argv)
        assert rows[-1]["cwd"] == kwargs["cwd"]
        assert rows[-1]["environment"] == kwargs["env"] == CHILD_ENVIRONMENT
        assert kwargs["start_new_session"] is True
        calls.append(rows[-1]["ticket"])
        return original(argv, *args, **kwargs)

    monkeypatch.setattr(transport.subprocess, "Popen", popen)
    return calls


def test_real_sdk_retains_intent_and_owned_identity_before_exposure_and_cleanup(tmp_path, monkeypatch):
    policy, _, status = fixture_policy(tmp_path)
    install_fixture(policy)
    observer = RecordingObserver(tmp_path / "owner.sqlite3")
    calls = dispatch_spy(monkeypatch, observer)
    cleanup = transport.CleanupObserver()

    async def run():
        async with transport.connect(
            policy.launch, Deadline.observe(), expected_status=status,
            cleanup=cleanup, lifecycle=observer,
        ) as client:
            assert client.status == status
            rows = observer.events()
            assert [(row["stage"], row["event"]) for row in rows] == [
                ("probe", "before"), ("probe", "started"), ("probe", "finished"),
                ("server", "before"), ("server", "started"),
            ]
            assert rows[2]["confirmed"] is True
            assert cleanup.result.active_processes == 1
            assert await client.check_status(status) == status

    asyncio.run(run())
    rows = observer.events()
    assert len(calls) == 2 and len(set(calls)) == 2
    assert [(row["stage"], row["event"]) for row in rows][-1] == ("server", "finished")
    assert all(row["confirmed"] for row in rows if row["event"] == "finished")
    assert cleanup.result.confirmed and cleanup.result.cleaned_processes == 2
    state = Path(policy.a_config["state_directory"])
    assert json.loads((state / "environment.json").read_bytes()) == CHILD_ENVIRONMENT


@pytest.mark.parametrize("fault", ["before", "started", "finished"])
def test_observer_failure_never_exposes_client_or_skips_owned_cleanup(tmp_path, monkeypatch, fault):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy)
    observer = RecordingObserver(tmp_path / "owner.sqlite3", fault=(fault, "probe"))
    calls = dispatch_spy(monkeypatch, observer)
    cleanup = transport.CleanupObserver()

    async def run():
        async with transport.connect(
            policy.launch, Deadline.observe(), cleanup=cleanup, lifecycle=observer,
        ):
            pytest.fail("failed durability hook exposed a client")

    with pytest.raises(DiscussionError, match="^state_conflict$"):
        asyncio.run(run())
    rows = observer.events()
    assert cleanup.result.attempted_processes == 1
    assert cleanup.result.active_processes == 0
    if fault == "before":
        assert calls == []
        assert [row["event"] for row in rows] == ["before"]
        assert cleanup.result.failed and not cleanup.result.confirmed
    else:
        assert len(calls) == 1
        assert [row["event"] for row in rows] == ["before", "started", "finished"]
        assert rows[-1]["confirmed"] is True
        assert cleanup.result.confirmed and cleanup.result.cleaned_processes == 1


@pytest.mark.parametrize("interruption", ["application", "cancel"])
def test_original_body_error_or_cancellation_survives_cleanup_acknowledgement_failure(tmp_path, interruption):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy)
    observer = RecordingObserver(tmp_path / "owner.sqlite3", fault=("finished", "server"))
    cleanup = transport.CleanupObserver()

    async def run():
        async with transport.connect(
            policy.launch, Deadline.observe(), cleanup=cleanup, lifecycle=observer,
        ):
            if interruption == "application":
                raise DiscussionError("invalid_context")
            asyncio.current_task().cancel()
            await asyncio.sleep(0)

    if interruption == "application":
        with pytest.raises(DiscussionError, match="^invalid_context$"):
            asyncio.run(run())
    else:
        with pytest.raises(asyncio.CancelledError):
            asyncio.run(run())
    rows = observer.events()
    assert rows[-1]["stage"] == "server" and rows[-1]["event"] == "finished"
    assert rows[-1]["confirmed"] is True
    assert cleanup.result.confirmed and cleanup.result.cleaned_processes == 2


def test_lifecycle_identity_survives_leader_exit_with_inherited_pipe(tmp_path):
    policy, _, _ = fixture_policy(tmp_path)
    install_fixture(policy, mode="leader_exit_pipe")
    server_path = Path(policy.server["cwd"]) / "src" / "liminal_bridge" / "conversation_server.py"
    source = server_path.read_text(encoding="utf-8")
    previous = "    private(state/'descendant.json',{'pid':child.pid,'group':os.getpgrp()})\n"
    replacement = (
        "    tail=pathlib.Path('/proc/'+str(child.pid)+'/stat').read_bytes().rsplit(b')',1)[1].split()\n"
        "    private(state/'descendant.json',{'pid':child.pid,'group':os.getpgrp(),"
        "'starttime':int(tail[19])})\n"
    )
    assert source.count(previous) == 1
    # Only this installed named fixture records the descendant before its
    # leader exits. The shared fixture and production transport stay unchanged.
    server_path.write_text(source.replace(previous, replacement), encoding="utf-8")
    observer = RecordingObserver(tmp_path / "owner.sqlite3")
    cleanup = transport.CleanupObserver()
    state = Path(policy.a_config["state_directory"])

    async def run():
        async with transport.connect(
            policy.launch, short_deadline(), cleanup=cleanup, lifecycle=observer,
        ):
            pytest.fail("exited profile leader exposed a client")

    with pytest.raises(DiscussionError):
        asyncio.run(run())
    leader = json.loads((state / "leader.json").read_bytes())
    child = json.loads((state / "descendant.json").read_bytes())
    def original_descendant_state():
        try:
            with open("/proc/" + str(child["pid"]) + "/stat", "rb") as handle:
                raw = handle.read(4097)
        except FileNotFoundError:
            return None
        assert len(raw) <= 4096
        values = raw.rsplit(b")", 1)[1].split()
        if int(values[19]) != child["starttime"] or int(values[2]) != child["group"]:
            return None
        return values[0]

    try:
        server = [row for row in observer.events() if row["stage"] == "server"]
        assert server[-1]["event"] == "finished" and server[-1]["confirmed"] is True
        assert server[-1]["identity"] == server[1]["identity"]
        assert server[-1]["identity"]["pid"] == leader["pid"] == child["group"]
        assert cleanup.result.confirmed and cleanup.result.cleaned_processes == 2
        assert original_descendant_state() in {None, b"Z", b"X"}
    finally:
        # A pidfd plus a second starttime/group check cannot signal a reused
        # numeric PID if a future regression leaves this fixture child alive.
        if original_descendant_state() not in {None, b"Z", b"X"}:
            try:
                descriptor = os.pidfd_open(child["pid"])
            except ProcessLookupError:
                descriptor = None
            if descriptor is not None:
                try:
                    if original_descendant_state() not in {None, b"Z", b"X"}:
                        signal.pidfd_send_signal(descriptor, signal.SIGKILL)
                finally:
                    os.close(descriptor)


def test_omitted_observer_does_not_add_process_identity_reads_or_change_cleanup(tmp_path, monkeypatch):
    policy, _, status = fixture_policy(tmp_path)
    install_fixture(policy)
    cleanup = transport.CleanupObserver()

    def unused(self):
        raise AssertionError("omitted lifecycle observer inspected process identity")

    monkeypatch.setattr(transport._OwnedProcess, "identity", unused)

    async def run():
        async with transport.connect(policy.launch, Deadline.observe(), cleanup=cleanup) as client:
            assert client.status == status

    asyncio.run(run())
    assert cleanup.result.confirmed and cleanup.result.cleaned_processes == 2
