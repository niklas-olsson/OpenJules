"""The prerequisite supervisor owns descendants across process sessions."""

import json
import os
from pathlib import Path
import subprocess
import sys
import time
from types import SimpleNamespace

import pytest

from tools.managed_cost_setup import alive_identity, discover_descendants, stop_owned
from tools.managed_costs import proc_stat


def test_cleanup_tracks_and_stops_a_real_child_in_a_new_session(tmp_path):
    identity_file = tmp_path / "child.json"
    script = (
        "import json,pathlib,subprocess,sys,time; "
        "child=subprocess.Popen([sys.executable,'-c','import time; time.sleep(30)'],start_new_session=True); "
        f"pathlib.Path({str(identity_file)!r}).write_text(json.dumps({{'pid':child.pid}})); "
        "time.sleep(30)"
    )
    process = subprocess.Popen([sys.executable, "-c", script], start_new_session=True)
    start = proc_stat(process.pid)["start_ticks"]
    known = {process.pid: start}
    try:
        cutoff = time.monotonic() + 5
        while not identity_file.exists() and time.monotonic() < cutoff:
            time.sleep(0.02)
        child = json.loads(identity_file.read_text())["pid"]
        child_start = proc_stat(child)["start_ticks"]
        assert os.getsid(child) == child and os.getsid(process.pid) == process.pid
        discover_descendants(process.pid, start, known)
        assert known[child] == child_start
        assert stop_owned(process.pid, start, known) == 0
        process.wait(timeout=5)
        assert not alive_identity(process.pid, start)
        assert not alive_identity(child, child_start)
        assert alive_identity(os.getpid(), proc_stat(os.getpid())["start_ticks"])
    finally:
        stop_owned(process.pid, start, known)
        process.wait(timeout=5)


def test_pid_reuse_guard_does_not_signal_a_different_incarnation(monkeypatch):
    import tools.managed_cost_setup as setup
    signaled = []
    monkeypatch.setattr(setup, "proc_stat", lambda pid: {"start_ticks": 999, "state": "S"})
    monkeypatch.setattr(setup.os, "kill", lambda pid, signal: signaled.append((pid, signal)))
    monkeypatch.setattr(setup, "discover_descendants", lambda *_: None)
    assert stop_owned(10001, 123, {10001: 123}) == 0
    assert signaled == []


@pytest.mark.parametrize("fail_metadata", [False, True])
def test_resolved_base_is_used_by_both_builds_and_metadata_failure_is_not_complete(tmp_path, monkeypatch, fail_metadata):
    import tools.managed_cost_setup as setup
    commands = []
    selected = "python@sha256:" + "a" * 64

    class Done:
        pid = os.getpid()
        returncode = 0

        def __init__(self, command, **kwargs):
            commands.append(command)
            if "--iidfile" in command:
                Path(command[command.index("--iidfile") + 1]).write_text("sha256:" + "b" * 64)

        def poll(self):
            return 0

    def metadata(command, **kwargs):
        if command[1] == "info":
            if fail_metadata:
                raise RuntimeError("PRIVATE_DIAGNOSTIC_MUST_NOT_ESCAPE")
            return b'{"ServerVersion":"fixture"}'
        return json.dumps([{"Id": "sha256:" + "b" * 64, "RepoDigests": [selected],
                            "Architecture": "amd64", "Os": "linux", "Size": 4096}]).encode()

    monkeypatch.setattr(setup.subprocess, "Popen", Done)
    monkeypatch.setattr(setup.subprocess, "check_output", metadata)
    monkeypatch.setattr(setup.importlib.metadata, "distributions", lambda: [])
    output = tmp_path / "setup"
    result = setup.run(SimpleNamespace(work_dir=output, zpm_checkout=tmp_path, polyphony_checkout=tmp_path))
    report = json.loads((output / "report.json").read_text())
    assert report["complete"] is (not fail_metadata)
    assert result == (1 if fail_metadata else 0)
    builds = [command for command in commands if command[:2] == ["docker", "build"]]
    assert len(builds) == 2
    assert all(command[command.index("--build-arg") + 1] == "PYTHON_BASE=" + selected for command in builds)
    assert report["resolved_ci_base_image"]["selected_build_reference"] == selected
    assert "PRIVATE_DIAGNOSTIC_MUST_NOT_ESCAPE" not in json.dumps(report)
