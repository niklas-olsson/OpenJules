"""Observer truthfulness and preservation tests, not runtime qualification."""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
from types import SimpleNamespace

import pytest

from tools import managed_cost_measurement as measured


def test_nested_spans_are_inclusive_and_preserve_exception_identity(tmp_path):
    recorder = measured.Recorder(tmp_path)
    failure = RuntimeError("PRIVATE_EXCEPTION_CONTENT")
    with pytest.raises(RuntimeError) as caught:
        with recorder.phase("case.total"):
            with recorder.phase("runtime.execute"):
                raise failure
    assert caught.value is failure
    report = recorder.report()
    outer, inner = report["spans"]
    assert outer["parent_id"] is None and inner["parent_id"] == outer["id"]
    assert outer["start_ns"] <= inner["start_ns"]
    assert outer["wall_ns"] >= inner["wall_ns"] >= 0
    assert all(row["outcome"] == "raised" and row["exception_type"] == "RuntimeError" for row in report["spans"])
    assert "PRIVATE_EXCEPTION_CONTENT" not in json.dumps(report)
    assert str(tmp_path) not in json.dumps(report)
    assert report["complete"] is True


def test_closed_labels_and_bounded_immutable_facts(tmp_path):
    recorder = measured.Recorder(tmp_path)
    for operation in (
        lambda: recorder.add("private-name", 1),
        lambda: recorder.fact("private-name", "value"),
        lambda: recorder.add("http.requests", True),
        lambda: recorder.observe_body("private-name", 1),
        lambda: recorder.fact("fixture", {"number": float("nan")}),
        lambda: recorder.fact("fixture", object()),
    ):
        with pytest.raises(ValueError):
            operation()
    with pytest.raises(ValueError):
        with recorder.phase("/private/path"):
            raise AssertionError("must not enter")
    value = {"files": [1, 2], "sha256": "a" * 64}
    recorder.fact("fixture", value)
    value["files"].append(3)
    recorder.fact("fixture", {"files": [1, 2], "sha256": "a" * 64})
    with pytest.raises(ValueError, match="changed"):
        recorder.fact("fixture", {"files": [3]})
    assert recorder.report()["facts"]["fixture"]["files"] == [1, 2]
    recorder.fact("control", {"count": 1})
    with pytest.raises(ValueError, match="changed"):
        recorder.fact("control", {"count": True})


def test_disabled_control_installs_no_hooks_but_keeps_explicit_oracles(tmp_path, monkeypatch):
    recorder = measured.Recorder(tmp_path, enabled=False)
    originals = os.fsync, subprocess.Popen.__init__
    recorder.install(monkeypatch)
    assert (os.fsync, subprocess.Popen.__init__) == originals
    with recorder.phase("case.total"):
        recorder.add("docker.created")
        recorder.observe_body("request", 7)
        recorder.fact("correctness", {"verified": True})
    report = recorder.report()
    assert not report["enabled"] and report["spans"] == []
    assert report["counters"]["docker.created"] == 1
    assert report["counters"]["http.request_bytes"] == 7
    assert report["facts"]["correctness"] == {"verified": True}
    assert report["fixture_impairment_declaration"]["applied_by_recorder"] is False


def test_paired_controls_prepare_identical_production_imports_in_fresh_processes(tmp_path):
    script = """
import json
import os
import subprocess
import sys
import pytest
from tools.managed_cost_measurement import Recorder
originals = os.fsync, subprocess.Popen.__init__
with pytest.MonkeyPatch.context() as patch:
    Recorder(sys.argv[1], enabled=sys.argv[2] == "enabled").install(patch)
    if sys.argv[2] == "disabled":
        assert (os.fsync, subprocess.Popen.__init__) == originals
    print(json.dumps(sorted(name for name in sys.modules if name.startswith("src."))))
"""
    loaded = []
    for mode in ("disabled", "enabled"):
        result = subprocess.run([sys.executable, "-c", script, str(tmp_path), mode],
                                capture_output=True, text=True, check=True, timeout=20)
        loaded.append(json.loads(result.stdout))
    assert loaded[0] == loaded[1]
    assert {"src.worker.managed_dispatch", "src.worker.child_runtime"} <= set(loaded[0])


def test_real_subprocess_fsync_and_restoration_keep_bytes_and_private_arguments(tmp_path):
    recorder = measured.Recorder(tmp_path)
    original_fsync, original_init = os.fsync, subprocess.Popen.__init__
    with pytest.MonkeyPatch.context() as patch:
        recorder.install(patch)
        with (tmp_path / "data").open("wb") as stream:
            stream.write(b"retained fixture bytes")
            stream.flush()
            os.fsync(stream.fileno())
        completed = subprocess.run(
            [sys.executable, "-I", "-c", "print('PRIVATE_SUBPROCESS_OUTPUT')"],
            capture_output=True, check=True, text=True,
        )
        assert completed.stdout == "PRIVATE_SUBPROCESS_OUTPUT\n"
        with pytest.raises(FileNotFoundError):
            subprocess.run([str(tmp_path / "PRIVATE_MISSING_EXECUTABLE")], check=True)
    assert os.fsync is original_fsync and subprocess.Popen.__init__ is original_init
    report = recorder.report()
    assert (tmp_path / "data").read_bytes() == b"retained fixture bytes"
    assert report["counters"]["fsync.calls"] == 1
    assert report["counters"]["subprocess.started.python"] == 1
    assert sum(value for name, value in report["counters"].items() if name.startswith("subprocess.started.")) == 1
    assert "PRIVATE_" not in json.dumps(report)


def test_capture_observation_never_opens_archive_and_does_not_replace_result(tmp_path):
    recorder = measured.Recorder(tmp_path)
    receipt = SimpleNamespace(
        artifacts_captured=True, capture_path="/private/nonexistent.tar",
        capture_sha256="a" * 64,
        manifest=json.dumps({"archive_bytes": 4096, "archive_sha256": "a" * 64, "private": "DO_NOT_COPY"}),
    )
    wrapped = recorder._wrap(lambda: receipt, "runtime.capture")
    assert wrapped() is receipt
    assert recorder.report()["captures"] == [{"kind": "root", "archive_bytes": 4096, "archive_sha256": "a" * 64}]
    assert "DO_NOT_COPY" not in json.dumps(recorder.report())
    receipt.manifest = "invalid private data"
    assert wrapped() is receipt
    assert recorder.report()["complete"] is False
    assert recorder.report()["problems"] == ["capture_projection_unavailable"]


def test_span_limit_preserves_effect_and_marks_incomplete(tmp_path, monkeypatch):
    recorder = measured.Recorder(tmp_path)
    monkeypatch.setattr(measured, "MAX_SPANS", 1)
    calls = []
    wrapped = recorder._wrap(lambda: calls.append(1), "runtime.execute")
    wrapped()
    wrapped()
    assert calls == [1, 1]
    report = recorder.report()
    assert len(report["spans"]) == 1
    assert not report["complete"] and report["problems"] == ["span_limit"]


def test_async_failure_and_unknown_exception_name_remain_original(tmp_path):
    recorder = measured.Recorder(tmp_path)
    private_type = type("PRIVATE_EXCEPTION_TYPE", (Exception,), {})
    failure = private_type("private message")

    async def operation():
        await asyncio.sleep(0)
        raise failure

    with pytest.raises(private_type) as caught:
        asyncio.run(recorder._wrap(operation, "forge.request")())
    assert caught.value is failure
    report = recorder.report()
    assert report["spans"][0]["exception_type"] == "OtherException"
    assert "PRIVATE_EXCEPTION_TYPE" not in json.dumps(report)


def test_body_counts_are_explicit_and_do_not_claim_requests_per_chunk(tmp_path):
    recorder = measured.Recorder(tmp_path)
    recorder.add("http.requests")
    recorder.observe_body("request", 2)
    recorder.observe_body("request", 3)
    recorder.observe_body("response", 4)
    report = recorder.report()
    assert report["counters"]["http.requests"] == 1
    assert report["counters"]["http.request_bytes"] == 5
    assert report["counters"]["http.response_bytes"] == 4


def test_active_report_is_not_complete_and_executable_names_are_categorized(tmp_path):
    recorder = measured.Recorder(tmp_path)
    with recorder.phase("case.total"):
        assert recorder.report()["problems"] == ["active_spans"]
    assert recorder.report()["complete"]
    assert measured._executable((["/private/bin/git", "private-arg"],), {}) == "git"
    assert measured._executable((["git"],), {"shell": True}) == "other"
    assert measured._executable(([Path("/private/bin/python3.12")],), {}) == "python"
    assert measured._executable(("PRIVATE_COMMAND",), {}) == "other"


def test_actual_snapshot_export_and_reuse_keep_exact_objects_with_hooks(tmp_path):
    from src.worker.source_snapshot import SourceSnapshots

    source = tmp_path / "source"
    source.mkdir()
    (source / "fixture.txt").write_text("PRIVATE_FIXTURE_CONTENT\n")

    def git(path, *args):
        return subprocess.check_output(
            ["git", "-C", str(path), "-c", "user.name=Fixture", "-c",
             "user.email=fixture@example.invalid", *args],
            stderr=subprocess.DEVNULL, timeout=10,
        )

    git(source, "init", "-q")
    git(source, "add", ".")
    git(source, "commit", "-qm", "fixture")
    base = git(source, "rev-parse", "HEAD").decode().strip()
    objects = []
    for enabled in (False, True):
        recorder = measured.Recorder(tmp_path, enabled=enabled)
        cache = SourceSnapshots(tmp_path / str(enabled))
        with pytest.MonkeyPatch.context() as patch:
            recorder.install(patch)
            first = cache.prepare(str(source), base, 1048576)
            assert cache.prepare(str(source), base, 1048576) == first
        objects.append(git(first, "cat-file", "--batch-all-objects", "--batch-check"))
        report = recorder.report()
        if enabled:
            assert [row["phase"] for row in report["spans"]].count("source.prepare") == 2
            assert [row["phase"] for row in report["spans"]].count("source.export") == 1
            assert report["counters"]["subprocess.started.git"] > 0
        assert report["complete"] and "PRIVATE_FIXTURE_CONTENT" not in json.dumps(report)
    assert objects[0] == objects[1]
