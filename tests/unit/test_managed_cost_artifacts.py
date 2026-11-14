"""Real Git/local HTTP checks for the finite, synthetic artifact lanes."""

import asyncio
from contextlib import contextmanager
import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import io
import json
from pathlib import Path
import tarfile
import threading
from types import SimpleNamespace

import httpx
import pytest

from src.worker.docker_runtime import ExecutionReceipt
from tools.managed_cost_artifacts import (
    BODY_RATE, LocalMeasuredTransport, _payload, _verify_archive, run_case,
)


class Recorder:
    """Enforce the measurement collaborator's closed counter/fact interface."""

    def __init__(self):
        self.counts = {"http.requests": 0, "http.request_bytes": 0, "http.response_bytes": 0}
        self.facts, self.phases = {}, []

    @contextmanager
    def phase(self, name):
        self.phases.append(name)
        yield

    def add(self, name, value=1):
        assert name in self.counts and type(value) is int and value >= 0
        self.counts[name] += value

    def fact(self, name, value):
        assert name in {"source", "artifacts", "publication"} and name not in self.facts
        self.facts[name] = json.loads(json.dumps(value))


def publication(blobs=1, lost=False):
    return {"kind": "publication", "params": {
        "blobs": blobs, "total_bytes": 32768, "delay_ms": 0,
        "body_bytes_per_second": BODY_RATE, "lose_draft_reply": lost,
    }}


def test_source_cold_and_admitted_reuse_keep_exact_deterministic_export(tmp_path, monkeypatch):
    case = {"kind": "source", "params": {"source_bytes": 4194304, "file_count": 64}}
    first_recorder, second_recorder = Recorder(), Recorder()
    first = run_case(case, tmp_path / "first", first_recorder, {}, monkeypatch)
    second = run_case(case, tmp_path / "second", second_recorder, {}, monkeypatch)
    assert first == second
    assert first["object_bytes"] > 4194304 and first["objects"] == 66
    assert first["same_instance_admitted_reuse"] is True
    assert first_recorder.phases == ["setup", "source.cold", "source.reuse"]
    assert "rehash" in first["reuse_scope"]
    assert first_recorder.counts["http.requests"] == 0


@pytest.mark.parametrize("blobs,lost", [(1, False), (32, False), (1, True)])
def test_actual_http_git_preserves_original_publication_without_duplicate_post(tmp_path, monkeypatch, blobs, lost):
    recorder = Recorder()
    result = run_case(publication(blobs, lost), tmp_path, recorder, {}, monkeypatch)
    assert result["blobs"] == blobs and result["changed_blob_bytes"] == 32768
    assert result["final_children"] == (1 if blobs == 1 else 2)
    assert result["draft_posts"] == 1 and result["replay_created_effects"] == 0
    assert result["original_operation_recovered"] is True
    assert result["lost_draft_reply"] is lost
    assert recorder.counts["http.requests"] > blobs
    assert recorder.counts["http.request_bytes"] > 32768
    assert recorder.counts["http.response_bytes"] > 32768
    encoded = json.dumps(result)
    assert "fixture-authority-" not in encoded and "fixture-forge-" not in encoded
    assert str(tmp_path) not in encoded and "Authorization" not in encoded
    assert "not isolated blob-count causality" in result["topology_comparison"]
    if lost:
        assert "publication.reconciliation" in recorder.phases


def test_publication_fixture_repeats_identical_candidate_commit_and_tree(tmp_path, monkeypatch):
    first = run_case(publication(), tmp_path / "one", Recorder(), {}, monkeypatch)
    second = run_case(publication(), tmp_path / "two", Recorder(), {}, monkeypatch)
    for key in ("candidate_sha256", "operation_sha256", "commit_sha", "tree_sha"):
        assert first[key] == second[key]


def test_http_counts_exact_utf8_body_bytes_and_rejects_other_origins(monkeypatch):
    request_body = '{ "message" : "\u00e5", "n": 2 }'.encode()
    response_body = b'{ "ok" : true }\n'
    received, sleeps = [], []

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            received.append(self.rfile.read(int(self.headers["Content-Length"])))
            self.send_response(200)
            self.send_header("Content-Length", str(len(response_body)))
            self.end_headers()
            self.wfile.write(response_body)

        def log_message(self, *_):
            pass

    async def observed_sleep(seconds):
        sleeps.append(seconds)

    monkeypatch.setattr(asyncio, "sleep", observed_sleep)
    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    recorder = Recorder()
    fixture = SimpleNamespace(endpoint=f"http://127.0.0.1:{server.server_port}")
    transport = LocalMeasuredTransport(fixture, recorder, delay_ms=20, body_bytes_per_second=BODY_RATE)

    async def request():
        async with httpx.AsyncClient(transport=transport, trust_env=False) as client:
            response = await client.post("https://api.github.com/repos/owner/project/test", content=request_body)
            assert response.content == response_body
            with pytest.raises(RuntimeError, match="fixture_http_origin_rejected"):
                await client.get("https://other.example.invalid/")

    try:
        asyncio.run(request())
    finally:
        server.shutdown()
        server.server_close()
        thread.join(3)
    assert received == [request_body]
    assert recorder.counts == {"http.requests": 1, "http.request_bytes": len(request_body),
                               "http.response_bytes": len(response_body)}
    assert sleeps == [.02, len(request_body) / BODY_RATE, len(response_body) / BODY_RATE]


def capture_receipt(tmp_path, *, corrupt=False):
    params = {"target_archive_bytes": 262144, "payload_bytes": 131072, "file_count": 1}
    output = io.BytesIO()
    body = _payload(0, params["payload_bytes"])
    if corrupt:
        body = b"!" + body[1:]
    with tarfile.open(fileobj=output, mode="w") as archive:
        info = tarfile.TarInfo("workspace/run/repo/fixture-payload/payload-0000.bin")
        info.size = len(body)
        archive.addfile(info, io.BytesIO(body))
    content = output.getvalue()
    target = tmp_path / "capture.tar"
    target.write_bytes(content)
    digest = hashlib.sha256(content).hexdigest()
    receipt = ExecutionReceipt("completed", True, True, True, str(target), digest, 0,
                               "+captured fixture change\n", "fixture\n",
                               json.dumps({"archive_bytes": len(content), "archive_sha256": digest}))
    return receipt, params


def test_archive_independently_checks_actual_sizes_hashes_and_ignored_payload(tmp_path, monkeypatch):
    def no_extract(*args, **kwargs):
        raise AssertionError("archives must not be extracted")

    monkeypatch.setattr(tarfile.TarFile, "extractall", no_extract)
    receipt, params = capture_receipt(tmp_path)
    facts = _verify_archive(receipt, params)
    assert facts["payload_bytes"] == 131072 and facts["payload_files"] == 1
    assert facts["archive_bytes"] != facts["target_archive_bytes"]
    bad, _ = capture_receipt(tmp_path, corrupt=True)
    with pytest.raises(RuntimeError, match="capture_payload_changed"):
        _verify_archive(bad, params)


def test_unknown_capture_keeps_guard_and_evidence_without_disposal(tmp_path, monkeypatch):
    from src.worker import docker_runtime
    attempted = []

    class UnknownRuntime:
        def __init__(self, *args):
            pass

        def ensure(self, *args):
            return SimpleNamespace(state="ready")

        def execute_attempt(self, *args):
            return ExecutionReceipt("unknown", True, False, True)

        def cancel_attempt(self, worker, spec, attempt, **kwargs):
            attempted.append((worker, attempt, kwargs))
            return ExecutionReceipt("unknown", True, False, True)

        def _row(self, *args):
            raise AssertionError("unknown resources must not enter disposal")

    monkeypatch.setattr(docker_runtime, "ManagedDockerRuntime", UnknownRuntime)
    case = {"kind": "capture", "params": {"target_archive_bytes": 262144,
                                            "payload_bytes": 131072, "file_count": 1},
            "_guard": {"uncertain": False}}
    recorder = Recorder()
    with pytest.raises(RuntimeError, match="capture_completion_unqualified"):
        run_case(case, tmp_path, recorder, {"runtime": (None, "sha256:" + "a" * 64)}, monkeypatch)
    assert case["_guard"]["uncertain"] is True
    assert recorder.facts["artifacts"]["unknown_retained"] is True
    assert recorder.facts["artifacts"]["artifacts_captured"] is False
    assert len(attempted) == 1 and attempted[0][1] == "synthetic-capture-original"
    assert attempted[0][2] == {"input_text": "generate synthetic archive payload"}
    assert recorder.facts["artifacts"]["recovery"]["disposition"] == "unresolved"


def test_capture_interruption_cancels_same_original_attempt_and_still_fails(tmp_path, monkeypatch):
    from src.worker import docker_runtime
    original = []

    class InterruptedRuntime:
        def __init__(self, *args):
            pass

        def ensure(self, *args):
            return SimpleNamespace(state="ready")

        def execute_attempt(self, worker, spec, attempt, text, seconds):
            original.append((worker, spec, attempt, text))
            raise KeyboardInterrupt

        def cancel_attempt(self, worker, spec, attempt, input_text):
            assert (worker, spec, attempt, input_text) == original[0]
            original.append("cancelled")
            return ExecutionReceipt("cancelled", True, True, True)

        def _row(self, *args):
            raise AssertionError("failed fixture disposal remains forbidden")

    monkeypatch.setattr(docker_runtime, "ManagedDockerRuntime", InterruptedRuntime)
    case = {"kind": "capture", "params": {"target_archive_bytes": 262144,
                                            "payload_bytes": 131072, "file_count": 1},
            "_guard": {"uncertain": False}}
    recorder = Recorder()
    with pytest.raises(KeyboardInterrupt):
        run_case(case, tmp_path, recorder, {"runtime": (None, "sha256:" + "a" * 64)}, monkeypatch)
    assert original[-1] == "cancelled" and case["_guard"]["uncertain"] is True
    assert recorder.facts["artifacts"]["unknown_retained"] is True
    assert recorder.facts["artifacts"]["recovery"]["disposition"] == "producer_reported_terminal_capture_retained"


def test_unavailable_native_image_fails_instead_of_skipping(tmp_path, monkeypatch):
    case = {"kind": "capture", "params": {"target_archive_bytes": 262144,
                                            "payload_bytes": 131072, "file_count": 1}}
    with pytest.raises(RuntimeError, match="native_runtime_image_required"):
        run_case(case, tmp_path, Recorder(), {}, monkeypatch)


def test_undeclared_publication_mode_is_rejected(tmp_path, monkeypatch):
    case = publication()
    case["params"]["blobs"] = 2
    with pytest.raises(RuntimeError, match="publication_case_not_declared"):
        run_case(case, tmp_path, Recorder(), {}, monkeypatch)
