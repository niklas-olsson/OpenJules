"""Declared native lifecycle cases using existing managed integration fixtures."""

from __future__ import annotations

from contextlib import contextmanager
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import hashlib
import json
import os
from pathlib import Path
import subprocess
import tarfile
import threading
import time

from tools.managed_costs import BudgetStop, STOP


@contextmanager
def measured_provider(answer, recorder):
    """Deterministic HTTP fixture. Actual consumed/written body lengths only."""
    rows, errors = [], []
    active = set()
    active_lock = threading.Lock()

    class Handler(BaseHTTPRequestHandler):
        def do_POST(self):
            with active_lock:
                active.add(threading.current_thread())
            try:
                size = int(self.headers.get("Content-Length", "0"))
                assert 0 < size <= 524288
                self.connection.settimeout(10)
                raw = self.rfile.read(size)
                assert len(raw) == size
                payload = json.loads(raw)
                recorder.observe_body("request", len(raw))
                recorder.add("http.requests")
                recorder.add("model.requests")
                rows.append(payload)
                assistant = answer(payload)
                content = json.dumps({"choices": [{"message": assistant}]}).encode()
                assert len(content) <= 262144
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(content)))
                self.end_headers()
                self.wfile.write(content)
                recorder.observe_body("response", len(content))
            except (BrokenPipeError, ConnectionResetError):
                errors.append("owned_connection_closed")
            except BaseException:
                errors.append("fixture_failure")
                self.close_connection = True
            finally:
                with active_lock:
                    active.discard(threading.current_thread())

        def log_message(self, *_):
            pass

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    server.daemon_threads = True
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield f"http://127.0.0.1:{server.server_port}/v1/chat/completions", rows, errors
    finally:
        server.shutdown()
        server.server_close()
        thread.join(2)
        assert not thread.is_alive()
        deadline = time.monotonic() + 5
        while time.monotonic() < deadline:
            with active_lock:
                pending = list(active)
            if not pending:
                break
            for handler in pending:
                handler.join(min(0.1, max(0, deadline - time.monotonic())))
        with active_lock:
            assert not active, "owned_provider_handler_unresolved"


def expected_tree(source):
    objects = []
    for name in ("left", "right"):
        content = (name + " implemented\n").encode()
        oid = subprocess.check_output(["git", "-C", str(source), "hash-object", "-w", "--stdin"], input=content, timeout=10).decode().strip()
        objects.append(f"100644 blob {oid}\t{name}.txt\n")
    return subprocess.check_output(["git", "-C", str(source), "mktree"], input="".join(objects).encode(), timeout=10).decode().strip()


def retained_tree(source, base, patch, index):
    import os
    environment = dict(os.environ) | {"GIT_INDEX_FILE": str(index)}
    subprocess.run(["git", "-C", str(source), "read-tree", base], env=environment, check=True, timeout=10, capture_output=True)
    subprocess.run(["git", "-C", str(source), "apply", "--cached", "--binary", "-"], input=patch.encode(), env=environment, check=True, timeout=10, capture_output=True)
    return subprocess.check_output(["git", "-C", str(source), "write-tree"], env=environment, timeout=10).decode().strip()


def finish(stack, guard, *, timeout=50):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if STOP.is_set():
            guard["uncertain"] = True
            raise BudgetStop("case_cancel_requested")
        worker = stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)
        stack.dispatcher.tick_worker(worker)
        row = stack.dispatcher.journal.get(stack.worker_id)
        if row and row["phase"] == "completed":
            return
        time.sleep(0.05)
    guard["uncertain"] = True
    raise TimeoutError("original_case_deadline")


def cancel_original(stack, guard):
    """Try original cancellation/capture. Unknown does not authorize deletion."""
    guard["uncertain"] = True
    try:
        root = stack.children.journal.context(stack.worker_id)
        receipt = stack.runtime.cancel_attempt(stack.worker_id, stack.spec, root.attempt_id)
        stack.authority.allowed = False
        deadline = time.monotonic() + 20
        while time.monotonic() < deadline:
            worker = stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)
            stack.dispatcher.tick_worker(worker)
            row = stack.dispatcher.journal.get(stack.worker_id)
            if row and row["phase"] == "completed":
                receipt = stack.runtime.inspect_attempt(stack.worker_id, stack.spec, root.attempt_id)
                guard["uncertain"] = not (
                    receipt.termination_confirmed and receipt.launch_fenced
                    and receipt.artifacts_captured and stack.authority.terminal_receipt is not None
                    and all(value["terminal"] for value in stack.child_authority.records.values()))
                return
            time.sleep(0.05)
    except BaseException:
        return  # the original uncertainty and owned resources remain retained


def native_lifecycle(case, workdir, recorder, images, monkeypatch):
    from tests.integration.test_managed_children_runtime import child_stack
    from tests.unit.test_managed_agent import message
    from tests.unit.test_managed_model_integration import TOKEN_VALUE

    delegated = case["kind"] == "children"
    # Both variants use byte-identical approved source and high-level result.
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
    root_turn = 0
    child_turns = {"left": 0, "right": 0}
    child_ids, patches = [], []
    first_requests = {}
    requests_lock = threading.Lock()

    def answer(payload):
        nonlocal root_turn
        messages = payload["messages"]
        instruction = messages[1]["content"]
        with requests_lock:
            if instruction.startswith("CHILD_"):
                name = "left" if instruction.startswith("CHILD_left") else "right"
                first_requests.setdefault(name, time.monotonic_ns())
                child_turns[name] += 1
                assert child_turns[name] <= 2
                return (message("write_file", path=name + ".txt", content=name + " implemented\n")
                        if child_turns[name] == 1 else message("finish", summary="Completed fixture file"))
            root_turn += 1
            first_requests.setdefault("root", time.monotonic_ns())
            if root_turn == 1 and case.get("_first_model_barrier") is not None:
                case["_first_model_barrier"].wait(timeout=4)
            if not delegated:
                if root_turn == 1:
                    return message("run_command", argv=["python3", "-I", "-c",
                        "from pathlib import Path; Path('left.txt').write_text('left implemented\\n'); Path('right.txt').write_text('right implemented\\n')"])
                assert root_turn == 2 and json.loads(messages[-1]["content"])["exit_code"] == 0
                return message("finish", summary="Changed both fixture files")
            if root_turn in {2, 3}:
                child_ids.append(json.loads(messages[-1]["content"])["child_id"])
            if root_turn in {4, 5}:
                value = json.loads(messages[-1]["content"])
                assert value["final"] is False
                assert value["artifact_sha256"] == hashlib.sha256(value["content"].encode()).hexdigest()
                patches.append(value["content"])
            if root_turn <= 2:
                name = "left" if root_turn == 1 else "right"
                return message("spawn_child", instructions=f"CHILD_{name}: change only {name}.txt",
                               seconds=35, max_turns=3, capabilities=["python"])
            if root_turn in {3, 4}:
                return message("child_result", child_id=child_ids[root_turn - 3], kind="patch")
            if root_turn == 5:
                assert len(patches) == 2
                script = "import subprocess; subprocess.run(['git','apply','-'],input=" + repr("".join(patches)) + ",text=True,check=True)"
                return message("run_command", argv=["python3", "-I", "-c", script])
            assert root_turn == 6 and json.loads(messages[-1]["content"])["exit_code"] == 0
            return message("finish", summary="Composed both fixture child changes")

    guard = case["_guard"]
    guard["uncertain"] = True
    result = {}
    with measured_provider(answer, recorder) as (endpoint, requests, errors):
        with child_stack(workdir, monkeypatch, images["agent"], endpoint, seconds=60) as stack:
            try:
                stack.authority.requirements = "Change left.txt and right.txt to their implemented lines and verify the retained result."
                expected = expected_tree(stack.source)
                dispatch_started = time.monotonic_ns()
                with recorder.phase("case.children" if delegated else "case.root"):
                    finish(stack, guard)
                acknowledgement_observed = time.monotonic_ns()
                root = stack.children.journal.context(stack.worker_id)
                receipt = stack.runtime.inspect_attempt(stack.worker_id, stack.spec, root.attempt_id)
                children = stack.children.journal.children(stack.worker_id)
                assert receipt.exit_code == 0 and receipt.termination_confirmed and receipt.launch_fenced and receipt.artifacts_captured
                assert len(children) == (2 if delegated else 0)
                assert all(child["phase"] == "completed" for child in children)
                assert all(value["terminal"] for value in stack.child_authority.records.values())
                assert stack.authority.terminal_receipt is not None and len(stack.authority.candidates) == 1
                content = Path(receipt.capture_path).read_bytes()
                assert hashlib.sha256(content).hexdigest() == receipt.capture_sha256
                actual = retained_tree(stack.source, stack.profile.base_commit, receipt.patch, workdir / "verification.index")
                assert actual == expected
                with tarfile.open(receipt.capture_path) as archive:
                    for name in ("left", "right"):
                        assert archive.extractfile(f"workspace/run/repo/{name}.txt").read() == (name + " implemented\n").encode()
                # Final child artifacts refer to this same complete root tar.
                child_hashes = []
                for child in children:
                    retained = json.loads(child["capture"])["contents"]
                    manifest = json.loads(retained["manifest"])
                    assert manifest["archive_sha256"] == receipt.capture_sha256
                    assert manifest["termination_method"] == "whole-container fence"
                    assert TOKEN_VALUE not in "".join(retained.values())
                    child_hashes.append({"child_id": child["child_id"], "uid": child["uid"],
                        "grant_digest": manifest["grant_digest"],
                        "artifact_hashes": {key: hashlib.sha256(value.encode()).hexdigest() for key, value in retained.items()}})
                assert len(requests) == (10 if delegated else 2) and not errors
                original_calls = len(requests)
                stack.dispatcher.tick_worker(stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id))
                replay = stack.runtime.inspect_attempt(stack.worker_id, stack.spec, root.attempt_id)
                assert replay == receipt and len(requests) == original_calls
                assert not stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)["active_executions"]
                assert all((stack.source / (name + ".txt")).read_text() == "old\n" for name in ("left", "right"))
                result = {"fixture": "actual-rootful-Docker; deterministic model and authority fixtures",
                    "source_base": stack.profile.base_commit, "expected_tree": expected, "retained_tree": actual,
                    "worker_id": stack.worker_id, "attempt_id": root.attempt_id,
                    "root_patch_sha256": hashlib.sha256(receipt.patch.encode()).hexdigest(),
                    "archive_sha256": receipt.capture_sha256, "archive_bytes": len(content),
                    "model_requests": original_calls, "children": child_hashes,
                    "dispatch_to_first_model_body_ns": first_requests["root"] - dispatch_started,
                    "dispatch_to_final_capture_acknowledgement_ns": acknowledgement_observed - dispatch_started,
                    "dispatch_to_first_child_model_body_ns": {name: first_requests[name] - dispatch_started for name in ("left", "right") if name in first_requests},
                    "first_work_proxy": "first complete model request body observed by the deterministic fixture, not first guest instruction",
                    "termination_confirmed": True, "launch_fenced": True, "canonical_fixture_capture_complete": True,
                    "replay_added_model_calls": 0, "independent_patch_reapplication": True,
                    "release_proof": "original dispatcher completed after root and child capture acknowledgements"}
                guard["uncertain"] = False
            except BaseException:
                cancel_original(stack, guard)
                if guard["uncertain"] and case.get("_parent_guard") is not None:
                    case["_parent_guard"]["uncertain"] = True
                raise
    return result


def two_workers(case, workdir, recorder, images, monkeypatch):
    # Actual two incarnations are dispatched in parallel under a fixed ceiling.
    # Their private fixtures and broker allowances are separate, not shared KP.
    results, failures = [], []
    barrier = threading.Barrier(2)
    model_barrier = threading.Barrier(2)
    lock = threading.Lock()
    monkeypatch.setenv("GIT_AUTHOR_DATE", "2026-01-01T00:00:00Z")
    monkeypatch.setenv("GIT_COMMITTER_DATE", "2026-01-01T00:00:00Z")
    from tests.unit.test_managed_model_integration import TOKEN_REFERENCE, TOKEN_VALUE
    monkeypatch.setenv(TOKEN_REFERENCE[4:], TOKEN_VALUE)

    class ExistingEnvironment:
        def setenv(self, name, value):
            assert os.environ.get(name) == value

    def run(index):
        child = workdir / str(index)
        child.mkdir(mode=0o700)
        guard = {"uncertain": True}
        try:
            barrier.wait(timeout=5)
            result = native_lifecycle(case | {"kind": "root", "_guard": guard,
                "_parent_guard": case["_guard"], "_first_model_barrier": model_barrier}, child, recorder, images, ExistingEnvironment())
            results.append(result)
        except BaseException:
            failures.append("worker_fixture_failed")
        finally:
            with lock:
                case["_guard"]["uncertain"] |= guard["uncertain"]

    threads = [threading.Thread(target=run, args=(i,)) for i in range(2)]
    case["_owned_threads"] = threads
    for thread in threads:
        thread.start()
    deadline = time.monotonic() + 75
    try:
        for thread in threads:
            thread.join(max(0, deadline - time.monotonic()))
    finally:
        if any(thread.is_alive() for thread in threads):
            case["_guard"]["uncertain"] = True
            STOP.set()
            cleanup_deadline = time.monotonic() + 15
            for thread in threads:
                thread.join(max(0, cleanup_deadline - time.monotonic()))
    assert not any(thread.is_alive() for thread in threads) and not failures and len(results) == 2
    assert len({row["worker_id"] for row in results}) == 2
    assert len({row["retained_tree"] for row in results}) == 1
    return {"workers": results, "worker_ceiling": 2, "shared_authority_qualification": False,
            "concurrent_first_model_calls_witnessed": True}


def control_cancel(case, workdir, recorder, images, monkeypatch):
    from tests.integration.test_managed_children_runtime import child_stack
    from tests.unit.test_managed_agent import message
    entered, release = threading.Event(), threading.Event()

    def held(_):
        entered.set()
        assert release.wait(15)
        return message("finish", summary="Held deterministic response")

    guard = case["_guard"]
    with measured_provider(held, recorder) as (endpoint, requests, errors):
        with child_stack(workdir, monkeypatch, images["agent"], endpoint, seconds=45) as stack:
            try:
                stack.dispatcher.tick_worker(stack.worker)
                assert entered.wait(10) and not release.is_set()
                original = stack.children.journal.context(stack.worker_id)
                before = time.monotonic_ns()
                stack.authority.allowed = False
                with recorder.phase("control.cancel"):
                    worker = stack.lifecycle.observe_worker(stack.spec.scope, stack.worker_id)
                    stack.dispatcher.tick_worker(worker)
                observed = stack.runtime.inspect_attempt(stack.worker_id, stack.spec, original.attempt_id)
                assert observed.termination_confirmed and observed.launch_fenced and observed.artifacts_captured
                captured_ns = time.monotonic_ns()
                assert not release.is_set() and len(requests) == 1
                release.set()
                finish(stack, guard, timeout=10)
                assert stack.children.journal.context(stack.worker_id).attempt_id == original.attempt_id
                assert len(requests) == 1 and stack.authority.terminal_receipt is not None
                return {"held_provider_requests": 1, "original_attempt_id": original.attempt_id,
                        "worker_id": stack.worker_id, "cancel_to_observed_capture_ns": captured_ns - before,
                        "cancel_to_final_fixture_acknowledgement_ns": time.monotonic_ns() - before,
                        "capture_before_provider_release": True, "launch_fenced": True,
                        "canonical_fixture_capture_complete": True, "provider_connection_closed": bool(errors)}
            except BaseException:
                release.set()
                cancel_original(stack, guard)
                raise
            finally:
                release.set()


def run_case(case, workdir, recorder, images, monkeypatch):
    kind = case["kind"]
    if kind in {"root", "children"}:
        return native_lifecycle(case, workdir, recorder, images, monkeypatch)
    if kind == "two_workers":
        return two_workers(case, workdir, recorder, images, monkeypatch)
    if kind == "control_cancel":
        return control_cancel(case, workdir, recorder, images, monkeypatch)
    if kind == "control_denial":
        from tests.integration.test_managed_socket_responsiveness import test_wrong_uid_is_denied_before_a_held_authorized_provider_reply
        with recorder.phase("control.denial"):
            test_wrong_uid_is_denied_before_a_held_authorized_provider_reply(workdir, monkeypatch, images["agent"])
        return {"existing_native_assertions_passed": True, "held_authorized_request": 1,
                "wrong_uid_denied_before_provider_release": True, "reservation_preserved": True,
                "http_body_observation": "NOT_MEASURED in this reused negative fixture; zero instrumented counters do not mean zero traffic"}
    if kind == "overhead":
        count = 1000
        start = time.monotonic_ns()
        for _ in range(count):
            pass
        baseline = time.monotonic_ns() - start
        start = time.monotonic_ns()
        for _ in range(count):
            with recorder.phase("overhead"):
                pass
        measured = time.monotonic_ns() - start
        return {"iterations": count, "empty_loop_ns": baseline, "instrumented_loop_ns": measured,
                "scope": "synthetic hook cost only; paired native root controls measure workload overhead"}
    raise ValueError("unknown_native_case")
