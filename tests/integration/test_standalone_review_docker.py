"""Actual selected Docker, model HTTP, host Git and original ingress journal.

Opt-in is explicit. An opted-in job with missing Docker/image fails. Model
responses and producer identity reads are deterministic fixtures. Git's only
transport substitution is an isolated HTTPS helper serving local receive-pack;
the production URL, argv, private auth config, CAS and porcelain stay intact.
This is source qualification, not live provider/GitHub or installed delivery.
"""

import hashlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
import threading
import time
import unittest
from unittest.mock import patch

from fastapi.testclient import TestClient

from src.api.webhook import create_app
from src.git_manager.review_publication import git_environment
from src.storage.ingress_receipts import ReceiptStore
from src.worker.review_github import OriginalHTTPReply
from src.worker.review_native import ReviewNativeBackend
from src.worker.standalone_review import StandaloneReviewAdapter
from tests.integration.test_review_ingress_http import signed
from tests.unit.review_ingress_support import event, host, normalized
from tests.unit.review_native_fixture import git
from tests.unit.test_standalone_review_engine import PLAN, call
from tests.unit.test_standalone_review_model import reply


@unittest.skipUnless(os.environ.get("OPENJULES_REVIEW_DOCKER_TESTS") == "1",
    "real standalone review Docker qualification requires explicit opt-in")
class RealReviewDockerTests(unittest.TestCase):
    def test_signed_original_journey_retains_capture_publishes_once_and_reopens(self):
        image = os.environ.get("OPENJULES_REVIEW_IMAGE_ID")
        self.assertIsNotNone(image, "opted-in qualification requires the explicitly built review fixture image")
        self.assertRegex(image, r"^sha256:[0-9a-f]{64}$")
        actual_image = subprocess.check_output(["docker", "image", "inspect", "--format", "{{.Id}}", image], text=True).strip()
        self.assertEqual(actual_image, image)
        endpoint = "unix://" + str(Path("/var/run/docker.sock").resolve(strict=True))
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            source = root / "source"
            source.mkdir(mode=0o700)
            git(source, "init", "--initial-branch=topic")
            (source / "hello.txt").write_text("original\n")
            git(source, "add", "hello.txt")
            git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "Original")
            original_head = git(source, "rev-parse", "HEAD").decode().strip()
            state = root / "state"
            state.mkdir(mode=0o700)
            remote = root / "receiver.git"
            git(root, "init", "--bare", str(remote))
            git(source, "push", str(remote), "HEAD:refs/heads/topic")
            model_calls, model_errors = [], []
            responses = [reply(PLAN), reply(None, calls=[call("correct-original", "run_command",
                {"command": "printf 'corrected\\n' > hello.txt"})]), reply("TASK_COMPLETED")]

            class ModelHandler(BaseHTTPRequestHandler):
                def log_message(self, *_):
                    pass

                def do_POST(self):
                    try:
                        if self.path != "/v1/chat/completions" or self.headers.get("Authorization") is not None:
                            raise ValueError("unexpected model route")
                        length = int(self.headers.get("Content-Length", "-1"))
                        if not 0 < length <= 50000:
                            raise ValueError("invalid fixture request bound")
                        raw = self.rfile.read(length)
                        value = json.loads(raw)
                        if value["model"] != "fixture-only" or value["stream"] is not False:
                            raise ValueError("unexpected model selection")
                        model_calls.append(value)
                        if not responses:
                            raise ValueError("unexpected additional model call")
                        body = responses.pop(0)
                        self.send_response(200)
                        self.send_header("Content-Type", "application/json")
                        self.send_header("Content-Length", str(len(body)))
                        self.end_headers()
                        self.wfile.write(body)
                    except BaseException:
                        model_errors.append("controlled_model_fixture_refused")
                        self.send_error(500)

            server = ThreadingHTTPServer(("127.0.0.1", 0), ModelHandler)
            server_thread = threading.Thread(target=server.serve_forever, daemon=True)
            server_thread.start()
            native = []
            try:
                def configure(document):
                    profile = document["bindings"][0]["standalone_review"]
                    profile["guest"].update(image=image, docker_endpoint=endpoint,
                        test_command="python3 -c \"from pathlib import Path; assert Path('hello.txt').read_text() == 'corrected\\n'\"")
                    profile["model"]["url"] = f"http://127.0.0.1:{server.server_port}/v1/chat/completions"
                    profile["limits"].update(total_ms=90000, cleanup_reserve_ms=15000,
                        model_call_ms=10000, exec_call_ms=15000, guest_api_ms=15000,
                        git_call_ms=15000, forge_call_ms=10000,
                        model_request_bytes=50000, model_request_total_bytes=300000,
                        exec_calls=16, exec_input_bytes=20000, exec_output_bytes=20000,
                        exec_output_total_bytes=320000, guest_api_calls=80,
                        source_bytes=1000000, source_objects=200, context_bytes=100000,
                        archive_bytes=2000000, patch_bytes=50000, log_bytes=100000,
                        files=1000, blob_bytes=100000, object_bytes=2000000, object_count=1000,
                        git_calls=256, git_output_bytes=1000000, git_output_total_bytes=256000000,
                        receipt_result_bytes=4000000)
                policy, path, environment, _, _, _, _ = host(root, mutate=configure)
                original = event()
                original["pull_request"]["head"]["sha"] = original_head
                original["review"]["commit_id"] = original_head
                producer_calls = []

                class ControlledProducerBackend(ReviewNativeBackend):
                    def _forge_request(self, operation, kind, method, route, payload, headers):
                        expected = "/repos/fixture/repo/pulls/7"
                        if (kind != "forge_get" or method != "GET" or payload is not None
                                or route not in {expected, expected + "/reviews/8001"}
                                or headers.get("Authorization") != "Bearer " + environment["REVIEW_FIXTURE_TOKEN"]):
                            raise AssertionError("unexpected producer effect")
                        value = original["pull_request"] if route == expected else {
                            **original["review"], "state": "CHANGES_REQUESTED"}
                        body = json.dumps(value, separators=(",", ":")).encode()
                        effect = operation.reserve(kind, response_bytes=operation.limits["forge_response_bytes"])
                        def exchange():
                            producer_calls.append(route)
                            return body
                        raw = operation.invoke(effect, exchange)
                        operation.consume(effect, response_bytes=len(raw))
                        operation.observe(effect, "closed", data={"local_closed": True})
                        return OriginalHTTPReply(200, raw, effect)

                helper_root = root / "helper"
                helper_root.mkdir(mode=0o700)
                observations = root / "git-observations.jsonl"
                helper = helper_root / "git-remote-https"
                helper.write_text(f'''#!{sys.executable}
import hashlib,json,os,subprocess,sys
url=sys.argv[-1]
header=subprocess.check_output(["git","config","--get-urlmatch","http.extraHeader",url]).strip()
with open({str(observations)!r},"a") as stream:
    stream.write(json.dumps({{"url":url,"header_sha256":hashlib.sha256(header).hexdigest()}})+"\\n")
while True:
    line=sys.stdin.buffer.readline()
    if line==b"capabilities\\n":
        sys.stdout.buffer.write(b"connect\\n\\n");sys.stdout.buffer.flush()
    elif line==b"connect git-receive-pack\\n":
        sys.stdout.buffer.write(b"\\n");sys.stdout.buffer.flush()
        os.execv("/usr/bin/git",["git","receive-pack",{str(remote)!r}])
    else:
        raise SystemExit(3)
''')
                helper.chmod(0o700)
                selected_git_environment = {**git_environment(), "GIT_EXEC_PATH": str(helper_root)}
                def native_factory(claim):
                    backend = ControlledProducerBackend(claim)
                    native.append(backend)
                    return backend
                adapter = StandaloneReviewAdapter(native_factory=native_factory)
                with patch.dict(os.environ, environment), patch("src.worker.review_native.git_environment",
                        return_value=selected_git_environment):
                    app = create_app(policy_path=str(path), review_adapter=adapter)
                    with TestClient(app, base_url="http://127.0.0.1:8000", client=("127.0.0.1", 34567)) as client:
                        body, headers = signed(original)
                        admitted = client.post("/api/webhook", content=body, headers=headers)
                        self.assertEqual(admitted.status_code, 202, admitted.text)
                        operation_id = admitted.json()["operation_id"]
                        cutoff = time.monotonic() + 100
                        while time.monotonic() < cutoff:
                            response = client.get("/api/ingress/receipts/" + operation_id,
                                headers={"Authorization": "Bearer test-operator-value"})
                            self.assertEqual(response.status_code, 200, response.text)
                            observed = response.json()
                            if observed["dispatch_state"] not in {"reserved", "may_have_started"}:
                                break
                            time.sleep(0.05)
                        else:
                            self.fail("actual review callback exceeded its fixture observation window")
                        self.assertEqual(observed["dispatch_state"], "returned", observed)
                        self.assertEqual(observed["result"]["status"], "returned", observed)
                result = observed["result"]
                self.assertEqual(model_errors, [])
                self.assertEqual(len(model_calls), 3)
                self.assertEqual(len(producer_calls), 4)
                self.assertEqual(result["facts"]["verification"]["exit_code"], 0)
                self.assertTrue(result["facts"]["capture"]["durable"])
                self.assertEqual(result["facts"]["publication"]["status"], "acknowledged")
                self.assertEqual(result["counters"]["guest_api_cleanup"], 6)
                for key in ("container_removed", "volume_removed", "auth_removed",
                        "local_processes_closed", "local_exchanges_closed"):
                    self.assertIs(result["facts"]["cleanup"].get(key), True, (key, result))
                candidate = result["facts"]["candidate"]["commit_sha"]
                self.assertEqual(git(remote, "rev-parse", "refs/heads/topic").decode().strip(), candidate)
                self.assertEqual(git(remote, "show", candidate + ":hello.txt"), b"corrected\n")
                self.assertEqual(git(remote, "rev-list", "--parents", "-n", "1", candidate).decode().split(),
                    [candidate, original_head])
                self.assertEqual(len(observations.read_text().splitlines()), 1)
                self.assertEqual(len(native), 1)
                capture = native[0].capture
                self.assertEqual(hashlib.sha256((capture.handle.directory / "archive.tar").read_bytes()).hexdigest(),
                    result["facts"]["capture"]["archive_sha256"])
                self.assertIn(b"+corrected", (capture.handle.directory / "change.patch").read_bytes())
                self.assertFalse(native[0].auth_path.exists())
                with ReceiptStore(policy) as store:
                    binding, review, actor = normalized(policy, original)
                    self.assertEqual(store.reserve_review("webhook", binding.binding_id, review, actor), observed)
                self.assertEqual(len(model_calls), 3)
                self.assertEqual(len(observations.read_text().splitlines()), 1)
            finally:
                server.shutdown()
                server.server_close()
                server_thread.join(timeout=5)
                # Separate fixture teardown, never evidence of runtime cleanup.
                for backend in native:
                    guest = backend.original_guest
                    if guest is not None:
                        if guest.container_id is not None:
                            subprocess.run(["docker", "rm", "-f", guest.container_id], capture_output=True, timeout=30)
                        subprocess.run(["docker", "volume", "rm", guest.volume_name], capture_output=True, timeout=30)


if __name__ == "__main__":
    unittest.main()
