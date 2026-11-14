"""Finite source, archive and actual local HTTP/Git cost fixtures.

These lanes observe existing production algorithms. Source and publication use
synthetic authority data; capture uses the real managed Docker root with an
explicit readiness fixture. Neither establishes installed canonical authority,
model quality, acceptance or release. No private request or journal is exported.
"""

from __future__ import annotations

import asyncio
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
from uuid import uuid4

import httpx


MIB = 1024 * 1024
MAX_ARCHIVE = 16 * MIB
BODY_RATE = 1_250_000
HTTP_LIMIT = 8_000_000
STAMP = "1740000000 +0000"


def _require(condition, code):
    if not condition:
        raise RuntimeError(code)


def _git(path, *args, data=None):
    environment = {
        "PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_TERMINAL_PROMPT": "0", "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_AUTHOR_DATE": STAMP, "GIT_COMMITTER_DATE": STAMP,
    }
    return subprocess.run(
        ["git", "-C", str(path), "-c", "core.hooksPath=/dev/null",
         "-c", "core.fsmonitor=false", *args],
        input=data, capture_output=True, check=True, timeout=10,
        env=environment,
    ).stdout


def _payload(index, length):
    """Stable, unique text blobs, including their final newline in the size."""
    _require(type(length) is int and length > 1, "fixture_payload_size")
    block = hashlib.sha256(f"managed-cost-fixture:{index}".encode()).hexdigest().encode()
    return (block * ((length - 2) // len(block) + 1))[:length - 1] + b"\n"


def _source(path, total, files, *, capture=False):
    path.mkdir(mode=0o755)
    if capture:
        (path / "initial.txt").write_bytes(b"base\n")
        (path / ".gitignore").write_bytes(b"fixture-payload/\n")
    else:
        for index in range(files):
            length = total // files + (index < total % files)
            (path / f"input-{index:04d}.txt").write_bytes(_payload(index, length))
    _git(path, "init", "-q")
    _git(path, "add", ".")
    _git(path, "-c", "user.name=Cost Fixture", "-c",
         "user.email=cost-fixture@example.invalid", "commit", "-qm", "synthetic base")
    return _git(path, "rev-parse", "HEAD").decode().strip()


def _source_case(params, workdir, recorder):
    _require(params == {"source_bytes": 4 * MIB, "file_count": 64}, "source_case_not_declared")
    from src.worker.source_snapshot import SourceSnapshots

    with recorder.phase("setup"):
        source = workdir / "source"
        base = _source(source, params["source_bytes"], params["file_count"])
        snapshots = SourceSnapshots(workdir / "snapshots")
    with recorder.phase("source.cold"):
        cold = snapshots.prepare(str(source), base, MAX_ARCHIVE)
    manifest = (cold.parent / "manifest.json").read_bytes()
    with recorder.phase("source.reuse"):
        reused = snapshots.prepare(str(source), base, MAX_ARCHIVE)
    metadata = json.loads(manifest)
    _require(cold == reused and (reused.parent / "manifest.json").read_bytes() == manifest,
             "source_reuse_changed")
    _require(_git(reused, "rev-parse", "HEAD").decode().strip() == base, "source_base_changed")
    facts = {
        "source_bytes": params["source_bytes"], "file_count": params["file_count"],
        "base_sha": base, "object_bytes": metadata["object_bytes"],
        "objects": metadata["objects"], "pack_sha256": metadata["pack_sha256"],
        "same_instance_admitted_reuse": True,
        "reuse_scope": "existing manifest admission; not a second full closure rehash",
    }
    recorder.fact("source", facts)
    return facts


def _capture_script(total, files):
    # Payload files stay in the archive but are ignored by the Git patch.
    # Generation is deliberately not inference and keeps patch size stable.
    return (
        "from pathlib import Path; import hashlib\n"
        "root=Path('fixture-payload'); root.mkdir()\n"
        f"total={total}; count={files}\n"
        "for i in range(count):\n"
        " n=total//count+(i<total%count)\n"
        " block=hashlib.sha256(('managed-cost-fixture:'+str(i)).encode()).hexdigest().encode()\n"
        " (root/('payload-%04d.bin'%i)).write_bytes((block*((n-2)//len(block)+1))[:n-1]+b'\\n')\n"
        "Path('initial.txt').write_text('captured fixture change\\n')\n"
        "print('synthetic payload ready')\n"
    )


def _verify_archive(receipt, params):
    """Independently check retained bytes without extracting an archive."""
    path = Path(receipt.capture_path)
    content = path.read_bytes()
    manifest = json.loads(receipt.manifest)
    _require(0 < len(content) <= MAX_ARCHIVE, "capture_size_unqualified")
    _require(hashlib.sha256(content).hexdigest() == receipt.capture_sha256
             == manifest["archive_sha256"] and len(content) == manifest["archive_bytes"],
             "capture_digest_changed")
    prefix = "workspace/run/repo/fixture-payload/"
    expected = {prefix + f"payload-{index:04d}.bin": index for index in range(params["file_count"])}
    observed = set()
    with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
        for member in archive:
            if not member.name.startswith(prefix) or not member.isfile():
                continue
            _require(member.name in expected and member.name not in observed,
                     "capture_payload_members_changed")
            index = expected[member.name]
            length = params["payload_bytes"] // params["file_count"] + (index < params["payload_bytes"] % params["file_count"])
            _require(member.size == length, "capture_payload_length_changed")
            handle = archive.extractfile(member)
            _require(handle is not None and handle.read(length + 1) == _payload(index, length),
                     "capture_payload_changed")
            observed.add(member.name)
    _require(observed == set(expected), "capture_payload_missing")
    _require("+captured fixture change" in receipt.patch and "fixture-payload" not in receipt.patch,
             "capture_patch_changed")
    return {"archive_bytes": len(content), "archive_sha256": receipt.capture_sha256,
            "patch_sha256": hashlib.sha256(receipt.patch.encode()).hexdigest(),
            "log_sha256": hashlib.sha256(receipt.log.encode()).hexdigest(),
            "payload_bytes": params["payload_bytes"], "payload_files": len(observed),
            "target_archive_bytes": params["target_archive_bytes"],
            "archive_limit_bytes": MAX_ARCHIVE}


def _dispose_capture_fixture(runtime, worker, spec):
    """Dispose only this verified, stopped synthetic fixture, without force.

    This is test resource disposal. It is not the production canonical cleanup
    protocol and must never be described as task release or acceptance.
    """
    row = runtime._row(worker, spec)
    identity = json.loads(row["volume_identity"])
    container = runtime._cleanup_container(worker, spec, row["container_id"], identity["Name"])
    volume = runtime._cleanup_volume(worker, spec, identity)
    container.remove(force=False)
    volume.remove(force=False)


def _capture_case(case, params, workdir, recorder, images):
    target = params.get("target_archive_bytes")
    _require(set(params) == {"target_archive_bytes", "payload_bytes", "file_count"}
             and type(target) is int and target in {262144, 4 * MIB, 12 * MIB}
             and type(params["payload_bytes"]) is int and type(params["file_count"]) is int
             and params["payload_bytes"] == target - 131072
             and (params["file_count"] == 1 or (target == 4 * MIB and params["file_count"] == 512)),
             "capture_case_not_declared")
    _require("runtime" in images, "native_runtime_image_required")
    from src.worker.docker_profile import DockerProfile
    from src.worker.docker_runtime import ManagedDockerRuntime
    from src.worker.lifecycle import RuntimeCapabilities, WorkerSpec

    client, image_id = images["runtime"]
    with recorder.phase("setup"):
        source = workdir / "source"
        base = _source(source, 0, 0, capture=True)
        profile = DockerProfile(
            "cost-capture-v1", "cost-fixture", "github:github.com/fixture/cost",
            str(source.resolve()), image_id,
            ("python3", "-I", "-c", _capture_script(params["payload_bytes"], params["file_count"])),
            base, max_seconds=60,
        )
        runtime = ManagedDockerRuntime(
            workdir / "runtime", [profile],
            lambda *_: RuntimeCapabilities(True, True, True, "explicit synthetic readiness fixture"),
            client,
        )
        spec = WorkerSpec(profile.deployment_id, profile.repository, "cost-capture", 1, "capture-launch", profile.name)
        worker, attempt = uuid4().hex, "synthetic-capture-original"
    guard = case.get("_guard", {})
    guard["uncertain"] = True
    facts = {"termination_confirmed": False, "launch_fenced": False,
             "artifacts_captured": False, "unknown_retained": True,
             "readiness": "explicit fixture; no canonical acceptance",
             "model_requests": 0}
    try:
        with recorder.phase("case.capture"):
            _require(runtime.ensure(worker, spec).state == "ready", "capture_ensure_not_ready")
            receipt = runtime.execute_attempt(worker, spec, attempt, "generate synthetic archive payload", 60)
        facts.update(termination_confirmed=receipt.termination_confirmed,
                     launch_fenced=receipt.launch_fenced, artifacts_captured=receipt.artifacts_captured)
        _require(receipt.state == "completed" and receipt.termination_confirmed
                 and receipt.launch_fenced and receipt.artifacts_captured and receipt.exit_code == 0,
                 "capture_completion_unqualified")
        with recorder.phase("control"):
            facts.update(_verify_archive(receipt, params))
            repeated = runtime.execute_attempt(worker, spec, attempt, "generate synthetic archive payload", 1)
            _require(repeated == receipt, "capture_replay_changed")
            _verify_archive(repeated, params)
            facts["same_attempt_replay_equal"] = True
            facts["unknown_retained"] = False
        guard["uncertain"] = False
        with recorder.phase("cleanup"):
            _dispose_capture_fixture(runtime, worker, spec)
        facts["fixture_resources_disposed"] = True
        facts["disposal_scope"] = "verified synthetic fixture only; no canonical release"
        return facts
    except BaseException:
        guard["uncertain"] = True
        facts["unknown_retained"] = True
        # A parent budget interruption is a BaseException, so it can bypass
        # execute_attempt's ordinary exception recovery. Request cancellation
        # through the same durable attempt and whole-container fence. This is
        # best-effort recovery within the parent's existing cleanup reserve;
        # it never turns the failed/censored sample into a successful trial or
        # permits fixture disposal. A second interruption remains unresolved.
        facts["recovery"] = {"attempted": True, "disposition": "unresolved"}
        try:
            with recorder.phase("control.cancel"):
                recovered = runtime.cancel_attempt(
                    worker, spec, attempt, input_text="generate synthetic archive payload")
            facts["recovery"].update(
                termination_confirmed=recovered.termination_confirmed,
                launch_fenced=recovered.launch_fenced,
                artifacts_captured=recovered.artifacts_captured,
            )
            if recovered.termination_confirmed and recovered.launch_fenced and recovered.artifacts_captured:
                facts["recovery"]["disposition"] = "producer_reported_terminal_capture_retained"
        except BaseException:
            pass  # The original unknown, original journals and resources remain.
        raise
    finally:
        recorder.fact("artifacts", facts)


class _PacedBody(httpx.AsyncByteStream):
    def __init__(self, body, recorder, rate):
        self.body, self.recorder, self.rate = body, recorder, rate

    async def __aiter__(self):
        for start in range(0, len(self.body), 16384):
            chunk = self.body[start:start + 16384]
            await asyncio.sleep(len(chunk) / self.rate)
            self.recorder.add("http.request_bytes", len(chunk))
            yield chunk


class LocalMeasuredTransport(httpx.AsyncBaseTransport):
    """Actual local HTTP with bounded body-consumption pacing, not a WAN model.

    GitHub is the approved synthetic destination. Only its exact origin and the
    fixture's own loopback authority may be routed. No redirects or ambient
    proxies are used, and all retained data is counts, never headers or bodies.
    """

    def __init__(self, fixture, recorder, *, delay_ms, body_bytes_per_second):
        _require(type(delay_ms) is int and delay_ms in {0, 20, 100}
                 and type(body_bytes_per_second) is int
                 and body_bytes_per_second == BODY_RATE, "http_impairment_not_declared")
        self.fixture, self.recorder = fixture, recorder
        self.delay, self.rate = delay_ms / 1000, body_bytes_per_second
        self.local = httpx.URL(fixture.endpoint)

    async def handle_async_request(self, request):
        url = request.url
        forge = url.scheme == "https" and url.host == "api.github.com" and url.port in {None, 443}
        authority = (url.scheme, url.host, url.port) == (self.local.scheme, self.local.host, self.local.port)
        _require(forge or authority, "fixture_http_origin_rejected")
        content = await request.aread()
        _require(len(content) <= HTTP_LIMIT, "fixture_request_body_limit")
        self.recorder.add("http.requests")
        await asyncio.sleep(self.delay)
        routed = httpx.Request(
            request.method, self.fixture.endpoint + url.raw_path.decode("ascii"),
            headers=request.headers,
            stream=_PacedBody(content, self.recorder, self.rate),
        )
        async with httpx.AsyncHTTPTransport(retries=0, trust_env=False) as transport:
            response = await transport.handle_async_request(routed)
            raw = bytearray()
            try:
                async for part in response.aiter_raw():
                    _require(len(raw) + len(part) <= HTTP_LIMIT, "fixture_response_body_limit")
                    for start in range(0, len(part), 16384):
                        chunk = part[start:start + 16384]
                        await asyncio.sleep(len(chunk) / self.rate)
                        raw.extend(chunk)
                        self.recorder.add("http.response_bytes", len(chunk))
                return httpx.Response(response.status_code, headers=response.headers,
                                      stream=httpx.ByteStream(bytes(raw)), request=request)
            finally:
                await response.aclose()


def _publication_case_data(root, blobs, total):
    """Retain the existing canonical fixture shape, replace only its patches."""
    from src.git_manager.managed_composition import content_hash, digest
    from tests.unit.test_managed_composition import captures, final_case

    case = final_case(root)
    source, base = case["source"], case["inputs"]["manifest"]["base"]
    names = ["alpha.txt"] if blobs == 1 else ["alpha.txt", "beta.txt"] + [f"changed-{i:02d}.txt" for i in range(30)]
    values = {name: _payload(index, total // blobs) for index, name in enumerate(names)}
    groups = [names] if blobs == 1 else [names[:16], names[16:]]

    def patch(group):
        for name in group:
            (source / name).write_bytes(values[name])
        _git(source, "add", ".")
        result = _git(source, "diff", "--cached", "--binary", "--no-renames", base).decode()
        tree = _git(source, "write-tree").decode().strip()
        _git(source, "reset", "--hard", "-q", base)
        return result, tree

    patches = [patch(group)[0] for group in groups]
    root_patch, expected_tree = patch(names)
    root_values, root_hashes = captures(root_patch)
    children, lineage = [], []
    responses = case["children"]["children"][:len(groups)]
    for response, child_patch in zip(responses, patches):
        child_values, hashes = captures(child_patch)
        child_id = response["child"]["id"]
        response["child"]["captured_artifacts"] = hashes
        children.append({"child_id": child_id, "artifacts": child_values})
        lineage.append({"child_id": child_id,
                        "grant_digest": response["binding"]["grant_digest"], "artifacts": hashes})
    requirements = f"Change {blobs} synthetic blobs and request independent review"
    candidate = case["snapshot"]["candidate"][0]
    candidate.update(patch=root_hashes["patch"], requirements=requirements, child_lineage=lineage)
    identity = {key: candidate[key] for key in ("base", "patch", "requirements", "revision", "task", "dependency_admissions", "child_lineage")}
    candidate["id"] = digest(identity)
    case["snapshot"]["task"][0].update(requirements=requirements, current_candidate=candidate["id"])
    case["snapshot"]["attempt"][0].update(approved_requirements=requirements,
                                              captured_artifacts=root_hashes, child_lineage=lineage)
    case["inputs"]["manifest"].update(candidate_id=candidate["id"], requirements_digest=content_hash(requirements),
                                        root_artifacts=root_hashes, lineage=lineage)
    case["inputs"].update(root=root_values, children=children)
    case["children"]["children"] = responses
    return case, expected_tree


def _publication_case(params, workdir, recorder, monkeypatch):
    _require(set(params) == {"blobs", "total_bytes", "delay_ms", "body_bytes_per_second", "lose_draft_reply"}
             and type(params["blobs"]) is int and params["blobs"] in {1, 32}
             and params["total_bytes"] == 32768 and type(params["delay_ms"]) is int
             and params["delay_ms"] in {0, 20, 100}
             and type(params["body_bytes_per_second"]) is int
             and params["body_bytes_per_second"] == BODY_RATE
             and type(params["lose_draft_reply"]) is bool, "publication_case_not_declared")
    from src.forge.managed_github import ManagedGitHubPublisher
    from src.git_manager.managed_composition import CompositionLimits
    from src.polyphony.managed_client import ManagedAuthorityClient
    from src.worker.managed_publication import CanonicalPublicationReader, PublicationService
    from tests.integration import test_managed_publication as fixture_module
    from tests.unit.test_managed_publication import policy

    with monkeypatch.context() as patch:
        patch.setenv("AUTHORITY_TEST_TOKEN", fixture_module.AUTHORITY_TOKEN)
        patch.setenv("PUBLICATION_TEST_TOKEN", fixture_module.FORGE_TOKEN)
        patch.setenv("GIT_AUTHOR_DATE", STAMP)
        patch.setenv("GIT_COMMITTER_DATE", STAMP)
        patch.setenv("GIT_CONFIG_NOSYSTEM", "1")
        patch.setenv("GIT_CONFIG_GLOBAL", "/dev/null")
        patch.setenv("GIT_CONFIG_SYSTEM", "/dev/null")
        with recorder.phase("setup"):
            case, expected_tree = _publication_case_data(workdir, params["blobs"], params["total_bytes"])
            fixture = fixture_module.ContractFixture(case, workdir)
        git_observation = {"calls": 0, "elapsed_ns": 0}
        original_git = fixture_module.git_bytes

        def observed_git(*args, **kwargs):
            started = time.perf_counter_ns()
            try:
                return original_git(*args, **kwargs)
            finally:
                git_observation["calls"] += 1
                git_observation["elapsed_ns"] += time.perf_counter_ns() - started

        patch.setattr(fixture_module, "git_bytes", observed_git)
        approved, limits = policy(), CompositionLimits()

        def service():
            transport = LocalMeasuredTransport(fixture, recorder, delay_ms=params["delay_ms"],
                                                body_bytes_per_second=params["body_bytes_per_second"])
            reader = CanonicalPublicationReader(
                ManagedAuthorityClient(fixture.endpoint, "env:AUTHORITY_TEST_TOKEN"),
                approved, fixture.base, limits, transport=transport)
            publisher = ManagedGitHubPublisher(approved, transport=transport)
            return PublicationService(reader, publisher, case["source"], workdir / "state", operation_seconds=120)

        with fixture:
            if params["lose_draft_reply"]:
                fixture.drop_after = "draft"
            candidate = case["inputs"]["manifest"]["candidate_id"]
            with recorder.phase("publication.initial"):
                initial = service().run(candidate)
            expected = "uncertain" if params["lose_draft_reply"] else "draft_published"
            _require(initial["status"] == expected, "publication_initial_unqualified")
            before = list(fixture.effects)
            label = "publication.reconciliation" if params["lose_draft_reply"] else "publication.replay"
            with recorder.phase(label):
                replay = service().run(candidate)
            _require(replay["status"] == "draft_published"
                     and replay["operation"] == initial["operation"]
                     and replay["commit_sha"] == initial["commit_sha"]
                     and fixture.effects == before, "publication_original_operation_changed")
            if not params["lose_draft_reply"]:
                _require(replay == initial, "publication_replay_changed")
            with recorder.phase("control"):
                _require(replay["tree_sha"] == expected_tree, "publication_tree_changed")
                raw = _git(fixture.repository, "cat-file", "commit", replay["commit_sha"])
                _require(raw.startswith(("tree " + expected_tree + "\nparent " + fixture.base + "\n").encode()),
                         "publication_actual_git_object_changed")
                drafts = sum(method == "POST" and path.endswith("/pulls") for method, path, *_ in fixture.requests)
                blobs = sum(effect == "blob" for effect, _ in fixture.effects)
                _require(drafts == 1 and blobs == params["blobs"] and len(fixture.proposals) == 1
                         and fixture.proposals[0]["draft"] is True and not fixture.errors,
                         "publication_effect_count_changed")
                _require(replay["ready_for_review"] is False and replay["release_authorized"] is False,
                         "publication_authority_changed")
            facts = {
                "blobs": blobs, "changed_blob_bytes": params["total_bytes"],
                "final_children": len(case["inputs"]["children"]),
                "topology_comparison": "one child for one blob; two children for 32 blobs; not isolated blob-count causality",
                "candidate_sha256": candidate, "operation_sha256": replay["operation"],
                "commit_sha": replay["commit_sha"], "tree_sha": replay["tree_sha"],
                "draft_posts": drafts, "original_operation_recovered": True,
                "lost_draft_reply": params["lose_draft_reply"],
                "replay_created_effects": 0, "fixture_git_helper": git_observation,
                "impairment": {"added_delay_ms_per_request": params["delay_ms"],
                               "body_consumption_bytes_per_second": BODY_RATE,
                               "scope": "actual local HTTP serialized bodies, not WAN, TLS, headers or wire rate"},
                "canonical_authority": "synthetic fixture", "forge": "real local HTTP and Git fixture; no live forge",
            }
            recorder.fact("publication", facts)
            return facts


def run_case(case, workdir: Path, recorder, images, monkeypatch):
    """Execute exactly one declared lane; missing prerequisites fail, not skip."""
    workdir = Path(workdir)
    workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    kind, params = case["kind"], case["params"]
    if kind == "source":
        return _source_case(params, workdir, recorder)
    if kind == "capture":
        return _capture_case(case, params, workdir, recorder, images)
    if kind == "publication":
        return _publication_case(params, workdir, recorder, monkeypatch)
    raise ValueError("unsupported_artifact_case")
