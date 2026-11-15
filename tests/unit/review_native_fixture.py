"""Private local fixture construction; no Docker, forge or provider service."""
import copy
from dataclasses import replace
import hashlib
import io
import json
import os
from pathlib import Path
import subprocess
import tarfile
import time
from types import MappingProxyType

from src.worker.review_contract import ReviewClaim, ReviewProfile
from src.worker.standalone_review import ReviewOperation


def freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze(item) for item in value)
    return value


def git(directory, *arguments, data=None):
    return subprocess.run(["git", "-C", str(directory), *arguments], input=data,
                          stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True,
                          env={"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
                               "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_CONFIG_GLOBAL": "/dev/null"}).stdout


class Credentials:
    forge = MappingProxyType({"kind": "pat", "token": "fixture-secret-not-a-live-forge-token", "username": "fixture"})
    model_key = None
    literal_secrets = (forge["token"],)

    def validate_epoch(self):
        return None


def fixture(root, *, clock=None, limits=None):
    root = Path(root)
    source = root / "original"
    source.mkdir(mode=0o700)
    git(source, "init", "--initial-branch=topic")
    (source / "hello.txt").write_text("original\n")
    git(source, "add", "hello.txt")
    git(source, "-c", "user.name=Fixture", "-c", "user.email=fixture@example.invalid", "commit", "-m", "Original")
    base = git(source, "rev-parse", "HEAD").decode().strip()
    state = root / "state"
    state.mkdir(mode=0o700)
    values = {"total_ms": 60000, "cleanup_reserve_ms": 10000,
              "model_call_ms": 5000, "exec_call_ms": 5000, "guest_api_ms": 5000,
              "git_call_ms": 5000, "forge_call_ms": 5000, "agent_turns": 4, "model_calls": 8,
              "model_request_bytes": 20000, "model_request_total_bytes": 160000,
              "model_response_bytes": 4096, "model_response_total_bytes": 32768,
              "model_output_tokens_per_call": 128, "model_output_tokens_total": 1024,
              "exec_calls": 30, "exec_input_bytes": 20000, "exec_output_bytes": 8192,
              "exec_output_total_bytes": 245760, "guest_api_calls": 100, "guest_api_cleanup_calls": 6,
              "source_bytes": 1000000, "source_objects": 100, "context_bytes": 100000,
              "archive_bytes": 1000000, "patch_bytes": 20000, "log_bytes": 20000,
              "files": 200, "path_bytes": 512, "blob_bytes": 20000, "patch_records": 100,
              "object_bytes": 1000000, "object_count": 300, "git_calls": 256,
              "git_output_bytes": 1000000, "git_output_total_bytes": 256000000,
              "forge_response_bytes": 20000, "forge_response_total_bytes": 100000,
              "receipt_result_bytes": 4000000}
    values.update(limits or {})
    document = {"schema": "standalone-review-source-cas-v1", "limits": values,
                "source": {"repository_path": str(source), "state_root": str(state)},
                "guest": {"docker_endpoint": "unix://" + str(root / "docker.sock"), "docker_api_version": "1.45",
                          "image": "sha256:" + "a" * 64, "uid": 1000, "gid": 1000,
                          "memory_bytes": 134217728, "cpu_quota_us": 50000, "pids_limit": 32,
                          "test_command": "python3 -m unittest"},
                "commit_author": {"name": "Review Fixture", "email": "review@example.invalid"}}
    review_body = "@OpenJules Please correct the selected line."
    original = {"operation": "review.start", "request_digest": "a" * 64,
                "binding": {"binding_id": "fixture", "forge": "github", "repository": "fixture/project",
                            "repository_id": 7, "installation_id": 8,
                            "clone_url": "https://github.com/fixture/project.git", "default_branch": "main"},
                "review": {"pull_number": 3, "review_id": 9, "author_id": 10,
                           "branch": "topic", "head_ref": "refs/heads/topic", "head_sha": base,
                           "review_body": review_body, "instruction": "Correct the selected line.",
                           "body_sha256": hashlib.sha256(review_body.encode()).hexdigest(),
                           "pull_body": "A fixture change.",
                           "pull_body_sha256": hashlib.sha256(b"A fixture change.").hexdigest()}}
    saved = []
    selected_clock = clock or time.monotonic
    claim = ReviewClaim("fixture-operation", "fixture-owner", selected_clock(), freeze(original),
                        ReviewProfile(freeze(document), "b" * 64), "c" * 64, Credentials(),
                        lambda: None, lambda: None, lambda value: saved.append(copy.deepcopy(value)))
    return claim, ReviewOperation(claim, clock=selected_clock), saved, source


def archive_bytes(patch=b"", log=b"fixture output\n", extra=()):
    stream = io.BytesIO()
    with tarfile.open(fileobj=stream, mode="w", format=tarfile.USTAR_FORMAT) as archive:
        for name, content, kind in [("workspace/run/change.patch", patch, tarfile.REGTYPE),
                                    ("workspace/run/output.log", log, tarfile.REGTYPE), *extra]:
            member = tarfile.TarInfo(name)
            member.type, member.mode, member.size = kind, 0o600, len(content)
            archive.addfile(member, io.BytesIO(content) if kind == tarfile.REGTYPE else None)
    return stream.getvalue()


def producer_payloads(claim):
    original = claim.original["review"]
    repository = {"id": 7, "full_name": "fixture/project"}
    return ({"number": 3, "state": "open", "merged": False,
             "base": {"repo": repository}, "head": {"repo": repository, "ref": "topic", "sha": original["head_sha"]},
             "body": "Current eligible PR description."},
            {"id": 9, "user": {"id": 10}, "state": "CHANGES_REQUESTED", "commit_id": original["head_sha"],
             "body": original["review_body"]})
