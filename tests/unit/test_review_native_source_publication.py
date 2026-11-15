"""Real local Git, files and processes; HTTPS service is a controlled helper.

The helper replaces only Git's HTTPS transport with a local receive-pack. The
production argv, selected auth configuration, actual Git CAS/porcelain and
candidate objects are exercised. This is not real forge or Docker delivery.
"""
import base64
from dataclasses import replace
import hashlib
import json
import os
from pathlib import Path
import subprocess
import selectors
import sys
import tarfile
import tempfile
import threading
import time
import unittest
from unittest import mock

from tests.unit.review_native_fixture import archive_bytes, fixture, git
from src.worker.review_contract import ReviewError, ReviewCapture
from src.worker.review_capture import retain_stopped_capture
from src.worker.review_native import ReviewNativeBackend, GuestHandle
from src.git_manager.review_publication import (
    ReviewProcesses, auth_config, git_environment, publication_status, push_arguments,
)


class LocalFixture(unittest.TestCase):
    def setUp(self):
        self.temporary = tempfile.TemporaryDirectory()
        self.root = Path(self.temporary.name)
        self.claim, self.operation, self.saved, self.original = fixture(self.root)
        self.backend = ReviewNativeBackend(self.claim)

    def tearDown(self):
        if self.backend.operation is not None and not self.backend.retiring:
            self.backend.retire(self.operation)
        self.temporary.cleanup()

    def source(self):
        # Producer identity is tested separately through the counted HTTP port.
        self.backend.original_checked = True
        return self.backend.prepare_source(self.operation)

    def captured(self, source, patch):
        owned = GuestHandle("fixture-incarnation", "fixture-volume", {}, source,
                            container_id="d" * 64, stopped=True, stop_acknowledged=True)
        self.backend.original_guest = owned
        self.operation.note("guest", {"container_id": owned.container_id, "stopped": True, "local_closed": True})
        capture = retain_stopped_capture(self.backend.root / "capture", owned.incarnation, owned.container_id,
                                         archive_bytes(patch), self.claim.profile.limits,
                                         check=lambda: self.operation.check(cleanup=True), assert_safe=self.operation.assert_safe)
        self.backend.capture = capture
        self.operation.note("capture", {"retained_id": capture.retained_id, "container_id": owned.container_id,
                          "archive_sha256": capture.archive_sha256, "archive_bytes": capture.archive_bytes,
                          "patch_sha256": capture.patch_sha256, "patch_bytes": len(capture.patch),
                          "log_sha256": capture.log_sha256, "log_bytes": len(capture.log),
                          "manifest_sha256": capture.manifest_sha256, "durable": True, "termination_confirmed": True})
        return capture

    def candidate(self):
        source = self.source()
        (self.original / "hello.txt").write_text("corrected\n")
        patch = git(self.original, "diff", "--binary", "--full-index")
        capture = self.captured(source, patch)
        return self.backend.compose(self.operation, source, capture)


class SourceCaptureTests(LocalFixture):
    def test_original_commit_metadata_literal_refuses_before_snapshot_exposure(self):
        # Independent source review identified that the original commit itself
        # is guest-bound, even when every selected file and text context is safe.
        from tests.unit.review_native_fixture import freeze
        from src.worker.standalone_review import ReviewOperation
        for field in ("message", "author"):
            with self.subTest(field=field):
                case = self.root / field
                case.mkdir()
                claim, _, _, repository = fixture(case)
                selected = claim.credentials.forge["token"]
                git(repository, "-c", "user.name=" + (selected if field == "author" else "Fixture"),
                    "-c", "user.email=fixture@example.invalid", "commit", "--amend", "--reset-author",
                    "-m", "Original metadata " + (selected if field == "message" else "without a literal"))
                head = git(repository, "rev-parse", "HEAD").decode().strip()
                self.assertEqual(git(repository, "show", head + ":hello.txt"), b"original\n")
                self.assertIn(selected.encode(), git(repository, "cat-file", "commit", head))
                claim = replace(claim, original=freeze({**claim.original,
                    "review": {**claim.original["review"], "head_sha": head}}))
                operation, backend = ReviewOperation(claim), ReviewNativeBackend(claim)
                backend.original_checked = True
                try:
                    with self.assertRaises(ReviewError) as caught:
                        backend.prepare_source(operation)
                    self.assertEqual(caught.exception.code, "secret_in_data")
                    first = operation.snapshot()["first_failure"]
                    self.assertEqual(first["code"], "secret_in_data")
                    self.assertIsNone(backend.source)
                    self.assertIsNone(backend.original_guest)
                    self.assertEqual(operation.snapshot()["counters"]["git"], 1)
                    self.assertEqual(operation.snapshot()["counters"]["guest_api"], 0)
                    self.assertEqual(operation.snapshot()["counters"]["model"], 0)
                    self.assertEqual(len(backend.processes.originals), 1)
                    self.assertTrue(backend.processes.originals[0]["closed"])
                    self.assertTrue(list((backend.root / "sources").glob("export-*")))
                    self.assertFalse(list((backend.root / "sources").glob("*/manifest.json")))
                    self.assertNotIn(selected, json.dumps(operation.snapshot()))
                finally:
                    backend.retire(operation)
                self.assertEqual(operation.snapshot()["first_failure"], first)
                self.assertTrue(all(item["closed"] for item in backend.processes.originals))

    def test_original_commit_literal_scan_reuses_the_original_counted_read(self):
        original_scan = self.operation.assert_safe
        scanned = []
        def scan(value):
            scanned.append(value)
            return original_scan(value)
        with mock.patch.object(self.operation, "assert_safe", side_effect=scan):
            source = self.source()
        raw = git(source.handle.snapshot, "cat-file", "commit", source.base_sha)
        self.assertEqual(scanned[0], raw)
        self.assertEqual(sum(value == raw for value in scanned), 1)
        self.assertEqual(self.operation.snapshot()["counters"]["git"], 10)
        self.assertEqual(len(self.backend.processes.originals), 10)
        self.assertIsNone(self.operation.snapshot()["first_failure"])
        self.assertIn("original\n", source.context)

    def test_commit_scan_cannot_extend_the_original_git_effect_deadline(self):
        case = self.root / "scan-deadline"
        case.mkdir()
        now = [time.monotonic()]
        claim, operation, _, _ = fixture(case, clock=lambda: now[0])
        backend = ReviewNativeBackend(claim)
        backend.original_checked = True
        original_scan = operation.assert_safe
        def scan(value):
            original_scan(value)
            now[0] = backend.processes.originals[0]["effect"].deadline + .001
        try:
            with mock.patch.object(operation, "assert_safe", side_effect=scan):
                with self.assertRaises(ReviewError) as caught:
                    backend.prepare_source(operation)
            self.assertEqual(caught.exception.code, "deadline_exhausted")
            self.assertLess(now[0], operation.work_deadline)
            self.assertIsNone(backend.source)
            self.assertIsNone(backend.original_guest)
            self.assertEqual(operation.snapshot()["counters"]["git"], 1)
            self.assertTrue(backend.processes.originals[0]["closed"])
        finally:
            backend.retire(operation)

    def test_admitted_utf8_author_byte_ceilings_are_preserved(self):
        from tests.unit.review_native_fixture import freeze
        from src.worker.review_contract import ReviewProfile
        from src.worker.standalone_review import ReviewOperation
        author = {"name": "é" * 64, "email": "e" * 241 + "@example.test"}
        self.assertEqual(len(author["name"].encode()), 128)
        self.assertEqual(len(author["email"].encode()), 254)
        profile = ReviewProfile(freeze({**self.claim.profile.document, "commit_author": author}), "f" * 64)
        self.claim = replace(self.claim, profile=profile)
        self.operation = ReviewOperation(self.claim)
        self.backend = ReviewNativeBackend(self.claim)
        candidate = self.candidate()
        raw = git(candidate.handle.repository, "cat-file", "commit", candidate.commit_sha)
        self.assertIn(("author " + author["name"] + " <" + author["email"] + ">").encode(), raw)

    def test_original_export_ignores_dirty_worktree_and_host_configuration(self):
        sentinel = self.root / "host-hook-ran"
        git(self.original, "config", "core.fsmonitor", "touch " + str(sentinel))
        (self.original / "hello.txt").write_text("uncommitted\n")
        (self.original / "untracked-secret").write_text("not selected")
        source = self.source()
        self.assertIn("original\n", source.context)
        self.assertNotIn("uncommitted", source.context)
        self.assertNotIn("untracked-secret", source.context)
        self.assertFalse(sentinel.exists())
        self.assertEqual(git(source.handle.snapshot, "rev-parse", "HEAD").decode().strip(), source.base_sha)
        self.assertNotIn(b"fsmonitor", (source.handle.snapshot / "config").read_bytes())
        self.assertGreater(self.operation.snapshot()["counters"]["git"], 5)

    def test_source_object_budget_refuses_original_export(self):
        altered = dict(self.claim.profile.document)
        altered["limits"] = {**self.claim.profile.limits, "source_objects": 1}
        from tests.unit.review_native_fixture import freeze
        from src.worker.review_contract import ReviewProfile
        from src.worker.standalone_review import ReviewOperation
        claim = replace(self.claim, profile=ReviewProfile(freeze(altered), "f" * 64))
        backend, operation = ReviewNativeBackend(claim), ReviewOperation(claim)
        backend.original_checked = True
        with self.assertRaises(ReviewError):
            backend.prepare_source(operation)
        self.assertIsNone(backend.source)
        backend.retire(operation)

    def test_candidate_is_host_composed_with_sole_original_parent(self):
        candidate = self.candidate()
        raw = git(candidate.handle.repository, "cat-file", "commit", candidate.commit_sha)
        self.assertEqual([line for line in raw.splitlines() if line.startswith(b"parent ")],
                         [b"parent " + self.claim.original["review"]["head_sha"].encode()])
        self.assertEqual(git(candidate.handle.repository, "show", candidate.commit_sha + ":hello.txt"), b"corrected\n")
        self.assertEqual(candidate.tree_sha, git(candidate.handle.repository, "rev-parse", candidate.commit_sha + "^{tree}").decode().strip())
        self.assertNotIn(b"fixture-secret", raw)
        self.assertTrue((self.backend.capture.handle.directory / "archive.tar").is_file())

    def test_exact_handle_identity_refuses_reconstructed_capture(self):
        source = self.source()
        capture = self.captured(source, b"")
        with self.assertRaises(ReviewError):
            self.backend.compose(self.operation, source, replace(capture))
        self.assertIsNone(self.backend.candidate)

    def test_no_change_yields_no_commit_and_cannot_publish(self):
        source = self.source()
        candidate = self.backend.compose(self.operation, source, self.captured(source, b""))
        self.assertIsNone(candidate.commit_sha)
        with self.assertRaises(ReviewError):
            self.backend.publish(self.operation, candidate)
        self.assertFalse(self.backend.publish_attempted)

    def test_capture_refuses_links_duplicates_traversal_and_secret_with_raw_custody(self):
        cases = [(("workspace/run/link", b"", tarfile.SYMTYPE),),
                 (("workspace/run/change.patch", b"x", tarfile.REGTYPE),),
                 (("../escape", b"x", tarfile.REGTYPE),)]
        for index, extra in enumerate(cases):
            raw = archive_bytes(extra=extra)
            path = self.root / ("rejected-" + str(index))
            with self.assertRaises(ReviewError):
                retain_stopped_capture(path, "fixture", "d" * 64, raw, self.claim.profile.limits,
                                       check=lambda: None, assert_safe=lambda _: None)
            self.assertEqual((path / "archive.tar").read_bytes(), raw)
            self.assertFalse((path / "manifest.json").exists())
        raw = archive_bytes(log=self.claim.credentials.forge["token"].encode())
        path = self.root / "secret-refusal"
        with self.assertRaises(ReviewError) as caught:
            retain_stopped_capture(path, "fixture", "d" * 64, raw, self.claim.profile.limits,
                                   check=lambda: None, assert_safe=self.operation.assert_safe)
        self.assertEqual(caught.exception.code, "secret_in_data")
        self.assertEqual((path / "archive.tar").read_bytes(), raw)

    def test_capture_is_exclusive_private_and_fsynced_before_return(self):
        path = self.root / "capture"
        actual_fsync = os.fsync
        with mock.patch("src.worker.review_capture.os.fsync", wraps=actual_fsync) as sync:
            capture = retain_stopped_capture(path, "fixture", "d" * 64, archive_bytes(), self.claim.profile.limits,
                                             check=lambda: None, assert_safe=lambda _: None)
        self.assertGreaterEqual(sync.call_count, 8)
        self.assertEqual(path.stat().st_mode & 0o777, 0o700)
        self.assertEqual((path / "manifest.json").stat().st_mode & 0o777, 0o600)
        self.assertEqual(capture.manifest_sha256, hashlib.sha256((path / "manifest.json").read_bytes()).hexdigest())
        with self.assertRaises(FileExistsError):
            retain_stopped_capture(path, "fixture", "d" * 64, archive_bytes(), self.claim.profile.limits,
                                   check=lambda: None, assert_safe=lambda _: None)


class GitPublicationTests(LocalFixture):
    def transport(self, candidate):
        remote = self.root / "receiver.git"
        git(self.root, "init", "--bare", str(remote))
        git(self.original, "push", str(remote), "HEAD:refs/heads/topic")
        helper_root = self.root / "helper"
        helper_root.mkdir()
        evidence = self.root / "helper-observations.jsonl"
        # No remote URL substitution is passed to production. Only the test's
        # explicit HTTPS remote helper connects to this local Git receiver.
        script = f'''#!{sys.executable}
import base64, hashlib, json, os, subprocess, sys
url = sys.argv[-1]
header = subprocess.check_output(["git", "config", "--get-urlmatch", "http.extraHeader", url]).strip()
with open({str(evidence)!r}, "a") as stream:
    stream.write(json.dumps({{"url": url, "header_sha256": hashlib.sha256(header).hexdigest(), "arguments": sys.argv[1:]}}) + "\\n")
while True:
    line = sys.stdin.buffer.readline()
    if line == b"capabilities\\n":
        sys.stdout.buffer.write(b"connect\\n\\n"); sys.stdout.buffer.flush()
    elif line == b"connect git-receive-pack\\n":
        sys.stdout.buffer.write(b"\\n"); sys.stdout.buffer.flush()
        os.execv("/usr/bin/git", ["git", "receive-pack", {str(remote)!r}])
    else:
        raise SystemExit(3)
'''
        helper = helper_root / "git-remote-https"
        helper.write_text(script)
        helper.chmod(0o700)
        environment = {**git_environment(), "GIT_EXEC_PATH": str(helper_root)}
        auth = self.root / "fixed-auth.config"
        destination = self.claim.original["binding"]["clone_url"]
        auth_config(auth, destination, "fixture", self.claim.credentials.forge["token"])
        argv = push_arguments(candidate.handle.repository, auth, destination, candidate.commit_sha,
                              "refs/heads/topic", self.claim.original["review"]["head_sha"])
        return remote, evidence, environment, argv, auth

    def test_real_git_exact_lease_changed_ref_ack_and_no_update_are_distinct(self):
        candidate = self.candidate()
        remote, evidence, environment, argv, auth = self.transport(candidate)
        processes = self.backend.processes
        result = processes.run(argv, limit=20000, environment=environment)
        self.assertEqual(publication_status(result.stdout, result.exit_code, candidate.commit_sha,
                                            "refs/heads/topic", candidate.parent_sha), "acknowledged")
        self.assertEqual(git(remote, "rev-parse", "refs/heads/topic").decode().strip(), candidate.commit_sha)
        self.assertEqual(git(remote, "for-each-ref", "--format=%(refname)").splitlines(), [b"refs/heads/topic"])
        # A separate controlled operation observes an already-equal remote. It
        # is not a retry by the production backend or attribution to this push.
        second = subprocess.run(argv, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE)
        self.assertEqual(publication_status(second.stdout, second.returncode, candidate.commit_sha,
                                            "refs/heads/topic", candidate.parent_sha), "observed_no_update")
        rows = [json.loads(line) for line in evidence.read_text().splitlines()]
        expected = "Authorization: Basic " + base64.b64encode(("fixture:" + self.claim.credentials.forge["token"]).encode()).decode()
        self.assertEqual(rows[0]["header_sha256"], hashlib.sha256(expected.encode()).hexdigest())
        self.assertEqual(rows[0]["url"], self.claim.original["binding"]["clone_url"])
        self.assertEqual(auth.stat().st_mode & 0o777, 0o600)
        self.assertNotIn(self.claim.credentials.forge["token"], " ".join(argv))
        self.assertNotIn(self.claim.credentials.forge["token"], json.dumps(environment))

    def test_real_git_stale_original_head_refuses_without_remote_change(self):
        candidate = self.candidate()
        remote, evidence, environment, argv, _ = self.transport(candidate)
        (self.original / "hello.txt").write_text("concurrent\n")
        git(self.original, "add", "hello.txt")
        git(self.original, "-c", "user.name=Other", "-c", "user.email=other@example.invalid", "commit", "-m", "Concurrent")
        concurrent = git(self.original, "rev-parse", "HEAD").decode().strip()
        git(self.original, "push", str(remote), "HEAD:refs/heads/topic")
        result = self.backend.processes.run(argv, limit=20000, environment=environment)
        self.assertEqual(publication_status(result.stdout, result.exit_code, candidate.commit_sha,
                                            "refs/heads/topic", candidate.parent_sha), "refused")
        self.assertEqual(git(remote, "rev-parse", "refs/heads/topic").decode().strip(), concurrent)
        self.assertEqual(len(evidence.read_text().splitlines()), 1)

    def test_backend_publication_once_with_fixed_real_argv_and_actual_facts(self):
        candidate = self.candidate()
        remote, evidence, environment, _, _ = self.transport(candidate)
        self.backend.publication_checked = True
        self.operation.note("verification", {"observed": True, "exit_code": 0, "local_closed": True})
        with mock.patch("src.worker.review_native.git_environment", return_value=environment):
            result = self.backend.publish(self.operation, candidate)
            with self.assertRaises(ReviewError):
                self.backend.publish(self.operation, candidate)
        self.assertEqual(result.status, "acknowledged")
        self.assertEqual(len(evidence.read_text().splitlines()), 1)
        self.assertEqual(git(remote, "rev-parse", "refs/heads/topic").decode().strip(), candidate.commit_sha)
        self.assertEqual(self.operation.snapshot()["facts"]["publication"]["status"], "acknowledged")

    def test_first_backend_push_after_separate_actor_already_published_is_no_update(self):
        # Regression scenario contributed by the independent source review.
        candidate = self.candidate()
        remote, evidence, environment, argv, _ = self.transport(candidate)
        self.backend.publication_checked = True
        self.operation.note("verification", {"observed": True, "exit_code": 0, "local_closed": True})
        subprocess.run(argv, env=environment, stdout=subprocess.PIPE, stderr=subprocess.PIPE, check=True)
        before = len(evidence.read_text().splitlines())
        with mock.patch("src.worker.review_native.git_environment", return_value=environment):
            result = self.backend.publish(self.operation, candidate)
        self.assertEqual(result.status, "observed_no_update")
        self.assertEqual(self.operation.snapshot()["facts"]["publication"]["status"], "observed_no_update")
        self.assertEqual(len(evidence.read_text().splitlines()) - before, 1)
        self.assertEqual(git(remote, "rev-parse", "refs/heads/topic").decode().strip(), candidate.commit_sha)

    def test_lost_original_porcelain_after_actual_remote_change_stays_unknown(self):
        # Regression scenario contributed by the independent source review.
        candidate = self.candidate()
        remote, evidence, environment, _, _ = self.transport(candidate)
        self.backend.publication_checked = True
        self.operation.note("verification", {"observed": True, "exit_code": 0, "local_closed": True})
        actual_read, lost = os.read, []
        def lose_original(descriptor, length):
            raw = actual_read(descriptor, length)
            if b"\t" + candidate.commit_sha.encode() + b":refs/heads/topic\t" in raw:
                lost.append(True)
                raise OSError("controlled missing original reply")
            return raw
        with mock.patch("src.worker.review_native.git_environment", return_value=environment), \
             mock.patch("src.git_manager.review_publication.os.read", side_effect=lose_original):
            with self.assertRaises(ReviewError) as caught:
                self.backend.publish(self.operation, candidate)
        self.assertEqual(caught.exception.code, "publication_outcome_unknown")
        self.assertTrue(caught.exception.unknown)
        self.assertEqual(lost, [True])
        self.assertEqual(git(remote, "rev-parse", "refs/heads/topic").decode().strip(), candidate.commit_sha)
        self.assertEqual(self.operation.snapshot()["facts"]["publication"]["status"], "outcome_unknown")
        with self.assertRaises(ReviewError):
            self.backend.publish(self.operation, candidate)
        self.assertEqual(len(evidence.read_text().splitlines()), 1)
        self.backend.processes.retire()
        self.assertTrue(all(row["closed"] or not row["entered"] for row in self.backend.processes.originals))

    def test_late_porcelain_validation_retains_ack_without_restoring_authority(self):
        candidate = self.candidate()
        remote, evidence, environment, _, _ = self.transport(candidate)
        self.backend.publication_checked = True
        self.operation.note("verification", {"observed": True, "exit_code": 0, "local_closed": True})
        actual_status = publication_status
        def late(raw, code, commit, ref, head):
            status = actual_status(raw, code, commit, ref, head)
            original = next(row for row in self.backend.processes.originals if row["publication"])
            self.operation._clock = lambda: original["effect"].deadline + .001
            return status
        with mock.patch("src.worker.review_native.git_environment", return_value=environment), \
             mock.patch("src.worker.review_native.publication_status", side_effect=late):
            with self.assertRaises(ReviewError) as caught:
                self.backend.publish(self.operation, candidate)
        self.assertEqual(caught.exception.code, "deadline_exhausted")
        result = self.operation.snapshot()
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["facts"]["publication"]["status"], "acknowledged")
        self.assertTrue(result["facts"]["publication"]["late_acknowledged"])
        self.assertEqual(git(remote, "rev-parse", "refs/heads/topic").decode().strip(), candidate.commit_sha)
        self.assertEqual(len(evidence.read_text().splitlines()), 1)

    def test_auth_refuses_destination_username_and_token_injection(self):
        for destination, username, token in [("https://github.com/fixture/project?token=x", "fixture", "x"),
                                              ("https://github.com/fixture/project", "bad:name", "x"),
                                              ("https://github.com/fixture/project", "fixture", "x\nheader")]:
            with self.assertRaises(ReviewError):
                auth_config(self.root / "should-not-exist", destination, username, token)
        self.assertFalse((self.root / "should-not-exist").exists())


class ProcessCustodyTests(LocalFixture):
    def test_stdin_positive_and_post_select_expiry_or_revocation_use_original_cutoff(self):
        # Regression scenarios contributed by the independent source review.
        from src.worker.standalone_review import ReviewOperation
        for mode in ("positive", "expired", "revoked", "credential_revoked"):
            clock, revoked = [0.0], [False]
            def productive():
                if revoked[0] and mode == "revoked":
                    raise ReviewError("authority_changed")
            def credential():
                if revoked[0] and mode == "credential_revoked":
                    raise ReviewError("authority_changed")
            claim = replace(self.claim, started_at=0.0, validate_productive=productive)
            operation = ReviewOperation(claim, clock=lambda: clock[0])
            processes = ReviewProcesses(operation)
            original_selector, original_write = selectors.DefaultSelector, os.write
            selected, writes = [False], []
            class ControlledSelector:
                def __init__(self):
                    self.actual = original_selector()
                def __getattr__(self, name):
                    return getattr(self.actual, name)
                def select(self, timeout):
                    ready = self.actual.select(timeout)
                    if not selected[0] and any(key.data == "stdin" for key, _ in ready):
                        selected[0] = True
                        if mode == "expired":
                            clock[0] = 5.001
                        elif mode in {"revoked", "credential_revoked"}:
                            revoked[0] = True
                    return ready
            def observed_write(descriptor, raw):
                writes.append((clock[0], len(raw)))
                return original_write(descriptor, raw)
            received = self.root / (mode + ".received")
            command = [sys.executable, "-c", "import pathlib,sys;pathlib.Path(sys.argv[1]).write_bytes(sys.stdin.buffer.read())", str(received)]
            with mock.patch("src.git_manager.review_publication.selectors.DefaultSelector", ControlledSelector), \
                 mock.patch("src.git_manager.review_publication.os.write", side_effect=observed_write), \
                 mock.patch.object(claim.credentials, "validate_epoch", side_effect=credential):
                if mode == "positive":
                    result = processes.run(command, data=b"original", limit=1000, environment=git_environment())
                    self.assertEqual(result.exit_code, 0)
                else:
                    with self.assertRaises(ReviewError) as caught:
                        processes.run(command, data=b"original", limit=1000, environment=git_environment())
                    self.assertEqual(caught.exception.code, "deadline_exhausted" if mode == "expired" else "authority_changed")
            # Observe only this retained child. No replacement or renewed call.
            processes.originals[0]["process"].wait(timeout=5)
            processes.retire()
            self.assertEqual(received.read_bytes(), b"original" if mode == "positive" else b"")
            self.assertEqual(writes, [(0.0, 8)] if mode == "positive" else [])
            self.assertEqual(len(processes.originals), 1)
            self.assertTrue(processes.originals[0]["closed"])

    def test_actual_wait_return_after_original_cutoff_retains_exit_without_ack(self):
        from src.worker.standalone_review import ReviewOperation
        now = [0.0]
        operation = ReviewOperation(replace(self.claim, started_at=0.0), clock=lambda: now[0])
        processes = ReviewProcesses(operation)
        actual_popen = subprocess.Popen
        def launch(*args, **kwargs):
            child = actual_popen(*args, **kwargs)
            actual_wait = child.wait
            def late_wait(*arguments, **keywords):
                result = actual_wait(*arguments, **keywords)
                now[0] = 5.001
                return result
            child.wait = late_wait
            return child
        with mock.patch("src.git_manager.review_publication.subprocess.Popen", side_effect=launch):
            with self.assertRaises(ReviewError) as caught:
                processes.run([sys.executable, "-c", "print('original bytes')"], limit=1000, environment=git_environment())
        self.assertEqual(caught.exception.code, "deadline_exhausted")
        original = processes.originals[0]
        self.assertTrue(original["closed"])
        self.assertEqual(original["result"].stdout, b"original bytes\n")
        row = operation.snapshot()["effects"][0]
        self.assertTrue(row["closed"])
        self.assertTrue(row["outcome_unknown"])
        self.assertFalse(row["acknowledged"])
        self.assertEqual(row["data"]["exit_code"], 0)
        processes.retire()

    def test_bounded_real_process_output_retains_original_child_until_retirement(self):
        processes = ReviewProcesses(self.operation)
        with self.assertRaises(ReviewError) as caught:
            processes.run([sys.executable, "-c", "import sys;sys.stdout.write('x'*1000)"],
                          limit=16, environment=git_environment())
        self.assertEqual(caught.exception.code, "capacity_exhausted")
        self.assertIsNotNone(processes.originals[0]["process"])
        processes.retire()
        self.assertIsNotNone(processes.originals[0]["process"].poll())
        self.assertTrue(processes.originals[0]["closed"])
        self.assertEqual(self.operation.snapshot()["first_failure"]["code"], "capacity_exhausted")

    def test_launch_entry_exception_is_unknown_without_fabricated_closure(self):
        processes = ReviewProcesses(self.operation)
        with mock.patch("src.git_manager.review_publication.subprocess.Popen", side_effect=OSError("private launch text")):
            with self.assertRaises(ReviewError) as caught:
                processes.run(["git", "--version"], limit=1000, environment=git_environment(), publication=True)
        self.assertTrue(caught.exception.unknown)
        self.assertTrue(processes.originals[0]["entered"])
        self.assertFalse(processes.originals[0]["closed"])
        processes.retire()
        result = self.operation.snapshot()
        self.assertFalse(result["facts"]["cleanup"]["local_processes_closed"])
        self.assertTrue(result["facts"]["cleanup"]["resources_retained"])
        self.assertNotIn("private launch", json.dumps(result))

    def test_post_launch_persistence_failure_keeps_actual_handle_and_joins(self):
        processes = ReviewProcesses(self.operation)
        original_note = self.operation.note
        def note(group, values):
            if group == "publication":
                raise ReviewError("record_unavailable", unknown=True)
            return original_note(group, values)
        with mock.patch.object(self.operation, "note", side_effect=note):
            with self.assertRaises(ReviewError):
                processes.run([sys.executable, "-c", "import time;time.sleep(30)"], limit=1000,
                              environment=git_environment(), publication=True)
        original = processes.originals[0]["process"]
        self.assertIsNotNone(original)
        processes.retire()
        self.assertIsNotNone(original.poll())
        self.assertTrue(processes.originals[0]["closed"])

    def test_passive_join_after_total_expiry_keeps_callback_live_without_signal(self):
        from src.worker.standalone_review import ReviewOperation
        now = [0.0]
        operation = ReviewOperation(replace(self.claim, started_at=0.0), clock=lambda: now[0])
        processes = ReviewProcesses(operation)
        effect = operation.reserve("git")
        operation.invoke(effect, lambda: None)
        released, joined = threading.Event(), threading.Event()
        class HeldProcess:
            pid = 123456
            def poll(self):
                return 0 if released.is_set() else None
            def wait(self):
                released.wait()
                joined.set()
                return 0
        processes.originals.append({"effect": effect, "process": HeldProcess(), "entered": True,
                                    "closed": False, "signalled": False, "publication": False})
        now[0] = 61.0
        thread = threading.Thread(target=processes.retire)
        with mock.patch("src.git_manager.review_publication.os.killpg") as signal:
            thread.start()
            self.assertFalse(joined.wait(.05))
            self.assertTrue(thread.is_alive())
            self.assertFalse(operation.snapshot()["facts"]["cleanup"]["local_processes_closed"])
            released.set()
            thread.join(2)
            signal.assert_not_called()
        self.assertFalse(thread.is_alive())
        self.assertTrue(processes.originals[0]["closed"])


if __name__ == "__main__":
    unittest.main()
