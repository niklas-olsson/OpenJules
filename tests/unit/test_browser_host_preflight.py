"""Mocked host checks never perform the one native namespace/IPC trial."""

import copy
import importlib.util
import json
import os
from pathlib import Path
import subprocess
import tempfile
import unittest
from unittest.mock import Mock, patch


ROOT = Path(__file__).resolve().parents[2]
SPEC = importlib.util.spec_from_file_location("browser_host_preflight", ROOT / "tools/browser_host_preflight.py")
probe = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(probe)
MANIFEST = ROOT / "docs/browser-engine-evidence/2026-11-14-hosted-prerequisite-1/manifest.json"


def host():
    value = {key: item for key, item in probe.HOST.items() if not key.startswith("minimum_")}
    value.update(uid=1001, euid=1001, gid=1001, egid=1001,
                 available_memory_bytes=8589934592, free_storage_bytes=8589934592,
                 user_namespace=101, network_namespace=102)
    return value


def facts():
    return {"uid": 1001, "euid": 1001, "gid": 1001, "egid": 1001,
            "user_namespace": 201, "network_namespace": 202,
            "interfaces": ["lo"], "ipv4_routes": 0, "ipv6_reject_routes": 1,
            "uid_map": ["1001", "1001", "1"], "gid_map": ["1001", "1001", "1"],
            "resource_limits": {"address_space": [134217728] * 2, "cpu": [2] * 2,
                "file_descriptors": [32] * 2, "file_size": [1048576] * 2, "core": [0] * 2}}


def environment(raw):
    source = "a" * 40
    return {"GITHUB_REF": "refs/heads/qualification/browser-host/run/" + probe.digest(raw) + "-" + source,
            "GITHUB_SHA": source, "GITHUB_REPOSITORY": probe.REPOSITORY,
            "GITHUB_EVENT_NAME": "push", "BROWSER_HOST_EVENT_CREATED": "true",
            "GITHUB_RUN_ATTEMPT": "1", "GITHUB_ACTIONS": "true", "GITHUB_RUN_ID": "1234"}


class ManifestAndHostTests(unittest.TestCase):
    def test_frozen_manifest_matches_source_and_workflow(self):
        value = probe.checked_manifest(MANIFEST.read_bytes(), ROOT)
        self.assertEqual(value["source_base_commit"], "7135d0988dff050df63acb89f75562dafccacf79")

    def test_changed_fields_hashes_and_boolean_budget_refuse(self):
        original = json.loads(MANIFEST.read_text())
        for change in ("tool_sha256", "workflow_sha256", "extra", "boolean_budget", "image"):
            value = copy.deepcopy(original)
            if change == "boolean_budget":
                value["limits"]["namespace_children"] = True
            elif change == "image":
                value["host"]["image_version"] = "later"
            else:
                value[change] = "0" * 64
            with self.subTest(change=change), self.assertRaises(probe.Refused):
                probe.checked_manifest(probe.encoded(value), ROOT)

    def test_duplicate_float_and_deep_json_refuse(self):
        for raw in (b'{"a":1,"a":1}', b'{"a":1.0}', b'{"a":NaN}'):
            with self.subTest(raw=raw[:20]), self.assertRaises(probe.Refused):
                probe.strict_json(raw)
        with self.assertRaises(probe.Refused):
            probe.checked_manifest(b"[" * 1500 + b"0" + b"]" * 1500, ROOT)

    def test_only_immutable_new_branch_first_attempt_can_arm(self):
        raw = MANIFEST.read_bytes()
        original = environment(raw)
        self.assertEqual(probe.ci_identity(original, probe.digest(raw))["workflow_run_attempt"], 1)
        for key, changed in (("GITHUB_REF", "refs/heads/review"), ("GITHUB_SHA", "b" * 40),
                             ("GITHUB_RUN_ATTEMPT", "2"), ("GITHUB_EVENT_NAME", "pull_request"),
                             ("BROWSER_HOST_EVENT_CREATED", "false"), ("GITHUB_REPOSITORY", "other/repo")):
            value = dict(original, **{key: changed})
            with self.subTest(key=key), self.assertRaises(probe.Refused):
                probe.ci_identity(value, probe.digest(raw))

    def test_changed_host_root_or_resources_refuse_before_child(self):
        raw = MANIFEST.read_bytes()
        for key, changed in (("image_version", "later"), ("python_version", "3.12.4"),
                             ("euid", 0), ("gid", 0), ("free_storage_bytes", 1),
                             ("available_memory_bytes", 1)):
            value = dict(host(), **{key: changed})
            with self.subTest(key=key), tempfile.TemporaryDirectory() as directory, \
                    patch.object(probe, "host_observation", return_value=value), \
                    patch.object(probe, "run_probe") as run:
                result = probe.execute(raw, ROOT, Path(directory), environment(raw))
            run.assert_not_called()
            self.assertEqual(result["status"], "changed_input")
            self.assertEqual(result["host"][key], changed)
            self.assertEqual(result["effects"]["namespace_child_attempts"], 0)
            self.assertEqual(result["browser_sandbox"], "NOT_RUN")

    def test_unclassified_exception_does_not_hide_unknown_cleanup(self):
        raw = MANIFEST.read_bytes()
        def failed_probe(_directory, _host, result):
            result.update(status="unknown", reason="owned_cleanup_unknown")
            raise RuntimeError("synthetic failure after uncertain cleanup")
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe, "host_observation", return_value=host()), \
                patch.object(probe, "executable_record", return_value={}), \
                patch.object(probe, "process_sample", return_value={}), \
                patch.object(probe, "run_probe", side_effect=failed_probe):
            result = probe.execute(raw, ROOT, Path(directory), environment(raw))
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "owned_cleanup_unknown")
        self.assertEqual(result["error_type"], "RuntimeError")


class ProbeProtocolTests(unittest.TestCase):
    def run_mocked(self, *, changed=None, sample=None, cleanup=None, read_failure=None, delay=None):
        child = Mock(pid=321, returncode=0)
        child.poll.return_value = None
        child.stdin.write.return_value = 1
        ready = {"phase": "ready", "pid": 321, "facts": facts(), "unix_socket_objects": 3, "unix_payload_bytes": 16}
        if changed:
            changed(ready)
        complete = {"phase": "complete", "status": "observed", "reason": "host_prerequisites_observed",
                    "sockets_created": 3, "sockets_closed": 3, "socket_path_absent": True, "facts": ready["facts"]}
        result = {"status": "refused", "effects": {"namespace_children": 0, "namespace_child_attempts": 0}}
        cleanup = cleanup or {"child_reaped": True, "exit_code": 0, "termination": "none"}
        sample = sample or {"pid": 321, "parent_pid": os.getpid(), "start_ticks": 456, "rss_bytes": 1048576, "uids": [1001] * 4}
        clock = Mock(return_value=100)
        messages = iter([ready, complete])
        child.observed_deadlines = []
        def spawn_child(*args, **kwargs):
            if delay == "spawn":
                clock.return_value = 106
            return child
        def receive(_child, deadline):
            child.observed_deadlines.append(deadline)
            if read_failure:
                raise read_failure
            message = next(messages)
            if delay == "completion" and message["phase"] == "complete":
                clock.return_value = 106
            return message
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe.time, "monotonic", clock), \
                patch.object(probe.subprocess, "Popen", side_effect=spawn_child) as spawn, \
                patch.object(probe, "read_message", side_effect=receive), \
                patch.object(probe, "process_sample", return_value=sample), \
                patch.object(probe, "cleanup_child", return_value=cleanup):
            probe.run_probe(Path(directory), host(), result)
        return result, spawn, child

    def test_one_fixed_child_minimal_environment_and_real_process_observation(self):
        result, spawn, child = self.run_mocked()
        spawn.assert_called_once()
        command = spawn.call_args.args[0]
        self.assertEqual(command[:8], ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--", "/usr/bin/python3", "-I", "-S"])
        self.assertEqual(spawn.call_args.kwargs["env"], {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"})
        self.assertTrue(spawn.call_args.kwargs["close_fds"])
        self.assertEqual(result["live_process_observation"]["start_ticks"], 456)
        child.stdin.write.assert_called_once_with(b"X")
        self.assertEqual(result["status"], "observed")
        self.assertTrue(result["cleanup"]["child_reaped"])

    def test_spawn_and_completed_reap_share_one_absolute_child_deadline(self):
        for delayed_stage in ("spawn", "completion"):
            with self.subTest(delayed_stage=delayed_stage):
                result, spawn, child = self.run_mocked(delay=delayed_stage)
                spawn.assert_called_once()
                self.assertEqual(child.observed_deadlines, [105, 105])
                self.assertEqual(result["status"], "refused")
                self.assertEqual(result["reason"], "child_completion_deadline")
                self.assertEqual(result["child_elapsed_ms"], 6000)
                self.assertEqual(child.wait.call_args.kwargs, {"timeout": 0})
                self.assertTrue(result["cleanup"]["child_reaped"])

    def test_namespace_route_map_limits_and_boolean_counts_are_validated(self):
        changes = [lambda item: item.update(unix_payload_bytes=True),
                   lambda item: item["facts"].update(uid=0),
                   lambda item: item["facts"].update(network_namespace=102),
                   lambda item: item["facts"].update(user_namespace=None),
                   lambda item: item["facts"].update(interfaces=["lo", "eth0"]),
                   lambda item: item["facts"].update(ipv4_routes=True),
                   lambda item: item["facts"].update(uid_map=["0", "1001", "1"]),
                   lambda item: item["facts"].update(resource_limits={})]
        for change in changes:
            result, spawn, child = self.run_mocked(changed=change)
            self.assertEqual(result["status"], "refused")
            spawn.assert_called_once()
            child.stdin.write.assert_not_called()

    def test_changed_live_process_uid_refuses_release(self):
        result, _, child = self.run_mocked(sample={"uids": [0] * 4})
        self.assertEqual(result["reason"], "live_child_identity_unavailable")
        child.stdin.write.assert_not_called()

    def test_cleanup_unknown_cannot_become_observed_or_refused(self):
        result, _, _ = self.run_mocked(cleanup={"child_reaped": False, "exit_code": None, "termination": "kill"})
        self.assertEqual(result["status"], "unknown")
        self.assertEqual(result["reason"], "owned_cleanup_unknown")

    def test_native_denial_keeps_exact_bounded_stderr_and_no_retry(self):
        result, spawn, child = self.run_mocked(
            read_failure=probe.Refused("child_pipe_incomplete"),
            cleanup={"child_reaped": True, "exit_code": 1, "termination": "none",
                     "stderr": "unshare: unshare failed: Operation not permitted\n", "stderr_truncated": False})
        self.assertEqual(result["status"], "refused")
        self.assertIn("Operation not permitted", result["cleanup"]["stderr"])
        spawn.assert_called_once()
        child.stdin.write.assert_not_called()

    def test_interrupted_spawn_retains_unknown_child_count(self):
        result = {"status": "refused", "effects": {"namespace_children": 0}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe.subprocess, "Popen", side_effect=probe.Deadline):
            probe.run_probe(Path(directory), host(), result)
        self.assertEqual(result["status"], "unknown")
        self.assertIsNone(result["effects"]["namespace_children"])

    def test_cleanup_interruption_retains_unknown(self):
        child = Mock(pid=321)
        result = {"status": "refused", "effects": {}}
        with tempfile.TemporaryDirectory() as directory, \
                patch.object(probe.subprocess, "Popen", return_value=child), \
                patch.object(probe, "read_message", side_effect=probe.Refused("child_pipe_incomplete")), \
                patch.object(probe, "cleanup_child", side_effect=probe.Deadline):
            with self.assertRaises(probe.Deadline):
                probe.run_probe(Path(directory), host(), result)
        self.assertEqual(result["status"], "unknown")

    def test_cleanup_escalates_once_and_each_wait_is_bounded(self):
        child = Mock(returncode=None)
        child.poll.return_value = None
        child.wait.side_effect = subprocess.TimeoutExpired("fixed-child", 1)
        result = probe.cleanup_child(child)
        child.terminate.assert_called_once_with()
        child.kill.assert_called_once_with()
        self.assertEqual([call.kwargs for call in child.wait.call_args_list], [{"timeout": 1}, {"timeout": 1}])
        self.assertFalse(result["child_reaped"])


class ProcAndPipeTests(unittest.TestCase):
    def test_route_and_mapping_observations_refuse_external_or_root_mapping(self):
        clean = {"/proc/net/route": b"Iface Destination\n",
                 "/proc/net/ipv6_route": b"0000 00 0000 00 0000 ffffffff 00000001 00000000 00200200 lo\n",
                 "/proc/self/uid_map": b"1001 1001 1\n", "/proc/self/gid_map": b"1001 1001 1\n"}
        def inspect(values, interfaces):
            with patch.object(probe.os, "getuid", return_value=1001), \
                    patch.object(probe.os, "geteuid", return_value=1001), \
                    patch.object(probe.os, "getgid", return_value=1001), \
                    patch.object(probe.os, "getegid", return_value=1001), \
                    patch.object(probe.os, "stat", side_effect=[Mock(st_ino=201), Mock(st_ino=202)]), \
                    patch.object(probe.socket, "if_nameindex", return_value=interfaces), \
                    patch.object(probe, "read_bounded", side_effect=lambda path, *args: values[path]):
                return probe.namespace_facts(101, 102, 1001, 1001)
        self.assertEqual(inspect(clean, [(1, "lo")])["ipv6_reject_routes"], 1)
        for changed in ({"/proc/net/route": b"Iface Destination\neth0 00000000\n"},
                        {"/proc/net/ipv6_route": b"0000 00 0000 00 0000 0 0 0 00000001 lo\n"},
                        {"/proc/self/uid_map": b"0 1001 1\n"}):
            with self.subTest(changed=changed), self.assertRaises(probe.Refused):
                inspect(dict(clean, **changed), [(1, "lo")])
        with self.assertRaises(probe.Refused):
            inspect(clean, [(1, "lo"), (2, "eth0")])

    def test_pid_reuse_or_parent_change_cannot_validate_rss(self):
        def stat_line(start, parent=50):
            fields = ["S", str(parent)] + ["0"] * 17 + [str(start)]
            return ("321 (fixed child) " + " ".join(fields) + "\n").encode()
        status = b"Pid:\t321\nPPid:\t50\nUid:\t1001 1001 1001 1001\nVmRSS:\t123 kB\n"
        for last in (stat_line(457), stat_line(456, parent=51)):
            with patch.object(probe, "read_bounded", side_effect=[stat_line(456), status, last]), self.assertRaises(probe.Refused):
                probe.process_sample(321, 50)
        with patch.object(probe, "read_bounded", side_effect=[stat_line(456), status, stat_line(456)]):
            self.assertEqual(probe.process_sample(321, 50)["rss_bytes"], 123 * 1024)

    def test_pipe_size_and_deadline_are_finite(self):
        child = Mock()
        selector = Mock()
        selector.__enter__ = Mock(return_value=selector)
        selector.__exit__ = Mock(return_value=False)
        selector.select.return_value = [True]
        with patch.object(probe.selectors, "DefaultSelector", return_value=selector), \
                patch.object(probe.os, "read", side_effect=[b"x" * 4096, b"x"]) as read:
            with self.assertRaisesRegex(probe.Refused, "child_pipe_oversized"):
                probe.read_message(child, probe.time.monotonic() + 1)
            self.assertEqual(read.call_args_list[-1].args[1], 1)
        selector.select.return_value = []
        with patch.object(probe.selectors, "DefaultSelector", return_value=selector):
            with self.assertRaisesRegex(probe.Refused, "child_pipe_deadline"):
                probe.read_message(child, probe.time.monotonic() + 1)


class ReceiptCompletionTests(unittest.TestCase):
    def complete(self):
        return {"schema_version": 1, "scope": "native-host-prerequisites-only", "receipt_complete": True,
                "manifest_sha256": "b" * 64, "source_commit": "a" * 40, "status": "observed",
                "cleanup": {"child_reaped": True, "socket_path_absent": True},
                "effects": {"namespace_children": 1, "namespace_child_attempts": 1},
                "child_elapsed_ms": 20.5, "elapsed_ms": 50.7}

    def classify(self, code, value):
        raw = probe.encoded(value) if value is not None else None
        return probe.classify_wrapper(code, raw, "b" * 64, "a" * 40)

    def test_complete_receipt_requires_agreeing_successful_supervisor(self):
        self.assertEqual(self.classify(0, self.complete())["status"], "observed")
        for exit_code in (124, 137, 143, 1, 3):
            with self.subTest(exit_code=exit_code):
                value = self.classify(exit_code, self.complete())
                self.assertEqual(value["status"], "unknown")
                self.assertEqual(value["owned_child_cleanup"], "unknown")

    def test_missing_incomplete_changed_or_contradictory_receipt_stays_unknown(self):
        variants = [None, {"status": "observed"}, dict(self.complete(), receipt_complete=False),
                    dict(self.complete(), manifest_sha256="c" * 64), dict(self.complete(), source_commit="c" * 40),
                    dict(self.complete(), cleanup={"child_reaped": False, "socket_path_absent": True}),
                    dict(self.complete(), effects={"namespace_children": True}),
                    dict(self.complete(), child_elapsed_ms=5000.001), dict(self.complete(), elapsed_ms=15000.001)]
        for value in variants:
            with self.subTest(value=value):
                self.assertEqual(self.classify(0, value)["status"], "unknown")
        for raw in (b'{"status":', b'{"status":"observed","elapsed_ms":1e999}'):
            self.assertEqual(probe.classify_wrapper(0, raw, "b" * 64, "a" * 40)["status"], "unknown")

    def test_complete_refusal_and_unknown_remain_distinct(self):
        refused = dict(self.complete(), status="refused")
        self.assertEqual(self.classify(3, refused)["status"], "refused")
        changed = dict(self.complete(), status="changed_input", cleanup=None,
                       effects={"namespace_child_attempts": 0, "namespace_children": 0})
        value = self.classify(3, changed)
        self.assertEqual(value["status"], "changed_input")
        self.assertEqual(value["owned_child_cleanup"], "not_started")
        self.assertEqual(self.classify(3, dict(self.complete(), status="unknown"))["status"], "unknown")

    def test_refusal_requires_confirmed_cleanup_or_exact_zero_attempts_and_children(self):
        value = dict(self.complete(), status="refused", cleanup={"child_reaped": False, "socket_path_absent": False})
        self.assertEqual(self.classify(3, value)["status"], "unknown")
        for effects in ({"namespace_child_attempts": 0},
                        {"namespace_child_attempts": 0, "namespace_children": 1},
                        {"namespace_child_attempts": 0, "namespace_children": None},
                        {"namespace_child_attempts": 0, "namespace_children": False},
                        {"namespace_child_attempts": False, "namespace_children": 0}):
            with self.subTest(effects=effects):
                self.assertEqual(self.classify(3, dict(value, effects=effects))["status"], "unknown")
        self.assertEqual(self.classify(3, dict(value, effects={"namespace_child_attempts": 0, "namespace_children": 0}))["owned_child_cleanup"], "not_started")

    def test_initial_marker_is_exclusive_and_survives_failed_final_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            probe.reserve_output(output, b"manifest")
            initial = output.read_bytes()
            value = json.loads(initial)
            self.assertEqual(value["status"], "unknown")
            self.assertFalse(value["receipt_complete"])
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)
            with self.assertRaises(FileExistsError):
                probe.reserve_output(output, b"replacement")
            with patch.object(probe.os, "fsync", side_effect=OSError("synthetic final fsync failure")):
                with self.assertRaises(OSError):
                    probe.complete_output(output, self.complete())
            self.assertEqual(output.read_bytes(), initial)

    def test_final_receipt_is_atomically_completed_after_fsync(self):
        with tempfile.TemporaryDirectory() as directory:
            output = Path(directory) / "report.json"
            probe.reserve_output(output, b"manifest")
            probe.complete_output(output, self.complete())
            self.assertTrue(json.loads(output.read_bytes())["receipt_complete"])
            self.assertFalse(output.with_name("report.pending").exists())
            self.assertEqual(output.stat().st_mode & 0o777, 0o600)


if __name__ == "__main__":
    unittest.main()
