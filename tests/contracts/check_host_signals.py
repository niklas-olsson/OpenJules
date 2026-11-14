"""Actual pinned Polyphony tool/ledger contract through an injected local caller.

This qualification does not implement or claim a connected production transport,
worker execution, live model, native service stack or browser demonstration.
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import secrets
import subprocess
import sys
import time
from unittest.mock import patch

POLYPHONY_REVISION = "6480e36355bf0d5de4e25a560d40e665fd76038c"
ROOT = Path(__file__).resolve().parents[2]


def revision(path):
    return subprocess.check_output(["git", "-C", str(path), "rev-parse", "HEAD"], text=True, timeout=10).strip()


def dirty(path):
    return bool(subprocess.check_output(
        ["git", "-C", str(path), "status", "--porcelain", "--untracked-files=no"], text=True, timeout=10).strip())


def run(args):
    started = time.monotonic()
    assert revision(args.polyphony_checkout) == POLYPHONY_REVISION, "producer revision differs from reviewed pin"
    assert not dirty(args.polyphony_checkout), "producer tracked tree differs from reviewed pin"
    assert not args.work_dir.exists(), "contract work directory must be fresh"
    args.work_dir.mkdir(mode=0o700, parents=True)
    host_key = secrets.token_hex(32)
    env = {key: value for key, value in os.environ.items() if key in {"PATH", "LANG", "LC_ALL", "TMPDIR"}}
    env.update(PYTHONNOUSERSITE="1", PYTHONDONTWRITEBYTECODE="1", SWARM_KEY="explicit-test-only-swarm",
               OPENJULES_HOST_KEY=host_key, LIMINAL_COLLAB_DB=str(args.work_dir / "producer.sqlite3"),
               LIMINAL_DB=str(args.work_dir / "unused-mesh.sqlite3"),
               LIMINAL_IDENTITY=str(args.work_dir / "unused-identity.pem"), LIMINAL_STORAGE_BACKEND="sqlite")
    calls = []
    report = {"schema": "openjules.standalone-signal-contract/v1", "passed": False,
              "openjules_revision": revision(ROOT), "polyphony_revision": POLYPHONY_REVISION,
              "checks": {}, "scope": "real producer tool functions, FastMCP encoding and temporary ledger; injected local caller only",
              "production_transport_qualified": False, "models_called": 0, "workers_executed": 0}
    report["openjules_tracked_tree_dirty"] = dirty(ROOT)
    report["consumer_files_sha256"] = {
        name: hashlib.sha256((ROOT / name).read_bytes()).hexdigest()
        for name in ("src/polyphony/outbox.py", "src/polyphony/controller.py", "src/polyphony/models.py",
                     "tests/contracts/check_host_signals.py", "tests/contracts/host_signal_producer.py")
    }
    report_path = args.work_dir / "report.json"

    def producer(request):
        remaining = started + 180 - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("contract deadline expired")
        result = subprocess.run(
            [str(args.polyphony_python), "-I", "-B", str(Path(__file__).with_name("host_signal_producer.py")),
             str(args.polyphony_checkout), str(args.work_dir)],
            cwd=args.work_dir, env=env, input=json.dumps(request).encode(),
            stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=min(30, remaining),
        )
        if time.monotonic() >= started + 180:
            raise TimeoutError("contract deadline expired")
        if result.returncode or len(result.stdout) > 262144 or len(result.stderr) > 65536:
            raise AssertionError("producer fixture failed or exceeded bounded output")
        return json.loads(result.stdout)

    def caller(name, arguments):
        calls.append(name)
        return producer({"operation": "call", "name": name, "arguments": arguments})

    try:
        setup = producer({"operation": "setup"})
        report["producer"] = setup | {"signal_ids": "fixture IDs omitted"}
        ids = setup["signal_ids"]
        before = producer({"operation": "inspect"})
        sys.path.insert(0, str(ROOT))
        from src.polyphony.outbox import McpOutboxBridge, OutboxError, OutboxOutcome
        from src.polyphony.controller import SwarmResourceController
        from src.polyphony.models import PolyphonyCohortConfig
        from src.polyphony.provisioner import MockContainerProvisioner
        # Any consumer SQL use fails. The separately executed producer owns its
        # explicitly created temporary ledger and native eligibility checks.
        with patch("sqlite3.connect", side_effect=AssertionError("consumer attempted foreign SQL")) as sql:
            bridge = McpOutboxBridge(host_key, caller)
            polled = bridge.poll_pending_signals()
            assert [item.signal_id for item in polled] == [ids["ordinary"]]
            assert polled[0].target_task_ids == ["ordinary"]
            report["checks"]["actual_tool_encoding_and_filtered_poll"] = "PASS"
            for label in ("managed-history", "malformed-history"):
                try:
                    bridge.acknowledge_signal(ids[label], "FULFILLED", "must refuse")
                except OutboxError as error:
                    assert error.outcome is OutboxOutcome.REFUSED
                else:
                    raise AssertionError("historical target acknowledged")
            assert producer({"operation": "inspect"}) == before
            report["checks"]["native_historical_target_refusal_and_unchanged_rows"] = "PASS"
            bad_key = McpOutboxBridge("deliberately-wrong-key", caller)
            try:
                bad_key.poll_pending_signals()
            except OutboxError as error:
                assert error.outcome is OutboxOutcome.REFUSED
            else:
                raise AssertionError("wrong host key accepted")
            report["checks"]["native_host_authentication_refusal"] = "PASS"
            provider = MockContainerProvisioner()
            config = PolyphonyCohortConfig(swarm_id="native-tool-fixture", repo_url="https://example.invalid/repo", base_worker_count=0)
            ctrl = SwarmResourceController(config, bridge, provider)
            outcome = ctrl.reconcile_signals()
            assert len(outcome) == 1 and outcome[0]["status"] == "FULFILLED"
            assert len(provider.list_active_workers()) == 1
            assert bridge.poll_pending_signals() == []
            after = producer({"operation": "inspect"})
            assert after["historical_rows"] == before["historical_rows"]
            assert after["statuses"][ids["ordinary"]] == "FULFILLED"
            report["checks"]["original_signal_id_new_status_ack_and_controller_fixture"] = "PASS"
            calls_before = len(calls)
            try:
                bridge.count_active_leases("fixture-worker")
            except OutboxError as error:
                assert error.outcome is OutboxOutcome.UNSUPPORTED
            else:
                raise AssertionError("invented idle observation")
            assert len(calls) == calls_before
            report["checks"]["missing_activity_is_unsupported_without_invented_tool"] = "PASS"
            sql.assert_not_called()
            report["checks"]["zero_consumer_sqlite_access"] = "PASS"
        assert not (args.work_dir / "unused-mesh.sqlite3").exists()
        assert not (args.work_dir / "unused-identity.pem").exists()
        report["producer_files_sha256"] = {
            name: hashlib.sha256((args.polyphony_checkout / name).read_bytes()).hexdigest()
            for name in ("src/liminal_bridge/server.py", "src/core/collaboration/ledger.py",
                         "src/core/collaboration/models.py", "src/core/collaboration/experimental_boundary.py")
        }
        if time.monotonic() >= started + 180:
            raise TimeoutError("contract deadline expired")
        report["passed"] = True
    except Exception as error:
        report["error_type"] = type(error).__name__
        raise
    finally:
        report["elapsed_seconds"] = round(time.monotonic() - started, 4)
        if report["elapsed_seconds"] > 180:
            report["passed"] = False
            report.setdefault("error_type", "TimeoutError")
        report["tool_calls"] = calls
        report["child_cleanup"] = "Each directly owned producer subprocess completed or subprocess.run timed out and reaped it; no descendant-process qualification."
        report_path.write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")
        print(json.dumps({"passed": report["passed"], "checks": report["checks"], "report": str(report_path)}, sort_keys=True))
    if not report["passed"]:
        raise RuntimeError("contract did not complete inside its limit")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--polyphony-checkout", type=Path, required=True)
    parser.add_argument("--polyphony-python", type=Path, required=True)
    parser.add_argument("--work-dir", type=Path, required=True)
    args = parser.parse_args()
    args.polyphony_checkout = args.polyphony_checkout.resolve(strict=True)
    args.polyphony_python = args.polyphony_python.absolute()
    args.work_dir = args.work_dir.absolute()
    run(args)


if __name__ == "__main__":
    main()
