"""The prerequisite command must never turn a refusal into browser authority."""

import copy
import importlib.util
import json
from pathlib import Path
import subprocess
from unittest.mock import Mock

import pytest


ROOT = Path(__file__).resolve().parents[2]
spec = importlib.util.spec_from_file_location(
    "browser_engine_preflight", ROOT / "tools/browser_engine_preflight.py"
)
preflight = importlib.util.module_from_spec(spec)
spec.loader.exec_module(preflight)
MANIFEST = ROOT / "docs/browser-engine-evidence/2026-11-14-host-1/manifest.json"


def manifest():
    return json.loads(MANIFEST.read_text())


def arrange(monkeypatch, *, effective_uid=1000, candidate_reason="expected_cache_binary_missing"):
    data = manifest()
    monkeypatch.setattr(preflight, "inspect_host", lambda: data["host"])
    monkeypatch.setattr(preflight.os, "getuid", lambda: 1000)
    monkeypatch.setattr(preflight.os, "geteuid", lambda: effective_uid)
    monkeypatch.setattr(
        preflight,
        "inspect_candidate",
        lambda _: {
            "status": "refused" if candidate_reason.endswith("missing") else "observed",
            "reason": candidate_reason,
        },
    )
    probe = Mock(return_value={"status": "observed", "children_started": 1})
    monkeypatch.setattr(preflight, "namespace_probe", probe)
    return data, probe


def test_effective_root_cannot_run_probe(monkeypatch):
    data, probe = arrange(monkeypatch, effective_uid=0)
    report = preflight.collect(data, "a" * 64)
    probe.assert_not_called()
    assert report["decision"] == "no_go_selected_host"
    assert report["checks"]["nonroot"]["status"] == "refused"


def test_missing_browser_stays_no_go_even_when_namespace_succeeds(monkeypatch):
    data, probe = arrange(monkeypatch)
    report = preflight.collect(data, "a" * 64)
    probe.assert_called_once_with()
    assert report["decision"] == "no_go_selected_host"
    assert report["effects"]["browser_sessions"] == 0
    assert "fixture_journeys" in report["not_run"]


def test_observed_prerequisites_never_authorize_launch(monkeypatch):
    data, _ = arrange(monkeypatch, candidate_reason="expected_cache_binary_present_not_verified")
    report = preflight.collect(data, "a" * 64)
    assert report["decision"] == "prerequisites_observed_only"
    assert report["browser_launch_authorized"] is False
    assert report["managed_execution_qualified"] is False
    assert "chromium_sandbox_verification" in report["not_run"]


def test_changed_host_and_metadata_cannot_run_child(monkeypatch):
    data, probe = arrange(monkeypatch)
    changed = copy.deepcopy(data)
    changed["host"]["kernel"] = "changed"
    preflight.collect(changed, "a" * 64)
    probe.assert_not_called()
    monkeypatch.setattr(preflight, "inspect_candidate", lambda _: {"status": "refused", "reason": "browser_metadata_mismatch"})
    preflight.collect(data, "a" * 64)
    probe.assert_not_called()


@pytest.mark.parametrize("change", ["tool", "fixture", "boolean_budget", "new_field"])
def test_changed_inputs_refuse_before_probe(tmp_path, monkeypatch, change):
    data = manifest()
    if change == "tool":
        data["tool_sha256"] = "0" * 64
    elif change == "fixture":
        data["fixtures"][preflight.FIXTURES[0]] = "0" * 64
    elif change == "boolean_budget":
        data["limits"]["namespace_children"] = True
    else:
        data["unexpected"] = "ignored fields must not become approvals"
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(data))
    probe = Mock(side_effect=AssertionError("must not launch"))
    monkeypatch.setattr(preflight, "namespace_probe", probe)
    with pytest.raises(preflight.InvalidInput):
        preflight.load_manifest(path)
    probe.assert_not_called()


def test_deep_and_duplicate_json_are_bounded_refusals(tmp_path):
    path = tmp_path / "manifest.json"
    for text in ('[' * 1500 + '0' + ']' * 1500, '{"schema_version":1,"schema_version":1}'):
        path.write_text(text)
        with pytest.raises(preflight.InvalidInput):
            preflight.load_manifest(path)


def test_existing_report_and_symlink_are_not_replaced(tmp_path):
    original = tmp_path / "receipt.json"
    preflight.write_report(original, {"kept": True})
    before = original.read_bytes()
    with pytest.raises(FileExistsError):
        preflight.reserve_report(original)
    alias = tmp_path / "alias.json"
    alias.symlink_to(original)
    with pytest.raises(FileExistsError):
        preflight.reserve_report(alias)
    assert original.read_bytes() == before
    assert original.stat().st_mode & 0o777 == 0o600


def test_child_output_is_discarded_and_timeout_reaping_is_bounded(monkeypatch):
    child = Mock()
    child.wait.side_effect = [subprocess.TimeoutExpired("unshare", 5), 0]
    spawn = Mock(return_value=child)
    monkeypatch.setattr(preflight.subprocess, "Popen", spawn)
    report = preflight.namespace_probe()
    assert report["status"] == "refused"
    assert report["child_reaped"] is True
    assert child.wait.call_args_list[0].kwargs == {"timeout": 5}
    assert child.wait.call_args_list[1].kwargs == {"timeout": 1}
    child.kill.assert_called_once_with()
    assert spawn.call_args.kwargs["stdout"] == subprocess.DEVNULL
    assert spawn.call_args.kwargs["stderr"] == subprocess.DEVNULL
    assert set(spawn.call_args.kwargs["env"]) == {"PATH", "LANG", "LC_ALL"}


def test_uncertain_reaping_is_not_reported_as_cleanup_success(monkeypatch):
    child = Mock()
    child.wait.side_effect = subprocess.TimeoutExpired("unshare", 1)
    monkeypatch.setattr(preflight.subprocess, "Popen", Mock(return_value=child))
    report = preflight.namespace_probe()
    assert report["reason"] == "namespace_cleanup_unknown"
    assert report["child_reaped"] is False


def test_overall_deadline_cleans_child_without_context_wait(monkeypatch):
    child = Mock()
    child.wait.side_effect = [TimeoutError("overall"), 0]
    monkeypatch.setattr(preflight.subprocess, "Popen", Mock(return_value=child))
    with pytest.raises(TimeoutError):
        preflight.namespace_probe()
    child.kill.assert_called_once_with()
    assert child.wait.call_args_list[-1].kwargs == {"timeout": 1}
