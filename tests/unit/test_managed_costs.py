"""Measurement admission and process-observation failure behavior."""

from copy import deepcopy
import json
import os
from pathlib import Path
import subprocess
import sys

import pytest

from tools.managed_costs import (
    BudgetStop, custody_report, discover_owned_containers, mark_container_terminal, ordered_cases, ownership_hooks, proc_stat, register_container, resource_summary,
    sample_owned, validate_manifest,
)
from tools.managed_cost_cases import expected_tree, retained_tree


def manifest():
    return json.loads((Path(__file__).parents[1] / "fixtures/managed-cost-manifest.json").read_text())


def test_module_cli_overhead_keeps_cancellation_and_ownership_identity(tmp_path):
    root = Path(__file__).resolve().parents[2]
    probe = tmp_path / "probe"
    probe.mkdir()
    identity_file = tmp_path / "identity.json"
    # Observe the real -m entry after its normal execution. Importing through a
    # runpy wrapper would change the module lifetime this regression protects.
    (probe / "sitecustomize.py").write_text(
        "import atexit, json, sys\n"
        "from pathlib import Path\n"
        "def observe_identity():\n"
        "    main = sys.modules['__main__']\n"
        "    canonical = sys.modules['tools.managed_costs']\n"
        "    cases = sys.modules['tools.managed_cost_cases']\n"
        "    facts = {\n"
        "        'module': canonical is main,\n"
        "        'stop': cases.STOP is main.STOP,\n"
        "        'budget_stop': cases.BudgetStop is main.BudgetStop,\n"
        "        'ownership_lock': canonical._OWNERSHIP_LOCK is main._OWNERSHIP_LOCK,\n"
        "        'registration': canonical.register_container is main.register_container,\n"
        "    }\n"
        f"    Path({str(identity_file)!r}).write_text(json.dumps(facts))\n"
        "atexit.register(observe_identity)\n"
    )
    case = next(row for row in manifest()["cases"] if row["kind"] == "overhead") | {"sample": 1}
    case_file = tmp_path / "case.json"
    case_file.write_text(json.dumps(case))
    workdir = tmp_path / "sample"
    result = subprocess.run(
        [sys.executable, "-m", "tools.managed_costs", "_case", "--case", str(case_file), "--work-dir", str(workdir)],
        cwd=root,
        env=os.environ | {"PYTHONPATH": os.pathsep.join((str(probe), str(root)))},
        capture_output=True, text=True, timeout=20,
    )
    assert result.returncode == 0, result.stderr
    report = json.loads((workdir / "sample.json").read_text())
    assert report["status"] == "PASS" and report["measurements"]["complete"]
    assert report["custody_unresolved"] is False
    assert json.loads(identity_file.read_text()) == {
        "module": True, "stop": True, "budget_stop": True,
        "ownership_lock": True, "registration": True,
    }


def test_reviewed_manifest_reserves_actual_finite_transfer_and_storage():
    value = validate_manifest(manifest())
    assert len(value["cases"]) == 18
    assert sum(row["samples"] for row in value["cases"]) == 66
    assert sum(row["samples"] * row["max_transfer_bytes"] for row in value["cases"]) == 179306496
    assert sum(row["samples"] * row["max_storage_bytes"] for row in value["cases"]) == 3272605696
    assert sum(row["samples"] * row["limit_seconds"] for row in value["cases"]) == 3665
    order = ordered_cases(value)
    first = [row["id"] for row in order if row["sample"] == 1]
    second = [row["id"] for row in order if row["sample"] == 2]
    assert second == list(reversed([row["id"] for row in value["cases"] if row["samples"] >= 2]))
    assert first.index("root") < first.index("root-observer-control")
    assert second.index("root-observer-control") < second.index("root")
    assert order[-1]["id"] == "installed-idle" and order[-1]["sample"] == 1
    assert len(order[:-1]) == 65 and all(row["kind"] != "installed_idle" for row in order[:-1])


@pytest.mark.parametrize("mutate", [
    lambda m: m["caps"].update(workers=3),
    lambda m: m["cases"][0].update(samples=True),
    lambda m: m["cases"][0].update(limit_seconds=0),
    lambda m: m["cases"][0].update(max_transfer_bytes=512 * 1024 * 1024),
    lambda m: m["cases"][0].update(max_storage_bytes=8 * 1024**3),
    lambda m: m["cases"][1].update(id=m["cases"][0]["id"]),
    lambda m: next(row for row in m["cases"] if row["kind"] == "installed_idle").update(samples=2),
])
def test_admission_refuses_changed_caps_and_boolean_aliases(mutate):
    value = manifest()
    mutate(value)
    with pytest.raises(ValueError):
        validate_manifest(value)


def fake_proc(root, pid, parent, start, rss, *, io=True):
    path = root / str(pid)
    path.mkdir()
    # stat positions after comm: state,ppid,...utime13,stime14,starttime21,rss23.
    fields = ["S", str(parent)] + ["0"] * 20
    fields[11], fields[12], fields[19], fields[21] = "3", "4", str(start), str(rss)
    (path / "stat").write_text(f"{pid} (controlled name with ) paren) " + " ".join(fields))
    if io:
        (path / "io").write_text("rchar: 100\nwchar: 200\nread_bytes: 0\nwrite_bytes: 4096\n")


def test_sampler_keeps_simultaneous_rss_and_excludes_unrelated_process(tmp_path):
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    fake_proc(proc, 11, 10, 102, 3)
    fake_proc(proc, 12, 11, 103, 4)
    fake_proc(proc, 99, 1, 104, 5000)
    value = sample_owned(10, 101, work, proc=proc)
    assert value["host_rss_bytes"] == 9 * os.sysconf("SC_PAGE_SIZE")
    assert {row["pid"] for row in value["processes"]} == {10, 11, 12}
    assert value["missing"] == []
    assert proc_stat(10, proc)["start_ticks"] == 101


def test_missing_owned_io_is_a_lower_bound_not_a_zero_measurement(tmp_path):
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    fake_proc(proc, 11, 10, 102, 3, io=False)
    value = sample_owned(10, 101, work, proc=proc)
    assert value["missing"] == ["owned_process_observation_unavailable"]
    result = resource_summary([value])
    assert result["complete_observations"] is False
    assert result["sampled_max_owned_mixed_memory_bytes"] is None
    assert result["sampled_observed_mixed_memory_lower_bound_bytes"] == 2 * os.sysconf("SC_PAGE_SIZE")


@pytest.mark.parametrize("io_available", [False, True])
def test_original_process_exit_during_io_is_an_explicit_exclusion(tmp_path, monkeypatch, io_available):
    import tools.managed_costs as costs
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    fake_proc(proc, 11, 10, 102, 3, io=io_available)
    original_stat = costs.proc_stat
    child_reads = 0

    def terminated(pid, root):
        nonlocal child_reads
        value = original_stat(pid, root)
        if pid == 11:
            child_reads += 1
            if child_reads > 1:
                value["state"] = "Z"
        return value

    monkeypatch.setattr(costs, "proc_stat", terminated)
    result = sample_owned(10, 101, work, proc=proc)
    assert result["processes_departed_during_observation"] == 1
    assert result["missing"] == []
    assert {row["pid"] for row in result["processes"]} == {10}
    assert resource_summary([result])["complete_observations"] is True


@pytest.mark.parametrize("terminal", ["zombie", "absent"])
def test_failed_io_can_confirm_original_exit_after_first_live_recheck(tmp_path, monkeypatch, terminal):
    import tools.managed_costs as costs
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    fake_proc(proc, 11, 10, 102, 3)
    original_stat, original_read = costs.proc_stat, Path.read_text
    child_reads, now, delays = 0, [0], []

    def transition(pid, root):
        nonlocal child_reads
        value = original_stat(pid, root)
        if pid == 11:
            child_reads += 1
            if child_reads == 3:
                if terminal == "absent":
                    for path in (proc / "11").iterdir():
                        path.unlink()
                    (proc / "11").rmdir()
                    raise FileNotFoundError
                value["state"] = "Z"
        return value

    def read(path, *args, **kwargs):
        if path == proc / "11/io":
            raise PermissionError(13, "PRIVATE_DETAIL_MUST_NOT_BE_EXPORTED")
        return original_read(path, *args, **kwargs)

    def advance(seconds):
        delays.append(seconds)
        now[0] += round(seconds * 1_000_000_000)

    monkeypatch.setattr(costs, "proc_stat", transition)
    monkeypatch.setattr(Path, "read_text", read)
    monkeypatch.setattr(costs.time, "monotonic_ns", lambda: now[0])
    monkeypatch.setattr(costs.time, "sleep", advance)
    result = sample_owned(10, 101, work, proc=proc)
    assert result["missing"] == [] and result["processes_departed_during_observation"] == 1
    assert delays == [0.005] and {row["pid"] for row in result["processes"]} == {10}
    diagnostic = result["process_read_diagnostics"][0]
    assert diagnostic["pid"] == 11 and diagnostic["start_ticks"] == 102
    assert diagnostic["error_code"] == "permission_denied" and diagnostic["errno"] == 13
    assert diagnostic["first_identity"] == "same" and diagnostic["first_state"] == "S"
    assert diagnostic["checks"] == 2 and diagnostic["confirmed_departed"] is True
    assert diagnostic["last_identity"] == ("same" if terminal == "zombie" else "absent")
    summary = resource_summary([result])
    assert summary["process_read_diagnostics"][0]["observation_timestamp_ns"] == 5_000_000
    assert "PRIVATE_DETAIL" not in json.dumps(summary)


def test_live_unreadable_processes_share_one_finite_confirmation_budget(tmp_path, monkeypatch):
    import tools.managed_costs as costs
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    fake_proc(proc, 11, 10, 102, 3, io=False)
    fake_proc(proc, 12, 10, 103, 3, io=False)
    now, delays = [0], []

    def advance(seconds):
        delays.append(seconds)
        now[0] += round(seconds * 1_000_000_000)

    monkeypatch.setattr(costs.time, "monotonic_ns", lambda: now[0])
    monkeypatch.setattr(costs.time, "sleep", advance)
    result = sample_owned(10, 101, work, proc=proc)
    assert now[0] == 50_000_000 and delays == [0.005] * 10
    assert result["missing"] == ["owned_process_observation_unavailable"]
    assert result["processes_departed_during_observation"] == 0
    assert [row["checks"] for row in result["process_read_diagnostics"]] == [11, 1]
    assert all(row["last_identity"] == "same" and not row["confirmed_departed"]
               for row in result["process_read_diagnostics"])
    assert resource_summary([result])["complete_observations"] is False


@pytest.mark.parametrize("replacement", ["reused_zombie", "unreadable"])
def test_failed_io_cannot_be_excused_by_reused_or_unreadable_process(tmp_path, monkeypatch, replacement):
    import tools.managed_costs as costs
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    fake_proc(proc, 11, 10, 102, 3, io=False)
    original_stat = costs.proc_stat
    child_reads = 0

    def changed(pid, root):
        nonlocal child_reads
        value = original_stat(pid, root)
        if pid == 11:
            child_reads += 1
            if child_reads > 1:
                if replacement == "unreadable":
                    raise PermissionError("controlled original identity unreadable")
                value.update(state="Z", start_ticks=999)
        return value

    monkeypatch.setattr(costs, "proc_stat", changed)
    result = sample_owned(10, 101, work, proc=proc)
    assert result["processes_departed_during_observation"] == 0
    assert result["missing"] == ["owned_process_observation_unavailable"]
    assert resource_summary([result])["complete_observations"] is False
    diagnostic = result["process_read_diagnostics"][0]
    assert diagnostic["confirmed_departed"] is False
    if replacement == "reused_zombie":
        assert diagnostic["checks"] == 1 and diagnostic["last_identity"] == "reused"
    else:
        assert diagnostic["last_identity"] == "unreadable"


def test_reused_root_pid_is_not_observed_as_the_owned_process(tmp_path):
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 999, 2)
    result = sample_owned(10, 101, work, proc=proc)
    assert result == {"available": False, "reason": "owned_root_exited_or_reused"}


def test_same_approved_source_and_result_tree_for_root_child_comparison(tmp_path):
    from tests.integration.test_managed_children_runtime import make_source
    source, base = make_source(tmp_path)
    wanted = expected_tree(source)
    for name in ("left", "right"):
        (source / (name + ".txt")).write_text(name + " implemented\n")
    subprocess.run(["git", "-C", str(source), "add", "."], check=True)
    patch = subprocess.check_output(["git", "-C", str(source), "diff", "--cached", "--binary", base], text=True)
    subprocess.run(["git", "-C", str(source), "reset", "--hard", "-q", base], check=True)
    assert retained_tree(source, base, patch, tmp_path / "index") == wanted
    assert (source / "left.txt").read_text() == "old\n"


def test_uncertain_cleanup_refuses_instead_of_faking_removal(tmp_path, monkeypatch):
    from docker.models.volumes import Volume
    from types import SimpleNamespace
    calls = []
    monkeypatch.setattr(Volume, "remove", lambda *_a, **_k: calls.append("remove"))
    recorder = SimpleNamespace(add=lambda *_: None, fact=lambda *_: None)
    with ownership_hooks(tmp_path, monkeypatch, recorder) as guard:
        guard["uncertain"] = True
        with pytest.raises(BudgetStop, match="owned_capture_unresolved"):
            Volume.remove(None)
    assert not calls


def test_discovery_tolerates_confirmed_concurrent_container_removal(tmp_path):
    from docker.errors import NotFound
    from types import SimpleNamespace

    def disappeared():
        raise NotFound("removed fixture")

    container = SimpleNamespace(reload=disappeared)
    client = SimpleNamespace(containers=SimpleNamespace(list=lambda **_: [container]))
    discover_owned_containers(tmp_path, client)
    assert not (tmp_path / "ownership.json").exists()


def test_missing_cgroup_requires_positive_terminal_engine_observation(tmp_path):
    from types import SimpleNamespace
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    (work / "ownership.json").write_text(json.dumps({"containers": [
        {"id": "owned", "state": "running", "pid": 40, "start_ticks": 700, "cgroup": "/owned"}
    ]}))
    missing = sample_owned(10, 101, work, proc=proc)
    assert missing["missing"] == ["owned_container_observation_unavailable"]
    stopped = SimpleNamespace(reload=lambda: None, attrs={"State": {"Running": False}})
    client = SimpleNamespace(containers=SimpleNamespace(get=lambda _: stopped))
    confirmed = sample_owned(10, 101, work, proc=proc, container_client=client)
    assert not confirmed["missing"] and confirmed["containers_terminal_during_observation"] == 1


def test_pending_installed_acquisition_reserves_memory_without_measuring_a_peak(tmp_path):
    proc, work = tmp_path / "proc", tmp_path / "work"
    proc.mkdir(); work.mkdir()
    fake_proc(proc, 10, 1, 101, 2)
    path = work / "installed-acquisition.json"
    path.write_text(json.dumps({"state": "may_acquire", "worker_ceiling": 1, "memory_reservation_bytes": 536870912}))
    row = sample_owned(10, 101, work, proc=proc)
    assert row["container_charge_bytes"] == 0
    assert row["pending_container_memory_reservation_bytes"] == 536870912
    summary = resource_summary([row])
    assert summary["observations_using_pending_acquisition_reservation"] == 1
    assert summary["sampled_max_owned_mixed_memory_bytes"] == 2 * os.sysconf("SC_PAGE_SIZE")
    path.write_text(json.dumps({"state": "removed", "worker_ceiling": 1, "memory_reservation_bytes": 0}))
    assert sample_owned(10, 101, work, proc=proc)["pending_container_memory_reservation_bytes"] == 0


def test_stale_discovery_cannot_reopen_terminal_container_state(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import tools.managed_costs as costs
    (tmp_path / "ownership.json").write_text(json.dumps({"containers": [{"id": "owned", "state": "removed"}]}))
    monkeypatch.setattr(costs, "proc_stat", lambda _: {"start_ticks": 123})
    monkeypatch.setattr(costs, "_cgroup", lambda _: "/owned")
    observed = SimpleNamespace(id="owned", reload=lambda: None, attrs={"State": {"Pid": 100, "Status": "running"}})
    client = SimpleNamespace(containers=SimpleNamespace(get=lambda _: observed))
    register_container(tmp_path, client, "owned")
    mark_container_terminal(tmp_path, "owned", "stopped")
    assert json.loads((tmp_path / "ownership.json").read_text())["containers"] == [{"id": "owned", "state": "removed"}]


def idle_retention_fixture(workdir):
    case = next(row for row in manifest()["cases"] if row["kind"] == "installed_idle") | {"sample": 1}
    proof = {"schema_version": 1, "state": "retained_stopped", "container_id": "a" * 64,
             "volume_name": "openjules-work-" + "b" * 40, "volume_identity_sha256": "c" * 64,
             "worker_id": "d" * 32, "reason": "executed_capture_required", "observed_stopped": True,
             "capacity_reserved": 0, "model_fixture_calls": 0, "tasks_enrolled": 0,
             "volume_storage_bytes": 4096,
             "scope": {"deployment_id": "cost-idle-" + "e" * 16,
                       "repository": "github:github.com/managed-cost-fixture/idle"}}
    registry = {"containers": [{"id": proof["container_id"], "state": "stopped",
                                "volume_names": [proof["volume_name"]]}]}
    (workdir / "ownership.json").write_text(json.dumps(registry))
    (workdir / "installed-acquisition.json").write_text(json.dumps({"scope": proof["scope"]}))
    (workdir / "installed-retention.json").write_text(json.dumps(proof))
    return case, proof, registry


def test_original_stopped_idle_retention_keeps_storage_without_claiming_removal(tmp_path):
    case, proof, _ = idle_retention_fixture(tmp_path)
    facts = {"installed_owned_worker_id": proof["worker_id"]}
    report = custody_report(case, tmp_path, facts, False)
    assert report == {"custody_unresolved": False, "retained_resources": [proof],
                      "retained_volume_storage_bytes": 4096}
    assert json.loads((tmp_path / "ownership.json").read_text())["containers"][0]["state"] == "stopped"
    assert custody_report(case, tmp_path, facts, True)["custody_unresolved"] is True


@pytest.mark.parametrize("change", ["missing", "wrong_worker", "wrong_scope", "wrong_volume",
                                   "running", "extra_container", "boolean_capacity", "negative_storage",
                                   "unexpected_field", "wrong_case"])
def test_idle_retention_cannot_excuse_unknown_or_mismatched_custody(tmp_path, change):
    case, proof, registry = idle_retention_fixture(tmp_path)
    facts = {"installed_owned_worker_id": proof["worker_id"]}
    if change == "wrong_worker":
        facts["installed_owned_worker_id"] = "f" * 32
    elif change == "wrong_scope":
        proof["scope"]["deployment_id"] = "cost-idle-" + "f" * 16
    elif change == "wrong_volume":
        registry["containers"][0]["volume_names"] = ["openjules-work-" + "f" * 40]
    elif change == "running":
        registry["containers"][0]["state"] = "running"
    elif change == "extra_container":
        registry["containers"].append({"id": "f" * 64, "state": "stopped", "volume_names": []})
    elif change == "boolean_capacity":
        proof["capacity_reserved"] = False
    elif change == "negative_storage":
        proof["volume_storage_bytes"] = -1
    elif change == "unexpected_field":
        proof["unqualified"] = "not a closed producer proof"
    elif change == "wrong_case":
        case["kind"] = "root"
    (tmp_path / "ownership.json").write_text(json.dumps(registry))
    (tmp_path / "installed-retention.json").write_text(json.dumps(proof))
    if change == "missing":
        (tmp_path / "installed-retention.json").unlink()
    report = custody_report(case, tmp_path, facts, False)
    assert report == {"custody_unresolved": True, "retained_resources": [],
                      "retained_volume_storage_bytes": 0}
