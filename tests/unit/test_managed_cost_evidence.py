"""Durable evidence must preserve failed trials and original comparable values."""

from copy import deepcopy
import hashlib
import json
from pathlib import Path
import statistics
import zipfile

import pytest

from tools.managed_cost_evidence import (
    MEMBERS, aggregate_spans, decode, encode, privacy_check, project_report, read_archive,
    source_binding,
)


def sample_report():
    manifest = json.loads((Path(__file__).parents[1] / "fixtures/managed-cost-manifest.json").read_text())
    rows = [{"case_id": case["id"], "sample": number, "status": "NOT_RUN", "diagnostic_code": "original_stop"}
            for case in manifest["cases"] for number in range(1, case["samples"] + 1)]
    measurement = {
        "schema_version": 1, "enabled": True, "complete": True, "problems": [],
        "observation_ns": 100, "process_cpu": {"self_user_seconds": 0.25}, "spans": [],
        "captures": [], "counters": {"http.requests": 2}, "facts": {"control": {"uncertain_resources_retained": False}},
        "fixture_impairment_declaration": {"added_request_delay_ms": 0, "body_bytes_per_second": 1250000,
                                            "applied_by_recorder": False}, "limits": ["fixture observations only"],
    }
    for row, wall in zip(rows[:5], [10, 80, 30, 20, 40]):
        row.update(status="PASS", wall_ns=wall, process_cpu={"self_user_seconds": 0.125},
                   custody_unresolved=False, facts={"source_base": "a" * 40}, measurements=deepcopy(measurement),
                   resource_summary={"complete_observations": True, "sampled_max_owned_mixed_memory_bytes": 4096},
                   resource_samples=[{"available": True, "timestamp_ns": 42, "missing": [],
                                      "processes": [{"pid": 15, "private_timeline_sentinel": 999}]}])
    rows[5].update(status="FAIL", wall_ns=900, custody_unresolved=True,
                   facts={"original_outcome": "unknown"}, measurements=deepcopy(measurement),
                   resource_summary={"complete_observations": False, "sampled_max_owned_mixed_memory_bytes": None},
                   resource_samples=[{"available": True, "missing": ["owned_process_observation_unavailable"]},
                                     {"available": False, "reason": "owned_root_exited_or_reused"}])
    return manifest, {"schema_version": 1, "investigation": "managed-costs-v1", "complete": False,
                      "samples": rows, "summary": {}, "elapsed_seconds": 20}


def test_projection_preserves_comparable_raw_values_and_failed_inventory():
    manifest, original = sample_report()
    before = deepcopy(original)
    result = project_report(original, manifest)
    assert original == before
    assert result["complete"] is False
    assert result["inventory"]["statuses"] == {"PASS": 5, "FAIL": 1, "NOT_RUN": 60}
    assert [(row["case_id"], row["sample"], row["status"]) for row in result["samples"]] == [
        (row["case_id"], row["sample"], row["status"]) for row in original["samples"]]
    values = [row["wall_ns"] for row in result["samples"] if row["status"] == "PASS"]
    assert values == [10, 80, 30, 20, 40] and statistics.median(values) == 30
    assert [min(values), max(values)] == [10, 80]
    assert result["samples"][0]["process_cpu"] == {"self_user_seconds": 0.125}
    assert result["samples"][0]["measurements"]["process_cpu"] == {"self_user_seconds": 0.25}
    assert result["samples"][5]["custody_unresolved"] is True
    assert result["samples"][5]["resource_summary"]["sampled_max_owned_mixed_memory_bytes"] is None
    assert result["samples"][5]["resource_series_omission"]["missing_codes"] == {"owned_process_observation_unavailable": 1}
    assert result["samples"][5]["resource_series_omission"]["unavailable_reasons"] == {"owned_root_exited_or_reused": 1}
    assert "private_timeline_sentinel" not in encode(result).decode()


@pytest.mark.parametrize("change", ["duplicate", "missing", "boolean_sample", "boolean_schema", "false_complete", "unknown_field", "pass_with_unknown_custody"])
def test_projection_refuses_changed_inventory_or_success_claim(change):
    manifest, report = sample_report()
    if change == "duplicate":
        report["samples"][-1] = deepcopy(report["samples"][0])
    elif change == "missing":
        report["samples"].pop()
    elif change == "boolean_sample":
        report["samples"][0]["sample"] = True
    elif change == "boolean_schema":
        report["schema_version"] = True
    elif change == "false_complete":
        report["complete"] = True
    elif change == "unknown_field":
        report["samples"][0]["raw_private_log"] = "must never be copied"
    else:
        report["samples"][0]["custody_unresolved"] = True
    with pytest.raises(ValueError):
        project_report(report, manifest)


def test_nested_intervals_remain_separate_and_missing_times_are_not_zero():
    spans = [
        {"id": 0, "parent_id": None, "phase": "runtime.ensure", "start_ns": 0,
         "wall_ns": 100, "thread_cpu_ns": 10, "outcome": "completed", "exception_type": None},
        {"id": 1, "parent_id": 0, "phase": "runtime.create", "start_ns": 10,
         "wall_ns": 60, "thread_cpu_ns": 5, "outcome": "completed", "exception_type": None},
        {"id": 2, "parent_id": None, "phase": "runtime.ensure", "start_ns": 200,
         "wall_ns": None, "thread_cpu_ns": None, "outcome": "running", "exception_type": None},
    ]
    result = aggregate_spans(spans)
    assert result["runtime.ensure"]["wall_ns"]["sum"] == 100
    assert result["runtime.create"]["wall_ns"]["sum"] == 60
    assert result["runtime.ensure"]["wall_ns"]["missing_count"] == 1
    assert result["runtime.ensure"]["outcomes"] == {"completed": 1, "running": 1}
    assert aggregate_spans([spans[2]])["runtime.ensure"]["wall_ns"]["sum"] is None


def test_zip_provenance_uses_exact_member_bytes_and_rejects_changed_archive(tmp_path):
    archive = tmp_path / "original.zip"
    member = b'{ "preserved" : 1 }\n'
    with zipfile.ZipFile(archive, "w") as output:
        for name in MEMBERS.values():
            output.writestr(name, member)
    expected = hashlib.sha256(archive.read_bytes()).hexdigest()
    documents, provenance = read_archive(archive, expected)
    assert documents["investigation"] == {"preserved": 1}
    assert provenance["members"]["investigation"]["sha256"] == hashlib.sha256(member).hexdigest()
    assert provenance["members"]["investigation"]["sha256"] != hashlib.sha256(encode(documents["investigation"])).hexdigest()
    with archive.open("ab") as output:
        output.write(b"changed archive bytes")
    with pytest.raises(ValueError, match="archive_digest_mismatch"):
        read_archive(archive, expected)


def test_archive_that_outgrows_earlier_size_observation_remains_bounded(tmp_path, monkeypatch):
    from types import SimpleNamespace
    import tools.managed_cost_evidence as evidence

    archive = tmp_path / "changed.zip"
    archive.write_bytes(b"x" * 200)
    original_stat = Path.stat
    monkeypatch.setattr(evidence, "MAX_ARCHIVE", 100)
    monkeypatch.setattr(Path, "stat", lambda path, *args, **kwargs:
                        SimpleNamespace(st_size=1) if path == archive else original_stat(path, *args, **kwargs))
    with pytest.raises(ValueError, match="archive_size_bound"):
        read_archive(archive, hashlib.sha256(b"x" * 200).hexdigest())


def test_source_manifest_schema_refuses_boolean_alias(monkeypatch):
    import tools.managed_cost_evidence as evidence

    raw = encode({"schema_version": True, "investigation": "managed-costs-v1"})
    monkeypatch.setattr(evidence.subprocess, "check_output", lambda *_args, **_kwargs: raw)
    report = {"environment": {"source_revision": "a" * 40}, "manifest_sha256": hashlib.sha256(raw).hexdigest()}
    with pytest.raises(ValueError, match="manifest_schema_changed"):
        source_binding(".", report, {}, {})


@pytest.mark.parametrize("text", ["/home/operator/private", "/workspace/scratch/private", "file:///retained",
                                 "Authorization: fixture", "Bearer abcdefghijklmnop", "ghp_" + "x" * 20])
def test_private_markers_are_refused_without_returning_the_value(text):
    with pytest.raises(ValueError, match="private_material_marker") as error:
        privacy_check({"fact": text})
    assert text not in str(error.value)


def test_private_literal_scan_does_not_store_the_requested_literal():
    with pytest.raises(ValueError, match="forbidden_literal_present"):
        privacy_check({"fact": "a private-example-project reference"}, ["private-example-project"])


@pytest.mark.parametrize("text", [b'{"one":1,"one":2}', b'{"number":NaN}'])
def test_ambiguous_json_is_not_reinterpreted(text):
    with pytest.raises(ValueError):
        decode(text)
