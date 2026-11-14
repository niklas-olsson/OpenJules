"""Project one finite investigation artifact into durable, bounded public facts.

This does not qualify a run, pool trials, change statuses or choose an optimization.
The original ZIP and exact member digests remain the provenance of every value.
"""

from __future__ import annotations

import argparse
from collections import Counter
import hashlib
import io
import json
from pathlib import Path
import re
import subprocess
import zipfile

from tools.managed_cost_measurement import COUNTERS, FACTS, PHASES


MEMBERS = {
    "investigation": "managed-cost-investigation/report.json",
    "prerequisites": "managed-cost-prerequisites/report.json",
    "acquisition": "managed-cost-prerequisites/python-inputs/acquisition-report.json",
}
MAX_MEMBER = 16 * 1024 * 1024
MAX_ARCHIVE = 32 * 1024 * 1024
MAX_PROJECTION = 4 * 1024 * 1024
REPORT_KEYS = frozenset({
    "schema_version", "investigation", "complete", "elapsed_seconds", "environment", "image_ids",
    "manifest_sha256", "declared_transfer_reserved_bytes", "samples", "summary", "limits",
    "admission_closed_reason", "retained_resources", "retained_volume_storage_bytes",
})
SAMPLE_KEYS = frozenset({
    "case_id", "sample", "status", "diagnostic_code", "exception_type", "wall_ns", "process_cpu",
    "facts", "measurements", "custody_unresolved", "resource_samples", "resource_summary",
    "retained_resources", "retained_volume_storage_bytes", "final_owned_volume_storage_bytes",
    "final_owned_storage_bytes",
})
MEASUREMENT_KEYS = frozenset({
    "schema_version", "enabled", "complete", "problems", "observation_ns", "process_cpu",
    "spans", "captures", "counters", "facts", "fixture_impairment_declaration", "limits",
})
SPAN_KEYS = frozenset({"id", "parent_id", "phase", "start_ns", "wall_ns", "thread_cpu_ns", "outcome", "exception_type"})
FIXTURES = frozenset({"requirements.txt", "requirements-dev.txt", "docker/Dockerfile.managed-agent",
                      "tests/fixtures/Dockerfile.managed-runtime"})
SETUP_KEYS = frozenset({"complete", "dependencies", "docker", "elapsed_cap_seconds", "elapsed_seconds",
                        "fixture_sha256", "images", "limits", "network_scope", "resolved_ci_base_image",
                        "sampled_disk_growth_cap_bytes", "schema_version", "scope", "steps"})
ACQUISITION_KEYS = frozenset({"acquired_wheel_bytes_including_repeated_local_copies", "acquisition_limits",
                            "acquisition_runs", "artifact_bytes", "artifact_count", "byte_scope", "interpreter",
                            "manifest_sha256", "mode", "passed", "schema_version", "seed", "source_revisions"})
PRIVATE_MARKERS = re.compile(
    r"(?:/(?:home|root|workspace|tmp|private)/|file://|[A-Za-z]:\\\\|"
    r"github_pat_[A-Za-z0-9_]+|gh[pousr]_[A-Za-z0-9]{16,}|sk-[A-Za-z0-9_-]{16,}|"
    r"-----BEGIN[^\n]*PRIVATE KEY-----|authorization\s*[:=]|bearer\s+[A-Za-z0-9._~+/-]{8,})",
    re.IGNORECASE,
)


def require(condition, code):
    if not condition:
        raise ValueError(code)


def digest(data):
    return hashlib.sha256(data).hexdigest()


def encode(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode() + b"\n"


def decode(data):
    def unique(pairs):
        value = {}
        for key, item in pairs:
            require(key not in value, "duplicate_json_key")
            value[key] = item
        return value

    def invalid_constant(_):
        raise ValueError("nonfinite_json_number")

    return json.loads(data, object_pairs_hook=unique, parse_constant=invalid_constant)


def read_archive(path, expected_sha256):
    require(re.fullmatch(r"[0-9a-f]{64}", expected_sha256) is not None, "invalid_archive_digest")
    path = Path(path)
    with path.open("rb") as source:
        raw = source.read(MAX_ARCHIVE + 1)
    require(0 < len(raw) <= MAX_ARCHIVE, "archive_size_bound")
    require(digest(raw) == expected_sha256, "archive_digest_mismatch")
    documents, provenance = {}, {}
    with zipfile.ZipFile(io.BytesIO(raw)) as archive:
        entries = archive.infolist()
        require(Counter(entry.filename for entry in entries) == Counter(MEMBERS.values()), "unexpected_archive_members")
        require(all(not entry.is_dir() and not entry.flag_bits & 1
                    and 0 < entry.file_size <= MAX_MEMBER for entry in entries), "archive_member_bound")
        require(sum(entry.file_size for entry in entries) <= MAX_ARCHIVE, "archive_expansion_bound")
        for name, member in MEMBERS.items():
            data = archive.read(member)
            documents[name] = decode(data)
            provenance[name] = {"member": member, "bytes": len(data), "sha256": digest(data)}
    return documents, {"sha256": expected_sha256, "bytes": len(raw), "members": provenance}


def source_binding(repository, report, prerequisites, acquisition):
    revision = report["environment"]["source_revision"]
    require(type(revision) is str and re.fullmatch(r"[0-9a-f]{40}", revision) is not None, "invalid_source_revision")

    def git(*args):
        return subprocess.check_output(["git", "-C", str(repository), *args], stderr=subprocess.DEVNULL, timeout=15)

    manifest_bytes = git("show", revision + ":tests/fixtures/managed-cost-manifest.json")
    require(digest(manifest_bytes) == report["manifest_sha256"], "source_manifest_mismatch")
    manifest = decode(manifest_bytes)
    require(manifest["investigation"] == "managed-costs-v1" and type(manifest["schema_version"]) is int
            and manifest["schema_version"] == 1, "manifest_schema_changed")
    require(report["environment"]["baseline_revision"] == manifest["baseline_revision"], "source_baseline_mismatch")
    production_tree = git("rev-parse", revision + ":src").decode().strip()
    require(production_tree == report["environment"]["production_tree"], "production_tree_mismatch")
    baseline = manifest["baseline_revision"]
    require(type(baseline) is str and re.fullmatch(r"[0-9a-f]{40}", baseline) is not None, "invalid_baseline_revision")
    require(git("rev-parse", baseline + ":src").decode().strip() == production_tree, "production_baseline_changed")
    pins = {"openjules": revision, "zpm": manifest["zpm_revision"], "polyphony": manifest["polyphony_revision"]}
    require(acquisition["source_revisions"] == pins, "acquisition_source_mismatch")
    require(set(prerequisites["fixture_sha256"]) == FIXTURES, "fixture_inventory_changed")
    for name, expected in prerequisites["fixture_sha256"].items():
        require(digest(git("show", revision + ":" + name)) == expected, "source_fixture_mismatch")
    require(set(report["image_ids"]) == {"agent", "runtime"}, "image_inventory_changed")
    for name, image in report["image_ids"].items():
        require(prerequisites["images"][name]["Id"] == image, "image_identity_mismatch")
    return manifest, {"revision": revision, "tree": git("rev-parse", revision + "^{tree}").decode().strip(),
                      "production_tree": production_tree, "component_revisions": pins,
                      "url": "https://github.com/niklas-olsson/OpenJules/commit/" + revision,
                      "manifest_sha256": digest(manifest_bytes)}


def aggregate_spans(spans):
    result = {}
    for span in spans:
        require(type(span) is dict and set(span) == SPAN_KEYS and span["phase"] in PHASES, "span_schema_changed")
        require(span["outcome"] in {"completed", "raised", "running"}, "span_outcome_changed")
        row = result.setdefault(span["phase"], {"count": 0, "outcomes": {}, "exceptions": {},
                                               "wall_ns": [], "thread_cpu_ns": []})
        row["count"] += 1
        row["outcomes"][span["outcome"]] = row["outcomes"].get(span["outcome"], 0) + 1
        if span["exception_type"] is not None:
            name = span["exception_type"]
            row["exceptions"][name] = row["exceptions"].get(name, 0) + 1
        for name in ("wall_ns", "thread_cpu_ns"):
            value = span[name]
            require(value is None or type(value) is int and value >= 0, "span_metric_invalid")
            if value is not None:
                row[name].append(value)
    for row in result.values():
        for name in ("wall_ns", "thread_cpu_ns"):
            values = row[name]
            row[name] = {"observed_count": len(values), "missing_count": row["count"] - len(values),
                         "sum": sum(values) if values else None,
                         "minimum": min(values) if values else None, "maximum": max(values) if values else None}
    return result


def project_report(report, manifest):
    require(type(report) is dict and set(report) <= REPORT_KEYS, "report_schema_changed")
    require(type(report["schema_version"]) is int and report["schema_version"] == 1
            and report["investigation"] == "managed-costs-v1"
            and type(report["complete"]) is bool, "report_identity_changed")
    expected = Counter((case["id"], number) for case in manifest["cases"] for number in range(1, case["samples"] + 1))
    samples = report["samples"]
    require(len(expected) == 66 and len(samples) == 66
            and all(type(row["sample"]) is int for row in samples)
            and Counter((row["case_id"], row["sample"]) for row in samples) == expected, "sample_inventory_mismatch")
    result = {key: value for key, value in report.items() if key != "samples"}
    result["samples"] = []
    for sample in samples:
        require(type(sample) is dict and set(sample) <= SAMPLE_KEYS, "sample_schema_changed")
        require(sample["status"] in {"PASS", "FAIL", "CENSORED", "NOT_RUN"}, "sample_status_changed")
        row = {key: value for key, value in sample.items() if key not in {"resource_samples", "measurements"}}
        if "measurements" in sample:
            measurement = sample["measurements"]
            require(set(measurement) == MEASUREMENT_KEYS and set(measurement["counters"]) <= COUNTERS
                    and set(measurement["facts"]) <= FACTS, "measurement_schema_changed")
            row["measurements"] = {key: value for key, value in measurement.items() if key != "spans"}
            row["measurements"]["phase_aggregates"] = aggregate_spans(measurement["spans"])
        if "resource_samples" in sample:
            observations = sample["resource_samples"]
            row["resource_series_omission"] = {
                "rows": len(observations),
                "unavailable_reasons": dict(Counter(item["reason"] for item in observations if item.get("available") is False)),
                "missing_codes": dict(Counter(code for item in observations for code in item.get("missing", []))),
            }
        if sample["status"] == "PASS":
            require(type(sample.get("wall_ns")) is int and sample["wall_ns"] >= 0
                    and sample.get("custody_unresolved") is False
                    and sample["measurements"]["complete"] is True
                    and sample["resource_summary"]["complete_observations"] is True, "passing_sample_incomplete")
        result["samples"].append(row)
    statuses = Counter(row["status"] for row in samples)
    require(not report["complete"] or statuses == {"PASS": 66}, "complete_report_has_incomplete_samples")
    result["inventory"] = {"expected": 66, "observed": len(samples), "statuses": dict(statuses)}
    return result


def privacy_check(value, forbidden_literals=()):
    text = encode(value).decode()
    require(PRIVATE_MARKERS.search(text) is None, "private_material_marker")
    require(all(type(word) is str and word and word.casefold() not in text.casefold()
                for word in forbidden_literals), "forbidden_literal_present")


def build_projection(archive, expected_sha256, repository, artifact_url, trial, forbidden_literals=()):
    require(re.fullmatch(r"https://github\.com/niklas-olsson/OpenJules/actions/runs/[0-9]+(?:/artifacts/[0-9]+)?", artifact_url)
            is not None, "public_artifact_url_required")
    require(re.fullmatch(r"[a-z][a-z0-9-]{0,39}", trial) is not None, "invalid_trial_label")
    documents, provenance = read_archive(archive, expected_sha256)
    report, setup, acquisition = (documents[name] for name in ("investigation", "prerequisites", "acquisition"))
    require(type(setup) is dict and set(setup) == SETUP_KEYS
            and type(acquisition) is dict and set(acquisition) == ACQUISITION_KEYS, "prerequisite_schema_changed")
    manifest, source = source_binding(repository, report, setup, acquisition)
    projection = {
        "schema_version": 1, "projection": "managed-cost-evidence-v1", "trial": trial,
        "projector_sha256": digest(Path(__file__).read_bytes()),
        "artifact": provenance | {"url": artifact_url}, "source": source, "manifest": manifest,
        "investigation": project_report(report, manifest), "prerequisites": setup, "acquisition": acquisition,
        "scope": [
            "one original trial only; original sample order, statuses and raw wall/CPU values retained; no pooling",
            "phase count, outcomes and timing aggregates retain inclusive observations; nested or overlapping phases are not additive partitions",
            "phase timing minima and maxima describe observed intervals; missing intervals remain explicitly missing",
            "process timelines and individual span identities are omitted; resource summaries and missing/unavailable counts remain",
            "source summaries are retained as reported; sample values permit independent median/range recalculation",
            "the projection is evidence preservation, not acceptance of a run, optimization, distribution or release",
            "pattern screening does not replace independent review of public facts and their source provenance",
        ],
    }
    privacy_check(projection, forbidden_literals)
    require(len(encode(projection)) <= MAX_PROJECTION, "projection_size_bound")
    return projection


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--archive", required=True)
    parser.add_argument("--archive-sha256", required=True)
    parser.add_argument("--source-checkout", default=".")
    parser.add_argument("--artifact-url", required=True)
    parser.add_argument("--trial", required=True)
    parser.add_argument("--output", required=True)
    parser.add_argument("--forbid-literal", action="append", default=[])
    args = parser.parse_args(argv)
    try:
        projection = build_projection(args.archive, args.archive_sha256, args.source_checkout,
                                      args.artifact_url, args.trial, args.forbid_literal)
        payload = encode(projection)
        with Path(args.output).open("xb") as destination:
            destination.write(payload)
    except (OSError, ValueError, KeyError, TypeError, subprocess.SubprocessError, zipfile.BadZipFile):
        parser.exit(1, "evidence projection refused; verify original inputs, schema, privacy and source bindings\n")
    print(json.dumps({"bytes": len(payload), "sha256": digest(payload),
                      "trial": args.trial, "complete": projection["investigation"]["complete"]}, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
