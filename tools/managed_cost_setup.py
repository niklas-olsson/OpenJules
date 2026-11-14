"""Finite prerequisite acquisition for the optional managed-cost investigation.

Uses existing CI package and Docker recipes. Acquisition/build time is outside
the measured trial, bounded separately, and never described as steady state.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import re
import signal
import subprocess
import sys
import time

from tools.managed_costs import proc_stat


def discover_descendants(root_pid, root_start, known):
    """Retain exact PID/start identities even if a child starts a new session."""
    rows = {}
    for path in Path("/proc").iterdir():
        if path.name.isdecimal():
            try:
                row = proc_stat(int(path.name))
                rows[row["pid"]] = row
            except (OSError, ValueError):
                pass
    if root_pid in rows and rows[root_pid]["start_ticks"] == root_start:
        known[root_pid] = root_start
    selected = {pid for pid, start in known.items() if pid in rows and rows[pid]["start_ticks"] == start}
    while True:
        grown = selected | {pid for pid, row in rows.items() if row["ppid"] in selected}
        if grown == selected:
            break
        selected = grown
    for pid in selected:
        known[pid] = rows[pid]["start_ticks"]
    return known


def alive_identity(pid, start):
    try:
        value = proc_stat(pid)
        return value["start_ticks"] == start and value["state"] not in {"Z", "X", "x"}
    except (OSError, ValueError):
        return False


def stop_owned(root_pid, root_start, known):
    """Freeze the owned descendant cohort before signaling it individually.

    New sessions remain descendants. Freezing before the final census prevents
    a known helper from forking an unobserved acquisition process during kill.
    PID/start checks prevent a reused PID from receiving any signal.
    """
    frozen = set()
    converged = False
    for _ in range(8):
        discover_descendants(root_pid, root_start, known)
        new = [(pid, start) for pid, start in known.items() if (pid, start) not in frozen and alive_identity(pid, start)]
        if not new:
            converged = True
            break
        for pid, start in new:
            if pid == os.getpid():
                raise RuntimeError("acquisition_owner_alias")
            try:
                if alive_identity(pid, start):
                    os.kill(pid, signal.SIGSTOP)
                    frozen.add((pid, start))
            except ProcessLookupError:
                pass
    for pid, start in frozen:
        if alive_identity(pid, start):
            try:
                os.kill(pid, signal.SIGTERM)
                os.kill(pid, signal.SIGCONT)
            except ProcessLookupError:
                pass
    cutoff = time.monotonic() + 3
    while time.monotonic() < cutoff and any(alive_identity(pid, start) for pid, start in known.items()):
        time.sleep(0.05)
    for pid, start in known.items():
        if alive_identity(pid, start):
            try:
                os.kill(pid, signal.SIGKILL)
            except ProcessLookupError:
                pass
    cutoff = time.monotonic() + 2
    while time.monotonic() < cutoff and any(alive_identity(pid, start) for pid, start in known.items()):
        time.sleep(0.05)
    return sum(alive_identity(pid, start) for pid, start in known.items()) + (0 if converged else 1)


def run(args):
    root = Path(args.work_dir).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    start = time.monotonic()
    deadline = start + 840
    initial = os.statvfs(root)
    available = initial.f_bavail * initial.f_frsize
    cap = 4 * 1024**3
    report = {"schema_version": 1, "scope": "prerequisite acquisition/build, not benchmark timings",
              "elapsed_cap_seconds": 840, "sampled_disk_growth_cap_bytes": cap,
              "network_scope": "existing Python requirements and existing native Docker CI recipes; no model or forge provider",
              "steps": [], "complete": False}
    base_reference = None

    def save():
        (root / "report.json").write_text(json.dumps(report, sort_keys=True, indent=2) + "\n")

    commands = [
        ("dependencies", [sys.executable, "-m", "pip", "install", "--disable-pip-version-check", "--retries", "0", "--timeout", "30", "-r", "requirements-dev.txt"]),
        ("finite-python-inputs", [sys.executable, str(Path(args.zpm_checkout) / "tests/contracts/prepare_dependencies.py"),
             "--polyphony-checkout", str(Path(args.polyphony_checkout).absolute()),
             "--openjules-checkout", str(Path.cwd()), "--work-dir", str(root / "python-inputs")]),
        ("base-image", ["docker", "pull", "python:3.12-slim"]),
        ("runtime-image", ["docker", "build", "--iidfile", str(root / "runtime-image.id"), "-f", "tests/fixtures/Dockerfile.managed-runtime", "."]),
        ("agent-image", ["docker", "build", "--iidfile", str(root / "agent-image.id"), "-f", "docker/Dockerfile.managed-agent", "."]),
    ]
    try:
        for name, command in commands:
            if time.monotonic() + 10 >= deadline:
                report["failure"] = "prerequisite_time_cap"
                break
            if name in {"runtime-image", "agent-image"}:
                if base_reference is None:
                    raise ValueError("resolved_ci_base_missing")
                command = command[:2] + ["--build-arg", "PYTHON_BASE=" + base_reference] + command[2:]
            began = time.monotonic()
            with (root / (name + ".private.log")).open("wb") as log:
                process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
                original_start = proc_stat(process.pid)["start_ticks"]
                known = {process.pid: original_start}
                failure = None
                max_growth = 0
                while process.poll() is None:
                    discover_descendants(process.pid, original_start, known)
                    current = os.statvfs(root)
                    growth = max(0, available - current.f_bavail * current.f_frsize)
                    max_growth = max(max_growth, growth)
                    if growth > cap:
                        failure = "sampled_prerequisite_disk_cap"
                    if time.monotonic() + 10 >= deadline:
                        failure = "prerequisite_time_cap"
                    if failure:
                        unresolved = stop_owned(process.pid, original_start, known)
                        process.wait(timeout=3)
                        report["owned_acquisition_processes_unresolved"] = unresolved
                        break
                    time.sleep(0.5)
            if process.returncode != 0 and not failure:
                report["owned_acquisition_processes_unresolved"] = stop_owned(process.pid, original_start, known)
            report["steps"].append({"name": name, "elapsed_seconds": time.monotonic() - began,
                                    "returncode": process.returncode, "sampled_shared_filesystem_growth_bytes": max_growth})
            if failure or process.returncode != 0:
                report["failure"] = failure or "prerequisite_command_failed"
                break
            if name == "base-image":
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("prerequisite_evidence_deadline")
                base = json.loads(subprocess.check_output(["docker", "image", "inspect", "python:3.12-slim"], timeout=min(10, remaining)))[0]
                candidates = [value for value in base.get("RepoDigests", [])
                              if re.fullmatch(r"(?:docker\.io/library/)?python@sha256:[0-9a-f]{64}", value)]
                if not candidates:
                    raise ValueError("resolved_ci_base_digest_missing")
                base_reference = sorted(candidates)[0]
                report["resolved_ci_base_image"] = {key: base.get(key) for key in ("Id", "RepoDigests", "Architecture", "Os", "Size")}
                report["resolved_ci_base_image"]["selected_build_reference"] = base_reference
            save()
        else:
            report["dependencies"] = sorted({dist.metadata["Name"] + "==" + dist.version for dist in importlib.metadata.distributions() if dist.metadata.get("Name")})
            report["fixture_sha256"] = {name: hashlib.sha256(Path(name).read_bytes()).hexdigest() for name in (
                "tests/fixtures/Dockerfile.managed-runtime", "docker/Dockerfile.managed-agent", "requirements-dev.txt", "requirements.txt")}
            report["images"] = {}
            for name in ("runtime", "agent"):
                identity = (root / (name + "-image.id")).read_text().strip()
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise TimeoutError("prerequisite_evidence_deadline")
                data = json.loads(subprocess.check_output(["docker", "image", "inspect", identity], timeout=min(10, remaining)))[0]
                report["images"][name] = {key: data.get(key) for key in ("Id", "RepoDigests", "Architecture", "Os", "Size")}
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise TimeoutError("prerequisite_evidence_deadline")
            data = json.loads(subprocess.check_output(["docker", "info", "--format", "{{json .}}"], timeout=min(10, remaining)))
            report["docker"] = {key: data.get(key) for key in ("ServerVersion", "Driver", "CgroupDriver", "CgroupVersion", "NCPU", "MemTotal", "KernelVersion", "SecurityOptions")}
            final = os.statvfs(root)
            if time.monotonic() > deadline or available - final.f_bavail * final.f_frsize > cap:
                raise TimeoutError("prerequisite_final_cap")
            report["complete"] = True
    except Exception:
        report["failure"] = "prerequisite_evidence_or_cleanup_failed"
    finally:
        report["elapsed_seconds"] = time.monotonic() - start
        report["limits"] = ["disk growth uses shared runner filesystem free-space changes; unrelated writes may conservatively stop setup",
                            "sampled at0.5seconds, not a hard disk quota or network byte meter",
                            "package input acquisition additionally uses the existing preparer's narrower artifact/time limits",
                            "private command logs and dependency payloads are not uploaded"]
        save()
    return 0 if report["complete"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--zpm-checkout", required=True)
    parser.add_argument("--polyphony-checkout", required=True)
    parser.add_argument("--work-dir", required=True)
    return run(parser.parse_args(argv))


if __name__ == "__main__":
    raise SystemExit(main())
