"""Finite native managed-cost investigation. This is not a service or optimizer.

Every sample is a new owned Python process. Reports contain aggregates and
synthetic fixture identities only; private journals, headers and output stay
in the private sample directory. The parent does not infer release from cleanup.
"""

from __future__ import annotations

import argparse
from contextlib import contextmanager
import fcntl
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import resource
import signal
import stat
import statistics
import subprocess
import sys
import threading
import time


# The native launcher uses ``python -m``. Case modules import this canonical
# name, so bind it before defining cancellation and ownership state. Otherwise
# Python would execute a second copy with a different STOP and BudgetStop.
if __name__ == "__main__":
    sys.modules["tools.managed_costs"] = sys.modules[__name__]


MIB = 1024 * 1024
MAX_REPORT = 16 * MIB
EXIT_CONFIRMATION_NS = 50_000_000
EXIT_CONFIRMATION_INTERVAL_NS = 5_000_000
EXIT_CONFIRMATION_CHECKS = 11
MAX_PROCESS_DIAGNOSTICS = 16
MAX_SUMMARY_PROCESS_DIAGNOSTICS = 256
MAX_CONTAINER_DIAGNOSTICS = 16
MAX_SUMMARY_CONTAINER_DIAGNOSTICS = 256
STOP = threading.Event()
_OWNERSHIP_LOCK = threading.Lock()


def canonical(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def write_private(path, value):
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    descriptor = os.open(temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(descriptor, "wb") as output:
        output.write(canonical(value) + b"\n")
    os.replace(temporary, path)


def proc_stat(pid, proc=Path("/proc")):
    text = (proc / str(pid) / "stat").read_text()
    fields = text[text.rfind(")") + 2:].split()
    if len(fields) < 22:
        raise ValueError("process_stat_incomplete")
    return {"pid": int(pid), "ppid": int(fields[1]), "state": fields[0],
            "start_ticks": int(fields[19]), "user_ticks": int(fields[11]),
            "system_ticks": int(fields[12]), "rss_bytes": int(fields[21]) * os.sysconf("SC_PAGE_SIZE")}


def _confirmed_process_departure(original, proc, deadline_ns):
    """Bounded confirmation after an original read fails, never a live omission.

    Linux can deny /proc/io after exit begins but before the same task is a
    zombie. Rechecking identity can establish that departure without treating
    an unreadable live process as zero. The caller shares one observation budget.
    """
    started = time.monotonic_ns()
    result = {"checks": 0, "first_identity": None, "first_state": None,
              "last_identity": None, "last_state": None, "confirmed_departed": False}
    while True:
        now = time.monotonic_ns()
        if result["checks"] and now >= deadline_ns:
            result["elapsed_ns"] = now - started
            return result
        identity, state = "unreadable", None
        try:
            current = proc_stat(original["pid"], proc)
        except FileNotFoundError:
            try:
                if not (proc / str(original["pid"])).exists():
                    identity = "absent"
            except OSError:
                pass
        except (OSError, ValueError):
            pass
        else:
            identity = "same" if current["start_ticks"] == original["start_ticks"] else "reused"
            state = current["state"] if current["state"] in {"R", "S", "D", "Z", "T", "t", "X", "x", "K", "W", "P", "I"} else "other"
        result["checks"] += 1
        if result["checks"] == 1:
            result.update(first_identity=identity, first_state=state)
        result.update(last_identity=identity, last_state=state)
        result["confirmed_departed"] = identity == "absent" or identity == "same" and state in {"Z", "X", "x"}
        now = time.monotonic_ns()
        if (result["confirmed_departed"] or identity == "reused"
                or result["checks"] >= EXIT_CONFIRMATION_CHECKS or now >= deadline_ns):
            result["elapsed_ns"] = now - started
            return result
        time.sleep(min(EXIT_CONFIRMATION_INTERVAL_NS, deadline_ns - now) / 1_000_000_000)


def _process_read_diagnostic(original, stage, error, confirmation):
    code = ("permission_denied" if isinstance(error, PermissionError) else
            "not_found" if isinstance(error, FileNotFoundError) else
            "os_error" if isinstance(error, OSError) else "invalid_data")
    return {"pid": original["pid"], "start_ticks": original["start_ticks"],
            "read_stage": stage, "error_code": code,
            "errno": error.errno if isinstance(error, OSError) else None, **confirmation}


def _container_engine_observation(original, client):
    """One fresh original-ID inspect, with no cached reload or error bodies."""
    from docker.errors import APIError, NotFound
    from requests.exceptions import ConnectionError, Timeout

    result = {"identity": "unavailable", "running": None, "restarting": None,
              "status": None, "init_pid": None, "error_code": None, "http_status": None}
    try:
        # Docker SDK containers.get already performs inspect_container. Calling
        # reload here would perform a second, differently timed engine read.
        current = client.containers.get(original["id"])
        attrs = current.attrs
        if type(attrs) is not dict or type(attrs.get("Id")) is not str:
            result["error_code"] = "invalid_engine_identity"
            return result
        if attrs["Id"] != original["id"]:
            result.update(identity="different", error_code="engine_identity_changed")
            return result
        result["identity"] = "same"
        state = attrs.get("State")
        if type(state) is not dict:
            result["error_code"] = "invalid_engine_state"
            return result
        for name, field in (("Running", "running"), ("Restarting", "restarting")):
            if type(state.get(name)) is bool:
                result[field] = state[name]
            else:
                result["error_code"] = "invalid_engine_state"
        status = state.get("Status")
        if type(status) is str and status in {"created", "running", "paused", "restarting", "removing", "exited", "dead"}:
            result["status"] = status
        else:
            result.update(status="other", error_code="invalid_engine_state")
        if type(state.get("Pid")) is int and state["Pid"] >= 0:
            result["init_pid"] = state["Pid"]
            if result["running"] is True and state["Pid"] not in {0, original["pid"]}:
                result.update(identity="init_pid_changed", error_code="engine_init_pid_changed")
        else:
            result["error_code"] = "invalid_engine_state"
        if (result["running"] is False and result["restarting"] is False
                and (result["status"] not in {"exited", "dead"} or result["init_pid"] != 0)):
            result["error_code"] = "engine_terminal_state_inconsistent"
    except NotFound:
        result.update(identity="absent", error_code="engine_not_found", http_status=404)
    except Timeout:
        result["error_code"] = "engine_timeout"
    except ConnectionError:
        result["error_code"] = "engine_connection_unavailable"
    except APIError as error:
        result["error_code"] = "engine_api_error"
        status = getattr(getattr(error, "response", None), "status_code", None)
        if type(status) is int and 100 <= status <= 599:
            result["http_status"] = status
    except Exception:
        result["error_code"] = "engine_observation_unavailable"
    return result


def _confirmed_container_departure(original, client, deadline_ns):
    """Confirm terminal state after a failed original process/cgroup read.

    Rechecks share the process observation's 50 ms window. An in-flight inspect
    retains the original client's request timeout, so this is not an IO deadline.
    Neither a live/restarted identity nor unreadable engine state is zero charge.
    """
    started = time.monotonic_ns()
    result = {"checks": 0, "first_engine": None, "last_engine": None, "confirmed_terminal": False}
    if type(original.get("id")) is not str or re.fullmatch(r"[0-9a-f]{64}", original["id"]) is None:
        result.update(unavailable_reason="invalid_original_container_identity", elapsed_ns=0)
        return result
    if client is None:
        result.update(unavailable_reason="engine_client_unavailable", elapsed_ns=0)
        return result
    while True:
        now = time.monotonic_ns()
        if result["checks"] and now >= deadline_ns:
            result["elapsed_ns"] = now - started
            return result
        observed = _container_engine_observation(original, client)
        result["checks"] += 1
        if result["checks"] == 1:
            result["first_engine"] = observed
        result["last_engine"] = observed
        result["confirmed_terminal"] = observed["identity"] == "absent" or (
            observed["identity"] == "same" and observed["running"] is False
            and observed["restarting"] is False and observed["error_code"] is None
            and observed["status"] in {"exited", "dead"} and observed["init_pid"] == 0
        )
        now = time.monotonic_ns()
        if (result["confirmed_terminal"] or observed["identity"] in {"different", "init_pid_changed"}
                or result["checks"] >= EXIT_CONFIRMATION_CHECKS or now >= deadline_ns):
            result["elapsed_ns"] = now - started
            return result
        time.sleep(min(EXIT_CONFIRMATION_INTERVAL_NS, deadline_ns - now) / 1_000_000_000)


def _container_read_diagnostic(original, stage, error, confirmation):
    code = ("permission_denied" if isinstance(error, PermissionError) else
            "not_found" if isinstance(error, FileNotFoundError) else
            "os_error" if isinstance(error, OSError) else "invalid_data")
    identity = original.get("id")
    if type(identity) is not str or re.fullmatch(r"[0-9a-f]{64}", identity) is None:
        identity = None
    detail = error.args[0] if error.args and type(error.args[0]) is str else None
    if detail not in {"container_pid_reused", "invalid_owned_cgroup", "negative_container_memory",
                      "container_counter_identity_changed"}:
        detail = None
    return {"container_id": identity, "init_pid": original["pid"], "start_ticks": original["start_ticks"],
            "read_stage": stage, "error_code": code, "read_detail": detail,
            "errno": error.errno if isinstance(error, OSError) else None, **confirmation}


def _cgroup(pid):
    values = (Path("/proc") / str(pid) / "cgroup").read_text().splitlines()
    rows = [line[3:] for line in values if line.startswith("0::")]
    if len(rows) != 1 or not rows[0].startswith("/") or ".." in Path(rows[0]).parts:
        raise ValueError("cgroup_v2_unavailable")
    return rows[0]


@contextmanager
def ownership_state(workdir):
    path = Path(workdir) / "ownership.json"
    with _OWNERSHIP_LOCK:
        descriptor = os.open(Path(workdir) / "ownership.lock", os.O_RDWR | os.O_CREAT, 0o600)
        try:
            fcntl.flock(descriptor, fcntl.LOCK_EX)
            data = json.loads(path.read_bytes()) if path.exists() else {"containers": []}
            yield data
            write_private(path, data)
        finally:
            os.close(descriptor)


def register_container(workdir, client, container_id):
    """Register an exact owned running container for passive cgroup sampling."""
    container = client.containers.get(container_id)
    container.reload()
    identity = container.id
    pid = container.attrs.get("State", {}).get("Pid", 0)
    state = container.attrs.get("State", {})
    row = {"id": identity, "state": "running" if pid else ("stopped" if state.get("Status") in {"exited", "dead"} else "created"),
           "pid": pid, "start_ticks": None, "cgroup": None,
           "volume_names": [mount["Name"] for mount in container.attrs.get("Mounts", [])
                            if mount.get("Type") == "volume" and mount.get("Destination") == "/workspace" and mount.get("Name")]}
    if pid:
        row["start_ticks"] = proc_stat(pid)["start_ticks"]
        row["cgroup"] = _cgroup(pid)
    with ownership_state(workdir) as data:
        ranks = {"created": 0, "running": 1, "stopped": 2, "removed": 3}
        original = next((old for old in data["containers"] if old["id"] == identity), None)
        if original is not None and ranks[original["state"]] > ranks[row["state"]]:
            return  # immutable container: a stale observer cannot reopen custody
        data["containers"] = [old for old in data["containers"] if old["id"] != identity] + [row]


def mark_container_terminal(workdir, container_id, state="stopped"):
    if state not in {"stopped", "removed"}:
        raise ValueError("invalid_terminal_observation")
    with ownership_state(workdir) as data:
        for row in data["containers"]:
            if row["id"] == container_id:
                if row["state"] != "removed":
                    row["state"] = state


def discover_owned_containers(workdir, client):
    """Read-only fallback for an owned creation whose reply was lost.

    Managed labels alone do not confer ownership. The exact test directory must
    also own the source or model-socket bind mount. No deletion occurs here.
    """
    root = Path(workdir).resolve()
    from docker.errors import NotFound
    for container in client.containers.list(all=True, filters={"label": "openjules.managed=1"}):
        try:
            container.reload()
        except NotFound:
            continue  # concurrent observed removal, not a task-release receipt
        owned = False
        for mount in container.attrs.get("Mounts", []):
            if mount.get("Type") != "bind" or mount.get("Destination") not in {"/source", "/run/openjules-model"}:
                continue
            try:
                Path(mount["Source"]).resolve().relative_to(root)
                owned = True
            except (KeyError, ValueError):
                continue
        if owned:
            try:
                register_container(workdir, client, container.id)
            except NotFound:
                continue


def owned_volume_bytes(workdir, client):
    path = Path(workdir) / "ownership.json"
    data = json.loads(path.read_bytes()) if path.exists() else {"containers": []}
    names = {name for row in data["containers"] if row["state"] != "removed" for name in row.get("volume_names", [])}
    if not names:
        return 0
    observed = {row["Name"]: row.get("UsageData", {}).get("Size") for row in client.df().get("Volumes", []) if row.get("Name") in names}
    if any(name not in observed or type(observed[name]) is not int or observed[name] < 0 for name in names):
        raise ValueError("owned_volume_size_unavailable")
    return sum(observed.values())


def retained_idle_proof(case, workdir, containers, worker_id):
    """Recognize one qualified stopped idle retention, never a deletion receipt."""
    path = Path(workdir) / "installed-retention.json"
    if not path.exists():
        return None
    if (case.get("id") != "installed-idle" or case.get("kind") != "installed_idle"
            or type(case.get("sample")) is not int or case["sample"] != 1):
        raise ValueError("retention_case_not_qualified")
    with os.fdopen(os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb") as source:
        info = os.fstat(source.fileno())
        if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16384:
            raise ValueError("retention_proof_invalid")
        proof = json.loads(source.read(16385))
    keys = {"schema_version", "state", "container_id", "volume_name", "volume_identity_sha256",
            "worker_id", "reason", "observed_stopped", "capacity_reserved", "model_fixture_calls",
            "tasks_enrolled", "volume_storage_bytes", "scope"}
    if type(proof) is not dict or set(proof) != keys:
        raise ValueError("retention_proof_invalid")
    if (type(proof["schema_version"]) is not int or proof["schema_version"] != 1
            or proof["state"] != "retained_stopped" or proof["reason"] != "executed_capture_required"
            or proof["observed_stopped"] is not True or proof["worker_id"] != worker_id
            or type(worker_id) is not str or re.fullmatch(r"[0-9a-f]{32}", worker_id) is None
            or any(type(proof[name]) is not int or proof[name] != 0
                   for name in ("capacity_reserved", "model_fixture_calls", "tasks_enrolled"))
            or type(proof["volume_storage_bytes"]) is not int
            or not 0 <= proof["volume_storage_bytes"] <= case["max_storage_bytes"]):
        raise ValueError("retention_proof_invalid")
    for name, pattern in (("container_id", r"[0-9a-f]{64}"),
                          ("volume_name", r"openjules-work-[0-9a-f]{40}"),
                          ("volume_identity_sha256", r"[0-9a-f]{64}")):
        if type(proof[name]) is not str or re.fullmatch(pattern, proof[name]) is None:
            raise ValueError("retention_identity_invalid")
    scope = proof["scope"]
    if (type(scope) is not dict or set(scope) != {"deployment_id", "repository"}
            or type(scope["deployment_id"]) is not str
            or re.fullmatch(r"cost-idle-[0-9a-f]{16}", scope["deployment_id"]) is None
            or scope["repository"] != "github:github.com/managed-cost-fixture/idle"):
        raise ValueError("retention_scope_invalid")
    acquisition = json.loads((Path(workdir) / "installed-acquisition.json").read_bytes())
    remaining = [row for row in containers if row["state"] != "removed"]
    if (acquisition.get("scope") != scope or len(remaining) != 1
            or remaining[0]["state"] != "stopped" or remaining[0]["id"] != proof["container_id"]
            or remaining[0].get("volume_names") != [proof["volume_name"]]):
        raise ValueError("retention_original_ownership_mismatch")
    return proof


def custody_report(case, workdir, measurement_facts, uncertain):
    """Report known retention separately from unresolved original custody."""
    result = {"custody_unresolved": bool(uncertain), "retained_resources": [],
              "retained_volume_storage_bytes": 0}
    ownership = Path(workdir) / "ownership.json"
    try:
        containers = json.loads(ownership.read_bytes())["containers"] if ownership.exists() else []
        retained = retained_idle_proof(case, workdir, containers,
                                       measurement_facts.get("installed_owned_worker_id"))
        if retained is not None:
            result["retained_resources"] = [retained]
            result["retained_volume_storage_bytes"] = retained["volume_storage_bytes"]
        elif any(row["state"] != "removed" for row in containers):
            result["custody_unresolved"] = True
    except (OSError, ValueError, KeyError, TypeError):
        result["custody_unresolved"] = True
    return result


def tree_bytes(path):
    total = 0
    for directory, directories, files in os.walk(path, followlinks=False):
        directories[:] = [name for name in directories if not (Path(directory) / name).is_symlink()]
        for name in files:
            entry = Path(directory) / name
            try:
                if not entry.is_symlink():
                    total += entry.stat().st_size
            except FileNotFoundError:
                pass
    return total


def sample_owned(root_pid, root_start, workdir, *, proc=Path("/proc"), cgroups=Path("/sys/fs/cgroup"), container_client=None):
    """One simultaneous approximate RSS sum, plus separate container charge.

    PID/start identities are checked before and after IO reads. Short-lived
    processes between samples and shared-page duplication are explicit limits.
    Missing reads are reported, never substituted with a zero measurement.
    """
    missing = []
    departed = 0
    process_diagnostics, process_diagnostics_omitted = [], 0
    confirmation_deadline_ns = None
    rows = {}
    for entry in proc.iterdir():
        if not entry.name.isdecimal():
            continue
        try:
            row = proc_stat(int(entry.name), proc)
            rows[row["pid"]] = row
        except (OSError, ValueError):
            continue  # unrelated processes may exit while enumerating
    root = rows.get(root_pid)
    if root is None or root["start_ticks"] != root_start:
        return {"available": False, "reason": "owned_root_exited_or_reused"}
    selected = {root_pid}
    while True:
        grown = selected | {pid for pid, row in rows.items() if row["ppid"] in selected}
        if grown == selected:
            break
        selected = grown
    ownership = Path(workdir) / "ownership.json"
    try:
        containers = json.loads(ownership.read_bytes())["containers"] if ownership.exists() else []
    except (OSError, ValueError, KeyError):
        containers = []
        missing.append("ownership_registry_unreadable")
    container_groups = {row["cgroup"] for row in containers if row.get("cgroup")}
    processes = []
    for pid in sorted(selected):
        first = rows[pid]
        if first["state"] in {"Z", "X", "x"}:
            continue
        stage = "cgroup"
        try:
            cg = _cgroup(pid) if proc == Path("/proc") else None
            if cg in container_groups:
                continue
            stage = "io"
            io = {}
            for line in (proc / str(pid) / "io").read_text().splitlines():
                key, value = line.split(":", 1)
                if key in {"rchar", "wchar", "read_bytes", "write_bytes"}:
                    io[key] = int(value.strip())
            stage = "stat_after_io"
            last = proc_stat(pid, proc)
            if first["start_ticks"] != last["start_ticks"]:
                raise ValueError("pid_reused")
            if last["state"] in {"Z", "X", "x"}:
                departed += 1
            else:
                processes.append({key: last[key] for key in ("pid", "start_ticks", "rss_bytes", "user_ticks", "system_ticks")} | {"io": io})
        except (OSError, ValueError) as error:
            # A process can become a zombie while /proc/io is being read.
            # Only a confirmed original exit excludes it; a live, reused or
            # unreadable identity remains missing, never a zero measurement.
            if confirmation_deadline_ns is None:
                confirmation_deadline_ns = time.monotonic_ns() + EXIT_CONFIRMATION_NS
            confirmation = _confirmed_process_departure(first, proc, confirmation_deadline_ns)
            if len(process_diagnostics) < MAX_PROCESS_DIAGNOSTICS:
                process_diagnostics.append(_process_read_diagnostic(first, stage, error, confirmation))
            else:
                process_diagnostics_omitted += 1
            if confirmation["confirmed_departed"]:
                departed += 1
            else:
                missing.append("owned_process_observation_unavailable")
    container_samples = []
    container_departures = 0
    container_diagnostics, container_diagnostics_omitted = [], 0
    for row in containers:
        if row.get("state") != "running":
            continue
        stage = "stat_before_memory"
        try:
            observed = proc_stat(row["pid"], proc)
            if observed["start_ticks"] != row["start_ticks"]:
                raise ValueError("container_pid_reused")
            stage = "cgroup_identity"
            group = row.get("cgroup")
            if not isinstance(group, str) or not group.startswith("/") or ".." in Path(group).parts:
                raise ValueError("invalid_owned_cgroup")
            stage = "memory_current"
            memory = int((cgroups / group.lstrip("/") / "memory.current").read_text())
            if memory < 0:
                raise ValueError("negative_container_memory")
            stage = "stat_after_memory"
            if proc_stat(row["pid"], proc)["start_ticks"] != row["start_ticks"]:
                raise ValueError("container_counter_identity_changed")
            container_samples.append({"id": row["id"], "init_pid": row["pid"],
                                      "start_ticks": row["start_ticks"], "memory_current_bytes": memory})
        except (OSError, ValueError) as error:
            # The stop/removal callback can race this passive observation.
            # Confirm an actual terminal engine observation; never invent zero
            # charge merely because a cgroup or PID read failed.
            if confirmation_deadline_ns is None:
                confirmation_deadline_ns = time.monotonic_ns() + EXIT_CONFIRMATION_NS
            confirmation = _confirmed_container_departure(row, container_client, confirmation_deadline_ns)
            if len(container_diagnostics) < MAX_CONTAINER_DIAGNOSTICS:
                container_diagnostics.append(_container_read_diagnostic(row, stage, error, confirmation))
            else:
                container_diagnostics_omitted += 1
            if confirmation["confirmed_terminal"]:
                container_departures += 1
            else:
                missing.append("owned_container_observation_unavailable")
    pending_charge = 0
    acquisition = Path(workdir) / "installed-acquisition.json"
    if acquisition.exists() and not any(row.get("state") in {"running", "stopped", "removed"} for row in containers):
        try:
            pending = json.loads(acquisition.read_bytes())
            if pending.get("worker_ceiling") != 1 or (
                (pending.get("state"), pending.get("memory_reservation_bytes"))
                not in {("may_acquire", 536870912), ("removed", 0)}
            ):
                raise ValueError("invalid_pending_acquisition")
            pending_charge = pending["memory_reservation_bytes"]
        except (OSError, ValueError):
            missing.append("pending_acquisition_observation_unavailable")
    return {"available": True, "timestamp_ns": time.monotonic_ns(),
            "processes": processes, "containers": container_samples,
            "host_rss_bytes": sum(row["rss_bytes"] for row in processes),
            "container_charge_bytes": sum(row["memory_current_bytes"] for row in container_samples),
            "pending_container_memory_reservation_bytes": pending_charge,
            "processes_departed_during_observation": departed,
            "process_read_diagnostics": process_diagnostics,
            "process_read_diagnostics_omitted": process_diagnostics_omitted,
            "containers_terminal_during_observation": container_departures,
            "container_read_diagnostics": container_diagnostics,
            "container_read_diagnostics_omitted": container_diagnostics_omitted,
            "missing": sorted(set(missing))}


def resource_summary(samples):
    good = [row for row in samples if row.get("available")]
    sums = [row["host_rss_bytes"] + row["container_charge_bytes"] for row in good]
    complete = bool(good) and not any(row["missing"] for row in good)
    gaps = [last["timestamp_ns"] - first["timestamp_ns"] for first, last in zip(good, good[1:])]
    diagnostics = [diagnostic | {"observation_timestamp_ns": row["timestamp_ns"]}
                   for row in good for diagnostic in row.get("process_read_diagnostics", [])]
    container_diagnostics = [diagnostic | {"observation_timestamp_ns": row["timestamp_ns"]}
                             for row in good for diagnostic in row.get("container_read_diagnostics", [])]
    return {"sample_count": len(good), "target_sampling_interval_seconds": 0.1,
            "actual_observation_gap_ns": {"minimum": min(gaps, default=None),
                                           "median": statistics.median(gaps) if gaps else None,
                                           "maximum": max(gaps, default=None)},
            "sampled_max_owned_mixed_memory_bytes": max(sums, default=None) if complete else None,
            "sampled_observed_mixed_memory_lower_bound_bytes": max(sums, default=None),
            "pending_acquisition_reservation_max_bytes": max((row.get("pending_container_memory_reservation_bytes", 0) for row in good), default=0),
            "observations_using_pending_acquisition_reservation": sum(row.get("pending_container_memory_reservation_bytes", 0) > 0 for row in good),
            "complete_observations": complete,
            "observations_with_missing_reads": sum(bool(row["missing"]) for row in good),
            "observed_process_departures": sum(row.get("processes_departed_during_observation", 0) for row in good),
            "process_read_diagnostics": diagnostics[:MAX_SUMMARY_PROCESS_DIAGNOSTICS],
            "process_read_diagnostics_omitted": sum(row.get("process_read_diagnostics_omitted", 0) for row in good)
                + max(0, len(diagnostics) - MAX_SUMMARY_PROCESS_DIAGNOSTICS),
            "process_exit_confirmation": {"shared_budget_ns_per_observation": EXIT_CONFIRMATION_NS,
                                           "interval_ns": EXIT_CONFIRMATION_INTERVAL_NS,
                                           "maximum_checks_per_failed_read": EXIT_CONFIRMATION_CHECKS,
                                           "one_initial_check_after_shared_window": True},
            "observed_container_departures": sum(row.get("containers_terminal_during_observation", 0) for row in good),
            "container_read_diagnostics": container_diagnostics[:MAX_SUMMARY_CONTAINER_DIAGNOSTICS],
            "container_read_diagnostics_omitted": sum(row.get("container_read_diagnostics_omitted", 0) for row in good)
                + max(0, len(container_diagnostics) - MAX_SUMMARY_CONTAINER_DIAGNOSTICS),
            "container_exit_confirmation": {"shared_window_with_process_reads_ns": EXIT_CONFIRMATION_NS,
                                             "interval_ns": EXIT_CONFIRMATION_INTERVAL_NS,
                                             "maximum_checks_per_failed_read": EXIT_CONFIRMATION_CHECKS,
                                             "one_initial_check_after_shared_window": True,
                                             "engine_request_timeout_seconds": 3,
                                             "in_flight_inspect_may_exceed_recheck_window": True},
            "scopes": ["simultaneous approximate descendant RSS, not summed individual peaks",
                       "separate owned cgroup-v2 memory.current; excludes container PIDs from host RSS",
                       "shared pages may be counted by several host processes; daemon and kernel cost excluded",
                       "short-lived process peaks and allocations between samples may be missed",
                       "pending installed acquisition uses its512MiB ceiling for admission, not a measured cgroup peak",
                       "io counters are per observed process lifetime, not whole-host physical IO"]}


class BudgetStop(RuntimeError):
    pass


@contextmanager
def ownership_hooks(workdir, monkeypatch, recorder):
    """Observe only containers created by this sample, never host-wide cleanup."""
    from docker.models.containers import Container, ContainerCollection
    from docker.models.volumes import Volume
    from src.worker.docker_runtime import ManagedDockerRuntime
    owned = set()
    guarded = {"uncertain": False}
    original_create, original_start = ContainerCollection.create, Container.start
    original_stop, original_remove = Container.stop, Container.remove
    original_volume_remove = Volume.remove
    original_ensure = ManagedDockerRuntime.ensure

    def create(collection, *args, **kwargs):
        if STOP.is_set():
            raise BudgetStop("new_admission_closed")
        if len(owned) >= 2:
            raise BudgetStop("worker_ceiling")
        try:
            container = original_create(collection, *args, **kwargs)
            owned.add(container.id)
            register_container(workdir, collection.client, container.id)
        except BaseException:
            guarded["uncertain"] = True
            raise
        recorder.add("docker.created")
        return container

    def start(container, *args, **kwargs):
        result = original_start(container, *args, **kwargs)
        if container.id in owned:
            register_container(workdir, container.client, container.id)
            recorder.add("docker.started")
        return result

    def stop(container, *args, **kwargs):
        result = original_stop(container, *args, **kwargs)
        if container.id in owned:
            container.reload()
            if not container.attrs.get("State", {}).get("Running"):
                mark_container_terminal(workdir, container.id)
                recorder.add("docker.stopped")
        return result

    def remove(container, *args, **kwargs):
        if container.id in owned and guarded["uncertain"]:
            raise BudgetStop("owned_capture_unresolved")
        result = original_remove(container, *args, **kwargs)
        if container.id in owned:
            owned.remove(container.id)
            mark_container_terminal(workdir, container.id, "removed")
            recorder.add("docker.removed")
        return result

    def volume_remove(volume, *args, **kwargs):
        if guarded["uncertain"]:
            raise BudgetStop("owned_capture_unresolved")
        return original_volume_remove(volume, *args, **kwargs)

    def ensure(runtime, worker, spec):
        if STOP.is_set():
            raise BudgetStop("new_admission_closed")
        try:
            result = original_ensure(runtime, worker, spec)
            if result.state == "unknown":
                guarded["uncertain"] = True
            return result
        except BaseException:
            guarded["uncertain"] = True
            raise

    monkeypatch.setattr(ContainerCollection, "create", create)
    monkeypatch.setattr(Container, "start", start)
    monkeypatch.setattr(Container, "stop", stop)
    monkeypatch.setattr(Container, "remove", remove)
    monkeypatch.setattr(Volume, "remove", volume_remove)
    monkeypatch.setattr(ManagedDockerRuntime, "ensure", ensure)
    try:
        yield guarded
    finally:
        recorder.fact("control", {"owned_containers_remaining": len(owned),
                                  "uncertain_resources_retained": guarded["uncertain"]})


def validate_manifest(value):
    if not isinstance(value, dict) or value.get("schema_version") != 1 or value.get("investigation") != "managed-costs-v1":
        raise ValueError("unsupported_manifest")
    cap = value.get("caps", {})
    if cap != {"elapsed_seconds": 1800, "cleanup_reserve_seconds": 90,
              "workers": 2, "children_per_root": 2, "storage_bytes": 8 * 1024**3,
              "sampled_memory_bytes": 4 * 1024**3, "fixture_transfer_bytes": 512 * MIB}:
        raise ValueError("investigation_caps_changed")
    cases = value.get("cases")
    if not isinstance(cases, list) or not 1 <= len(cases) <= 30:
        raise ValueError("case_count_invalid")
    ids = set()
    kinds = {"source", "capture", "publication", "root", "children", "two_workers", "control_denial", "control_cancel", "installed_idle", "overhead"}
    for case in cases:
        if not isinstance(case, dict) or set(case) != {"id", "kind", "samples", "limit_seconds", "max_transfer_bytes", "max_storage_bytes", "instrumented", "params"}:
            raise ValueError("case_schema_invalid")
        if not isinstance(case["id"], str) or not case["id"].replace("-", "").isalnum() or case["id"] in ids:
            raise ValueError("case_identity_invalid")
        ids.add(case["id"])
        if case["kind"] not in kinds or type(case["samples"]) is not int or not 1 <= case["samples"] <= 5:
            raise ValueError("case_parameters_invalid")
        if type(case["limit_seconds"]) is not int or not 1 <= case["limit_seconds"] <= 600 or type(case["instrumented"]) is not bool:
            raise ValueError("case_limits_invalid")
        for name, maximum in (("max_transfer_bytes", 512 * MIB), ("max_storage_bytes", 8 * 1024**3)):
            if type(case[name]) is not int or not 0 <= case[name] <= maximum:
                raise ValueError("case_budget_invalid")
    if sum(case["samples"] * case["max_transfer_bytes"] for case in cases) > cap["fixture_transfer_bytes"]:
        raise ValueError("declared_transfer_exceeds_investigation_cap")
    if sum(case["samples"] * case["max_storage_bytes"] for case in cases) > cap["storage_bytes"]:
        raise ValueError("declared_storage_exceeds_investigation_cap")
    idle = [case for case in cases if case["kind"] == "installed_idle"]
    if len(idle) != 1 or idle[0]["id"] != "installed-idle" or idle[0]["samples"] != 1:
        raise ValueError("final_idle_case_not_qualified")
    return value


def ordered_cases(manifest):
    """Alternate comparable runs; the sole idle retention must finish the trial."""
    result = []
    for sample in range(max(row["samples"] for row in manifest["cases"])):
        rows = manifest["cases"] if sample % 2 == 0 else list(reversed(manifest["cases"]))
        for case in rows:
            if case["kind"] != "installed_idle" and sample < case["samples"]:
                result.append(case | {"sample": sample + 1})
    result.extend(case | {"sample": 1} for case in manifest["cases"] if case["kind"] == "installed_idle")
    return result


def _git(*arguments):
    return subprocess.check_output(["git", *arguments], text=True, timeout=10).strip()


def identity(manifest):
    revision = _git("rev-parse", "HEAD")
    if _git("status", "--porcelain"):
        raise ValueError("source_checkout_not_clean")
    if _git("diff", "--name-only", manifest["baseline_revision"], "--", "src", "docker", "tests/integration"):
        raise ValueError("production_or_existing_native_fixture_drift")
    cpu = next((line.split(":", 1)[1].strip() for line in Path("/proc/cpuinfo").read_text().splitlines()
                if line.startswith("model name") and ":" in line), "unavailable")
    return {"source_revision": revision, "baseline_revision": manifest["baseline_revision"],
            "production_tree": _git("rev-parse", "HEAD:src"),
            "interpreter": sys.version.split()[0], "platform": platform.platform(),
            "machine": platform.machine(), "kernel": platform.release(),
            "cpu_count": os.cpu_count(), "cpu_model": cpu[:256], "clock_ticks_per_second": os.sysconf("SC_CLK_TCK")}


def run_child(args):
    import docker
    import pytest
    from tools.managed_cost_measurement import Recorder
    from tools.managed_cost_cases import run_case as runtime_case
    from tools.managed_cost_artifacts import run_case as artifact_case
    case = json.loads(Path(args.case).read_bytes())
    workdir = Path(args.work_dir)
    workdir.mkdir(parents=True, exist_ok=True, mode=0o700)
    def interrupted(*_):
        STOP.set()
        if "_guard" in case:
            case["_guard"]["uncertain"] = True
        raise KeyboardInterrupt

    signal.signal(signal.SIGTERM, interrupted)
    signal.signal(signal.SIGINT, interrupted)
    recorder = Recorder(workdir, enabled=case["instrumented"],
                        impairment_ms=case["params"].get("delay_ms", 0),
                        bytes_per_second=case["params"].get("body_bytes_per_second", 1250000))
    patch = pytest.MonkeyPatch()
    recorder.install(patch)
    client = None
    images = {}
    started = time.monotonic_ns()
    before = resource.getrusage(resource.RUSAGE_SELF)
    report = {"case_id": case["id"], "sample": case["sample"], "status": "FAIL", "facts": {}}
    try:
        if case["kind"] not in {"source", "publication", "overhead"}:
            client = docker.from_env(timeout=10)
            client.api.max_redirects = 0
            client.ping()
            info = client.info()
            if any("rootless" in option or "userns" in option for option in info.get("SecurityOptions", [])):
                raise ValueError("unsupported_docker_topology")
            for key, value in (("runtime", args.runtime_image), ("agent", args.agent_image)):
                if value:
                    image = client.images.get(value)
                    if image.id != value:
                        raise ValueError("immutable_image_id_changed")
                    images[key] = (client, image.id)
        with ownership_hooks(workdir, patch, recorder) as guard:
            case["_guard"] = guard
            if case["kind"] in {"source", "capture", "publication"}:
                result = artifact_case(case, workdir, recorder, images, patch)
            elif case["kind"] == "installed_idle":
                from tools.managed_cost_installed import run_case
                result = run_case(case, workdir, recorder, images, patch)
            else:
                result = runtime_case(case, workdir, recorder, images, patch)
            report["facts"] = result
        report["status"] = "CENSORED" if STOP.is_set() else "PASS"
    except BaseException as error:
        report["diagnostic_code"] = "budget_stop" if isinstance(error, BudgetStop) or STOP.is_set() else "case_assertion_or_prerequisite_failed"
        report["exception_type"] = type(error).__name__ if type(error).__name__ in {"AssertionError", "ValueError", "RuntimeError", "TimeoutExpired", "BudgetStop", "FileNotFoundError", "PermissionError"} else "OtherException"
        report["status"] = "CENSORED" if STOP.is_set() or isinstance(error, BudgetStop) else "FAIL"
    finally:
        after = resource.getrusage(resource.RUSAGE_SELF)
        report.update(wall_ns=time.monotonic_ns() - started,
                      process_cpu={"self_user_seconds": after.ru_utime - before.ru_utime,
                                   "self_system_seconds": after.ru_stime - before.ru_stime},
                      measurements=recorder.report())
        if not report["measurements"].get("complete", False) and report["status"] == "PASS":
            report["status"] = "FAIL"
            report["diagnostic_code"] = "measurement_incomplete"
        measurement_facts = report["measurements"].get("facts", {})
        report.update(custody_report(case, workdir, measurement_facts,
                      case.get("_guard", {}).get("uncertain")
                      or measurement_facts.get("failed_sample_cleanup") == "unresolved"))
        if report["custody_unresolved"] and report["status"] == "PASS":
            report["status"] = "FAIL"
            report["diagnostic_code"] = "original_resource_custody_unresolved"
        running_owned_threads = any(thread.is_alive() for thread in case.get("_owned_threads", []))
        if running_owned_threads:
            report["custody_unresolved"] = True
            report["status"] = "CENSORED"
            report["diagnostic_code"] = "owned_worker_threads_unresolved"
        else:
            patch.undo()
        if client is not None and not running_owned_threads:
            client.close()
        write_private(workdir / "sample.json", report)
    return 0 if report["status"] == "PASS" else 1


def summarize(rows):
    result = {}
    for name in sorted({row["case_id"] for row in rows}):
        selected = [row for row in rows if row["case_id"] == name]
        timings = [row["wall_ns"] for row in selected if row["status"] == "PASS"]
        result[name] = {"samples": len(selected), "passed": len(timings),
                        "wall_ns_raw": timings, "median_wall_ns": statistics.median(timings) if timings else None,
                        "range_wall_ns": [min(timings), max(timings)] if timings else None,
                        "percentiles_reported": False}
    return result


def run_suite(args):
    import docker
    manifest_bytes = Path(args.manifest).read_bytes()
    if hashlib.sha256(manifest_bytes).hexdigest() != args.manifest_sha256:
        raise ValueError("manifest_digest_mismatch")
    manifest = validate_manifest(json.loads(manifest_bytes))
    environment = identity(manifest)
    if platform.system() != "Linux" or platform.machine() not in {"x86_64", "AMD64"} or sys.version_info[:2] != (3, 12):
        raise ValueError("declared_host_mismatch")
    root = Path(args.work_dir).absolute()
    root.mkdir(mode=0o700, parents=True, exist_ok=False)
    filesystem = os.statvfs(root)
    environment["work_filesystem"] = {
        "type": subprocess.check_output(["stat", "-f", "-c", "%T", str(root)], text=True, timeout=5).strip(),
        "block_bytes": filesystem.f_bsize, "allocation_unit_bytes": filesystem.f_frsize,
    }
    caps = manifest["caps"]
    started = time.monotonic()
    deadline = started + caps["elapsed_seconds"]
    rows = []
    scheduled = ordered_cases(manifest)
    observation_client = docker.from_env(timeout=3)
    observation_client.api.max_redirects = 0
    used_transfer = 0
    stopped = None
    for case in scheduled:
        safe_case = {key: value for key, value in case.items()}
        if stopped or time.monotonic() + case["limit_seconds"] + caps["cleanup_reserve_seconds"] > deadline:
            stopped = stopped or "insufficient_remaining_case_budget"
            rows.append({"case_id": case["id"], "sample": case["sample"], "status": "NOT_RUN", "diagnostic_code": stopped})
            continue
        if used_transfer + case["max_transfer_bytes"] > caps["fixture_transfer_bytes"]:
            stopped = "insufficient_transfer_budget"
            rows.append({"case_id": case["id"], "sample": case["sample"], "status": "NOT_RUN", "diagnostic_code": stopped})
            continue
        sample_dir = root / f"{case['id']}-{case['sample']}"
        sample_dir.mkdir(mode=0o700)
        for key in ("zpm_checkout", "polyphony_checkout", "dependency_plan"):
            value = getattr(args, key, None)
            if value:
                safe_case[key] = str(Path(value).absolute())
        case_file = sample_dir / "case.json"
        write_private(case_file, safe_case)
        command = [sys.executable, "-m", "tools.managed_costs", "_case", "--case", str(case_file), "--work-dir", str(sample_dir)]
        for flag in ("runtime_image", "agent_image"):
            if getattr(args, flag):
                command.extend(["--" + flag.replace("_", "-"), getattr(args, flag)])
        with (sample_dir / "private-output.log").open("wb") as log:
            process = subprocess.Popen(command, stdout=log, stderr=subprocess.STDOUT, start_new_session=True)
            original = proc_stat(process.pid)["start_ticks"]
            observations = []
            sample_deadline = time.monotonic() + case["limit_seconds"]
            censored = None
            missing_streak = 0
            while process.poll() is None:
                if len(observations) % 10 == 0:
                    try:
                        discover_owned_containers(sample_dir, observation_client)
                        disk_bytes = tree_bytes(root) + owned_volume_bytes(sample_dir, observation_client)
                        if disk_bytes > caps["storage_bytes"]:
                            censored = "owned_storage_cap"
                    except BaseException:
                        censored = "owned_container_discovery_unavailable"
                observation = sample_owned(process.pid, original, sample_dir, container_client=observation_client)
                observations.append(observation)
                missing_streak = missing_streak + 1 if observation.get("missing") else 0
                if missing_streak >= 10:
                    censored = "owned_resource_observation_unavailable"
                if observation.get("available") and observation["host_rss_bytes"] + observation["container_charge_bytes"] + observation.get("pending_container_memory_reservation_bytes", 0) > caps["sampled_memory_bytes"]:
                    censored = "sampled_memory_cap"
                if time.monotonic() >= sample_deadline:
                    censored = "case_deadline"
                if censored:
                    process.send_signal(signal.SIGTERM)
                    try:
                        process.wait(timeout=min(60, max(1, deadline - time.monotonic())))
                    except subprocess.TimeoutExpired:
                        # Kill only this owned process group; never claim this
                        # releases managed resources. Original guest watchdogs
                        # and durable journals remain the recovery authority.
                        os.killpg(process.pid, signal.SIGKILL)
                        process.wait(timeout=5)
                    break
                time.sleep(0.1)
        sample_path = sample_dir / "sample.json"
        if sample_path.is_file() and sample_path.stat().st_size <= MAX_REPORT:
            row = json.loads(sample_path.read_bytes())
        else:
            row = {"case_id": case["id"], "sample": case["sample"], "status": "CENSORED", "diagnostic_code": "child_report_unavailable"}
        if row.get("case_id") != case["id"] or row.get("sample") != case["sample"]:
            row = {"case_id": case["id"], "sample": case["sample"], "status": "FAIL", "diagnostic_code": "child_report_identity_mismatch", "custody_unresolved": True}
        if process.returncode != 0 and row["status"] == "PASS":
            row["status"] = "FAIL"
            row["diagnostic_code"] = "child_exit_not_successful"
        row["resource_summary"] = resource_summary(observations)
        row["resource_samples"] = observations
        if not row["resource_summary"]["complete_observations"] and row["status"] == "PASS":
            row["status"] = "FAIL"
            row["diagnostic_code"] = "resource_measurement_incomplete"
        if censored:
            row["status"] = "CENSORED"
            row["diagnostic_code"] = censored
            stopped = censored
        if row.get("custody_unresolved") or row.get("diagnostic_code") == "child_report_unavailable":
            stopped = "original_resource_custody_unresolved"
        if row.get("retained_resources"):
            # The final idle worker is deliberately retained by the producer.
            # Account for that storage and close admission, without pretending
            # a stopped container or retained volume was physically removed.
            stopped = stopped or "qualified_idle_retention_closes_admission"
            try:
                expected = custody_report(case, sample_dir, row.get("measurements", {}).get("facts", {}), False)
                if (expected["custody_unresolved"] or expected["retained_resources"] != row["retained_resources"]
                        or expected["retained_volume_storage_bytes"] != row.get("retained_volume_storage_bytes")
                        or case != scheduled[-1]):
                    raise ValueError("retention_proof_not_final_or_changed")
                row["final_owned_volume_storage_bytes"] = owned_volume_bytes(sample_dir, observation_client)
                row["final_owned_storage_bytes"] = tree_bytes(root) + row["final_owned_volume_storage_bytes"]
                if row["final_owned_storage_bytes"] > caps["storage_bytes"]:
                    raise ValueError("retained_storage_cap")
            except Exception:
                row["custody_unresolved"] = True
                row["status"] = "FAIL"
                row["diagnostic_code"] = "retained_resource_qualification_incomplete"
                stopped = "original_resource_custody_unresolved"
        # Reserve the declared bound; unmeasured fixture traffic is never
        # incorrectly treated as zero budget consumption.
        used_transfer += case["max_transfer_bytes"]
        rows.append(row)
        report = {"schema_version": 1, "investigation": "managed-costs-v1", "environment": environment,
                  "manifest_sha256": args.manifest_sha256, "image_ids": {"runtime": args.runtime_image, "agent": args.agent_image},
                  "samples": rows, "summary": summarize(rows), "complete": False,
                  "elapsed_seconds": time.monotonic() - started, "declared_transfer_reserved_bytes": used_transfer}
        write_private(root / "report.json", report)
    report = {"schema_version": 1, "investigation": "managed-costs-v1", "environment": environment,
              "manifest_sha256": args.manifest_sha256, "image_ids": {"runtime": args.runtime_image, "agent": args.agent_image},
              "samples": rows, "summary": summarize(rows),
              "complete": len(rows) == len(scheduled) and all(row["status"] == "PASS" for row in rows),
              "elapsed_seconds": time.monotonic() - started, "declared_transfer_reserved_bytes": used_transfer,
              "admission_closed_reason": stopped,
              "retained_resources": [resource for row in rows for resource in row.get("retained_resources", [])],
              "retained_volume_storage_bytes": sum(row.get("retained_volume_storage_bytes", 0) for row in rows),
              "limits": ["synthetic local authority/model/forge fixtures; no live provider or forge mutation",
                         "source and Docker image reuse do not reuse an execution incarnation",
                         "nested span wall/thread CPU is inclusive and must not be added",
                         "five comparable samples support median/range, not p95 or a service objective",
                         "only explicitly labeled installed idle uses real pinned sibling services",
                         "the final never-dispatched idle worker remains stopped and retained; known custody is not physical removal"]}
    write_private(root / "report.json", report)
    observation_client.close()
    return 0 if report["complete"] else 1


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("operation", choices=("run", "_case"))
    parser.add_argument("--work-dir", required=True)
    parser.add_argument("--manifest")
    parser.add_argument("--manifest-sha256")
    parser.add_argument("--case")
    parser.add_argument("--runtime-image")
    parser.add_argument("--agent-image")
    parser.add_argument("--zpm-checkout")
    parser.add_argument("--polyphony-checkout")
    parser.add_argument("--dependency-plan")
    args = parser.parse_args(argv)
    return run_child(args) if args.operation == "_case" else run_suite(args)


if __name__ == "__main__":
    raise SystemExit(main())
