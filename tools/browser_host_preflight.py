"""One reviewed CI host prerequisite, with no candidate acquisition or browser.

Source checkout is ordinary CI setup. This helper owns exactly one fixed
namespace child; it does not qualify Chromium's sandbox or a browser journey.
"""

import argparse
import hashlib
import json
import math
import os
from pathlib import Path
import platform
import re
import resource
import selectors
import signal
import socket
import stat
import subprocess
import sys
import time

LIMITS = {
    "candidate_acquisition_bytes": 0, "browser_sessions": 0,
    "page_actions": 0, "model_calls": 0, "inet_connections": 0,
    "namespace_children": 1, "unix_socket_objects": 3, "unix_payload_bytes": 16,
    "child_seconds": 5, "overall_seconds": 15, "cleanup_seconds": 3,
    "supervisor_term_seconds": 14, "supervisor_kill_seconds": 1,
    "owned_storage_bytes": 1048576, "report_bytes": 65536,
    "pipe_bytes": 8192, "stderr_bytes": 1024, "child_address_space_bytes": 134217728,
    "child_cpu_seconds": 2, "child_file_descriptors": 32,
}
HOST = {
    "runner_environment": "github-hosted", "runner_os": "Linux", "runner_arch": "X64",
    "image_os": "ubuntu24", "image_version": "20261111.370.1",
    "os_id": "ubuntu", "os_version_id": "24.04", "os_release": "24.04.5",
    "kernel": "7.0.0-1017-azure", "machine": "x86_64",
    "python_version": "3.12.3", "python_executable": "/usr/bin/python3",
    "minimum_available_memory_bytes": 4294967296,
    "minimum_free_storage_bytes": 4294967296,
}
PAYLOAD = b"oj-host-ipc-0001"
REPOSITORY = "niklas-olsson/OpenJules"
WORKFLOW = ".github/workflows/browser-host-prerequisite.yml"
RUN_REF = re.compile(r"refs/heads/qualification/browser-host/run/([0-9a-f]{64})-([0-9a-f]{40})\Z")
CHILD_ENV = {"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}


class Refused(ValueError):
    pass


class Deadline(TimeoutError):
    pass


def encoded(value):
    return (json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False) + "\n").encode()


def digest(raw):
    return hashlib.sha256(raw).hexdigest()


def read_bounded(path, maximum=65536):
    with open(path, "rb") as source:
        raw = source.read(maximum + 1)
    if len(raw) > maximum:
        raise Refused("input_size_exceeded")
    return raw


def strict_json(raw, *, allow_floats=False):
    def pairs(items):
        result = {}
        for name, value in items:
            if name in result:
                raise Refused("duplicate_json_field")
            result[name] = value
        return result

    def non_integer(_):
        raise Refused("non_integer_json_number")

    def decimal(text):
        value = float(text)
        if not math.isfinite(value):
            raise Refused("non_finite_json_number")
        return value

    try:
        return json.loads(raw, object_pairs_hook=pairs, parse_float=decimal if allow_floats else non_integer,
                          parse_constant=non_integer)
    except (UnicodeError, json.JSONDecodeError, RecursionError):
        raise Refused("invalid_json") from None


def checked_manifest(raw, root):
    value = strict_json(raw)
    if (type(value) is not dict or set(value) != {
            "schema_version", "run_id", "source_base_commit", "tool_sha256",
            "workflow_sha256", "host", "limits", "scope"}
            or type(value["schema_version"]) is not int or value["schema_version"] != 1
            or value["run_id"] != "oj-browser-host-20261114-1"
            or value["scope"] != "native-host-prerequisites-only"
            or not isinstance(value["source_base_commit"], str)
            or not re.fullmatch(r"[0-9a-f]{40}", value["source_base_commit"])
            or type(value["limits"]) is not dict or value["limits"] != LIMITS
            or any(type(v) is not int for v in value["limits"].values())
            or type(value["host"]) is not dict or value["host"] != HOST
            or any(type(value["host"][key]) is not type(expected) for key, expected in HOST.items())):
        raise Refused("manifest_fields_changed")
    if value["tool_sha256"] != digest(read_bounded(root / "tools/browser_host_preflight.py")):
        raise Refused("helper_bytes_changed")
    if value["workflow_sha256"] != digest(read_bounded(root / WORKFLOW)):
        raise Refused("workflow_bytes_changed")
    return value


def ci_identity(environ, plan_hash):
    match = RUN_REF.fullmatch(environ.get("GITHUB_REF", ""))
    source = environ.get("GITHUB_SHA", "")
    if (not match or match.group(1) != plan_hash or match.group(2) != source
            or environ.get("GITHUB_REPOSITORY") != REPOSITORY
            or environ.get("GITHUB_EVENT_NAME") != "push"
            or environ.get("BROWSER_HOST_EVENT_CREATED") != "true"
            or environ.get("GITHUB_RUN_ATTEMPT") != "1"
            or environ.get("GITHUB_ACTIONS") != "true"
            or not re.fullmatch(r"[1-9][0-9]{0,19}", environ.get("GITHUB_RUN_ID", ""))):
        raise Refused("immutable_activation_changed")
    return {"source_commit": source, "workflow_run_id": environ["GITHUB_RUN_ID"], "workflow_run_attempt": 1}


def executable_record(path):
    resolved = Path(path).resolve(strict=True)
    info = resolved.stat()
    if not stat.S_ISREG(info.st_mode) or not 0 < info.st_size <= 16777216:
        raise Refused("host_executable_unavailable")
    return {"path": path, "bytes": info.st_size, "sha256": digest(read_bounded(resolved, 16777216))}


def status_fields(raw):
    result = {}
    for line in raw.decode("ascii").splitlines():
        if ":" in line:
            name, value = line.split(":", 1)
            result[name] = value.strip()
    return result


def process_sample(pid, expected_parent):
    directory = Path("/proc") / str(pid)
    first = read_bounded(directory / "stat").decode("ascii").rsplit(") ", 1)[1].split()
    current = status_fields(read_bounded(directory / "status"))
    second = read_bounded(directory / "stat").decode("ascii").rsplit(") ", 1)[1].split()
    if (first[19] != second[19] or first[0] == "Z" or second[0] == "Z"
            or int(current["Pid"]) != pid or int(current["PPid"]) != expected_parent
            or int(first[1]) != expected_parent or int(second[1]) != expected_parent):
        raise Refused("owned_process_identity_changed")
    rss = current["VmRSS"].split()
    if len(rss) != 2 or rss[1] != "kB" or not rss[0].isdecimal():
        raise Refused("owned_process_memory_unavailable")
    return {"pid": pid, "parent_pid": expected_parent, "start_ticks": int(first[19]),
            "rss_bytes": int(rss[0]) * 1024, "uids": [int(v) for v in current["Uid"].split()]}


def host_observation(environ, directory):
    release = platform.freedesktop_os_release()
    memory = status_fields(read_bounded("/proc/meminfo"))["MemAvailable"].split()
    if len(memory) != 2 or memory[1] != "kB" or not memory[0].isdecimal():
        raise Refused("available_memory_unavailable")
    disk = os.statvfs(directory)
    value = {
        "runner_environment": environ.get("RUNNER_ENVIRONMENT"),
        "runner_os": environ.get("RUNNER_OS"), "runner_arch": environ.get("RUNNER_ARCH"),
        "image_os": environ.get("ImageOS"), "image_version": environ.get("ImageVersion"),
        "os_id": release.get("ID"), "os_version_id": release.get("VERSION_ID"),
        "os_release": release.get("VERSION", "").split(" ")[0],
        "kernel": platform.release(), "machine": platform.machine(),
        "python_version": platform.python_version(), "python_executable": sys.executable,
        "uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "egid": os.getegid(),
        "available_memory_bytes": int(memory[0]) * 1024,
        "free_storage_bytes": disk.f_bavail * disk.f_frsize,
        "user_namespace": os.stat("/proc/self/ns/user").st_ino,
        "network_namespace": os.stat("/proc/self/ns/net").st_ino,
    }
    return value


def require_host(value):
    for key, expected in HOST.items():
        if key.startswith("minimum_"):
            continue
        if value[key] != expected:
            raise Refused("declared_host_changed")
    if any(value[key] <= 0 for key in ("uid", "euid", "gid", "egid")) or value["uid"] != value["euid"] or value["gid"] != value["egid"]:
        raise Refused("nonroot_identity_unavailable")
    if (value["available_memory_bytes"] < HOST["minimum_available_memory_bytes"]
            or value["free_storage_bytes"] < HOST["minimum_free_storage_bytes"]):
        raise Refused("declared_host_resources_unavailable")


def namespace_facts(parent_user, parent_net, uid, gid):
    current = {"uid": os.getuid(), "euid": os.geteuid(), "gid": os.getgid(), "egid": os.getegid(),
               "user_namespace": os.stat("/proc/self/ns/user").st_ino,
               "network_namespace": os.stat("/proc/self/ns/net").st_ino}
    if uid <= 0 or gid <= 0 or current["uid"] != uid or current["euid"] != uid or current["gid"] != gid or current["egid"] != gid:
        raise Refused("child_nonroot_identity_changed")
    if current["user_namespace"] == parent_user or current["network_namespace"] == parent_net:
        raise Refused("namespace_isolation_unavailable")
    interfaces = sorted(name for _, name in socket.if_nameindex())
    v4 = read_bounded("/proc/net/route").decode("ascii").splitlines()
    v6 = read_bounded("/proc/net/ipv6_route").decode("ascii").splitlines()
    # Fresh network namespaces may retain an unreachable IPv6 loopback sentinel.
    # Any non-loopback interface or non-reject route is outside this empty route.
    if interfaces != ["lo"] or any(line.strip() for line in v4[1:]):
        raise Refused("unexpected_network_route")
    for line in v6:
        parts = line.split()
        if len(parts) != 10 or parts[-1] != "lo" or not int(parts[8], 16) & 0x200:
            raise Refused("unexpected_network_route")
    current.update(interfaces=interfaces, ipv4_routes=0, ipv6_reject_routes=len(v6),
                   uid_map=read_bounded("/proc/self/uid_map", 1024).decode("ascii").split(),
                   gid_map=read_bounded("/proc/self/gid_map", 1024).decode("ascii").split())
    if current["uid_map"] != [str(uid), str(uid), "1"] or current["gid_map"] != [str(gid), str(gid), "1"]:
        raise Refused("namespace_identity_map_changed")
    return current


def write_message(value):
    raw = encoded(value)
    if len(raw) > 4096 or os.write(1, raw) != len(raw):
        raise Refused("child_pipe_write_failed")


def child_main(directory, parent_user, parent_net, uid, gid):
    objects = []
    path = Path(directory) / "probe.sock"
    status, reason, facts = "refused", "child_probe_failed", None
    stage = "namespace_observation"
    try:
        resource.setrlimit(resource.RLIMIT_CORE, (0, 0))
        resource.setrlimit(resource.RLIMIT_AS, (LIMITS["child_address_space_bytes"],) * 2)
        resource.setrlimit(resource.RLIMIT_CPU, (LIMITS["child_cpu_seconds"],) * 2)
        resource.setrlimit(resource.RLIMIT_NOFILE, (LIMITS["child_file_descriptors"],) * 2)
        resource.setrlimit(resource.RLIMIT_FSIZE, (LIMITS["owned_storage_bytes"],) * 2)
        facts = namespace_facts(parent_user, parent_net, uid, gid)
        facts["resource_limits"] = {name: list(resource.getrlimit(kind)) for name, kind in (
            ("address_space", resource.RLIMIT_AS), ("cpu", resource.RLIMIT_CPU),
            ("file_descriptors", resource.RLIMIT_NOFILE), ("file_size", resource.RLIMIT_FSIZE),
            ("core", resource.RLIMIT_CORE))}
        stage = "unix_probe"
        parent = path.parent
        info = parent.lstat()
        if parent != parent.resolve() or not stat.S_ISDIR(info.st_mode) or info.st_uid != uid or stat.S_IMODE(info.st_mode) != 0o700:
            raise Refused("unix_endpoint_directory_changed")
        if path.exists() or path.is_symlink() or len(os.fsencode(path)) > 107:
            raise Refused("unix_endpoint_path_unavailable")
        listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        objects.append(listener)
        listener.settimeout(0.5)
        listener.bind(str(path))
        listener.listen(1)
        client = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        objects.append(client)
        client.settimeout(0.5)
        client.connect(str(path))
        accepted, _ = listener.accept()
        objects.append(accepted)
        accepted.settimeout(0.5)
        client.sendall(PAYLOAD)
        actual = bytearray()
        while len(actual) < len(PAYLOAD):
            data = accepted.recv(len(PAYLOAD) - len(actual))
            if not data:
                raise Refused("unix_payload_incomplete")
            actual.extend(data)
        if actual != PAYLOAD:
            raise Refused("unix_payload_changed")
        write_message({"phase": "ready", "pid": os.getpid(), "facts": facts,
                       "unix_socket_objects": len(objects), "unix_payload_bytes": len(actual)})
        with selectors.DefaultSelector() as selector:
            selector.register(0, selectors.EVENT_READ)
            if not selector.select(2) or os.read(0, 1) != b"X":
                raise Refused("parent_release_unavailable")
        status, reason = "observed", "host_prerequisites_observed"
    except Refused as error:
        reason = str(error)
    except OSError:
        reason = stage + "_operation_refused"
    except BaseException:
        reason = "child_probe_unclassified_failure"
    finally:
        closed = 0
        for item in reversed(objects):
            try:
                item.close()
                closed += 1
            except OSError:
                pass
        try:
            if path.exists() and stat.S_ISSOCK(path.lstat().st_mode):
                path.unlink()
        except OSError:
            pass
    if closed != len(objects) or path.exists():
        status, reason = "unknown", "child_cleanup_unknown"
    write_message({"phase": "complete", "status": status, "reason": reason,
                   "sockets_created": len(objects), "sockets_closed": closed,
                   "socket_path_absent": not path.exists(), "facts": facts})
    return 0 if status == "observed" and closed == 3 and not path.exists() else 3


def read_message(child, deadline):
    data = bytearray()
    with selectors.DefaultSelector() as selector:
        selector.register(child.stdout, selectors.EVENT_READ)
        while True:
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not selector.select(remaining):
                raise Refused("child_pipe_deadline")
            part = os.read(child.stdout.fileno(), min(4096, LIMITS["pipe_bytes"] // 2 + 1 - len(data)))
            if not part:
                raise Refused("child_pipe_incomplete")
            data.extend(part)
            if len(data) > LIMITS["pipe_bytes"] // 2:
                raise Refused("child_pipe_oversized")
            if data.endswith(b"\n"):
                value = strict_json(data)
                if type(value) is not dict:
                    raise Refused("child_pipe_invalid")
                return value


def cleanup_child(child):
    mode = "none"
    result = {"child_reaped": False, "exit_code": None, "termination": mode}
    try:
        if child.poll() is None:
            mode = "term"
            child.terminate()
            try:
                child.wait(timeout=1)
            except subprocess.TimeoutExpired:
                mode = "kill"
                child.kill()
                child.wait(timeout=1)
        result.update(child_reaped=child.poll() is not None, exit_code=child.returncode, termination=mode)
    except BaseException:
        result.update(child_reaped=False, exit_code=None, termination=mode)
    finally:
        try:
            os.set_blocking(child.stderr.fileno(), False)
            raw = os.read(child.stderr.fileno(), LIMITS["stderr_bytes"] + 1)
            result["stderr"] = raw[:LIMITS["stderr_bytes"]].decode("utf-8", errors="replace")
            result["stderr_truncated"] = len(raw) > LIMITS["stderr_bytes"]
        except BaseException:
            result["stderr_unavailable"] = True
        for stream in (child.stdin, child.stdout, child.stderr):
            if stream is not None:
                try:
                    stream.close()
                except BaseException:
                    pass
    return result


def run_probe(directory, host, report):
    child = None
    started = time.monotonic()
    deadline = started + LIMITS["child_seconds"]
    report["effects"]["namespace_child_attempts"] = 1
    command = ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--",
               "/usr/bin/python3", "-I", "-S", str(Path(__file__).resolve()), "--child", str(directory),
               str(host["user_namespace"]), str(host["network_namespace"]), str(host["uid"]), str(host["gid"])]
    try:
        child = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                 stderr=subprocess.PIPE, env=CHILD_ENV, cwd=directory,
                                 close_fds=True, start_new_session=True, bufsize=0)
        report["effects"]["namespace_children"] = 1
        ready = read_message(child, deadline)
        report["child"] = ready
        if (set(ready) != {"phase", "pid", "facts", "unix_socket_objects", "unix_payload_bytes"}
                or ready.get("phase") != "ready" or type(ready.get("pid")) is not int or ready["pid"] != child.pid
                or type(ready["unix_socket_objects"]) is not int or ready["unix_socket_objects"] != 3
                or type(ready["unix_payload_bytes"]) is not int or ready["unix_payload_bytes"] != len(PAYLOAD)
                or type(ready["facts"]) is not dict):
            raise Refused("child_prerequisite_refused")
        facts = ready["facts"]
        if (any(type(facts.get(key)) is not int or facts[key] != host["uid"] for key in ("uid", "euid"))
                or any(type(facts.get(key)) is not int or facts[key] != host["gid"] for key in ("gid", "egid"))
                or any(type(facts.get(key)) is not int or facts[key] <= 0 or facts[key] == host[key]
                       for key in ("user_namespace", "network_namespace"))
                or facts.get("interfaces") != ["lo"] or type(facts.get("ipv4_routes")) is not int or facts["ipv4_routes"] != 0
                or type(facts.get("ipv6_reject_routes")) is not int or facts["ipv6_reject_routes"] < 0
                or facts.get("uid_map") != [str(host["uid"]), str(host["uid"]), "1"]
                or facts.get("gid_map") != [str(host["gid"]), str(host["gid"]), "1"]
                or facts.get("resource_limits") != {"address_space": [134217728] * 2, "cpu": [2] * 2,
                    "file_descriptors": [32] * 2, "file_size": [1048576] * 2, "core": [0] * 2}):
            raise Refused("child_namespace_evidence_changed")
        sample = process_sample(child.pid, os.getpid())
        if sample["uids"] != [host["uid"]] * 4 or child.poll() is not None:
            raise Refused("live_child_identity_unavailable")
        report["live_process_observation"] = sample
        if child.stdin.write(b"X") != 1:
            raise Refused("child_release_failed")
        complete = read_message(child, deadline)
        report["child_completion"] = complete
        child.wait(timeout=max(0, deadline - time.monotonic()))
        if time.monotonic() > deadline:
            raise Refused("child_completion_deadline")
        if (child.returncode != 0 or complete != {"phase": "complete", "status": "observed",
                "reason": "host_prerequisites_observed", "sockets_created": 3,
                "sockets_closed": 3, "socket_path_absent": True, "facts": facts}):
            raise Refused("child_prerequisite_refused")
        report.update(status="observed", reason="host_prerequisites_observed")
    except Refused as error:
        report.update(status="refused", reason=str(error))
    except (OSError, subprocess.TimeoutExpired):
        report.update(status="refused", reason="child_spawn_or_wait_refused")
    finally:
        report["cleanup"] = {"child_reaped": False, "exit_code": None,
                             "termination": "ownership_unavailable", "socket_path_absent": False}
        completed = False
        try:
            if child is not None:
                report["cleanup"].update(cleanup_child(child))
            else:
                report["effects"]["namespace_children"] = None
            path = directory / "probe.sock"
            if report["cleanup"]["child_reaped"] and path.exists() and stat.S_ISSOCK(path.lstat().st_mode):
                path.unlink()
            report["cleanup"]["socket_path_absent"] = not path.exists()
            completed = True
        finally:
            finished = time.monotonic()
            report["child_elapsed_ms"] = round((finished - started) * 1000, 3)
            if report["status"] == "observed" and finished > deadline:
                report.update(status="refused", reason="child_completion_deadline")
            if not completed or not report["cleanup"]["child_reaped"] or not report["cleanup"]["socket_path_absent"]:
                report.update(status="unknown", reason="owned_cleanup_unknown")


def execute(manifest_raw, root, directory, environ):
    started = time.monotonic()
    report = {"schema_version": 1, "scope": "native-host-prerequisites-only",
              "manifest_sha256": digest(manifest_raw), "status": "changed_input", "reason": "input_unavailable",
              "effects": {"namespace_child_attempts": 0, "namespace_children": 0,
                          "candidate_acquisition_bytes": 0, "browser_sessions": 0, "page_actions": 0,
                          "model_calls": 0, "inet_connections": 0},
              "ci_setup": "Pinned source checkout is ordinary CI traffic, outside candidate acquisition; bytes are not measured here.",
              "elapsed_scope": "Probe input checks, effects and owned-child cleanup; excludes final report serialization, write and fsync.",
              "browser_sandbox": "NOT_RUN", "browser_journey": "NOT_RUN", "limits": dict(LIMITS)}
    previous = signal.getsignal(signal.SIGALRM)
    def deadline(_signum, _frame):
        raise Deadline()
    signal.signal(signal.SIGALRM, deadline)
    signal.setitimer(signal.ITIMER_REAL, LIMITS["overall_seconds"] - LIMITS["cleanup_seconds"])
    try:
        manifest = checked_manifest(manifest_raw, root)
        report.update(run_id=manifest["run_id"], source_base_commit=manifest["source_base_commit"])
        report.update(ci_identity(environ, report["manifest_sha256"]))
        report["host"] = host_observation(environ, directory)
        require_host(report["host"])
        report["host"]["executables"] = [executable_record(path) for path in (
            "/usr/bin/python3", "/usr/bin/unshare", "/usr/bin/timeout")]
        report["host"]["observer"] = process_sample(os.getpid(), os.getppid())
        report["status"] = "refused"
        run_probe(directory, report["host"], report)
    except Refused as error:
        report["reason"] = str(error)
    except Deadline:
        if report["status"] != "unknown":
            report.update(status="refused", reason="overall_effect_deadline")
    except BaseException as error:
        report["error_type"] = type(error).__name__
        if report["status"] != "unknown":
            report.update(status="refused", reason="preflight_unclassified_failure")
    finally:
        signal.setitimer(signal.ITIMER_REAL, 0)
        signal.signal(signal.SIGALRM, previous)
    report["elapsed_ms"] = round((time.monotonic() - started) * 1000, 3)
    if report["elapsed_ms"] > LIMITS["overall_seconds"] * 1000 and report["status"] != "unknown":
        report.update(status="refused", reason="overall_deadline_exceeded")
    return report


def reserve_output(output, manifest_raw):
    marker = {"schema_version": 1, "scope": "native-host-prerequisites-only",
              "manifest_sha256": digest(manifest_raw), "receipt_complete": False,
              "status": "unknown", "reason": "receipt_incomplete",
              "owned_child_cleanup": "unknown"}
    descriptor = os.open(output, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(encoded(marker))
        target.flush()
        os.fsync(target.fileno())
    sync_directory(output.parent)


def sync_directory(directory):
    descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def complete_output(output, report):
    result = encoded(dict(report, receipt_complete=True))
    if len(result) > LIMITS["report_bytes"]:
        raise Refused("report_size_exceeded")
    pending = output.with_name("report.pending")
    descriptor = os.open(pending, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC, 0o600)
    with os.fdopen(descriptor, "wb") as target:
        target.write(result)
        target.flush()
        os.fsync(target.fileno())
    os.replace(pending, output)
    sync_directory(output.parent)


def classify_wrapper(exit_code, raw, manifest_hash, source_commit):
    result = {"schema_version": 1, "scope": "native-host-prerequisite-cli-completion",
              "supervisor_exit_code": exit_code, "receipt_sha256": digest(raw) if raw else None,
              "status": "unknown", "reason": "receipt_missing_or_incomplete", "owned_child_cleanup": "unknown"}
    if exit_code in (124, 137):
        result["reason"] = "supervisor_deadline_unknown"
        return result
    try:
        value = strict_json(raw, allow_floats=True)
    except (Refused, TypeError):
        return result
    if (type(value) is not dict or value.get("receipt_complete") is not True
            or type(value.get("schema_version")) is not int or value["schema_version"] != 1
            or value.get("scope") != "native-host-prerequisites-only"
            or value.get("manifest_sha256") != manifest_hash or value.get("source_commit") != source_commit):
        return result
    result["receipt_status"] = value.get("status")
    if value.get("status") == "observed":
        cleanup = value.get("cleanup", {})
        effects = value.get("effects", {})
        child_ms, total_ms = value.get("child_elapsed_ms"), value.get("elapsed_ms")
        if (exit_code == 0 and type(cleanup) is dict and cleanup.get("child_reaped") is True
                and cleanup.get("socket_path_absent") is True
                and type(effects) is dict and type(effects.get("namespace_children")) is int
                and effects["namespace_children"] == 1
                and type(child_ms) in (int, float) and 0 <= child_ms <= LIMITS["child_seconds"] * 1000
                and type(total_ms) in (int, float) and 0 <= total_ms <= LIMITS["overall_seconds"] * 1000):
            result.update(status="observed", reason="complete_receipt_and_supervisor_agree", owned_child_cleanup="observed")
        else:
            result["reason"] = "receipt_and_supervisor_contradict"
    elif exit_code == 3 and value.get("status") in ("refused", "changed_input"):
        cleanup, effects = value.get("cleanup", {}), value.get("effects", {})
        if type(cleanup) is dict and cleanup.get("child_reaped") is True and cleanup.get("socket_path_absent") is True:
            result.update(status=value["status"], reason="complete_refusal_receipt", owned_child_cleanup="observed")
        elif (type(effects) is dict and all(type(effects.get(key)) is int and effects[key] == 0
                for key in ("namespace_child_attempts", "namespace_children"))):
            result.update(status=value["status"], reason="complete_refusal_receipt", owned_child_cleanup="not_started")
        else:
            result["reason"] = "refusal_cleanup_unknown"
    elif value.get("status") == "unknown":
        result["reason"] = "receipt_retains_unknown"
    else:
        result["reason"] = "receipt_and_supervisor_contradict"
    return result


def report_wrapper(exit_code, output, manifest):
    raw = None
    try:
        raw = read_bounded(output, LIMITS["report_bytes"])
    except (OSError, Refused):
        pass
    manifest_hash = digest(read_bounded(manifest, 16384))
    result = classify_wrapper(exit_code, raw, manifest_hash, os.environ.get("GITHUB_SHA", ""))
    result["supervisor"] = executable_record("/usr/bin/timeout")
    result["supervisor"].update(term_seconds=14, kill_after_seconds=1,
        ownership="The namespace child has a separate session; supervisor termination does not establish its reaping.")
    print(encoded(result).decode(), end="", flush=True)
    return 0 if result["status"] == "observed" else 3 if result["status"] in ("refused", "changed_input") else 2


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest")
    parser.add_argument("--output")
    parser.add_argument("--classify-wrapper", type=int)
    parser.add_argument("--child", nargs=5, metavar=("DIRECTORY", "PARENT_USER_NS", "PARENT_NET_NS", "UID", "GID"))
    args = parser.parse_args()
    if args.child:
        if args.manifest or args.output or args.classify_wrapper is not None:
            parser.error("child and parent modes are separate")
        return child_main(args.child[0], *(int(v) for v in args.child[1:]))
    if not args.manifest or not args.output:
        parser.error("manifest and output are required")
    output = Path(args.output)
    if args.classify_wrapper is not None:
        return report_wrapper(args.classify_wrapper, output, args.manifest)
    directory = output.parent
    if not output.is_absolute() or directory != directory.resolve() or output.name != "report.json":
        parser.error("output requires a new absolute private report path")
    info = directory.lstat()
    if not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) != 0o700 or any(directory.iterdir()):
        parser.error("output parent must be an empty owned mode-0700 directory")
    raw = read_bounded(args.manifest, 16384)
    reserve_output(output, raw)
    report = execute(raw, Path(__file__).resolve().parents[1], directory, os.environ)
    complete_output(output, report)
    return 0 if report["status"] == "observed" else 3


if __name__ == "__main__":
    raise SystemExit(main())
