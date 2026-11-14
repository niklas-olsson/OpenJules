"""Bounded, non-launching prerequisite evidence for the browser investigation.

This command cannot acquire or start a browser, authorize a task, or qualify a
sandbox. A successful namespace probe is only one prerequisite observation.
"""

from __future__ import annotations

import argparse
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import platform
import re
import signal
import stat
import subprocess
import time


ROOT = Path(__file__).resolve().parents[1]
FIXTURES = (
    "tests/fixtures/browser-engine/alpha.html",
    "tests/fixtures/browser-engine/beta.html",
)
LIMITS = {
    "acquisition_bytes": 0,
    "browser_sessions": 0,
    "page_actions": 0,
    "model_calls": 0,
    "namespace_children": 1,
    "child_timeout_seconds": 5,
    "overall_timeout_seconds": 30,
    "report_bytes": 65536,
}
COMMAND = ["/usr/bin/unshare", "--user", "--map-current-user", "--net", "--", "/bin/true"]


class InvalidInput(ValueError):
    """A bounded error that contains no input or filesystem contents."""


def digest(data: bytes) -> str:
    return hashlib.sha256(data).hexdigest()


def read_regular(path: Path, limit: int) -> bytes:
    """Read a bounded regular file without following its final symlink."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > limit:
            raise InvalidInput("invalid_input_file")
        data = b""
        while len(data) <= limit:
            block = os.read(fd, min(8192, limit + 1 - len(data)))
            if not block:
                return data
            data += block
        raise InvalidInput("input_too_large")
    finally:
        os.close(fd)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise InvalidInput("duplicate_key")
        result[key] = value
    return result


def _keys(value, keys):
    if type(value) is not dict or set(value) != set(keys):
        raise InvalidInput("invalid_manifest_schema")


def load_manifest(path: Path, root: Path = ROOT):
    raw = read_regular(path, 16384)
    try:
        manifest = json.loads(raw, object_pairs_hook=_unique_object)
    except (ValueError, UnicodeError, RecursionError) as exc:
        raise InvalidInput("invalid_manifest_json") from exc
    _keys(manifest, ("schema_version", "run_id", "source_base_commit", "tool_sha256", "host", "candidate", "comparison", "fixtures", "limits"))
    if type(manifest["schema_version"]) is not int or manifest["schema_version"] != 1:
        raise InvalidInput("unsupported_schema")
    if not isinstance(manifest["run_id"], str) or not re.fullmatch(r"[a-z0-9-]{1,80}", manifest["run_id"]):
        raise InvalidInput("invalid_run_id")
    if not isinstance(manifest["source_base_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", manifest["source_base_commit"]):
        raise InvalidInput("invalid_source_commit")
    if type(manifest["tool_sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", manifest["tool_sha256"]):
        raise InvalidInput("invalid_tool_digest")
    if digest(read_regular(root / "tools/browser_engine_preflight.py", 65536)) != manifest["tool_sha256"]:
        raise InvalidInput("tool_digest_mismatch")
    _keys(manifest["host"], ("system", "machine", "kernel", "python", "os_id", "os_version"))
    if any(type(x) is not str or not re.fullmatch(r"[A-Za-z0-9._+-]{1,80}", x) for x in manifest["host"].values()):
        raise InvalidInput("invalid_host_identity")
    _keys(manifest["candidate"], ("playwright_version", "browsers_json_sha256", "chromium_revision", "chromium_version"))
    candidate = manifest["candidate"]
    for field in ("playwright_version", "chromium_revision", "chromium_version"):
        if type(candidate[field]) is not str or not re.fullmatch(r"[0-9.]{1,40}", candidate[field]):
            raise InvalidInput("invalid_candidate_identity")
    if type(candidate["browsers_json_sha256"]) is not str or not re.fullmatch(r"[0-9a-f]{64}", candidate["browsers_json_sha256"]):
        raise InvalidInput("invalid_candidate_digest")
    _keys(manifest["comparison"], ("kitesurf_commit", "camoufox_selected"))
    if not isinstance(manifest["comparison"]["kitesurf_commit"], str) or not re.fullmatch(r"[0-9a-f]{40}", manifest["comparison"]["kitesurf_commit"]):
        raise InvalidInput("invalid_comparison_identity")
    if manifest["comparison"]["camoufox_selected"] is not False:
        raise InvalidInput("unsupported_candidate")
    _keys(manifest["limits"], LIMITS)
    if any(type(manifest["limits"][key]) is not int or manifest["limits"][key] != value for key, value in LIMITS.items()):
        raise InvalidInput("unsupported_budget")
    _keys(manifest["fixtures"], FIXTURES)
    for name in FIXTURES:
        expected = manifest["fixtures"][name]
        if type(expected) is not str or not re.fullmatch(r"[0-9a-f]{64}", expected):
            raise InvalidInput("invalid_fixture_digest")
        if digest(read_regular(root / name, 65536)) != expected:
            raise InvalidInput("fixture_digest_mismatch")
    return manifest, digest(raw)


def inspect_host():
    release = platform.freedesktop_os_release()
    return {
        "system": platform.system(),
        "machine": platform.machine(),
        "kernel": platform.release(),
        "python": platform.python_version(),
        "os_id": release.get("ID", "unknown"),
        "os_version": release.get("VERSION_ID", "unknown"),
    }


def inspect_candidate(expected):
    """Inspect installed metadata only; never import/start the browser driver."""
    try:
        dist = importlib.metadata.distribution("playwright")
    except importlib.metadata.PackageNotFoundError:
        return {"status": "refused", "reason": "playwright_missing"}
    version = dist.version
    if version != expected["playwright_version"]:
        return {"status": "refused", "reason": "playwright_version_mismatch", "observed_version": version}
    metadata_path = Path(dist.locate_file("playwright/driver/package/browsers.json"))
    try:
        raw = read_regular(metadata_path, 65536)
        config = json.loads(raw)
        browser = next(x for x in config["browsers"] if x["name"] == "chromium")
    except (OSError, ValueError, KeyError, StopIteration, TypeError):
        return {"status": "refused", "reason": "browser_metadata_unreadable"}
    observed = {"playwright_version": version, "browsers_json_sha256": digest(raw), "chromium_revision": browser.get("revision"), "chromium_version": browser.get("browserVersion")}
    if observed != expected:
        return {"status": "refused", "reason": "browser_metadata_mismatch", "observed": observed}
    # The selected topology deliberately uses Playwright's standard Linux cache.
    # An environment override is a changed input, not a route to a substitute.
    if "PLAYWRIGHT_BROWSERS_PATH" in os.environ:
        return {"status": "refused", "reason": "undeclared_browser_cache_override", "observed": observed}
    binary = Path.home() / ".cache/ms-playwright" / ("chromium-" + expected["chromium_revision"]) / "chrome-linux64/chrome"
    try:
        info = binary.lstat()
        present = stat.S_ISREG(info.st_mode) and os.access(binary, os.X_OK)
    except OSError:
        present = False
    return {"status": "observed" if present else "refused", "reason": "expected_cache_binary_present_not_verified" if present else "expected_cache_binary_missing", "observed": observed, "browser_artifact_verified": False}


def namespace_probe():
    """One fixed child with discarded output, a deadline, and confirmed reaping."""
    for path in (COMMAND[0], COMMAND[-1]):
        if not Path(path).is_file() or not os.access(path, os.X_OK):
            return {"status": "not_run", "reason": "probe_executable_missing", "children_started": 0}
    start = time.monotonic()
    try:
        child = subprocess.Popen(COMMAND, stdin=subprocess.DEVNULL, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL, env={"PATH": "/usr/bin:/bin", "LANG": "C", "LC_ALL": "C"}, close_fds=True)
    except OSError:
        return {"status": "not_run", "reason": "namespace_probe_spawn_refused", "children_started": 0}
    try:
        code = child.wait(timeout=LIMITS["child_timeout_seconds"])
    except subprocess.TimeoutExpired:
        reaped = _kill_and_reap(child)
        return {"status": "refused", "reason": "namespace_probe_timeout" if reaped else "namespace_cleanup_unknown", "children_started": 1, "child_reaped": reaped, "elapsed_ms": round((time.monotonic() - start) * 1000, 3)}
    except BaseException:
        _kill_and_reap(child)
        raise
    return {"status": "observed" if code == 0 else "refused", "reason": "namespace_creation_observed" if code == 0 else "namespace_creation_refused", "children_started": 1, "child_reaped": True, "exit_code": code, "elapsed_ms": round((time.monotonic() - start) * 1000, 3)}


def _kill_and_reap(child):
    try:
        child.kill()
    except ProcessLookupError:
        pass
    try:
        child.wait(timeout=1)
        return True
    except subprocess.TimeoutExpired:
        return False


def collect(manifest, manifest_sha256, root: Path = ROOT):
    start = time.monotonic()
    host = inspect_host()
    nonroot = os.getuid() != 0 and os.geteuid() != 0
    host_matches = host == manifest["host"]
    candidate = inspect_candidate(manifest["candidate"])
    # Browser absence does not prevent this no-page host prerequisite probe.
    # Unknown host, root execution, or metadata mismatch prevents all children.
    metadata_known = candidate["reason"] in {"expected_cache_binary_missing", "expected_cache_binary_present_not_verified"}
    namespace = namespace_probe() if nonroot and host_matches and metadata_known else {"status": "not_run", "reason": "precondition_refused", "children_started": 0}
    observed = nonroot and host_matches and candidate["status"] == "observed" and namespace["status"] == "observed"
    elapsed = time.monotonic() - start
    if elapsed > LIMITS["overall_timeout_seconds"]:
        observed = False
    return {
        "schema_version": 1,
        "run_id": manifest["run_id"],
        "source_base_commit": manifest["source_base_commit"],
        "manifest_sha256": manifest_sha256,
        "tool_sha256": manifest["tool_sha256"],
        "fixture_sha256": manifest["fixtures"],
        "decision": "prerequisites_observed_only" if observed else "no_go_selected_host",
        "scope": "selected_host_and_declared_namespace_route",
        "checks": {"nonroot": {"status": "observed" if nonroot else "refused"}, "host": {"status": "observed" if host_matches else "refused", "expected": manifest["host"], "observed": host}, "candidate": candidate, "namespace": namespace, "overall_deadline": {"status": "observed" if elapsed <= LIMITS["overall_timeout_seconds"] else "refused"}},
        "effects": {"acquisition_bytes": 0, "browser_sessions": 0, "page_actions": 0, "model_calls": 0, "namespace_children": namespace["children_started"]},
        "not_run": ["chromium_sandbox_verification", "fixture_journeys", "kitesurf_runtime", "browser_authentication", "same_target_observation", "takeover_and_handback", "stop_and_recovery", "retained_browser_results"],
        "limits": manifest["limits"],
        "elapsed_ms": round(elapsed * 1000, 3),
        "browser_launch_authorized": False,
        "managed_execution_qualified": False,
        "browser_local_execution_qualified": False,
    }


def reserve_report(path: Path):
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    try:
        os.write(fd, b'{"status":"incomplete"}\n')
        os.fsync(fd)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    except BaseException:
        os.close(fd)
        raise
    return fd


def write_report(path: Path, report, reserved_fd=None):
    data = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode()
    if len(data) > LIMITS["report_bytes"]:
        raise InvalidInput("report_too_large")
    # Preserve prior evidence. Existing files and symlinks cannot be overwritten.
    fd = reserve_report(path) if reserved_fd is None else reserved_fd
    with os.fdopen(fd, "wb") as stream:
        stream.seek(0)
        stream.write(data)
        stream.truncate()
        stream.flush()
        os.fsync(stream.fileno())


def _deadline(_signum, _frame):
    raise TimeoutError("overall_deadline")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--manifest", required=True, type=Path)
    parser.add_argument("--output", required=True, type=Path)
    args = parser.parse_args()
    prior_handler = signal.signal(signal.SIGALRM, _deadline)
    # Reserve two seconds inside the total bound for a one-second reap and the
    # bounded failure receipt. Do not spend the whole envelope before cleanup.
    prior_timer = signal.setitimer(signal.ITIMER_REAL, LIMITS["overall_timeout_seconds"] - 2)
    reserved_fd = None
    binding = None
    manifest = None
    try:
        manifest, binding = load_manifest(args.manifest)
        # Claim this evidence path atomically before any child process effect.
        reserved_fd = reserve_report(args.output)
        report = collect(manifest, binding)
        fd, reserved_fd = reserved_fd, None
        write_report(args.output, report, fd)
    except TimeoutError:
        if reserved_fd is not None:
            failure = {
                "schema_version": 1,
                "decision": "incomplete_preflight",
                "reason": "overall_deadline",
                "manifest_sha256": binding,
                "tool_sha256": manifest["tool_sha256"] if manifest else None,
                "namespace_cleanup": "unknown",
                "browser_launch_authorized": False,
                "effects": {"acquisition_bytes": 0, "browser_sessions": 0, "page_actions": 0, "model_calls": 0, "namespace_children": "unknown"},
            }
            fd, reserved_fd = reserved_fd, None
            write_report(args.output, failure, fd)
        print('{"error":"overall_deadline"}')
        return 2
    except (OSError, ValueError, KeyError, TypeError, RecursionError):
        print('{"error":"preflight_input_or_output_refused"}')
        return 2
    finally:
        if reserved_fd is not None:
            os.close(reserved_fd)
        signal.setitimer(signal.ITIMER_REAL, *prior_timer)
        signal.signal(signal.SIGALRM, prior_handler)
    print(json.dumps({"decision": report["decision"], "manifest_sha256": binding}))
    return 0 if report["decision"] == "prerequisites_observed_only" else 3


if __name__ == "__main__":
    raise SystemExit(main())
