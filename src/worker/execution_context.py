"""Host installation context; legacy refusal, never task authorization.

The selector is owned by the installer, at a fixed interpreter-relative path.
Its absence in a separate standalone interpreter preserves ordinary behavior.
Canonical entry points keep their own config, credential and authority checks.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import re
import stat
import sys
import threading

SELECTOR_NAME = "openjules-managed-installation.json"
SELECTOR_LIMIT = 4096
CONFIG_LIMIT = 1_000_000
_DIGEST = re.compile(r"[0-9a-f]{64}")
_lock = threading.RLock()
_managed_process = False
_selector_observed = False


class LegacyExecutionRefused(RuntimeError):
    """A fixed refusal that must never enter execution-failure cleanup."""

    def __init__(self, reason="managed_installation_requires_canonical_ingress"):
        self.reason = reason
        super().__init__(reason)


class ManagedInstallationInvalid(ValueError):
    def __init__(self):
        super().__init__("managed_installation_unavailable")


def _selector_present():
    global _selector_observed
    path = Path(sys.prefix) / SELECTOR_NAME
    with _lock:
        try:
            path.lstat()
        except FileNotFoundError:
            if _selector_observed:
                raise ManagedInstallationInvalid()
            return False
        except OSError:
            _selector_observed = True
            raise ManagedInstallationInvalid() from None
        _selector_observed = True
        return True


def require_legacy_execution():
    """Refuse before queueing or effects; caller payload/env cannot waive this."""
    with _lock:
        if _managed_process or _selector_observed:
            raise LegacyExecutionRefused()
        try:
            present = _selector_present()
        except ManagedInstallationInvalid:
            raise LegacyExecutionRefused() from None
        if present:
            raise LegacyExecutionRefused()


def _read_regular(path, limit, *, private=False):
    # O_NOFOLLOW also refuses dangling symlinks. Read at most the approved bound,
    # and validate the opened file rather than trusting only a prior path stat.
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    with os.fdopen(fd, "rb") as stream:
        info = os.fstat(stream.fileno())
        if (
            not stat.S_ISREG(info.st_mode)
            or (private and stat.S_IMODE(info.st_mode) & 0o077)
            or info.st_size > limit
        ):
            raise ManagedInstallationInvalid()
        value = stream.read(limit + 1)
        if len(value) > limit:
            raise ManagedInstallationInvalid()
        return value


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            raise ManagedInstallationInvalid()
        result[key] = value
    return result


def validate_managed_installation(*, required=False):
    """Verify the original selector binding without restricting other configs.

    This reads no credentials and starts no Docker, model or network client.
    A valid selector is a negative legacy restriction, not an allowlist for
    alternate host-supplied canonical service/publication/cleanup configs.
    """
    try:
        if not _selector_present():
            if required:
                raise ManagedInstallationInvalid()
            return None
        raw = _read_regular(
            Path(sys.prefix) / SELECTOR_NAME, SELECTOR_LIMIT, private=True
        )
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=_unique_object)
        if (
            not isinstance(value, dict)
            or set(value) != {
                "schema_version", "managed_config_path", "managed_config_sha256"
            }
            or type(value["schema_version"]) is not int
            or value["schema_version"] != 1
        ):
            raise ManagedInstallationInvalid()
        name, expected = value["managed_config_path"], value["managed_config_sha256"]
        if (
            not isinstance(name, str)
            or "\x00" in name
            or not Path(name).is_absolute()
            or str(Path(name).resolve(strict=True)) != name
            or not isinstance(expected, str)
            or not _DIGEST.fullmatch(expected)
        ):
            raise ManagedInstallationInvalid()
        content = _read_regular(Path(name), CONFIG_LIMIT, private=True)
        if hashlib.sha256(content).hexdigest() != expected:
            raise ManagedInstallationInvalid()
        return hashlib.sha256(raw).hexdigest()
    except (OSError, ValueError, TypeError, RuntimeError):
        raise ManagedInstallationInvalid() from None


def select_managed_context():
    """Irreversibly refuse legacy work in this process, without reading host files."""
    global _managed_process
    with _lock:
        _managed_process = True


def enter_managed_context():
    """Called by the actual managed entrypoint, not by component app builders."""
    select_managed_context()
    validate_managed_installation()


def probe_managed_installation():
    digest = validate_managed_installation(required=True)
    try:
        require_legacy_execution()
    except LegacyExecutionRefused as exc:
        if exc.reason != "managed_installation_requires_canonical_ingress":
            raise ManagedInstallationInvalid() from None
    else:
        raise ManagedInstallationInvalid()
    return {
        "schema_version": 1,
        "selector_sha256": digest,
        "legacy_execution_allowed": False,
    }


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--probe-managed-installation", action="store_true", required=True)
    parser.parse_args(argv)
    try:
        report = probe_managed_installation()
    except ManagedInstallationInvalid:
        print(json.dumps({"error": "managed_installation_unavailable"}, sort_keys=True))
        return 2
    print(json.dumps(report, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
