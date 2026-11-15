"""Neutral stopped-guest evidence retention for one original review.

No extraction, guest execution, authority decision or resource removal occurs
here. The caller proves original termination and owns all deadlines/custody.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import stat
import tarfile

from .review_contract import ReviewCapture, ReviewError


def sha256(raw: bytes) -> str:
    return hashlib.sha256(raw).hexdigest()


def canonical(value) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), allow_nan=False).encode()


def private_directory(path: Path, *, create=False) -> Path:
    if create:
        path.mkdir(mode=0o700)
    info = path.lstat()
    if (not stat.S_ISDIR(info.st_mode) or path.resolve() != path
            or info.st_uid != os.getuid() or stat.S_IMODE(info.st_mode) & 0o077):
        raise ReviewError("custody_unavailable")
    return path


def durable_file(path: Path, raw: bytes) -> None:
    """Exclusive original bytes; an existing destination is never replaced."""
    fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600)
    with os.fdopen(fd, "wb") as output:
        output.write(raw)
        output.flush()
        os.fsync(output.fileno())
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


@dataclass(frozen=True)
class CaptureHandle:
    directory: Path
    incarnation: str
    container_id: str


def retain_stopped_capture(directory, incarnation, container_id, raw, limits, *, check, assert_safe):
    """Retain bounded raw bytes first; refuse unsafe projections without unlinking.

    The raw archive remains evidence on a projection failure. Its members never
    become host filesystem paths, and neither guest Git metadata nor a guest
    commit is imported into the candidate repository.
    """
    check()
    if type(raw) is not bytes or len(raw) > limits["archive_bytes"]:
        raise ReviewError("capture_refused")
    directory = private_directory(Path(directory), create=True)
    check()
    durable_file(directory / "archive.tar", raw)
    selected = {}
    names = set()
    expected = {"workspace/run/change.patch": limits["patch_bytes"],
                "workspace/run/output.log": limits["log_bytes"]}
    try:
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            for member in archive:
                check()
                name = member.name.rstrip("/") if member.isdir() else member.name
                if (not name or name.startswith("/") or "\\" in name
                        or len(name.encode("utf-8")) > limits["path_bytes"]
                        or any(ord(c) < 32 or ord(c) == 127 for c in name)
                        or any(p in {"", ".", ".."} for p in name.split("/"))
                        or name in names or not (member.isfile() or member.isdir())
                        or member.issparse() or member.size < 0
                        or member.size > limits["archive_bytes"]):
                    raise ReviewError("capture_refused")
                names.add(name)
                if len(names) > limits["files"]:
                    raise ReviewError("capture_refused")
                if name in expected:
                    if not member.isfile() or member.size > expected[name]:
                        raise ReviewError("capture_refused")
                    stream = archive.extractfile(member)
                    if stream is None:
                        raise ReviewError("capture_refused")
                    content = stream.read(member.size + 1)
                    if len(content) != member.size:
                        raise ReviewError("capture_refused")
                    content.decode("utf-8", errors="strict")
                    assert_safe(content)
                    selected[name] = content
        if set(selected) != set(expected):
            raise ReviewError("capture_refused")
        assert_safe(raw)
    except ReviewError:
        raise
    except (OSError, ValueError, UnicodeError, tarfile.TarError):
        raise ReviewError("capture_refused") from None
    check()
    patch = selected["workspace/run/change.patch"]
    log = selected["workspace/run/output.log"]
    manifest = canonical({"schema": "standalone-review-capture-v1", "incarnation": incarnation,
                          "container_id": container_id, "archive_sha256": sha256(raw),
                          "archive_bytes": len(raw), "patch_sha256": sha256(patch),
                          "patch_bytes": len(patch), "log_sha256": sha256(log), "log_bytes": len(log),
                          "termination_confirmed": True, "evidence": "untrusted-guest-artifacts"})
    for name, content in (("change.patch", patch), ("output.log", log), ("manifest.json", manifest)):
        check()
        durable_file(directory / name, content)
    check()
    retained_id = "capture_" + sha256(manifest)
    return ReviewCapture(CaptureHandle(directory, incarnation, container_id), retained_id,
                         sha256(raw), len(raw), sha256(patch), patch, sha256(log), log, sha256(manifest))
