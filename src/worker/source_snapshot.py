"""Bounded export of exactly one approved Git commit, with no host checkout.

Only Git objects are read from the source. Its configuration, refs, hooks,
replacement objects and untracked/ignored files never enter the task mount.
"""

from __future__ import annotations

import fcntl
import hashlib
import json
import os
from pathlib import Path
import re
import selectors
import shutil
import signal
import subprocess
import tempfile
import time


MAX_SOURCE_OBJECTS = 100000


class SnapshotUnavailable(RuntimeError):
    pass


def _bare(path: Path, base: str) -> None:
    for directory in ("objects/info", "objects/pack", "refs/heads"):
        (path / directory).mkdir(parents=True, exist_ok=True)
    (path / "config").write_text(
        "[core]\nrepositoryformatversion = 0\nbare = true\n", encoding="ascii"
    )
    (path / "HEAD").write_text("ref: refs/heads/approved\n", encoding="ascii")
    (path / "refs/heads/approved").write_text(base + "\n", encoding="ascii")


def _git(
    git_dir: Path,
    arguments: list[str],
    *,
    deadline: float,
    limit: int,
    data: bytes = b"",
    objects: Path | None = None,
) -> bytes:
    """Fixed Git plumbing with bounded stdout/stderr and an elapsed deadline."""
    if time.monotonic() >= deadline:
        raise SnapshotUnavailable("source export deadline exceeded")
    environment = {
        "PATH": os.defpath,
        "GIT_CONFIG_NOSYSTEM": "1",
        "GIT_CONFIG_GLOBAL": "/dev/null",
        "GIT_CONFIG_SYSTEM": "/dev/null",
        "GIT_ATTR_NOSYSTEM": "1",
        "GIT_NO_REPLACE_OBJECTS": "1",
        "GIT_TERMINAL_PROMPT": "0",
        "GIT_OPTIONAL_LOCKS": "0",
        "LC_ALL": "C",
    }
    if objects is not None:
        environment["GIT_OBJECT_DIRECTORY"] = str(objects)
    command = [
        "git",
        "--no-pager",
        "--git-dir=" + str(git_dir),
        "-c",
        "core.hooksPath=/dev/null",
        "-c",
        "core.fsmonitor=false",
        "-c",
        "pack.threads=1",
        *arguments,
    ]
    process = subprocess.Popen(
        command,
        stdin=subprocess.PIPE,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        env=environment,
        start_new_session=True,
    )
    output = bytearray()
    errors = 0
    position = 0
    selector = selectors.DefaultSelector()
    try:
        for stream in (process.stdout, process.stderr, process.stdin):
            os.set_blocking(stream.fileno(), False)
        selector.register(process.stdout, selectors.EVENT_READ, "stdout")
        selector.register(process.stderr, selectors.EVENT_READ, "stderr")
        if data:
            selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
        else:
            process.stdin.close()
        while selector.get_map():
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                raise SnapshotUnavailable("source export deadline exceeded")
            for key, _ in selector.select(min(remaining, 0.1)):
                if key.data == "stdin":
                    try:
                        position += os.write(
                            key.fileobj.fileno(), data[position : position + 65536]
                        )
                    except BrokenPipeError:
                        position = len(data)
                    if position == len(data):
                        selector.unregister(key.fileobj)
                        key.fileobj.close()
                    continue
                chunk = os.read(key.fileobj.fileno(), 65536)
                if not chunk:
                    selector.unregister(key.fileobj)
                    key.fileobj.close()
                elif key.data == "stdout":
                    if len(output) + len(chunk) > limit:
                        raise SnapshotUnavailable("source export byte limit exceeded")
                    output.extend(chunk)
                else:
                    errors += len(chunk)
                    if errors > 8192:
                        raise SnapshotUnavailable(
                            "source export diagnostic limit exceeded"
                        )
        if process.wait(timeout=max(0.001, deadline - time.monotonic())) != 0:
            raise SnapshotUnavailable("approved Git object export failed")
        return bytes(output)
    except (OSError, subprocess.TimeoutExpired) as exc:
        raise SnapshotUnavailable("approved Git object export failed") from exc
    finally:
        selector.close()
        if process.poll() is None:
            os.killpg(process.pid, signal.SIGKILL)
            process.wait()
        for stream in (process.stdin, process.stdout, process.stderr):
            if not stream.closed:
                stream.close()


class SourceSnapshots:
    """Immutable, local, content-addressed shallow Git exports."""

    def __init__(self, root: Path, *, git_runner=None, retain_failed=False):
        self.root = root
        # Optional neutral mechanics for an independently owned operation.
        # Existing managed callers keep their original runner and cleanup.
        if type(retain_failed) is not bool:
            raise ValueError("invalid source retention")
        self.git_runner = git_runner or _git
        self.retain_failed = retain_failed
        root.mkdir(mode=0o700, parents=True, exist_ok=True)
        (root / "locks").mkdir(mode=0o700, exist_ok=True)

    def prepare(
        self, source_path: str, base: str, max_bytes: int, *, timeout: float = 30,
        deadline: float | None = None, max_objects: int = MAX_SOURCE_OBJECTS,
    ) -> Path:
        if not re.fullmatch(r"[0-9a-f]{40}", base):
            raise SnapshotUnavailable("a full approved commit ID is required")
        source = Path(source_path).resolve(strict=True)
        git_dir = source / ".git" if (source / ".git").is_dir() else source
        objects = git_dir / "objects"
        if (source / ".git").is_file() or not objects.is_dir() or objects.is_symlink():
            raise SnapshotUnavailable(
                "a complete local Git object directory is required"
            )
        key = hashlib.sha256((str(source) + "\0" + base).encode()).hexdigest()
        destination = self.root / key
        deadline = min(time.monotonic() + timeout, deadline if deadline is not None else float("inf"))
        if type(max_objects) is not int or not 1 <= max_objects <= MAX_SOURCE_OBJECTS:
            raise SnapshotUnavailable("invalid source object limit")
        if time.monotonic() >= deadline:
            raise SnapshotUnavailable("source export deadline exceeded")
        with (self.root / "locks" / (key + ".lock")).open("a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError as exc:
                raise SnapshotUnavailable(
                    "approved source export is in progress"
                ) from exc
            try:
                if destination.exists():
                    metadata = json.loads((destination / "manifest.json").read_text())
                    if (metadata["base"] != base or metadata["object_bytes"] > max_bytes
                            or metadata["objects"] > max_objects):
                        raise SnapshotUnavailable(
                            "approved source exceeds profile limit"
                        )
                    return destination / "repo"
                return self._export(objects, base, max_bytes, deadline, destination, max_objects)
            finally:
                fcntl.flock(lock, fcntl.LOCK_UN)

    def _export(
        self,
        objects: Path,
        base: str,
        max_bytes: int,
        deadline: float,
        destination: Path,
        max_objects: int = MAX_SOURCE_OBJECTS,
    ) -> Path:
        staging = Path(tempfile.mkdtemp(prefix="export-", dir=self.root))
        try:
            reader, exported = staging / "reader", staging / "repo"
            # This controlled metadata directory reads only the source object
            # database. It never opens the source repository's config or refs.
            _bare(reader, base)
            _bare(exported, base)
            commit = self.git_runner(
                reader,
                ["cat-file", "commit", base],
                deadline=deadline,
                limit=min(max_bytes, 1048576),
                objects=objects,
            )
            actual = hashlib.sha1(
                b"commit " + str(len(commit)).encode() + b"\0" + commit
            ).hexdigest()
            if actual != base or not re.match(rb"tree [0-9a-f]{40}\n", commit):
                raise SnapshotUnavailable("approved commit object does not match")
            tree = commit[5:45].decode("ascii")
            entries = self.git_runner(
                reader,
                ["ls-tree", "-r", "-t", "-z", tree],
                deadline=deadline,
                limit=max_bytes,
                objects=objects,
            )
            selected = {base: "commit", tree: "tree"}
            for entry in entries.split(b"\0"):
                if not entry:
                    continue
                header, separator, _ = entry.partition(b"\t")
                match = re.fullmatch(
                    rb"([0-7]{6}) (blob|tree|commit) ([0-9a-f]{40})", header
                )
                if not separator or match is None:
                    raise SnapshotUnavailable("invalid approved tree entry")
                mode, kind, identity = match.groups()
                if kind == b"commit" and mode == b"160000":
                    continue  # A gitlink is metadata, not permission to export another repository.
                if kind not in {b"blob", b"tree"}:
                    raise SnapshotUnavailable("unsupported approved tree entry")
                selected[identity.decode("ascii")] = kind.decode("ascii")
            if len(selected) > max_objects:
                raise SnapshotUnavailable("approved source object count exceeds limit")
            object_input = ("\n".join(sorted(selected)) + "\n").encode("ascii")
            sizes = self.git_runner(
                reader,
                ["cat-file", "--batch-check=%(objectname) %(objecttype) %(objectsize)"],
                data=object_input,
                deadline=deadline,
                limit=max_bytes,
                objects=objects,
            )
            total = 0
            checked = set()
            for line in sizes.decode("ascii").splitlines():
                identity, kind, size = line.split(" ")
                if (
                    selected.get(identity) != kind
                    or identity in checked
                    or not size.isdigit()
                ):
                    raise SnapshotUnavailable(
                        "approved source object validation failed"
                    )
                total += int(size)
                checked.add(identity)
            if checked != set(selected) or total > max_bytes:
                raise SnapshotUnavailable("approved source exceeds profile byte limit")
            pack = self.git_runner(
                reader,
                [
                    "pack-objects",
                    "--stdout",
                    "--window=0",
                    "--no-reuse-delta",
                    "--no-reuse-object",
                    "--threads=1",
                    "--compression=1",
                ],
                data=object_input,
                deadline=deadline,
                limit=max_bytes * 2 + 1048576,
                objects=objects,
            )
            self.git_runner(
                exported,
                ["index-pack", "--stdin"],
                data=pack,
                deadline=deadline,
                limit=1024,
            )
            actual_objects = self.git_runner(
                exported,
                ["cat-file", "--batch-all-objects", "--batch-check=%(objectname)"],
                deadline=deadline,
                limit=max_bytes,
            )
            if set(actual_objects.decode("ascii").splitlines()) != set(selected):
                raise SnapshotUnavailable(
                    "exported object set differs from approved commit"
                )
            (exported / "shallow").write_text(base + "\n", encoding="ascii")
            shutil.rmtree(reader)
            (staging / "manifest.json").write_text(
                json.dumps(
                    {
                        "schema_version": 1,
                        "base": base,
                        "object_bytes": total,
                        "objects": len(selected),
                        "pack_sha256": hashlib.sha256(pack).hexdigest(),
                    },
                    sort_keys=True,
                ),
                encoding="utf-8",
            )
            for directory, _, files in os.walk(exported):
                Path(directory).chmod(0o755)
                for name in files:
                    (Path(directory) / name).chmod(0o644)
            for directory, _, files in os.walk(staging, topdown=False):
                for name in files:
                    with (Path(directory) / name).open("rb") as handle:
                        os.fsync(handle.fileno())
                descriptor = os.open(directory, os.O_RDONLY | os.O_DIRECTORY)
                try:
                    os.fsync(descriptor)
                finally:
                    os.close(descriptor)
            os.replace(staging, destination)
            descriptor = os.open(self.root, os.O_RDONLY | os.O_DIRECTORY)
            try:
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            return destination / "repo"
        finally:
            if staging.exists() and not self.retain_failed:
                shutil.rmtree(staging)
