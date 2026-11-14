"""Owned bounded session records, with no native runtime or network effects."""

from __future__ import annotations

import fcntl
import hashlib
import os
from pathlib import Path
import stat
import tempfile

from .types import SessionUnavailable, canonical, strict_json


JOURNAL_LIMIT = 4 * 1024 * 1024


def private_directory(path):
    info = path.lstat()
    if (not path.is_absolute() or path != path.resolve(strict=True)
            or not stat.S_ISDIR(info.st_mode) or info.st_uid != os.getuid()
            or stat.S_IMODE(info.st_mode) != 0o700):
        raise SessionUnavailable()


def private_bytes(path, maximum):
    descriptor = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC)
    with os.fdopen(descriptor, "rb") as source:
        before = os.fstat(source.fileno())
        if (not stat.S_ISREG(before.st_mode) or before.st_uid != os.getuid()
                or stat.S_IMODE(before.st_mode) != 0o600 or before.st_nlink != 1
                or not 0 <= before.st_size <= maximum):
            raise SessionUnavailable()
        raw = source.read(maximum + 1)
        after = os.fstat(source.fileno())
    if len(raw) != before.st_size or len(raw) > maximum or any(
            getattr(before, name) != getattr(after, name)
            for name in ("st_dev", "st_ino", "st_size", "st_mtime_ns", "st_ctime_ns", "st_uid", "st_mode", "st_nlink")):
        raise SessionUnavailable()
    return raw


def sync_directory(path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC)
    try:
        os.fsync(descriptor)
    finally:
        os.close(descriptor)


def discard_temporary(path):
    if path is not None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            raise SessionUnavailable() from None


class SessionStore:
    def __init__(self, directory, *, create=False, maximum=16777216):
        self.root = Path(directory)
        self.lock = None
        self.current_digest = None
        self.closed = False
        self.maximum = maximum
        self.anchor = None
        try:
            if create:
                private_directory(self.root.parent)
                self.root.mkdir(mode=0o700)
                sync_directory(self.root.parent)
            private_directory(self.root)
            flags = os.O_RDWR | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC
            if create:
                flags |= os.O_CREAT | os.O_EXCL
            self.lock = os.open(self.root / "owner.lock", flags, 0o600)
            info = os.fstat(self.lock)
            if (not stat.S_ISREG(info.st_mode) or info.st_uid != os.getuid()
                    or stat.S_IMODE(info.st_mode) != 0o600 or info.st_nlink != 1):
                raise SessionUnavailable()
            fcntl.flock(self.lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            self.lock_identity = (info.st_dev, info.st_ino)
            info = self.root.lstat()
            self.root_identity = (info.st_dev, info.st_ino)
            self.journal = self.root / "session.json"
            self.origin = self.root / "origin.json"
            self.results = self.root / "results"
            if create:
                self.results.mkdir(mode=0o700)
                sync_directory(self.root)
            else:
                private_directory(self.results)
                self.anchor = strict_json(private_bytes(self.origin, 4096))
                if (type(self.anchor) is not dict
                        or set(self.anchor) != {"schema_version", "spec_sha256", "created_at_ms", "backend_epoch",
                            "lock_identity", "root_identity", "maximum"}
                        or type(self.anchor["schema_version"]) is not int or self.anchor["schema_version"] != 1
                        or self.anchor["lock_identity"] != list(self.lock_identity)
                        or self.anchor["root_identity"] != list(self.root_identity)
                        or type(self.anchor["maximum"]) is not int or not 1 <= self.anchor["maximum"] <= 16777216):
                    raise SessionUnavailable()
                self.maximum = self.anchor["maximum"]
                raw = private_bytes(self.journal, JOURNAL_LIMIT)
                self.current_digest = hashlib.sha256(raw).hexdigest()
                self._anchor_matches(strict_json(raw))
                self._used()
        except (OSError, ValueError, RuntimeError):
            self.close()
            raise SessionUnavailable() from None

    def load(self):
        try:
            raw = private_bytes(self.journal, JOURNAL_LIMIT)
            if hashlib.sha256(raw).hexdigest() != self.current_digest:
                raise SessionUnavailable()
            state = strict_json(raw)
            self._anchor_matches(state)
            return state
        except (OSError, ValueError, RuntimeError):
            raise SessionUnavailable() from None

    def _anchor_matches(self, state):
        try:
            if (self.anchor["spec_sha256"] != hashlib.sha256(canonical(state["spec"]).encode()).hexdigest()
                    or self.anchor["created_at_ms"] != state["created_at_ms"]
                    or self.anchor["backend_epoch"] != state["backend_epoch"]
                    or self.maximum != state["spec"]["limits"]["result_bytes"]):
                raise SessionUnavailable()
        except (KeyError, TypeError, ValueError):
            raise SessionUnavailable() from None

    def _used(self):
        private_directory(self.root)
        private_directory(self.results)
        info = self.root.lstat()
        if (info.st_dev, info.st_ino) != self.root_identity:
            raise SessionUnavailable()
        info = (self.root / "owner.lock").lstat()
        if (info.st_dev, info.st_ino) != self.lock_identity:
            raise SessionUnavailable()
        used, count = 0, 0
        for directory in (self.root, self.results):
            for entry in directory.iterdir():
                if entry == self.results:
                    continue
                count += 1
                if count > 1024:
                    raise SessionUnavailable()
                if directory == self.results:
                    if not (len(entry.name) == 69 and entry.name.endswith(".blob")
                            and all(c in "0123456789abcdef" for c in entry.name[:64])):
                        raise SessionUnavailable()
                elif entry.name not in {"owner.lock", "session.json", "origin.json"} and not entry.name.startswith((".session-", ".result-", ".origin-")):
                    raise SessionUnavailable()
                used += len(private_bytes(entry, self.maximum))
                if used > self.maximum:
                    raise SessionUnavailable()
        return used

    def _create_anchor(self, state):
        anchor = {"schema_version": 1, "spec_sha256": hashlib.sha256(canonical(state["spec"]).encode()).hexdigest(),
            "created_at_ms": state["created_at_ms"], "backend_epoch": state["backend_epoch"],
            "lock_identity": list(self.lock_identity), "root_identity": list(self.root_identity), "maximum": self.maximum}
        descriptor, name = tempfile.mkstemp(prefix=".origin-", dir=self.root)
        temporary = Path(name)
        try:
            with os.fdopen(descriptor, "wb") as target:
                target.write((canonical(anchor) + "\n").encode())
                target.flush()
                os.fsync(target.fileno())
            os.link(temporary, self.origin, follow_symlinks=False)
            temporary.unlink()
            sync_directory(self.root)
            self.anchor = anchor
        finally:
            discard_temporary(temporary)

    def save(self, state):
        """Commit before effects. A failed commit never authorizes dispatch."""
        temporary = None
        try:
            if self.closed:
                raise SessionUnavailable()
            private_directory(self.root)
            raw = (canonical(state) + "\n").encode()
            if len(raw) > JOURNAL_LIMIT:
                raise SessionUnavailable()
            if self.anchor is None:
                self._create_anchor(state)
            self._anchor_matches(state)
            if strict_json(private_bytes(self.origin, 4096)) != self.anchor:
                raise SessionUnavailable()
            # Account for the old journal plus its atomic replacement, so even
            # the retained temporary bytes stay within the declared total cap.
            if self._used() + len(raw) > self.maximum:
                raise SessionUnavailable()
            if self.current_digest is not None:
                old = private_bytes(self.journal, JOURNAL_LIMIT)
                if hashlib.sha256(old).hexdigest() != self.current_digest:
                    raise SessionUnavailable()
            descriptor, name = tempfile.mkstemp(prefix=".session-", dir=self.root)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as target:
                target.write(raw)
                target.flush()
                os.fsync(target.fileno())
            if self.current_digest is None:
                # First publication never adopts or overwrites another state.
                os.link(temporary, self.journal, follow_symlinks=False)
                temporary.unlink()
            else:
                os.replace(temporary, self.journal)
            sync_directory(self.root)
            self.current_digest = hashlib.sha256(raw).hexdigest()
        except (OSError, ValueError, RuntimeError):
            raise SessionUnavailable() from None
        finally:
            discard_temporary(temporary)

    def retain(self, content, maximum):
        """Content-addressed bytes, including failed-write leftovers in the cap."""
        temporary = None
        try:
            if self.closed or type(content) is not bytes or len(content) > maximum:
                raise SessionUnavailable()
            private_directory(self.results)
            key = hashlib.sha256(content).hexdigest()
            path = self.results / (key + ".blob")
            used = self._used()
            if path.exists():
                if private_bytes(path, maximum) != content:
                    raise SessionUnavailable()
                return {"sha256": key, "bytes": len(content)}
            if used + len(content) > min(maximum, self.maximum):
                raise SessionUnavailable()
            descriptor, name = tempfile.mkstemp(prefix=".result-", dir=self.root)
            temporary = Path(name)
            with os.fdopen(descriptor, "wb") as target:
                target.write(content)
                target.flush()
                os.fsync(target.fileno())
            os.link(temporary, path, follow_symlinks=False)
            temporary.unlink()
            sync_directory(self.results)
            return {"sha256": key, "bytes": len(content)}
        except (OSError, ValueError, RuntimeError):
            raise SessionUnavailable() from None
        finally:
            discard_temporary(temporary)

    def read_result(self, record, maximum):
        try:
            if (type(record) is not dict or set(record) != {"sha256", "bytes"}
                    or type(record["sha256"]) is not str or len(record["sha256"]) != 64
                    or any(c not in "0123456789abcdef" for c in record["sha256"])
                    or type(record["bytes"]) is not int or not 0 <= record["bytes"] <= maximum):
                raise SessionUnavailable()
            private_directory(self.results)
            raw = private_bytes(self.results / (record["sha256"] + ".blob"), maximum)
            if len(raw) != record["bytes"] or hashlib.sha256(raw).hexdigest() != record["sha256"]:
                raise SessionUnavailable()
            return raw
        except (OSError, ValueError, RuntimeError):
            raise SessionUnavailable() from None

    def close(self):
        if self.lock is not None:
            os.close(self.lock)
            self.lock = None
        self.closed = True
