"""Experience and learned skills manager (EXPERIENCE.md).

Manages reading, formatting, and appending compounded capabilities across tasks.
"""

import datetime
from contextlib import contextmanager
import fcntl
import logging
import os
import stat
from typing import List, Optional

logger = logging.getLogger(__name__)

DEFAULT_HEADER = """# Project Experience & Compounded Skills Library

Accumulated learnings, guardrails, and project-specific patterns discovered by OpenJules across tasks.
This file is autonomously updated by the adaptive agent harness to accelerate future work.

---
"""


class ExperienceManager:
    """Reads, extracts, and records learnings in EXPERIENCE.md."""

    def __init__(self, experience_path: str = "EXPERIENCE.md"):
        # This setting comes from repository data and names a host-side file.
        # Refuse escape syntax before any model call or filesystem operation.
        if (
            not isinstance(experience_path, str)
            or not experience_path
            or len(experience_path.encode("utf-8")) > 4096
            or "\\" in experience_path
            or "\0" in experience_path
            or any(part in {"", ".", ".."} for part in experience_path.split("/"))
            or ":" in experience_path
        ):
            raise ValueError("experience_path must be a relative workspace file")
        self.experience_path = experience_path
        self._parts = experience_path.split("/")

    @contextmanager
    def _parent(self, workspace_dir: str, *, create: bool = False):
        """Walk beneath the original workspace without following symlinks.

        Descriptor-relative opens also avoid check-then-open races on each
        repository-controlled path component. The host owns the workspace root.
        """
        flags = os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC
        directory = os.open(workspace_dir, flags)
        try:
            for part in self._parts[:-1]:
                if create:
                    try:
                        os.mkdir(part, mode=0o700, dir_fd=directory)
                    except FileExistsError:
                        pass
                following = os.open(part, flags, dir_fd=directory)
                os.close(directory)
                directory = following
            yield directory, self._parts[-1]
        finally:
            os.close(directory)

    @staticmethod
    def _regular_file(fd):
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_nlink != 1:
            raise ValueError("experience file must be a regular single-link workspace file")
        return info

    def load_experience(self, workspace_dir: str) -> str:
        """Reads existing experience file from workspace if present."""
        try:
            with self._parent(workspace_dir) as (directory, name):
                fd = os.open(name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
                             dir_fd=directory)
                with os.fdopen(fd, "r", encoding="utf-8") as f:
                    self._regular_file(f.fileno())
                    return f.read().strip()
        except (OSError, ValueError):
            logger.debug("Repository experience is absent or unavailable")
        return ""

    def append_experience(
        self,
        workspace_dir: str,
        task_title: str,
        problem_summary: str,
        solution_pattern: str,
        discovered_rules: List[str],
    ) -> str:
        """Appends a new experience entry to EXPERIENCE.md in the workspace."""
        timestamp = datetime.datetime.now(datetime.timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        rules_formatted = "\n".join(f"- {rule}" for rule in discovered_rules) if discovered_rules else "- Standard verification practices apply."

        entry = (
            f"\n### [{timestamp}] Task: {task_title}\n\n"
            f"**Problem:** {problem_summary}\n\n"
            f"**Strategy & Solution:** {solution_pattern}\n\n"
            f"**Compounded Rules / Guardrails:**\n"
            f"{rules_formatted}\n\n"
            f"---\n"
        )

        with self._parent(workspace_dir, create=True) as (directory, name):
            fd = os.open(name, os.O_WRONLY | os.O_APPEND | os.O_CREAT | os.O_NOFOLLOW
                         | os.O_NONBLOCK | os.O_CLOEXEC, 0o600, dir_fd=directory)
            with os.fdopen(fd, "a", encoding="utf-8") as f:
                self._regular_file(f.fileno())
                # Never wait indefinitely for another task's optional memory
                # write. Appending under this lock preserves earlier entries.
                fcntl.flock(f.fileno(), fcntl.LOCK_EX | fcntl.LOCK_NB)
                prefix = DEFAULT_HEADER.rstrip() + "\n" if os.fstat(f.fileno()).st_size == 0 else ""
                f.write(prefix + "\n" + entry)
                f.flush()

        logger.info("Appended repository experience")
        return os.path.join(os.path.abspath(workspace_dir), self.experience_path)
