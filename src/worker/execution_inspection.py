"""Bounded read-only inspection of installed source and immutable image bytes."""

import hashlib
from pathlib import Path
import re
import tempfile
import time


def source_commit(profile):
    # Reuse the bounded isolated Git plumbing, never the source's configuration,
    # hooks, replacement refs, ignored files or executable checkout commands.
    from .source_snapshot import _bare, _git

    source = Path(profile.source_path).resolve(strict=True)
    git_dir = source / ".git" if (source / ".git").is_dir() else source
    objects = git_dir / "objects"
    if (source / ".git").is_file() or not objects.is_dir() or objects.is_symlink():
        raise ValueError("complete approved source objects are required")
    with tempfile.TemporaryDirectory(prefix="openjules-contract-inspection-") as temporary:
        reader = Path(temporary)
        _bare(reader, profile.base_commit)
        value = _git(reader, ["cat-file", "commit", profile.base_commit],
                     deadline=time.monotonic() + 10, limit=min(profile.max_archive_bytes, 1048576), objects=objects)
    actual = hashlib.sha1(b"commit " + str(len(value)).encode() + b"\0" + value).hexdigest()
    if actual != profile.base_commit or not re.match(rb"tree [0-9a-f]{40}\n", value):
        raise ValueError("approved source commit is unavailable")


def installed_image(profile, client):
    source_commit(profile)
    image = client.images.get(profile.image)
    if profile.image.startswith("sha256:"):
        if image.id != profile.image:
            raise ValueError("installed image config differs from the approved ID")
    elif profile.image not in image.attrs.get("RepoDigests", []):
        raise ValueError("installed image differs from the approved manifest")
    return {"config_digest": image.id, "os": image.attrs.get("Os"),
            "architecture": image.attrs.get("Architecture"),
            "variant": image.attrs.get("Variant") or None}
