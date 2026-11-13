"""Finite, offline Python environment for the three native image test modules.

The operator reviews exact public wheel identities before this module installs
anything. This is a qualification fixture, not an installer or online resolver.
"""
from __future__ import annotations

import email.parser
import os
from pathlib import Path
import re
import sys
import urllib.parse
import zipfile

from tools.managed_image import (
    DIGEST, LIMITS, Fetcher, hash_file, json_bytes, read_json, require, verify_file,
)


def canonical_name(value):
    return re.sub(r"[-_.]+", "-", value).lower()


def validate_plan(plan):
    require(isinstance(plan, dict) and set(plan) == {
        "format", "python", "platform", "requirements", "wheels", "metadata", "discovery"},
        "unsupported qualification manifest fields")
    require(plan["format"] == "openjules-image-qualification-v1" and plan["python"] == [3, 12]
            and plan["platform"] == "linux-amd64", "unsupported qualification environment")
    require(plan["requirements"] == ["pytest", "pytest-asyncio", "docker", "httpx"],
            "unsupported native qualification roots")
    require(isinstance(plan["wheels"], list) and 4 <= len(plan["wheels"]) <= 32, "invalid wheel inventory")
    names, filenames = set(), set()
    for wheel in plan["wheels"]:
        require(set(wheel) == {"name", "version", "filename", "url", "size", "sha256"}, "invalid wheel fields")
        name = canonical_name(wheel["name"])
        require(re.fullmatch(r"[a-z0-9][a-z0-9-]*", name) and name not in names, "duplicate or invalid wheel name")
        names.add(name)
        filename = wheel["filename"]
        require(re.fullmatch(r"[A-Za-z0-9_.+-]+-py(?:2\.)?3-none-any\.whl", filename)
                and filename not in filenames, "qualification requires distinct universal wheels")
        filenames.add(filename)
        require(type(wheel["size"]) is int and 0 < wheel["size"] <= 32 * 1024 * 1024
                and DIGEST.fullmatch(wheel["sha256"]), "invalid wheel size or SHA-256")
        url = urllib.parse.urlsplit(wheel["url"])
        require(url.scheme == "https" and url.hostname == "files.pythonhosted.org"
                and not url.username and not url.password and not url.query and not url.fragment
                and url.path.endswith("/" + filename), "unsupported public wheel URL")
    require(set(plan["requirements"]) <= names and "pip" in names, "missing qualification seed/root wheel")
    require(next(item["version"] for item in plan["wheels"] if item["name"] == "pip") == "25.3",
            "unsupported pinned pip seed")
    overhead = plan["discovery"].get("reserved_transfer_bytes")
    require(type(overhead) is int and 0 < overhead <= LIMITS["transfer_bytes"], "invalid metadata acquisition accounting")
    require(isinstance(plan["metadata"], list) and len(plan["metadata"]) == len(names)
            and all(type(item.get("size")) is int and item["size"] > 0
                    and DIGEST.fullmatch(item.get("sha256", "")) for item in plan["metadata"]),
            "invalid qualification metadata provenance")
    require(overhead >= sum(item["size"] for item in plan["metadata"]), "metadata acquisition is undercounted")


def check_wheel(path, expected):
    verify_file(path, expected)
    with zipfile.ZipFile(path) as archive:
        metadata = [item for item in archive.infolist()
                    if re.fullmatch(r"[^/]+\.dist-info/METADATA", item.filename)]
        require(len(metadata) == 1 and metadata[0].file_size <= 1024 * 1024,
                "wheel has ambiguous or oversized distribution metadata")
        fields = email.parser.BytesParser().parsebytes(archive.read(metadata[0]))
        require(canonical_name(fields["Name"]) == canonical_name(expected["name"])
                and fields["Version"] == expected["version"], "wheel name/version mismatch")


def provision(repository, root, budget, approved, expected_sha):
    require(list(sys.version_info[:2]) == [3, 12], "qualification manifest requires Python 3.12")
    require(approved.is_file() and not approved.is_symlink() and approved.stat().st_size <= 1024 * 1024
            and hash_file(approved) == expected_sha, "approved qualification manifest hash mismatch")
    data = approved.read_bytes()
    plan = read_json(data)
    require(json_bytes(plan) == data, "qualification manifest must preserve original canonical bytes")
    validate_plan(plan)
    # Discovery was a separate read-only operation. Charge its complete retained
    # conservative request/body reservation to this candidate as well.
    budget.reserve(plan["discovery"]["reserved_transfer_bytes"], "qualification metadata discovery")
    fetcher = Fetcher(root, budget)
    wheels = root / "qualification/wheels"
    for wheel in plan["wheels"]:
        relative = "qualification/wheels/" + wheel["filename"]
        fetcher.download(wheel["url"], relative, size=wheel["size"], sha256=wheel["sha256"])
        check_wheel(root / relative, wheel)
    temporary = root / "qualification/tmp"
    temporary.mkdir()
    env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LANG": "C.UTF-8",
           "TMPDIR": str(temporary), "PIP_CONFIG_FILE": os.devnull,
           "PIP_DISABLE_PIP_VERSION_CHECK": "1", "PIP_NO_CACHE_DIR": "1",
           "PIP_NO_INDEX": "1", "PYTHONNOUSERSITE": "1"}
    venv = root / "qualification/venv"
    budget.run([sys.executable, "-I", "-m", "venv", "--without-pip", "--copies", str(venv)], env=env)
    python = venv / "bin/python"
    requirements = root / "qualification/requirements.txt"
    requirements.write_text("".join(
        (wheels / wheel["filename"]).as_uri() + " --hash=" + wheel["sha256"] + "\n"
        for wheel in plan["wheels"]), encoding="utf-8")
    seed = next(wheel for wheel in plan["wheels"] if wheel["name"] == "pip")
    command = [str(python), "-I", "-c",
               "import runpy,sys;sys.path.insert(0,sys.argv.pop(1));runpy.run_module('pip',run_name='__main__')",
               str(wheels / seed["filename"]), "--disable-pip-version-check", "install",
               "--no-index", "--no-deps", "--no-cache-dir", "--require-hashes", "--only-binary=:all:",
               "--prefix", str(venv), "-r", str(requirements)]
    output = budget.run(command, env=env)
    (root / "qualification/install.txt").write_bytes(output)
    budget.run([str(python), "-I", "-m", "pip", "--disable-pip-version-check", "check"], env=env)
    actual = read_json(budget.run([str(python), "-I", "-c",
        "import importlib.metadata,json;print(json.dumps({d.metadata['Name']:d.version for d in importlib.metadata.distributions()}))"], env=env))
    actual = {canonical_name(name): version for name, version in actual.items()}
    expected = {canonical_name(wheel["name"]): wheel["version"] for wheel in plan["wheels"]}
    require(actual == expected, "qualification interpreter contains missing or undeclared distributions")
    (root / "qualification/manifest.json").write_bytes(data)
    return str(python), {"manifest_sha256": expected_sha, "installed_distributions": actual,
                         "wheel_bytes": sum(wheel["size"] for wheel in plan["wheels"]),
                         "metadata_discovery_reserved_bytes": plan["discovery"]["reserved_transfer_bytes"],
                         "offline_install": True, "no_seed_ensurepip": True}
