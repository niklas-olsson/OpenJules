#!/usr/bin/env python3
"""Acquire, seal, build and qualify one operator-local managed-agent archive.

No registry push or release operation exists. Acquisition is separate from the
networkless build. The approved manifest identifies inputs, not reproducible
output bytes or permission to redistribute them.
"""
from __future__ import annotations

import argparse
import ctypes
import gzip
import hashlib
import io
import json
import lzma
import os
from pathlib import Path, PurePosixPath
import re
import shutil
import signal
import subprocess
import sys
import tarfile
import time
import urllib.parse
import urllib.request

GIB = 1024 ** 3
LIMITS = {"transfer_bytes": 2 * GIB, "archive_bytes": GIB,
          "storage_bytes": 8 * GIB, "seconds": 1800}
SOURCE_FILES = tuple("src/agent/" + name for name in (
    "managed_runner.py", "child_outcome.py", "child_tools.py", "public_tools.py",
    "managed_root_runner.py"))
RECIPE = "docker/Dockerfile.managed-agent"
TESTS = (
    "tests/integration/test_managed_agent_container.py",
    "tests/integration/test_managed_model_runtime.py",
    "tests/integration/test_managed_children_runtime.py",
)
DIGEST = re.compile(r"sha256:[0-9a-f]{64}\Z")
SHA = re.compile(r"[0-9a-f]{40}\Z")
PLATFORM = {"os": "linux", "architecture": "amd64", "variant": None}
REGISTRY = "https://registry-1.docker.io/v2/library/python"
AUTH = "https://auth.docker.io/token?service=registry.docker.io&scope=repository:library/python:pull"
MEDIA = "application/vnd.oci.image.manifest.v1+json,application/vnd.docker.distribution.manifest.v2+json"


class Refused(ValueError):
    pass


def require(value, message):
    if not value:
        raise Refused(message)


def json_bytes(value):
    return json.dumps(value, sort_keys=True, separators=(",", ":"),
                      ensure_ascii=True, allow_nan=False).encode() + b"\n"


def read_json(data):
    def pairs(items):
        result = {}
        for key, value in items:
            require(key not in result, "duplicate JSON key")
            result[key] = value
        return result
    return json.loads(data, object_pairs_hook=pairs,
                      parse_constant=lambda _: (_ for _ in ()).throw(Refused("nonfinite JSON")))


def digest(data):
    return "sha256:" + hashlib.sha256(data).hexdigest()


def hash_file(path):
    with Path(path).open("rb") as stream:
        return "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()


def safe_relative(value):
    require(isinstance(value, str) and value and "\\" not in value,
            "invalid relative path")
    path = PurePosixPath(value)
    require(not path.is_absolute() and all(p not in ("", ".", "..") for p in value.split("/")),
            "unsafe relative path")
    return value


def file_record(path, relative=None):
    path = Path(path)
    require(path.is_file() and not path.is_symlink(), "input must be a regular file")
    return {"path": relative or path.name, "size": path.stat().st_size, "sha256": hash_file(path)}


def verify_file(path, record):
    require(type(record.get("size")) is int and 0 <= record["size"] <= LIMITS["transfer_bytes"],
            "invalid declared size")
    require(DIGEST.fullmatch(record.get("sha256", "")), "invalid SHA-256")
    require(Path(path).is_file() and not Path(path).is_symlink(), "missing regular input")
    require(Path(path).stat().st_size == record["size"] and hash_file(path) == record["sha256"],
            "input size or SHA-256 mismatch")


def stop_group(process, grace=5):
    """Finish the owned session even when its leader already returned."""
    try:
        os.killpg(process.pid, signal.SIGTERM)
    except ProcessLookupError:
        pass
    try:
        process.wait(timeout=grace)
    except subprocess.TimeoutExpired:
        pass
    try:
        os.killpg(process.pid, signal.SIGKILL)
    except ProcessLookupError:
        pass
    process.wait(timeout=5)
    # Budget uses Linux subreaping; reap only this owned process group.
    deadline = time.monotonic() + 5
    while True:
        try:
            child, _ = os.waitpid(-process.pid, os.WNOHANG)
        except ChildProcessError:
            break
        if child == 0:
            require(time.monotonic() < deadline, "owned process cleanup did not finish")
            time.sleep(0.05)


class Budget:
    """The whole private work directory includes both owned Docker data roots.

    Disk enforcement observes apparent bytes at one-second intervals, and stops
    the candidate on excess. It is not a filesystem quota. Each network request
    also reserves 64 KiB of header/redirect overhead, separate from body bytes.
    """
    def __init__(self, root):
        self.root = Path(root)
        self.start = time.monotonic()
        self.transfer = 0
        self.payload = 0
        self.peak = 0
        if sys.platform == "linux":
            require(ctypes.CDLL(None, use_errno=True).prctl(36, 1, 0, 0, 0) == 0, "cannot retain owned child cleanup")
        self.requests = 0
        self.entries = []

    def check(self):
        require(time.monotonic() - self.start < LIMITS["seconds"], "30-minute candidate limit exceeded")
        total = 0
        for directory, _, files in os.walk(self.root, followlinks=False):
            for name in files:
                try:
                    entry = (Path(directory) / name).lstat()
                    total += entry.st_size
                except FileNotFoundError:
                    pass  # Docker can remove its own temporary files.
        self.peak = max(self.peak, total)
        for name in ("managed-agent.docker.tar", "verification.docker.tar"):
            output = self.root / name
            require(not output.exists() or output.stat().st_size <= LIMITS["archive_bytes"], "1-GiB archive ceiling exceeded")
        require(total <= LIMITS["storage_bytes"], "8-GiB observed storage ceiling exceeded")

    def reserve(self, size, description):
        require(type(size) is int and size >= 0, "invalid transfer reservation")
        require(self.transfer + size <= LIMITS["transfer_bytes"], "2-GiB transfer ceiling exceeded")
        self.transfer += size
        self.entries.append({"description": description, "reserved_bytes": size})
        # Persist the reservation before acquisition; a failure does not refund it.
        (self.root / "acquisition-ledger.json").write_bytes(json_bytes(self.report()))
        self.check()

    def request(self):
        self.requests += 1
        self.reserve(65536, "HTTP request/redirect header overhead ceiling")

    def report(self):
        return {"limits": LIMITS, "reserved_transfer_bytes": self.transfer,
                "received_payload_bytes": self.payload, "http_requests": self.requests,
                "peak_observed_storage_bytes": self.peak,
                "elapsed_seconds": round(time.monotonic() - self.start, 3),
                "storage_measurement": "owned directory apparent bytes; sampled once per second; not a filesystem quota",
                "entries": self.entries}

    def run(self, argv, *, env=None, cwd=None, input=None, maximum=16 * 1024 * 1024):
        self.check()
        # Temporary output is included in storage observations and bounded after
        # each poll. No command or output contains provider credentials.
        output = self.root / "command-output.tmp"
        with output.open("wb") as stream:
            process = subprocess.Popen(argv, stdin=subprocess.PIPE if input is not None else subprocess.DEVNULL,
                                       stdout=stream, stderr=subprocess.STDOUT, cwd=cwd, env=env,
                                       start_new_session=True)
            try:
                if input is not None:
                    process.stdin.write(input)
                    process.stdin.close()
                while process.poll() is None:
                    self.check()
                    require(output.stat().st_size <= maximum, "command output exceeds bound")
                    time.sleep(0.5)
                self.check()
                require(output.stat().st_size <= maximum, "command output exceeds bound")
                data = output.read_bytes()
                if process.returncode:
                    # Keep bounded diagnostic text locally; callers decide what
                    # public evidence to retain. No secrets are supplied here.
                    (self.root / "failed-command.txt").write_bytes(data)
                    raise Refused(f"command failed ({process.returncode}): {argv[0]}; see failed-command.txt")
                return data
            finally:
                stop_group(process)
                output.unlink(missing_ok=True)


class Redirects(urllib.request.HTTPRedirectHandler):
    def __init__(self, budget):
        self.budget = budget

    def redirect_request(self, request, response, code, message, headers, url):
        require(urllib.parse.urlsplit(url).scheme == "https", "non-HTTPS acquisition redirect")
        self.budget.request()
        result = super().redirect_request(request, response, code, message, headers, url)
        if request.get_method() == "HEAD":
            result.method = "HEAD"
        if urllib.parse.urlsplit(request.full_url).netloc != urllib.parse.urlsplit(url).netloc:
            result.remove_header("Authorization")
        return result


class Fetcher:
    def __init__(self, root, budget):
        self.root, self.budget = Path(root), budget
        self.opener = urllib.request.build_opener(Redirects(budget))
        self.token = None

    def open(self, url, *, method="GET", headers=None):
        require(urllib.parse.urlsplit(url).scheme == "https", "acquisition requires HTTPS")
        self.budget.request()
        return self.opener.open(urllib.request.Request(url, method=method, headers=headers or {}), timeout=30)

    def registry_headers(self):
        if self.token is None:
            # Public, short-lived registry access token, never retained.
            self.budget.reserve(65536, "public registry token response ceiling")
            with self.open(AUTH) as response:
                data = response.read(65537)
            self.budget.payload += len(data)
            require(len(data) <= 65536, "oversized registry authentication response")
            self.token = read_json(data)["token"]
        return {"Authorization": "Bearer " + self.token, "Accept": MEDIA,
                "Accept-Encoding": "identity"}

    def download(self, url, relative, *, size=None, sha256=None, registry=False):
        safe_relative(relative)
        target = self.root / relative
        target.parent.mkdir(parents=True, exist_ok=True)
        require(not target.exists(), "acquisition input already exists")
        headers = self.registry_headers() if registry else {"Accept-Encoding": "identity"}
        if size is None:
            with self.open(url, method="HEAD", headers=headers) as response:
                length = response.headers.get("Content-Length")
            require(length is not None and length.isdecimal(), "input lacks an exact advertised byte size")
            size = int(length)
        require(type(size) is int and 0 <= size <= LIMITS["transfer_bytes"], "invalid input byte size")
        self.budget.reserve(size, relative)
        total = 0
        with self.open(url, headers=headers) as response, target.open("xb") as output:
            declared = response.headers.get("Content-Length")
            require(declared is None or declared == str(size), "changed advertised input size")
            while True:
                data = response.read(min(1024 * 1024, size + 1 - total))
                if not data:
                    break
                total += len(data)
                self.budget.payload += len(data)
                require(total <= size, "input exceeds declared byte size")
                output.write(data)
                self.budget.check()
        require(total == size, "truncated acquisition input")
        record = file_record(target, relative) | {"url": url}
        require(sha256 is None or record["sha256"] == sha256, "acquired input SHA-256 mismatch")
        return record


class Daemon:
    """Own a fresh rootful Docker daemon and its complete measured data directory."""
    def __init__(self, root, budget, name):
        self.path, self.budget = Path(root) / name, budget
        self.process = None
        self.env = {"PATH": os.environ.get("PATH", "/usr/local/bin:/usr/bin:/bin"), "LANG": "C.UTF-8"}

    def __enter__(self):
        require(os.geteuid() == 0, "isolated native distribution requires root on Linux/amd64")
        require(sys.platform == "linux" and os.uname().machine == "x86_64", "unsupported distribution host")
        require(not self.path.exists(), "Docker data root must be fresh")
        self.path.mkdir()
        (self.path / "client-config").mkdir(mode=0o700)
        self.env["DOCKER_CONFIG"] = str(self.path / "client-config")
        daemon_config = self.path / "daemon.json"
        daemon_config.write_text("{}\n")
        self.env["DOCKER_HOST"] = "unix://" + str(self.path / "docker.sock")
        self.env["DOCKER_BUILDKIT"] = "0"  # No dynamically downloaded builder image.
        self.log = (self.path / "daemon.log").open("wb")
        self.process = subprocess.Popen([
            "dockerd", "--config-file=" + str(daemon_config), "--host=" + self.env["DOCKER_HOST"],
            "--data-root=" + str(self.path / "data"), "--exec-root=" + str(self.path / "exec"),
            "--pidfile=" + str(self.path / "pid"), "--storage-driver=vfs", "--bridge=none",
            "--iptables=false", "--ip6tables=false", "--ip-forward=false", "--ip-masq=false",
        ], stdout=self.log, stderr=subprocess.STDOUT, env=self.env, start_new_session=True)
        started = time.monotonic()
        try:
            while True:
                require(self.process.poll() is None, "owned Docker daemon exited")
                if (self.path / "docker.sock").exists():
                    try:
                        info = read_json(self.run(["info", "--format", "{{json .}}"]))
                        require(Path(info["DockerRootDir"]).resolve() == (self.path / "data").resolve()
                                and info["Driver"] == "vfs", "Docker daemon identity/data root mismatch")
                        self.identity = info["ID"]
                        break
                    except Refused:
                        pass
                require(time.monotonic() - started < 40, "owned Docker daemon did not become ready")
                time.sleep(0.5)
            self.version = read_json(self.run(["version", "--format", "{{json .}}"]))
            return self
        except BaseException:
            self.__exit__(None, None, None)
            raise

    def run(self, args, **kwargs):
        return self.budget.run(["docker", *args], env=self.env, **kwargs)

    def __exit__(self, *unused):
        if self.process is not None:
            stop_group(self.process, grace=20)
        if hasattr(self, "log"):
            self.log.close()
        self.budget.check()


def tar_add_bytes(archive, name, data):
    entry = tarfile.TarInfo(name)
    entry.size, entry.mode = len(data), 0o644
    archive.addfile(entry, io.BytesIO(data))


def base_archive(root, manifest, config, budget):
    root = Path(root)
    require(config.get("os") == "linux" and config.get("architecture") == "amd64"
            and config.get("variant") in (None, ""), "wrong base platform")
    layers = manifest.get("layers")
    diff_ids = config.get("rootfs", {}).get("diff_ids")
    require(isinstance(layers, list) and 1 <= len(layers) <= 32 and len(layers) == len(diff_ids),
            "unsupported base layer layout")
    target = root / "base.docker.tar"
    with tarfile.open(target, "w", format=tarfile.PAX_FORMAT) as archive:
        config_path = root / ("base/" + manifest["config"]["digest"][7:] + ".json")
        config_name = config_path.name
        tar_add_bytes(archive, config_name, config_path.read_bytes())
        names = []
        for index, layer in enumerate(layers):
            blob = root / ("base/" + layer["digest"][7:] + ".layer")
            expanded = root / "expanded-layer.tmp"
            opener = gzip.open if layer["mediaType"].endswith("gzip") else open
            require(layer["mediaType"] in ("application/vnd.oci.image.layer.v1.tar+gzip",
                    "application/vnd.docker.image.rootfs.diff.tar.gzip", "application/vnd.oci.image.layer.v1.tar"),
                    "unsupported base compression")
            with opener(blob, "rb") as source, expanded.open("wb") as output:
                while data := source.read(1024 * 1024):
                    output.write(data)
                    budget.check()
            require(hash_file(expanded) == diff_ids[index], "base uncompressed layer identity mismatch")
            name = str(index) + "/layer.tar"
            archive.add(expanded, arcname=name, recursive=False)
            expanded.unlink()
            names.append(name)
            budget.check()
        tar_add_bytes(archive, "manifest.json", json_bytes([{
            "Config": config_name, "RepoTags": [], "Layers": names}]))
    return target


def release_indexes(data):
    # Signature verification is performed separately with the original base
    # keyring before these package indexes can authorize a build.
    text = data.decode("utf-8")
    records = {}
    section = False
    for line in text.splitlines():
        if line == "SHA256:":
            section = True
        elif section and line.startswith(" "):
            parts = line.split()
            if len(parts) == 3:
                sha, size, path = parts
                require(re.fullmatch("[0-9a-f]{64}", sha) and size.isdecimal(), "invalid signed index entry")
                records[path] = {"sha256": "sha256:" + sha, "size": int(size)}
        elif section:
            break
    require(records, "InRelease has no SHA-256 index")
    return records


def package_records(path):
    records, fields = {}, {}
    with lzma.open(path, "rt", encoding="utf-8") as stream:
        for line in stream:
            if line == "\n":
                if "Filename" in fields:
                    name = safe_relative(fields["Filename"])
                    records[name] = {"package": fields["Package"], "version": fields["Version"],
                                     "architecture": fields["Architecture"], "size": int(fields["Size"]),
                                     "sha256": "sha256:" + fields["SHA256"]}
                fields = {}
            elif not line.startswith(" ") and ": " in line:
                key, value = line.rstrip("\n").split(": ", 1)
                fields[key] = value
    return records


def parse_apt_selection(selected):
    packages = []
    for line in selected.splitlines():
        if line.startswith("'"):
            match = re.fullmatch(r"'file:/inputs/(repos/[^']+\.deb)' (\S+) ([0-9]+)(?: \S+)?", line.rstrip())
            require(match, "unsupported apt selection encoding")
            packages.append({"path": safe_relative(urllib.parse.unquote(match[1], errors="strict")),
                             "filename": match[2], "size": int(match[3])})
    require(packages and len(packages) <= 128, "empty or oversized package selection")
    return packages


def apt_plan(root, daemon):
    # Only signed, acquired local metadata is visible. No apt server is reached.
    command = r'''set -eu
rm -f /etc/apt/sources.list /etc/apt/sources.list.d/*
for suite in bookworm bookworm-updates; do
 printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] file:/inputs/repos/debian %s main\n' "$suite" >> /etc/apt/sources.list
done
printf 'deb [check-valid-until=no signed-by=/usr/share/keyrings/debian-archive-keyring.gpg] file:/inputs/repos/debian-security bookworm-security main\n' >> /etc/apt/sources.list
printf 'KEYRING '
sha256sum /usr/share/keyrings/debian-archive-keyring.gpg
for release in /inputs/repos/*/dists/*/InRelease; do
 printf 'VERIFY %s\n' "$release"
 gpgv --status-fd=1 --keyring /usr/share/keyrings/debian-archive-keyring.gpg "$release"
done
apt-get -o APT::Sandbox::User=root -o Acquire::Languages=none -o Acquire::By-Hash=false update
printf '\nPACKAGES_BEGIN\n'
apt-get -o APT::Sandbox::User=root --print-uris --yes --download-only --no-install-recommends install git ca-certificates
printf '\nPACKAGES_END\nBASE_PACKAGES_BEGIN\n'
dpkg-query -W -f='${Package}\t${Version}\t${Architecture}\n'
printf 'BASE_PACKAGES_END\n'
'''
    config = read_json((root / "base/config.json").read_bytes())
    image = digest((root / "base/config.json").read_bytes())
    require(config["os"] == "linux" and config["architecture"] == "amd64", "wrong solver platform")
    result = daemon.run(["run", "--rm", "--pull=never", "--network=none", "--cap-drop=ALL",
                         "--security-opt=no-new-privileges", "--memory=512m", "--pids-limit=128",
                         "--mount", "type=bind,src=" + str(root / "repos") + ",dst=/inputs/repos,readonly",
                         image, "sh", "-ec", command])
    (root / "apt-verification.txt").write_bytes(result)
    text = result.decode()
    require(text.count("[GNUPG:] VALIDSIG ") >= 3, "missing verified snapshot signatures")
    keyring = re.search(r"^KEYRING ([0-9a-f]{64})  /usr/share/keyrings/debian-archive-keyring.gpg$", text, re.M)
    require(keyring, "missing base keyring identity")
    selected = text.split("PACKAGES_BEGIN\n", 1)[1].split("PACKAGES_END\n", 1)[0]
    packages = parse_apt_selection(selected)
    base_packages = text.split("BASE_PACKAGES_BEGIN\n", 1)[1].split("BASE_PACKAGES_END\n", 1)[0]
    signatures = [line for line in text.splitlines() if line.startswith("[GNUPG:] VALIDSIG ")]
    return packages, {"keyring_sha256": "sha256:" + keyring[1], "valid_signatures": signatures,
                      "base_packages": base_packages.splitlines(), "apt_update_verified": True}


def git_file(repository, revision, path):
    require(SHA.fullmatch(revision), "source/recipe revision must be a complete Git commit")
    return subprocess.check_output(["git", "--no-replace-objects", "-c", "safe.directory=" + str(repository), "-C", str(repository), "show", revision + ":" + path])


def qualification_source(repository, root, budget):
    """Copy exact Git blobs into an owned snapshot; never execute checkout files."""
    git = ["git", "--no-replace-objects", "-c", "safe.directory=" + str(repository), "-C", str(repository)]
    revision = budget.run([*git, "rev-parse", "HEAD"], maximum=1024).decode().strip()
    require(SHA.fullmatch(revision), "invalid native qualification revision")
    listing = budget.run([*git, "ls-tree", "-r", "-z", revision, "--",
                          "src", "tests", "pytest.ini", "pyproject.toml"], maximum=1024 * 1024)
    entries = []
    for line in listing.rstrip(b"\0").split(b"\0"):
        description, path = line.decode().split("\t", 1)
        mode, kind, oid = description.split()
        require(mode in ("100644", "100755") and kind == "blob" and SHA.fullmatch(oid),
                "qualification source must contain regular Git blobs")
        entries.append((safe_relative(path), mode, oid))
    require(0 < len(entries) <= 4096 and set(TESTS) <= {entry[0] for entry in entries},
            "qualification source inventory is incomplete or oversized")
    blobs = budget.run([*git, "cat-file", "--batch"],
                       input="".join(oid + "\n" for _, _, oid in entries).encode(), maximum=32 * 1024 * 1024)
    source = root / "qualification/source"
    source.mkdir()
    offset, records = 0, []
    for path, mode, oid in entries:
        end = blobs.index(b"\n", offset)
        actual_oid, kind, length = blobs[offset:end].decode().split()
        size = int(length)
        require(actual_oid == oid and kind == "blob" and 0 <= size <= 16 * 1024 * 1024,
                "unexpected qualification blob identity or size")
        content = blobs[end + 1:end + 1 + size]
        require(len(content) == size and blobs[end + 1 + size:end + 2 + size] == b"\n"
                and hashlib.sha1(b"blob " + str(size).encode() + b"\0" + content).hexdigest() == oid,
                "qualification blob content mismatch")
        offset = end + 2 + size
        target = source / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(content)
        target.chmod(int(mode[-3:], 8))
        records.append(file_record(target, path) | {"git_blob": oid})
    require(offset == len(blobs), "unexpected qualification blob payload")
    inventory = root / "qualification/source.json"
    inventory.write_bytes(json_bytes(records))
    budget.check()
    return source, {"revision": revision, "inventory_sha256": hash_file(inventory), "files": len(records)}


def acquire(args, root, budget):
    fetcher = Fetcher(root, budget)
    require(DIGEST.fullmatch(args.base_manifest), "base must be an immutable manifest SHA-256")
    require(re.fullmatch(r"[0-9]{8}T[0-9]{6}Z", args.snapshot), "invalid Debian snapshot timestamp")
    records = []
    manifest_record = fetcher.download(REGISTRY + "/manifests/" + args.base_manifest,
                                       "base/manifest.json", sha256=args.base_manifest, registry=True)
    records.append(manifest_record)
    manifest = read_json((root / manifest_record["path"]).read_bytes())
    require(manifest.get("schemaVersion") == 2 and "config" in manifest and "layers" in manifest,
            "base must be one platform manifest, not a multi-platform index")
    descriptor = manifest["config"]
    require(DIGEST.fullmatch(descriptor.get("digest", "")), "invalid base config descriptor")
    record = fetcher.download(REGISTRY + "/blobs/" + descriptor["digest"],
                             "base/" + descriptor["digest"][7:] + ".json",
                             size=descriptor["size"], sha256=descriptor["digest"], registry=True)
    records.append(record)
    shutil.copyfile(root / record["path"], root / "base/config.json")
    config = read_json((root / record["path"]).read_bytes())
    for descriptor in manifest["layers"]:
        require(DIGEST.fullmatch(descriptor.get("digest", "")), "invalid base layer descriptor")
        records.append(fetcher.download(REGISTRY + "/blobs/" + descriptor["digest"],
                        "base/" + descriptor["digest"][7:] + ".layer", size=descriptor["size"],
                        sha256=descriptor["digest"], registry=True))
    base = base_archive(root, manifest, config, budget)
    indexes = {}
    for archive, suite in (("debian", "bookworm"), ("debian", "bookworm-updates"),
                           ("debian-security", "bookworm-security")):
        prefix = f"https://snapshot.debian.org/archive/{archive}/{args.snapshot}/"
        relative = f"repos/{archive}/dists/{suite}/InRelease"
        record = fetcher.download(prefix + f"dists/{suite}/InRelease", relative)
        records.append(record)
        index = "main/binary-amd64/Packages.xz"
        expected = release_indexes((root / relative).read_bytes())[index]
        relative = f"repos/{archive}/dists/{suite}/{index}"
        record = fetcher.download(prefix + f"dists/{suite}/{index}", relative, **expected)
        records.append(record)
        for path, entry in package_records(root / relative).items():
            key = f"repos/{archive}/" + path
            if key in indexes:
                require(indexes[key] == entry | {"url": prefix + path}, "ambiguous signed package identity")
            indexes[key] = entry | {"url": prefix + path}
    with Daemon(root, budget, "solver-daemon") as daemon:
        daemon.run(["image", "load", "--input", str(base)])
        packages, trust = apt_plan(root, daemon)
        tools = {"docker": daemon.version, "python": sys.version, "git": subprocess.check_output(["git", "--version"], text=True).strip()}
    shutil.rmtree(root / "solver-daemon")
    for package in packages:
        require(package["path"] in indexes, "solver selected an undeclared package")
        entry = indexes[package["path"]]
        require(entry["size"] == package["size"] and entry["architecture"] in ("amd64", "all"),
                "solver/index package mismatch")
        record = fetcher.download(entry["url"], package["path"], size=entry["size"], sha256=entry["sha256"])
        records.append(record | {key: entry[key] for key in ("package", "version", "architecture")})
    sources = []
    for path in (*SOURCE_FILES, RECIPE):
        revision = args.recipe_commit if path == RECIPE else args.source_commit
        data = git_file(args.repository, revision, path)
        target = root / "source" / path
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(data)
        sources.append(file_record(target, path) | {"commit": revision})
    result = {"format": "openjules-managed-image-inputs-v1", "platform": PLATFORM,
              "base_manifest_sha256": args.base_manifest, "base_config_id": digest((root / "base/config.json").read_bytes()),
              "snapshot": args.snapshot, "inputs": records, "source_files": sources,
              "source_repository": "https://github.com/niklas-olsson/OpenJules",
              "source_commit": args.source_commit, "recipe_commit": args.recipe_commit,
              "apt": trust, "builder": {"kind": "docker-classic", "network": "none", "package_mode": "sealed",
              "source_permissions": "pyproject declares MIT; accompanying source permission/text remains required before public binary publication"}}
    validate_inputs(result)
    verify_closed_inputs(root, result, packages)
    (root / "inputs.json").write_bytes(json_bytes(result))
    (root / "acquisition-report.json").write_bytes(json_bytes(budget.report() | {"tools": tools}))
    print("INPUT_MANIFEST " + json.dumps(result, sort_keys=True))
    print("INPUT_MANIFEST_SHA256 " + hash_file(root / "inputs.json"))
    return result


def validate_inputs(manifest):
    require(isinstance(manifest, dict) and manifest.get("format") == "openjules-managed-image-inputs-v1", "unsupported input manifest")
    require(set(manifest) == {"format", "platform", "base_manifest_sha256", "base_config_id", "snapshot",
                             "inputs", "source_files", "source_repository", "source_commit", "recipe_commit", "apt", "builder"},
            "unknown or missing input manifest fields")
    require(manifest.get("platform") == PLATFORM, "unsupported image platform")
    require(manifest.get("builder", {}).get("kind") == "docker-classic" and
            manifest["builder"].get("network") == "none" and manifest["builder"].get("package_mode") == "sealed",
            "unsupported build contract")
    require(DIGEST.fullmatch(manifest.get("base_manifest_sha256", "")) and
            DIGEST.fullmatch(manifest.get("base_config_id", "")), "invalid base identities")
    require(SHA.fullmatch(manifest.get("source_commit", "")) and SHA.fullmatch(manifest.get("recipe_commit", "")),
            "invalid source revisions")
    records = manifest.get("inputs")
    require(isinstance(records, list) and 1 <= len(records) <= 256, "invalid input inventory")
    paths = set()
    for record in records:
        require(set(record) == {"path", "size", "sha256", "url"} or
                set(record) == {"path", "size", "sha256", "url", "package", "version", "architecture"},
                "unknown input descriptor fields")
        path = safe_relative(record.get("path"))
        require(path not in paths, "duplicate input path")
        require(path.startswith(("base/", "repos/")), "undeclared input location")
        paths.add(path)
        require(DIGEST.fullmatch(record.get("sha256", "")) and type(record.get("size")) is int
                and 0 <= record["size"] <= LIMITS["transfer_bytes"], "invalid input identity")
        url = urllib.parse.urlsplit(record.get("url", ""))
        require(url.scheme == "https" and not url.username and not url.password and not url.fragment
                and url.hostname in ("registry-1.docker.io", "snapshot.debian.org"), "unsupported acquisition origin")
    require(sum(x["size"] for x in records) <= LIMITS["transfer_bytes"], "input set exceeds transfer ceiling")
    sources = manifest.get("source_files", [])
    require(len(sources) == len(SOURCE_FILES) + 1 and {x.get("path") for x in sources} == set((*SOURCE_FILES, RECIPE)),
            "source inventory must contain exactly the production recipe and five helpers")
    for entry in sources:
        require(set(entry) == {"path", "size", "sha256", "commit"}, "unknown source descriptor fields")
        require(type(entry["size"]) is int and 0 <= entry["size"] <= 1024 * 1024
                and DIGEST.fullmatch(entry["sha256"]), "invalid source identity")
        require(entry.get("commit") == (manifest["recipe_commit"] if entry["path"] == RECIPE else manifest["source_commit"]),
                "source revision mismatch")


def verify_closed_inputs(root, manifest, selected=None):
    """Bind the inventory to immutable registry and signed snapshot parents."""
    records = {item["path"]: item for item in manifest["inputs"]}
    base = read_json((root / "base/manifest.json").read_bytes())
    require(hash_file(root / "base/manifest.json") == manifest["base_manifest_sha256"], "base manifest changed")
    require(base.get("schemaVersion") == 2 and "config" in base and "layers" in base, "invalid platform manifest")
    expected = {"base/manifest.json"}
    for descriptor, suffix in [(base["config"], ".json"), *[(item, ".layer") for item in base["layers"]]]:
        require(DIGEST.fullmatch(descriptor.get("digest", "")), "invalid immutable base descriptor")
        name = "base/" + descriptor["digest"][7:] + suffix
        expected.add(name)
        record = records.get(name, {})
        require(record.get("sha256") == descriptor["digest"] and record.get("size") == descriptor["size"],
                "compressed base input differs from its immutable manifest")
    require(base["config"]["digest"] == manifest["base_config_id"], "base config binding mismatch")
    packages = {}
    for archive, suite in (("debian", "bookworm"), ("debian", "bookworm-updates"),
                           ("debian-security", "bookworm-security")):
        release = f"repos/{archive}/dists/{suite}/InRelease"
        index = f"repos/{archive}/dists/{suite}/main/binary-amd64/Packages.xz"
        expected.update((release, index))
        signed = release_indexes((root / release).read_bytes())["main/binary-amd64/Packages.xz"]
        require(records[index]["sha256"] == signed["sha256"] and records[index]["size"] == signed["size"],
                "package index differs from signed release")
        for name, entry in package_records(root / index).items():
            key = f"repos/{archive}/" + name
            if key in packages:
                require(packages[key] == entry, "ambiguous signed package identity")
            packages[key] = entry
    declared = {item["path"]: item for item in manifest["inputs"] if item["path"].endswith(".deb")}
    if selected is not None:
        require(len(selected) == len(declared) and {item["path"] for item in selected} == set(declared),
                "sealed package inventory differs from actual offline apt selection")
        for item in selected:
            require(item["size"] == declared[item["path"]]["size"], "solver package size mismatch")
    require(declared, "no declared packages")
    for name, record in declared.items():
        require(name in packages and all(record.get(key) == value for key, value in packages[name].items()),
                "declared package differs from signed index")
    expected.update(declared)
    require(set(records) == expected, "undeclared or omitted build inputs")


def restore_inputs(args, root, budget, manifest):
    validate_inputs(manifest)
    fetcher = Fetcher(root, budget)
    for record in manifest["inputs"]:
        fetcher.download(record["url"], record["path"], size=record["size"], sha256=record["sha256"],
                         registry=record["url"].startswith(REGISTRY + "/"))
    base = read_json((root / "base/manifest.json").read_bytes())
    require(hash_file(root / "base/manifest.json") == manifest["base_manifest_sha256"], "base manifest changed")
    config_path = root / ("base/" + base["config"]["digest"][7:] + ".json")
    require(hash_file(config_path) == manifest["base_config_id"], "base config changed")
    shutil.copyfile(config_path, root / "base/config.json")
    config = read_json(config_path.read_bytes())
    base_archive(root, base, config, budget)
    for record in manifest["source_files"]:
        target = root / "source" / record["path"]
        target.parent.mkdir(parents=True, exist_ok=True)
        target.write_bytes(git_file(args.repository, record["commit"], record["path"]))
        verify_file(target, record)
    verify_closed_inputs(root, manifest)
    (root / "inputs.json").write_bytes(json_bytes(manifest))


def oci_archive_metadata(archive, members, image, config_name, config_bytes, layers, permitted):
    """Validate Moby's OCI graph and bounded V1 compatibility metadata."""
    require({"index.json", "oci-layout"} <= set(members),
            "unreferenced archive payload: incomplete OCI layout")
    metadata = []

    def document(name):
        require(name in members and members[name].isfile() and members[name].size <= 65536,
                "missing or oversized OCI/compatibility metadata")
        data = archive.extractfile(members[name]).read()
        metadata.append({"path": name, "size": len(data), "sha256": digest(data)})
        permitted.add(name)
        return data, read_json(data)

    _, layout = document("oci-layout")
    require(layout == {"imageLayoutVersion": "1.0.0"}, "unsupported OCI layout version")
    _, index = document("index.json")
    require(isinstance(index, dict) and set(index) == {"schemaVersion", "mediaType", "manifests"}
            and index["schemaVersion"] == 2 and index["mediaType"] == "application/vnd.oci.image.index.v1+json"
            and isinstance(index["manifests"], list) and len(index["manifests"]) == 1,
            "archive OCI index must identify one untagged image")
    descriptor = index["manifests"][0]
    require(isinstance(descriptor, dict) and set(descriptor) == {"mediaType", "digest", "size"}
            and descriptor["mediaType"] == "application/vnd.oci.image.manifest.v1+json"
            and DIGEST.fullmatch(descriptor["digest"]) and type(descriptor["size"]) is int,
            "unsupported OCI manifest descriptor")
    name = "blobs/sha256/" + descriptor["digest"].split(":")[1]
    data, manifest = document(name)
    require(digest(data) == descriptor["digest"] and len(data) == descriptor["size"],
            "OCI manifest content identity mismatch")
    require(isinstance(manifest, dict) and set(manifest) == {"schemaVersion", "mediaType", "config", "layers"}
            and manifest["schemaVersion"] == 2
            and manifest["mediaType"] == "application/vnd.oci.image.manifest.v1+json",
            "unsupported OCI manifest")
    require(config_name == "blobs/sha256/" + digest(config_bytes).split(":")[1]
            and manifest["config"] == {"mediaType": "application/vnd.oci.image.config.v1+json",
                                       "digest": digest(config_bytes), "size": len(config_bytes)},
            "OCI and Docker config identities disagree")
    descriptors = [{"mediaType": "application/vnd.oci.image.layer.v1.tar", "digest": layer["diff_id"],
                    "size": layer["size"]} for layer in layers]
    require(manifest["layers"] == descriptors
            and all(layer["path"] == "blobs/sha256/" + layer["diff_id"].split(":")[1] for layer in layers),
            "OCI and Docker ordered layer identities disagree")
    require(image.get("LayerSources") == {layer["diff_id"]: descriptor
                                         for layer, descriptor in zip(layers, descriptors)},
            "Docker layer-source descriptors disagree with OCI layers")
    # Moby also emits one V1 config per layer, although neither modern graph
    # references it. Admit only content-addressed, bounded, complete metadata
    # chains ending at this exact modern config, never arbitrary extra blobs.
    compatibility = {}
    allowed = {"id", "parent", "comment", "created", "container", "container_config",
               "docker_version", "author", "config", "architecture", "variant", "os", "Size"}
    for name, member in members.items():
        if member.isdir() or name in permitted:
            continue
        data, value = document(name)
        require(name == "blobs/sha256/" + digest(data).split(":")[1]
                and isinstance(value, dict) and set(value) <= allowed
                and re.fullmatch(r"[0-9a-f]{64}", value.get("id", ""))
                and value["id"] not in compatibility and value.get("os") == "linux",
                "unreferenced archive payload is not recognized V1 metadata")
        compatibility[value["id"]] = value
    require(len(compatibility) == len(layers), "incomplete V1 compatibility metadata")
    parent = ""
    config = read_json(config_bytes)
    for number in range(len(layers)):
        candidates = [value for value in compatibility.values() if value.get("parent", "") == parent]
        require(len(candidates) == 1, "ambiguous V1 compatibility parent chain")
        value = candidates[0]
        del compatibility[value["id"]]
        if number + 1 == len(layers):
            require(value.get("config") == config.get("config")
                    and all(config.get(key) == item for key, item in value.items() if key not in {"id", "parent"}),
                    "V1 terminal metadata differs from modern image config")
        else:
            require(set(value) <= {"id", "parent", "created", "container_config", "os"}
                    and value.get("created") == "1970-01-01T00:00:00Z"
                    and isinstance(value.get("container_config"), dict)
                    and all(item in (None, False, "", 0) for item in value["container_config"].values()),
                    "unsupported V1 intermediate metadata")
        parent = value["id"]
    return metadata


def inspect_archive(path, *, expected=None, diagnostic=None):
    """Check archive identity and every ordered uncompressed layer, without extraction."""
    path = Path(path)
    require(path.is_file() and not path.is_symlink() and path.stat().st_size <= LIMITS["archive_bytes"],
            "archive missing, nonregular or larger than 1 GiB")
    if expected is not None:
        require(expected.get("format") == "docker-image-save"
                and expected.get("platform") == PLATFORM
                and expected.get("registry_manifest_digest") is None
                and DIGEST.fullmatch(expected.get("image_id", ""))
                and expected.get("config_sha256") == expected["image_id"],
                "invalid expected archive contract")
        verify_file(path, expected["archive"])
    record = file_record(path)
    with tarfile.open(path, "r:") as archive:
        members = {}
        for member in archive:
            name = member.name.rstrip("/")
            safe_relative(name)
            require(name not in members and (member.isfile() or member.isdir()), "duplicate or nonregular archive member")
            require(len(members) < 4096, "too many archive members")
            members[name] = member
        if diagnostic is not None:
            inventory = []
            for name, member in members.items():
                entry = {"path": name, "size": member.size, "type": "directory" if member.isdir() else "file"}
                if member.isfile() and member.size <= 65536:
                    data = archive.extractfile(member).read()
                    try:
                        entry["json"] = read_json(data)
                        entry["sha256"] = digest(data)
                    except (ValueError, UnicodeError):
                        pass
                inventory.append(entry)
            Path(diagnostic).write_bytes(json_bytes(inventory))
        require("manifest.json" in members and members["manifest.json"].size <= 65536, "missing or oversized Docker manifest")
        images = read_json(archive.extractfile(members["manifest.json"]).read())
        require(isinstance(images, list) and len(images) == 1, "archive must contain one image")
        image = images[0]
        require(isinstance(image, dict) and set(image) <= {"Config", "RepoTags", "Layers", "LayerSources"}
                and {"Config", "RepoTags", "Layers"} <= set(image)
                and isinstance(image["Layers"], list) and image["RepoTags"] in (None, []),
                "unsupported Docker archive manifest")
        config_name = safe_relative(image["Config"])
        require(config_name in members and members[config_name].size <= 1024 * 1024, "invalid image config member")
        config_bytes = archive.extractfile(members[config_name]).read()
        config = read_json(config_bytes)
        platform = {key: config.get(key) or None for key in PLATFORM}
        require(platform == PLATFORM, "archive platform is unsupported")
        diff_ids = config.get("rootfs", {}).get("diff_ids")
        require(isinstance(diff_ids, list) and len(diff_ids) == len(image["Layers"]) and 0 < len(diff_ids) <= 128,
                "invalid archive layer inventory")
        layers = []
        permitted = {"manifest.json", config_name, "repositories"}
        for name, diff_id in zip(image["Layers"], diff_ids):
            safe_relative(name)
            require(name in members and members[name].isfile(), "missing archive layer")
            stream = archive.extractfile(members[name])
            actual = "sha256:" + hashlib.file_digest(stream, "sha256").hexdigest()
            require(actual == diff_id, "uncompressed layer/config identity mismatch")
            layers.append({"path": name, "size": members[name].size, "diff_id": actual})
            permitted.add(name)
            if name.endswith("/layer.tar"):
                parent = str(PurePosixPath(name).parent)
                permitted.update((parent + "/json", parent + "/VERSION"))
        require(len({item["path"] for item in layers}) == len(layers), "duplicate archive layer reference")
        metadata = []
        if "index.json" in members or "oci-layout" in members:
            metadata = oci_archive_metadata(archive, members, image, config_name, config_bytes, layers, permitted)
        for name, member in members.items():
            require(member.isdir() or name in permitted, "unreferenced archive payload")
            if member.isfile() and name in permitted - {config_name, *image["Layers"]}:
                require(member.size <= 65536, "oversized archive metadata")
        result = {"format": "docker-image-save", "archive": record, "platform": platform,
                  "image_id": digest(config_bytes), "config_sha256": digest(config_bytes),
                  "layers": layers, "registry_manifest_digest": None,
                  "layout": "moby-docker-save-oci-v1" if metadata else "classic-docker-save",
                  "metadata": metadata}
    if expected is not None:
        require(result["image_id"] == expected["image_id"] and result["platform"] == expected["platform"]
                and result["layers"] == expected["layers"], "archive does not match approved image identities")
    return result


def inspect_loaded(daemon, record):
    image = read_json(daemon.run(["image", "inspect", record["image_id"]]))[0]
    require(image["Id"] == record["image_id"] and image["Os"] == "linux" and image["Architecture"] == "amd64",
            "loaded image identity/platform mismatch")
    require(image["RootFS"]["Layers"] == [x["diff_id"] for x in record["layers"]], "loaded image layer mismatch")


def inspect_packages(daemon, image_id, manifest):
    expected = {}
    for line in manifest["apt"]["base_packages"]:
        name, version, architecture = line.split("\t")
        expected[(name, architecture)] = version
    for item in manifest["inputs"]:
        if item["path"].endswith(".deb"):
            expected[(item["package"], item["architecture"])] = item["version"]
    output = daemon.run(["run", "--rm", "--pull=never", "--network=none", "--read-only",
                         "--cap-drop=ALL", "--security-opt=no-new-privileges", image_id,
                         "dpkg-query", "-W", "-f=${db:Status-Abbrev}\t${Package}\t${Version}\t${Architecture}\n"])
    actual = {}
    for line in output.decode().splitlines():
        status, name, version, architecture = line.split("\t")
        require(status == "ii " and (name, architecture) not in actual,
                "built image contains an unconfigured or repeated package")
        actual[(name, architecture)] = version
    require(actual == expected, "built image package set differs from approved base and additions")
    return ["\t".join((name, version, architecture))
            for (name, architecture), version in sorted(actual.items())]


def build(args, root, budget, manifest):
    from tools.managed_image_qualification import provision

    qualification_python, qualification_inputs = provision(
        args.repository, root, budget, args.approved_qualification,
        args.approved_qualification_sha256,
    )
    test_source, test_source_record = qualification_source(args.repository, root, budget)
    restore_inputs(args, root, budget, manifest)
    context = root / "context"
    shutil.copytree(root / "source", context)
    packages = context / "docker/managed-agent-packages"
    packages.mkdir()
    for record in manifest["inputs"]:
        if record["path"].endswith(".deb"):
            target = packages / PurePosixPath(record["path"]).name
            require(not target.exists(), "duplicate package filename")
            shutil.copyfile(root / record["path"], target)
            verify_file(target, record)
    require(any(packages.iterdir()), "sealed package set is empty")
    context_manifest = [file_record(path, path.relative_to(context).as_posix())
                        for path in sorted(context.rglob("*")) if path.is_file()]
    (root / "context.json").write_bytes(json_bytes(context_manifest))
    with Daemon(root, budget, "build-daemon") as daemon:
        daemon.run(["image", "load", "--input", str(root / "base.docker.tar")])
        selected, trust = apt_plan(root, daemon)
        require(trust == manifest["apt"], "snapshot trust/base package evidence changed")
        verify_closed_inputs(root, manifest, selected)
        iid = root / "image.id"
        arguments = ["build", "--network=none", "--pull=false", "--no-cache", "--force-rm",
                     "--build-arg", "PYTHON_BASE=" + manifest["base_config_id"],
                     "--build-arg", "OPENJULES_PACKAGE_MODE=sealed", "--iidfile", str(iid),
                     "-f", str(context / RECIPE), str(context)]
        output = daemon.run(arguments)
        (root / "build.log").write_bytes(output)
        image_id = iid.read_text().strip()
        require(DIGEST.fullmatch(image_id), "builder did not return an immutable image ID")
        installed_packages = inspect_packages(daemon, image_id, manifest)
        archive = root / "managed-agent.docker.tar"
        daemon.run(["image", "save", "--output", str(archive), image_id])
        record = inspect_archive(archive, diagnostic=root / "archive-inventory.json")
        require(record["image_id"] == image_id, "exported image differs from built image")
        record.update({"input_manifest_sha256": hash_file(root / "inputs.json"),
                       "context_sha256": hash_file(root / "context.json"), "build_arguments": ["--network=none", "--pull=false", "--no-cache", "--force-rm", "PYTHON_BASE=" + manifest["base_config_id"], "OPENJULES_PACKAGE_MODE=sealed"],
                       "docker_version": daemon.version, "source_commit": manifest["source_commit"],
                       "recipe_commit": manifest["recipe_commit"],
                       "installed_packages": installed_packages,
                       "distribution_permission": "operator-local-only; public source permission/text and bundled-notice approval pending"})
    # Remove only this command's stopped, owned daemon data. The next import is
    # into an empty daemon with no base, build cache, image or registry credential.
    shutil.rmtree(root / "build-daemon")
    budget.reserve(archive.stat().st_size, "archive transfer to clean verification input")
    verification = root / "verification.docker.tar"
    shutil.copyfile(archive, verification)
    inspect_archive(verification, expected=record)
    with Daemon(root, budget, "verification-daemon") as daemon:
        daemon.run(["image", "load", "--input", str(verification)])
        inspect_loaded(daemon, record)
        temporary = root / "native-temporary"
        temporary.mkdir()
        env = daemon.env | {"OPENJULES_MANAGED_DOCKER_TESTS": "1", "OPENJULES_MANAGED_AGENT_IMAGE_ID": image_id,
                            "LITELLM_LOCAL_MODEL_COST_MAP": "True", "PYTEST_DISABLE_PLUGIN_AUTOLOAD": "1",
                            "PYTHONNOUSERSITE": "1", "PYTHONDONTWRITEBYTECODE": "1", "TMPDIR": str(temporary)}
        test_command = [qualification_python, "-B", "-m", "pytest", "-p", "pytest_asyncio.plugin", "-p", "no:cacheprovider",
                        "--basetemp", str(temporary / "pytest"), "-v", *TESTS]
        output = budget.run(test_command, cwd=test_source, env=env)
        (root / "native-tests.txt").write_bytes(output)
        text = output.decode(errors="replace")
        require(" skipped" not in text and " passed" in text, "native qualification did not execute all selected tests")
        record["qualification"] = {"tests": list(TESTS), "native": True, "provider": "deterministic HTTP fixtures",
                                   "authority": "fixtures", "fresh_import": True,
                                   "test_revision": test_source_record["revision"], "test_source": test_source_record}
        record["qualification"]["python_inputs"] = qualification_inputs
    verification.unlink()
    shutil.rmtree(root / "verification-daemon")
    record["measurements"] = budget.report()
    (root / "artifact.json").write_bytes(json_bytes(record))
    print("ARTIFACT_RECORD " + json.dumps(record, sort_keys=True))
    print(output.decode(errors="replace"))


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="action", required=True)
    prepare = sub.add_parser("acquire")
    prepare.add_argument("--base-manifest", required=True)
    prepare.add_argument("--snapshot", required=True)
    prepare.add_argument("--source-commit", required=True)
    prepare.add_argument("--recipe-commit", required=True)
    sealed = sub.add_parser("build")
    sealed.add_argument("--approved-inputs", required=True, type=Path)
    sealed.add_argument("--approved-inputs-sha256", required=True)
    sealed.add_argument("--approved-qualification", required=True, type=Path)
    sealed.add_argument("--approved-qualification-sha256", required=True)
    for command in (prepare, sealed):
        command.add_argument("--repository", type=Path, default=Path.cwd())
        command.add_argument("--output", type=Path, required=True)
    verify = sub.add_parser("verify")
    verify.add_argument("--archive", type=Path, required=True)
    verify.add_argument("--record", type=Path, required=True)
    verify.add_argument("--record-sha256", required=True)
    args = parser.parse_args(argv)
    if args.action == "verify":
        require(args.record.stat().st_size <= 1024 * 1024 and hash_file(args.record) == args.record_sha256,
                "approved artifact record hash mismatch")
        record = read_json(args.record.read_bytes())
        print(json.dumps(inspect_archive(args.archive, expected=record), sort_keys=True))
        return
    root = args.output.resolve()
    require(not root.exists(), "output directory must not already exist")
    root.mkdir(mode=0o700, parents=True)
    budget = Budget(root)
    args.repository = args.repository.resolve()
    try:
        if args.action == "acquire":
            acquire(args, root, budget)
        else:
            require(args.approved_inputs.stat().st_size <= 1024 * 1024, "oversized input manifest")
            require(hash_file(args.approved_inputs) == args.approved_inputs_sha256, "approved manifest hash mismatch")
            manifest = read_json(args.approved_inputs.read_bytes())
            require(json_bytes(manifest) == args.approved_inputs.read_bytes(), "input manifest must use its original canonical bytes")
            build(args, root, budget, manifest)
    finally:
        (root / "resource-report.json").write_bytes(json_bytes(budget.report()))


if __name__ == "__main__":
    try:
        main()
    except (ValueError, OSError, KeyError, TypeError) as error:
        print("Managed image candidate refused: " + str(error), file=sys.stderr)
        raise SystemExit(1)
