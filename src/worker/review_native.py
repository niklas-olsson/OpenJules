"""Original source, offline guest and host publication ports for one review.

This is a review-only transport implementation. It has no scheduler, policy
store, managed authority, provider fallback, constructor client or retry.
"""
from __future__ import annotations

from dataclasses import dataclass
import hashlib
import io
import json
import os
from pathlib import Path
import re
import shlex
import shutil
import socket
import ssl
import stat
import struct
import tarfile
import time

from .review_contract import (PreparedReviewSource, OriginalReviewGuest, ReviewCandidate,
                              ReviewClaim, ReviewError, ReviewExecObservation, ReviewPublication)
from .review_capture import canonical, durable_file, private_directory, retain_stopped_capture, sha256
from .review_github import OriginalHTTPReply, ReviewGitHub, decode_object
from .source_snapshot import SourceSnapshots, SnapshotUnavailable
from src.git_manager import managed_composition as composition
from src.git_manager.review_publication import (ReviewProcesses, ReviewGit, auth_config,
                                                git_environment, publication_status, push_arguments,
                                                remember_failure, source_runner)


HEADER_BYTES = 16384
METADATA_BYTES = 65536
FRAME_BYTES = 16384
MIN_CLEANUP_CALLS = 6
IDENTITY = re.compile(r"[0-9a-f]{64}")


@dataclass(frozen=True)
class SourceHandle:
    snapshot: Path
    entries: tuple
    object_bytes: int
    objects: int


@dataclass
class GuestHandle:
    incarnation: str
    volume_name: str
    labels: dict
    source: PreparedReviewSource
    volume_identity: bytes | None = None
    container_id: str | None = None
    create_entered: bool = False
    start_entered: bool = False
    started: bool = False
    stopped: bool = False
    stop_attempted: bool = False
    stop_acknowledged: bool = False
    confirmation_attempted: bool = False
    archive_attempted: bool = False
    artifacts_attempted: bool = False
    container_removed: bool = False
    volume_removed: bool = False


@dataclass(frozen=True)
class CandidateHandle:
    repository: Path


class WireReader:
    """One original HTTP response with a shared header/framing refusal ceiling."""

    def __init__(self, connection, operation, effect):
        self.connection, self.operation, self.effect = connection, operation, effect
        self.metadata = 0

    def read(self, count):
        remaining = self.effect.deadline - self.operation.now()
        if remaining <= 0:
            raise ReviewError("deadline_exhausted", unknown=True)
        self.connection.settimeout(remaining)
        raw = self.connection.recv(count)
        if self.operation.now() >= self.effect.deadline:
            raise ReviewError("deadline_exhausted", unknown=True)
        return raw

    def line(self, maximum=4096):
        value = bytearray()
        while True:
            if len(value) >= maximum or self.metadata >= HEADER_BYTES:
                raise ReviewError("protocol_refused", unknown=True)
            part = self.read(1)
            if not part:
                raise ReviewError("protocol_refused", unknown=True)
            self.metadata += 1
            value.extend(part)
            if value.endswith(b"\r\n"):
                return bytes(value[:-2])

    def exact(self, size):
        result = bytearray()
        while len(result) < size:
            part = self.read(min(size - len(result), 65536))
            if not part:
                raise ReviewError("protocol_refused", unknown=True)
            result.extend(part)
        return bytes(result)

    def response(self, maximum):
        status = self.line()
        match = re.fullmatch(rb"HTTP/1\.[01] ([1-5][0-9]{2}) [\x20-\x7e]*", status)
        if not match:
            raise ReviewError("protocol_refused", unknown=True)
        code = int(match[1])
        headers = {}
        while True:
            line = self.line()
            if not line:
                break
            key, separator, value = line.partition(b":")
            if (not separator or not re.fullmatch(rb"[A-Za-z0-9!#$%&'*+.^_`|~-]+", key)
                    or any(byte < 32 and byte != 9 or byte == 127 for byte in value)):
                raise ReviewError("protocol_refused", unknown=True)
            name = key.decode("ascii").lower()
            headers.setdefault(name, []).append(value.strip().decode("ascii"))
        if headers.get("content-encoding", ["identity"]) not in (["identity"], [""]):
            raise ReviewError("protocol_refused", unknown=True)
        lengths, encodings = headers.get("content-length", []), headers.get("transfer-encoding", [])
        if len(lengths) > 1 or len(encodings) > 1 or lengths and encodings:
            raise ReviewError("protocol_refused", unknown=True)
        result = bytearray()
        def append(part):
            self.operation.consume(self.effect, response_bytes=len(part))
            if len(result) + len(part) > maximum:
                raise ReviewError("capacity_exhausted", unknown=True)
            result.extend(part)
        if code in {204, 304}:
            if lengths not in ([], ["0"]) or encodings:
                raise ReviewError("protocol_refused", unknown=True)
        elif lengths:
            if not re.fullmatch(r"0|[1-9][0-9]{0,15}", lengths[0]):
                raise ReviewError("protocol_refused", unknown=True)
            size = int(lengths[0])
            if size > maximum:
                raise ReviewError("capacity_exhausted", unknown=True)
            while len(result) < size:
                append(self.exact(min(65536, size - len(result))))
        elif encodings:
            if encodings != ["chunked"]:
                raise ReviewError("protocol_refused", unknown=True)
            while True:
                line = self.line(128)
                if not re.fullmatch(rb"[0-9A-Fa-f]{1,16}", line):
                    raise ReviewError("protocol_refused", unknown=True)
                size = int(line, 16)
                if size == 0:
                    if self.line(128):
                        raise ReviewError("protocol_refused", unknown=True)
                    break
                if size > maximum - len(result):
                    raise ReviewError("capacity_exhausted", unknown=True)
                left = size
                while left:
                    part = self.exact(min(left, 65536))
                    append(part)
                    left -= len(part)
                if self.line(2):
                    raise ReviewError("protocol_refused", unknown=True)
        else:
            while True:
                part = self.read(min(65536, maximum - len(result) + 1))
                if not part:
                    break
                append(part)
        return code, bytes(result)


def _request_wire(method, path, payload, headers):
    if method not in {"GET", "POST", "PUT", "DELETE"} or not re.fullmatch(r"/[A-Za-z0-9/_.?=&%:-]+", path):
        raise ReviewError("protocol_refused")
    raw = canonical(payload) if payload is not None and type(payload) is not bytes else payload or b""
    values = {"Host": "localhost", "Connection": "close", "Content-Type": "application/json",
              "Content-Length": str(len(raw)), **headers}
    lines = []
    for name, value in values.items():
        if (type(name) is not str or type(value) is not str
                or not re.fullmatch(r"[A-Za-z0-9-]+", name)
                or any(ord(char) < 32 or ord(char) > 126 for char in value)):
            raise ReviewError("protocol_refused")
        lines.append(name + ": " + value + "\r\n")
    prefix = (method + " " + path + " HTTP/1.1\r\n" + "".join(lines) + "\r\n").encode("ascii")
    if len(prefix) > HEADER_BYTES:
        raise ReviewError("capacity_exhausted")
    return prefix, raw


def demultiplex(raw, maximum):
    result = bytearray()
    offset = framing = 0
    while offset < len(raw):
        if len(raw) - offset < 8:
            raise ReviewError("protocol_refused", unknown=True)
        header = raw[offset:offset + 8]
        size = int.from_bytes(header[4:], "big")
        offset += 8
        framing += 8
        if (header[0] not in {1, 2} or header[1:4] != b"\0\0\0" or framing > FRAME_BYTES
                or size > len(raw) - offset or size > maximum - len(result)):
            raise ReviewError("protocol_refused", unknown=True)
        result.extend(raw[offset:offset + size])
        offset += size
    return bytes(result)


_EXEC_SCRIPT = r'''import os,stat,subprocess,sys
limit,log_limit=int(sys.argv[2]),int(sys.argv[3])
fd=os.open('/workspace/run/output.log',os.O_WRONLY|os.O_APPEND|os.O_NOFOLLOW)
info=os.fstat(fd)
if not stat.S_ISREG(info.st_mode) or info.st_nlink!=1 or info.st_size>log_limit:
    os.close(fd);sys.exit(125)
p=subprocess.Popen(['/bin/sh','-c',sys.argv[1]],stdout=subprocess.PIPE,stderr=subprocess.STDOUT,start_new_session=True)
total=0;logged=info.st_size
try:
    while True:
        part=p.stdout.read1(min(65536,limit-total+1))
        if not part:break
        total+=len(part)
        sys.stdout.buffer.write(part);sys.stdout.buffer.flush()
        if total>limit or logged+len(part)>log_limit:
            os.killpg(p.pid,9);p.wait();sys.exit(125)
        offset=0
        while offset<len(part):offset+=os.write(fd,part[offset:])
        logged+=len(part)
    sys.exit(p.wait())
finally:
    os.close(fd)
'''

_PATCH_SCRIPT = r'''import os,subprocess,sys
base,limit=sys.argv[1],int(sys.argv[2])
git=['git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false','-c','diff.renames=false']
subprocess.run(git+['add','--all'],check=True)
fd=os.open('/workspace/run/change.patch',os.O_WRONLY|os.O_CREAT|os.O_EXCL|os.O_NOFOLLOW,0o600)
p=subprocess.Popen(git+['diff','--cached','--binary',base],stdout=subprocess.PIPE,start_new_session=True)
total=0
try:
    while True:
        part=p.stdout.read1(min(65536,limit-total+1))
        if not part:break
        total+=len(part)
        if total>limit:
            os.killpg(p.pid,9);p.wait();sys.exit(125)
        offset=0
        while offset<len(part):offset+=os.write(fd,part[offset:])
    os.fsync(fd);sys.exit(p.wait())
finally:
    os.close(fd)
'''


class ReviewNativeBackend:
    """One claim and one exact set of private source/resource handles."""

    def __init__(self, claim: ReviewClaim):
        if type(claim) is not ReviewClaim:
            raise ReviewError("protocol_refused")
        self.claim = claim
        self.operation = None
        self.processes = None
        self.github = ReviewGitHub(claim, self._forge_request)
        self.root = None
        self.source = self.guest = self.capture = self.candidate = None
        self.original_guest = None
        self.original_checked = False
        self.publication_checked = False
        self.source_attempted = self.guest_attempted = self.compose_attempted = self.publish_attempted = False
        self.retiring = False
        self.connections = []
        self.auth_path = None
        self.auth_removed = False
        self.publication_result = None
        self.endpoint_identity = None
        self.peer_identity = None

    @property
    def limits(self):
        return self.claim.profile.limits

    def _bind(self, operation, *, cleanup=False):
        if operation.claim is not self.claim or self.operation not in (None, operation):
            raise ReviewError("protocol_refused")
        if self.operation is None:
            self.operation = operation
            self.processes = ReviewProcesses(operation)
        operation.check(cleanup=cleanup)

    def _failed(self, operation, error, code, *, unknown=False):
        fixed = error if isinstance(error, ReviewError) else ReviewError(code, unknown=unknown)
        first = remember_failure(operation, fixed)
        # Returned/locally closed transport is not a validated operation result.
        # Preserve uncertainty if a guard or decoder interrupts that original
        # join, including revocation after return but before validation.
        for original in self.connections:
            if original["request_entered"] and not original["validated"]:
                try:
                    operation.observe(original["effect"], "outcome_unknown", code=first.code)
                except ReviewError:
                    pass
        return first

    def _directory(self, operation):
        if self.root is None:
            operation.check()
            parent = private_directory(Path(self.claim.profile.document["source"]["state_root"]))
            name = "review_" + sha256((self.claim.operation_id + "\0" + self.claim.owner_epoch).encode())
            self.root = private_directory(parent / name, create=True)
            durable_file(self.root / "owner.json", canonical({"schema": "standalone-review-native-v1",
                         "operation_id": self.claim.operation_id, "owner_epoch": self.claim.owner_epoch,
                         "base": self.claim.original["review"]["head_sha"]}))
        return self.root

    def _http(self, operation, kind, method, path, payload, headers, *, maximum, cleanup=False, deadline=None):
        prefix, body = _request_wire(method, path, payload, headers)
        effect = operation.reserve(kind, request_bytes=len(prefix) + len(body), response_bytes=maximum,
                                   cleanup=cleanup, **({"deadline": deadline} if deadline is not None else {}))
        owned = {"socket": None, "closed": False, "effect": effect, "request_entered": False, "validated": False}
        self.connections.append(owned)
        def before_send(connection):
            # Socket/DNS/TLS preparation and a prior write can block. Their
            # completion never carries the original grant across that wait.
            operation.check(cleanup=cleanup)
            if not cleanup:
                try:
                    self.claim.credentials.validate_epoch()
                except BaseException:
                    operation.fail("authority_changed")
            remaining = effect.deadline - operation.now()
            if remaining <= 0:
                raise ReviewError("deadline_exhausted", unknown=True)
            connection.settimeout(remaining)
        def exchange():
            if kind == "guest_api":
                endpoint = self.claim.profile.document["guest"]["docker_endpoint"]
                connection = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
                owned["socket"] = connection
                remaining = effect.deadline - operation.now()
                if remaining <= 0:
                    raise ReviewError("deadline_exhausted", unknown=True)
                connection.settimeout(remaining)
                connection.connect(endpoint[7:])
                if hasattr(socket, "SO_PEERCRED"):
                    peer = struct.unpack("3i", connection.getsockopt(socket.SOL_SOCKET, socket.SO_PEERCRED, 12))
                    if self.peer_identity is not None and peer != self.peer_identity:
                        raise ReviewError("guest_refused")
                    self.peer_identity = peer
            else:
                addresses = socket.getaddrinfo("api.github.com", 443, type=socket.SOCK_STREAM)
                remaining = effect.deadline - operation.now()
                if not addresses or remaining <= 0:
                    raise ReviewError("deadline_exhausted", unknown=True)
                family, kind_, protocol, _, address = addresses[0]
                connection = socket.socket(family, kind_, protocol)
                owned["socket"] = connection
                remaining = effect.deadline - operation.now()
                if remaining <= 0:
                    raise ReviewError("deadline_exhausted", unknown=True)
                connection.settimeout(remaining)
                connection.connect(address)
                context = ssl.create_default_context()
                remaining = effect.deadline - operation.now()
                if remaining <= 0:
                    raise ReviewError("deadline_exhausted", unknown=True)
                connection.settimeout(remaining)
                connection = context.wrap_socket(connection, server_hostname="api.github.com")
                owned["socket"] = connection
            before_send(connection)
            owned["request_entered"] = True
            guest = self.original_guest
            if kind == "guest_api" and guest is not None:
                if path.startswith("/v1.45/containers/create?"):
                    guest.create_entered = True
                elif path == "/v1.45/containers/" + str(guest.container_id) + "/start":
                    guest.start_entered = True
            connection.sendall(prefix)
            if body:
                before_send(connection)
                connection.sendall(body)
            return WireReader(connection, operation, effect).response(maximum)
        def guarded_exchange():
            try:
                return exchange()
            except BaseException as error:
                code = {"guest_api": "guest_outcome_unknown", "forge_get": "source_unavailable", "forge_token": "credential_unavailable"}[kind]
                # The facade owns custody, while this producer owns the first
                # concrete protocol/deadline refusal observed on this stack.
                raise self._failed(operation, error, code, unknown=True) from None
        try:
            result = operation.invoke(effect, guarded_exchange)
            operation.check(cleanup=cleanup)
            return OriginalHTTPReply(*result, effect, cleanup, owned)
        except BaseException as error:
            code = {"guest_api": "guest_outcome_unknown", "forge_get": "source_unavailable", "forge_token": "credential_unavailable"}[kind]
            fixed = self._failed(operation, error, code, unknown=True)
            try:
                operation.observe(effect, "outcome_unknown", code=fixed.code)
            except ReviewError:
                pass
            raise fixed from None
        finally:
            connection = owned["socket"]
            try:
                if connection is not None:
                    connection.close()
                owned["closed"] = True
            except BaseException as error:
                self._failed(operation, error, "cleanup_unconfirmed", unknown=True)
            try:
                if owned["request_entered"]:
                    operation.observe(effect, "entered", data={"route_sha256": sha256(path.encode()),
                                                               "payload_sha256": sha256(body)})
                    guest = self.original_guest
                    if kind == "guest_api" and guest is not None:
                        operation.note("guest", {"create_entered": guest.create_entered,
                                                 "start_entered": guest.start_entered})
                if owned["closed"]:
                    operation.observe(effect, "closed", data={"local_closed": True})
            except ReviewError:
                pass

    def _forge_request(self, operation, kind, method, path, payload, headers):
        return self._http(operation, kind, method, path, payload, {"Host": "api.github.com", **headers},
                          maximum=self.limits["forge_response_bytes"])

    def _docker(self, operation, method, path, payload=None, *, cleanup=False, maximum=None, deadline=None, archive=False):
        profile = self.claim.profile.document["guest"]
        endpoint = profile["docker_endpoint"]
        if (profile["docker_api_version"] != "1.45" or type(endpoint) is not str
                or not endpoint.startswith("unix:///") or len(endpoint[7:].encode()) > 4096):
            raise ReviewError("guest_refused")
        selected = Path(endpoint[7:])
        info = selected.lstat()
        if str(selected) != endpoint[7:] or selected.resolve() != selected or not stat.S_ISSOCK(info.st_mode):
            raise ReviewError("guest_refused")
        identity = (info.st_dev, info.st_ino, info.st_uid, info.st_gid)
        if self.endpoint_identity is not None and identity != self.endpoint_identity:
            raise ReviewError("guest_refused")
        self.endpoint_identity = identity
        maximum = min(maximum or METADATA_BYTES, self.limits["archive_bytes"])
        headers = {"Content-Type": "application/x-tar"} if archive else {}
        return self._http(operation, "guest_api", method, "/v1.45" + path, payload, headers,
                          maximum=maximum, cleanup=cleanup, deadline=deadline)

    def check_original(self, operation, *, phase):
        try:
            self._bind(operation)
            if phase == "publication" and (self.capture is None or self.candidate is None):
                raise ReviewError("protocol_refused")
            self.github.check(operation, phase)
            operation.check()
            if phase == "initial":
                self.original_checked = True
            else:
                self.publication_checked = True
        except BaseException as error:
            raise self._failed(operation, error, "source_refused") from None

    def _composition_limits(self):
        values = self.limits
        return composition.CompositionLimits(artifact_bytes=values["patch_bytes"], total_artifact_bytes=values["patch_bytes"],
                    source_bytes=values["source_bytes"], blob_bytes=values["blob_bytes"], max_files=values["files"],
                    max_children=1, max_path_bytes=values["path_bytes"], max_patch_records=values["patch_records"],
                    max_objects=values["object_count"], object_bytes=values["object_bytes"],
                    git_output_bytes=values["git_output_bytes"], seconds=min(120, values["total_ms"] / 1000))

    def prepare_source(self, operation):
        try:
            self._bind(operation)
            if not self.original_checked or self.source_attempted:
                raise ReviewError("protocol_refused")
            self.source_attempted = True
            directory = self._directory(operation)
            source = Path(self.claim.profile.document["source"]["repository_path"])
            private_directory(source)
            base = self.claim.original["review"]["head_sha"]
            snapshot = SourceSnapshots(directory / "sources", git_runner=source_runner(self.processes), retain_failed=True).prepare(
                str(source), base, self.limits["source_bytes"], timeout=max(.000001, operation.work_deadline - operation.now()),
                deadline=operation.work_deadline, max_objects=self.limits["source_objects"])
            usage = decode_object((snapshot.parent / "manifest.json").read_bytes())
            git = ReviewGit(self.processes, snapshot, self._composition_limits(), deadline=operation.work_deadline)
            tree = git.run("rev-parse", base + "^{tree}").decode("ascii").strip()
            if not composition.SHA.fullmatch(tree):
                raise ReviewError("source_refused")
            entries = composition._entries(git, base)
            context = bytearray()
            for entry in entries:
                raw = git.run("cat-file", "blob", entry["sha"], limit=self.limits["blob_bytes"])
                operation.assert_safe(raw)
                if composition.object_hash("blob", raw) != entry["sha"]:
                    raise ReviewError("source_refused")
                try:
                    text = raw.decode("utf-8", errors="strict")
                except UnicodeError:
                    text = "[binary source omitted from text context]\n"
                value = ("\n### " + entry["path"] + "\n" + text).encode()
                if len(context) + len(value) > self.limits["context_bytes"]:
                    raise ReviewError("capacity_exhausted")
                context.extend(value)
            operation.assert_safe(bytes(context))
            operation.check()
            self.source = PreparedReviewSource(SourceHandle(snapshot, tuple(entries), usage["object_bytes"], usage["objects"]),
                                               base, tree, usage["pack_sha256"], usage["object_bytes"], context.decode("utf-8"))
            operation.note("source", {"base_sha": base, "tree_sha": tree, "snapshot_sha256": usage["pack_sha256"],
                                      "source_bytes": usage["object_bytes"], "source_objects": usage["objects"]})
            return self.source
        except BaseException as error:
            raise self._failed(operation, error, "source_unavailable") from None

    def _environment(self):
        return {"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8",
                "HOME": "/workspace/run/home", "TMPDIR": "/workspace/run/tmp",
                "PYTHONDONTWRITEBYTECODE": "1", "PYTHONUNBUFFERED": "1",
                "GIT_CONFIG_NOSYSTEM": "1", "GIT_CONFIG_GLOBAL": "/dev/null",
                "GIT_CONFIG_SYSTEM": "/dev/null", "GIT_TERMINAL_PROMPT": "0",
                "GIT_NO_REPLACE_OBJECTS": "1"}

    def _volume_identity(self, value, guest):
        if (type(value) is not dict or value.get("Name") != guest.volume_name
                or value.get("Driver") != "local" or value.get("Scope") != "local"
                or value.get("Options") not in (None, {}) or value.get("Labels") != guest.labels
                or type(value.get("CreatedAt")) is not str or not 1 <= len(value["CreatedAt"]) <= 64):
            raise ReviewError("guest_refused")
        return canonical({name: value[name] for name in ("Name", "Driver", "Scope", "Labels", "CreatedAt")})

    def _container_identity(self, value, guest, *, stopped=False):
        selected = self.claim.profile.document["guest"]
        try:
            config, host, state = value["Config"], value["HostConfig"], value["State"]
            if (value["Id"] != guest.container_id or value["Image"] != selected["image"]
                    or config["Labels"] != guest.labels or config["User"] != f'{selected["uid"]}:{selected["gid"]}'
                    or config["WorkingDir"] != "/workspace/run"
                    or config["Entrypoint"] != ["/bin/sh", "-c", "while :; do sleep 3600; done"]
                    or config.get("Healthcheck", {}).get("Test") != ["NONE"]
                    or config["Cmd"] not in ([], None)
                    or sorted(config["Env"]) != sorted(k + "=" + v for k, v in self._environment().items())
                    or host["NetworkMode"] != "none" or host["ReadonlyRootfs"] is not True
                    or host["Privileged"] is not False or host["CapDrop"] != ["ALL"]
                    or host.get("CapAdd") not in (None, [])
                    or host["SecurityOpt"] not in (["no-new-privileges:true"], ["no-new-privileges"])
                    or host["Memory"] != selected["memory_bytes"] or host["MemorySwap"] != selected["memory_bytes"]
                    or host["CpuPeriod"] != 100000 or host["CpuQuota"] != selected["cpu_quota_us"]
                    or host["PidsLimit"] != selected["pids_limit"] or host["AutoRemove"] is not False
                    or host["RestartPolicy"]["Name"] != "no" or host["LogConfig"]["Type"] != "none"
                    or host.get("PublishAllPorts") is not False):
                raise ReviewError("guest_refused")
            mounts = value["Mounts"]
            if type(mounts) is not list or len(mounts) != 2:
                raise ReviewError("guest_refused")
            source = next(row for row in mounts if row["Destination"] == "/source")
            workspace = next(row for row in mounts if row["Destination"] == "/workspace")
            if (source["Type"] != "bind" or source["Source"] != str(guest.source.handle.snapshot)
                    or source["RW"] is not False or source["Propagation"] != "rprivate"
                    or workspace["Type"] != "volume" or workspace["Name"] != guest.volume_name
                    or workspace["Driver"] != "local" or workspace["RW"] is not True):
                raise ReviewError("guest_refused")
            if stopped and (state["Running"] is not False or state.get("Restarting") is not False
                            or state.get("Paused") is not False or state["Status"] not in {"created", "exited", "dead"}):
                raise ReviewError("guest_outcome_unknown", unknown=True)
        except (KeyError, TypeError, StopIteration):
            raise ReviewError("guest_refused") from None

    def create_guest(self, operation, source):
        try:
            self._bind(operation)
            if source is not self.source or source is None or self.guest_attempted:
                raise ReviewError("protocol_refused")
            self.guest_attempted = True
            if self.limits["guest_api_cleanup_calls"] < MIN_CLEANUP_CALLS:
                raise ReviewError("capacity_exhausted")
            selected = self.claim.profile.document["guest"]
            reply = self._docker(operation, "GET", "/images/" + selected["image"] + "/json")
            status, raw = reply
            image = decode_object(raw)
            if status != 200 or image.get("Id") != selected["image"] or image.get("Config", {}).get("Volumes") not in (None, {}):
                raise ReviewError("guest_refused")
            image_env = image.get("Config", {}).get("Env") or []
            if (type(image_env) is not list or any(type(value) is not str or "=" not in value
                    or value.split("=", 1)[0] not in self._environment() for value in image_env)):
                raise ReviewError("guest_refused")
            reply.acknowledge(operation)
            incarnation = "review_" + sha256((self.claim.operation_id + "\0" + self.claim.owner_epoch).encode())
            labels = {"openjules.managed": "0", "openjules.review.incarnation": incarnation,
                      "openjules.review.operation": sha256(self.claim.operation_id.encode()),
                      "openjules.review.owner": sha256(self.claim.owner_epoch.encode())}
            owned = GuestHandle(incarnation, "openjules-review-" + incarnation[7:47], labels, source)
            self.original_guest = owned
            operation.note("guest", {"incarnation": incarnation, "volume_name": owned.volume_name,
                                     "create_entered": False, "create_acknowledged": False,
                                     "start_entered": False, "start_acknowledged": False, "stopped": False,
                                     "local_closed": True})
            reply = self._docker(operation, "POST", "/volumes/create",
                                       {"Name": owned.volume_name, "Driver": "local", "DriverOpts": {}, "Labels": labels})
            status, raw = reply
            if status != 201:
                raise ReviewError("guest_refused")
            owned.volume_identity = self._volume_identity(decode_object(raw), owned)
            reply.acknowledge(operation)
            env = [key + "=" + value for key, value in self._environment().items()]
            payload = {"Image": selected["image"], "User": f'{selected["uid"]}:{selected["gid"]}',
                       "Entrypoint": ["/bin/sh", "-c", "while :; do sleep 3600; done"], "Cmd": [],
                       "Healthcheck": {"Test": ["NONE"]},
                       "WorkingDir": "/workspace/run", "Env": env, "Labels": labels,
                       "Tty": False, "OpenStdin": False, "AttachStdin": False,
                       "HostConfig": {"NetworkMode": "none", "ReadonlyRootfs": True, "Privileged": False,
                           "CapDrop": ["ALL"], "CapAdd": [], "SecurityOpt": ["no-new-privileges:true"],
                           "Memory": selected["memory_bytes"], "MemorySwap": selected["memory_bytes"],
                           "CpuPeriod": 100000, "CpuQuota": selected["cpu_quota_us"], "PidsLimit": selected["pids_limit"],
                           "AutoRemove": False, "PublishAllPorts": False, "RestartPolicy": {"Name": "no"},
                           "LogConfig": {"Type": "none", "Config": {}},
                           "Mounts": [{"Type": "bind", "Source": str(source.handle.snapshot), "Target": "/source",
                                       "ReadOnly": True, "BindOptions": {"Propagation": "rprivate"}},
                                      {"Type": "volume", "Source": owned.volume_name, "Target": "/workspace",
                                       "ReadOnly": False, "VolumeOptions": {"NoCopy": True}}]}}
            reply = self._docker(operation, "POST", "/containers/create?name=" + owned.volume_name, payload)
            status, raw = reply
            value = decode_object(raw)
            container_id = value.get("Id")
            if status != 201 or type(container_id) is not str or not IDENTITY.fullmatch(container_id):
                raise ReviewError("guest_outcome_unknown", unknown=True)
            owned.container_id = container_id
            reply.acknowledge(operation)
            operation.note("guest", {"container_id": container_id, "create_acknowledged": True})
            reply = self._docker(operation, "GET", "/containers/" + container_id + "/json")
            status, raw = reply
            if status != 200:
                raise ReviewError("guest_outcome_unknown", unknown=True)
            self._container_identity(decode_object(raw), owned, stopped=True)
            reply.acknowledge(operation)
            buffer = io.BytesIO()
            with tarfile.open(fileobj=buffer, mode="w", format=tarfile.USTAR_FORMAT) as archive:
                for name in ("run", "run/home", "run/tmp", "run/output.log"):
                    member = tarfile.TarInfo(name)
                    member.uid, member.gid = selected["uid"], selected["gid"]
                    member.mode = 0o600 if name.endswith(".log") else 0o700
                    member.type = tarfile.REGTYPE if name.endswith(".log") else tarfile.DIRTYPE
                    archive.addfile(member, io.BytesIO(b"") if member.isfile() else None)
            reply = self._docker(operation, "PUT", "/containers/" + container_id + "/archive?path=%2Fworkspace&noOverwriteDirNonDir=1",
                                     buffer.getvalue(), archive=True)
            status, _ = reply
            if status != 200:
                raise ReviewError("guest_refused")
            reply.acknowledge(operation)
            reply = self._docker(operation, "POST", "/containers/" + container_id + "/start", {})
            status, _ = reply
            if status != 204:
                raise ReviewError("guest_outcome_unknown", unknown=True)
            owned.started = True
            reply.acknowledge(operation)
            operation.note("guest", {"start_acknowledged": True})
            self.guest = OriginalReviewGuest(owned, incarnation)
            command = ("git -c core.hooksPath=/dev/null -c core.fsmonitor=false -c protocol.file.allow=always "
                       "clone --no-checkout --no-hardlinks --no-local "
                       "--upload-pack='git -c safe.directory=/source upload-pack' /source /workspace/run/repo && "
                       "git -C /workspace/run/repo remote remove origin && "
                       "git -C /workspace/run/repo -c core.hooksPath=/dev/null checkout --detach " + source.base_sha)
            result = self._execute(operation, self.guest, command, workdir="/workspace/run")
            if result.exit_code != 0:
                raise ReviewError("guest_refused")
            return self.guest
        except BaseException as error:
            raise self._failed(operation, error, "guest_refused") from None

    def execute(self, operation, guest, command):
        return self._execute(operation, guest, command)

    def _execute(self, operation, guest, command, *, workdir="/workspace/run/repo"):
        effect = None
        try:
            self._bind(operation)
            if (guest is not self.guest or guest is None or guest.handle is not self.original_guest
                    or not guest.handle.started or guest.handle.stop_attempted or self.retiring
                    or type(command) is not str or not command or "\0" in command
                    or len(command.encode()) > self.limits["exec_input_bytes"]):
                raise ReviewError("guest_refused")
            operation.assert_safe(command.encode())
            effect = operation.reserve("exec", request_bytes=len(command.encode()), response_bytes=self.limits["exec_output_bytes"])
            selected = self.claim.profile.document["guest"]
            payload = {"AttachStdout": True, "AttachStderr": True, "AttachStdin": False, "Tty": False,
                       "Privileged": False, "User": f'{selected["uid"]}:{selected["gid"]}', "WorkingDir": workdir,
                       "Env": [key + "=" + value for key, value in self._environment().items()],
                       "Cmd": ["python3", "-I", "-S", "-c", _EXEC_SCRIPT, command,
                               str(self.limits["exec_output_bytes"]), str(self.limits["log_bytes"])]}
            def execute_original():
                reply = self._docker(operation, "POST", "/containers/" + guest.handle.container_id + "/exec", payload,
                                           deadline=effect.deadline)
                status, raw = reply
                value = decode_object(raw)
                exec_id = value.get("Id")
                if status != 201 or type(exec_id) is not str or not IDENTITY.fullmatch(exec_id):
                    raise ReviewError("guest_outcome_unknown", unknown=True)
                reply.acknowledge(operation)
                reply = self._docker(operation, "POST", "/exec/" + exec_id + "/start", {"Detach": False, "Tty": False},
                                           maximum=self.limits["exec_output_bytes"] + FRAME_BYTES, deadline=effect.deadline)
                status, raw = reply
                if status != 200:
                    raise ReviewError("guest_outcome_unknown", unknown=True)
                output = demultiplex(raw, self.limits["exec_output_bytes"])
                operation.consume(effect, response_bytes=len(output))
                operation.assert_safe(output)
                reply.acknowledge(operation)
                reply = self._docker(operation, "GET", "/exec/" + exec_id + "/json", deadline=effect.deadline)
                status, raw = reply
                value = decode_object(raw)
                if (status != 200 or value.get("ID") != exec_id or value.get("ContainerID") != guest.handle.container_id
                        or value.get("Running") is not False or type(value.get("ExitCode")) is not int
                        or not 0 <= value["ExitCode"] <= 255):
                    raise ReviewError("guest_outcome_unknown", unknown=True)
                reply.acknowledge(operation)
                if operation.now() >= effect.deadline:
                    raise ReviewError("deadline_exhausted", unknown=True)
                operation.observe(effect, "acknowledged", data={"exit_code": value["ExitCode"]})
                operation.observe(effect, "closed", data={"local_closed": True})
                if value["ExitCode"] in {125, 126, 127}:
                    raise ReviewError("guest_refused")
                return ReviewExecObservation("exec_" + str(effect.id), value["ExitCode"], output, True)
            def guarded_execute():
                try:
                    return execute_original()
                except BaseException as error:
                    raise self._failed(operation, error, "guest_outcome_unknown", unknown=True) from None
            result = operation.invoke(effect, guarded_execute)
            operation.check()
            if operation.now() >= effect.deadline:
                raise ReviewError("deadline_exhausted", unknown=True)
            return result
        except BaseException as error:
            fixed = self._failed(operation, error, "guest_outcome_unknown", unknown=effect is not None)
            if effect is not None:
                try:
                    operation.observe(effect, "outcome_unknown" if fixed.unknown else "refused", code=fixed.code)
                except ReviewError:
                    pass
            raise fixed from None

    def _capture_original(self, operation, owned):
        if (owned is not self.original_guest or owned.container_id is None
                or owned.archive_attempted or owned.confirmation_attempted):
            raise ReviewError("capture_outcome_unknown", unknown=True)
        stop_error = None
        if not owned.stop_attempted:
            owned.stop_attempted = True
            try:
                reply = self._docker(operation, "POST", "/containers/" + owned.container_id + "/stop?t=0", {}, cleanup=True)
                status, _ = reply
                if status not in {204, 304}:
                    raise ReviewError("guest_outcome_unknown", unknown=True)
                owned.stop_acknowledged = True
                reply.acknowledge(operation)
            except ReviewError as error:
                stop_error = error
        owned.confirmation_attempted = True
        reply = self._docker(operation, "GET", "/containers/" + owned.container_id + "/json", cleanup=True)
        status, raw = reply
        if status != 200:
            raise ReviewError("guest_outcome_unknown", unknown=True)
        self._container_identity(decode_object(raw), owned, stopped=True)
        owned.stopped = True
        reply.acknowledge(operation)
        operation.note("guest", {"stopped": True, "local_closed": all(item["closed"] for item in self.connections)})
        # A later stopped observation does not repair an ambiguous original start
        # or stop exchange into an execution/capture acknowledgement.
        if stop_error is not None or not owned.stop_acknowledged or owned.start_entered and not owned.started:
            raise stop_error or ReviewError("capture_outcome_unknown", unknown=True)
        if not all(item["closed"] for item in self.connections):
            raise ReviewError("capture_outcome_unknown", unknown=True)
        owned.archive_attempted = True
        reply = self._docker(operation, "GET", "/containers/" + owned.container_id + "/archive?path=%2Fworkspace",
                                   cleanup=True, maximum=self.limits["archive_bytes"])
        status, raw = reply
        if status != 200:
            raise ReviewError("capture_outcome_unknown", unknown=True)
        operation.note("capture", {"container_id": owned.container_id, "archive_sha256": sha256(raw),
                                   "archive_bytes": len(raw), "termination_confirmed": True})
        retained = retain_stopped_capture(self.root / "capture", owned.incarnation, owned.container_id, raw, self.limits,
                                         check=lambda: operation.check(cleanup=True), assert_safe=operation.assert_safe)
        self.capture = retained
        reply.acknowledge(operation)
        operation.note("capture", {"retained_id": retained.retained_id, "patch_sha256": retained.patch_sha256,
                                   "patch_bytes": len(retained.patch), "log_sha256": retained.log_sha256,
                                   "log_bytes": len(retained.log), "manifest_sha256": retained.manifest_sha256,
                                   "durable": True, "termination_confirmed": True})
        return retained

    def stop_and_capture(self, operation, guest):
        try:
            self._bind(operation)
            if guest is not self.guest or guest is None or guest.handle is not self.original_guest or self.capture is not None:
                raise ReviewError("protocol_refused")
            owned = guest.handle
            if owned.artifacts_attempted or owned.stop_attempted:
                raise ReviewError("protocol_refused")
            owned.artifacts_attempted = True
            command = ("python3 -I -S -c " + shlex.quote(_PATCH_SCRIPT) + " " + guest.handle.source.base_sha
                       + " " + str(self.limits["patch_bytes"]))
            result = self._execute(operation, guest, command)
            if result.exit_code != 0:
                raise ReviewError("capture_refused")
            return self._capture_original(operation, owned)
        except BaseException as error:
            raise self._failed(operation, error, "capture_refused") from None

    def compose(self, operation, source, capture):
        try:
            self._bind(operation)
            if (source is not self.source or source is None or capture is not self.capture or capture is None
                    or self.compose_attempted or self.original_guest is None or not self.original_guest.stopped
                    or not self.original_guest.stop_acknowledged
                    or capture.handle.container_id != self.original_guest.container_id):
                raise ReviewError("protocol_refused")
            self.compose_attempted = True
            operation.assert_safe(capture.patch)
            limits = self._composition_limits()
            usage = source.handle
            if 2 * usage.objects > limits.max_objects or 2 * usage.object_bytes > limits.object_bytes:
                raise ReviewError("capacity_exhausted")
            directory = self.root / "candidate"
            if directory.exists():
                raise ReviewError("candidate_refused")
            shutil.copytree(source.handle.snapshot, directory)
            directory.chmod(0o700)
            git = ReviewGit(self.processes, directory, limits, deadline=operation.work_deadline)
            def check_objects(count=0, size=0):
                actual_count, actual_size = composition._object_usage(git)
                if (actual_count + usage.objects + count > limits.max_objects
                        or actual_size + usage.object_bytes + size > limits.object_bytes):
                    raise ReviewError("capacity_exhausted")
            git.run("read-tree", source.base_sha, limit=1024)
            patch = capture.patch.decode("utf-8", errors="strict")
            paths = composition._patch(git, patch, apply=False)
            if paths:
                check_objects(*composition._patch_reservation(git, patch, paths))
                composition._patch(git, patch)
            check_objects(*composition._tree_reservation(git))
            tree = git.run("write-tree", limit=128).decode("ascii").strip()
            if not composition.SHA.fullmatch(tree):
                raise ReviewError("candidate_refused")
            composition._entries(git, tree)
            check_objects()
            if tree == source.tree_sha:
                self.candidate = ReviewCandidate(CandidateHandle(directory), source.base_sha, tree, None)
                operation.note("candidate", {"parent_sha": source.base_sha, "tree_sha": tree, "commit_sha": None, "no_change": True})
                return self.candidate
            author = self.claim.profile.document["commit_author"]
            if any(type(author[key]) is not str or not 1 <= len(author[key].encode("utf-8")) <= maximum
                   or any(ord(char) < 32 or ord(char) == 127 or char in "<>" for char in author[key])
                   for key, maximum in (("name", 128), ("email", 254))):
                raise ReviewError("candidate_refused")
            if author["email"].count("@") != 1 or any(char.isspace() for char in author["email"]):
                raise ReviewError("candidate_refused")
            timestamp = int(time.time())
            person = f'{author["name"]} <{author["email"]}> {timestamp} +0000'
            message = ("Apply requested review changes\n\nOpenJules-Review: " + str(self.claim.original["review"]["review_id"])
                       + "\nOpenJules-Original-Head: " + source.base_sha + "\n")
            raw = (f"tree {tree}\nparent {source.base_sha}\nauthor {person}\ncommitter {person}\n\n" + message).encode()
            operation.assert_safe(raw)
            check_objects(1, len(raw))
            commit = composition.object_hash("commit", raw)
            actual = git.run("hash-object", "-t", "commit", "-w", "--stdin", data=raw, limit=128).decode("ascii").strip()
            if actual != commit or git.run("cat-file", "commit", commit, limit=len(raw)) != raw:
                raise ReviewError("candidate_refused")
            check_objects()
            operation.check()
            self.candidate = ReviewCandidate(CandidateHandle(directory), source.base_sha, tree, commit)
            operation.note("candidate", {"parent_sha": source.base_sha, "tree_sha": tree, "commit_sha": commit, "no_change": False})
            return self.candidate
        except BaseException as error:
            raise self._failed(operation, error, "candidate_refused") from None

    def publish(self, operation, candidate):
        try:
            self._bind(operation)
            if (candidate is not self.candidate or candidate is None or candidate.commit_sha is None
                    or candidate.parent_sha != self.claim.original["review"]["head_sha"]
                    or not self.publication_checked or self.publish_attempted):
                raise ReviewError("protocol_refused")
            self.publish_attempted = True
            binding, original = self.claim.original["binding"], self.claim.original["review"]
            destination = binding["clone_url"]
            if destination not in {"https://github.com/" + binding["repository"], "https://github.com/" + binding["repository"] + ".git"}:
                raise ReviewError("publication_refused")
            username, token = self.github.credential(operation)
            self.auth_path = self.root / "git-auth.config"
            auth_config(self.auth_path, destination, username, token)
            operation.note("publication", {"original_ref": original["head_ref"], "expected_head": original["head_sha"],
                                           "candidate_sha": candidate.commit_sha, "invoked": False, "local_closed": False})
            command = push_arguments(candidate.handle.repository, self.auth_path, destination, candidate.commit_sha,
                                     original["head_ref"], original["head_sha"])
            result = self.processes.run(command, limit=self.limits["git_output_bytes"], environment=git_environment(), publication=True)
            status = publication_status(result.stdout, result.exit_code, candidate.commit_sha, original["head_ref"], original["head_sha"])
            operation.check()
            if operation.now() >= result.effect.deadline:
                raise ReviewError("deadline_exhausted", unknown=True)
            self.publication_result = ReviewPublication(status, True)
            try:
                operation.note("publication", {"status": status, "local_closed": True})
            except ReviewError:
                pass  # Preserve the actual original observation on store failure.
            if status in {"refused", "outcome_unknown"}:
                remember_failure(operation, ReviewError("publication_refused" if status == "refused" else "publication_outcome_unknown",
                                                       unknown=status == "outcome_unknown"))
            return self.publication_result
        except BaseException as error:
            invoked = self.processes is not None and any(row.get("publication") and row["entered"] for row in self.processes.originals)
            fixed = self._failed(operation, error, "publication_outcome_unknown" if invoked else "publication_refused", unknown=invoked)
            if self.publish_attempted and self.publication_result is None:
                try:
                    retained = next((row["result"] for row in self.processes.originals
                                     if row.get("publication") and row.get("result") is not None), None)
                    status = publication_status(retained.stdout, retained.exit_code, candidate.commit_sha,
                                                self.claim.original["review"]["head_ref"], candidate.parent_sha) if retained else None
                    if status == "acknowledged":
                        operation.note("publication", {"status": status, "invoked": True,
                                                       "local_closed": True, "late_acknowledged": True})
                    else:
                        operation.note("publication", {"status": status or ("outcome_unknown" if invoked else "refused")})
                except ReviewError:
                    pass
            raise fixed from None

    def retire(self, operation):
        # This method must not return while an original local child remains live,
        # even when productive authority, the store, or total time is exhausted.
        if operation.claim is not self.claim or self.operation not in (None, operation):
            raise ReviewError("protocol_refused")
        if self.operation is None:
            self.operation, self.processes = operation, ReviewProcesses(operation)
        if self.retiring:
            raise ReviewError("protocol_refused")
        self.retiring = True
        owned = self.original_guest
        try:
            operation.check(cleanup=True)
            if owned is not None and owned.container_id is not None:
                if self.capture is None and not owned.archive_attempted and not owned.confirmation_attempted:
                    self._capture_original(operation, owned)
                if self.capture is not None and owned.stopped and owned.stop_acknowledged:
                    reply = self._docker(operation, "DELETE", "/containers/" + owned.container_id + "?force=false&v=false", cleanup=True)
                    status, _ = reply
                    if status not in {204, 404}:
                        raise ReviewError("cleanup_unconfirmed", unknown=True)
                    owned.container_removed = True
                    reply.acknowledge(operation)
                    operation.note("cleanup", {"container_removed": True})
                    reply = self._docker(operation, "GET", "/volumes/" + owned.volume_name, cleanup=True)
                    status, raw = reply
                    if status == 404:
                        owned.volume_removed = True
                        reply.acknowledge(operation)
                    elif status == 200:
                        if self._volume_identity(decode_object(raw), owned) != owned.volume_identity:
                            raise ReviewError("cleanup_unconfirmed", unknown=True)
                        reply.acknowledge(operation)
                        reply = self._docker(operation, "DELETE", "/volumes/" + owned.volume_name + "?force=false", cleanup=True)
                        status, _ = reply
                        if status not in {204, 404}:
                            raise ReviewError("cleanup_unconfirmed", unknown=True)
                        owned.volume_removed = True
                        reply.acknowledge(operation)
                    else:
                        raise ReviewError("cleanup_unconfirmed", unknown=True)
                    operation.note("cleanup", {"volume_removed": owned.volume_removed})
        except BaseException as error:
            self._failed(operation, error, "cleanup_unconfirmed", unknown=True)
        finally:
            try:
                self.processes.retire()
            finally:
                # Direct sockets have no detached SDK futures. Original exchange
                # calls stay on this callback; close is observed, never inferred.
                for connection in self.connections:
                    if not connection["closed"]:
                        if connection["socket"] is not None:
                            connection["socket"].close()
                        connection["closed"] = True
                local_closed = all(row["closed"] for row in self.connections)
                processes_closed = all(row["closed"] or not row["entered"] for row in self.processes.originals)
                try:
                    operation.note("cleanup", {"local_exchanges_closed": local_closed,
                                               "local_processes_closed": processes_closed})
                    if self.auth_path is not None and processes_closed and local_closed:
                        operation.check(cleanup=True)
                        self.auth_path.unlink()
                        descriptor = os.open(self.auth_path.parent, os.O_RDONLY | os.O_DIRECTORY)
                        try:
                            os.fsync(descriptor)
                        finally:
                            os.close(descriptor)
                        self.auth_removed = True
                    elif self.auth_path is None:
                        self.auth_removed = True
                    retained = bool(owned is not None and not (owned.container_removed and owned.volume_removed)) or not processes_closed or not local_closed
                    operation.note("cleanup", {"auth_removed": self.auth_removed, "resources_retained": retained or not self.auth_removed})
                    if owned is not None:
                        operation.note("guest", {"retained": retained})
                except BaseException as error:
                    self._failed(operation, error, "cleanup_unconfirmed", unknown=True)
