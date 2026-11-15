"""A controlled Unix HTTP peer, not Docker and not guest execution."""
import copy
import hashlib
import io
import json
from pathlib import Path
import socket
import os
import stat
import struct
import threading
from types import SimpleNamespace
from unittest import mock


class UnixDockerFixture:
    def __init__(self, path, image, archive):
        self.path, self.image, self.archive = Path(path), image, archive
        self.requests, self.errors = [], []
        self.container_id = "d" * 64
        self.volume = self.container = None
        self.running = False
        self.execs = {}
        self.before_response = None
        self.override = None
        self.closed = threading.Event()
        self.listener = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        self.listener.bind(str(path))
        self.listener.listen(1)
        self.listener.settimeout(.05)
        self.thread = threading.Thread(target=self.serve, daemon=True)
        self.thread.start()

    def close(self):
        self.closed.set()
        self.thread.join(2)
        self.listener.close()
        if self.thread.is_alive():
            raise AssertionError("original fixture listener did not stop")

    def serve(self):
        while not self.closed.is_set():
            try:
                connection, _ = self.listener.accept()
            except socket.timeout:
                continue
            with connection:
                connection.settimeout(2)
                try:
                    prefix = bytearray()
                    while not prefix.endswith(b"\r\n\r\n"):
                        part = connection.recv(1)
                        if not part or len(prefix) >= 65536:
                            raise AssertionError("invalid controlled request prefix")
                        prefix.extend(part)
                    lines = bytes(prefix).split(b"\r\n")
                    method, path, protocol = lines[0].decode().split(" ")
                    headers = dict(line.decode().split(": ", 1) for line in lines[1:] if line)
                    size = int(headers.get("Content-Length", 0))
                    if size > 2000000:
                        raise AssertionError("oversize controlled request")
                    body = bytearray()
                    while len(body) < size:
                        part = connection.recv(size - len(body))
                        if not part:
                            raise AssertionError("incomplete controlled request")
                        body.extend(part)
                    request = {"method": method, "path": path, "headers": headers, "body": bytes(body)}
                    self.requests.append(request)
                    response = self.override(request) if self.override else None
                    if response is None:
                        response = self.route(method, path, bytes(body))
                    if self.before_response:
                        self.before_response(request, response)
                    if response == "DROP":
                        continue
                    if type(response) is bytes:
                        connection.sendall(response)
                        continue
                    status, payload = response
                    raw = payload if type(payload) is bytes else json.dumps(payload, separators=(",", ":")).encode()
                    if status in {204, 304}:
                        raw = b""
                    connection.sendall(f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(raw)}\r\nConnection: close\r\n\r\n".encode() + raw)
                except BaseException as error:
                    self.errors.append(error)

    def inspect(self):
        config = {key: copy.deepcopy(self.container[key]) for key in ("Labels", "User", "WorkingDir", "Entrypoint", "Cmd", "Env", "Healthcheck")}
        mounts = self.container["HostConfig"]["Mounts"]
        return {"Id": self.container_id, "Image": self.image, "Config": config,
                "HostConfig": copy.deepcopy(self.container["HostConfig"]),
                "State": {"Running": self.running, "Restarting": False, "Paused": False,
                          "Status": "running" if self.running else "exited"},
                "Mounts": [{"Destination": "/source", "Type": "bind", "Source": mounts[0]["Source"],
                            "RW": False, "Propagation": "rprivate"},
                           {"Destination": "/workspace", "Type": "volume", "Name": self.volume["Name"],
                            "Driver": "local", "RW": True}]}

    def route(self, method, path, raw):
        if not path.startswith("/v1.45/"):
            raise AssertionError("API negotiation/fallback attempted")
        path = path[len("/v1.45"):]
        payload = json.loads(raw) if raw and not path.startswith("/containers/" + self.container_id + "/archive") else None
        if method == "GET" and path == "/images/" + self.image + "/json":
            return 200, {"Id": self.image, "Config": {"Env": ["PATH=/usr/local/bin:/usr/bin:/bin"], "Volumes": None}}
        if method == "POST" and path == "/volumes/create":
            self.volume = {"Name": payload["Name"], "Driver": "local", "Scope": "local", "Options": {},
                           "Labels": payload["Labels"], "CreatedAt": "2026-01-01T00:00:00Z"}
            return 201, self.volume
        if method == "POST" and path.startswith("/containers/create?"):
            self.container = payload
            return 201, {"Id": self.container_id, "Warnings": []}
        if method == "GET" and path == "/containers/" + self.container_id + "/json":
            return 200, self.inspect()
        if method == "PUT" and path == "/containers/" + self.container_id + "/archive?path=%2Fworkspace&noOverwriteDirNonDir=1":
            return 200, b""
        if method == "POST" and path == "/containers/" + self.container_id + "/start":
            self.running = True
            return 204, b""
        if method == "POST" and path == "/containers/" + self.container_id + "/exec":
            identity = hashlib.sha256(str(len(self.execs)).encode()).hexdigest()
            self.execs[identity] = payload
            return 201, {"Id": identity}
        if method == "POST" and path.startswith("/exec/") and path.endswith("/start"):
            output = b"controlled fixture output\n"
            return 200, b"\x01\0\0\0" + len(output).to_bytes(4, "big") + output
        if method == "GET" and path.startswith("/exec/") and path.endswith("/json"):
            identity = path.split("/")[2]
            if identity not in self.execs:
                raise AssertionError("unowned exec inspected")
            return 200, {"ID": identity, "ContainerID": self.container_id, "Running": False, "ExitCode": 0}
        if method == "POST" and path == "/containers/" + self.container_id + "/stop?t=0":
            self.running = False
            return 204, b""
        if method == "GET" and path == "/containers/" + self.container_id + "/archive?path=%2Fworkspace":
            if self.running:
                raise AssertionError("capture before original stop")
            return 200, self.archive
        if method == "DELETE" and path == "/containers/" + self.container_id + "?force=false&v=false":
            if self.running:
                raise AssertionError("removal while running")
            return 204, b""
        if method == "GET" and path == "/volumes/" + self.volume["Name"]:
            return 200, self.volume
        if method == "DELETE" and path == "/volumes/" + self.volume["Name"] + "?force=false":
            return 204, b""
        raise AssertionError("unexpected controlled daemon operation: " + method + " " + path)


class MemoryDockerFixture(UnixDockerFixture):
    """Explicit socket substitution for sandboxes that prohibit AF_UNIX.

    The production wire encoder, bounded reader, exact route construction and
    semantic joins still run. This does not qualify the real Unix transport.
    """
    def __init__(self, path, image, archive):
        self.path, self.image, self.archive = Path(path), image, archive
        self.requests, self.errors, self.connections = [], [], []
        self.container_id = "d" * 64
        self.volume = self.container = None
        self.running = False
        self.execs = {}
        self.before_response = self.override = None
        original_lstat = Path.lstat
        fixture = self
        def lstat(path):
            if path == fixture.path:
                return SimpleNamespace(st_mode=stat.S_IFSOCK | 0o600, st_dev=1, st_ino=2,
                                       st_uid=os.getuid(), st_gid=os.getgid())
            return original_lstat(path)
        self.patches = [mock.patch("src.worker.review_native.socket.socket", side_effect=self.socket),
                        mock.patch("src.worker.review_native.Path.lstat", lstat)]
        for patch in self.patches:
            patch.start()

    def close(self):
        for patch in reversed(self.patches):
            patch.stop()

    def socket(self, family, kind, *args):
        if family != socket.AF_UNIX or kind != socket.SOCK_STREAM or args:
            raise AssertionError("non-original socket transport")
        fixture = self
        class Exchange:
            def __init__(self):
                self.request, self.reply = bytearray(), None
                self.closed = self.connected = False
                self.reads = []
            def settimeout(self, timeout):
                if timeout <= 0:
                    raise AssertionError("expired socket timeout")
            def connect(self, endpoint):
                if self.connected or endpoint != str(fixture.path):
                    raise AssertionError("connection retry/fallback")
                self.connected = True
            def getsockopt(self, level, option, length):
                return struct.pack("3i", os.getpid(), os.getuid(), os.getgid())
            def sendall(self, raw):
                if not self.connected or self.closed or self.reply is not None:
                    raise AssertionError("unowned/late send")
                self.request.extend(raw)
            def recv(self, count):
                self.reads.append(count)
                if self.reply is None:
                    prefix, separator, body = bytes(self.request).partition(b"\r\n\r\n")
                    if not separator:
                        raise AssertionError("incomplete request framing")
                    lines = prefix.split(b"\r\n")
                    method, path, _ = lines[0].decode().split(" ")
                    headers = dict(line.decode().split(": ", 1) for line in lines[1:])
                    if len(body) != int(headers["Content-Length"]):
                        raise AssertionError("incomplete original body")
                    request = {"method": method, "path": path, "headers": headers, "body": body}
                    fixture.requests.append(request)
                    result = fixture.override(request) if fixture.override else None
                    if result is None:
                        result = fixture.route(method, path, body)
                    if fixture.before_response:
                        fixture.before_response(request, result)
                    if result == "DROP":
                        raw = b""
                    elif type(result) is bytes:
                        raw = result
                    else:
                        status, payload = result
                        body = payload if type(payload) is bytes else json.dumps(payload, separators=(",", ":")).encode()
                        if status in {204, 304}:
                            body = b""
                        raw = f"HTTP/1.1 {status} Fixture\r\nContent-Length: {len(body)}\r\nConnection: close\r\n\r\n".encode() + body
                    self.reply = io.BytesIO(raw)
                return self.reply.read(count)
            def close(self):
                self.closed = True
        connection = Exchange()
        self.connections.append(connection)
        return connection
