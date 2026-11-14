"""Fresh-process application/effect witness; deterministic local fixtures only."""

import builtins
import hashlib
import importlib.abc
import io
import json
import os
from pathlib import Path
import socket
import sqlite3
import subprocess
import sys

sys.path.insert(0, sys.argv[1])
from fastapi import BackgroundTasks
from fastapi.testclient import TestClient
from starlette.websockets import WebSocketDisconnect

effects = dict(imports=0, storage=0, private_reads=0, writes=0, queue=0, network=0, processes=0)
forbidden = (
    "src.worker.executor", "src.worker.pr_reviewer", "src.worker.dispatcher",
    "src.agent", "src.sandbox", "src.forge", "src.polyphony", "src.storage",
    "docker", "litellm", "github",
)


class EffectImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if any(fullname == name or fullname.startswith(name + ".") for name in forbidden):
            effects["imports"] += 1
            raise AssertionError("Effectful dependency imported before admission")


def forbidden_effect(kind):
    def fail(*args, **kwargs):
        effects[kind] += 1
        raise AssertionError("Unadmitted effect: " + kind)
    return fail


original_open, original_io_open, original_os_open = builtins.open, io.open, os.open
prior = Path.cwd() / "prior-work.sqlite3"
prior_digest = hashlib.sha256(prior.read_bytes()).hexdigest()


def guarded_open(original):
    def open_file(file, mode="r", *args, **kwargs):
        if not isinstance(file, int) and Path(file).resolve() == prior:
            return forbidden_effect("private_reads")()
        if any(flag in mode for flag in "wax+"):
            return forbidden_effect("writes")()
        return original(file, mode, *args, **kwargs)
    return open_file


def guarded_os_open(file, flags, *args, **kwargs):
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
        return forbidden_effect("writes")()
    return original_os_open(file, flags, *args, **kwargs)


sys.meta_path.insert(0, EffectImports())
builtins.open, io.open = guarded_open(original_open), guarded_open(original_io_open)
os.open = guarded_os_open
sqlite3.connect = forbidden_effect("storage")
BackgroundTasks.add_task = forbidden_effect("queue")
socket.socket.connect = forbidden_effect("network")
subprocess.Popen = forbidden_effect("processes")

from src.api.webhook import app

expected = app.state.standalone_ingress["reason"]
cases = json.loads(sys.argv[2])
with TestClient(app) as client:
    assert client.get("/health").json()["standalone_ingress"]["state"] == "disabled"
    assert client.get("/").status_code == 200
    assert client.get("/static/standalone.css").status_code == 200
    for method, path in cases:
        response = client.request(method, path, content=b'{"approved":true}', headers={
            "Authorization": "Bearer supplied-token", "X-GitHub-Event": "issues",
            "X-Hub-Signature-256": "sha256=" + "0" * 64,
            "Origin": "http://127.0.0.1:8000", "X-Forwarded-Host": "approved.invalid",
        })
        assert response.status_code == 503, (method, path, response.text)
        assert response.json() == {"detail": expected}
    for path in ("/ws/tasks/private", "/api/polyphony/ws/private"):
        try:
            with client.websocket_connect(path):
                raise AssertionError("WebSocket was accepted")
        except WebSocketDisconnect as error:
            assert error.code == 1008 and error.reason == expected

builtins.open, io.open, os.open = original_open, original_io_open, original_os_open
assert hashlib.sha256(prior.read_bytes()).hexdigest() == prior_digest
assert set(path.name for path in Path.cwd().iterdir()) == {"prior-work.sqlite3"}
assert not any(effects.values()), effects
assert not any(any(name == prefix or name.startswith(prefix + ".") for prefix in forbidden) for name in sys.modules)
print(json.dumps({"effects": effects, "policy": app.state.standalone_ingress["policy"],
                  "http_refusals": len(cases), "websocket_refusals": 2, "prior_data_unchanged": True}))
