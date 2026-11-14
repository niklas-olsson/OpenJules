"""Cold-import actual validator CLI under no-effects sentinels."""

import builtins
import importlib.abc
import io
import json
import os
from pathlib import Path
import runpy
import socket
import sqlite3
import subprocess
import sys
import threading
import traceback

root = Path(sys.argv[1])
arguments = sys.argv[2:]
module = "src.worker.installation_validation"
if arguments[:1] == ["managed-service"]:
    module = "src.worker.managed_service"
    arguments = arguments[1:]
    # Invalid configuration must precede even the installed-context host check.
    sys.prefix = "/private/managed-interpreter"
sys.path.insert(0, str(root))
effects = dict(writes=0, private_reads=0, host_inspection=0, secrets=0,
               database=0, process=0, network=0, threads=0, imports=0)
effect_stacks = []
forbidden_paths = ("/private/",)


def fail(kind):
    def refused(*_args, **_kwargs):
        effects[kind] += 1
        effect_stacks.append((kind, traceback.format_stack(limit=16)))
        raise AssertionError("validation effect: " + kind)
    return refused


def private_path(value):
    return isinstance(value, (str, bytes, os.PathLike)) and os.fsdecode(value).startswith(forbidden_paths)


def open_guard(original):
    def guarded(path, mode="r", *args, **kwargs):
        if any(flag in mode for flag in "wax+"):
            return fail("writes")()
        if private_path(path):
            return fail("private_reads")()
        return original(path, mode, *args, **kwargs)
    return guarded


builtins.open = open_guard(builtins.open)
io.open = open_guard(io.open)
original_os_open = os.open


def os_open(path, flags, *args, **kwargs):
    if flags & (os.O_WRONLY | os.O_RDWR | os.O_CREAT):
        return fail("writes")()
    if private_path(path):
        return fail("private_reads")()
    return original_os_open(path, flags, *args, **kwargs)


os.open = os_open
for method in ("stat", "lstat", "access"):
    original = getattr(os, method)

    def inspect(path, *args, _original=original, **kwargs):
        if private_path(path):
            return fail("host_inspection")()
        return _original(path, *args, **kwargs)

    setattr(os, method, inspect)
for method in ("mkdir", "makedirs", "remove", "unlink", "rmdir", "rename", "replace", "chmod"):
    setattr(os, method, fail("writes"))

original_environ_get = type(os.environ).__getitem__


def environment(mapping, key):
    if isinstance(key, str) and (key.startswith("FIXTURE_") or key == "DO_NOT_RESOLVE"):
        return fail("secrets")()
    return original_environ_get(mapping, key)


type(os.environ).__getitem__ = environment
sqlite3.connect = fail("database")
subprocess.Popen = fail("process")
threading.Thread.start = fail("threads")


class NoSocket(socket.socket):
    def __init__(self, *_args, **_kwargs):
        fail("network")()


socket.socket = NoSocket
socket.getaddrinfo = fail("network")
socket.create_connection = fail("network")


class NoLegacyImports(importlib.abc.MetaPathFinder):
    def find_spec(self, fullname, path=None, target=None):
        if fullname in {"docker", "urllib3", "litellm", "src.worker.executor", "src.worker.pr_reviewer",
                        "src.api.webhook", "src.polyphony.registry", "src.agent.engine"}:
            fail("imports")()


sys.meta_path.insert(0, NoLegacyImports())
sys.argv = ["installation-validation", *arguments]
try:
    runpy.run_module(module, run_name="__main__")
except SystemExit as completed:
    assert set(effects.values()) == {0}, (effects, effect_stacks)
    raise SystemExit(completed.code)
raise AssertionError("validator CLI did not terminate")
