"""Fixed host Git mechanics for one original standalone review.

The operation owner supplies admission, budgets and the journal. This module
does not accept guest Git configuration, create a managed identity, or retry.
"""
from __future__ import annotations

from dataclasses import dataclass
import base64
import os
from pathlib import Path
import re
import selectors
import signal
import subprocess

from src.worker.review_contract import ReviewError
from src.worker.review_capture import durable_file
from .managed_composition import CompositionError


SHA = re.compile(r"[0-9a-f]{40}")
DESTINATION = re.compile(r"https://github\.com/[A-Za-z0-9][A-Za-z0-9-]*/[A-Za-z0-9_.-]+(?:\.git)?")
USERNAME = re.compile(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}")
HARDENING = ("-c", "core.hooksPath=/dev/null", "-c", "core.fsmonitor=false",
             "-c", "pack.threads=1", "-c", "credential.helper=",
             "-c", "http.proxy=", "-c", "https.proxy=",
             "-c", "http.followRedirects=false", "-c", "http.saveCookies=false",
             "-c", "protocol.allow=never", "-c", "protocol.https.allow=always")


@dataclass(frozen=True)
class ProcessResult:
    stdout: bytes
    exit_code: int
    effect: object


def remember_failure(operation, error):
    """The facade raises its original sticky error after retaining it."""
    try:
        operation.fail(error.code, unknown=error.unknown)
    except ReviewError as original:
        return original
    return error


class ReviewProcesses:
    """Original subprocess custody, including passive join after a cutoff."""

    def __init__(self, operation):
        self.operation = operation
        self.originals = []

    def run(self, command, *, data=b"", limit, environment, deadline=None, publication=False):
        op = self.operation
        maximum = min(limit, op.claim.profile.limits["git_output_bytes"])
        effect = op.reserve("git", request_bytes=len(data), response_bytes=maximum,
                            **({"deadline": deadline} if deadline is not None else {}))
        owned = {"effect": effect, "process": None, "result": None, "entered": False, "closed": False,
                 "signalled": False, "publication": publication}
        self.originals.append(owned)
        selector = selectors.DefaultSelector()
        output = bytearray()
        position = 0
        try:
            def launch():
                owned["entered"] = True
                process = subprocess.Popen(command, stdin=subprocess.PIPE, stdout=subprocess.PIPE,
                                           stderr=subprocess.PIPE, env=environment, start_new_session=True)
                owned["process"] = process
                if publication:
                    op.note("publication", {"invoked": True})
                return process
            process = op.invoke(effect, launch)
            for stream in (process.stdin, process.stdout, process.stderr):
                os.set_blocking(stream.fileno(), False)
            selector.register(process.stdout, selectors.EVENT_READ, "stdout")
            selector.register(process.stderr, selectors.EVENT_READ, "stderr")
            if data:
                selector.register(process.stdin, selectors.EVENT_WRITE, "stdin")
            else:
                process.stdin.close()
            observed = 0
            while selector.get_map():
                remaining = effect.deadline - op.now()
                if remaining <= 0:
                    raise ReviewError("deadline_exhausted", unknown=True)
                for key, _ in selector.select(min(remaining, .05)):
                    if op.now() >= effect.deadline:
                        raise ReviewError("deadline_exhausted", unknown=True)
                    if key.data == "stdin":
                        op.check()
                        try:
                            op.claim.credentials.validate_epoch()
                        except BaseException:
                            op.fail("authority_changed")
                        if op.now() >= effect.deadline:
                            raise ReviewError("deadline_exhausted", unknown=True)
                        try:
                            position += os.write(key.fileobj.fileno(), data[position:position + 65536])
                        except BrokenPipeError:
                            position = len(data)
                        if position == len(data):
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                    else:
                        chunk = os.read(key.fileobj.fileno(), min(65536, maximum - observed + 1))
                        if not chunk:
                            selector.unregister(key.fileobj)
                            key.fileobj.close()
                            continue
                        op.consume(effect, response_bytes=len(chunk))
                        observed += len(chunk)
                        if observed > maximum:
                            raise ReviewError("capacity_exhausted", unknown=True)
                        if key.data == "stdout":
                            output.extend(chunk)
            remaining = effect.deadline - op.now()
            if remaining <= 0:
                raise ReviewError("deadline_exhausted", unknown=True)
            code = process.wait(timeout=remaining)
            owned["closed"] = True
            owned["result"] = ProcessResult(bytes(output), code, effect)
            op.observe(effect, "closed", data={"exit_code": code, "local_closed": True})
            if op.now() >= effect.deadline:
                raise ReviewError("deadline_exhausted", unknown=True)
            if code == 0:
                op.observe(effect, "acknowledged")
            op.check()
            if op.now() >= effect.deadline:
                raise ReviewError("deadline_exhausted", unknown=True)
            return owned["result"]
        except BaseException as error:
            fixed = error if isinstance(error, ReviewError) else ReviewError(
                "publication_outcome_unknown" if publication else "source_unavailable", unknown=owned["entered"])
            fixed = remember_failure(op, fixed)
            try:
                op.observe(effect, "outcome_unknown" if fixed.unknown else "refused", code=fixed.code)
            except BaseException:
                pass
            raise fixed from None
        finally:
            selector.close()
            process = owned["process"]
            if process is not None:
                for stream in (process.stdin, process.stdout, process.stderr):
                    if stream is not None and not stream.closed:
                        stream.close()

    def retire(self):
        """Signal only inside original retirement authority, then passive join.

        The callback remains alive if the original child has not actually ended.
        Waiting after total expiry adds no request, signal, retry or deadline.
        """
        op = self.operation
        for owned in self.originals:
            process = owned["process"]
            if process is None or owned["closed"]:
                continue
            if process.poll() is None and not owned["signalled"]:
                try:
                    op.check(cleanup=True)
                    owned["signalled"] = True
                    os.killpg(process.pid, signal.SIGKILL)
                except (ReviewError, OSError):
                    remember_failure(op, ReviewError("cleanup_unconfirmed", unknown=True))
            if process.poll() is None:
                remember_failure(op, ReviewError("cleanup_unconfirmed", unknown=True))
                try:
                    op.note("cleanup", {"local_processes_closed": False, "resources_retained": True})
                except ReviewError:
                    pass
            code = process.wait()  # Original custody join, never a new timed attempt.
            owned["closed"] = True
            try:
                op.observe(owned["effect"], "closed", data={"exit_code": code, "local_closed": True})
            except ReviewError:
                pass
        closed = all(item["closed"] or not item["entered"] for item in self.originals)
        if not closed:
            remember_failure(op, ReviewError("cleanup_unconfirmed", unknown=True))
        op.note("cleanup", {"local_processes_closed": closed, **({"resources_retained": True} if not closed else {})})


def git_environment(*, objects=None):
    result = {"PATH": os.defpath, "LC_ALL": "C", "GIT_CONFIG_NOSYSTEM": "1",
              "GIT_CONFIG_GLOBAL": "/dev/null", "GIT_CONFIG_SYSTEM": "/dev/null",
              "GIT_ATTR_NOSYSTEM": "1", "GIT_NO_REPLACE_OBJECTS": "1",
              "GIT_TERMINAL_PROMPT": "0", "GIT_OPTIONAL_LOCKS": "0"}
    if objects is not None:
        result["GIT_OBJECT_DIRECTORY"] = str(objects)
    return result


class ReviewGit:
    def __init__(self, processes, directory, limits, *, deadline=None):
        self.processes, self.directory, self.limits, self.deadline = processes, Path(directory), limits, deadline

    def run(self, *arguments, data=b"", failure=None, limit=None):
        if len(arguments) > 32 or any(type(a) is not str or "\0" in a or len(a) > 4096 for a in arguments):
            raise CompositionError("git_arguments_invalid")
        result = self.processes.run(["git", "--no-pager", "--git-dir=" + str(self.directory),
                                     *HARDENING, *arguments], data=data,
                                    limit=min(limit or self.limits.git_output_bytes, self.limits.git_output_bytes),
                                    environment=git_environment(), deadline=self.deadline)
        if result.exit_code:
            expected = failure if result.exit_code == 1 or (result.exit_code == 128 and failure == "malformed_patch") else None
            raise CompositionError(expected or "git_tool_failure")
        return result.stdout


def source_runner(processes):
    def run(directory, arguments, *, deadline, limit, data=b"", objects=None):
        result = processes.run(["git", "--no-pager", "--git-dir=" + str(directory),
                                *HARDENING, *arguments], data=data, limit=limit,
                               environment=git_environment(objects=objects), deadline=deadline)
        if result.exit_code:
            raise ReviewError("source_unavailable")
        if arguments[:2] == ["cat-file", "commit"]:
            # The original commit object, including its metadata, enters the
            # guest snapshot. Inspect the already-counted, bounded decoded
            # bytes before the neutral exporter can pack or expose them.
            processes.operation.assert_safe(result.stdout)
            processes.operation.check()
            if processes.operation.now() >= result.effect.deadline:
                raise ReviewError("deadline_exhausted", unknown=True)
        return result.stdout
    return run


def auth_config(path: Path, destination: str, username: str, token: str):
    if (type(destination) is not str or not DESTINATION.fullmatch(destination)
            or type(username) is not str or not USERNAME.fullmatch(username)
            or type(token) is not str or not 1 <= len(token.encode()) <= 65536
            or any(ord(c) < 33 or ord(c) > 126 for c in token)):
        raise ReviewError("credential_unavailable")
    header = base64.b64encode((username + ":" + token).encode("ascii")).decode("ascii")
    raw = ('[http "' + destination + '"]\n\textraHeader = "Authorization: Basic ' + header + '"\n').encode("ascii")
    durable_file(path, raw)
    return raw


def push_arguments(directory, auth_path, destination, candidate, original_ref, original_head):
    if (not DESTINATION.fullmatch(destination) or not SHA.fullmatch(candidate)
            or not SHA.fullmatch(original_head) or not original_ref.startswith("refs/heads/")
            or any(c in original_ref for c in "\r\n\0") or len(original_ref) > 1024):
        raise ReviewError("publication_refused")
    return ["git", "--no-pager", "--git-dir=" + str(directory), *HARDENING,
            "-c", "include.path=" + str(auth_path), "push", "--porcelain", "--no-follow-tags",
            "--recurse-submodules=no", "--force-with-lease=" + original_ref + ":" + original_head,
            "--", destination, candidate + ":" + original_ref]


def publication_status(raw: bytes, code: int, candidate: str, original_ref: str, original_head: str) -> str:
    """Only one exact original ref's actual changed-ref acknowledgement counts."""
    try:
        text = raw.decode("utf-8", errors="strict")
    except UnicodeError:
        return "outcome_unknown"
    lines = text.splitlines()
    rows = [line.split("\t") for line in lines if "\t" in line]
    if len(rows) != 1 or len(rows[0]) != 3 or rows[0][1] != candidate + ":" + original_ref:
        return "outcome_unknown"
    flag = rows[0][0]
    if flag == " " and code == 0:
        changed = re.fullmatch(r"([0-9a-f]{4,40})\.\.([0-9a-f]{4,40})", rows[0][2])
        if changed and original_head.startswith(changed[1]) and candidate.startswith(changed[2]):
            return "acknowledged"
    if flag == "=" and code == 0 and rows[0][2] == "[up to date]":
        return "observed_no_update"
    if flag == "!" and code != 0:
        return "refused"
    return "outcome_unknown"
