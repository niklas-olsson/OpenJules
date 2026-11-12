"""Exact opt-in policy and bounded host inputs for managed public discussion.

Public records carry no execution authority. This module contains no provider,
canonical authority or process dispatch. Existing child/grant JSON retains its
ASCII escaping; the new public block uses that same canonical representation.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import json
import math
import os
from pathlib import Path
import re
import stat

from . import discussion_types as discussion

PROTOCOL = "managed-public-pull-v1"
REQUEST_PREFIX = "mpub1:"
MODEL_PREFIX = "/public/"
ROOT_SOCKET = "/run/openjules-model/public.sock"
ROOT_COMMAND = ("python3", "-I", "-S", "/opt/openjules/managed_root_runner.py")
CHILD_COMMAND = ("python3", "-I", "-S", "/opt/openjules/managed_runner.py")
POLICY_LIMIT = 65536
REQUEST_LIMIT = 131072
RESPONSE_LIMIT = 262144
ACTOR_LIMIT = 3
SLOT_LIMIT = 6
ACTOR_SLOT_LIMIT = 2
OWNER_LIMIT = 128
HISTORY_LIMIT = 32
PAGE_LIMIT = 32
SELECTED_LIMIT = 16
SELECTED_BYTES = 65536
SELECTED_PAGES = 8
TRANSCRIPT_LIMIT = 32
TRANSCRIPT_BYTES = 262144
RECORD_LIMIT = 16384
PUBLIC_SECONDS = 45
READ_SECONDS = 15
WATCH_SECONDS = 10
ROOT_CAPTURE_LIMIT = 327680
CHILD_CAPTURE_LIMIT = 131072
KEY = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,63}")
REQUEST_ID = re.compile(r"mpub1:[A-Za-z0-9][A-Za-z0-9._:-]{0,121}")
CHILD_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}")
HEX64 = re.compile(r"[0-9a-f]{64}")
HEX32 = re.compile(r"[0-9a-f]{32}")
AUTHOR = re.compile(r"[0-9a-f]{16}")
DECLINE_TEXT = "I decline this offered public discussion turn."
CODES = frozenset({
    "invalid_request", "not_authorized", "conflict", "request_limit",
    "slot_limit", "transcript_limit", "expired", "actor_left",
    "context_unavailable", "retry_later", "canonical_pending",
    "provider_uncertain", "publication_uncertain", "transport_unavailable",
    "state_conflict",
})
OPERATIONS = {
    "public_activate": {
        "child_id", "persona_key", "instruction_key", "selected_message_ids", "reply_to",
    },
    "public_turn": {
        "persona_key", "instruction_key", "selected_message_ids", "reply_to",
    },
    "public_pull": {"slot_id"},
    "public_decline": {"slot_id"},
    "public_pending": set(),
    "public_status": {"slot_id"},
    "public_read": {"after", "stream_id", "watch_seconds"},
    "public_invite": {"invitation_key"},
}
ROOT_OPERATIONS = frozenset({
    "public_activate", "public_turn", "public_status", "public_read", "public_invite",
})
CHILD_OPERATIONS = frozenset({
    "public_pull", "public_decline", "public_pending", "public_status", "public_read",
})
SLOT_STATES = frozenset({
    "offered", "context_frozen", "model_pending", "response_retained",
    "publication_pending", "published", "declined", "leave_pending", "left",
    "expired", "refused", "uncertain",
})


class ManagedPublicError(RuntimeError):
    def __init__(self, code: str):
        self.code = code if code in CODES else "state_conflict"
        super().__init__(self.code)


def canonical(value, *, limit=None, code="state_conflict") -> bytes:
    try:
        raw = json.dumps(
            value, sort_keys=True, separators=(",", ":"), allow_nan=False,
        ).encode("utf-8")
        if limit is not None and len(raw) > limit:
            raise ValueError("bounded canonical object required")
        return raw
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ManagedPublicError(code) from None


def digest(value) -> str:
    return hashlib.sha256(canonical(value)).hexdigest()


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def _constant(_value):
    raise ValueError("nonfinite constant")


def object_value(raw, limit=REQUEST_LIMIT, *, code="invalid_request", retained=False):
    try:
        if isinstance(raw, str):
            raw = raw.encode("utf-8")
        if not isinstance(raw, bytes) or not 0 < len(raw) <= limit:
            raise ValueError("bounded JSON bytes required")
        value = json.loads(
            raw.decode("utf-8"), object_pairs_hook=_pairs, parse_constant=_constant,
        )
        if not isinstance(value, dict):
            raise ValueError("object required")
        encoded = canonical(value, limit=limit, code=code)
        if retained and encoded != raw:
            raise ValueError("retained value is not canonical")
        return value
    except (TypeError, ValueError, OverflowError, RecursionError):
        raise ManagedPublicError(code) from None


def fields(value, required, optional=(), *, code="invalid_request"):
    if (
        not isinstance(value, dict)
        or not set(required) <= set(value)
        or set(value) - set(required) - set(optional)
    ):
        raise ManagedPublicError(code)
    return value


def integer(value, minimum, maximum, *, code="invalid_request"):
    if type(value) is not int or not minimum <= value <= maximum:
        raise ManagedPublicError(code)
    return value


def finite(value, minimum, maximum, *, code="invalid_request"):
    # Range comparison precedes conversion, including arbitrary-size JSON ints.
    try:
        valid = (
            type(value) in {int, float}
            and minimum < value <= maximum
            and math.isfinite(float(value))
        )
    except (TypeError, ValueError, OverflowError):
        valid = False
    if not valid:
        raise ManagedPublicError(code)
    return value


def text(value, maximum, *, nonempty=True, code="invalid_request"):
    try:
        valid = (
            isinstance(value, str)
            and (not nonempty or bool(value))
            and "\0" not in value
            and len(value.encode("utf-8")) <= maximum
        )
    except (UnicodeError, ValueError):
        valid = False
    if not valid:
        raise ManagedPublicError(code)
    return value


def matches(pattern, value, *, code="invalid_request"):
    if not isinstance(value, str) or pattern.fullmatch(value) is None:
        raise ManagedPublicError(code)
    return value


def absolute_path(value, *, code="state_conflict"):
    text(value, 4096, code=code)
    path = Path(value)
    if not path.is_absolute() or path.anchor != "/" or str(path) != value or ".." in path.parts:
        raise ManagedPublicError(code)
    return path


def _directory_descriptor(path):
    """Inspect every original component without resolving away a symlink."""
    descriptor = os.open("/", os.O_RDONLY | os.O_DIRECTORY | os.O_CLOEXEC)
    try:
        for name in path.parts[1:]:
            child = os.open(
                name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
                dir_fd=descriptor,
            )
            os.close(descriptor)
            descriptor = child
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _file_facts(info):
    return (
        info.st_dev, info.st_ino, info.st_mode, info.st_uid, info.st_nlink,
        info.st_size, info.st_mtime_ns, info.st_ctime_ns,
    )


def read_scope(server) -> dict:
    """Validate one bounded private descriptor; return no scope-secret bytes."""
    parent = descriptor = checked_parent = None
    try:
        path = absolute_path(server["scope_key_file"])
        parent = _directory_descriptor(path.parent)
        supplied = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        if (
            not stat.S_ISREG(supplied.st_mode) or supplied.st_uid != os.geteuid()
            or stat.S_IMODE(supplied.st_mode) not in {0o400, 0o600}
            or supplied.st_nlink != 1 or not 0 < supplied.st_size <= 4096
        ):
            raise ValueError("invalid private scope file")
        descriptor = os.open(
            path.name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
            dir_fd=parent,
        )
        before = os.fstat(descriptor)
        if _file_facts(before) != _file_facts(supplied):
            raise ValueError("scope leaf changed before open")
        raw = bytearray()
        while len(raw) <= 4096:
            chunk = os.read(descriptor, min(4097 - len(raw), 4096))
            if not chunk:
                break
            raw.extend(chunk)
        after = os.fstat(descriptor)
        current = os.stat(path.name, dir_fd=parent, follow_symlinks=False)
        checked_parent = _directory_descriptor(path.parent)
        parent_before, parent_after = os.fstat(parent), os.fstat(checked_parent)
        if (
            len(raw) != before.st_size or len(raw) > 4096
            or (parent_before.st_dev, parent_before.st_ino)
            != (parent_after.st_dev, parent_after.st_ino)
            or _file_facts(before) != _file_facts(after)
            or _file_facts(before) != _file_facts(current)
            or "\0" in bytes(raw).decode("utf-8")
            or hashlib.sha256(raw).hexdigest() != server["scope_key_sha256"]
        ):
            raise ValueError("scope binding changed")
        return {
            "path": str(path), "sha256": server["scope_key_sha256"],
            "device": before.st_dev, "inode": before.st_ino,
            "mode": stat.S_IMODE(before.st_mode), "uid": before.st_uid,
        }
    except Exception:
        raise ManagedPublicError("state_conflict") from None
    finally:
        if descriptor is not None:
            os.close(descriptor)
        if parent is not None:
            os.close(parent)
        if checked_parent is not None:
            os.close(checked_parent)


@dataclass(frozen=True)
class PublicPolicy:
    """Store an immutable canonical policy; every projection is a fresh copy."""

    encoded: bytes

    @classmethod
    def parse(cls, value):
        try:
            fields(value, {
                "protocol", "public_approved", "topic", "server", "personas",
                "instructions", "invitations",
            })
            if value["protocol"] != PROTOCOL or value["public_approved"] is not True:
                raise ManagedPublicError("invalid_request")
            text(value["topic"], 256)
            if any(ord(character) < 32 for character in value["topic"]):
                raise ManagedPublicError("invalid_request")
            for name, low, high in (
                ("personas", 1, 3), ("instructions", 1, 8), ("invitations", 0, 1),
            ):
                items = value[name]
                if not isinstance(items, dict) or not low <= len(items) <= high:
                    raise ManagedPublicError("invalid_request")
                for key, item in items.items():
                    matches(KEY, key)
                    if name == "invitations":
                        fields(item, {"target", "content"})
                        matches(AUTHOR, item["target"])
                        text(item["content"], 4096)
                        if not item["content"].strip():
                            raise ManagedPublicError("invalid_request")
                    else:
                        text(item, 4096)
                        if not item.strip():
                            raise ManagedPublicError("invalid_request")
            server = fields(
                value["server"], {"python", "cwd", "scope_key_file", "scope_key_sha256"},
                {"bootstrap"},
            )
            for name in ("python", "cwd", "scope_key_file"):
                absolute_path(server[name], code="invalid_request")
            matches(HEX64, server["scope_key_sha256"])
            if "bootstrap" in server:
                bootstrap = fields(server["bootstrap"], {"host", "port"})
                if bootstrap["host"] != "127.0.0.1":
                    raise ManagedPublicError("invalid_request")
                integer(bootstrap["port"], 1, 65535)
            return cls(canonical(value, limit=POLICY_LIMIT, code="invalid_request"))
        except (ManagedPublicError, TypeError, ValueError, OverflowError, RecursionError):
            raise ValueError("invalid managed public discussion policy") from None

    @property
    def document(self):
        return json.loads(self.encoded)

    @property
    def server(self):
        return self.document["server"]

    @property
    def fingerprint(self):
        return hashlib.sha256(self.encoded).hexdigest()

    def check_server(self):
        """Trust host executables separately from private, no-link state files."""
        directory = None
        try:
            server = self.server
            launch = absolute_path(server["python"])
            # A venv launcher is normally a symlink. Bind the resolved identity,
            # but the subprocess argv must retain this ORIGINAL launch path.
            resolved = launch.resolve(strict=True)
            info = launch.stat()
            if not stat.S_ISREG(info.st_mode) or not os.access(launch, os.X_OK):
                raise ValueError("trusted Python executable required")
            cwd = absolute_path(server["cwd"])
            directory = _directory_descriptor(cwd)
            cwd_info = os.fstat(directory)
            scope = read_scope(server)
            return {
                "launch_path": str(launch), "resolved_executable": str(resolved),
                "executable_device": info.st_dev, "executable_inode": info.st_ino,
                "executable_size": info.st_size, "executable_mtime_ns": info.st_mtime_ns,
                "cwd": str(cwd), "cwd_device": cwd_info.st_dev,
                "cwd_inode": cwd_info.st_ino, "scope": scope,
            }
        except Exception:
            raise ValueError("managed public host bindings are unavailable") from None
        finally:
            if directory is not None:
                os.close(directory)


def validate_root_command(command):
    try:
        if (
            not isinstance(command, (list, tuple))
            or tuple(command[:4]) != ROOT_COMMAND
            or (len(command) - 4) % 2
        ):
            raise ValueError("approved root command required")
        options = {}
        allowed = {
            "--socket", "--control-socket", "--public-socket",
            "--max-turns", "--control-timeout-seconds", "--verify-json",
        }
        for offset in range(4, len(command), 2):
            name, value = command[offset:offset + 2]
            if not isinstance(name, str) or name not in allowed or name in options:
                raise ValueError("unique exact root option required")
            text(value, 524288)
            options[name] = value
        if any(options.get(name) != value for name, value in {
            "--socket": "/run/openjules-model/model.sock",
            "--control-socket": "/run/openjules-model/control.sock",
            "--public-socket": ROOT_SOCKET,
        }.items()):
            raise ValueError("fixed root sockets required")
        if "--max-turns" in options:
            value = options["--max-turns"]
            if not re.fullmatch(r"[0-9]+", value):
                raise ValueError("bounded explicit integer required")
            integer(int(value), 1, 1000)
        if "--control-timeout-seconds" in options:
            finite(float(options["--control-timeout-seconds"]), 0, 120)
        if "--verify-json" in options:
            verify = json.loads(
                options["--verify-json"], object_pairs_hook=_pairs,
                parse_constant=_constant,
            )
            if not isinstance(verify, list) or len(verify) > 128:
                raise ValueError("bounded verification argv required")
            for item in verify:
                text(item, 4096)
        return tuple(command)
    except (ManagedPublicError, TypeError, ValueError, OverflowError, RecursionError):
        raise ValueError("managed public discussion requires the approved root runner") from None


def validate_request(payload, role):
    fields(payload, {"schema_version", "request_id", "operation"},
           set().union(*OPERATIONS.values()))
    integer(payload["schema_version"], 1, 1)
    matches(REQUEST_ID, payload["request_id"])
    operation = payload["operation"]
    if not isinstance(operation, str) or operation not in OPERATIONS:
        raise ManagedPublicError("invalid_request")
    if set(payload) != {"schema_version", "request_id", "operation"} | OPERATIONS[operation]:
        raise ManagedPublicError("invalid_request")
    if role not in {"root", "child"} or operation not in (
        ROOT_OPERATIONS if role == "root" else CHILD_OPERATIONS
    ):
        raise ManagedPublicError("not_authorized")
    if "child_id" in payload:
        matches(CHILD_ID, payload["child_id"])
    if "slot_id" in payload:
        matches(HEX64, payload["slot_id"])
    for name in ("persona_key", "instruction_key", "invitation_key"):
        if name in payload:
            matches(KEY, payload[name])
    if "selected_message_ids" in payload:
        selected = payload["selected_message_ids"]
        if not isinstance(selected, list) or len(selected) > SELECTED_LIMIT:
            raise ManagedPublicError("invalid_request")
        for item in selected:
            matches(HEX64, item)
        if len(set(selected)) != len(selected):
            raise ManagedPublicError("invalid_request")
        if payload["reply_to"] is not None and payload["reply_to"] not in selected:
            raise ManagedPublicError("invalid_request")
    if operation == "public_read":
        integer(payload["after"], 0, (1 << 63) - 1)
        integer(payload["watch_seconds"], 0, WATCH_SECONDS)
        if payload["stream_id"] is not None:
            matches(HEX32, payload["stream_id"])
        elif payload["after"] > 0:
            raise ManagedPublicError("invalid_request")
    canonical(payload, limit=REQUEST_LIMIT, code="invalid_request")
    return payload


def model_key(worker_id, root_attempt_id, actor_key, activation_key, slot_id):
    return MODEL_PREFIX + digest([
        PROTOCOL, worker_id, root_attempt_id, actor_key, activation_key, slot_id,
    ])


def publication_key(slot_id):
    matches(HEX64, slot_id, code="state_conflict")
    return "oj-public:" + slot_id


def invitation_key(author, approved_key, original_request_id):
    matches(AUTHOR, author, code="state_conflict")
    matches(KEY, approved_key, code="state_conflict")
    matches(REQUEST_ID, original_request_id, code="state_conflict")
    return "oj-public-invite:" + digest([author, approved_key, original_request_id])


def public_messages(policy, persona_key, instruction_key, context):
    document = policy.document
    if (
        persona_key not in document["personas"]
        or instruction_key not in document["instructions"]
        or not isinstance(context, list) or len(context) > SELECTED_LIMIT
        or sum(len(canonical(record)) for record in context) > SELECTED_BYTES
    ):
        raise ManagedPublicError("context_unavailable")
    try:
        # Only extract the common pure message projection here. The real model,
        # token allocation and token_parameter come from ModelBroker at dispatch.
        return discussion.public_provider_request(
            model="managed-public-projection",
            persona=document["personas"][persona_key],
            instruction=document["instructions"][instruction_key],
            context=context, tokens=1,
        )["messages"]
    except discussion.DiscussionError:
        raise ManagedPublicError("context_unavailable") from None


def public_output(raw, credential):
    """Use the shared completion parser before retaining any provider text."""
    try:
        result = discussion.provider_output(raw)
        if credential and credential in result["content"]:
            raise ValueError("credential echo")
        return result
    except Exception:
        # Keep the common broker's charged uncertain reservation. Do not retain
        # untrusted completion metadata, raw text or a credential echo.
        raise ManagedPublicError("provider_uncertain") from None


def public_model_payload(policy, actor, slot):
    """Private broker identity; only messages are projected to the provider."""
    if actor["binding_digest"] is None or slot["context"] is None:
        raise ManagedPublicError("state_conflict")
    return {
        "schema_version": 1, "request_id": slot["model_key"],
        "public_protocol": PROTOCOL, "public_actor": actor["binding_digest"],
        "public_slot": slot["slot_id"],
        "messages": public_messages(
            policy, slot["persona_key"], slot["instruction_key"], slot["context"],
        ),
    }


def signed_intent(status, key, kind, content, *, reply_to=None, target=None):
    """Exact approved public fields and escaped record-fit check before say."""
    if not isinstance(kind, str) or kind not in {"message", "decline", "leave", "invite"}:
        raise ManagedPublicError("state_conflict")
    matches(discussion.KEY, key, code="state_conflict")
    text(content, 8192, nonempty=False, code="state_conflict")
    if reply_to is not None:
        matches(HEX64, reply_to, code="state_conflict")
    if target is not None:
        matches(AUTHOR, target, code="state_conflict")
    intent = {
        "topic": status["topic"], "session_id": status["session_id"],
        "swarm_id": status["swarm_id"], "visibility": "public",
        "request_key": key, "kind": kind, "content": content,
        "reply_to": reply_to, "target": target, "references": [],
    }
    candidate = {
        "message_id": "0" * 64, "signature": "0" * 128,
        "body": intent | {
            "schema_version": 1, "author": status["author"],
            "public_key": status["public_key"], "timestamp": 0,
        },
    }
    # Generated finite time.time() scalar has at most32 ASCII bytes. This is
    # the same conservative original-record bound used by standalone B.
    if len(canonical(candidate)) + 31 > RECORD_LIMIT:
        raise ManagedPublicError("provider_uncertain")
    return intent
