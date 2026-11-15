"""Closed optional host policy for one standalone review operation."""

from __future__ import annotations

import hashlib
import math
import re
from types import MappingProxyType
from urllib.parse import urlsplit

from src.api.ingress_policy import (
    IngressError, POLICY_LIMIT, absolute_path, canonical_json, exact_object,
    positive_integer,
)
from src.worker.review_contract import PROFILE_SCHEMA, ReviewError, ReviewProfile

LIMIT_FIELDS = frozenset({
    "total_ms", "cleanup_reserve_ms", "model_call_ms", "exec_call_ms",
    "guest_api_ms", "git_call_ms", "forge_call_ms", "agent_turns", "model_calls",
    "model_request_bytes", "model_request_total_bytes", "model_response_bytes",
    "model_response_total_bytes", "model_output_tokens_per_call",
    "model_output_tokens_total", "exec_calls", "exec_input_bytes",
    "exec_output_bytes", "exec_output_total_bytes", "guest_api_calls",
    "guest_api_cleanup_calls", "source_bytes", "source_objects", "context_bytes",
    "archive_bytes", "patch_bytes", "log_bytes", "files", "path_bytes",
    "blob_bytes", "patch_records", "object_bytes", "object_count", "git_calls",
    "git_output_bytes", "git_output_total_bytes", "forge_response_bytes",
    "forge_response_total_bytes", "receipt_result_bytes",
})
_ENV = re.compile(r"env:([A-Za-z_][A-Za-z0-9_]{0,127})\Z")
_SHA256 = re.compile(r"[0-9a-f]{64}\Z")


def _bad(code="invalid_review_profile", status=422):
    raise IngressError(code, status)


def text(value, maximum, *, empty=False):
    if type(value) is not str or "\x00" in value:
        _bad()
    try:
        length = len(value.encode("utf-8"))
    except UnicodeError:
        _bad()
    if length > maximum or (not empty and not length):
        _bad()
    return value


def freeze(value):
    """Only validated JSON data crosses this recursively immutable boundary."""
    if type(value) is dict:
        return MappingProxyType({key: freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(freeze(item) for item in value)
    return value


def thaw(value):
    if isinstance(value, MappingProxyType):
        return {key: thaw(item) for key, item in value.items()}
    if type(value) is tuple:
        return [thaw(item) for item in value]
    if type(value) is dict:
        return {key: thaw(item) for key, item in value.items()}
    return value


def secret_reference(value):
    match = _ENV.fullmatch(value) if type(value) is str else None
    if match is None or match.group(1).startswith("OPENJULES_INGRESS_"):
        _bad("invalid_review_secret_reference")
    return match.group(1)


def _model_endpoint(value):
    text(value, 4096)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _bad("invalid_review_model_endpoint")
    if (
        not parsed.hostname or parsed.username is not None or parsed.password is not None
        or "?" in value or "#" in value or parsed.scheme not in {"http", "https"}
        or any(ord(char) < 33 or ord(char) > 126 for char in value)
        or "\\" in value or not parsed.path.startswith("/")
        or parsed.netloc != parsed.netloc.lower()
        or (port is not None and not 1 <= port <= 65535)
        or (parsed.scheme == "http" and parsed.hostname not in {"127.0.0.1", "::1"})
        or "%" in parsed.netloc
    ):
        _bad("invalid_review_model_endpoint")
    return value


def parse_review_profile(value, installation_id):
    """Pure syntax/capacity validation, with no credential or client reads."""
    exact_object(value, {"schema", "source", "guest", "model", "forge_auth", "commit_author", "limits"})
    if value["schema"] != PROFILE_SCHEMA:
        _bad("unsupported_review_profile", 404)
    source = exact_object(value["source"], {"repository_path", "state_root"})
    repository_path = absolute_path(source["repository_path"])
    state_root = absolute_path(source["state_root"])
    if (repository_path == state_root or repository_path in state_root.parents
            or state_root in repository_path.parents):
        _bad("overlapping_review_paths")

    guest = exact_object(value["guest"], {
        "docker_endpoint", "docker_api_version", "image", "uid", "gid",
        "test_command", "memory_bytes", "cpu_quota_us", "pids_limit",
    })
    endpoint = text(guest["docker_endpoint"], 4103)
    if not endpoint.startswith("unix:///") or any(char in endpoint for char in "?#%\\"):
        _bad("invalid_review_docker_endpoint")
    socket_path = endpoint[len("unix://"):]
    if (socket_path.startswith("//") or str(absolute_path(socket_path)) != socket_path
            or any(ord(c) < 33 or ord(c) == 127 for c in socket_path)):
        _bad("invalid_review_docker_endpoint")
    if guest["docker_api_version"] != "1.45":
        _bad("unsupported_review_docker_api", 404)
    image = guest["image"]
    if type(image) is not str or not image.startswith("sha256:") or not _SHA256.fullmatch(image[7:]):
        _bad("immutable_review_image_required")
    for name in ("uid", "gid", "memory_bytes", "cpu_quota_us", "pids_limit"):
        positive_integer(guest[name])
    if guest["uid"] >= 2**32 - 1 or guest["gid"] >= 2**32 - 1:
        _bad()
    text(guest["test_command"], 16384)

    model = exact_object(value["model"], {"url", "model", "temperature", "credential_ref"})
    _model_endpoint(model["url"])
    text(model["model"], 256)
    temperature = model["temperature"]
    try:
        finite = type(temperature) in (int, float) and math.isfinite(temperature)
    except (OverflowError, ValueError):
        finite = False
    if not finite:
        _bad()
    if model["credential_ref"] is not None:
        secret_reference(model["credential_ref"])

    auth = value["forge_auth"]
    if type(auth) is not dict:
        _bad()
    if auth.get("kind") == "pat":
        exact_object(auth, {"kind", "token_ref", "username"})
        secret_reference(auth["token_ref"])
        username = text(auth["username"], 128)
        if re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]*", username) is None:
            _bad("invalid_review_git_username")
    elif auth.get("kind") == "app":
        exact_object(auth, {"kind", "app_id_ref", "private_key_path_ref"})
        secret_reference(auth["app_id_ref"])
        secret_reference(auth["private_key_path_ref"])
        if installation_id is None:
            _bad("review_installation_required")
    else:
        _bad("unsupported_review_authentication", 404)

    author = exact_object(value["commit_author"], {"name", "email"})
    for key, maximum in (("name", 128), ("email", 254)):
        text(author[key], maximum)
        if any(ord(c) < 32 or ord(c) == 127 or c in "<>" for c in author[key]):
            _bad("invalid_review_commit_author")
    if author["email"].count("@") != 1 or any(c.isspace() for c in author["email"]):
        _bad("invalid_review_commit_author")

    limits = exact_object(value["limits"], LIMIT_FIELDS)
    for bound in limits.values():
        positive_integer(bound)
    if not limits["cleanup_reserve_ms"] < limits["total_ms"]:
        _bad("invalid_review_cleanup_reserve")
    # One declared stop/inspect/archive/remove/volume-inspect/volume-remove tail.
    if not 6 <= limits["guest_api_cleanup_calls"] < limits["guest_api_calls"]:
        _bad("invalid_review_cleanup_reserve")
    for item, total in (
        ("model_request_bytes", "model_request_total_bytes"),
        ("model_response_bytes", "model_response_total_bytes"),
        ("model_output_tokens_per_call", "model_output_tokens_total"),
        ("exec_output_bytes", "exec_output_total_bytes"),
        ("git_output_bytes", "git_output_total_bytes"),
        ("forge_response_bytes", "forge_response_total_bytes"),
    ):
        if limits[item] > limits[total]:
            _bad("invalid_review_aggregate_bound")
    if sum(limits.values()) > 2**63 - 1:
        _bad("unrepresentable_review_bounds")
    # Reuse the supported composition constraints before credentials, source
    # preparation or any runtime effect. These constructors perform no I/O.
    from src.git_manager.managed_composition import CompositionLimits
    from src.worker.source_snapshot import MAX_SOURCE_OBJECTS
    if limits["source_objects"] > MAX_SOURCE_OBJECTS:
        _bad("unsupported_review_source_bounds")
    try:
        CompositionLimits(
            artifact_bytes=limits["patch_bytes"],
            total_artifact_bytes=limits["patch_bytes"],
            source_bytes=limits["source_bytes"], blob_bytes=limits["blob_bytes"],
            max_files=limits["files"], max_children=1,
            max_path_bytes=limits["path_bytes"],
            max_patch_records=limits["patch_records"],
            max_objects=limits["object_count"], object_bytes=limits["object_bytes"],
            git_output_bytes=limits["git_output_bytes"],
            seconds=min(120, limits["total_ms"] / 1000),
        )
    except ValueError:
        _bad("unsupported_review_composition_bounds")
    # Pure result-schema capacity calculation. It imports no runtime/client.
    from src.worker.review_result import required_result_capacity
    try:
        capacity = required_result_capacity(limits)
    except ReviewError:
        _bad("unrepresentable_review_bounds")
    if limits["receipt_result_bytes"] < capacity:
        _bad("review_result_capacity_insufficient")
    raw = canonical_json(value).encode("utf-8")
    if len(raw) > POLICY_LIMIT:
        _bad("review_profile_too_large", 413)
    return ReviewProfile(freeze(value), hashlib.sha256(raw).hexdigest())


def scan_review_secrets(value, secrets, *, maximum_bytes=1048576, maximum_nodes=1024, maximum_members=128):
    """A bounded literal scan over validated review data, not general tainting."""
    pending, visited, total = [value], 0, 0
    while pending:
        item = pending.pop()
        visited += 1
        if visited > maximum_nodes:
            _bad("invalid_review_structure")
        if type(item) is dict or isinstance(item, MappingProxyType):
            if len(item) > maximum_members or any(type(key) is not str for key in item):
                _bad("invalid_review_structure")
            for key, child in item.items():
                pending.extend((key, child))
        elif type(item) in (list, tuple):
            if len(item) > maximum_members:
                _bad("invalid_review_structure")
            pending.extend(item)
        elif type(item) is str:
            text(item, maximum_bytes, empty=True)
            total += len(item.encode("utf-8"))
            if total > maximum_bytes:
                _bad("invalid_review_structure")
            if any(secret in item for secret in secrets):
                _bad("selected_secret_in_review_input")
        elif type(item) is bool:
            pass
        elif type(item) is int:
            if not -(2**63) <= item < 2**63:
                _bad("invalid_review_structure")
        elif type(item) is float:
            if not math.isfinite(item):
                _bad("invalid_review_structure")
        elif item is not None:
            _bad("invalid_review_structure")
