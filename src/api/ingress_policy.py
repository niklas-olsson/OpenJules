"""Strict, host-owned policy for the qualified standalone task ingress.

Loading policy never imports an executor, connects a forge, or creates storage.
Authentication values are frozen for one owner epoch. A changed selected file or
authentication value closes admission until the owner stops and reenrolls.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import os
from pathlib import Path
import re
import stat
import threading
from types import MappingProxyType
from typing import Mapping
from urllib.parse import urlsplit

from src.worker.execution_context import LegacyExecutionRefused, require_legacy_execution

POLICY_LIMIT = 262_144
BODY_LIMIT = 1_048_576
MAX_MEMBERS = 128
MAX_INTEGER = 2**63 - 1
TASK_BODY_LIMIT = 262_144
_ID = re.compile(r"[A-Za-z0-9][A-Za-z0-9._:-]{0,127}\Z")
_SECRET_REF = re.compile(r"env:([A-Za-z_][A-Za-z0-9_]*)\Z")
_AUTH_SUFFIX = re.compile(r"[A-Za-z_][A-Za-z0-9_]{0,63}\Z")
_AUTH_PREFIXES = {
    "bearer": "OPENJULES_INGRESS_BEARER_",
    "github_hmac_sha256": "OPENJULES_INGRESS_HMAC_",
}
_REPOSITORY = re.compile(r"[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+\Z")
_HOSTNAME = re.compile(r"[a-z0-9](?:[a-z0-9.-]*[a-z0-9])?\Z")
SUPPORTED_OPERATIONS = frozenset({"task.start", "review.start", "receipt.read"})


class IngressError(ValueError):
    """Only fixed codes are safe to expose; never include submitted data."""

    def __init__(self, code: str, status: int = 422, *, receipt=None):
        self.code = code
        self.status = status
        self.receipt = receipt
        super().__init__(code)


def _error(code="invalid_schema", status=422):
    raise IngressError(code, status)


def _unique_object(pairs):
    result = {}
    for key, value in pairs:
        if key in result:
            _error("duplicate_field")
        result[key] = value
    return result


def strict_json(raw: bytes, maximum: int = BODY_LIMIT):
    if not isinstance(raw, bytes):
        _error()
    if len(raw) > maximum:
        _error("body_too_large", 413)
    try:
        return json.loads(
            raw.decode("utf-8"), object_pairs_hook=_unique_object,
            parse_constant=lambda _: _error("invalid_json"),
        )
    except IngressError:
        raise
    except (UnicodeError, ValueError, TypeError, RecursionError):
        _error("invalid_json")


def canonical_json(value) -> str:
    try:
        return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"), allow_nan=False)
    except (ValueError, TypeError, RecursionError):
        _error("invalid_schema")


def digest_json(value) -> str:
    return hashlib.sha256(canonical_json(value).encode("utf-8")).hexdigest()


def exact_object(value, required, optional=()):
    if type(value) is not dict or not set(required) <= set(value):
        _error()
    if set(value) - set(required) - set(optional):
        _error("unknown_field")
    return value


def identifier(value):
    if not isinstance(value, str) or not _ID.fullmatch(value):
        _error()
    return value


def positive_integer(value):
    if type(value) is not int or not 1 <= value <= MAX_INTEGER:
        _error()
    return value


def bounded_text(value, maximum, *, empty=False):
    if not isinstance(value, str) or "\x00" in value:
        _error()
    try:
        size = len(value.encode("utf-8"))
    except UnicodeError:
        _error()
    if size > maximum or (not empty and not size):
        _error()
    return value


def bounded_task(payload):
    """No Pydantic coercion or client-controlled execution configuration."""
    exact_object(payload, {"issue_id", "issue_title", "issue_body"})
    return {
        "issue_id": positive_integer(payload["issue_id"]),
        "issue_title": bounded_text(payload["issue_title"], 1024),
        "issue_body": bounded_text(payload["issue_body"], TASK_BODY_LIMIT, empty=True),
    }


def branch_name(value):
    """The same literal branch grammar for enrolled tasks and exact reviews."""
    branch = bounded_text(value, 256)
    if (branch in ("@", "HEAD") or branch.startswith(("-", "/")) or branch.endswith(("/", "."))
            or any(x in branch for x in ("..", "@{", "//"))
            or any(part.startswith(".") or part.endswith(".lock") for part in branch.split("/"))
            or any(ord(c) < 33 or ord(c) == 127 or c in "~^:?*[\\" for c in branch)):
        _error("invalid_branch")
    return branch


def absolute_path(value):
    bounded_text(value, 4096)
    path = Path(value)
    if not path.is_absolute() or str(path) != value or ".." in path.parts:
        _error("invalid_path")
    return path


def read_private_json(path, maximum=POLICY_LIMIT):
    """Validate the opened regular file, its ownership, and its bounded bytes."""
    path = absolute_path(os.fspath(path))
    try:
        if path.parent.resolve(strict=True) != path.parent:
            _error("private_file_unavailable", 503)
        fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
        with os.fdopen(fd, "rb") as stream:
            info = os.fstat(stream.fileno())
            if (
                not stat.S_ISREG(info.st_mode)
                or info.st_uid != os.getuid()
                or stat.S_IMODE(info.st_mode) & 0o077
                or info.st_nlink != 1
                or info.st_size > maximum
            ):
                _error("private_file_unavailable", 503)
            raw = stream.read(maximum + 1)
        return strict_json(raw, maximum)
    except IngressError:
        raise
    except (OSError, RuntimeError):
        _error("private_file_unavailable", 503)


def _origin(value, mode):
    bounded_text(value, 512)
    try:
        parsed = urlsplit(value)
        port = parsed.port
    except ValueError:
        _error("invalid_origin")
    if (
        parsed.username is not None or parsed.password is not None
        or parsed.query or parsed.fragment or parsed.path not in ("", "/")
        or not parsed.netloc or parsed.netloc != parsed.netloc.lower()
        or any(c.isspace() for c in value)
    ):
        _error("invalid_origin")
    if mode == "local_only":
        if parsed.scheme != "http" or parsed.hostname not in ("127.0.0.1", "::1") or port is None:
            _error("invalid_origin")
        authority = f"[{parsed.hostname}]:{port}" if parsed.hostname == "::1" else f"{parsed.hostname}:{port}"
    else:
        if parsed.scheme != "https" or not parsed.hostname:
            _error("invalid_origin")
        if parsed.hostname != "::1" and not _HOSTNAME.fullmatch(parsed.hostname):
            _error("invalid_origin")
        authority = parsed.netloc
    if port is not None and not 1 <= port <= 65535:
        _error("invalid_origin")
    if parsed.netloc != authority:
        _error("invalid_origin")
    return f"{parsed.scheme}://{authority}", authority


@dataclass(frozen=True)
class Binding:
    binding_id: str
    forge: str
    repository: str
    repository_id: int
    installation_id: int | None
    clone_url: str
    default_branch: str
    review_profile: object | None = field(default=None, repr=False)

    @property
    def canonical_repository(self):
        return f"github:{self.repository_id}"

    def effect_input(self):
        return {
            "binding_id": self.binding_id, "forge": self.forge,
            "repository": self.repository, "repository_id": self.repository_id,
            "installation_id": self.installation_id, "clone_url": self.clone_url,
            "default_branch": self.default_branch,
        }


@dataclass(frozen=True)
class Principal:
    principal_id: str
    kind: str
    actor_ids: frozenset[int]
    grants: Mapping[str, frozenset[str]]
    _secret_ref: str = field(repr=False)
    _secret: str = field(repr=False)


class _Epoch:
    def __init__(self):
        self.lock = threading.RLock()
        self.revoked = False


def _assert_auth_environment_separation(principals, environment):
    """Reject equal-value ambient aliases; this is not general secret tainting."""
    if len(environment) > 4096:
        _error("authentication_environment_unavailable", 503)
    try:
        current = tuple(environment.items())
    except (RuntimeError, TypeError):
        _error("authentication_environment_unavailable", 503)
    for principal in principals:
        for name, value in current:
            if (name != principal._secret_ref and isinstance(value, str) and value.isascii()
                    and hmac.compare_digest(value, principal._secret)):
                _error("ingress_execution_secret_alias", 503)


@dataclass(frozen=True)
class Policy:
    policy_id: str
    digest: str
    mode: str
    origin: str
    authority: str
    store_path: Path
    journal_id: str
    bindings: Mapping[str, Binding]
    principals: Mapping[str, Principal]
    _path: Path = field(repr=False)
    _environment: Mapping[str, str] = field(repr=False, compare=False)
    _epoch: _Epoch = field(default_factory=_Epoch, repr=False, compare=False)

    def ensure_current(self):
        with self._epoch.lock:
            if self._epoch.revoked:
                _error("policy_epoch_revoked", 503)
            try:
                require_legacy_execution()
                if digest_json(read_private_json(self._path)) != self.digest:
                    _error("policy_changed", 503)
                for principal in self.principals.values():
                    current = self._environment.get(principal._secret_ref)
                    if not isinstance(current, str) or not hmac.compare_digest(
                        current.encode("utf-8"), principal._secret.encode("utf-8")
                    ):
                        _error("credentials_changed", 503)
                _assert_auth_environment_separation(self.principals.values(), self._environment)
            except Exception as exc:
                # Returning the old bytes or credentials does not reopen this
                # owner epoch after revocation has actually been observed.
                self._epoch.revoked = True
                if isinstance(exc, LegacyExecutionRefused) or (isinstance(exc, IngressError) and exc.status == 503):
                    raise
                _error("policy_unavailable", 503)

    def authenticate_bearer(self, token):
        self.ensure_current()
        if not isinstance(token, str):
            _error("authentication_required", 401)
        try:
            token_bytes = token.encode("utf-8")
        except UnicodeError:
            _error("authentication_required", 401)
        if not 1 <= len(token_bytes) <= 4096:
            _error("authentication_required", 401)
        matched = None
        for principal in self.principals.values():
            if principal.kind == "bearer" and hmac.compare_digest(
                token_bytes, principal._secret.encode("utf-8")
            ):
                matched = principal
        if matched is None:
            _error("authentication_required", 401)
        return matched

    def github_auth(self):
        self.ensure_current()
        values = [p for p in self.principals.values() if p.kind == "github_hmac_sha256"]
        if len(values) != 1:
            _error("authentication_required", 401)
        return values[0], values[0]._secret

    def require_grant(self, principal_id, binding_id, operation):
        identifier(principal_id)
        identifier(binding_id)
        principal = self.principals.get(principal_id)
        binding = self.bindings.get(binding_id)
        if principal is None or binding is None or operation not in principal.grants.get(binding_id, ()):
            _error("scope_denied", 403)
        return binding

    def assert_execution_separation(self, values):
        """Compare selected host values without opening files or using clients.

        The execution adapter supplies only the actual legacy credential/config
        sources it can route to providers, executors or guests. Authentication
        secrets cannot serve either role by environment name or equal value.
        Diagnostics deliberately disclose neither a variable name nor a value.
        """
        if not isinstance(values, Mapping) or len(values) > MAX_MEMBERS:
            _error("execution_separation_unavailable", 503)
        for name, value in values.items():
            if (not isinstance(name, str) or _SECRET_REF.fullmatch("env:" + name) is None
                    or (value is not None and not isinstance(value, str))):
                _error("execution_separation_unavailable", 503)
            try:
                encoded = None if value is None else value.encode("utf-8")
            except UnicodeError:
                _error("execution_separation_unavailable", 503)
            if encoded is not None and len(encoded) > 131_072:
                _error("execution_separation_unavailable", 503)
            for principal in self.principals.values():
                if name == principal._secret_ref or (
                    encoded is not None and hmac.compare_digest(encoded, principal._secret.encode("utf-8"))
                ):
                    _error("ingress_execution_secret_alias", 503)

    def assert_no_ingress_secrets(self, normalized):
        """Refuse literal frozen authentication values in admitted strings.

        Callers supply the already bounded normalized task/binding/source tree.
        This compares configured literal values only. It neither decodes other
        encodings nor detects arbitrary secret content. It performs no I/O.
        """
        pending, visited, string_bytes = [normalized], 0, 0
        while pending:
            value = pending.pop()
            visited += 1
            if visited > 128:
                _error("invalid_schema")
            if type(value) is dict:
                if len(value) > 128 or any(type(key) is not str for key in value):
                    _error("invalid_schema")
                for key, child in value.items():
                    pending.extend((key, child))
            elif isinstance(value, str):
                try:
                    string_bytes += len(value.encode("utf-8"))
                except UnicodeError:
                    _error("invalid_schema")
                if string_bytes > BODY_LIMIT:
                    _error("invalid_schema")
                if any(principal._secret in value for principal in self.principals.values()):
                    _error("ingress_secret_in_input")
            elif value is not None and type(value) is not int:
                _error("invalid_schema")


def load_policy(path, environ=None):
    require_legacy_execution()
    environment = os.environ if environ is None else environ
    path = absolute_path(os.fspath(path))
    value = read_private_json(path)
    exact_object(value, {
        "schema_version", "policy_id", "mode", "transport", "receipt_store", "bindings", "principals",
    })
    if type(value["schema_version"]) is not int or value["schema_version"] != 1:
        _error("unsupported_policy", 503)
    policy_id = identifier(value["policy_id"])
    if value["mode"] not in ("local_only", "remote"):
        _error()
    transport = exact_object(value["transport"], {"external_origin"})
    origin, authority = _origin(transport["external_origin"], value["mode"])
    receipt = exact_object(value["receipt_store"], {"path", "journal_id"})
    store_path, journal_id = absolute_path(receipt["path"]), identifier(receipt["journal_id"])
    bindings = {}
    if type(value["bindings"]) is not list or len(value["bindings"]) > MAX_MEMBERS:
        _error()
    for item in value["bindings"]:
        exact_object(item, {"binding_id", "forge", "repository", "repository_id", "installation_id", "clone_url", "default_branch", "cohort_profiles"}, {"standalone_review"})
        name = identifier(item["binding_id"])
        if name in bindings:
            _error("duplicate_binding")
        if item["forge"] != "github" or type(item["cohort_profiles"]) is not dict or item["cohort_profiles"]:
            _error("unsupported_capability", 404)
        repository = bounded_text(item["repository"], 256)
        if not _REPOSITORY.fullmatch(repository) or any(part in (".", "..") for part in repository.split("/")):
            _error()
        repository_id = positive_integer(item["repository_id"])
        installation = item["installation_id"]
        if installation is not None:
            positive_integer(installation)
        clone_url = bounded_text(item["clone_url"], 512)
        if clone_url not in (f"https://github.com/{repository}", f"https://github.com/{repository}.git"):
            _error("unsupported_clone_url", 404)
        branch = branch_name(item["default_branch"])
        review_profile = None
        if "standalone_review" in item:
            from src.api.review_policy import parse_review_profile
            review_profile = parse_review_profile(item["standalone_review"], installation)
        bindings[name] = Binding(name, "github", repository, repository_id, installation, clone_url, branch, review_profile)
    principals = {}
    if type(value["principals"]) is not list or len(value["principals"]) > MAX_MEMBERS:
        _error()
    authentication_values, hmac_count = set(), 0
    for item in value["principals"]:
        exact_object(item, {"principal_id", "authentication", "grants"}, {"github_actor_ids"})
        name = identifier(item["principal_id"])
        if name in principals:
            _error("duplicate_principal")
        authentication = exact_object(item["authentication"], {"kind", "secret_ref"})
        kind = authentication["kind"]
        if kind not in ("bearer", "github_hmac_sha256"):
            _error("unsupported_authentication", 404)
        ref = authentication["secret_ref"]
        match = _SECRET_REF.fullmatch(ref) if isinstance(ref, str) else None
        if match is None:
            _error("invalid_secret_reference")
        env_name = match.group(1)
        prefix = _AUTH_PREFIXES[kind]
        if not env_name.startswith(prefix) or _AUTH_SUFFIX.fullmatch(env_name[len(prefix):]) is None:
            _error("invalid_secret_reference")
        secret = environment.get(env_name)
        if not isinstance(secret, str) or any(ord(c) < 33 or ord(c) > 126 for c in secret) or not 1 <= len(secret) <= 4096:
            _error("authentication_unavailable", 503)
        if secret in authentication_values:
            _error("ambiguous_authentication", 503)
        authentication_values.add(secret)
        actors = frozenset()
        if kind == "bearer":
            if "github_actor_ids" in item:
                _error()
        else:
            hmac_count += 1
            if hmac_count > 1:
                _error("ambiguous_authentication", 503)
            source_actors = item.get("github_actor_ids")
            if type(source_actors) is not list or not 1 <= len(source_actors) <= MAX_MEMBERS:
                _error()
            actors = frozenset(positive_integer(actor) for actor in source_actors)
            if len(actors) != len(source_actors):
                _error("duplicate_actor")
        if type(item["grants"]) is not list or len(item["grants"]) > MAX_MEMBERS:
            _error()
        grants = {}
        for grant in item["grants"]:
            exact_object(grant, {"binding_id", "operations"})
            binding_id = identifier(grant["binding_id"])
            operations = grant["operations"]
            if binding_id not in bindings or binding_id in grants or type(operations) is not list or any(not isinstance(op, str) for op in operations):
                _error()
            if len(operations) != len(set(operations)):
                _error("duplicate_operation")
            if not set(operations) <= SUPPORTED_OPERATIONS:
                _error("unsupported_capability", 404)
            if "review.start" in operations and (
                kind != "github_hmac_sha256" or bindings[binding_id].review_profile is None
            ):
                _error("unsupported_capability", 404)
            grants[binding_id] = frozenset(operations)
        principals[name] = Principal(name, kind, actors, MappingProxyType(grants), env_name, secret)
    _assert_auth_environment_separation(principals.values(), environment)
    return Policy(policy_id, digest_json(value), value["mode"], origin, authority, store_path, journal_id,
                  MappingProxyType(bindings), MappingProxyType(principals), path, environment)
