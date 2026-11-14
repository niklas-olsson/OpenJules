"""Finite same-origin pairing for an already authorized standalone session.

This is a component boundary, not an HTTP listener or proof of TLS. A trusted
adapter supplies the actual connection's TLS flag and uncombined raw headers.
Host code prebinds a short-lived code to an existing core grant. Redemption
cannot select rights or issue a grant. Every later purpose is authorized again
by the core; browser-cookie expiry never extends a core right.

Records are bounded and process-local. Restart loses every code and cookie
alias, without replay or renewal. Core restart/LOST semantics independently
govern the backend and any deliberate retained-observation regrant.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import math
import re
import secrets
import threading
from typing import TYPE_CHECKING, Protocol
from urllib.parse import urlsplit
import json

if TYPE_CHECKING:
    from .types import Authorization, Clock


RIGHTS = frozenset({"observe", "control", "stop"})
COOKIE_NAME = "__Host-openjules-session"
SECRET = re.compile(r"[A-Za-z0-9_-]{43}\Z")
HEADER_NAME = re.compile(r"[!#$%&'*+.^_`|~0-9A-Za-z-]+\Z")
MAX_INTEGER = 2**53 - 1
SECURITY_HEADERS = frozenset({"host", "origin", "cookie", "x-csrf-token", "sec-fetch-site"})


class PairingDenied(ValueError):
    """A fixed public code, never request, credential or core-error content."""

    def __init__(self, code: str):
        self.code = code
        super().__init__(code)


class GrantAuthority(Protocol):
    def authorize(self, token: str, right: str) -> Authorization: ...
    def revoke(self, token: str) -> None: ...


@dataclass(frozen=True)
class PairingLimits:
    pending_codes: int = 8
    browser_sessions: int = 8
    issued_codes: int = 32
    redemption_attempts: int = 128
    pairing_ttl_ms: int = 60_000
    cookie_ttl_ms: int = 300_000

    def __post_init__(self):
        bounds = {"pending_codes": 64, "browser_sessions": 64,
                  "issued_codes": 128, "redemption_attempts": 256,
                  "pairing_ttl_ms": 60_000, "cookie_ttl_ms": 300_000}
        if any(type(getattr(self, name)) is not int or not 1 <= getattr(self, name) <= maximum
               for name, maximum in bounds.items()):
            raise PairingDenied("invalid_limits")


@dataclass(frozen=True, repr=False)
class RequestContext:
    method: str
    path: str
    tls: bool
    headers: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class PairingReply:
    set_cookie: str = field(repr=False)
    csrf_token: str = field(repr=False)
    authorization: Authorization
    expires_at_ms: int


@dataclass(frozen=True)
class SessionView:
    csrf_token: str = field(repr=False)
    authorization: Authorization
    expires_at_ms: int


@dataclass(frozen=True)
class AuthenticatedRequest:
    """Server-private input for a core call; never serialize the grant token."""

    grant_token: str = field(repr=False)
    authorization: Authorization


@dataclass(frozen=True)
class _Pending:
    grant_token: str = field(repr=False)
    identity: tuple[str, str, str, str]
    binding_right: str
    expires_at_ms: int
    deadline: float
    cookie_expires_at_ms: int
    cookie_deadline: float


@dataclass(frozen=True)
class _Session:
    grant_token: str = field(repr=False)
    csrf_token: str = field(repr=False)
    identity: tuple[str, str, str, str]
    binding_right: str
    expires_at_ms: int
    deadline: float


def _digest(value: str) -> str:
    return hashlib.sha256(value.encode("ascii")).hexdigest()


def _integer(value):
    if type(value) is not int or not 0 <= value <= MAX_INTEGER:
        raise PairingDenied("invalid_deadline")
    return value


def _identity(authorization, right):
    try:
        identity = tuple(getattr(authorization, name) for name in
                         ("actor_id", "session_id", "context_id", "target_id"))
        expiry = authorization.expires_at_ms
        if authorization.right != right or any(type(item) is not str or not 0 < len(item.encode("utf-8")) <= 512
                                              for item in identity):
            raise PairingDenied("invalid_authorization")
        _integer(expiry)
        return identity, expiry
    except (AttributeError, UnicodeError, TypeError):
        raise PairingDenied("invalid_authorization") from None


def _origin(value):
    if type(value) is not str or len(value) > 512 or any(ord(c) < 33 or ord(c) > 126 for c in value):
        raise PairingDenied("invalid_origin_configuration")
    try:
        parsed = urlsplit(value)
        if (parsed.scheme != "https" or not parsed.hostname or parsed.username is not None
                or parsed.password is not None or parsed.path or parsed.query or parsed.fragment
                or parsed.port in {0, 443} or parsed.netloc != parsed.netloc.lower()
                or value != "https://" + parsed.netloc or "%" in parsed.netloc
                or "\\" in parsed.netloc or parsed.netloc.endswith(":")):
            raise PairingDenied("invalid_origin_configuration")
        return value, parsed.netloc
    except ValueError:
        raise PairingDenied("invalid_origin_configuration") from None


def _headers(request, method, path, origin, authority):
    if (type(request) is not RequestContext or request.tls is not True or request.method != method
            or request.path != path or method not in {"GET", "POST"}
            or type(path) is not str or not path.startswith("/") or "?" in path or "#" in path
            or type(request.headers) is not tuple or len(request.headers) > 64):
        raise PairingDenied("invalid_request_context")
    selected, size = {}, 0
    for pair in request.headers:
        if type(pair) is not tuple or len(pair) != 2:
            raise PairingDenied("invalid_headers")
        name, value = pair
        if (type(name) is not str or type(value) is not str or not HEADER_NAME.fullmatch(name)
                or len(name) > 128 or len(value) > 4096
                or any(ord(character) < 32 or ord(character) > 126 for character in value)):
            raise PairingDenied("invalid_headers")
        size += len(name) + len(value)
        if size > 16_384:
            raise PairingDenied("invalid_headers")
        name = name.lower()
        if name in SECURITY_HEADERS:
            if name in selected:
                raise PairingDenied("duplicate_security_header")
            selected[name] = value
    if selected.get("host") != authority:
        raise PairingDenied("host_denied")
    observed = selected.get("origin")
    if observed is not None and observed != origin:
        raise PairingDenied("origin_denied")
    if method == "POST" and observed != origin:
        raise PairingDenied("origin_required")
    if method == "GET" and observed is None and selected.get("sec-fetch-site") != "same-origin":
        raise PairingDenied("same_origin_read_required")
    return selected


def _pairing_body(raw):
    if type(raw) is not bytes or not 1 <= len(raw) <= 512:
        raise PairingDenied("invalid_pairing_body")
    def unique(items):
        result = {}
        for key, value in items:
            if key in result:
                raise PairingDenied("invalid_pairing_body")
            result[key] = value
        return result
    try:
        value = json.loads(raw.decode("utf-8"), object_pairs_hook=unique,
                           parse_constant=lambda _: (_ for _ in ()).throw(PairingDenied("invalid_pairing_body")))
    except (ValueError, UnicodeError, RecursionError):
        raise PairingDenied("invalid_pairing_body") from None
    if type(value) is not dict or set(value) != {"code"} or type(value["code"]) is not str or not SECRET.fullmatch(value["code"]):
        raise PairingDenied("invalid_pairing_body")
    return value["code"]


class PairingBroker:
    """One process-local broker. All issuer/revocation calls are host-only.

    binding_right is a host choice. Bind an owner alias through its longer Stop
    right when observation/control expire sooner; it never supplies those other
    rights. Protected GET /session can recover the same CSRF value after reload
    under that original binding. No request chooses a different binding.
    """

    def __init__(self, authority: GrantAuthority, origin: str, *, clock: Clock,
                 limits: PairingLimits = PairingLimits()):
        if type(limits) is not PairingLimits:
            raise PairingDenied("invalid_limits")
        self._origin, self._host = _origin(origin)
        self._authority, self._clock, self._limits = authority, clock, limits
        self._lock = threading.RLock()
        self._codes: dict[str, _Pending] = {}
        self._sessions: dict[str, _Session] = {}
        self._secret_hashes: set[str] = set()
        # Only a grant that already consumed an issued code can enter this set,
        # so its size is bounded by issued_codes. An unconfirmed core revocation
        # never permits another alias or pairing code for the original grant.
        self._revoked_grants: set[str] = set()
        self._issued = self._attempts = 0
        self._last_monotonic = -1.0

    def _now(self):
        wall, mono = self._clock.wall_ms(), self._clock.monotonic()
        _integer(wall)
        if type(mono) not in {int, float} or not math.isfinite(mono) or mono < 0 or mono < self._last_monotonic:
            raise PairingDenied("invalid_clock")
        self._last_monotonic = mono
        return wall, mono

    def _purge(self, wall, mono):
        for values in (self._codes, self._sessions):
            for key, record in list(values.items()):
                if wall >= record.expires_at_ms or mono >= record.deadline:
                    del values[key]

    def _authorize(self, token, right, identity=None):
        if type(right) is not str or right not in RIGHTS:
            raise PairingDenied("invalid_purpose")
        if _digest(token) in self._revoked_grants:
            raise PairingDenied("grant_revocation_pending")
        try:
            authorized = self._authority.authorize(token, right)
        except Exception:
            raise PairingDenied("grant_denied") from None
        actual, expiry = _identity(authorized, right)
        if identity is not None and actual != identity:
            raise PairingDenied("grant_identity_changed")
        return authorized, actual, expiry

    def _secret(self, forbidden):
        for _ in range(3):
            value = secrets.token_urlsafe(32)
            if type(value) is str and SECRET.fullmatch(value) and value != forbidden:
                digest = _digest(value)
                if digest not in self._secret_hashes:
                    self._secret_hashes.add(digest)
                    return value
        raise PairingDenied("entropy_unavailable")

    def _confirmed(self, record, authorization):
        # Authorization is a trusted call but can take time. Do not return a
        # cookie-authenticated operation after the alias or right has expired.
        wall, mono = self._now()
        if (wall >= record.expires_at_ms or mono >= record.deadline
                or wall >= authorization.expires_at_ms):
            raise PairingDenied("session_unavailable")

    def issue_code(self, grant_token: str, pairing_expiry_ms: int, *, binding_right: str = "observe") -> str:
        """Trusted host prebinding only. Never expose this as a public issuer."""
        if (type(grant_token) is not str or not 32 <= len(grant_token) <= 256
                or not re.fullmatch(r"[A-Za-z0-9_-]+", grant_token)):
            raise PairingDenied("invalid_host_grant")
        _integer(pairing_expiry_ms)
        with self._lock:
            wall, mono = self._now()
            self._purge(wall, mono)
            if self._issued >= self._limits.issued_codes or len(self._codes) >= self._limits.pending_codes:
                raise PairingDenied("pairing_capacity")
            _, identity, grant_expiry = self._authorize(grant_token, binding_right)
            if not wall < pairing_expiry_ms <= min(grant_expiry, wall + self._limits.pairing_ttl_ms):
                raise PairingDenied("invalid_pairing_expiry")
            cookie_expiry = min(grant_expiry, wall + self._limits.cookie_ttl_ms)
            deadline = mono + (pairing_expiry_ms - wall) / 1000
            cookie_deadline = mono + (cookie_expiry - wall) / 1000
            if not math.isfinite(deadline) or not math.isfinite(cookie_deadline):
                raise PairingDenied("invalid_deadline")
            code = self._secret(grant_token)
            self._codes[_digest(code)] = _Pending(grant_token, identity, binding_right,
                pairing_expiry_ms, deadline, cookie_expiry, cookie_deadline)
            self._issued += 1
            return code

    def redeem(self, request: RequestContext, body: bytes) -> PairingReply:
        """Consume before returning. A lost response never reissues the code."""
        _headers(request, "POST", "/pair", self._origin, self._host)
        code = _pairing_body(body)
        with self._lock:
            wall, mono = self._now()
            self._purge(wall, mono)
            if self._attempts >= self._limits.redemption_attempts:
                raise PairingDenied("pairing_attempt_limit")
            self._attempts += 1
            pending = self._codes.get(_digest(code))
            if pending is None:
                raise PairingDenied("pairing_unavailable")
            if len(self._sessions) >= self._limits.browser_sessions:
                raise PairingDenied("session_capacity")
            authorized, _, _ = self._authorize(pending.grant_token, pending.binding_right, pending.identity)
            wall, mono = self._now()
            if (wall >= pending.expires_at_ms or mono >= pending.deadline
                    or wall >= pending.cookie_expires_at_ms or mono >= pending.cookie_deadline):
                del self._codes[_digest(code)]
                raise PairingDenied("pairing_unavailable")
            self._confirmed(pending, authorized)
            alias, csrf = self._secret(pending.grant_token), self._secret(pending.grant_token)
            record = _Session(pending.grant_token, csrf, pending.identity, pending.binding_right,
                              pending.cookie_expires_at_ms, pending.cookie_deadline)
            del self._codes[_digest(code)]
            self._sessions[_digest(alias)] = record
            seconds = math.ceil(min((record.expires_at_ms - wall) / 1000, record.deadline - mono))
            cookie = f"{COOKIE_NAME}={alias}; Path=/; Max-Age={seconds}; Secure; HttpOnly; SameSite=Strict"
            return PairingReply(cookie, csrf, authorized, record.expires_at_ms)

    def _session(self, headers):
        raw = headers.get("cookie", "")
        prefix = COOKIE_NAME + "="
        if not raw.startswith(prefix) or not SECRET.fullmatch(raw[len(prefix):]):
            raise PairingDenied("session_unavailable")
        wall, mono = self._now()
        self._purge(wall, mono)
        record = self._sessions.get(_digest(raw[len(prefix):]))
        if record is None:
            raise PairingDenied("session_unavailable")
        return record

    def session(self, request: RequestContext) -> SessionView:
        """Protected bootstrap read for reload, with no rights/expiry renewal."""
        headers = _headers(request, "GET", "/session", self._origin, self._host)
        with self._lock:
            record = self._session(headers)
            authorized, _, _ = self._authorize(record.grant_token, record.binding_right, record.identity)
            self._confirmed(record, authorized)
            return SessionView(record.csrf_token, authorized, record.expires_at_ms)

    def authorize_request(self, request: RequestContext, *, right: str,
                          method: str, path: str) -> AuthenticatedRequest:
        """The server route chooses right/method/path, never the request body.

        This returns a private core-call input. The core must still validate the
        operation's own right, original target and all supplied generations.
        """
        headers = _headers(request, method, path, self._origin, self._host)
        with self._lock:
            record = self._session(headers)
            if method == "POST":
                supplied = headers.get("x-csrf-token", "")
                if not SECRET.fullmatch(supplied) or not hmac.compare_digest(supplied, record.csrf_token):
                    raise PairingDenied("csrf_denied")
            authorized, _, _ = self._authorize(record.grant_token, right, record.identity)
            self._confirmed(record, authorized)
            return AuthenticatedRequest(record.grant_token, authorized)

    def revoke(self, cookie_alias: str) -> None:
        """Host-only revocation, locally fencing every alias of the same grant.

        The local intent survives an unknown core outcome for this process's
        lifetime. Only a genuinely different host-issued grant may pair again.
        """
        if type(cookie_alias) is not str or not SECRET.fullmatch(cookie_alias):
            raise PairingDenied("session_unavailable")
        with self._lock:
            record = self._sessions.get(_digest(cookie_alias))
            if record is None:
                raise PairingDenied("session_unavailable")
            grant_digest = _digest(record.grant_token)
            self._revoked_grants.add(grant_digest)
            for values in (self._sessions, self._codes):
                for key, bound in list(values.items()):
                    if _digest(bound.grant_token) == grant_digest:
                        del values[key]
            try:
                self._authority.revoke(record.grant_token)
            except Exception:
                raise PairingDenied("revocation_unconfirmed") from None
