"""Authenticated canonical authority client for the managed worker path.

This client never falls back to the in-memory legacy Polyphony client. HTTP
failures are uncertain outcomes. Callers retain the original request identity.
"""

from __future__ import annotations

import asyncio
import json
import math
import os
import re
from urllib.parse import urlsplit

import httpx

from src.worker.lifecycle import WorkerScope


class AuthorityUnavailable(RuntimeError):
    """The canonical reply was unavailable or did not match its scope."""


UNSUPPORTED_CHILD_OUTCOME_REASON = (
    "Canonical managed authority is unsupported: child_initial_outcome=1"
)


class AuthorityUnsupported(AuthorityUnavailable):
    """A validated authority lacks the configured initial child outcome version."""

    def __init__(self):
        super().__init__(UNSUPPORTED_CHILD_OUTCOME_REASON)


class AuthorityRejected(AuthorityUnavailable):
    def __init__(self, status: int, *, claim_not_allocated: bool = False):
        self.status = status
        self.claim_not_allocated = claim_not_allocated
        super().__init__(f"Canonical authority rejected the request (HTTP {status})")


def token_from_reference(reference: str) -> str:
    if not isinstance(reference, str) or not re.fullmatch(
        r"env:[A-Za-z_][A-Za-z0-9_]*", reference
    ):
        raise ValueError("credential must be an environment-variable reference")
    token = os.environ.get(reference[4:], "")
    if len(token) < 32 or any(character.isspace() for character in token):
        raise ValueError("referenced credential is missing or invalid")
    return token


class ManagedAuthorityClient:
    def __init__(
        self,
        endpoint: str,
        token_ref: str,
        *,
        timeout_seconds: float = 10,
        max_response_bytes: int = 5_000_000,
    ):
        parts = urlsplit(endpoint)
        if (
            parts.scheme not in {"http", "https"}
            or not parts.hostname
            or parts.username is not None
            or parts.password is not None
            or parts.query
            or parts.fragment
            or parts.path not in {"", "/"}
            or (
                parts.scheme == "http"
                and parts.hostname not in {"localhost", "127.0.0.1", "::1"}
            )
        ):
            raise ValueError(
                "authority endpoint requires HTTPS or a loopback HTTP root"
            )
        # Access .port now so malformed URLs fail during configuration.
        parts.port
        if (
            isinstance(timeout_seconds, bool)
            or not isinstance(timeout_seconds, (int, float))
            or not math.isfinite(timeout_seconds)
            or not 0 < timeout_seconds <= 120
        ):
            raise ValueError("authority timeout must be between zero and 120 seconds")
        if (
            type(max_response_bytes) is not int
            or not 1024 <= max_response_bytes <= 20_000_000
        ):
            raise ValueError("invalid authority response limit")
        if not isinstance(token_ref, str) or not re.fullmatch(
            r"env:[A-Za-z_][A-Za-z0-9_]*", token_ref
        ):
            raise ValueError("authority credential must be an environment reference")
        self.endpoint = endpoint.rstrip("/")
        self.token_ref = token_ref
        self.timeout_seconds = timeout_seconds
        self.max_response_bytes = max_response_bytes

    async def _request_async(self, method: str, operation: str, data: dict) -> dict:
        # The timeout encloses connect, upload, headers and streaming body, so a
        # server cannot hold a worker indefinitely by trickling response bytes.
        try:
            token = token_from_reference(self.token_ref)
            async with asyncio.timeout(self.timeout_seconds):
                async with httpx.AsyncClient(
                    trust_env=False,
                    follow_redirects=False,
                    timeout=self.timeout_seconds,
                    headers={"Authorization": f"Bearer {token}"},
                ) as client:
                    arguments = {"params": data} if method == "GET" else {"json": data}
                    async with client.stream(
                        method, f"{self.endpoint}/managed/{operation}", **arguments
                    ) as response:
                        if response.status_code != 200:
                            # Never copy untrusted response bodies or headers
                            # into logs, including authentication errors.
                            unallocated = False
                            if operation == "claim" and response.status_code == 409:
                                error_body = bytearray()
                                async for part in response.aiter_bytes():
                                    error_body.extend(part)
                                    if len(error_body) > 4096:
                                        break
                                if len(error_body) <= 4096:
                                    try:
                                        rejection = json.loads(error_body)
                                        unallocated = (
                                            isinstance(rejection, dict)
                                            and rejection.get("code")
                                            == "claim_not_allocated"
                                            and rejection.get("allocated") is False
                                        )
                                    except ValueError:
                                        pass
                            raise AuthorityRejected(
                                response.status_code, claim_not_allocated=unallocated
                            )
                        content = bytearray()
                        async for part in response.aiter_bytes():
                            content.extend(part)
                            if len(content) > self.max_response_bytes:
                                raise AuthorityUnavailable(
                                    "Canonical response exceeds its limit"
                                )
                        result = json.loads(content)
            if not isinstance(result, dict):
                raise AuthorityUnavailable("Canonical response must be an object")
            return result
        except AuthorityUnavailable:
            raise
        except (OSError, ValueError, httpx.HTTPError, TimeoutError):
            raise AuthorityUnavailable(
                "Canonical authority request did not complete"
            ) from None

    def request(self, method: str, operation: str, data: dict) -> dict:
        if method not in {"GET", "POST"} or operation not in {
            "capabilities",
            "snapshot",
            "claim",
            "permission",
            "capture",
            "observe",
            "candidate",
        }:
            raise ValueError("unsupported managed operation")
        return asyncio.run(self._request_async(method, operation, data))

    @staticmethod
    def scope_payload(scope: WorkerScope) -> dict:
        return {
            "schema_version": 1,
            "deployment_id": scope.deployment_id,
            "repository": scope.repository,
        }

    @staticmethod
    def verify_scope(result: dict, scope: WorkerScope) -> dict:
        if (
            type(result.get("schema_version")) is not int
            or result["schema_version"] != 1
            or result.get("deployment_id") != scope.deployment_id
            or result.get("repository") != scope.repository
        ):
            raise AuthorityUnavailable("Canonical response scope does not match")
        return result

    def capabilities(self, scope: WorkerScope, profile: str, base: str) -> dict:
        result = self.request(
            "GET",
            "capabilities",
            {
                "deployment_id": scope.deployment_id,
                "repository": scope.repository,
                "profile": profile,
            },
        )
        self.verify_scope(result, scope)
        if (
            result.get("service") != "keystone-polyphony"
            or result.get("protocol") != "managed-runtime-v1"
            or result.get("profile") != profile
            or result.get("base") != base
            or result.get("managed_dispatch") is not True
            or result.get("external_root") is not True
            or result.get("profile_supported") is not True
        ):
            raise AuthorityUnavailable(
                "Canonical external-runtime capability is not established"
            )
        return result

    def snapshot(self, scope: WorkerScope) -> dict:
        result = self.request(
            "GET",
            "snapshot",
            {"deployment_id": scope.deployment_id, "repository": scope.repository},
        )
        return self.verify_scope(result, scope)

    def call(self, operation: str, scope: WorkerScope, **payload) -> dict:
        result = self.request("POST", operation, self.scope_payload(scope) | payload)
        return self.verify_scope(result, scope)
