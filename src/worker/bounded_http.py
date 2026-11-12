"""Shared bounded POST transport; callers retain payload and parsing policy."""

from __future__ import annotations

import asyncio
from typing import Callable

import httpx


class HTTPResponseRejected(RuntimeError):
    """The fixed status, content-encoding or response-byte contract was rejected."""

    def __init__(self):
        super().__init__("bounded HTTP response rejected")


async def post_bounded_json(
    endpoint: str,
    payload: dict,
    headers: dict[str, str],
    *,
    timeout_seconds: float,
    max_response_bytes: int,
    decode: Callable,
):
    # Keep decoding inside the same absolute timeout and HTTP ownership scopes.
    # There is no retry, redirect, environment-derived proxy or body logging.
    async with asyncio.timeout(timeout_seconds):
        async with httpx.AsyncClient(
            trust_env=False, follow_redirects=False, timeout=timeout_seconds
        ) as client:
            async with client.stream(
                "POST", endpoint, json=payload, headers=headers
            ) as response:
                if response.status_code != 200 or response.headers.get(
                    "Content-Encoding", "identity"
                ) not in {"", "identity"}:
                    raise HTTPResponseRejected()
                raw = bytearray()
                async for part in response.aiter_raw():
                    raw.extend(part)
                    if len(raw) > max_response_bytes:
                        raise HTTPResponseRejected()
                return decode(raw)
