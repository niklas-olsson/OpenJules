"""One explicit, bounded model route for the standalone review profile.

The neutral HTTP ownership rules match bounded_http: no ambient proxy,
redirect, retry, content decompression or provider-error logging. This route
additionally binds each actual send to its original review effect deadline.
It does not construct canonical task permissions or use the managed broker.
"""

from __future__ import annotations

import asyncio
from dataclasses import dataclass
import hashlib
import json
import math
import re
from types import MappingProxyType
from collections.abc import Mapping

import httpx

from .review_contract import ReviewError


_CALL_ID = re.compile(r"[A-Za-z0-9_-]{1,128}\Z")
_TOOLS = frozenset({"read_file", "write_file", "apply_patch", "run_command", "list_files"})


def _pairs(items):
    result = {}
    for key, value in items:
        if key in result:
            raise ValueError("duplicate field")
        result[key] = value
    return result


def strict_json(raw):
    return json.loads(raw, object_pairs_hook=_pairs,
                      parse_constant=lambda value: (_ for _ in ()).throw(ValueError("nonfinite number")))


def bounded_json(value, maximum):
    """Check encoded chunks before accumulating the local request body."""
    body = bytearray()
    for piece in json.JSONEncoder(ensure_ascii=True, allow_nan=False, separators=(",", ":")).iterencode(value):
        part = piece.encode("ascii")
        if len(part) > maximum - len(body):
            raise ReviewError("capacity_exhausted")
        body.extend(part)
    return bytes(body)


def _freeze(value):
    if type(value) is dict:
        return MappingProxyType({key: _freeze(item) for key, item in value.items()})
    if type(value) is list:
        return tuple(_freeze(item) for item in value)
    return value


def assert_safe_decoded(operation, value, maximum):
    """Check selected literal secrets in an already bounded decoded JSON tree.

    This is not taint tracking or a claim about transformed private facts.
    Keys and nested strings are checked before any JSON/base64 re-encoding.
    """
    pending, consumed = [value], 0
    while pending:
        item = pending.pop()
        consumed += 1
        if type(item) is str:
            try:
                raw = item.encode("utf-8")
            except UnicodeError:
                operation.fail("protocol_refused")
            consumed += len(raw)
            operation.assert_safe(raw)
        elif type(item) in (dict, type(MappingProxyType({}))):
            if any(type(key) is not str for key in item):
                operation.fail("protocol_refused")
            pending.extend(item.keys())
            pending.extend(item.values())
        elif type(item) in (list, tuple):
            pending.extend(item)
        elif item is not None and type(item) not in (bool, int, float):
            operation.fail("protocol_refused")
        if consumed > maximum or len(pending) > maximum - consumed:
            operation.fail("capacity_exhausted")


@dataclass(frozen=True)
class ReviewToolCall:
    id: str
    name: str
    arguments_json: str
    arguments: Mapping


@dataclass(frozen=True)
class ReviewModelReply:
    content: str | None
    tool_calls: tuple[ReviewToolCall, ...]

    def message(self):
        result = {"role": "assistant", "content": self.content}
        if self.tool_calls:
            result["tool_calls"] = [
                {"id": call.id, "type": "function",
                 "function": {"name": call.name, "arguments": call.arguments_json}}
                for call in self.tool_calls]
        return result


def _response(raw, *, allow_tools, maximum_calls, maximum_tokens):
    value = strict_json(raw)
    if (type(value) is not dict or not {"choices"} <= set(value)
            or set(value) - {"id", "object", "created", "model", "choices", "usage", "system_fingerprint", "service_tier"}):
        raise ValueError("response shape")
    choices = value["choices"]
    if type(choices) is not list or len(choices) != 1 or type(choices[0]) is not dict:
        raise ValueError("choices shape")
    choice = choices[0]
    if (set(choice) - {"index", "message", "finish_reason", "logprobs"}
            or not {"index", "message", "finish_reason"} <= set(choice)
            or type(choice["index"]) is not int or choice["index"] != 0
            or choice.get("logprobs") is not None):
        raise ValueError("choice shape")
    message = choice["message"]
    if (type(message) is not dict or not {"role", "content"} <= set(message)
            or set(message) - {"role", "content", "tool_calls", "refusal"}
            or message["role"] != "assistant" or message.get("refusal") is not None
            or (message["content"] is not None and type(message["content"]) is not str)):
        raise ValueError("message shape")
    calls = message.get("tool_calls", [])
    if type(calls) is not list or len(calls) > maximum_calls or (calls and not allow_tools):
        raise ValueError("tool shape")
    if choice["finish_reason"] != ("tool_calls" if calls else "stop"):
        raise ValueError("incomplete response")
    if not calls and (type(message["content"]) is not str or not message["content"].strip()):
        raise ValueError("empty response")
    output, identifiers = [], set()
    for call in calls:
        if (type(call) is not dict or set(call) != {"id", "type", "function"}
                or type(call["id"]) is not str or not _CALL_ID.fullmatch(call["id"])
                or call["id"] in identifiers or call["type"] != "function"):
            raise ValueError("tool identity")
        function = call["function"]
        if (type(function) is not dict or set(function) != {"name", "arguments"}
                or type(function["name"]) is not str or function["name"] not in _TOOLS
                or type(function["arguments"]) is not str):
            raise ValueError("tool function")
        arguments = strict_json(function["arguments"])
        if type(arguments) is not dict:
            raise ValueError("tool arguments")
        identifiers.add(call["id"])
        output.append(ReviewToolCall(call["id"], function["name"], function["arguments"], _freeze(arguments)))
    usage = value.get("usage")
    if usage is not None:
        if (type(usage) is not dict or set(usage) != {"prompt_tokens", "completion_tokens", "total_tokens"}
                or any(type(item) is not int or item < 0 for item in usage.values())
                or usage["completion_tokens"] > maximum_tokens
                or usage["total_tokens"] != usage["prompt_tokens"] + usage["completion_tokens"]):
            raise ValueError("usage shape")
    return ReviewModelReply(message["content"], tuple(output))


class StandaloneReviewModel:
    """Constructs no client until an original operation reserves a call.

    The injected client factory is trusted test infrastructure, not profile or
    provider data. Every original client/response is awaited through closure.
    A timeout closes local admission; it never asserts provider termination.
    """

    def __init__(self, *, client_factory=httpx.AsyncClient):
        self._client_factory = client_factory
        self._busy, self._retired, self._operation = False, False, None

    @staticmethod
    def _within_original_call(operation, effect):
        operation.check()
        # Synchronous parsing, validation and persistence are not preempted by
        # asyncio's timer. Their elapsed time consumes this same call cutoff.
        now = operation.now()
        if not math.isfinite(now) or now >= effect.deadline:
            operation.observe(effect, "outcome_unknown", code="deadline_exhausted")
            operation.fail("deadline_exhausted", unknown=True)

    def complete(self, operation, messages, *, tools=None):
        if self._busy or self._retired or (self._operation is not None and self._operation is not operation):
            operation.fail("protocol_refused")
        self._operation = operation
        operation.check()
        try:
            asyncio.get_running_loop()
        except RuntimeError:
            pass
        else:
            operation.fail("protocol_refused")
        model = operation.profile.document["model"]
        if type(messages) is not list or not messages:
            operation.fail("protocol_refused")
        if tools is not None and (type(tools) is not list or len(tools) != len(_TOOLS)
                                  or {item.get("function", {}).get("name") for item in tools} != _TOOLS):
            operation.fail("protocol_refused")
        payload = {"model": model["model"], "messages": messages, "temperature": model["temperature"],
                   "max_tokens": operation.limits["model_output_tokens_per_call"], "stream": False}
        if tools is not None:
            payload.update(tools=tools, tool_choice="auto")
        try:
            body = bounded_json(payload, operation.limits["model_request_bytes"])
            route = bounded_json({"url": model["url"], "model": model["model"],
                                  "temperature": model["temperature"]}, operation.limits["model_request_bytes"])
        except (ValueError, TypeError, RecursionError, UnicodeError):
            operation.fail("protocol_refused")
        except ReviewError as error:
            operation.fail(error.code)
        operation.assert_safe(body)
        effect = operation.reserve(
            "model", request_bytes=len(body), response_bytes=operation.limits["model_response_bytes"],
            output_tokens=operation.limits["model_output_tokens_per_call"],
            data={"payload_sha256": hashlib.sha256(body).hexdigest(), "route_sha256": hashlib.sha256(route).hexdigest()})
        headers = {"Content-Type": "application/json", "Accept-Encoding": "identity"}
        token = operation.claim.credentials.model_key
        if token is not None:
            if type(token) is not str or not token or any(char.isspace() or ord(char) < 33 or ord(char) == 127 for char in token):
                operation.fail("credential_unavailable")
            headers["Authorization"] = "Bearer " + token
        self._busy = True
        try:
            # The original callback thread waits for this loop and its original
            # local HTTP scopes. No background provider task is detached.
            result = asyncio.run(self._exchange(operation, effect, model["url"], body, headers, tools is not None))
            self._within_original_call(operation, effect)
            return result
        finally:
            self._busy = False

    def retire(self, operation):
        if self._operation is not None and self._operation is not operation:
            operation.fail("protocol_refused")
        if self._busy:
            operation.fail("custody_unavailable", unknown=True)
        if self._retired:
            return
        self._operation, self._retired = operation, True
        effects = [item for item in operation.snapshot()["effects"] if item["kind"] == "model"]
        closed = all(not item["entered"] or item["closed"] for item in effects)
        unknown = any(item["outcome_unknown"] for item in effects)
        operation.note("model", {"local_closed": closed, "provider_outcome_unknown": unknown})
        if not closed:
            operation.fail("cleanup_unconfirmed", unknown=True)

    async def _exchange(self, operation, effect, endpoint, body, headers, allow_tools):
        client = response = None
        closed = True
        loop = asyncio.get_running_loop()
        remaining = effect.deadline - operation.now()
        if remaining <= 0 or not math.isfinite(remaining):
            operation.fail("deadline_exhausted")
        absolute = loop.time() + remaining
        try:
            async with asyncio.timeout_at(absolute):
                client = self._client_factory(trust_env=False, follow_redirects=False,
                                              timeout=remaining)
                # Request construction and serialization precede actual entry.
                request = client.build_request("POST", endpoint, content=body, headers=headers)
                response = await operation.invoke_async(effect, lambda: client.send(request, stream=True))
                self._within_original_call(operation, effect)
                if (response.status_code != 200 or response.headers.get("Content-Encoding", "identity") not in {"", "identity"}):
                    operation.observe(effect, "refused", code="model_refused")
                    operation.fail("model_refused")
                raw = bytearray()
                async for chunk in response.aiter_raw():
                    operation.consume(effect, response_bytes=len(chunk))
                    self._within_original_call(operation, effect)
                    # consume checked the original allowance before accumulation.
                    raw.extend(chunk)
                operation.assert_safe(bytes(raw))
                try:
                    result = _response(raw, allow_tools=allow_tools,
                                       maximum_calls=operation.limits["exec_calls"],
                                       maximum_tokens=operation.limits["model_output_tokens_per_call"])
                    assert_safe_decoded(operation,
                                        [result.content, *({"id": call.id, "name": call.name,
                                                            "arguments": call.arguments} for call in result.tool_calls)],
                                        operation.limits["model_response_bytes"])
                except (ValueError, TypeError, RecursionError, UnicodeError):
                    operation.observe(effect, "refused", code="model_refused")
                    operation.fail("model_refused")
                self._within_original_call(operation, effect)
                operation.observe(effect, "acknowledged")
                return result
        except ReviewError:
            raise
        except BaseException:
            entered = operation.snapshot()["effects"][effect.id - 1]["entered"]
            operation.observe(effect, "outcome_unknown" if entered else "refused",
                              code="model_outcome_unknown" if entered else "model_refused")
            operation.fail("model_outcome_unknown" if entered else "model_refused", unknown=entered)
        finally:
            record = operation.snapshot()["effects"][effect.id - 1]
            if record["entered"] and not (record["acknowledged"] or record["refused"] or record["outcome_unknown"]):
                # Original authority can disappear after API entry but before
                # validating the reply. Preserve that exchange's uncertainty;
                # closing its local scopes does not establish provider outcome.
                operation.observe(effect, "outcome_unknown", code="model_outcome_unknown")
            # Closing the original local scopes is custody, not a new request.
            # Await actual closure even after the productive deadline expires.
            for owned in (response, client):
                if owned is None:
                    continue
                try:
                    original_close = asyncio.create_task(owned.aclose())
                    while not original_close.done():
                        try:
                            await asyncio.shield(original_close)
                        except asyncio.CancelledError:
                            operation.observe(effect, "outcome_unknown", code="model_outcome_unknown")
                            # Retain and join this exact original close future.
                            continue
                    original_close.result()
                except BaseException:
                    closed = False
                    operation.observe(effect, "outcome_unknown", code="model_outcome_unknown")
            if closed:
                operation.observe(effect, "closed", data={"local_closed": True})
