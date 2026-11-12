"""Explicit host-approved, noncoding public-discussion participant.

This NEW component uses the restricted profile-v1 contract. It never falls back
to the ordinary Polyphony server or promotes public text to protected authority.
"""

from __future__ import annotations

import argparse
import asyncio
import os
import signal
import sys
import time

import anyio

from ..polyphony.conversation_client import connect
from .bounded_http import HTTPResponseRejected, post_bounded_json
from .discussion_journal import DiscussionJournal
from .discussion_types import (
    CLEANUP_SECONDS, Deadline, DiscussionError, KEY, Policy,
    PROVIDER_RESPONSE_LIMIT, Turn, canonical, fields, integer, matches,
    read_private_bytes, strict_json, text, validate_output,
)


def _token(policy, *, required=True):
    value = os.environ.get(policy.provider["token_ref"][4:], "")
    if not required:
        return value or None
    if (
        not value or len(value) > 8192
        or any(ord(character) < 33 or ord(character) > 126 for character in value)
    ):
        raise DiscussionError("invalid_policy")
    return value


def _secret_present(value, token):
    if not token:
        return False
    if isinstance(value, str):
        return token in value
    if isinstance(value, dict):
        return any(
            _secret_present(key, token) or _secret_present(item, token)
            for key, item in value.items()
        )
    if isinstance(value, (list, tuple)):
        return any(_secret_present(item, token) for item in value)
    return False


def _provider_output(raw):
    try:
        value = strict_json(raw, PROVIDER_RESPONSE_LIMIT, "provider_rejected")
        choices = value.get("choices")
        if not isinstance(choices, list) or len(choices) != 1:
            raise DiscussionError("provider_rejected")
        choice = choices[0]
        fields(choice, {"message", "finish_reason"}, {"index", "logprobs"},
               code="provider_rejected")
        if choice["finish_reason"] != "stop":
            raise DiscussionError("provider_rejected")
        if "index" in choice:
            integer(choice["index"], 0, 0, "provider_rejected")
        message = choice["message"]
        fields(message, {"role", "content"}, {
            "tool_calls", "function_call", "refusal",
        }, code="provider_rejected")
        if (
            message["role"] != "assistant"
            or message.get("tool_calls") not in (None, [])
            or message.get("function_call") is not None
            or message.get("refusal") is not None
        ):
            raise DiscussionError("provider_rejected")
        text(message["content"], PROVIDER_RESPONSE_LIMIT, nonempty=True,
             code="provider_rejected")
        return validate_output(strict_json(
            message["content"].encode("utf-8"),
            PROVIDER_RESPONSE_LIMIT, "provider_rejected",
        ))
    except DiscussionError:
        raise
    except Exception:
        raise DiscussionError("provider_rejected") from None


async def _provider(policy, request, token, deadline):
    # No tool schema, retry, proxy, fallback model or caller-selected endpoint.
    return await post_bounded_json(
        policy.provider["endpoint"], request,
        {"Authorization": "Bearer " + token, "Accept-Encoding": "identity"},
        timeout_seconds=deadline.remaining(
            policy.provider.get("request_timeout_seconds", 30)
        ),
        max_response_bytes=PROVIDER_RESPONSE_LIMIT,
        decode=_provider_output,
    )


def _turn_deadline(value):
    return Deadline.retained(
        value["expires_at"], value["monotonic_cutoff"], value["boot_id"]
    )


async def _persist(deadline, callback):
    # Local acknowledgement only. Its ceiling shares the original operation's
    # cleanup cutoff; it grants no provider or publication dispatch permission.
    cutoff = min(
        time.monotonic() + CLEANUP_SECONDS,
        deadline.monotonic_cutoff + CLEANUP_SECONDS,
    )
    with anyio.CancelScope(shield=True):
        if time.monotonic() >= cutoff:
            raise DiscussionError("process_cleanup_failed")
        with anyio.fail_after(max(0.001, cutoff - time.monotonic())):
            await anyio.lowlevel.checkpoint()
            result = callback()
            await anyio.lowlevel.checkpoint()
        return result


async def _record_interruption(journal, key, deadline, error):
    try:
        current = journal.get(key)
        if current["state"] == "reserved":
            await _persist(deadline, lambda: journal.provider_failed(key, uncertain=True))
        elif current["state"] == "publishing":
            await _persist(deadline, lambda: journal.publication_failed(key))
    except Exception:
        error.add_note("discussion acknowledgement could not be retained")


def _result(journal, key, reason=None):
    value = journal.get(key)
    return {
        **journal.receipt(key),
        "reason": value["reason"] or reason,
        "execution_authorized": False,
    }


async def initialize(policy):
    deadline = Deadline.observe()
    async with connect(policy, deadline) as client:
        interpreter = client.interpreter
        status = client.status
    # B state becomes usable only after the preflight process is closed/reaped.
    return DiscussionJournal.initialize(
        policy, interpreter, status, deadline=deadline
    )


async def observe(policy, *, after=0, stream_id=None, watch=0):
    deadline = Deadline.observe()
    with DiscussionJournal(policy, read_only=True, deadline=deadline) as journal:
        async with connect(
            policy, deadline, expected_status=journal.binding["status"],
            expected_interpreter=journal.binding["interpreter"],
        ) as client:
            page = await client.history(after, stream_id=stream_id, watch=watch)
            result = {"schema_version": 1, "status": client.status, "history": page}
            token = _token(policy, required=False)
            if _secret_present(result, token):
                raise DiscussionError("invalid_context")
            return result


async def turn(policy, request_path):
    request = Turn.parse(read_private_bytes(request_path, code="invalid_turn"))
    # This invocation envelope permits local historical receipt reads. Network
    # and state transitions below use the earlier immutable per-turn cutoff.
    with DiscussionJournal(policy, deadline=Deadline.observe()) as journal:
        existing = journal.get(request.key)
        token = None
        if existing is None or existing["state"] == "prepared":
            token = _token(policy)
            if _secret_present(request.document, token) or _secret_present(
                policy.binding(), token
            ):
                raise DiscussionError("invalid_turn")
        value = journal.prepare(request)
        if value["state"] in {"complete", "rejected", "provider_uncertain"}:
            return _result(journal, request.key)
        if value["state"] == "prepared" and journal.status()["provider_uncertain"]:
            raise DiscussionError("provider_uncertain")
        deadline = _turn_deadline(value)
        journal.deadline = deadline
        try:
            deadline.remaining()
            async with connect(
                policy, deadline, expected_status=journal.binding["status"],
                expected_interpreter=journal.binding["interpreter"],
            ) as client:
                if value["state"] == "prepared":
                    if value["context"] is None:
                        context = await client.selected_context(request)
                        if _secret_present(context, token):
                            raise DiscussionError("invalid_context")
                        value = journal.freeze_context(request.key, context)
                    if _secret_present(value["context"], token) or _secret_present(
                        [policy.document["persona"], policy.provider["model"]], token
                    ):
                        raise DiscussionError("invalid_context")
                    value = journal.reserve(request.key)
                    # The exact approved request is now durable before its one
                    # attempt. Any interruption from here is charged/uncertain.
                    try:
                        output = await _provider(
                            policy, value["provider_request"], token, deadline
                        )
                        if _secret_present(output, token):
                            raise DiscussionError("provider_rejected")
                    except HTTPResponseRejected:
                        await _persist(deadline, lambda: journal.provider_failed(
                            request.key, uncertain=False
                        ))
                        return _result(journal, request.key)
                    except DiscussionError as error:
                        if error.code != "provider_rejected":
                            await _record_interruption(journal, request.key, deadline, error)
                            raise
                        await _persist(deadline, lambda: journal.provider_failed(
                            request.key, uncertain=False
                        ))
                        return _result(journal, request.key)
                    except BaseException as error:
                        await _record_interruption(journal, request.key, deadline, error)
                        raise
                    value = await _persist(deadline, lambda: journal.provider_result(
                        request.key, output
                    ))
                    if value["state"] == "rejected":
                        return _result(journal, request.key)
                # Revalidate the same public identity before dispatching a post.
                # A retained response needs no new provider token or allowance.
                optional_secret = token or _token(policy, required=False)
                if _secret_present(value["intent"], optional_secret):
                    raise DiscussionError("invalid_context")
                await client.check_status(journal.binding["status"])
                value = journal.begin_publication(request.key, client.status)
                try:
                    ack = await client.say(value["intent"])
                    await _persist(deadline, lambda: journal.publication_result(request.key, ack))
                except BaseException as error:
                    await _record_interruption(journal, request.key, deadline, error)
                    raise
                return _result(journal, request.key)
        except BaseException as error:
            # Transport task-group cancellation can arrive while the HTTP call
            # or a say response is outstanding. Persist only the known boundary.
            await _record_interruption(journal, request.key, deadline, error)
            if isinstance(error, (KeyboardInterrupt, SystemExit)):
                raise
            if isinstance(error, anyio.get_cancelled_exc_class()):
                raise
            reason = error.code if isinstance(error, DiscussionError) else "operation_failed"
            return _result(journal, request.key, reason)


def _arguments(argv):
    parser = argparse.ArgumentParser(
        prog="openjules-discussion",
        description="Bounded public discussion under an explicit private host policy.",
    )
    parser.add_argument("--config", required=True)
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("init", help="Initialize a wholly absent private state directory.")
    commands.add_parser("status", help="Read retained allowance and uncertainty status.")
    receipt = commands.add_parser("receipt", help="Read one retained local turn receipt.")
    receipt.add_argument("request_key")
    history = commands.add_parser("observe", help="Read one bounded signed public page.")
    history.add_argument("--after", type=int, default=0)
    history.add_argument("--stream-id")
    history.add_argument("--watch", type=int, default=0)
    execute = commands.add_parser("turn", help="Submit or recover one immutable approved turn.")
    execute.add_argument("--request", required=True)
    return parser.parse_args(argv)


async def _run(args, policy):
    if args.command == "init":
        return await initialize(policy)
    if args.command == "observe":
        integer(args.watch, 0, 30, "invalid_context")
        return await observe(
            policy, after=args.after, stream_id=args.stream_id, watch=args.watch
        )
    if args.command == "turn":
        return await turn(policy, args.request)
    with DiscussionJournal(policy, read_only=True) as journal:
        if args.command == "status":
            return journal.status()
        matches(KEY, args.request_key, "invalid_turn")
        return journal.receipt(args.request_key)


def main(argv=None):
    args = _arguments(argv)
    previous = signal.getsignal(signal.SIGTERM)

    def interrupted(*_):
        raise KeyboardInterrupt()

    signal.signal(signal.SIGTERM, interrupted)
    try:
        policy = Policy.load(args.config)
        result = asyncio.run(_run(args, policy))
        token = _token(policy, required=False)
        if _secret_present(result, token):
            raise DiscussionError("operation_failed")
        print(canonical(result).decode("utf-8"))
        if args.command == "turn":
            if result["state"] == "complete" and result.get("reason") is None:
                return 0
            return 2 if result["state"] == "rejected" else 3
        return 0
    except KeyboardInterrupt:
        print(canonical({
            "schema_version": 1, "state": "interrupted",
            "reason": "operation_failed", "execution_authorized": False,
        }).decode("utf-8"))
        return 130
    except Exception as error:
        reason = error.code if isinstance(error, DiscussionError) else "operation_failed"
        print(canonical({
            "schema_version": 1, "state": "refused", "reason": reason,
            "execution_authorized": False,
        }).decode("utf-8"))
        return 2
    finally:
        signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
