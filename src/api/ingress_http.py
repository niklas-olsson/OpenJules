"""Bounded authenticated HTTP admission for the selected legacy issue adapter.

Policy and the original receipt store own authorization and durable identity.
This module validates actual HTTP inputs and owns only its in-process callback
lifetime. A task handler's return is never canonical completion or acceptance.
"""

from __future__ import annotations

import asyncio
from asyncio import wrap_future
from concurrent.futures import CancelledError as NativeCancelled, ThreadPoolExecutor
from contextlib import asynccontextmanager
import ipaddress
import re

from fastapi import Request
from fastapi.responses import JSONResponse
from starlette.requests import ClientDisconnect

from src.api.ingress_adapter import GitHubTaskAdapter, ReviewCredentialSnapshot
from src.api.ingress_policy import IngressError, bounded_task, strict_json
from src.api.standalone_ingress import ingress_failure
from src.storage.ingress_receipts import ReceiptStore
from src.worker.execution_context import LegacyExecutionRefused, require_legacy_execution

BODY_LIMIT = 1024 * 1024
HEADER_LIMIT = 16384
BODY_SECONDS = 30
MAX_CALLBACKS = 128
CONCURRENT_CALLBACKS = 4
_SINGLE = frozenset({"host", "origin", "authorization", "content-type", "content-length",
                     "transfer-encoding", "idempotency-key", "x-hub-signature-256",
                     "x-github-event", "x-github-delivery"})
_COMMAND = re.compile(r"\A/(?:jules|openjules) run(?:\s|\Z)")


def _refuse(code, status=422):
    raise IngressError(code, status)


def _integer(value):
    if type(value) is not int or not 1 <= value < 2**63:
        _refuse("ingress_source_invalid")
    return value


def _object(value):
    if type(value) is not dict:
        _refuse("ingress_source_invalid")
    return value


def _text(value, maximum):
    if type(value) is not str:
        _refuse("ingress_source_invalid")
    try:
        valid = 1 <= len(value.encode("utf-8")) <= maximum
    except UnicodeError:
        valid = False
    if not valid:
        _refuse("ingress_source_invalid")
    return value


def request_headers(request, policy):
    """Check transport and exact authority before receiving a private body."""
    require_legacy_execution()
    raw = request.scope.get("headers", [])
    if len(raw) > 64 or sum(len(key) + len(value) for key, value in raw) > HEADER_LIMIT:
        _refuse("ingress_headers_too_large", 431)
    headers = {}
    for key, value in raw:
        try:
            key, value = key.decode("ascii").lower(), value.decode("ascii")
        except UnicodeError:
            _refuse("ingress_headers_invalid")
        if not re.fullmatch(r"[!#$%&'*+.^_`|~0-9a-z-]+", key):
            _refuse("ingress_headers_invalid")
        if any(ord(char) < 32 or ord(char) == 127 for char in value):
            _refuse("ingress_headers_invalid")
        if key in _SINGLE and key in headers:
            _refuse("ingress_headers_ambiguous")
        if key == "forwarded" or key.startswith("x-forwarded-"):
            _refuse("ingress_forwarded_authority_unsupported", 403)
        headers[key] = value
    if headers.get("host") != policy.authority:
        _refuse("ingress_authority_refused", 403)
    if "origin" in headers and headers["origin"] != policy.origin:
        _refuse("ingress_origin_refused", 403)
    # Remote mode explicitly selects the operator's authenticated HTTPS proxy
    # and isolated backend. The app never infers TLS/isolation from forwarding
    # headers; backend HTTP and direct ASGI HTTPS are deliberate deployments.
    schemes = {"http"} if policy.mode == "local_only" else {"http", "https"}
    if request.scope.get("scheme") not in schemes:
        _refuse("ingress_transport_refused", 403)
    if policy.mode == "local_only":
        client = request.scope.get("client")
        try:
            local = client is not None and ipaddress.ip_address(client[0]).is_loopback
        except ValueError:
            local = False
        if not local:
            _refuse("ingress_local_peer_required", 403)
    if request.scope.get("query_string"):
        _refuse("ingress_query_unsupported")
    return headers


def bearer_principal(policy, headers):
    authorization = headers.get("authorization", "")
    if (not authorization.startswith("Bearer ") or len(authorization) > 4103
            or not authorization[7:] or any(ord(char) <= 32 for char in authorization[7:])):
        _refuse("ingress_authentication_required", 401)
    return policy.authenticate_bearer(authorization[7:])


async def bounded_body(request, headers):
    content_type = headers.get("content-type", "").lower()
    if content_type not in {"application/json", "application/json;charset=utf-8", "application/json; charset=utf-8"}:
        _refuse("ingress_json_required", 415)
    declared = headers.get("content-length")
    if declared is not None:
        if not re.fullmatch(r"0|[1-9][0-9]{0,9}", declared):
            _refuse("ingress_length_invalid")
        declared = int(declared)
        if declared > BODY_LIMIT:
            _refuse("ingress_body_too_large", 413)
    if "transfer-encoding" in headers:
        if declared is not None or headers["transfer-encoding"].lower() != "chunked":
            _refuse("ingress_length_ambiguous")
    chunks, length = [], 0
    try:
        async with asyncio.timeout(BODY_SECONDS):
            async for chunk in request.stream():
                length += len(chunk)
                if length > BODY_LIMIT:
                    _refuse("ingress_body_too_large", 413)
                chunks.append(chunk)
    except TimeoutError:
        _refuse("ingress_body_timeout", 408)
    except ClientDisconnect:
        _refuse("ingress_body_unavailable")
    if declared is not None and declared != length:
        _refuse("ingress_length_invalid")
    return b"".join(chunks)


def webhook_task(policy, principal, payload, event):
    """Derive source identity only from the authenticated GitHub body."""
    payload = _object(payload)
    issue = _object(payload.get("issue"))
    repository = _object(payload.get("repository"))
    review_shapes = {"pull_request", "review", "review_comment", "pull_request_review", "pull_request_review_comment"}
    if review_shapes.intersection(issue) or review_shapes.intersection(payload):
        _refuse("ingress_adapter_unsupported", 404)
    repository_id = _integer(repository.get("id"))
    name = _text(repository.get("full_name"), 256)
    action = payload.get("action")
    body = issue.get("body")
    task = bounded_task({"issue_id": _integer(issue.get("number")),
                         "issue_title": issue.get("title"),
                         "issue_body": "" if body is None else body})
    if "comment" in payload:
        if action != "created" or event not in {None, "issue_comment"}:
            _refuse("ingress_adapter_unsupported", 404)
        comment = _object(payload["comment"])
        text = _text(comment.get("body"), 256 * 1024)
        if not _COMMAND.match(text.strip()):
            _refuse("ingress_trigger_required", 403)
        actor = _integer(_object(comment.get("user")).get("id"))
        source_kind, source_id = "github_issue_comment", _integer(comment.get("id"))
        task = bounded_task(task | {"issue_body": task["issue_body"] + "\n\nTriggering comment:\n" + text})
    else:
        if action not in {"opened", "labeled"} or event not in {None, "issues"}:
            _refuse("ingress_adapter_unsupported", 404)
        labels = issue.get("labels")
        if (type(labels) is not list or len(labels) > 100
                or not any(type(label) is dict and label.get("name") in {"openjules", "openjules:run"}
                           for label in labels)):
            _refuse("ingress_trigger_required", 403)
        actor = _integer(_object(payload.get("sender")).get("id"))
        source_kind, source_id = "github_issue_initial", task["issue_id"]
    if actor not in principal.actor_ids:
        _refuse("ingress_actor_refused", 403)
    candidates = []
    for binding in policy.bindings.values():
        if binding.repository_id != repository_id or binding.repository != name:
            continue
        if binding.installation_id is not None:
            installation = _object(payload.get("installation"))
            if _integer(installation.get("id")) != binding.installation_id:
                continue
        try:
            policy.require_grant(principal.principal_id, binding.binding_id, "task.start")
        except IngressError as exc:
            if exc.status == 403:
                continue
            raise
        candidates.append(binding)
    if len(candidates) != 1:
        _refuse("ingress_binding_refused", 403)
    return candidates[0], task, source_kind, source_id, actor


class CallbackQueue:
    """Own finite local callbacks without becoming another task authority."""

    def __init__(self, store, adapter, review_adapter=None):
        self.store, self.adapter = store, adapter
        self.review_adapter = review_adapter
        self.jobs = set()
        self.semaphore = asyncio.Semaphore(CONCURRENT_CALLBACKS)
        # Threads start only upon an admitted submission. Keep their native
        # futures separate from cancellable event-loop wrappers.
        self.pool = ThreadPoolExecutor(max_workers=CONCURRENT_CALLBACKS, thread_name_prefix="ingress-callback")
        self.closed = False
        self.custody_failed = False

    def can_accept(self):
        return not self.closed and len(self.jobs) < MAX_CALLBACKS

    @staticmethod
    def _schedule(coroutine):
        return asyncio.create_task(coroutine)

    def submit(self, ticket):
        coroutine = self._run(ticket)
        try:
            job = self._schedule(coroutine)
        except Exception:
            coroutine.close()
            # asyncio did not create a task, so this wrapper is proven absent.
            # Registration still retains the original uncertain receipt/fence.
            self.store.registration_failed(ticket)
            self.store.callback_quiesced(ticket)
            return False
        self.jobs.add(job)
        job.add_done_callback(self.jobs.discard)
        return True

    def _invoke(self, ticket):
        try:
            require_legacy_execution()
            original = self.store.claim_callback(ticket)
            if original is None:
                return
            if original.get("operation") == "review.start":
                if self.review_adapter is None:
                    raise IngressError("review_adapter_unavailable", 503)
                claim = self.store.review_claim(ticket, original)
                outcome = self.review_adapter(claim.original, claim)
                self.store.finish_review(ticket, outcome)
            else:
                outcome = self.adapter(original)
                if type(outcome) is not bool:
                    self.store.uncertain(ticket)
                else:
                    self.store.finish(ticket, handler_return=outcome)
        except BaseException:
            try:
                self.store.uncertain(ticket)
            except BaseException:
                self.custody_failed = True
        finally:
            try:
                self.store.callback_quiesced(ticket)
            except BaseException:
                self.custody_failed = True

    async def _run(self, ticket):
        worker = None
        invocation = None
        try:
            invocation = self.store.begin_callback(ticket)
            if invocation is None:
                return
            async with self.semaphore:
                worker = self.pool.submit(self._invoke, invocation)
                # Cancellation cannot acknowledge a still-running owned thread.
                cancelled = False
                while not worker.done():
                    try:
                        await asyncio.shield(wrap_future(worker))
                    except asyncio.CancelledError:
                        cancelled = True
                worker.result()
                if cancelled:
                    raise asyncio.CancelledError
        except asyncio.CancelledError:
            if worker is None and invocation is not None:
                self.store.uncertain(invocation)
                self.store.callback_quiesced(invocation)
        except NativeCancelled:
            # A cancelled original concurrent future proves its thread callable
            # never started. Preserve conservative unknown, never task cancel.
            self.store.uncertain(invocation)
            self.store.callback_quiesced(invocation)
        except BaseException:
            # No error body, exception text, task content or host path is logged.
            self.custody_failed = True

    async def close(self):
        self.closed = True
        self.store.close_admission()
        if self.jobs:
            joined = asyncio.gather(*tuple(self.jobs), return_exceptions=True)
            while not joined.done():
                try:
                    await asyncio.shield(joined)
                except asyncio.CancelledError:
                    # Keep original store custody until every owned callback is
                    # quiescent, even if the ASGI shutdown itself is cancelled.
                    continue
        if self.custody_failed:
            _refuse("ingress_callback_custody_unresolved", 503)
        self.pool.shutdown(wait=True, cancel_futures=False)
        self.store.close()


def configured_lifespan(policy, adapter=None, review_adapter=None):
    @asynccontextmanager
    async def lifespan(app):
        require_legacy_execution()
        task_bindings = tuple(binding for binding in policy.bindings.values() if any(
            "task.start" in principal.grants.get(binding.binding_id, ())
            for principal in policy.principals.values()
        ))
        selected_adapter = adapter
        if selected_adapter is None and task_bindings:
            selected_adapter = GitHubTaskAdapter(bindings=task_bindings,
                separation_validator=policy.assert_execution_separation)
        from src.storage.review_receipts import enabled_review_bindings
        review_credentials = {binding.binding_id: ReviewCredentialSnapshot(binding, policy)
            for binding in enabled_review_bindings(policy)}
        selected_review = review_adapter
        if review_credentials and selected_review is None:
            from src.worker.standalone_review import StandaloneReviewAdapter
            selected_review = StandaloneReviewAdapter()
        def epoch_validator():
            validator = getattr(selected_adapter, "validate_epoch", None)
            if validator is not None:
                validator()
            for snapshot in review_credentials.values():
                snapshot.validate_epoch()
        store = ReceiptStore(policy, epoch_validator=epoch_validator,
            review_credentials=review_credentials)
        callbacks = CallbackQueue(store, selected_adapter, selected_review)
        app.state.ingress_store = store
        app.state.ingress_callbacks = callbacks
        try:
            yield
        finally:
            await callbacks.close()
    return lifespan


def install_routes(app, policy, verify_signature):
    """Install explicitly selected operations on the existing bounded routes."""
    @app.exception_handler(IngressError)
    async def ingress_error(_request, exc):
        return JSONResponse(status_code=exc.status,
                            content=ingress_failure(exc.status, exc.code, getattr(exc, "receipt", None)),
                            headers={"Cache-Control": "no-store"})

    @app.exception_handler(LegacyExecutionRefused)
    async def managed_refusal(_request, exc):
        return JSONResponse(status_code=409, content=ingress_failure(409, exc.reason),
                            headers={"Cache-Control": "no-store"})

    def state(request):
        store = getattr(request.app.state, "ingress_store", None)
        callbacks = getattr(request.app.state, "ingress_callbacks", None)
        if store is None or callbacks is None:
            _refuse("ingress_owner_unavailable", 503)
        return store, callbacks

    def dispatch(request, principal, binding, task, source_kind, source_id, key, actor=None):
        require_legacy_execution()
        store, callbacks = state(request)
        available = callbacks.can_accept()
        receipt = store.reserve(principal.principal_id, binding.binding_id,
                                source_kind, source_id, key, task, actor_id=actor,
                                allow_new=available)
        if receipt["dispatch_state"] != "reserved":
            return JSONResponse(status_code=202, content=receipt, headers={"Cache-Control": "no-store"})
        if not available:
            return JSONResponse(status_code=503,
                                content=ingress_failure(503, "ingress_callbacks_unavailable", receipt),
                                headers={"Cache-Control": "no-store"})
        ticket = store.fence(receipt["operation_id"], principal.principal_id)
        status = 202
        if ticket is not None and not callbacks.submit(ticket):
            status = 503
        # The operation's admission response is available under task.start.
        # A webhook principal need not possess the separate receipt.read grant.
        # Exact reserve replay projects this original row and cannot requeue.
        receipt = store.reserve(principal.principal_id, binding.binding_id,
                                source_kind, source_id, key, task, actor_id=actor)
        return JSONResponse(status_code=status, content=receipt, headers={"Cache-Control": "no-store"})

    @app.post("/api/tasks")
    async def submit_task(request: Request):
        headers = request_headers(request, policy)
        principal = bearer_principal(policy, headers)
        key = headers.get("idempotency-key", "")
        if not 1 <= len(key) <= 256 or any(ord(char) <= 32 for char in key):
            _refuse("ingress_idempotency_key_required")
        payload = strict_json(await bounded_body(request, headers), BODY_LIMIT)
        if (type(payload) is not dict or set(payload) != {"schema_version", "binding_id", "issue_id", "issue_title", "issue_body"}
                or type(payload["schema_version"]) is not int or payload["schema_version"] != 1):
            _refuse("ingress_task_invalid")
        binding_id = _text(payload["binding_id"], 128)
        binding = policy.require_grant(principal.principal_id, binding_id, "task.start")
        task = bounded_task({key: value for key, value in payload.items() if key not in {"binding_id", "schema_version"}})
        return dispatch(request, principal, binding, task, "operator_task", None, key)

    def dispatch_review(request, principal, binding, review, actor):
        require_legacy_execution()
        store, callbacks = state(request)
        available = callbacks.can_accept()
        receipt = store.reserve_review(principal.principal_id, binding.binding_id, review, actor,
            allow_new=available)
        if receipt["dispatch_state"] != "reserved":
            return JSONResponse(status_code=202, content=receipt, headers={"Cache-Control": "no-store"})
        if not available:
            return JSONResponse(status_code=503,
                content=ingress_failure(503, "ingress_callbacks_unavailable", receipt),
                headers={"Cache-Control": "no-store"})
        ticket = store.fence(receipt["operation_id"], principal.principal_id)
        status = 202 if ticket is None or callbacks.submit(ticket) else 503
        receipt = store.reserve_review(principal.principal_id, binding.binding_id, review, actor)
        return JSONResponse(status_code=status, content=receipt, headers={"Cache-Control": "no-store"})

    @app.post("/api/webhook")
    async def github_webhook(request: Request):
        headers = request_headers(request, policy)
        principal, secret = policy.github_auth()
        raw = await bounded_body(request, headers)
        signature = headers.get("x-hub-signature-256")
        if not verify_signature(raw, signature, secret):
            _refuse("ingress_authentication_required", 401)
        value = strict_json(raw, BODY_LIMIT)
        if type(value) is dict and "review" in value:
            from src.api.review_ingress import webhook_review
            binding, review, actor = webhook_review(policy, principal, value, headers.get("x-github-event"))
            return dispatch_review(request, principal, binding, review, actor)
        binding, task, kind, source_id, actor = webhook_task(policy, principal, value, headers.get("x-github-event"))
        return dispatch(request, principal, binding, task, kind, source_id, None, actor)

    @app.get("/api/ingress/receipts/{operation_id}")
    async def read_receipt(operation_id: str, request: Request):
        headers = request_headers(request, policy)
        principal = bearer_principal(policy, headers)
        store, _callbacks = state(request)
        return JSONResponse(content=store.read(operation_id, principal.principal_id),
                            headers={"Cache-Control": "no-store"})
