"""Canonical child grants joined to local admission, execution and capture.

This supervisor owns no tasks or new inference allowances. Its journal records
delivery identities and runtime facts needed to recover the existing root.
"""

from __future__ import annotations

import json
import math
from pathlib import Path
import threading
import time

from src.polyphony.child_client import ChildAuthorityClient, ChildRejected
from src.polyphony.managed_client import AuthorityUnavailable
from .child_journal import ChildJournal
from .child_outcomes import work_outcome
from .child_sessions import (
    ColdSessionStore, SESSION_OPERATIONS, SESSION_PROTOCOL, session_binding,
    validate_request as validate_session_request,
)
from .child_runtime import ChildRuntime
from .child_types import (
    CHILD_ID,
    IDENTIFIER,
    ChildPolicy,
    RootContext,
    canonical,
    digest,
    text_hash,
    verify_grant,
)
from .lifecycle import LifecycleConflict, RuntimeUnavailable


class ChildDenied(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


class ChildTurnExpired(RuntimeError):
    """An optional original cutoff elapsed before the canonical turn request."""


class ChildSupervisor:
    def __init__(
        self,
        directory,
        policies,
        authority,
        lifecycle,
        runtime,
        model_broker,
        root_permission,
        root_active,
    ):
        self.policies = dict(policies)
        if not self.policies or any(
            not isinstance(value, ChildPolicy) for value in self.policies.values()
        ):
            raise ValueError("approved child policies are required")
        if not callable(root_permission) or not callable(root_active):
            raise ValueError(
                "canonical and local root permission callbacks are required"
            )
        self.authority = ChildAuthorityClient(authority)
        self.lifecycle, self.runtime, self.model_broker = (
            lifecycle,
            runtime,
            model_broker,
        )
        self.root_permission, self.root_active = root_permission, root_active
        self.boot_id = Path("/proc/sys/kernel/random/boot_id").read_text().strip()
        self.journal = ChildJournal(directory)
        self.sessions = ColdSessionStore(self.journal)
        self.driver = ChildRuntime(runtime, self)
        self.guard = threading.RLock()
        self.operations = {}
        self.closed = False
        self.endpoints = None  # Installed once by the separate host socket adapter.

    def policy(self, spec):
        try:
            return self.policies[(spec.deployment_id, spec.repository, spec.profile)]
        except KeyError:
            raise ChildDenied("unsupported") from None

    def enabled(self, spec):
        return (spec.deployment_id, spec.repository, spec.profile) in self.policies

    def _operation_lock(self, worker_id):
        with self.guard:
            return self.operations.setdefault(worker_id, threading.Lock())

    def prepare_worker(self, worker_id, spec, directory):
        try:
            self.journal.worker(worker_id)
        except LifecycleConflict:
            previous = self.runtime._row(worker_id, spec)
            if previous is not None and (
                previous["create_dispatched"] or previous["container_id"]
            ):
                raise RuntimeUnavailable(
                    "owned child-enabled worker is missing its recovery journal"
                ) from None
        self.journal.prepare(worker_id, spec, self.policy(spec))
        if self.endpoints is None:
            raise RuntimeUnavailable("child transport is not installed")
        self.endpoints.prepare_root(worker_id, spec, directory)

    def bind_root(self, worker_id, spec, response, cutoff):
        if not self.enabled(spec):
            return
        self.journal.prepare(worker_id, spec, self.policy(spec))
        root = RootContext.bind(worker_id, spec, response, cutoff, self.boot_id)
        self.journal.bind(root)

    def model_admission_open(self, worker_id, child_id):
        """A new-call gate only; do not use from admitted-call permission checks."""
        root = self.journal.context(worker_id)
        policy = self.policy(root.spec)
        if policy.session_protocol is None:
            return True
        return not self.sessions.admission_closed(root, policy, child_id)

    def _session_enabled(self, root):
        return self.policy(root.spec).session_protocol == SESSION_PROTOCOL

    def _observe_sessions(self, root):
        if self._session_enabled(root):
            self.sessions.observe(
                root, self.policy(root.spec), time.monotonic(), self.boot_id
            )

    def _handle_session(self, worker_id, payload):
        root = self.journal.context(worker_id)
        policy = self.policy(root.spec)
        if not self._session_enabled(root):
            raise ChildDenied("unsupported")
        try:
            validate_session_request(payload, policy)
        except (TypeError, ValueError, OverflowError, RecursionError):
            raise ChildDenied("invalid_request") from None
        operation = payload["operation"]
        result = {
            "schema_version": 1, "request_id": payload["request_id"], "ok": True
        }
        if operation == "session_status":
            self._root_permission(root)
            session = self.sessions.get(root, policy, payload["session_id"])
            for row in session["rounds"]:
                if row["child"] is not None:
                    # Existing observation records exec return and its terminal
                    # logical observation in the same child-journal transaction.
                    self.driver.observe(root, row["child"])
            self._observe_sessions(root)
            return result | self.sessions.project(root, policy, payload["session_id"])
        if operation == "session_start":
            session_id = session_binding(root, policy, payload)["session_id"]
            prior = next(
                (item for item in self.sessions.all(root, policy)
                 if item["session_id"] == session_id),
                None,
            )
            self._root_permission(root, admission=prior is None)
        else:
            session_id = payload["session_id"]
            prior = self.sessions.get(root, policy, session_id)
            self._root_permission(root, admission=len(prior["rounds"]) == 1)
        lock = self._operation_lock(worker_id)
        if not lock.acquire(blocking=False):
            raise ChildDenied("retry_later")
        try:
            if operation == "session_start":
                session_id = self.sessions.start(root, policy, payload)
                first = self.sessions.get(root, policy, session_id)["rounds"][0]
                child = self._resolve(root, first["intent"])
                if child is not None and self.local_allowed(root, child, admission=True):
                    self._admit_and_launch(root, child)
            else:
                current = self.sessions.get(root, policy, session_id)
                first = current["rounds"][0]["child"]
                if first is not None:
                    self.driver.observe(root, first)
                self._observe_sessions(root)
                self.sessions.queue(root, policy, payload, time.monotonic())
                current = self.sessions.get(root, policy, session_id)
                self.endpoints.stop_child_model(
                    root, current["rounds"][0]["child_id"]
                )
                # Queue acknowledgement never progresses a successor. Only the
                # ordinary serialized reconciliation path can establish its fence.
            self._observe_sessions(root)
            return result | self.sessions.project(root, policy, session_id)
        finally:
            lock.release()

    def _progress_sessions(self, root):
        """The caller owns the existing per-worker operation lock."""
        if not self._session_enabled(root):
            return
        policy = self.policy(root.spec)
        self._observe_sessions(root)
        for session in self.sessions.all(root, policy):
            first = session["rounds"][0]
            if not first["model_closed"]:
                continue
            owner_stopped = self.endpoints.stop_child_model(root, first["child_id"])
            if (
                session["closure"] is not None
                or len(session["rounds"]) != 2
                or session["rounds"][1]["state"] != "queued"
            ):
                continue
            child = first["child"]
            if (
                not owner_stopped or child["phase"] != "exec_returned"
                or type(child["exit_code"]) is not int or child["exit_code"] != 0
            ):
                continue
            if not self.local_allowed(root, child, admission=True):
                continue
            self._root_permission(root, admission=True)
            if self.model_broker is None:
                raise RuntimeUnavailable("cold follow-up requires the shared model gate")
            # No wait/join occurs under either lock. The context releases this
            # exact model gate before any ordinary canonical delivery below.
            with self.model_broker.child_followup_gate(
                root.worker_id, root.attempt_id
            ) as gate:
                if gate == "busy":
                    continue
                if gate == "unresolved":
                    self.sessions.block_uncertain(root, policy, session["session_id"])
                    continue
                if not self.endpoints.stop_child_model(root, first["child_id"]):
                    continue
                if not self.local_allowed(root, child, admission=True):
                    continue
                self.sessions.promote(
                    root, policy, session["session_id"], time.monotonic()
                )
            second = self.sessions.get(
                root, policy, session["session_id"]
            )["rounds"][1]
            if second["state"] != "linked":
                continue
            child = self._resolve(root, second["intent"])
            if child is not None and self.local_allowed(root, child, admission=True):
                self._admit_and_launch(root, child)
        self._observe_sessions(root)

    def local_allowed(self, root, child=None, *, admission=False):
        if (
            self.closed
            or root.boot_id != self.boot_id
            or time.monotonic() >= root.monotonic_deadline
        ):
            return False
        worker = self.journal.worker(root.worker_id)
        if worker["retire"] or (admission and worker["closed"]):
            return False
        if admission and not self.lifecycle.root_admission_open(
            root.spec.scope, root.worker_id, root.attempt_id
        ):
            return False
        current = self.journal.context(root.worker_id)
        if (
            current.attempt_id != root.attempt_id
            or current.spec != root.spec
            or current.boot_id != self.boot_id
        ):
            return False
        if time.monotonic() >= current.monotonic_deadline or not self.root_active(
            current
        ):
            return False
        if child is not None:
            fresh = self.journal.child(root.worker_id, child["child_id"])
            if (
                fresh["revoked"]
                or fresh["boot_id"] != self.boot_id
                or time.monotonic()
                >= min(fresh["deadline"], fresh["armed_deadline"] or fresh["deadline"])
            ):
                return False
            if fresh["phase"] in {"uncertain", "captured", "completed"}:
                return False
        return True

    def _root_permission(self, root, *, admission=False):
        if not self.local_allowed(root, admission=admission):
            raise ChildDenied("not_authorized")
        before = time.monotonic()
        try:
            remaining = self.root_permission(root)
        except Exception:
            raise ChildDenied("not_authorized") from None
        if (
            type(remaining) not in {int, float}
            or not math.isfinite(remaining)
            or remaining <= 0
        ):
            raise ChildDenied("not_authorized")
        cutoff = min(
            root.monotonic_deadline,
            self.journal.context(root.worker_id).monotonic_deadline,
            before + remaining,
        )
        # The authority reply cannot undo a local drain, cancel or phase change.
        if cutoff <= time.monotonic() or not self.local_allowed(
            root, admission=admission
        ):
            raise ChildDenied("not_authorized")
        return cutoff

    def permission(self, worker_id, child_id):
        root = self.journal.context(worker_id)
        child = self.journal.child(worker_id, child_id)
        cutoff = self._root_permission(root)
        before = time.monotonic()
        response = self.authority.call(
            "permission", root.spec.scope, root.attempt_id, child_id=child_id
        )
        verify_grant(
            response,
            root,
            self.policy(root.spec),
            original=json.loads(child["grant_json"]),
        )
        if not response["launch_allowed"] or not self.local_allowed(root, child):
            raise ChildDenied("not_authorized")
        cutoff = min(
            cutoff,
            self.local_cutoff(worker_id, child_id),
            before + response["remaining_seconds"],
        )
        if cutoff <= time.monotonic():
            raise ChildDenied("not_authorized")
        return cutoff

    def local_cutoff(self, worker_id, child_id):
        root = self.journal.context(worker_id)
        child = self.journal.child(worker_id, child_id)
        if not self.local_allowed(root, child):
            raise ChildDenied("not_authorized")
        return min(
            root.monotonic_deadline,
            child["deadline"],
            child["armed_deadline"] or child["deadline"],
        )

    def reserve_turn(
        self, worker_id, child_id, request_id, request_digest, *, admission_cutoff=None,
    ):
        if admission_cutoff is not None:
            if (
                type(admission_cutoff) not in {int, float}
                or not 0 < admission_cutoff <= 1e15
                or not math.isfinite(admission_cutoff)
            ):
                raise ValueError("invalid child turn admission cutoff")
            if admission_cutoff <= time.monotonic():
                raise ChildTurnExpired("original child turn cutoff elapsed")
        root = self.journal.context(worker_id)
        child = self.journal.child(worker_id, child_id)
        cutoff = self.permission(worker_id, child_id)
        key = "openjules-turn:" + digest(
            [worker_id, root.attempt_id, child_id, request_id]
        )
        before = time.monotonic()
        if admission_cutoff is not None and admission_cutoff <= before:
            # permission() includes root and child authority waits. This local
            # cutoff cannot authorize a canonical request after either wait.
            raise ChildTurnExpired("original child turn cutoff elapsed")
        response = self.authority.call(
            "turn",
            root.spec.scope,
            root.attempt_id,
            child_id=child_id,
            request_key=key,
            request_digest=request_digest,
        )
        verify_grant(
            response,
            root,
            self.policy(root.spec),
            original=json.loads(child["grant_json"]),
        )
        turn = response.get("turn", {})
        if (
            turn.get("child_id") != child_id
            or turn.get("root_attempt_id") != root.attempt_id
            or turn.get("request_digest") != request_digest
        ):
            raise AuthorityUnavailable(
                "canonical child turn changed its request binding"
            )
        if not response["launch_allowed"] or not self.local_allowed(root, child):
            raise ChildDenied("not_authorized")
        cutoff = min(
            cutoff,
            self.local_cutoff(worker_id, child_id),
            before + response["remaining_seconds"],
        )
        if cutoff <= time.monotonic():
            raise ChildDenied("not_authorized")
        return cutoff

    def _deliver_close(self, root):
        worker = self.journal.worker(root.worker_id)
        if worker["closed"] and not worker["close_delivered"]:
            self.authority.call(
                "close",
                root.spec.scope,
                root.attempt_id,
                reason=worker["close_reason"] or "runtime admission closed",
            )
            self.journal.close_delivered(root.worker_id)

    def _resolve(self, root, intent):
        if intent["status"] == "rejected":
            return None
        policy = self.policy(root.spec)
        if policy.session_protocol is not None:
            self.sessions.check_intent(root, policy, intent)
            if self.sessions.delivery_expired(
                root, policy, intent["request_id"], time.monotonic(), self.boot_id
            ):
                # An unresolved grant may have reached authority already. Close
                # admission before its original-key recovery, never mint a late
                # successor merely because the root's later deadline remains.
                self.journal.close_admission(
                    root.worker_id, "cold successor interval expired", retire=True
                )
        requested = json.loads(intent["payload"])
        if self.journal.worker(root.worker_id)["closed"]:
            # A replay after drain cannot accidentally allocate a previously
            # undelivered grant while the canonical admission is still open.
            self._deliver_close(root)
        before = time.monotonic()
        try:
            response = self.authority.call(
                "grant",
                root.spec.scope,
                root.attempt_id,
                request_key=intent["delivery_key"],
                **requested,
            )
        except ChildRejected as exc:
            if exc.child_not_allocated:
                self.journal.reject(root.worker_id, intent["request_id"])
                return None
            raise
        original = None
        if intent["child_id"]:
            original = json.loads(
                self.journal.child(root.worker_id, intent["child_id"])["grant_json"]
            )
        verify_grant(response, root, policy, requested, original)
        # Even a denied current permission retains the immutable allocated child.
        cutoff = min(root.monotonic_deadline, before + response["remaining_seconds"])
        child = self.journal.grant(
            root.worker_id, intent["request_id"], response, cutoff, self.boot_id, policy
        )
        if not response["launch_allowed"]:
            self.journal.update(root.worker_id, child["child_id"], revoked=1)
        return self.journal.child(root.worker_id, child["child_id"])

    def _admit_and_launch(self, root, child):
        if child["phase"] in {"running", "exec_returned", "captured", "completed"}:
            return
        cutoff = self.permission(root.worker_id, child["child_id"])
        policy = self.policy(root.spec)
        if policy.session_protocol is not None:
            cutoff = self.sessions.launch_cutoff(
                root, policy, child["child_id"], cutoff, time.monotonic()
            )
        if not self.local_allowed(root, child, admission=True):
            raise ChildDenied("not_authorized")
        if child["phase"] == "granted":
            active = self.lifecycle.observe_worker(root.spec.scope, root.worker_id)[
                "active_executions"
            ]
            if child["child_id"] not in active:
                try:
                    self.lifecycle.begin_execution(
                        root.spec.scope,
                        root.worker_id,
                        child["child_id"],
                        parent_id=root.attempt_id,
                    )
                except LifecycleConflict:
                    if self.local_allowed(root, child, admission=True):
                        raise ChildDenied("retry_later") from None
                    raise ChildDenied("not_authorized") from None
            self.journal.update(root.worker_id, child["child_id"], phase="admitted")
        self.endpoints.prepare_child(
            root, self.journal.child(root.worker_id, child["child_id"])
        )
        self.driver.launch(
            root, self.journal.child(root.worker_id, child["child_id"]), cutoff
        )

    def _status(self, child):
        binding = json.loads(child["grant_json"])["binding"]
        result = {
            "child_id": child["child_id"],
            "state": child["phase"],
            "deadline": binding["deadline"],
            "capabilities": binding["capabilities"],
        }
        root = self.journal.context(child["worker_id"])
        if self.policy(root.spec).outcome_protocol is not None:
            report = (
                json.loads(child["outcome_report"]) if child["outcome_report"] else None
            )
            result.update(
                final=False,
                initial_outcome=work_outcome(binding, report)
                | {
                    "canonical_committed": False,
                    "release_authorized": False,
                },
            )
        return result

    def report_outcome(self, worker_id, child_id, payload):
        if (
            not isinstance(payload, dict)
            or set(payload) != {"schema_version", "request_id", "outcome", "summary"}
            or type(payload["schema_version"]) is not int
            or payload["schema_version"] != 1
        ):
            raise ChildDenied("invalid_request")
        root = self.journal.context(worker_id)
        if self.closed or self.policy(root.spec).outcome_protocol is None:
            raise ChildDenied("not_authorized")
        child = self.journal.child(worker_id, child_id)
        try:
            report = self.journal.retain_outcome(
                worker_id,
                child_id,
                payload["request_id"],
                payload["outcome"],
                payload["summary"],
            )
        except (ValueError, UnicodeError):
            raise ChildDenied("invalid_request") from None
        outcome = work_outcome(json.loads(child["grant_json"])["binding"], report)
        return {
            "schema_version": 1,
            "request_id": payload["request_id"],
            "ok": True,
            "child_id": child_id,
            "work_turn_id": outcome["work_turn_id"],
            "report": report,
            "final": False,
            "canonical_committed": False,
            "release_authorized": False,
        }

    def handle(self, worker_id, payload):
        if (
            not isinstance(payload, dict)
            or type(payload.get("schema_version")) is not int
            or payload["schema_version"] != 1
        ):
            raise ChildDenied("invalid_request")
        request_id, operation = payload.get("request_id"), payload.get("operation")
        if isinstance(operation, str) and operation in SESSION_OPERATIONS:
            return self._handle_session(worker_id, payload)
        fields = {
            "spawn": {"instructions", "seconds", "max_turns", "capabilities"},
            "status": {"child_id"},
            "result": {"child_id", "kind", "offset", "limit"},
            "cancel": {"child_id", "reason"},
            "close": {"reason"},
        }
        if (
            not isinstance(request_id, str)
            or not IDENTIFIER.fullmatch(request_id)
            or not isinstance(operation, str)
            or operation not in fields
            or set(payload)
            != fields[operation] | {"schema_version", "request_id", "operation"}
        ):
            raise ChildDenied("invalid_request")
        root = self.journal.context(worker_id)
        result = {"schema_version": 1, "request_id": request_id, "ok": True}
        if operation in {"close", "cancel"}:
            reason = payload["reason"]
            if (
                not isinstance(reason, str)
                or not reason
                or "\0" in reason
                or len(reason.encode()) > 2000
            ):
                raise ChildDenied("invalid_request")
            if operation == "cancel":
                if not isinstance(payload["child_id"], str) or not CHILD_ID.fullmatch(
                    payload["child_id"]
                ):
                    raise ChildDenied("invalid_request")
                child = self.journal.child(worker_id, payload["child_id"])
                self.journal.update(worker_id, child["child_id"], revoked=1)
                self.journal.close_admission(worker_id, reason, retire=True)
                self.authority.call(
                    "revoke",
                    root.spec.scope,
                    root.attempt_id,
                    child_id=child["child_id"],
                    reason=reason,
                )
                result.update(
                    child_id=child["child_id"], state="worker_retirement_requested"
                )
            else:
                self.journal.close_admission(worker_id, reason)
            self._deliver_close(root)
            return result
        if operation == "spawn":
            policy = self.policy(root.spec)
            try:
                requested = policy.request(
                    {key: payload[key] for key in fields[operation]}
                )
            except ValueError:
                raise ChildDenied("invalid_request") from None
            prior = next(
                (
                    item
                    for item in self.journal.intents(worker_id)
                    if item["request_id"] == request_id
                ),
                None,
            )
            self._root_permission(root, admission=prior is None)
            lock = self._operation_lock(worker_id)
            if not lock.acquire(timeout=0.05):
                raise ChildDenied("retry_later")
            try:
                if policy.session_protocol is not None:
                    self.sessions.all(root, policy)
                intent = self.journal.reserve(worker_id, request_id, requested, policy)
                child = self._resolve(root, intent)
                if child is None:
                    raise ChildDenied("child_not_allocated")
                allowed = self.local_allowed(root, child, admission=True)
                if allowed:
                    self._admit_and_launch(root, child)
                return (
                    result
                    | self._status(self.journal.child(worker_id, child["child_id"]))
                    | {"launch_allowed": allowed}
                )
            finally:
                lock.release()
        self._root_permission(root)
        child_id = payload["child_id"]
        if not isinstance(child_id, str) or not CHILD_ID.fullmatch(child_id):
            raise ChildDenied("invalid_request")
        child = self.journal.child(worker_id, child_id)
        child = self.driver.observe(root, child)
        if operation == "status":
            return result | self._status(child)
        kind, offset, limit = payload["kind"], payload["offset"], payload["limit"]
        if (
            not isinstance(kind, str)
            or kind not in {"patch", "log"}
            or type(offset) is not int
            or offset < 0
            or type(limit) is not int
            or not 1 <= limit <= 65536
        ):
            raise ChildDenied("invalid_request")
        provisional = json.loads(child["provisional"])
        if kind not in provisional:
            provisional[kind] = self.driver.provisional(root, child, kind)
            self.journal.update(worker_id, child_id, provisional=canonical(provisional))
        content = provisional[kind].encode()
        if offset > len(content):
            raise ChildDenied("invalid_request")
        try:
            content[:offset].decode("utf-8")
        except UnicodeDecodeError:
            raise ChildDenied("invalid_request") from None
        chunk = content[offset : offset + limit].decode("utf-8", errors="ignore")
        if not chunk and offset < len(content):
            raise ChildDenied("invalid_request")
        return result | {
            "child_id": child_id,
            "kind": kind,
            "offset": offset,
            "final": False,
            "content": chunk,
            "content_sha256": text_hash(chunk),
            "artifact_sha256": text_hash(provisional[kind]),
            "total_bytes": len(content),
        }

    def mark_retiring(
        self, worker_id, reason="worker retirement closes child admission"
    ):
        try:
            self.journal.close_admission(worker_id, reason, retire=True)
            if self.endpoints is not None:
                self.endpoints.revoke(worker_id)
        except LifecycleConflict:
            pass

    def retiring(self, worker_id):
        try:
            return bool(self.journal.worker(worker_id)["retire"])
        except LifecycleConflict:
            return False

    def close_admission(self, worker_id, reason="runtime drain"):
        self.journal.close_admission(worker_id, reason)

    def reconcile(self, worker_id):
        root = self.journal.context(worker_id)
        lock = self._operation_lock(worker_id)
        if not lock.acquire(blocking=False):
            return
        try:
            self._deliver_close(root)
            for intent in self.journal.intents(worker_id):
                if intent["child_id"] is None and intent["status"] != "rejected":
                    self._resolve(root, intent)
            for child in self.journal.children(worker_id):
                if child["phase"] in {"captured", "completed"}:
                    continue
                try:
                    self.permission(worker_id, child["child_id"])
                    if not self.journal.worker(worker_id)["closed"]:
                        self._admit_and_launch(root, child)
                    self.driver.observe(
                        root, self.journal.child(worker_id, child["child_id"])
                    )
                except ChildDenied as exc:
                    if exc.code != "retry_later":
                        self.journal.close_admission(
                            worker_id,
                            "child permission revoked or expired",
                            retire=True,
                        )
            self._progress_sessions(root)
        finally:
            lock.release()

    def finalize(self, worker_id, receipt):
        root = self.journal.context(worker_id)
        self.mark_retiring(worker_id)
        lock = self._operation_lock(worker_id)
        if not lock.acquire(timeout=0.05):
            raise RuntimeUnavailable("child grant delivery is still in progress")
        try:
            if self._session_enabled(root):
                self.sessions.all(root, self.policy(root.spec))
            self._deliver_close(root)
            for intent in self.journal.intents(worker_id):
                if intent["status"] != "rejected":
                    self._resolve(root, intent)
            known = {
                child["child_id"]: child for child in self.journal.children(worker_id)
            }
            canonical_children = self.authority.children(
                root.spec.scope, root.attempt_id
            )
            returned = set()
            for response in canonical_children["children"]:
                verify_grant(response, root, self.policy(root.spec))
                child_id = response["binding"]["child_id"]
                if child_id not in known or child_id in returned:
                    raise RuntimeUnavailable(
                        "canonical child listing changed its owned lineage"
                    )
                verify_grant(
                    response,
                    root,
                    self.policy(root.spec),
                    original=json.loads(known[child_id]["grant_json"]),
                )
                returned.add(child_id)
            if returned != set(known):
                raise RuntimeUnavailable(
                    "canonical children lack matching durable local delivery intent"
                )
            for child in self.journal.children(worker_id):
                if child["capture"] is None:
                    contents = self.driver.final_capture(root, child, receipt)
                    state = (
                        "timed_out"
                        if child["exec_dispatched"]
                        and time.monotonic() >= child["deadline"]
                        else "exited"
                    )
                    self.journal.freeze_capture(
                        worker_id,
                        child["child_id"],
                        contents,
                        state,
                        expected_report=child["outcome_report"],
                    )
                    child = self.journal.child(worker_id, child["child_id"])
                captured = json.loads(child["capture"])
                expected_outcome = json.loads(captured["contents"]["manifest"]).get(
                    "work_outcome"
                )
                if (
                    self.policy(root.spec).outcome_protocol is not None
                    and expected_outcome is None
                ):
                    raise RuntimeUnavailable(
                        "enabled child outcome is missing from final capture"
                    )
                artifacts = json.loads(child["artifacts"])
                for kind, content in captured["contents"].items():
                    expected = text_hash(content)
                    if kind in artifacts and artifacts[kind] != expected:
                        raise LifecycleConflict("delivered child artifact changed")
                    if kind not in artifacts:
                        response = self.authority.call(
                            "capture",
                            root.spec.scope,
                            root.attempt_id,
                            child_id=child["child_id"],
                            kind=kind,
                            content=content,
                        )
                        if (
                            response.get("child_id") != child["child_id"]
                            or response.get("kind") != kind
                            or response.get("artifact_id") != expected
                            or response.get("runtime_principal")
                            != root.runtime_principal
                        ):
                            raise AuthorityUnavailable(
                                "canonical child capture receipt changed"
                            )
                        artifacts[kind] = expected
                        self.journal.update(
                            worker_id, child["child_id"], artifacts=canonical(artifacts)
                        )
                result = self.authority.call(
                    "observe",
                    root.spec.scope,
                    root.attempt_id,
                    child_id=child["child_id"],
                    state=captured["state"],
                    termination_confirmed=True,
                    launch_fenced=True,
                    artifacts=artifacts,
                )
                terminal = result.get("child", {})
                outcome_matches = True
                if expected_outcome is not None:
                    try:
                        outcome_matches = canonical(
                            terminal.get("initial_outcome")
                        ) == canonical(
                            expected_outcome
                            | {
                                "artifacts": artifacts,
                                "canonical_committed": True,
                                "release_authorized": False,
                            }
                        )
                    except (TypeError, ValueError):
                        outcome_matches = False
                if (
                    terminal.get("id") != child["child_id"]
                    or terminal.get("termination_confirmed") is not True
                    or terminal.get("launch_fenced") is not True
                    or terminal.get("captured_artifacts") != artifacts
                    or terminal.get("binding")
                    != json.loads(child["grant_json"])["binding"]
                    or terminal.get("state") != captured["state"]
                    or not outcome_matches
                ):
                    raise AuthorityUnavailable(
                        "canonical child terminal receipt is incomplete"
                    )
                self.journal.update(worker_id, child["child_id"], phase="completed")
                active = self.lifecycle.observe_worker(root.spec.scope, worker_id)[
                    "active_executions"
                ]
                if child["child_id"] in active:
                    self.lifecycle.record_execution_end(
                        root.spec.scope,
                        worker_id,
                        child["child_id"],
                        termination_confirmed=True,
                        artifacts_captured=True,
                    )
            if self._session_enabled(root):
                self._observe_sessions(root)
                self.sessions.validate_final(root, self.policy(root.spec))
        finally:
            lock.release()

    def close(self):
        if self.closed:
            return
        self.closed = True
        if self.endpoints is not None:
            self.endpoints.close(self.journal.close)
        else:
            self.journal.close()
