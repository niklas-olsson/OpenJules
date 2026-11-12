"""Explicit managed-public operations joined to original child/model authority.

This host manager is not constructed by omitted policies. Every public body is
derived from approved keys and signed public context. Private instructions and
runtime lineage remain in the existing private journal and child captures.
"""

from __future__ import annotations

from contextlib import contextmanager
from copy import deepcopy
from dataclasses import replace
import hashlib
import threading
import time

from .child_supervisor import ChildDenied
from .child_types import verify_grant
from .discussion_types import Deadline, DiscussionError
from .lifecycle import LifecycleConflict, RuntimeUnavailable
from .managed_public_journal import PublicStore, remaining
from .managed_public_profiles import OwnedProfiles
from .managed_public_types import (
    PROTOCOL, CODES, DECLINE_TEXT, RESPONSE_LIMIT, SELECTED_BYTES, SELECTED_PAGES,
    ManagedPublicError, canonical, digest, finite,
    object_value, public_model_payload, validate_request,
)
from .model_broker import BrokerDenied


def _denied(code="not_authorized"):
    raise ManagedPublicError(code)


class PublicSupervisor:
    """One public operation lease per existing worker, never an inference loop."""

    def __init__(self, children):
        self.children = children
        self.journal = children.journal
        self.runtime = children.runtime
        self.model = children.model_broker
        self.store = PublicStore(self.journal)
        self.profiles = OwnedProfiles(self.store)
        self.guard = threading.Condition(threading.RLock())
        self.active = {}
        self.retiring = set()
        self.closed = False
        self.released = False
        self.endpoints = None  # Installed by the separate fixed-UID adapter.

    def enabled(self, spec):
        return self.children.enabled(spec) and (
            getattr(self.children.policy(spec), "public_discussion", None) is not None
        )

    def _root(self, worker_id):
        root = self.journal.context(worker_id)
        if not self.enabled(root.spec):
            _denied()
        return root, self.children.policy(root.spec)

    def endpoint_allowed(self, worker_id):
        worker = self.journal.worker(worker_id)
        if worker["retire"]:
            return False
        if worker["context"] is None:
            return True
        root, policy = self._root(worker_id)
        header = self.store.view(root, policy)["header"]
        return not header["closed"] and header["frozen"] is None

    def _identity(self, root, policy, child_id=None):
        attempt = self.runtime._attempt(root.worker_id)
        runtime = self.runtime._row(root.worker_id, root.spec)
        if (
            attempt is None or runtime is None or attempt["attempt_id"] != root.attempt_id
            or not attempt["exec_dispatched"] or not attempt["exec_id"]
        ):
            _denied("retry_later")
        value = {
            "schema_version": 1, "protocol": PROTOCOL,
            "worker_id": root.worker_id, "root_attempt_id": root.attempt_id,
            "task_id": root.task_id, "requirements_revision": root.requirements_revision,
            "profile_digest": root.profile_digest, "child_policy_digest": policy.fingerprint,
            "role": "root", "child_id": None,
            "uid": self.model.peer_uid_for_worker(root.worker_id),
            "exec_id": attempt["exec_id"], "grant_digest": None,
            "instructions_digest": attempt["input_sha256"],
        }
        if value["uid"] != self.runtime._profile(root.spec).uid:
            _denied("state_conflict")
        if child_id is not None:
            child = self.journal.child(root.worker_id, child_id)
            if not child["exec_dispatched"] or not child["exec_id"]:
                _denied("retry_later")
            grant = object_value(child["grant_json"], 1048576, retained=True)
            verify_grant(grant, root, policy)
            binding = grant["binding"]
            value.update({
                "role": "child", "child_id": child_id, "uid": child["uid"],
                "exec_id": child["exec_id"], "grant_digest": binding["grant_digest"],
                "instructions_digest": binding["instructions_digest"],
            })
        return value

    def _local_cutoff(self, root, child_id=None):
        """Current local fences, with no authority call or effect."""
        if root.boot_id != self.children.boot_id:
            _denied("expired")
        current = self.journal.context(root.worker_id)
        attempt = self.runtime._attempt(root.worker_id)
        if (
            current.attempt_id != root.attempt_id or current.spec != root.spec
            or current.boot_id != root.boot_id
            or attempt is None or attempt["attempt_id"] != root.attempt_id
        ):
            _denied("state_conflict")
        cutoff = min(root.monotonic_deadline, current.monotonic_deadline, attempt["deadline"])
        # Earlier child watchdogs still retire the whole root, including after
        # their exec returns. No public decision disarms or extends those facts.
        for child in self.journal.children(root.worker_id):
            if child["boot_id"] != root.boot_id:
                _denied("expired")
            cutoff = min(cutoff, child["deadline"], child["armed_deadline"] or child["deadline"])
        if child_id is not None:
            child = self.journal.child(root.worker_id, child_id)
            cutoff = min(cutoff, child["deadline"], child["armed_deadline"] or child["deadline"])
        finite(cutoff, 0, 1e15, code="state_conflict")
        return cutoff

    def _permission(self, root, child_id=None, *, admission=False):
        if child_id is None:
            cutoff = self.children._root_permission(root, admission=admission)
        else:
            cutoff = self.children.permission(root.worker_id, child_id)
            if admission and not self.children.local_allowed(
                root, self.journal.child(root.worker_id, child_id), admission=True,
            ):
                _denied()
        cutoff = min(cutoff, self._local_cutoff(root, child_id))
        if cutoff <= time.monotonic():
            _denied("expired")
        return cutoff

    def _deadline(self, root, request, slot=None, *, permission=None):
        if remaining(request, root.boot_id) <= 0:
            _denied("expired")
        cutoff = min(request["monotonic_cutoff"], self._local_cutoff(root))
        expires = min(request["expires_at"], root.deadline)
        if slot is not None:
            if remaining(slot, root.boot_id) <= 0:
                _denied("expired")
            cutoff = min(cutoff, slot["monotonic_cutoff"])
            expires = min(expires, slot["expires_at"])
        if permission is not None:
            cutoff = min(cutoff, permission)
        result = Deadline(expires, cutoff)
        result.remaining()
        return result

    @contextmanager
    def _lease(self, worker_id, request_id, who):
        token = {"request_id": request_id, "actor_id": who, "slot_id": None}
        with self.guard:
            if self.closed or worker_id in self.retiring:
                _denied()
            if worker_id in self.active:
                _denied("retry_later")
            self.active[worker_id] = token
        try:
            yield token
        finally:
            with self.guard:
                if self.active.get(worker_id) is not token:
                    _denied("state_conflict")
                del self.active[worker_id]
                self.guard.notify_all()

    def model_binding(self, worker_id, child_id, payload, *, admission):
        """Trusted local callback used while the common model gate is held."""
        root, policy = self._root(worker_id)
        bundle = self.store.view(root, policy)
        who = "root" if child_id is None else child_id
        actor = bundle["actors"].get(who)
        slot = bundle["slots"].get(payload.get("public_slot"))
        if (
            actor is None or slot is None or slot["actor_id"] != who
            or actor["identity"] != self._identity(root, policy, child_id)
            or slot["decision_request_id"] is None
            or canonical(public_model_payload(bundle["policy"], actor, slot)) != canonical(payload)
            or slot["model_call_digest"] != digest(payload)
        ):
            _denied("state_conflict")
        request = bundle["requests"][slot["decision_request_id"]]
        cutoff = min(
            slot["monotonic_cutoff"], request["monotonic_cutoff"], root.monotonic_deadline,
        )
        if admission:
            with self.guard:
                active = self.active.get(worker_id)
                if (
                    self.closed or active is None or active["actor_id"] != who
                    or active["request_id"] != request["request_id"]
                    or active["slot_id"] != slot["slot_id"]
                ):
                    _denied()
            child = None if child_id is None else self.journal.child(worker_id, child_id)
            if (
                bundle["header"]["closed"] or bundle["header"]["frozen"] is not None
                or actor["closed"] or slot["response"] is not None
                or slot["state"] != "model_pending" or request["state"] == "refused"
                or not self.children.local_allowed(root, child)
            ):
                _denied()
            cutoff = self._deadline(root, request, slot).monotonic_cutoff
        return {
            "policy": bundle["policy"], "actor": actor, "slot": slot, "cutoff": cutoff,
        }

    def _result(self, root, policy, request_id):
        bundle = self.store.view(root, policy)
        request = bundle["requests"][request_id]
        operation = request["payload"]["operation"]
        actor = bundle["actors"][request["actor_id"]]
        if operation == "public_pending":
            result = {
                "actor": self.store.project_actor(actor),
                "slots": [
                    self.store.project_slot(bundle, key)
                    for key, slot in bundle["slots"].items()
                    if slot["actor_id"] == actor["actor_id"]
                ],
            }
        elif operation == "public_read":
            if request["result"] is None:
                _denied(request["error"] or "publication_uncertain")
            result = {"actor": self.store.project_actor(actor), "history": request["result"]}
        elif operation == "public_invite":
            invitation = request["invitation"]
            if invitation is None or invitation["receipt"] is None:
                _denied(request["error"] or "publication_uncertain")
            result = {
                "actor": self.store.project_actor(actor),
                **{name: invitation[name] for name in (
                    "invitation_key", "publication_request_key", "state", "reason", "receipt",
                )},
            }
        else:
            slot = bundle["slots"][request["slot_id"]]
            if operation in {"public_turn", "public_pull", "public_decline"} and slot["receipt"] is None:
                _denied(slot["reason"] or request["error"] or "publication_uncertain")
            result = {"slot": self.store.project_slot(bundle, slot["slot_id"])}
        envelope = {
            "schema_version": 1, "request_id": request_id, "ok": True,
            "result": result | {"execution_authorized": False},
        }
        canonical(envelope, limit=RESPONSE_LIMIT)
        return envelope

    def _record_failure(self, root, policy, request_id, code):
        if code in {"retry_later", "canonical_pending"}:
            return code
        bundle = self.store.view(root, policy)
        request = bundle["requests"].get(request_id)
        if request is None or request["result"] is not None:
            return code
        slot = bundle["slots"].get(request["slot_id"])
        if slot is not None and slot["receipt"] is not None:
            return code
        invitation = request["invitation"]
        if invitation is not None and invitation["receipt"] is not None:
            return code
        # An unsuccessful retry cannot turn an earlier unknown dispatch into
        # conclusive refusal. Original-key recovery and final capture retain it.
        if slot is not None and slot["state"] in {
            "model_pending", "publication_pending", "leave_pending", "uncertain",
        }:
            if slot["publication_intent"] is not None:
                code = "publication_uncertain"
            elif slot["model_call_digest"] is not None:
                code = "provider_uncertain"
        if invitation is not None and invitation["state"] in {"publication_pending", "uncertain"}:
            code = "publication_uncertain"
        self.store.failure(
            root, policy, request_id, code,
            slot_id=None if slot is None else slot["slot_id"],
            uncertain=code in {"provider_uncertain", "publication_uncertain"},
        )
        return code

    def _owned_uncertainty(self, root, policy, identity, payload, fallback):
        """Classify only an exact retained owner, with a read-only snapshot."""
        if fallback not in {"not_authorized", "expired"}:
            return fallback
        try:
            with self.journal.connection() as db:
                db.execute("BEGIN")
                bundle = self.store._checked(db, root.worker_id, policy)
                request = bundle["requests"].get(payload["request_id"])
                if (
                    request is None or request["payload"] != payload
                    or request["actor_id"] != ("root" if identity["child_id"] is None else identity["child_id"])
                    or bundle["actors"][request["actor_id"]]["identity"] != identity
                ):
                    return fallback
                invitation = request["invitation"]
                if (
                    invitation is not None and invitation["receipt"] is None
                    and invitation["state"] in {"publication_pending", "uncertain"}
                ):
                    return "publication_uncertain"
                slot = bundle["slots"].get(request["slot_id"])
                if slot is not None and slot["receipt"] is None and slot["state"] in {
                    "model_pending", "publication_pending", "leave_pending", "uncertain",
                }:
                    if slot["publication_intent"] is not None:
                        return "publication_uncertain"
                    if slot["model_call_digest"] is not None:
                        return "provider_uncertain"
                return fallback
        except (ManagedPublicError, LifecycleConflict, KeyError, TypeError, ValueError):
            return "state_conflict"

    def handle(self, worker_id, payload, *, child_id=None):
        role, who = ("root", "root") if child_id is None else ("child", child_id)
        validate_request(payload, role)
        root, policy = self._root(worker_id)
        identity = self._identity(root, policy, child_id)
        request_id = payload["request_id"]
        try:
            with self._lease(worker_id, request_id, who) as lease:
                accepted = False
                try:
                    # Store owns this key before any external permission, process,
                    # model or public-wire effect. An original key replays for free.
                    request = self.store.accept(
                        root, policy, identity, payload, self._local_cutoff(root, child_id),
                    )
                    accepted = True
                    self._operation(root, policy, request, identity, lease)
                    return self._result(root, policy, request_id)
                except (ManagedPublicError, DiscussionError, ChildDenied, BrokerDenied) as error:
                    code = self._code(error)
                    if accepted:
                        code = self._record_failure(root, policy, request_id, code)
                    raise ManagedPublicError(code) from None
                except (LifecycleConflict, KeyError, TypeError, ValueError, OverflowError, RecursionError):
                    code = "state_conflict"
                    if accepted:
                        code = self._record_failure(root, policy, request_id, code)
                    raise ManagedPublicError(code) from None

        except ManagedPublicError as error:
            # An accepted handler can meet a later retirement fence before it
            # owns the operation lease. Do not misreport its old unknown post
            # as a conclusive new refusal, and never mutate a rejected owner.
            code = self._owned_uncertainty(root, policy, identity, payload, error.code)
            if code != error.code:
                raise ManagedPublicError(code) from None
            raise

    @staticmethod
    def _code(error):
        if isinstance(error, ManagedPublicError):
            return error.code
        if isinstance(error, ChildDenied):
            return error.code if error.code in {"retry_later", "canonical_pending"} else "not_authorized"
        if isinstance(error, BrokerDenied):
            if error.code in {"retry_later", "canonical_pending", "not_authorized", "invalid_request"}:
                return error.code
            return "not_authorized" if error.code == "budget_exhausted" else (
                "state_conflict" if error.code == "conflict" else "provider_uncertain"
            )
        return error.code if error.code in {"expired", "state_conflict"} else "transport_unavailable"

    def _operation(self, root, policy, request, identity, lease):
        payload, key, who = request["payload"], request["request_id"], request["actor_id"]
        operation = payload["operation"]
        if operation == "public_pending":
            return  # All lifetime slots, live under this original local read key.
        if operation == "public_status":
            self.store.claim(root, policy, key, payload["slot_id"])
            return
        bundle = self.store.view(root, policy)
        if operation == "public_read":
            if request["result"] is not None:
                return
            if request["page_charges"]:
                _denied("publication_uncertain")
            if request["state"] == "refused":
                _denied(request["error"])
            permission = self._permission(root, identity["child_id"])
            deadline = self._deadline(root, request, permission=permission)
            self.profiles.call(root, policy, who, deadline, "ready")
            self.store.charge_history(root, policy, key)
            deadline.remaining()
            page = self.profiles.call(
                root, policy, who, deadline, "history", {
                    "after": payload["after"], "stream_id": payload["stream_id"],
                    "watch": payload["watch_seconds"],
                },
            )
            self.store.retain_page(root, policy, key, page)
            return
        if operation == "public_invite":
            self._invite(root, policy, request)
            return
        if operation in {"public_activate", "public_turn"}:
            if request["slot_id"] is None:
                permission = self._permission(root, admission=True)
                target = identity if operation == "public_turn" else self._identity(
                    root, policy, payload["child_id"],
                )
                if target["child_id"] is not None:
                    permission = min(permission, self._permission(root, target["child_id"], admission=True))
                deadline = self._deadline(root, request, permission=permission)
                slot = self.store.offer(
                    root, policy, key, target, deadline.monotonic_cutoff,
                )
            else:
                slot = bundle["slots"][request["slot_id"]]
            if operation == "public_activate":
                return  # No profile start, inference, grant, or public post.
        else:
            slot = self.store.claim(root, policy, key, payload["slot_id"])
        lease["slot_id"] = slot["slot_id"]
        if slot["receipt"] is not None:
            if slot["receipt"]["record"]["body"]["kind"] == "leave":
                self._finish_leave(root, policy, slot)
            return
        if slot["state"] in {"expired", "refused"} or request["state"] == "refused":
            reason = slot["reason"] or request["error"] or "not_authorized"
            _denied("actor_left" if reason == "refused_left" else reason)
        self._slot(root, policy, request, slot, fixed=operation == "public_decline")

    def _selected(self, root, policy, request, slot, deadline):
        requested, seen, selected = set(slot["selected_message_ids"]), set(), []
        used, after = 0, 0
        who = slot["actor_id"]
        status = self.store.view(root, policy)["actors"][who]["status"]
        for _ in range(SELECTED_PAGES):
            self.store.charge_history(root, policy, request["request_id"], slot_id=slot["slot_id"])
            deadline.remaining()
            page = self.profiles.call(
                root, policy, who, deadline, "history",
                {"after": after, "stream_id": status["stream_id"], "watch": 0},
            )
            if page["gap"] is not None:
                _denied("context_unavailable")
            for item in page["messages"]:
                record = item["record"]
                identifier = record["message_id"]
                if identifier in requested:
                    if identifier in seen:
                        _denied("context_unavailable")
                    selected.append(record)
                    seen.add(identifier)
                    used += len(canonical(record))
                    if used > SELECTED_BYTES:
                        _denied("context_unavailable")
            if seen == requested:
                return selected
            if not page["has_more"] or page["next_cursor"] <= after:
                _denied("context_unavailable")
            after = page["next_cursor"]
        _denied("context_unavailable")

    def _model_result(self, root, policy, slot, result):
        if (
            not isinstance(result, dict) or type(result.get("schema_version")) is not int
            or result["schema_version"] != 1 or result.get("request_id") != slot["model_key"]
            or result.get("ok") is not True or set(result) != {
                "schema_version", "request_id", "ok", "output",
            }
        ):
            _denied("not_authorized" if isinstance(result, dict) and result.get("ok") is False else "provider_uncertain")
        return self.store.retain_response(root, policy, slot["slot_id"], result["output"])

    def _recover_model(self, root, policy, slot):
        bundle = self.store.view(root, policy)
        actor = bundle["actors"][slot["actor_id"]]
        payload = public_model_payload(bundle["policy"], actor, slot)
        observation = self.model.inspect_public(
            root.worker_id, root.attempt_id, payload, child_id=actor["identity"]["child_id"],
        )
        if observation["status"] == "complete":
            return self._model_result(root, policy, slot, observation["result"])
        if observation["status"] in {"reserved", "uncertain"}:
            _denied("provider_uncertain")
        return slot

    def _slot(self, root, policy, request, slot, *, fixed=False):
        who, slot_id = slot["actor_id"], slot["slot_id"]
        if slot["model_call_digest"] is not None and slot["response"] is None:
            # Bounded local completion acknowledgement precedes expiry checks.
            # It never refreshes permission, reserves a turn or invokes HTTP.
            slot = self._recover_model(root, policy, slot)
        if slot["response"] is None:
            permission = self._permission(root, None if who == "root" else who)
            deadline = self._deadline(root, request, slot, permission=permission)
            self.profiles.call(root, policy, who, deadline, "ready")
            if fixed:
                slot = self.store.retain_response(
                    root, policy, slot_id,
                    {"kind": "decline", "content": DECLINE_TEXT}, fixed_decline=True,
                )
            else:
                if slot["context"] is None:
                    records = self._selected(root, policy, request, slot, deadline)
                    slot = self.store.freeze_context(root, policy, slot_id, records)
                deadline.remaining()
                payload = self.store.model_intent(root, policy, slot_id)
                try:
                    reply = self.model.complete_public(
                        root.worker_id, payload, child_id=None if who == "root" else who,
                    )
                except BrokerDenied:
                    # A final permission check can reject after the real
                    # completed response was durably written. Retain that exact
                    # response locally, but do not bypass publication permission.
                    latest = self.store.view(root, policy)["slots"][slot_id]
                    self._recover_model(root, policy, latest)
                    raise
                slot = self._model_result(root, policy, slot, reply)
        permission = self._permission(root, None if who == "root" else who)
        deadline = self._deadline(root, request, slot, permission=permission)
        recovery = slot_id if slot["response"]["kind"] == "leave" else None
        self.profiles.call(root, policy, who, deadline, "ready", recovery_slot=recovery)
        intent = self.store.publication_intent(root, policy, slot_id)
        deadline.remaining()
        try:
            receipt = self.profiles.call(
                root, policy, who, deadline, "say", {"intent": intent}, recovery_slot=recovery,
            )
        except (ManagedPublicError, DiscussionError):
            _denied("publication_uncertain")
        self.store.receipt(root, policy, slot_id, receipt)
        if recovery is not None:
            self._finish_leave(root, policy, slot)

    def _finish_leave(self, root, policy, slot):
        who = slot["actor_id"]
        self.profiles.stop_actor(root.worker_id, who)
        cutoff = time.monotonic() + 5
        while not self.profiles.quiescent(root.worker_id, who=who):
            if time.monotonic() >= cutoff:
                _denied("transport_unavailable")
            time.sleep(0.01)
        bundle = self.store.view(root, policy)
        if any(
            row["actor_id"] == who and row["state"] != "stopped"
            for row in bundle["processes"].values()
        ):
            _denied("state_conflict")

    def _invite(self, root, policy, request):
        if request["invitation"] is not None and request["invitation"]["receipt"] is not None:
            return
        if request["state"] == "refused":
            _denied(request["error"])
        permission = self._permission(root)
        deadline = self._deadline(root, request, permission=permission)
        self.store.invite(root, policy, request["request_id"])
        self.profiles.call(root, policy, "root", deadline, "ready")
        intent = self.store.invitation_intent(root, policy, request["request_id"])
        deadline.remaining()
        try:
            receipt = self.profiles.call(root, policy, "root", deadline, "say", {"intent": intent})
        except (ManagedPublicError, DiscussionError):
            _denied("publication_uncertain")
        self.store.invitation_receipt(root, policy, request["request_id"], receipt)

    def retire(self, worker_id):
        """Durable closure first; stop requests never wait under a journal lock."""
        root, policy = self._root(worker_id)
        with self.guard:
            self.retiring.add(worker_id)
        try:
            self.store.close(root, policy)
        finally:
            # Even an unreadable journal cannot keep accepting new work. Final
            # capture separately requires the durable closed/frozen proof.
            if self.endpoints is not None:
                self.endpoints.stop_worker(worker_id)
            self.profiles.stop_worker(worker_id)

    def quiescent(self, worker_id):
        with self.guard:
            if worker_id in self.active:
                return False
        return (
            (self.endpoints is None or self.endpoints.quiescent(worker_id))
            and self.profiles.quiescent(worker_id)
        )

    def _freeze(self, root, policy):
        self.retire(root.worker_id)
        if not self.quiescent(root.worker_id):
            raise RuntimeUnavailable("managed public owners are still active")
        bundle = self.store.view(root, policy)
        if bundle["header"]["frozen"] is None:
            for slot in bundle["slots"].values():
                if slot["model_call_digest"] is not None and slot["response"] is None:
                    try:
                        self._recover_model(root, policy, slot)
                    except (BrokerDenied, DiscussionError, ManagedPublicError) as error:
                        code = self._code(error)
                        self.store.failure(
                            root, policy, slot["decision_request_id"], code,
                            slot_id=slot["slot_id"],
                            uncertain=code in {"provider_uncertain", "publication_uncertain"},
                        )
            # Store independently refuses unknown start/cleanup facts. Observed
            # task completion alone is never a process-termination certificate.
            self.store.freeze(root, policy, owners_quiescent=True)
        extensions = self.store.extensions(root, policy)
        self.profiles.release_worker(root.worker_id)
        if self.endpoints is not None:
            self.endpoints.release_worker(root.worker_id)
        return extensions

    def effective_receipt(self, worker_id, receipt, *, prepare):
        """Derive both capture paths from one frozen snapshot and original bytes."""
        root, policy = self._root(worker_id)
        if not (
            receipt.termination_confirmed is True
            and receipt.launch_fenced is True
            and receipt.artifacts_captured is True
            and isinstance(receipt.manifest, str)
        ):
            raise RuntimeUnavailable("managed public capture requires the whole-worker fence")
        try:
            if prepare:
                public, _children = self._freeze(root, policy)
            else:
                if not self.quiescent(worker_id):
                    raise RuntimeUnavailable("managed public owners are still active")
                public, _children = self.store.extensions(root, policy)
            original = object_value(
                receipt.manifest, 4_000_000, code="state_conflict", retained=True,
            )
            if (
                "managed_public_v1" in original
                or "managed_public_original_manifest_sha256" in original
                or original.get("worker_id") != worker_id
                or original.get("attempt_id") != root.attempt_id
            ):
                _denied("state_conflict")
            manifest = original | {
                "managed_public_v1": public,
                "managed_public_original_manifest_sha256": hashlib.sha256(
                    receipt.manifest.encode("utf-8")
                ).hexdigest(),
            }
            encoded = canonical(manifest, limit=4_000_000).decode("utf-8")
            return replace(receipt, manifest=encoded)
        except (ManagedPublicError, DiscussionError, LifecycleConflict) as error:
            raise RuntimeUnavailable("managed public capture is unresolved") from error

    def child_manifest(self, root, child_id, manifest):
        """Add only this child's private map before its first immutable capture."""
        policy = self.children.policy(root.spec)
        public, private = self.store.extensions(root, policy)
        if (
            child_id not in private or "managed_public_v1" in manifest
            or manifest.get("worker_id") != root.worker_id
            or manifest.get("root_attempt_id") != root.attempt_id
            or manifest.get("child_id") != child_id
        ):
            raise RuntimeUnavailable("managed public child capture changed")
        result = manifest | {"managed_public_v1": private[child_id]}
        canonical(result, limit=min(policy.max_result_bytes, 4_000_000))
        return result

    def validate_child_capture(self, root, child_id, manifest):
        _public, private = self.store.extensions(root, self.children.policy(root.spec))
        if (
            child_id not in private
            or canonical(manifest.get("managed_public_v1")) != canonical(private[child_id])
        ):
            raise RuntimeUnavailable("managed public child evidence changed")

    def close(self, released):
        """Retain the private journal until every real handler and owner exits."""
        with self.guard:
            if self.closed:
                return
            self.closed = True
        if self.endpoints is not None:
            self.endpoints.stop_all()
        self.profiles.close()

        def release_when_stopped():
            if self.endpoints is not None:
                self.endpoints.join()
            self.profiles.thread.join()
            with self.guard:
                self.guard.wait_for(lambda: not self.active)
                if self.released:
                    return
                self.released = True
            released()

        if (
            (self.endpoints is None or self.endpoints.all_quiescent())
            and not self.profiles.thread.is_alive()
        ):
            with self.guard:
                active = bool(self.active)
            if not active:
                release_when_stopped()
                return
        threading.Thread(
            target=release_when_stopped, daemon=True, name="managed-public-close",
        ).start()
