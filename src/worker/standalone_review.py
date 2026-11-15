"""One original, explicitly admitted standalone review operation.

The operation owns bounded facts and dispatch admission, never a canonical
task or a retry queue. Native resources remain with the supplied backend.
"""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import math
import threading
import time

from .review_contract import ReviewClaim, ReviewError, REVIEW_CODES, RESULT_SCHEMA
from .review_result import (
    COUNTERS, DATA_FIELDS, FACT_FIELDS, KINDS, MAX_INTEGER, STATES,
    required_result_capacity, validate_fact, validate_result,
)


@dataclass(frozen=True)
class ReviewEffect:
    id: int
    deadline: float
    _owner: object = field(repr=False, compare=False)


class ReviewOperation:
    """Sticky admission and facts for one original callback and clock epoch.

    ``response_bytes`` in reserve is an upper allowance, never an observation.
    ``consume`` records actual bytes, including a rejected over-limit chunk.
    Effects expose immutable original deadlines for streaming/nested calls.
    """

    def __init__(self, claim: ReviewClaim, *, clock=time.monotonic):
        if not isinstance(claim, ReviewClaim) or not callable(clock):
            raise ReviewError("protocol_refused")
        self.claim, self.profile, self.limits = claim, claim.profile, claim.profile.limits
        self._clock, self._lock, self._owner = clock, threading.RLock(), object()
        self._effects, self._secrets, self._invoking = {}, [], set()
        self._record_broken, self._finalized = False, False
        total, reserve = self.limits["total_ms"], self.limits["cleanup_reserve_ms"]
        if (type(total) is not int or type(reserve) is not int or not 0 < reserve < total
                or type(claim.started_at) not in (int, float) or not math.isfinite(claim.started_at)
                or claim.started_at < 0):
            raise ReviewError("protocol_refused")
        if self.limits["receipt_result_bytes"] < required_result_capacity(self.limits):
            raise ReviewError("capacity_exhausted")
        self._work_deadline = claim.started_at + (total - reserve) / 1000
        self._retirement_deadline = claim.started_at + total / 1000
        original, review = claim.original, claim.original["review"]
        self._result = {
            "schema": RESULT_SCHEMA, "operation_id": claim.operation_id, "owner_epoch": claim.owner_epoch,
            "profile_digest": claim.profile.digest, "activation_digest": claim.activation_digest,
            "request_digest": original["request_digest"],
            "identity": {"repository_id": original["binding"]["repository_id"],
                         "pull_number": review["pull_number"], "review_id": review["review_id"],
                         "head_ref": review["head_ref"], "head_sha": review["head_sha"]},
            "status": "running", "first_failure": None,
            "timing": {"started_ms": int(claim.started_at * 1000),
                       "work_deadline_ms": int(self.work_deadline * 1000),
                       "total_deadline_ms": int(self.retirement_deadline * 1000)},
            "counters": dict.fromkeys(COUNTERS, 0), "effects": [],
            "facts": {name: {} for name in FACT_FIELDS},
        }
        for value in claim.credentials.literal_secrets:
            self.add_secret(value)
        self._save()

    def _latch(self, code, unknown=False):
        if type(code) is not str or code not in REVIEW_CODES or type(unknown) is not bool:
            code, unknown = "unexpected_failure", True
        if self._result["first_failure"] is None:
            self._result["first_failure"] = {"code": code, "unknown": unknown}
        self._result["status"] = "unknown" if (unknown or self._result["status"] == "unknown"
                                                  or self._result["first_failure"]["unknown"]) else "refused"

    @property
    def work_deadline(self):
        return self._work_deadline

    @property
    def retirement_deadline(self):
        return self._retirement_deadline

    @property
    def total_deadline(self):
        return self._retirement_deadline

    def now(self):
        return self._clock()

    def _save(self, *, retirement=False, observation=False):
        if self._record_broken:
            if retirement or observation:
                return False
            raise ReviewError(self._result["first_failure"]["code"], unknown=True)
        try:
            safe = validate_result(self._result, max_bytes=self.limits["receipt_result_bytes"])
            self.claim.persist_result(safe)
        except BaseException:
            self._record_broken = True
            self._latch("record_unavailable", True)
            if retirement or observation:
                return False
            raise ReviewError(self._result["first_failure"]["code"], unknown=True) from None
        return True

    def snapshot(self):
        with self._lock:
            return validate_result(self._result, max_bytes=self.limits["receipt_result_bytes"])

    def fact(self, name):
        return self.snapshot()["facts"][name]

    def fail(self, code, unknown=False):
        """Retain the first failure, persist it, then stop this caller."""
        with self._lock:
            self._latch(code, unknown)
            self._save(observation=True)
            failure = self._result["first_failure"]
            raise ReviewError(failure["code"], unknown=self._result["status"] == "unknown")

    def check(self, cleanup=False):
        with self._lock:
            if type(cleanup) is not bool:
                self.fail("protocol_refused")
            if self._finalized:
                self.fail("protocol_refused")
            if self._record_broken and not cleanup:
                raise ReviewError(self._result["first_failure"]["code"], unknown=True)
            failure = self._result["first_failure"]
            if failure is not None and not cleanup:
                raise ReviewError(failure["code"], unknown=self._result["status"] == "unknown")
            try:
                if cleanup:
                    self.claim.validate_retirement()
                else:
                    self.claim.validate_productive()
                    self.claim.credentials.validate_epoch()
            except BaseException:
                self.fail("custody_unavailable" if cleanup else "authority_changed", unknown=cleanup)
            # Validators can take time or observe a concurrent original failure.
            if not cleanup and self._result["first_failure"] is not None:
                failure = self._result["first_failure"]
                raise ReviewError(failure["code"], unknown=self._result["status"] == "unknown")
            cutoff = self.retirement_deadline if cleanup else self.work_deadline
            now = self._clock()
            if not math.isfinite(now) or now >= cutoff:
                self.fail("deadline_exhausted", unknown=cleanup)

    def remaining(self, timeout_ms, cleanup=False):
        if type(timeout_ms) is not int or not 0 < timeout_ms <= MAX_INTEGER:
            self.fail("protocol_refused")
        self.check(cleanup)
        remaining = min(timeout_ms / 1000, (self.retirement_deadline if cleanup else self.work_deadline) - self._clock())
        if remaining <= 0:
            self.fail("deadline_exhausted", unknown=cleanup)
        return remaining

    def _number(self, value):
        if type(value) is not int or not 0 <= value <= MAX_INTEGER:
            self.fail("protocol_refused")
        return value

    def reserve(self, kind, *, request_bytes=0, response_bytes=0, output_tokens=0, cleanup=False, deadline=None, data=None):
        with self._lock:
            if type(kind) is not str or kind not in KINDS or type(cleanup) is not bool or (cleanup and kind != "guest_api"):
                self.fail("protocol_refused")
            self.check(cleanup)
            request_bytes, response_bytes, output_tokens = (self._number(v) for v in (request_bytes, response_bytes, output_tokens))
            if output_tokens and kind != "model":
                self.fail("protocol_refused")
            if data is None:
                data = {}
            if type(data) is not dict or set(data) - set(DATA_FIELDS) or any(not DATA_FIELDS[k](v) for k, v in data.items()):
                self.fail("protocol_refused")
            counter = dict(self._result["counters"])
            maximum = {"forge_get": 4, "forge_token": 1, "git": self.limits["git_calls"],
                       "guest_api": self.limits["guest_api_calls"], "exec": self.limits["exec_calls"],
                       "model": self.limits["model_calls"]}[kind]
            if counter[kind] >= maximum:
                self.fail("capacity_exhausted")
            if kind == "guest_api":
                if cleanup:
                    if counter["guest_api_cleanup"] >= self.limits["guest_api_cleanup_calls"]:
                        self.fail("capacity_exhausted", unknown=True)
                    counter["guest_api_cleanup"] += 1
                elif counter["guest_api"] - counter["guest_api_cleanup"] >= maximum - self.limits["guest_api_cleanup_calls"]:
                    self.fail("capacity_exhausted")
                if response_bytes > self.limits["archive_bytes"]:
                    self.fail("capacity_exhausted")
                counter["guest_api_response_reserved"] += response_bytes
            counter[kind] += 1
            prefix = "forge" if kind.startswith("forge_") else kind
            if kind != "guest_api":
                per_response = self.limits[prefix + ("_output_bytes" if prefix in {"git", "exec"} else "_response_bytes")]
                total_response = self.limits[prefix + ("_output_total_bytes" if prefix in {"git", "exec"} else "_response_total_bytes")]
                key = prefix + "_response_reserved"
                if response_bytes > per_response or counter[key] + response_bytes > total_response:
                    self.fail("capacity_exhausted")
                counter[key] += response_bytes
            if kind == "model":
                if (request_bytes > self.limits["model_request_bytes"]
                        or counter["model_request_bytes"] + request_bytes > self.limits["model_request_total_bytes"]
                        or not 0 < output_tokens <= self.limits["model_output_tokens_per_call"]
                        or counter["model_output_tokens"] + output_tokens > self.limits["model_output_tokens_total"]):
                    self.fail("capacity_exhausted")
                counter["model_request_bytes"] += request_bytes
                counter["model_output_tokens"] += output_tokens
            if kind == "exec":
                if request_bytes > self.limits["exec_input_bytes"]:
                    self.fail("capacity_exhausted")
                counter["exec_request_bytes"] += request_bytes
            if any(v > MAX_INTEGER for v in counter.values()):
                self.fail("capacity_exhausted")
            duration = self.limits[{"forge_get": "forge_call_ms", "forge_token": "forge_call_ms",
                                   "git": "git_call_ms", "guest_api": "guest_api_ms",
                                   "exec": "exec_call_ms", "model": "model_call_ms"}[kind]]
            captured = min(self.retirement_deadline if cleanup else self.work_deadline,
                           self._clock() + duration / 1000)
            if deadline is not None:
                if type(deadline) not in (int, float) or not math.isfinite(deadline):
                    self.fail("protocol_refused")
                captured = min(captured, deadline)
            if self._clock() >= captured:
                self.fail("deadline_exhausted", unknown=cleanup)
            record = {"id": len(self._result["effects"]) + 1, "kind": kind, "cleanup": cleanup,
                      "deadline_ms": int(captured * 1000), "request_bytes": request_bytes,
                      "response_reserved": response_bytes, "response_bytes": 0, "output_tokens": output_tokens,
                      "code": None, "data": dict(data), **dict.fromkeys(STATES, False)}
            effect = ReviewEffect(record["id"], captured, self._owner)
            self._effects[effect.id] = effect
            self._result["effects"].append(record)
            self._result["counters"] = counter
            self._save(retirement=cleanup)
            return effect

    def _record(self, effect):
        if (not isinstance(effect, ReviewEffect) or effect._owner is not self._owner
                or self._effects.get(effect.id) is not effect):
            self.fail("protocol_refused")
        return self._result["effects"][effect.id - 1]

    def _enter(self, effect, call):
        with self._lock:
            record = self._record(effect)
            if (not callable(call) or effect.id in self._invoking or record["entered"]
                    or record["refused"] or record["outcome_unknown"] or record["closed"]):
                self.fail("protocol_refused")
            self.check(record["cleanup"])
            self._invoking.add(effect.id)
        # Admission may wait for the original lock/validator. Check after that
        # preparation, directly before entering the fixed callable.
        now = self._clock()
        if not math.isfinite(now) or now >= effect.deadline:
            with self._lock:
                record["refused"] = True
                record["code"] = "deadline_exhausted"
                self.fail("deadline_exhausted", unknown=record["cleanup"])
        record["entered"] = True
        return record

    def _raised(self, record):
        with self._lock:
            record["outcome_unknown"] = True
            if record["code"] is None:
                record["code"] = {"model": "model_outcome_unknown", "guest_api": "guest_outcome_unknown",
                                  "exec": "guest_outcome_unknown"}.get(record["kind"], "unexpected_failure")
            self._latch(record["code"], True)
            self._save(observation=True)
        raise ReviewError(self._result["first_failure"]["code"], unknown=self._result["status"] == "unknown") from None

    def _returned(self, effect, record, raw):
        with self._lock:
            if self._clock() >= effect.deadline:
                record["outcome_unknown"] = True
                if record["code"] is None:
                    record["code"] = "deadline_exhausted"
                self._latch("deadline_exhausted", True)
            record["returned"] = True
            # A returned original handle must reach its owner even if retaining
            # the observation fails. The sticky store fault closes new effects.
            self._save(observation=True)
        return raw

    def invoke(self, effect, call):
        record = self._enter(effect, call)
        try:
            raw = call()
        except BaseException:
            self._raised(record)
        return self._returned(effect, record, raw)

    async def invoke_async(self, effect, call):
        """Enter one fixed async API directly after the same original checks."""
        record = self._enter(effect, call)
        try:
            raw = await call()
        except BaseException:
            self._raised(record)
        return self._returned(effect, record, raw)

    def observe(self, effect, state, *, code=None, data=None):
        with self._lock:
            record = self._record(effect)
            if type(state) is not str or state not in STATES or (code is not None and (type(code) is not str or code not in REVIEW_CODES)):
                self.fail("protocol_refused")
            if state in {"entered", "returned", "acknowledged"} and not record["entered"]:
                self.fail("protocol_refused")
            if data is not None:
                if type(data) is not dict or set(data) - set(DATA_FIELDS) or any(not DATA_FIELDS[k](v) for k, v in data.items()):
                    self.fail("protocol_refused")
                for key, value in data.items():
                    if (key in record["data"] and record["data"][key] is not None and record["data"][key] != value
                            and not (key == "local_closed" and record["data"][key] is False and value is True)):
                        self.fail("protocol_refused")
                    record["data"][key] = value
            record[state] = True
            if record["code"] is None and code is not None:
                record["code"] = code
            if state == "outcome_unknown":
                self._latch(code or "unexpected_failure", True)
            elif state == "refused":
                self._latch(code or "protocol_refused")
            self._save(observation=True)

    def consume(self, effect, *, response_bytes=0):
        with self._lock:
            record = self._record(effect)
            amount = self._number(response_bytes)
            if not record["entered"]:
                self.fail("protocol_refused")
            prefix = "forge" if record["kind"].startswith("forge_") else record["kind"]
            key = prefix + "_response_bytes"
            if record["response_bytes"] + amount > MAX_INTEGER or self._result["counters"][key] + amount > MAX_INTEGER:
                self.fail("capacity_exhausted", unknown=True)
            record["response_bytes"] += amount
            self._result["counters"][key] += amount
            if record["response_bytes"] > record["response_reserved"]:
                record["outcome_unknown"] = True
                if record["code"] is None:
                    record["code"] = "capacity_exhausted"
                self._latch("capacity_exhausted", True)
                self._save(observation=True)
                raise ReviewError("capacity_exhausted", unknown=True)
            self._save(observation=True)

    def note(self, name, value):
        with self._lock:
            try:
                incoming = validate_fact(name, value)
            except ReviewError:
                self.fail("protocol_refused")
            existing = self._result["facts"][name]
            merged = dict(existing)
            for key, item in incoming.items():
                if key in existing and existing[key] is not None and existing[key] != item:
                    monotone = (type(item) is bool and existing[key] is False and item is True)
                    monotone |= name == "engine" and key == "turns" and item >= existing[key]
                    cleanup = {**self._result["facts"]["cleanup"], **(incoming if name == "cleanup" else {})}
                    removal = key in {"retained", "resources_retained"} and item is False and all(
                        cleanup.get(k) is True
                        for k in ("container_removed", "volume_removed", "local_processes_closed", "local_exchanges_closed"))
                    if not monotone and not removal:
                        self.fail("protocol_refused")
                merged[key] = item
            candidate = {**self._result, "facts": {**self._result["facts"], name: merged}}
            try:
                validate_result(candidate, max_bytes=self.limits["receipt_result_bytes"])
            except ReviewError:
                self.fail("protocol_refused")
            self._result["facts"][name] = merged
            self._save(observation=True)

    def add_secret(self, value):
        if type(value) is not str or not value or len(value.encode("utf-8")) > 131_072:
            raise ReviewError("credential_unavailable")
        encoded = value.encode("utf-8")
        if encoded not in self._secrets:
            self._secrets.append(encoded)

    def assert_safe(self, value):
        if type(value) is not bytes:
            self.fail("protocol_refused")
        if any(secret in value for secret in self._secrets):
            self.fail("secret_in_data")

    def finish(self):
        with self._lock:
            if any(record["entered"] and not record["closed"] for record in self._result["effects"]):
                self._latch("cleanup_unconfirmed", True)
            if self._result["first_failure"] is None:
                self._result["status"] = "returned"
            self._finalized = True
            self._save(observation=True)
            return self.snapshot()


class StandaloneReviewAdapter:
    """Run one admitted review callback, retaining its original resource owner.

    Factories are trusted application/test wiring and are never profile data.
    Constructing the adapter performs no I/O or client/resource acquisition.
    """

    def __init__(self, *, native_factory=None, model_factory=None, clock=time.monotonic):
        self._native_factory = native_factory
        self._model_factory = model_factory
        self._clock = clock

    @staticmethod
    def _error(operation, error):
        try:
            if isinstance(error, ReviewError):
                operation.fail(error.code, unknown=error.unknown)
            operation.fail("unexpected_failure", unknown=True)
        except ReviewError:
            pass

    @staticmethod
    def _source(operation, source):
        from .review_contract import PreparedReviewSource
        if not isinstance(source, PreparedReviewSource):
            operation.fail("source_refused")
        fact = operation.fact("source")
        if (source.base_sha != operation.claim.original["review"]["head_sha"]
                or any(fact.get(key) != getattr(source, key) for key in ("base_sha", "tree_sha", "snapshot_sha256", "source_bytes"))
                or type(source.source_bytes) is not int or source.source_bytes > operation.limits["source_bytes"]
                or type(source.context) is not str or len(source.context.encode("utf-8")) > operation.limits["context_bytes"]):
            operation.fail("source_refused")
        operation.assert_safe(source.context.encode("utf-8"))

    @staticmethod
    def _capture(operation, capture):
        from .review_contract import ReviewCapture
        if not isinstance(capture, ReviewCapture) or type(capture.patch) is not bytes or type(capture.log) is not bytes:
            operation.fail("capture_refused", unknown=True)
        guest, fact = operation.fact("guest"), operation.fact("capture")
        if (guest.get("stopped") is not True or guest.get("local_closed") is not True
                or fact.get("durable") is not True or fact.get("termination_confirmed") is not True
                or fact.get("container_id") != guest.get("container_id")
                or not guest.get("container_id")
                or any(fact.get(key) != getattr(capture, key) for key in (
                    "retained_id", "archive_sha256", "archive_bytes", "patch_sha256", "log_sha256", "manifest_sha256"))
                or fact.get("patch_bytes") != len(capture.patch) or fact.get("log_bytes") != len(capture.log)
                or capture.patch_sha256 != hashlib.sha256(capture.patch).hexdigest()
                or capture.log_sha256 != hashlib.sha256(capture.log).hexdigest()
                or capture.archive_bytes > operation.limits["archive_bytes"]
                or len(capture.patch) > operation.limits["patch_bytes"] or len(capture.log) > operation.limits["log_bytes"]):
            operation.fail("capture_refused", unknown=True)
        operation.assert_safe(capture.patch)
        operation.assert_safe(capture.log)

    def __call__(self, original, claim: ReviewClaim):
        from src.agent.standalone_review_engine import StandaloneReviewEngine, checked_exec
        from .review_contract import OriginalReviewGuest, ReviewCandidate, ReviewPublication
        from .standalone_review_model import StandaloneReviewModel
        if (not isinstance(claim, ReviewClaim) or original is not claim.original
                or original.get("operation_id") != claim.operation_id):
            raise ReviewError("protocol_refused")
        operation = ReviewOperation(claim, clock=self._clock)
        native = model = None
        try:
            operation.check()
            if self._native_factory is None:
                from .review_native import ReviewNativeBackend
                factory = ReviewNativeBackend
            else:
                factory = self._native_factory
            native = factory(claim)
            operation.check()
            native.check_original(operation, phase="initial")
            operation.check()
            source = native.prepare_source(operation)
            self._source(operation, source)
            operation.check()
            guest = native.create_guest(operation, source)
            fact = operation.fact("guest")
            if (not isinstance(guest, OriginalReviewGuest) or guest.incarnation != fact.get("incarnation")
                    or not fact.get("container_id")
                    or any(fact.get(key) is not True for key in (
                        "create_entered", "create_acknowledged", "start_entered", "start_acknowledged"))
                    or fact.get("stopped") is True):
                operation.fail("guest_outcome_unknown", unknown=True)
            model = self._model_factory() if self._model_factory is not None else StandaloneReviewModel()
            StandaloneReviewEngine(model).run(operation, native, source, guest)
            model.retire(operation)
            operation.check()
            command = claim.profile.document["guest"]["test_command"]
            if type(command) is not str or not command.strip() or len(command.encode("utf-8")) > operation.limits["exec_input_bytes"]:
                operation.fail("protocol_refused")
            operation.assert_safe(command.encode("utf-8"))
            verification = checked_exec(operation, native.execute(operation, guest, command))
            operation.note("verification", {"command_sha256": hashlib.sha256(command.encode("utf-8")).hexdigest(),
                                            "exchange_id": verification.exchange_id, "exit_code": verification.exit_code,
                                            "local_closed": verification.local_closed, "observed": True})
            if verification.exit_code != 0:
                operation.fail("verification_failed")
            operation.check()
            capture = native.stop_and_capture(operation, guest)
            self._capture(operation, capture)
            operation.check()
            candidate = native.compose(operation, source, capture)
            fact = operation.fact("candidate")
            if (not isinstance(candidate, ReviewCandidate) or candidate.parent_sha != source.base_sha
                    or any(fact.get(key) != getattr(candidate, key) for key in ("parent_sha", "tree_sha", "commit_sha"))):
                operation.fail("candidate_refused")
            if candidate.commit_sha is None:
                if fact.get("no_change") is not True or candidate.tree_sha != source.tree_sha:
                    operation.fail("candidate_refused")
            else:
                if fact.get("no_change") is not False:
                    operation.fail("candidate_refused")
                operation.check()
                native.check_original(operation, phase="publication")
                operation.check()
                publication = native.publish(operation, candidate)
                fact = operation.fact("publication")
                if (not isinstance(publication, ReviewPublication) or publication.status != fact.get("status")
                        or publication.local_closed is not fact.get("local_closed")):
                    operation.fail("publication_outcome_unknown", unknown=True)
                if publication.status == "outcome_unknown" or not publication.local_closed:
                    operation.fail("publication_outcome_unknown", unknown=True)
                if publication.status == "refused":
                    operation.fail("publication_refused")
                if publication.status not in {"acknowledged", "observed_no_update"}:
                    operation.fail("protocol_refused")
                operation.check()
        except BaseException as error:
            self._error(operation, error)
        finally:
            if model is not None:
                try:
                    model.retire(operation)
                except BaseException as error:
                    self._error(operation, error)
            if native is not None:
                try:
                    native.retire(operation)
                except BaseException as error:
                    self._error(operation, error)
        return operation.finish()
