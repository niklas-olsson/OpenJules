"""Data-only interfaces for the explicitly admitted standalone review path.

These local Python objects do not grant managed task authority. Credentials,
source handles and guest observations never become public receipt fields by
dataclass serialization. The review result has its own closed validator.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Callable, Mapping, Protocol


PROFILE_SCHEMA = "standalone-review-source-cas-v1"
RESULT_SCHEMA = "standalone-review-result-v1"
REVIEW_CODES = frozenset({
    "authority_changed", "custody_unavailable", "deadline_exhausted",
    "capacity_exhausted", "source_unavailable", "source_refused",
    "credential_unavailable", "model_refused", "model_outcome_unknown",
    "guest_refused", "guest_outcome_unknown", "capture_refused",
    "capture_outcome_unknown", "candidate_refused", "publication_refused",
    "publication_outcome_unknown", "verification_failed", "protocol_refused",
    "record_unavailable", "cleanup_unconfirmed", "secret_in_data",
    "unexpected_failure",
})


class ReviewError(RuntimeError):
    """A fixed diagnostic. Never construct it from external exception text."""

    def __init__(self, code: str, *, unknown: bool = False):
        if type(code) is not str or code not in REVIEW_CODES or type(unknown) is not bool:
            code, unknown = "unexpected_failure", True
        self.code, self.unknown = code, unknown
        super().__init__(code)


@dataclass(frozen=True)
class ReviewProfile:
    """Validated, recursively immutable profile and its canonical digest."""

    document: Mapping[str, Any] = field(repr=False)
    digest: str

    @property
    def limits(self) -> Mapping[str, int]:
        return self.document["limits"]


class ReviewCredentials(Protocol):
    """Private startup snapshot; token minting is a later counted effect."""

    def validate_epoch(self) -> None: ...

    @property
    def model_key(self) -> str | None: ...

    @property
    def forge(self) -> Mapping[str, Any]: ...

    @property
    def literal_secrets(self) -> tuple[str, ...]: ...


@dataclass(frozen=True)
class ReviewClaim:
    """Original fenced callback capability, constructed only by its owner."""

    operation_id: str
    owner_epoch: str
    started_at: float
    original: Mapping[str, Any] = field(repr=False)
    profile: ReviewProfile = field(repr=False)
    activation_digest: str
    credentials: ReviewCredentials = field(repr=False)
    validate_productive: Callable[[], None] = field(repr=False)
    validate_retirement: Callable[[], None] = field(repr=False)
    persist_result: Callable[[Mapping[str, Any]], None] = field(repr=False)


@dataclass(frozen=True)
class PreparedReviewSource:
    handle: Any = field(repr=False)
    base_sha: str
    tree_sha: str
    snapshot_sha256: str
    source_bytes: int
    context: str = field(repr=False)


@dataclass(frozen=True)
class OriginalReviewGuest:
    handle: Any = field(repr=False)
    incarnation: str


@dataclass(frozen=True)
class ReviewExecObservation:
    exchange_id: str
    exit_code: int | None
    output: bytes = field(repr=False)
    local_closed: bool


@dataclass(frozen=True)
class ReviewCapture:
    handle: Any = field(repr=False)
    retained_id: str
    archive_sha256: str
    archive_bytes: int
    patch_sha256: str
    patch: bytes = field(repr=False)
    log_sha256: str
    log: bytes = field(repr=False)
    manifest_sha256: str


@dataclass(frozen=True)
class ReviewCandidate:
    handle: Any = field(repr=False)
    parent_sha: str
    tree_sha: str
    commit_sha: str | None


@dataclass(frozen=True)
class ReviewPublication:
    status: str  # acknowledged, refused, observed_no_update, outcome_unknown
    local_closed: bool


class ReviewNativePorts(Protocol):
    """One private original-resource owner. No independent clock or retry."""

    def check_original(self, operation, *, phase: str) -> None: ...

    def prepare_source(self, operation) -> PreparedReviewSource: ...

    def create_guest(self, operation, source: PreparedReviewSource) -> OriginalReviewGuest: ...

    def execute(self, operation, guest: OriginalReviewGuest, command: str) -> ReviewExecObservation: ...

    def stop_and_capture(self, operation, guest: OriginalReviewGuest) -> ReviewCapture: ...

    def compose(self, operation, source: PreparedReviewSource, capture: ReviewCapture) -> ReviewCandidate: ...

    def publish(self, operation, candidate: ReviewCandidate) -> ReviewPublication: ...

    def retire(self, operation) -> None: ...
