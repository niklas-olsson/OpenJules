"""Canonical authority errors without importing a transport or legacy facade."""

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
