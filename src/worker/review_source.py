"""Pure managed-publication refusal shared by legacy review entry points."""

import re


class ReviewSourceRejected(ValueError):
    """A legacy feedback operation cannot act on this supplied source."""

    def __init__(self, reason: str):
        self.reason = reason
        super().__init__(reason)


def require_legacy_review_source(branch_name, *source_texts):
    """Refuse current managed-publication signals; absence grants no authority.

    PublicationService appends a 64-hex operation to every slash-terminated
    PublicationPolicy prefix. This also covers custom managed branch prefixes.
    Public markers can only cause refusal, never authorize legacy execution.
    """
    if (
        not isinstance(branch_name, str)
        or not branch_name
        or any(
            value is not None and not isinstance(value, str) for value in source_texts
        )
    ):
        raise ReviewSourceRejected("invalid_legacy_review_source")
    if (
        "/" in branch_name
        and re.fullmatch(r"[0-9a-f]{64}", branch_name.rsplit("/", 1)[1])
    ) or any(
        value is not None and "<!-- openjules-publication:" in value
        for value in source_texts
    ):
        raise ReviewSourceRejected("managed_publication_requires_canonical_review")
