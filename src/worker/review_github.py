"""The fixed four GitHub reads and optional one App mint for a review.

Payload URLs are never destinations. The caller supplies the counted bounded
transport; this class owns only original identity checks and selected secrets.
"""
from __future__ import annotations

from datetime import datetime, timezone
from dataclasses import dataclass
import hashlib
import json
import re
import time

from .review_contract import ReviewError
from .review_source import ReviewSourceRejected, require_legacy_review_source


@dataclass(frozen=True)
class OriginalHTTPReply:
    """Returned bytes and their original effect, not a semantic acknowledgement."""
    status: int
    body: bytes
    effect: object
    cleanup: bool = False
    custody: object = None

    def __iter__(self):
        return iter((self.status, self.body))

    def acknowledge(self, operation):
        operation.check(cleanup=self.cleanup)
        if operation.now() >= self.effect.deadline:
            operation.observe(self.effect, "outcome_unknown", code="deadline_exhausted")
            operation.fail("deadline_exhausted", unknown=True)
        operation.observe(self.effect, "acknowledged")
        if self.custody is not None:
            self.custody["validated"] = True
        # Persistence/validators may themselves consume the original call's
        # remaining interval. An actual ACK never renews productive authority.
        operation.check(cleanup=self.cleanup)
        if operation.now() >= self.effect.deadline:
            operation.observe(self.effect, "outcome_unknown", code="deadline_exhausted")
            operation.fail("deadline_exhausted", unknown=True)


def decode_object(raw):
    def pairs(values):
        result = {}
        for key, value in values:
            if key in result:
                raise ReviewError("protocol_refused")
            result[key] = value
        return result
    def invalid(_):
        raise ReviewError("protocol_refused")
    try:
        value = json.loads(raw.decode("utf-8", errors="strict"), object_pairs_hook=pairs,
                           parse_constant=invalid, parse_float=invalid)
        if type(value) is not dict:
            raise ReviewError("protocol_refused")
        pending, visited = [(value, 0)], 0
        while pending:
            item, depth = pending.pop()
            visited += 1
            if depth > 32 or visited > 100000:
                raise ReviewError("protocol_refused")
            children = item.values() if type(item) is dict else item if type(item) is list else ()
            pending.extend((child, depth + 1) for child in children)
        return value
    except (ValueError, UnicodeError, RecursionError):
        raise ReviewError("protocol_refused") from None


class ReviewGitHub:
    def __init__(self, claim, request):
        self.claim, self.request = claim, request
        self.token = None
        self.expires = None
        self.mint_attempted = False
        self.phases = set()

    def credential(self, operation):
        self.claim.credentials.validate_epoch()
        selected = self.claim.credentials.forge
        if self.token is not None:
            if self.expires is not None and time.time() >= self.expires:
                raise ReviewError("credential_unavailable")
            return selected["username"], self.token
        if selected["kind"] == "pat":
            token = selected["token"]
        elif selected["kind"] == "app":
            if self.mint_attempted:
                raise ReviewError("credential_unavailable", unknown=True)
            self.mint_attempted = True
            operation.check()
            from .auth import generate_jwt
            bearer = generate_jwt(selected["app_id"], selected["private_key"])
            operation.add_secret(bearer)
            installation = self.claim.original["binding"]["installation_id"]
            if type(installation) is not int or installation != selected["installation_id"]:
                raise ReviewError("credential_unavailable")
            payload = {"repository_ids": [self.claim.original["binding"]["repository_id"]],
                       "permissions": {"contents": "write", "pull_requests": "read"}}
            reply = self.request(operation, "forge_token", "POST",
                                       f"/app/installations/{installation}/access_tokens", payload,
                                       self.headers(bearer))
            status, raw = reply
            if status != 201:
                raise ReviewError("credential_unavailable")
            value = decode_object(raw)
            token = value.get("token")
            self._retain_token(operation, token)
            permissions = value.get("permissions")
            repositories = value.get("repositories")
            if (type(permissions) is not dict or permissions.get("contents") != "write"
                    or permissions.get("pull_requests") != "read"
                    or set(permissions) - {"contents", "pull_requests", "metadata"}
                    or permissions.get("metadata", "read") != "read"
                    or value.get("repository_selection") != "selected"
                    or type(repositories) is not list or len(repositories) != 1
                    or type(repositories[0]) is not dict
                    or type(repositories[0].get("id")) is not int
                    or repositories[0]["id"] != self.claim.original["binding"]["repository_id"]):
                raise ReviewError("credential_unavailable")
            try:
                expiry = value["expires_at"]
                if type(expiry) is not str or not re.fullmatch(r"\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}Z", expiry):
                    raise ValueError
                self.expires = datetime.strptime(expiry, "%Y-%m-%dT%H:%M:%SZ").replace(tzinfo=timezone.utc).timestamp()
            except (KeyError, ValueError):
                raise ReviewError("credential_unavailable") from None
            if time.time() >= self.expires:
                raise ReviewError("credential_unavailable")
            reply.acknowledge(operation)
        else:
            raise ReviewError("credential_unavailable")
        self._retain_token(operation, token)
        self.token = token
        if self.expires is not None and time.time() >= self.expires:
            raise ReviewError("credential_unavailable")
        return selected["username"], token

    @staticmethod
    def _retain_token(operation, token):
        if (type(token) is not str or not 1 <= len(token.encode()) <= 65536
                or any(ord(char) < 33 or ord(char) > 126 for char in token)):
            raise ReviewError("credential_unavailable")
        operation.add_secret(token)

    @staticmethod
    def headers(token):
        return {"Authorization": "Bearer " + token, "Accept": "application/vnd.github+json",
                "X-GitHub-Api-Version": "2022-11-28"}

    def check(self, operation, phase):
        if phase not in {"initial", "publication"} or phase in self.phases:
            raise ReviewError("protocol_refused")
        if phase == "publication" and "initial" not in self.phases:
            raise ReviewError("protocol_refused")
        self.phases.add(phase)
        original = self.claim.original
        binding, review = original["binding"], original["review"]
        try:
            require_legacy_review_source(review["branch"], review["pull_body"], review["review_body"])
        except ReviewSourceRejected:
            raise ReviewError("source_refused") from None
        _, token = self.credential(operation)
        prefix = "/repos/" + binding["repository"] + "/pulls/" + str(review["pull_number"])
        reply = self.request(operation, "forge_get", "GET", prefix, None, self.headers(token))
        status, raw = reply
        if status != 200:
            raise ReviewError("source_refused")
        pull = decode_object(raw)
        self.validate_pull(pull)
        reply.acknowledge(operation)
        # A fresh permission/credential check precedes the second original GET.
        _, token = self.credential(operation)
        reply = self.request(operation, "forge_get", "GET", prefix + "/reviews/" + str(review["review_id"]),
                                   None, self.headers(token))
        status, raw = reply
        if status != 200:
            raise ReviewError("source_refused")
        response = decode_object(raw)
        self.validate_review(response)
        reply.acknowledge(operation)

    def validate_pull(self, pull):
        binding, original = self.claim.original["binding"], self.claim.original["review"]
        try:
            if (type(pull.get("number")) is not int or pull["number"] != original["pull_number"]
                    or pull.get("state") != "open" or pull.get("merged") is not False):
                raise ReviewError("source_refused")
            for role in ("base", "head"):
                repository = pull[role]["repo"]
                if (type(repository["id"]) is not int or repository["id"] != binding["repository_id"]
                        or repository["full_name"] != binding["repository"]):
                    raise ReviewError("source_refused")
            if pull["head"]["ref"] != original["branch"] or pull["head"]["sha"] != original["head_sha"]:
                raise ReviewError("source_refused")
            body = pull.get("body")
            if body is not None and (type(body) is not str or len(body.encode()) > 262144):
                raise ReviewError("source_refused")
            require_legacy_review_source(original["branch"], body, original["review_body"])
        except (KeyError, TypeError, ReviewSourceRejected):
            raise ReviewError("source_refused") from None

    def validate_review(self, value):
        original = self.claim.original["review"]
        try:
            body = value["body"]
            if (type(value.get("id")) is not int or value["id"] != original["review_id"]
                    or type(value["user"]["id"]) is not int or value["user"]["id"] != original["author_id"]
                    or value.get("state") != "CHANGES_REQUESTED" or value.get("commit_id") != original["head_sha"]
                    or type(body) is not str or len(body.encode()) > 262144
                    or body != original["review_body"]
                    or hashlib.sha256(body.encode()).hexdigest() != original["body_sha256"]):
                raise ReviewError("source_refused")
            require_legacy_review_source(original["branch"], original["pull_body"], body)
        except (KeyError, TypeError, ReviewSourceRejected):
            raise ReviewError("source_refused") from None
