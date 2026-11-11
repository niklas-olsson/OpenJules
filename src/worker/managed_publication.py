"""Operator command for final canonical composition and ordinary draft PRs.

The private journal records immutable inputs and delivery/effect facts. It owns
no task, execution budget, acceptance decision or repository merge authority.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import contextmanager
from dataclasses import asdict
import fcntl
import json
import math
import os
from pathlib import Path
import re
import stat
import time

import httpx

from src.forge.managed_github import (
    ForgeError,
    ManagedGitHubPublisher,
    PublicationPolicy,
)
from src.git_manager.managed_composition import (
    CHILD,
    DIGEST,
    SHA,
    CompositionError,
    CompositionLimits,
    canonical,
    compose,
    content_hash,
    digest,
    validate_inputs,
)
from src.polyphony.managed_client import ManagedAuthorityClient, token_from_reference
from src.worker.execution_context import validate_managed_installation


class PublicationError(RuntimeError):
    def __init__(self, code):
        self.code = code
        super().__init__(code)


def _require(value, code="canonical_mismatch"):
    if not value:
        raise PublicationError(code)


class CanonicalPublicationReader:
    """Read-only authenticated API consumer. No authority mutation is exposed."""

    def __init__(self, authority, policy, base, limits, *, transport=None):
        self.authority = authority
        self.policy, self.base, self.limits = policy, base, limits
        self.transport = transport

    @property
    def scope(self):
        return {
            "deployment_id": self.policy.deployment_id,
            "repository": self.policy.repository,
        }

    async def _request(self, resource, query, deadline, maximum, text):
        try:
            token = token_from_reference(self.authority.token_ref)
            seconds = min(self.authority.timeout_seconds, deadline - time.monotonic())
            if seconds <= 0:
                raise PublicationError("publication_deadline")
            async with asyncio.timeout(seconds):
                async with httpx.AsyncClient(
                    transport=self.transport,
                    trust_env=False,
                    follow_redirects=False,
                    timeout=seconds,
                ) as client:
                    async with client.stream(
                        "GET",
                        self.authority.endpoint + "/managed/" + resource,
                        params=self.scope | query,
                        headers={
                            "Authorization": "Bearer " + token,
                            "Accept-Encoding": "identity",
                        },
                    ) as response:
                        if response.status_code != 200:
                            raise PublicationError("canonical_unavailable")
                        if response.headers.get("Content-Encoding", "identity") not in {
                            "",
                            "identity",
                        }:
                            raise PublicationError("canonical_unavailable")
                        raw = bytearray()
                        async for chunk in response.aiter_raw():
                            if len(raw) + len(chunk) > maximum:
                                raise PublicationError("canonical_byte_limit")
                            raw.extend(chunk)
            return raw.decode("utf-8") if text else json.loads(raw)
        except PublicationError:
            raise
        except (OSError, ValueError, httpx.HTTPError, TimeoutError):
            raise PublicationError("canonical_unavailable") from None

    def _get(self, resource, *, query=None, deadline, text=False):
        return asyncio.run(
            self._request(
                resource,
                query or {},
                deadline,
                (
                    self.limits.artifact_bytes
                    if text
                    else self.authority.max_response_bytes
                ),
                text,
            )
        )

    def _scope(self, value):
        _require(
            isinstance(value, dict)
            and type(value.get("schema_version")) is int
            and value["schema_version"] == 1
            and all(value.get(key) == expected for key, expected in self.scope.items())
        )

    def read(self, candidate_id, child_order, *, deadline, cached=None):
        _require(
            isinstance(candidate_id, str) and DIGEST.fullmatch(candidate_id),
            "invalid_candidate",
        )
        snapshot = self._get("snapshot", deadline=deadline)
        self._scope(snapshot)

        def one(kind, identity):
            _require(isinstance(snapshot.get(kind), list))
            found = [
                row
                for row in snapshot[kind]
                if isinstance(row, dict) and row.get("id") == identity
            ]
            _require(len(found) == 1, "stale_candidate")
            return found[0]

        candidate = one("candidate", candidate_id)
        task, root = one("task", candidate.get("task")), one(
            "attempt", candidate.get("attempt")
        )
        binding = root.get("runtime_binding", {})
        _require(
            task.get("managed_scope") == self.scope and root.get("task") == task["id"]
        )
        _require(
            task.get("current_candidate") == candidate_id
            and task.get("status") in {"awaiting_review", "accepted"}
            and task.get("revision")
            == candidate.get("revision")
            == root.get("requirements_revision")
            and type(task.get("revision")) is int
            and task["revision"] >= 1
            and task.get("requirements")
            == candidate.get("requirements")
            == root.get("approved_requirements"),
            "stale_candidate",
        )
        _require(
            isinstance(task.get("requirements"), str)
            and not task.get("dependency_problem"),
            "stale_candidate",
        )
        _require(
            root.get("execution_mode") == "external"
            and root.get("termination_confirmed") is True
            and root.get("launch_fenced") is True
            and root.get("state") in {"exited", "timed_out"}
        )
        _require(
            isinstance(binding, dict)
            and all(binding.get(k) == v for k, v in self.scope.items())
            and binding.get("attempt_id") == root["id"]
            and binding.get("base") == self.base == candidate.get("base")
            and binding.get("requirements_revision") == task["revision"]
        )
        for name in ("runtime_principal", "worker_id", "profile"):
            _require(
                isinstance(binding.get(name), str)
                and 0 < len(binding[name]) <= 512
                and "\0" not in binding[name]
            )
        _require(
            isinstance(binding.get("profile_digest"), str)
            and DIGEST.fullmatch(binding["profile_digest"])
        )
        _require(
            candidate.get("author") == root.get("worker")
            and candidate.get("author_principal") == binding["runtime_principal"]
        )
        _require(
            isinstance(root.get("captured_artifacts"), dict)
            and root["captured_artifacts"].get("patch") == candidate.get("patch")
        )
        original_lineage = candidate.get("child_lineage")
        _require(
            isinstance(original_lineage, list)
            and 1 <= len(original_lineage) <= self.limits.max_children
            and root.get("child_lineage") == original_lineage,
            "invalid_lineage",
        )
        identity = {
            key: candidate.get(key)
            for key in (
                "base",
                "patch",
                "requirements",
                "revision",
                "task",
                "dependency_admissions",
                "child_lineage",
            )
        }
        _require(digest(identity) == candidate_id, "canonical_candidate_hash_mismatch")
        expected = {}
        for item in original_lineage:
            _require(
                isinstance(item, dict)
                and set(item) == {"child_id", "grant_digest", "artifacts"},
                "invalid_lineage",
            )
            child_id = item["child_id"]
            _require(
                isinstance(child_id, str)
                and CHILD.fullmatch(child_id)
                and child_id not in expected,
                "invalid_lineage",
            )
            expected[child_id] = item
        if child_order is None:
            child_order = sorted(expected)
        _require(
            isinstance(child_order, list)
            and all(isinstance(item, str) for item in child_order)
            and len(child_order) == len(expected)
            and set(child_order) == set(expected),
            "invalid_lineage",
        )
        response = self._get(
            "children", query={"attempt_id": root["id"]}, deadline=deadline
        )
        self._scope(response)
        _require(
            response.get("root_attempt_id") == root["id"]
            and isinstance(response.get("children"), list)
            and len(response["children"]) == len(expected),
            "invalid_lineage",
        )
        seen = set()
        for result in response["children"]:
            self._scope(result)
            grant, child = result.get("binding", {}), result.get("child", {})
            _require(isinstance(grant, dict) and isinstance(child, dict))
            child_id = grant.get("child_id")
            _require(
                isinstance(child_id, str)
                and child_id in expected
                and child_id not in seen,
                "invalid_lineage",
            )
            seen.add(child_id)
            _require(
                result.get("root_attempt_id") == root["id"]
                and child.get("id") == child_id
                and child.get("binding") == grant
            )
            immutable = {
                **self.scope,
                "root_attempt_id": root["id"],
                "parent_attempt_id": root["id"],
                "task_id": task["id"],
                "requirements_revision": task["revision"],
                "base": self.base,
                **{
                    name: binding[name]
                    for name in (
                        "runtime_principal",
                        "worker_id",
                        "profile",
                        "profile_digest",
                    )
                },
            }
            _require(all(grant.get(name) == value for name, value in immutable.items()))
            _require(
                grant.get("grant_digest")
                == expected[child_id]["grant_digest"]
                == digest(
                    {
                        key: value
                        for key, value in grant.items()
                        if key != "grant_digest"
                    }
                )
            )
            _require(
                isinstance(child.get("instructions"), str)
                and grant.get("instructions_digest")
                == content_hash(child["instructions"])
            )
            _require(
                child.get("termination_confirmed") is True
                and child.get("launch_fenced") is True
                and child.get("captured_artifacts") == expected[child_id]["artifacts"],
                "unresolved_child",
            )
        started = root.get("started")
        _require(
            type(started) in {int, float}
            and math.isfinite(started)
            and 0 < started <= 4_000_000_000
        )
        manifest = {
            "schema_version": 1,
            **self.scope,
            "task_id": task["id"],
            "attempt_id": root["id"],
            "candidate_id": candidate_id,
            "base": self.base,
            "revision": task["revision"],
            "requirements_digest": content_hash(task["requirements"]),
            "dependency_admissions": candidate["dependency_admissions"],
            "timestamp": int(started),
            **{
                key: binding[key]
                for key in (
                    "runtime_principal",
                    "worker_id",
                    "profile",
                    "profile_digest",
                )
            },
            "root_artifacts": root["captured_artifacts"],
            "lineage": [expected[item] for item in child_order],
        }
        if cached is not None:
            _require(cached["manifest"] == manifest, "stale_candidate")
            validate_inputs(cached, self.limits)
            return cached
        total = 0

        def artifacts(hashes, child_id=None):
            nonlocal total
            _require(
                isinstance(hashes, dict) and set(hashes) == {"patch", "log", "manifest"}
            )
            content = {}
            for kind, sha in hashes.items():
                _require(isinstance(sha, str) and DIGEST.fullmatch(sha))
                resource = (
                    "children/" + child_id + "/artifacts/" if child_id else "artifacts/"
                ) + sha
                value = self._get(
                    resource,
                    query={"attempt_id": root["id"]} if child_id else {},
                    deadline=deadline,
                    text=True,
                )
                _require(content_hash(value) == sha, "artifact_hash_mismatch")
                total += len(value.encode())
                _require(total <= self.limits.total_artifact_bytes, "artifact_limit")
                content[kind] = value
            return content

        result = {
            "manifest": manifest,
            "root": artifacts(root["captured_artifacts"]),
            "children": [
                {
                    "child_id": child_id,
                    "artifacts": artifacts(expected[child_id]["artifacts"], child_id),
                }
                for child_id in child_order
            ],
        }
        validate_inputs(result, self.limits)
        return result


def _private_directory(path):
    path.mkdir(mode=0o700, parents=True, exist_ok=True)
    if (
        path.is_symlink()
        or not path.is_dir()
        or stat.S_IMODE(path.stat().st_mode) & 0o077
    ):
        raise PublicationError("state_directory_not_private")


def _write(path, value):
    raw = canonical(value).encode()
    if len(raw) > 70_000_000:
        raise PublicationError("journal_byte_limit")
    temporary = path.with_suffix(".pending")
    fd = os.open(
        temporary, os.O_WRONLY | os.O_CREAT | os.O_TRUNC | os.O_NOFOLLOW, 0o600
    )
    with os.fdopen(fd, "wb") as handle:
        handle.write(raw)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)
    directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(directory)
    finally:
        os.close(directory)


class PublicationJournal:
    def __init__(self, root):
        self.root = Path(root).absolute()
        _private_directory(self.root)

    @contextmanager
    def locked(self):
        fd = os.open(
            self.root / "operation.lock", os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                raise PublicationError("publication_busy") from None
            try:
                yield
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    def location(self, operation):
        _require(
            isinstance(operation, str) and DIGEST.fullmatch(operation),
            "invalid_operation",
        )
        directory = self.root / operation
        _private_directory(directory)
        return directory

    def read(self, operation):
        path = self.location(operation) / "state.json"
        if not path.exists():
            return None
        if (
            path.is_symlink()
            or stat.S_IMODE(path.stat().st_mode) & 0o077
            or path.stat().st_size > 70_000_000
        ):
            raise PublicationError("invalid_journal")
        try:
            result = json.loads(path.read_bytes())
        except (OSError, ValueError):
            raise PublicationError("invalid_journal") from None
        _require(
            isinstance(result, dict) and result.get("operation") == operation,
            "invalid_journal",
        )
        return result

    def save(self, value):
        _write(self.location(value["operation"]) / "state.json", value)


class PublicationService:
    def __init__(
        self,
        reader,
        publisher,
        source_path,
        state_directory,
        *,
        limits=None,
        operation_seconds=300,
    ):
        if (
            type(operation_seconds) not in {int, float}
            or not math.isfinite(operation_seconds)
            or not 1 <= operation_seconds <= 600
        ):
            raise ValueError("invalid publication operation bound")
        self.reader, self.publisher = reader, publisher
        self.policy = publisher.policy
        self.source_path = str(Path(source_path).resolve(strict=True))
        self.journal = PublicationJournal(state_directory)
        self.limits = limits or CompositionLimits()
        self.operation_seconds = operation_seconds

    def _current(self, state, deadline):
        self.reader.read(
            state["candidate_id"],
            state["child_order"],
            deadline=deadline,
            cached=state["inputs"],
        )

    @staticmethod
    def _summary(state, status, reason=None):
        result = {
            "schema_version": 1,
            "operation": state["operation"],
            "status": status,
            "candidate_id": state["candidate_id"],
            "ready_for_review": False,
            "release_authorized": False,
        }
        if state.get("composition"):
            result.update(
                {
                    key: state["composition"][key]
                    for key in ("manifest_sha256", "tree_sha", "commit_sha")
                }
            )
        if state.get("proposal"):
            result["proposal"] = state["proposal"]
        if reason:
            result["reason"] = reason
        return result

    def _observed(self, state, proposal, deadline):
        state["proposal"] = proposal
        state["phase"] = "pr_observed"
        self.journal.save(state)
        if proposal["state"] == "closed":
            return self._summary(state, "existing_closed")
        try:
            self._current(state, deadline)
            self.publisher.validate_repository(
                state["inputs"]["manifest"]["base"],
                state["composition"]["base_tree_sha"],
                deadline=deadline,
            )
            if proposal["base_sha"] != state["inputs"]["manifest"]["base"]:
                raise ForgeError("stale_base")
            if (
                self.publisher.read_branch(state["branch"], deadline=deadline)
                != state["composition"]["commit_sha"]
            ):
                raise ForgeError("feature_branch_changed")
        except (PublicationError, ForgeError, CompositionError) as exc:
            # This detects change after an effect. It cannot make a remote GitHub
            # creation atomic with a separate canonical authority transaction.
            status = (
                "draft_stale"
                if exc.code
                in {"stale_candidate", "stale_base", "feature_branch_changed"}
                else "draft_pending_reconciliation"
            )
            return self._summary(state, status, exc.code)
        return self._summary(
            state, "draft_published" if proposal["draft"] else "existing_ready"
        )

    def run(self, candidate_id, child_order=None):
        _require(
            isinstance(candidate_id, str) and DIGEST.fullmatch(candidate_id),
            "invalid_candidate",
        )
        operation = digest(
            [self.policy.deployment_id, self.policy.repository, candidate_id]
        )
        deadline = time.monotonic() + self.operation_seconds
        with self.journal.locked():
            state = self.journal.read(operation)
            if state is None:
                inputs = self.reader.read(candidate_id, child_order, deadline=deadline)
                manifest = validate_inputs(inputs, self.limits)
                order = [item["child_id"] for item in manifest["lineage"]]
                state = {
                    "schema_version": 1,
                    "operation": operation,
                    "candidate_id": candidate_id,
                    "child_order": order,
                    "inputs": inputs,
                    "policy_fingerprint": self.policy.fingerprint,
                    "limits": asdict(self.limits),
                    "phase": "captured",
                    "branch": self.policy.branch_prefix + operation,
                    "identity": {
                        "name": self.policy.author_name,
                        "email": self.policy.author_email,
                        "timestamp": manifest["timestamp"],
                    },
                }
                self.journal.save(state)
            _require(
                state.get("policy_fingerprint") == self.policy.fingerprint
                and state.get("limits") == asdict(self.limits)
                and state.get("candidate_id") == candidate_id
                and state.get("branch") == self.policy.branch_prefix + operation
                and (child_order is None or child_order == state.get("child_order")),
                "operation_input_changed",
            )
            validate_inputs(state["inputs"], self.limits)
            manifest = state["inputs"]["manifest"]
            marker = (
                "<!-- openjules-publication:"
                + operation
                + ":"
                + digest(manifest)
                + " -->"
            )
            new_pr_intent = False
            try:
                if state.get("pr_intent") or state.get("proposal"):
                    # Read-only reconciliation is still allowed after revocation.
                    # The original operation cannot silently create a second PR.
                    proposal = self.publisher.find_proposal(
                        state["branch"],
                        state["composition"]["commit_sha"],
                        marker,
                        deadline=deadline,
                    )
                    if proposal is None:
                        return self._summary(
                            state, "uncertain", "pr_creation_requires_reconciliation"
                        )
                    return self._observed(state, proposal, deadline)
                self._current(state, deadline)
                composed = compose(
                    state["inputs"],
                    self.source_path,
                    self.journal.location(operation) / "git",
                    state["identity"],
                    limits=self.limits,
                    deadline=deadline,
                )
                metadata = {
                    key: composed[key]
                    for key in (
                        "manifest_sha256",
                        "tree_sha",
                        "base_tree_sha",
                        "commit_sha",
                    )
                }
                _require(
                    state.get("composition", metadata) == metadata,
                    "composition_changed",
                )
                state["composition"] = metadata
                state["phase"] = "composed"
                self.journal.save(state)
                self.publisher.credential()
                self.publisher.validate_repository(
                    manifest["base"], composed["base_tree_sha"], deadline=deadline
                )
                if not state.get("objects_uploaded"):
                    state["phase"] = "objects_intent"
                    self.journal.save(state)
                    self.publisher.upload_objects(
                        composed, manifest["base"], deadline=deadline
                    )
                    state["objects_uploaded"] = True
                    state["phase"] = "objects_uploaded"
                    self.journal.save(state)
                self._current(state, deadline)
                self.publisher.validate_repository(
                    manifest["base"], composed["base_tree_sha"], deadline=deadline
                )
                branch = self.publisher.read_branch(state["branch"], deadline=deadline)
                if branch not in {None, composed["commit_sha"]}:
                    raise ForgeError("feature_branch_changed")
                if branch is None:
                    state["branch_intent"] = True
                    state["phase"] = "branch_intent"
                    self.journal.save(state)
                    self.publisher.create_branch(
                        state["branch"], composed["commit_sha"], deadline=deadline
                    )
                state["phase"] = "branch_observed"
                self.journal.save(state)
                proposal = self.publisher.find_proposal(
                    state["branch"], composed["commit_sha"], marker, deadline=deadline
                )
                if proposal:
                    return self._observed(state, proposal, deadline)
                self._current(state, deadline)
                self.publisher.validate_repository(
                    manifest["base"], composed["base_tree_sha"], deadline=deadline
                )
                if (
                    self.publisher.read_branch(state["branch"], deadline=deadline)
                    != composed["commit_sha"]
                ):
                    raise ForgeError("feature_branch_changed")
                body = (
                    "## Mechanical composition awaiting review\n\n"
                    "This draft reconstructs final canonical child patches and matches the captured root candidate's Git tree. "
                    "Repository checks and independent review remain pending against the actual PR head and base.\n\n"
                    f"- Candidate: `{candidate_id}`\n- Root attempt: `{manifest['attempt_id']}`\n"
                    f"- Approved base: `{manifest['base']}`\n- Composite tree: `{composed['tree_sha']}`\n"
                    f"- Git commit: `{composed['commit_sha']}`\n- Provenance manifest: `{composed['manifest_sha256']}`\n\n"
                    "Ordered final child patch hashes:\n"
                    + "\n".join(
                        f"- `{item['child_id']}`: `{item['artifacts']['patch']}`"
                        for item in manifest["lineage"]
                    )
                )
                self.publisher.credential()
                if time.monotonic() >= deadline:
                    raise ForgeError("publication_deadline")
                state["pr_intent"] = True
                state["phase"] = "pr_intent"
                self.journal.save(state)
                new_pr_intent = True
                proposal = self.publisher.create_draft(
                    state["branch"],
                    composed["commit_sha"],
                    marker,
                    body,
                    deadline=deadline,
                )
                return self._observed(state, proposal, deadline)
            except CompositionError as exc:
                state["last_problem"] = {
                    "code": exc.code,
                    "child_id": exc.child_id,
                    "paths": list(exc.paths),
                }
                self.journal.save(state)
                status = (
                    "unavailable"
                    if exc.code
                    in {
                        "composition_deadline",
                        "source_unavailable",
                        "git_tool_failure",
                    }
                    else "conflict"
                )
                return self._summary(state, status, exc.code)
            except PublicationError as exc:
                return self._summary(
                    state,
                    (
                        "unavailable"
                        if exc.code in {"canonical_unavailable", "publication_deadline"}
                        else "conflict"
                    ),
                    exc.code,
                )
            except ForgeError as exc:
                if (
                    new_pr_intent
                    and not exc.uncertain
                    and exc.code
                    in {
                        "publication_unavailable",
                        "publication_deadline",
                        "forge_request_limit",
                    }
                ):
                    # These local failures explicitly occurred before transport.
                    state["pr_intent"] = False
                    state["phase"] = "branch_observed"
                    self.journal.save(state)
                    status = "unavailable"
                elif state.get("pr_intent"):
                    status = "uncertain"
                elif exc.uncertain or (
                    state.get("branch_intent") and exc.code == "forge_unavailable"
                ):
                    status = "uncertain"
                elif exc.code in {
                    "publication_unavailable",
                    "forge_unavailable",
                    "forge_request_rejected",
                    "publication_deadline",
                }:
                    status = "unavailable"
                else:
                    status = "conflict"
                return self._summary(state, status, exc.code)


def configured_service(configuration):
    validate_managed_installation()
    if (
        not isinstance(configuration, dict)
        or set(configuration)
        - {
            "schema_version",
            "state_directory",
            "source_path",
            "base_commit",
            "authority",
            "forge",
            "limits",
            "operation_seconds",
        }
        or not {
            "schema_version",
            "state_directory",
            "source_path",
            "base_commit",
            "authority",
            "forge",
        }
        <= set(configuration)
    ):
        raise ValueError("invalid publication configuration")
    if (
        type(configuration["schema_version"]) is not int
        or configuration["schema_version"] != 1
    ):
        raise ValueError("unsupported publication configuration version")
    base = configuration["base_commit"]
    if not isinstance(base, str) or not SHA.fullmatch(base):
        raise ValueError("an approved full source commit is required")
    authority = configuration["authority"]
    if not isinstance(authority, dict) or set(authority) != {"endpoint", "token_ref"}:
        raise ValueError(
            "explicit authority endpoint and credential reference are required"
        )
    client = ManagedAuthorityClient(**authority)
    policy = PublicationPolicy(**configuration["forge"])
    if policy.token_ref == client.token_ref:
        raise ValueError("forge and authority credential references must be distinct")
    limits = CompositionLimits(**configuration.get("limits", {}))
    reader = CanonicalPublicationReader(client, policy, base, limits)
    return PublicationService(
        reader,
        ManagedGitHubPublisher(policy),
        configuration["source_path"],
        configuration["state_directory"],
        limits=limits,
        operation_seconds=configuration.get("operation_seconds", 300),
    )


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True, type=Path)
    parser.add_argument("--candidate", required=True)
    parser.add_argument(
        "--child",
        action="append",
        help="complete final lineage in intended order; default canonical ID order",
    )
    args = parser.parse_args(argv)
    try:
        if args.config.stat().st_size > 65536:
            raise ValueError
        result = configured_service(json.loads(args.config.read_text())).run(
            args.candidate, args.child
        )
    except (
        ValueError,
        TypeError,
        KeyError,
        OSError,
        PublicationError,
        CompositionError,
    ) as exc:
        result = {
            "schema_version": 1,
            "status": "unavailable",
            "reason": getattr(exc, "code", "invalid_configuration_or_state"),
            "ready_for_review": False,
            "release_authorized": False,
        }
    print(json.dumps(result, indent=2, sort_keys=True))
    return (
        0
        if result["status"] in {"draft_published", "existing_closed", "existing_ready"}
        else 3
    )


if __name__ == "__main__":
    raise SystemExit(main())
