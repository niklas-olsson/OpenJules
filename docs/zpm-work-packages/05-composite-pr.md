# [DRAFT][Agent] Compose child artifacts into one verified Git commit and PR

## Rationale and lineage

This succeeds [Polyphony #114](https://github.com/niklas-olsson/keystone-polyphony/issues/114), preserving its [deterministic integration review](https://github.com/niklas-olsson/keystone-polyphony/issues/114#issuecomment-6754459812). OpenJules already owns Git execution and forge publication. It should compose child contributions there, while Polyphony retains authoritative provenance and acceptance and the target repository retains its normal merge policy.

> Agent-authored successor draft, 2026-11-10, informed by separately spawned reviewers. Source discussions remain linked. Integration produces reviewable work; it does not grant automatic merge authority.

## Evidence

[`src/worker/executor.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/worker/executor.py) commits, pushes and opens proposals through [`src/git_manager/lifecycle.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/git_manager/lifecycle.py) and forge providers. Extend this existing path rather than adding another PR engine to Polyphony.

The source review also identifies misleading GitHub-shaped evidence in Polyphony's experimental admission emitter and an invalid three-positional-argument `git merge-tree --write-tree` invocation. [Polyphony #109](https://github.com/niklas-olsson/keystone-polyphony/issues/109) owns removal/quarantine of the false authority path. Do not copy those implementations as trusted publication evidence.

## Deliverable

Implement one operation from exact child artifact inputs to a reviewable composite commit and one normal feature PR.

1. Receive an immutable manifest with root task/revision, approved base Git SHA, ordered child artifact hashes, source attempts and applicable dependency/review receipts. Verify scope, current permissions and artifact integrity before applying changes.
2. Create one fresh integration worktree. Use tested Git primitives to check/apply patches. Distinguish command/tool failures from actual content conflicts; correct the source review's invalid merge-tree helper before any reuse. Validate path boundaries and the approved handling of symlinks/submodules. No child writes directly to a shared integration branch.
3. Preserve original artifacts and their authorship. On conflicting edits, return a structured problem with exact inputs and affected paths. Permit a bounded correction task; do not erase the other contribution or publish a partial branch.
4. Record the resulting diff/tree and actual Git commit SHA. Artifact digest, candidate ID, Git SHA and workflow-run ID are different identifiers and cannot substitute for one another.
5. Run the target repository's configured lint/tests against the final combined content in the approved isolated profile. Perform required independent composite review; individual child success does not establish combined correctness.
6. Publish through scoped forge authority. Use expected-ref checks and an idempotent publication key. After a timeout, query the scoped branch/PR and expected head before retrying. A lost response must not create duplicate PRs.
7. Preserve existing repository checks, review and merge policy. A new composite commit or changed PR head/base requires fresh applicable evidence. Failed validation returns an actionable result and retained artifacts.

## Acceptance

- [ ] Two non-overlapping child patches yield one real composite commit and one PR with exact source provenance.
- [ ] Conflicting patches produce a recoverable conflict and no partial publication.
- [ ] Tampered artifact, wrong base, stale revision or disallowed path is rejected before protected effects.
- [ ] Parent/runtime failure during integration retains recoverable inputs and a truthful operation state.
- [ ] Replaying integration/publication after lost responses returns the same result or reconciles the same branch/PR.
- [ ] Combined lint/test failure blocks a validated-success claim, even when each child passed separately.
- [ ] Candidate IDs, invented workflow IDs and stale head-bound evidence cannot satisfy repository CI/review requirements.
- [ ] A real parent-plus-two-children demonstration reaches a normal reviewed PR; no automatic staging/main write or merge bypass occurs.

## Dependencies and boundary

Uses [OpenJules: real Polyphony adapter](01-polyphony-adapter.md), [OpenJules: execution confinement and capture](03-runtime-confinement.md) and durable coding artifacts from [OpenJules: bounded child sessions](04-child-sessions.md). Test mechanical composition independently with deterministic artifacts. [Polyphony #109](https://github.com/niklas-olsson/keystone-polyphony/issues/109) supplies canonical artifact/acceptance semantics. The general DAG in [Polyphony #113](https://github.com/niklas-olsson/keystone-polyphony/issues/113) is not a prerequisite for composing two approved sibling artifacts. [ZPM #3](https://github.com/niklas-olsson/zero-point-modulator/issues/3) exercises this path as the installable system trial. Mechanical patch application, observation and retry reconciliation make zero model calls.
