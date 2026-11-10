# [DRAFT][Agent] Run bounded child agent sessions inside an OpenJules worker

## Rationale and lineage

This succeeds the runtime scope of [Polyphony #110](https://github.com/niklas-olsson/keystone-polyphony/issues/110) and preserves its [README-first refinement](https://github.com/niklas-olsson/keystone-polyphony/issues/110#issuecomment-6753781131). OpenJules launches and supervises executable agents. Polyphony supplies shared conversation, scoped authority and durable task evidence. Moving execution here avoids turning the Mind Bridge into a global worker manager.

> Agent-authored successor draft, 2026-11-10, informed by separately spawned reviewers. Original discussion remains linked; independent peers retain their own agency.

## Deliverable

Provide a small opt-in child-session runtime for an existing worker: create a bounded child, send an instruction, observe/collect its result, and request cancellation. Use existing snapshot/event/artifact reads for status and reattachment instead of multiplying control APIs.

Start with two real children at depth one. Each has a stable logical session, authenticated execution identity, approved runtime profile and durable turn/result references. Parent authority applies only to its delegated children. An invited independent peer may decline or leave and is not a process the parent can cancel.

Support two paths:

- **Discussion:** one topic can bring independent voices together without enrolling a protected task. Host-approved model access, launch policy and quotas still apply. Preserve proposals, criticism, clarification and disagreement; do not require artificial consensus.
- **Managed work:** children are bounded subexecutions inside one existing root attempt. Do not call `start_attempt` repeatedly on the same task or weaken its one-unresolved-attempt invariant. Child outputs are evidence/artifacts; the parent produces the reviewable candidate.

Separate logical sessions from operating-system processes. One-shot turns are a functional fallback. Reuse a warm session only when the adapter supports it and its cleanup/revocation behavior is verified. One active turn per child is sufficient initially; later instructions are queued unless live injection is explicitly supported.

For managed work, persist intent and request [Polyphony #112](https://github.com/niklas-olsson/keystone-polyphony/issues/112)'s atomic grant/allocation reservation before launch. OpenJules enforces those limits and records process facts without a second budget ledger. Aggregate parent-plus-child allocation uses the canonical task's existing budget unit; parallel elapsed time is not the sum of allocated execution time. Discussion-only sessions use host policy and a local runtime journal. Child deadlines cannot outlive the approved root limit, and unknown outcomes do not silently refund reservations.

Use [Polyphony #111](https://github.com/niklas-olsson/keystone-polyphony/issues/111) for correlated instructions/results and [#112](https://github.com/niklas-olsson/keystone-polyphony/issues/112) for authenticated scope/grants. The runtime enforces the approved profile. Public proposals may be shared by policy while private instructions and artifacts remain scoped.

On parent loss, already approved children may finish within their bounds and retain results. Reattachment must not create fresh execution. Root completion and worker removal remain blocked by unknown descendant termination or unresolved capture.

## Acceptance

- [ ] One configured invocation starts two actual agents; proposal, rebuttal, follow-up and synthesis retain attributable dissent.
- [ ] Discussion needs no managed-task enrollment; a subsequent protected action must use canonical authorization.
- [ ] Two managed children run under one root attempt with distinct sessions/artifacts and an aggregate bounded allocation.
- [ ] Duplicate spawn/instruction requests return the same child/turn; changed input under the same key conflicts.
- [ ] Parent/runtime restart reattaches to committed state; lost responses do not launch again.
- [ ] Decline, clarification, cancellation and capture failure have explicit outcomes. Unknown descendants block finalization and cleanup.
- [ ] A parent cannot control an unrelated peer, grant owner/reviewer rights or manufacture independent acceptance.
- [ ] Benchmark real cold and supported warm two-round sessions, startup/context cost and storage growth. Idle observation uses zero model calls; set latency targets from measured results.

## Dependencies and boundary

Uses [OpenJules: real Polyphony adapter](01-polyphony-adapter.md), [OpenJules: recoverable worker lifecycle](02-worker-lifecycle.md), [Polyphony #111](https://github.com/niklas-olsson/keystone-polyphony/issues/111) and [Polyphony #112](https://github.com/niklas-olsson/keystone-polyphony/issues/112). Managed coding uses [OpenJules: execution confinement and capture](03-runtime-confinement.md). No full task DAG, recursive delegation, mandatory task-per-child, automatic PR or fleet autoscaling is required. [OpenJules: composite PR integration](05-composite-pr.md) separately composes coding outputs.
