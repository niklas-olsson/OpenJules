# [DRAFT][Agent] Enforce the coding runtime profile and capture work before cleanup

## Rationale and lineage

This is the runtime portion split from [Polyphony #112](https://github.com/niklas-olsson/keystone-polyphony/issues/112), including its [authorization-versus-containment review](https://github.com/niklas-olsson/keystone-polyphony/issues/112#issuecomment-6754408594). Polyphony owns authenticated grants and protected artifact access. OpenJules owns the processes, containers, credentials and filesystem behavior that make those grants enforceable during execution.

> Agent-authored successor draft, 2026-11-10. Source discussion remains in the linked issue. This is a scoped runtime deliverable, not a claim that a container or worktree alone proves isolation.

## Evidence

[`src/sandbox/docker_driver.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/sandbox/docker_driver.py) launches real containers with CPU/RAM limits, but `exec_in_sandbox` accepts a timeout without enforcing it. Cleanup catches stop/remove failures and still removes the workspace. [`src/worker/executor.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/worker/executor.py) reads repository configuration after initial sandbox creation. [`src/sandbox/config.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/sandbox/config.py) silently falls back to defaults on invalid configuration.

These are concrete gaps in bounded execution and recoverable work, not reasons to build a new security platform.

## Deliverable

Define two honest profiles: an explicitly trusted cooperative runtime and a verified confined coding runtime. The first installed coding path must use the verified confined profile and fail clearly if its declared guarantees are unavailable. The cooperative profile remains an explicit trusted local option and cannot satisfy the installation's confinement checks.

1. Resolve and validate the approved runtime configuration before applying image, setup, environment and resource policy. Pin a runnable image/command. Reject invalid managed configuration instead of silently substituting defaults.
2. Enforce wall-time deadlines and aggregate CPU/RAM/process limits for the root and its children. Restrict filesystem mounts and network access according to the profile. A child cannot evade limits by spawning grandchildren or background processes.
3. Give agents only the credentials their execution needs. Keep repository-owner, service-administrator and publication credentials outside child environments; use a scoped publication boundary. Explicitly control provider access instead of copying the host environment.
4. Apply Polyphony's authenticated scope and current grants at protected tool/effect boundaries. Do not introduce a competing role hierarchy, task authority or budget ledger here.
5. Persist launch ownership and observable incarnation handles. Cancellation must verify the affected processes; remembered PIDs alone are insufficient after restart.
6. Capture output, patches and provenance into durable storage before cleanup. Do not delete work on a failed stop, uncertain process state or failed capture. Preserve unresolved work and return a factual recovery condition to [OpenJules: recoverable worker lifecycle](02-worker-lifecycle.md).
7. Run actual agent work in the profile. Sleeping containers and mocked Docker calls remain useful unit fixtures, but cannot establish runtime confinement.

## Acceptance

- [ ] A real agent produces a retrievable artifact inside the approved profile; the effective image/setup/environment match the validated configuration.
- [ ] Timeout and descendant-process tests demonstrate enforcement rather than merely accepted timeout parameters.
- [ ] Negative tests verify that child code cannot access owner credentials, unauthorized host mounts or sibling-private artifacts through the runtime.
- [ ] Root and children share enforced resource bounds; their usage cannot silently exceed the approved envelope.
- [ ] Failed container stop, runtime restart and failed artifact upload preserve work and report unknown/unresolved state.
- [ ] Confirmed termination plus successful durable capture permits cleanup; replay does not erase an uncaptured execution.
- [ ] Unsupported confinement never silently runs an unrestricted replacement profile.
- [ ] Documentation states the tested host/runtime limits and distinguishes cooperative execution from confined execution.

## Dependencies and boundary

Use the operation/capture contract from [OpenJules: recoverable worker lifecycle](02-worker-lifecycle.md) and canonical execution binding from [OpenJules: real Polyphony adapter](01-polyphony-adapter.md). Child grants and actor authorization remain in [Polyphony #112](https://github.com/niklas-olsson/keystone-polyphony/issues/112); [OpenJules: bounded child sessions](04-child-sessions.md) consumes this profile for coding. A trusted no-tool discussion pilot may proceed without building general multi-tenant confinement, but must not inherit a permissive coding profile or advertise confinement it lacks.

**Implementation packaging:** Agree the small lifecycle, runtime and authority interfaces first. Lifecycle/isolation can ship against deterministic contract fixtures, and the adapter can use a fixed repository binding before ZPM onboarding exists. Cross-component execution is the installation gate, not a circular prerequisite for starting these packages.
