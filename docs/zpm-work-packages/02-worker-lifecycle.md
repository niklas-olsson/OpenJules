# [DRAFT][Agent] Expose recoverable worker start, observation, drain and stop for ZPM

## Rationale

ZPM should reconcile the requested number of workers without taking over task selection or individual agent supervision. OpenJules must expose truthful, idempotent runtime operations so retries, restarts and scale-down do not duplicate execution or erase work. A worker is execution capacity; its child agents are not additional ZPM replicas.

> Agent-authored draft, 2026-11-10, informed by separately spawned reviewers. Scope is a small OpenJules runtime contract, not a new orchestration framework.

## Evidence

[`src/worker/swarm_orchestrator.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/worker/swarm_orchestrator.py) has per-process concurrency semaphores and in-memory active-task maps. [`src/worker/dispatcher.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/worker/dispatcher.py) uses FastAPI background tasks. Neither supplies durable worker identity, start reconciliation or drain semantics. The [SQLite store](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/storage/sqlite_storage.py) currently records dashboard data, not runtime ownership.

## Deliverable

Expose this minimum provider contract, with names illustrative rather than mandatory HTTP routes:

- `ensure_worker(repository_binding, slot_id, generation, launch_key, approved_profile)`
- `list_or_find_workers(repository_binding, launch_key)`
- `observe_worker(handle)`
- `drain_worker(handle, request_key)`
- `stop_worker(handle, request_key)`

Authenticate callers and scope every operation to its repository binding. Persist the logical slot, immutable incarnation/boot identity, approved specification, operation keys and provider receipts. Replaying a key with identical input returns the same result; different input conflicts. Scoped discovery must recover a lost start response even when ZPM never received the provider handle.

Document worker states such as starting, ready, busy, draining, stopped, failed and unknown. Distinguish process liveness, readiness to claim work, and recoverability of artifacts. Return reasons and active root/child execution references without manufacturing successful status.

Start with one active root attempt per worker capacity unit. Child agents consume that worker's resource envelope and the canonical root task allocation. They do not increase the fleet worker count. Local admission limits may enforce the approved profile but must not run a competing replica policy.

Drain atomically closes admission for new root claims and new child launches. Already approved work may finish within its limits or receive an authorized cancellation. Draining must remain effective across restart. A stop request is not proof of death: report stopped only after confirmed termination of the worker's owned executions and durable capture of recoverable artifacts. Unknown children or failed capture keep the worker unresolved.

Keep the runtime journal limited to process facts and operation receipts. Polyphony remains the task, allocation and acceptance authority. Its durable state must survive scaling the worker to zero.

## Acceptance

- [ ] Repeated ensure with the same key/specification creates one incarnation; changed specification conflicts.
- [ ] ZPM can recover a lost ensure response through scoped discovery without creating another worker.
- [ ] Controller/runtime restart preserves handles, drain state and pending operations; old process IDs alone never authorize signals.
- [ ] Drain racing a claim or child launch has one deterministic admission outcome.
- [ ] Worker with active children reports them and cannot claim completed stop while any termination or capture remains unknown.
- [ ] Failed stop/capture retains artifacts and a visible reason; no timeout-based assertion of death or automatic fresh launch.
- [ ] Every execution ingress honors worker admission. Observation and idle reconciliation make zero model calls.
- [ ] A fake provider exercises retries/crashes; a real OpenJules worker proves start, claim, drain and confirmed stop.

## Dependencies and boundary

Managed task admission uses [OpenJules: real Polyphony adapter](01-polyphony-adapter.md). Coding runtime guarantees use [OpenJules: execution confinement and capture](03-runtime-confinement.md). [ZPM #2](https://github.com/niklas-olsson/zero-point-modulator/issues/2) owns desired capacity and consumes this interface; it does not allocate child tasks or refund task budgets. Coordinate these contracts without requiring a generalized plugin registry, cloud scheduler or message bus.

**Implementation packaging:** Agree the small lifecycle, runtime and authority interfaces first. Lifecycle/isolation can ship against deterministic contract fixtures, and the adapter can use a fixed repository binding before ZPM onboarding exists. Cross-component execution is the installation gate, not a circular prerequisite for starting these packages.
