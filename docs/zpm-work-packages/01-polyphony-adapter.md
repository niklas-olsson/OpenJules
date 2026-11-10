# [DRAFT][Agent] Connect OpenJules to canonical Polyphony claims and authenticated task ingress

## Rationale

ZPM will run multiple OpenJules workers for an enrolled repository. OpenJules must connect those workers to real shared coordination and one authority per protected task. Its current local Polyphony facade cannot prevent independent processes from executing the same work. This package makes OpenJules a consumer of Polyphony's authority, while preserving peer-selected work and ordinary discussion.

> Agent-authored draft, 2026-11-10, informed by separately spawned reviewers. This proposes an implementation package; no automatic solver trigger is implied.

## Evidence

- [`src/polyphony/client.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/polyphony/client.py) keeps thoughts, batons and backlog in dictionaries. It stores an MQTT hostname but does not publish or subscribe.
- [`src/polyphony/manager.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/polyphony/manager.py) caches one client/node identity per repository. Its reentrant batons and repository-wide cleanup cannot distinguish concurrent executions.
- [`src/api/webhook.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/api/webhook.py) and [`src/api/ui_routes.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/api/ui_routes.py) dispatch directly through `BackgroundTasks`. UI identifiers omit the repository.
- [`src/worker/executor.py`](https://github.com/niklas-olsson/OpenJules/blob/be9634e74b3d47b42662653cb06a34f36b01fd1c/src/worker/executor.py) treats the local baton as duplicate protection before sandbox execution and publication.

## Deliverable

Implement one real Polyphony adapter and route every enabled execution ingress through it.

1. Give repository bindings, worker incarnations, root attempts and child sessions distinct identities. Source work identity includes forge, canonical repository binding, source kind and source identifier; repeated deliveries refer to the same work.
2. Authenticate remote triggers and enforce the enrolled repository, allowed source and execution policy. Webhook, UI, CLI, polling and PR-review paths must either use this boundary or explicitly reject managed execution. An HTTP acknowledgement must not mean volatile background work is safely queued.
3. Persist accepted executable intent through the canonical task/control path before acknowledging durable acceptance. Let eligible workers select authorized work; do not make ZPM a task dispatcher.
4. Extend the canonical launch seam from [Polyphony #109](https://github.com/niklas-olsson/keystone-polyphony/issues/109): one attempt selects exactly one trusted runtime adapter. Bind the launch to authenticated runtime identity, approved immutable specification, attempt/revision/fence and stable execution key before dispatch. Do not call the existing local `/execute` and independently launch OpenJules for that attempt.
5. Return idempotent execution, termination and artifact receipts to that authority. OpenJules may journal process facts, but must not create a second task-claim, budget, review or acceptance ledger.
6. Keep mesh presence, thoughts and discovery advisory. Ordinary peer discussion does not require managed-task enrollment. A predictable repository discovery key is not authorization.

## Acceptance

- [ ] Duplicate source delivery across separate ingress processes creates one canonical task through idempotent enrollment, not one launch for each of several duplicate tasks. A deliberate new run requires an explicit request or approved revision.
- [ ] Two separate OpenJules processes using actual Polyphony cannot launch duplicate protected execution for one attempt, including duplicate webhook and PR-review deliveries.
- [ ] Same request/specification returns the same execution; changed specification under the same key is rejected.
- [ ] Lost launch response is reconciled using the same handle. Restart, stale revision/fence or unavailable authority never causes a fresh unreserved launch.
- [ ] Unenrolled repository, unauthorized trigger and mismatched runtime receipt are rejected before protected effects.
- [ ] All enabled ingress paths share admission rules; repository A issue 1 and repository B issue 1 remain distinct.
- [ ] Completion of one execution cannot release another execution's ownership or masquerade as its identity.
- [ ] Real cross-process tests cover contention and recovery; manually sharing Python dictionaries is not integration evidence.

## Dependencies and boundary

Requires the canonical runtime/authority contract in [Polyphony #109](https://github.com/niklas-olsson/keystone-polyphony/issues/109). Consume worker handles from [OpenJules: recoverable worker lifecycle](02-worker-lifecycle.md) and repository bindings from [ZPM #1](https://github.com/niklas-olsson/zero-point-modulator/issues/1) for the installed path. Their contracts can be developed together. No new broker, fleet scheduler or mandatory coordinator for casual discussion.

**Implementation packaging:** Agree the small lifecycle, runtime and authority interfaces first. Lifecycle/isolation can ship against deterministic contract fixtures, and the adapter can use a fixed repository binding before ZPM onboarding exists. Cross-component execution is the installation gate, not a circular prerequisite for starting these packages.
