# OpenJules work packages for repository-installed swarms

These five agent-authored work packages were prepared on 2026-11-10 after a review by three separately spawned agents and a cross-repository review of Polyphony, OpenJules and ZPM. They are proposed implementation work, not implemented capability or runtime validation.

## Why these packages are here

OpenJules owns executable workers, bounded child agents, runtime confinement and Git/forge publication. ZPM owns repository enrollment and desired worker capacity. Polyphony owns shared conversation, protected task authority, delegated grants and artifact provenance.

Issue creation in this OpenJules fork currently returns HTTP 410 because the repository's issue tracker is disabled. This draft PR preserves the complete packages in their intended implementation repository until issues can be published. It does not need to be merged to create those issues.

| Work package | Origin and purpose |
| --- | --- |
| [Real Polyphony adapter](01-polyphony-adapter.md) | New prerequisite: replace process-local coordination and deduplicate source requests at canonical enrollment |
| [Recoverable worker lifecycle](02-worker-lifecycle.md) | New prerequisite: expose worker ensure/observe/discover/drain/stop to ZPM |
| [Runtime confinement and capture](03-runtime-confinement.md) | Runtime portion split from [Polyphony #112](https://github.com/niklas-olsson/keystone-polyphony/issues/112) |
| [Bounded child sessions](04-child-sessions.md) | Prepared successor to [Polyphony #110](https://github.com/niklas-olsson/keystone-polyphony/issues/110) |
| [Composite Git commit and PR](05-composite-pr.md) | Prepared successor to [Polyphony #114](https://github.com/niklas-olsson/keystone-polyphony/issues/114) |

The [Polyphony #110](https://github.com/niklas-olsson/keystone-polyphony/issues/110) and [Polyphony #114](https://github.com/niklas-olsson/keystone-polyphony/issues/114) source issues remain open until their OpenJules successor issues exist. Their original discussions remain the historical record. [Polyphony #112](https://github.com/niklas-olsson/keystone-polyphony/issues/112) continues to track provider-neutral authorization; this directory tracks its runtime counterpart.

## Installation path and implementation order

[ZPM #1](https://github.com/niklas-olsson/zero-point-modulator/issues/1) defines enrollment. [ZPM #2](https://github.com/niklas-olsson/zero-point-modulator/issues/2) reconciles worker capacity. [ZPM #3](https://github.com/niklas-olsson/zero-point-modulator/issues/3) owns the reproducible installation and complete acceptance trial, including the flat package map.

Agree the small interfaces first. Lifecycle and isolation may be implemented against deterministic contract fixtures; the adapter may use a fixed repository binding before ZPM onboarding exists. Full integration is the installation gate, not a prerequisite for beginning each component.

A busy worker counts toward desired capacity. Child sessions consume that worker's resources and the canonical task budget without increasing the replica count. Task authority and saved artifacts outlive worker scale-to-zero. Drain stops new root and child admission, and uncertain termination or capture remains explicit.

[Polyphony #113](https://github.com/niklas-olsson/keystone-polyphony/issues/113) is optional later work for separately accepted subtasks. The initial two-child and two-patch workflow does not require it.

## Completing issue publication

After the issue tracker is enabled:

1. Create one OpenJules draft issue from each package's title and body.
2. Replace package-file references with the returned issue URLs.
3. Link the successor issues from [Polyphony #110](https://github.com/niklas-olsson/keystone-polyphony/issues/110) and [Polyphony #114](https://github.com/niklas-olsson/keystone-polyphony/issues/114) before closing those sources as superseded, not implemented.
4. Update [Polyphony #112](https://github.com/niklas-olsson/keystone-polyphony/issues/112) and the ZPM package map with the runtime issue links.
5. Retain original comments and source lineage. Keep automatic execution labels separate from this design work.

## Review evidence

The reviewed source baselines are Polyphony commit `3a912baad6cdc31b19653a31ec937e0c7c102b42` and OpenJules commit `be9634e74b3d47b42662653cb06a34f36b01fd1c`. Source links in the packages are pinned to those commits. [Polyphony PR #106](https://github.com/niklas-olsson/keystone-polyphony/pull/106) and [Polyphony PR #115](https://github.com/niklas-olsson/keystone-polyphony/pull/115) are merged; their existing behavior is included as baseline.

The cross-review added canonical source-enrollment idempotency, explicit ownership of child allocation, clear confined-coding acceptance, and contract fixtures to avoid circular work-package dependencies. Documentation structure, references and package consistency were reviewed. No code implementation, live worker trial, containment test or repository test suite was run for these planning documents.
