# Local Actions runners

Public local jobs request only `[factory-openjules]`; these runners have no
GitHub default labels. Trusted non-PR jobs and same-repository PR-family jobs
whose author association is `OWNER`, `MEMBER` or `COLLABORATOR` use that label.
Forks, other author associations and missing PR/head metadata use the original
GitHub-hosted Ubuntu label instead. Routing changes only `runs-on`, not existing
job conditions, build commands, qualification gates or artifact actions.
Artifact storage/billing is separate from runner compute.

One runner executes one job at a time for this repository (including matrix
jobs). Its per-repository runner/daemon envelope is 2 CPU and 4 GiB RAM.
All repositories share a host-wide aggregate ceiling of 3 CPU and 10 GiB RAM;
per-repository limits are ceilings, not simultaneous capacity guarantees.
An offline host leaves jobs queued until its matching runner returns; GitHub's
normal queue expiry still applies.

External-contributor jobs are not skipped by routing. Normal GitHub approval
requirements still apply. Keep branch creation/write access restricted to trusted
collaborators; PR-controlled workflow YAML is not an immutable isolation boundary.
A maintainer must review workflow changes before permitting untrusted execution.

The default branch also has a manual, owner-only `local-runner-health.yml` smoke
workflow using the custom label. It is separate from normal contributor CI and
does not qualify workloads or change retained evidence.

Docker workloads require a private per-repository Docker daemon and state;
never mount the host Docker socket. Qualification scripts may require a local
Unix socket, shared workspace paths, or their own rootful `dockerd`; do not
silently relax these requirements to accommodate a different runner topology.

`browser-host-prerequisite.yml` remains byte-for-byte unchanged on its original
GitHub-hosted runner. Its frozen host assertions, workflow hash, evidence and
mandatory tests are not reclassified by adding a general-purpose local runner.
No new local browser-host qualification is claimed.
