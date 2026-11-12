# Managed Docker runtime

`ManagedDockerRuntime` implements the worker lifecycle on one trusted Linux
host with a local Docker daemon. It runs an operator-approved command against
an immutable base commit in an isolated container and retains the resulting
workspace archive, patch, log and capture manifest. It makes no model calls
while idle. A real canonical authority adapter and dispatcher must authorize
each attempt before this runtime is invoked.

This is a root-only execution slice for [runtime #4](https://github.com/niklas-olsson/OpenJules/issues/4)
and [lifecycle #3](https://github.com/niklas-olsson/OpenJules/issues/3).
Child execution, independent review, verified PR publication and hostile
multi-tenant hosting remain outside this driver. An optional
[host-owned model broker](managed-model-broker.md) connects approved root coding
agents without giving their container general networking or provider credentials.

## Profile and service ownership

The host supplies `DockerProfile` values. Their identity is the exact
`(deployment_id, repository, name)` tuple, so independent repositories can use
the same local profile name. Changing any value under an existing scoped name
is rejected by the persistent journal. Publish a new profile name for changes.

Required fields are `name`, `deployment_id`, canonical `repository`, an absolute
`source_path`, immutable `image`, command argv and full 40-character
`base_commit`. The source must be a complete local Git clone or bare repository,
not a Git worktree whose administrative directory is outside the mounted path.
The approved commit must exist in that source. The host exports only that raw
commit and its exact tree/blob closure into a sanitized shallow bare repository.
It reads objects through a fresh controlled metadata directory, with replacement
objects disabled and no source configuration, refs or hooks. The explicit object
list excludes parent history, unrelated refs and submodule commit objects. The
exported object set is verified before the cache is atomically published.

Each export has a cumulative 30-second deadline, bounded process output and an
uncompressed object-byte limit equal to `max_archive_bytes`. The original host
checkout is **never mounted** into the task container. Ignored files such as
`.env`, credential-bearing Git configuration and unapproved history stay on the
host. The container sees only the completed sanitized export. Repository
cloning, checkout, agent commands and diff generation run inside the container.

The image must already be installed and contain Python 3 and Git. Supply its
`sha256:...` image ID or exact `repository@sha256:...` digest. A mutable image tag
is rejected. The runtime does not pull images or execute setup from the source
repository. The host operator owns image preparation and approval.

Default resource settings are 512 MiB memory with swap disabled, one CPU quota,
128 processes, a 300-second maximum attempt and a 16 MiB archive limit. All are
explicit profile fields. `max_archive_bytes` limits capture memory and output;
it is **not a filesystem quota**. Docker named volumes can consume host storage
until an external storage quota is reached. This remains an operational limit
for the approved-repository baseline and an open confinement requirement for
untrusted multi-tenant deployments.

The normal task UID is 65532. UID 0 and the watchdog's reserved UID 65534 are
rejected. `environment_refs` accepts only explicit supported model API-key
names mapped to `env:HOST_VARIABLE`; it does not accept Docker, Git, authority,
host path or arbitrary process environment settings. No model credentials are
needed for deterministic qualification commands. Network mode is always `none`,
so configuring a guest key does not make a remote model reachable. Profiles
configured with the host model broker reject all guest environment references;
their provider credential stays on the host and their only added mount is the
worker's authenticated read-only broker directory.

## Container and deadline boundary

The container has a read-only root filesystem, no Linux capabilities,
`no-new-privileges`, no privileged mode, no host network, no Docker socket and
no authority credentials. The sanitized source is mounted read-only. A dedicated
Docker volume contains the writable workspace. Temporary data and the small
control directory use bounded tmpfs mounts.

A fixed Python PID 1 watchdog runs as UID/GID 65534. The task runs through Docker
exec as UID/GID 65532 or the other approved nonroot identity. The control directory is
mode 0700, owned by the watchdog. The task cannot modify its deadline or signal
that different-UID process. The host writes a single monotonic-clock deadline
before dispatch. The watchdog reads it once and exits at that deadline. Exiting
PID 1 terminates the entire PID namespace, including background descendants,
even when the host supervisor dies. This requires the supported local Linux
daemon topology and its shared monotonic clock.

PID 1 also reaps adopted children that have already exited, returning their PID
slots to the unchanged container allowance. Each existing 50-millisecond loop
performs at most 128 nonblocking waits and checks the original deadline before
each wait. It does not signal live descendants or change their grants, execution
status or capture obligations. Reaping is process bookkeeping; whole-container
termination and verified capture remain the release boundary.

Idle containers expire after
24 hours. The trusted dispatch daemon calls `recover_idle(worker_id, spec)` for
an idle worker that becomes unknown. Recovery confirms the exact owned
container is stopped, the original start committed and no attempt exists before
capturing and releasing that incarnation. ZPM can replace it at the unchanged
target. Missing containers, unresolved starts and unavailable Docker retain
their reservations. Recovery never stops a running worker, and the ordinary
`observe` method remains free of capture and termination effects.

The dispatcher rechecks canonical permission immediately before execution and
subtracts request time from the returned allocation. Runtime deadlines never
extend a recorded attempt. Polling failure is not termination evidence; Docker
must confirm the whole container has stopped before artifacts can release its
capacity reservation.

## One attempt per incarnation

One worker incarnation executes at most one root attempt. Completing, timing
out or cancelling that attempt retires and stops the entire container. This
gives a concrete descendant termination boundary. ZPM can then provision a new
generation to restore the selected capacity. There is deliberate container
churn; an exec response alone does not justify reusing the container.

`execute_attempt(worker_id, spec, attempt_id, input_text, seconds, *, deadline_monotonic=None)` resolves the
command from the approved profile. Requirements are delivered through stdin
and `OPENJULES_INPUT_FILE`. An immutable attempt/input binding is persisted
before any execution request. Repeating it observes the original execution or
returns its saved receipt; it never runs the command again. The cutoff is
captured at function entry, before locks and preparation, and can be shortened
by the dispatcher's fixed monotonic deadline. Validation, journalling and Docker
preparation never create a fresh duration. Changed input or a
second attempt on that worker conflicts. `inspect_attempt` recovers the saved
result. `cancel_attempt` also works before runtime dispatch and creates a
permanent tombstone that a later execution request cannot bypass.

The driver does not allocate task budgets, declare ownership or accept work.
The trusted dispatcher must obtain canonical permission and lifecycle
`begin_execution` admission first. Terminal facts must reach Polyphony, and its
artifact acknowledgements must be retained, before the dispatcher clears local
execution occupancy.

## Crash and late-request handling

The driver journals immutable specifications and per-incarnation effects on
local SQLite with synchronous durability. Local file locks serialize driver
operations across API processes without holding a database transaction during
Docker I/O. Store the database, locks and capture directory on persistent local
storage. Network filesystems and independent copies controlling the same
daemon are unsupported.

Container creation uses a deterministic name and exact ownership/specification
labels. A lost create response is discovered by that name, then bound to its
full immutable Docker container ID. Foreign labels or changed IDs are rejected.
Containers and volumes are never automatically deleted, renamed or pruned.
Their retained names prevent delayed duplicate creates from becoming a second
container. The [explicit host cleanup operation](#explicit-host-cleanup) supports
only newly tracked, fully acknowledged resource creation and complete canonical
capture. Legacy or uncertain creates keep their name fences. Manual removal
while requests might still arrive invalidates recovery.

Docker start is dispatched at most once. Its intent is persisted first. If the
response is lost and Docker still shows a zero `StartedAt`, the driver preserves
uncertainty, including during stop. An apparently stopped container is not a
fence against a delayed original start. A later nonzero `StartedAt` proves that
the only start request committed, after which whole-container stop can safely
fence execution. A crash between committing start intent and sending the request
may require explicit operator recovery; the runtime does not trade uncertainty
for a duplicate launch.

The runtime retains an unresolved reservation on unavailable Docker, unknown
termination, failed capture or capture overflow. Docker API socket timeouts do
not establish absence or death. The driver does not remove those records just
because another request times out.

## Capture and evidence

After verified whole-container termination, the host asks Docker for the
workspace tar stream, enforces the configured byte limit, writes it to a
temporary file, fsyncs it, atomically installs it and fsyncs its directory.
No archive paths are extracted onto the host. Only bounded regular patch/log
members are read as data; symlink or duplicate evidence members fail closed.
The raw archive, SHA-256 digest and immutable manifest survive service restart.

The patch and command log originate inside the task container. Their presence
does not establish that tests passed or that a reviewer approved the result.
The manifest explicitly identifies that provenance and whether each file was
present. A killed command can have a useful preserved workspace without a final
patch. The canonical integration must retain that distinction and must not
fabricate a verified commit or PR from it.

## Explicit host cleanup

After an executed worker's entire container has stopped and its root and child
artifacts have reached Polyphony, the host operator can remove that worker's
container and workspace volume. Stop the managed OpenJules service through its
supervisor first; leave the canonical authority available. Use the same private
configuration and the exact scoped worker identity returned by discovery:

```sh
python -m src.worker.managed_service \
  --config /private/installation/config/openjules.json \
  --cleanup-worker WORKER_ID \
  --deployment-id DEPLOYMENT_ID \
  --repository github:github.com/owner/repository
```

The command performs no stop, launch, model call or endpoint restoration. It has
no HTTP/task-facing equivalent. Existing service, dispatcher, lifecycle and
runtime locks exclude concurrent work. A busy dispatcher, lifecycle or runtime
lock returns a retained JSON result. Model and child service ownership is checked
when constructing the command; a busy service lock refuses configuration with
exit status 2 before cleanup begins. The JSON result reports `cleaned` or
`retained`, a fixed reason, and confirmed container/volume removal progress.
Exit status is zero only for completed cleanup. Retry the same scoped worker
after a transient failure.

Cleanup requires all of the following evidence:

- A new creation-tracking journal record with exactly one dispatched and one
  durably acknowledged volume create, and the same for container creation.
  Tracking precedes each create, including volume-first failures. Observation
  cannot replace a lost acknowledgement. Existing records migrate as ineligible.
- Creation through Docker SDK **7.2.0**, its stock local Unix-socket client/API
  and adapter, zero adapter retries, zero redirects and no response hooks. This
  transport proof is recorded separately at each resource creation. The managed
  runtime disables redirects before using its own client. Other SDK/custom
  transports may execute under the existing contract but remain ineligible for
  this cleanup qualification. The same qualified transport is required to delete.
- Terminal local execution references and a complete dispatch delivery. A fresh
  canonical permission read must return the original immutable binding and
  complete terminal root capture. Every child must have a resolved grant, closed
  admission, completed immutable capture and matching canonical child lineage.
- A bounded regular, non-symlink host archive whose actual bytes still match the
  capture receipt and manifest. Its worker, attempt, profile and container identity
  must agree. Missing or changed capture blocks further deletion.
- The exact stopped container ID and ownership labels, its recorded workspace
  mount, and the original volume name, creation timestamp, local driver/scope,
  options and ownership labels. A changed same-name resource is refused.

The operation first journals its exact targets, archive hash and canonical proof.
It removes the container without force or implicit volume deletion and verifies
its original ID is absent. Only then does it revalidate and remove the single
owned volume without force. In-use volumes remain retained. No arbitrary path,
foreign resource, source snapshot, host archive, journal, model record or lock is
removed. The original worker/attempt tombstones and execution receipt remain.

Progress survives a lost delete response or a process crash. Absence can complete
an interrupted step only after its matching cleanup intent exists; absence before
intent remains unresolved. Partial replay rechecks capture, canonical proof and
resource identity. Canonical unavailability can therefore leave a volume retained
after its container was removed. A completed replay returns its historical receipt
without touching later resources, and old ensure/execute/stop requests cannot
recreate the cleaned incarnation.

This first slice intentionally retains idle workers, incomplete claims, legacy
records, and every lost/retried/partially acknowledged resource create. It is not
automatic garbage collection, archive expiry or a disk quota. The trusted-host
contract permanently reserves managed resource names, including after completed
cleanup or a lost delete response. Never manually recycle those names. Docker
volumes have no container-like immutable ID, and a delayed timed-out delete cannot
distinguish a later manually created replacement. Original tombstones prevent
the supported runtime from reusing names. Do not manually remove name fences or
edit journals to make an ineligible worker qualify.

`tests/unit/test_managed_cleanup.py` exercises adverse evidence, transport
redirects, creation uncertainty, deletion response loss, simulated journal-commit
crash boundaries, child receipt completeness, locks and replay with deterministic
fixtures. The actual two-child Docker trial also starts a fresh cleanup process
and deliberately exits it after physical container deletion, before durable
progress acknowledgement. Another fresh process reopens the journals and finishes
only the remaining volume deletion. The test verifies unchanged archives and
child captures, preserved receipts and zero additional model calls. Its canonical
authority and provider remain explicit fixtures. Only the mandatory opted-in
Docker CI run qualifies those runtime effects; local fixtures cannot establish them.

## Verification

Run the focused adversarial unit contracts:

```sh
python -m pytest tests/unit/test_managed_docker_runtime.py tests/unit/test_source_snapshot.py tests/unit/test_watchdog_reaping.py
```

They model late create/start, process restart, conflicting identities, capture
failure, hostile tar members, idle recovery and expired preparation deadlines.
Real Git tests verify that ignored secrets, host configuration, other refs and
ancestor objects are absent from the exported clone. These fake-Docker tests are not confinement
proof. Real qualification is a separate explicit gate:

```sh
OPENJULES_MANAGED_DOCKER_TESTS=1 \
  python -m pytest tests/integration/test_managed_docker_runtime.py
```

Once enabled, missing Docker fails the test. The gate builds the small Python/Git
fixture or accepts `OPENJULES_MANAGED_IMAGE_ID`. It executes an actual Git change,
captures the patch, checks container configuration, kills a supervising host
process and verifies that the watchdog still terminates the container. Task
code also attempts and fails to signal the watchdog or overwrite its control
file. A parametrized native test runs each actual PID 1 watchdog script, requiring
256 adopted exits to be reaped under the unchanged 128-PID limit while an adopted
live descendant continues running until the normal whole-worker fence. This
tests the scripts directly; the separate managed-child tests qualify child-policy
routing and the earliest armed deadline after supervisor shutdown.
Fixture code does real work but is not an LLM agent, a child-agent swarm
or proof of canonical authority integration. The combined installation gate
must exercise those service boundaries separately.
