# Worker lifecycle contract for ZPM

This guide covers the durable capacity journal, runtime adapter interface, local
admission barrier and authenticated HTTP contract introduced for
[OpenJules #3](https://github.com/niklas-olsson/OpenJules/issues/3). The
[managed service](managed-service.md) connects this layer to Polyphony's canonical
authority and the [managed Docker runtime](managed-docker-runtime.md).

Constructing `WorkerLifecycle` without an explicitly supplied runtime still uses
`UnavailableRuntime`: it reports unavailable and rejects launches. The legacy
`BackgroundTasks` executor is never a managed fallback.

## Ownership

ZPM chooses desired worker capacity. OpenJules records worker incarnations and
runtime observations. Polyphony remains the authority for task enrollment,
claims, revision/fence checks, aggregate allocations, artifacts and acceptance.
The lifecycle database contains no replacement task queue or task budget ledger.

A worker is one capacity unit with at most one unresolved root execution. A
root may have depth-one child executions. These consume its runtime envelope and
canonical task allocation; they do not become additional ZPM replicas.

## Configure the API explicitly

`src.api.worker_lifecycle.create_worker_app` creates a small API application.
`create_worker_router` can be mounted in a deployment's existing FastAPI app.
Neither factory imports or initializes Docker, an LLM or `TaskExecutor`.

```python
from src.api.worker_lifecycle import create_worker_app
from src.worker.lifecycle import WorkerLifecycle, WorkerScope

# Read this credential through the deployment's existing secret mechanism.
# A token must contain at least 32 characters. Do not commit real credentials.
scope = WorkerScope("deployment-uuid", "github:github.com/owner/repository")
lifecycle = WorkerLifecycle("/var/lib/openjules/workers.sqlite", runtime=approved_runtime)
app = create_worker_app(lifecycle, {operator_token: {scope}})
```

`approved_runtime` and `operator_token` above are explicitly supplied deployment
objects, not built-in defaults. Run the resulting app through the deployment's
usual ASGI server. Keep this database and its adjacent `.runtime-locks` directory
on local persistent storage shared by API processes on one Linux/Unix host.
Do not place SQLite or these locks on a network filesystem or create independent
registries for replicas controlling the same runtimes. Multiple control hosts
require a separate shared coordinator and are outside this implementation.

The token authorizes an exact `(deployment_id, repository)` pair. Every operation
requires both fields, even when a worker ID or launch key is known. Scope checks
happen before lookup or effects. Another deployment's workers cannot be adopted,
observed or drained through a matching repository name alone.

## HTTP version 1

All requests use `Authorization: Bearer <deployment-token>`. The bearer is not
stored in the worker journal or returned in snapshots. POST bodies require
`schema_version: 1` and reject unknown fields. Capabilities and snapshots also
include `schema_version: 1`.

| Operation | Route | Input |
| --- | --- | --- |
| Capabilities | `GET /api/workers/capabilities` | Query: `deployment_id`, `repository`, `profile` |
| Ensure | `POST /api/workers/ensure` | JSON: `schema_version`, `deployment_id`, `repository`, `slot_id`, `generation`, `launch_key`, `profile` |
| Discover | `GET /api/workers` | Query: `deployment_id`, `repository`, optional `launch_key` |
| Observe | `GET /api/workers/{worker_id}` | Query: `deployment_id`, `repository` |
| Drain | `POST /api/workers/{worker_id}/drain` | JSON: `schema_version`, `deployment_id`, `repository`, `request_key` |
| Stop | `POST /api/workers/{worker_id}/stop` | Same fields as drain |

Capabilities echo the authorized `deployment_id`, `repository` and requested
`profile`, and return `operations` (`ensure`, `discover`, `observe`, `drain`,
`stop`), `managed_dispatch`, `profile_supported`, `repository_access` and `reason`.
Clients reject mismatched scope/profile echoes rather than reusing readiness
from another binding.
The three flags must be actual booleans and all true before new capacity is
launched. Repository access means a trusted runtime has verified access to the
source repository, not merely that the API token matches its scope. Managed
dispatch requires the canonical protected-task capabilities, including the
required authority and grants. A local dictionary, PID or HTTP health check
does not establish these capabilities.

The default runtime returns all flags false. A trusted adapter may report true
only after real preflight verification. ZPM must treat missing/unsupported
capabilities as blocked; no model calls or task effects belong in preflight.

### Typed readiness refusal

Both v1 and v2 capabilities may include this optional, closed `diagnostic`
object after authenticated scope/profile checks establish that a valid canonical
authority lacks the approved profile's `child_initial_outcome=1` capability:

```json
{
  "schema_version": 1,
  "producer": "openjules",
  "dimension": "canonical_authority",
  "code": "required_capability_unsupported",
  "requirement": {"name": "child_initial_outcome", "version": 1}
}
```

The object is bounded to 1 KiB of UTF-8 JSON. All keys and literals are closed;
versions are integers, never booleans. Its only valid readiness combination is
`profile_supported: true`, `repository_access: false`, `managed_dispatch: false`.
Positive responses and unclassified refusals omit `diagnostic` entirely, including
authority outages, malformed replies, wrong scope and unapproved profiles. The
producer never emits `diagnostic: null` or copies authority text into this object.
V2 still verifies and echoes the original destination binding; this addition
does not change its other fields or advertised feature support.

During producer-first rollout, the fixed legacy `reason` remains
`Canonical managed authority is unsupported: child_initial_outcome=1`. Updated
consumers classify the typed object without matching human wording. A negative
older response without a diagnostic is generically blocked; an otherwise valid
healthy older response keeps its existing readiness path. A present null,
malformed, oversized, unknown or contradictory diagnostic must block even an
otherwise positive response. Shared response examples are retained in
[`tests/fixtures/capability-diagnostic-v1.json`](../tests/fixtures/capability-diagnostic-v1.json).

This diagnostic is an observation. It grants no worker/task permission, changes
no target or deadline, and proves neither termination nor release. Existing
admission and capture/recovery rules remain authoritative.

### Worker snapshots

Ensure, observe, drain and stop return a worker snapshot:

```json
{
  "schema_version": 1,
  "deployment_id": "deployment-uuid",
  "repository": "github:github.com/owner/repository",
  "slot_id": "slot-0",
  "generation": 1,
  "launch_key": "stable-operation-key",
  "profile": "approved-profile-revision",
  "worker_id": "opaque-immutable-incarnation",
  "state": "ready",
  "reason": "",
  "termination_confirmed": false,
  "artifacts_captured": false,
  "admission_open": true,
  "active_executions": []
}
```

Discovery returns `{ "schema_version": 1, "workers": [...] }`. The runtime's
private process/container handle is not exposed as an authority-bearing API ID.
An immutable `worker_id` is distinct from a reusable logical slot and its
monotonically increasing generation. Approved profile identifiers must bind to
immutable runtime policy; changing a profile is a new specification/generation,
not permission to reinterpret an old launch.
Generation values are positive signed 64-bit integers; out-of-range input is
rejected before any launch or journal mutation.

Invalid input is 422, authentication failure is 401, unauthorized scope is 403,
an unknown scoped worker is 404, conflicting replay or admission is 409, and
unavailable managed runtime preflight is 503. Raw provider exception text is not
returned or stored. Adapter-supplied `reason` must contain only public diagnostics.

## HTTP version 2: destination identity

The optional [execution destination configuration](managed-service.md#optional-execution-destination-identity)
adds `/api/v2/workers` with `schema_version: 2`. It retains the same scoped bearer
authorization, durable worker semantics and canonical authority boundary.
Every operation requires an operator-approved expected destination binding:

```json
{
  "destination_id": "execution-host-a",
  "journal_incarnation": "11111111111111111111111111111111",
  "policy_binding_id": "22222222222222222222222222222222",
  "policy_binding_version": 1
}
```

The shown opaque values are examples, not enrollable identities. Initialization
generates the actual lowercase 32-hex-character UUID values. The destination ID
uses `[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. Versions in JSON must be integers, not
booleans or strings. GET query versions must be exactly `2` and `1`. Duplicate
or unknown query/body fields and ambiguous JSON are rejected. V2 POST bodies
are bounded to 65,536 bytes.

All GET requests include `schema_version`, `deployment_id`, `repository` and
the four binding fields above as flat query parameters. POST bodies include
`schema_version`, `deployment_id`, `repository` and a nested
`destination_binding` object containing those four fields.

| Operation | V2 route | Additional input |
| --- | --- | --- |
| Capabilities | `GET /api/v2/workers/capabilities` | Original `profile` query field. |
| Ensure | `POST /api/v2/workers/ensure` | `slot_id`, `generation`, original `launch_key`, `profile`. |
| Discover | `GET /api/v2/workers` | Original `profile`, optional original `launch_key`. |
| Observe | `GET /api/v2/workers/{worker_id}` | No additional query fields. |
| Drain | `POST /api/v2/workers/{worker_id}/drain` | Original `request_key`. |
| Stop | `POST /api/v2/workers/{worker_id}/stop` | Original `request_key`. |

Successful snapshots and capabilities use schema 2 and echo the full verified
nested `destination_binding`. Discovery also echoes that binding in its envelope,
including an empty result:

```json
{
  "schema_version": 2,
  "destination_binding": {
    "destination_id": "execution-host-a",
    "journal_incarnation": "11111111111111111111111111111111",
    "policy_binding_id": "22222222222222222222222222222222",
    "policy_binding_version": 1
  },
  "workers": []
}
```

The original full binding is committed with the worker and launch operation
before runtime I/O. Drain/stop operation payloads retain the same binding.
Discovery is restricted to the supplied original profile; a wrong destination,
journal incarnation or policy ID cannot become an apparently empty response.
Observe and control validate the expected scoped policy binding before worker
lookup, then compare it with the worker's retained original binding.

Authentication/scope checks precede identity lookup and effects. Malformed
input is 422, an identity or immutable replay conflict is 409, and missing or
inconsistent original state is 503. A scoped worker is 404 only after the expected
binding validates. These errors are not evidence that a previously uncertain
launch never happened. Keep its original reservation and reconcile the original
journal/key. There is no cross-destination retry, replacement-journal adoption
or remote enrollment fallback.

Identity-only capabilities advertise `identity_binding: 1`,
`portable_manifest: false` and `local_admission: false`; existing per-worker
drain and execution admission remain. Identity alone must not activate
multi-destination ZPM placement. The separately selected full contract below
does not reinterpret these IDs or upgrade old reservations.

| Configuration/state | Compatibility |
| --- | --- |
| Legacy configuration and unbound journals | Existing v1 routes and behavior remain available; v2 bindings are refused. |
| Initialized bound destination | Only v2 may create, discover, observe, drain or stop workers; v1 requests are 409. |
| Bound files with opt-in removed | Startup and current legacy component constructors refuse the bound state. |
| Existing populated v1 state | Destination initialization refuses migration; original v1 recovery remains available. |
| Existing identity-only destination | Full-mode initialization refuses upgrade, including an already initialized empty destination. |
| Missing member, changed incarnation or required format/feature | No recreation, silent downgrade or empty discovery; preserve uncertainty. |

### Full execution contract v1

Fresh [schema-2 service configuration](managed-service.md#full-execution-contract-and-local-admission)
adds a full mode to the v2 transport. Full capabilities report the exact integer
versions `identity_binding: 1`, `portable_manifest: 1` and `local_admission: 1`.
Qualification is conjunctive: the existing `managed_dispatch`,
`profile_supported` and `repository_access` flags must also be true, and the
following endpoint must return the exact approved manifest. Support flags do
not imply current readiness or admission.

`GET /api/v2/workers/execution-contract` requires the usual scope, binding and
profile query fields plus `contract_version=1`. Its closed response contains
`schema_version: 2`, `contract_version: 1`, `deployment_id`, `repository`,
`profile`, `destination_binding`, `manifest`, `execution_manifest_sha256` and
this separate current admission observation:

```json
{
  "version": 1,
  "revision": 2,
  "new_effects_open": true,
  "worker_ceiling": 2,
  "unreleased_workers": 0
}
```

For a new full ensure, add the following original qualification triple to the
existing body. The digest and revision shown here are illustrative:

```json
{
  "contract_version": 1,
  "execution_manifest_sha256": "sha256:1111111111111111111111111111111111111111111111111111111111111111",
  "admission_revision": 2
}
```

The version and revision are exact JSON integers, with revision from 1 through
9007199254740991. The triple is committed with the original binding, worker and
operation before external I/O. Full snapshots preserve every existing snapshot
field and add that triple plus `disposition`, normally null. Worker-ID observe,
drain and stop inputs remain unchanged and return the original snapshot mode.
They never substitute today's digest or revision.

| Discovery mode | Additional query fields | Exact envelope beyond `schema_version` and `destination_binding` |
| --- | --- | --- |
| Original identity | `profile`, optional `launch_key` | `workers` containing identity snapshots. |
| Original full key | `profile`, original `launch_key`, all three original qualification fields | The original triple and `workers` containing full snapshots. |
| Mixed inventory | `profile`, `contract_version=1`; no key, digest or admission revision | `contract_version: 1` and `workers` containing unchanged identity/full snapshots. |

An identity discovery that would encounter a full row conflicts; it cannot hide
the row or silently add fields. A full keyed empty result validates the original
binding and approved digest, without asserting today's revision or readiness.
Mixed inventory is a protocol compatibility envelope, not a migration command;
fresh full destinations do not adopt prior identity workers. Query revisions
use canonical positive decimal spelling. Partial triples, extra fields,
different original tuples and wrong modes are refused.

For a new valid full request, final admission compares revision, then open state,
then the unreleased-worker ceiling in one lifecycle transaction. A refusal
creates a permanent worker/operation tombstone with `state: "stopped"`,
`reason: "never_admitted"`, closed per-worker admission, no active executions,
and confirmed termination/capture. Its non-null disposition is exactly:

```json
{
  "version": 1,
  "kind": "never_admitted",
  "reason": "stale_admission_revision",
  "observed_admission_revision": 3
}
```

The other reasons are `closed` and `ceiling`, with the stated precedence. Exact
replay returns that same original tombstone after restart or reopening. A
generic error, failed readiness, empty discovery or unavailable journal is not
this receipt and cannot release an uncertain original reservation. Any prior
committed admission, even if its external call was never sent, disqualifies a
`never_admitted` receipt. Known original keys resolve retained history before
current image, manifest, admission or runtime qualification. Original admitted
work can finish and be captured after closure under its existing bounds.

The internal worker specification used by Docker, dispatcher and canonical
authority remains schema 1. V2 is an external lifecycle identity projection,
not a change to Polyphony's claim, grant or profile digest.

## Launch and retry guarantees

The service commits the immutable specification, worker identity and operation
key before calling the driver. SQLite transactions serialize concurrent requests
from API processes. The same key and specification returns the same worker;
changed input or operation kind conflicts. A different key cannot create another
incarnation in an unresolved slot.

Each worker has a host process lock covering runtime observation, command
dispatch and receipt application. It serializes calls across API processes and
is released by the kernel if a supervisor dies. A concurrent request does not
steal the lock on a timeout: it returns the existing reserved snapshot. The
client retries its original operation key. Control intent closes admission
before waiting for runtime access, so a blocked launch cannot race with a stop
receipt and release a slot prematurely. Older observations cannot overwrite a
newer runtime control receipt.

The journal distinguishes pending commands from commands with an accepted
receipt. A retry observes the same incarnation first. If no receipt resolves a
pending ensure, drain or stop, it resumes that command against the same worker
identity. This recovers a crash between intent commit and driver dispatch.
An already acknowledged command is observed, and a terminal incarnation is
never signalled again. Drain or stop intent suppresses later launch resumption.

**Driver requirement:** all commands must be durable and idempotent by worker
ID and immutable specification. A repeated ensure must reconcile the original
launch, never create a second process. Stop and drain must fence delayed or
concurrent creation, including a remote request that outlives its supervisor.
Every terminal receipt requires `launch_fenced=True`, meaning the backend has
permanently prevented that incarnation from being created or recreated. An
absence or `not_started=True` alone cannot establish this. After a cancelled
launch, the backend retains a tombstone for subsequent retries.

Host locks are concurrency control, not a substitute for those runtime
guarantees. The service does not claim exactly-once physical execution under
arbitrary runtime failures. It guarantees one durable reservation, retries with
the original identity, serialized receipt application, and retained uncertainty.
The trusted runtime must locate the exact worker and immutable runtime handle.
The journal binds a runtime handle to only one worker, including across
deployment and repository scopes, and retains that binding after termination.
Drivers must namespace handles across their supported backends. Reusing a handle
for another worker produces an unknown observation and cannot open admission.
If it cannot establish the outcome or launch fence, it returns `unknown`. A
deadline, absent heartbeat or remembered PID cannot establish process death.

## Admission, drain and capture

The trusted task adapter must first obtain canonical Polyphony permission, then
call `begin_execution` before a root or child launch. This local call records
runtime occupancy; it does not grant task permission or allocate task budget.
Repeated execution identities conflict rather than authorize another invocation.
The adapter reconciles the original canonical attempt instead of executing again.
Admission takes the runtime lock, refreshes readiness and records occupancy while
holding that lock. A concurrent runtime call makes admission temporarily conflict;
the adapter retries after reconciliation. It cannot launch using the cached
snapshot that observation endpoints may return during an in-flight call.

Drain records its closed admission state before invoking the driver. It races
atomically with `begin_execution`, preventing new roots or children after drain
has committed. Already admitted execution may finish within its original limits
or be cancelled through the trusted runtime. Drain remains effective after reopen.

The trusted adapter records each execution's termination and durable capture
through `record_execution_end`. A worker becomes terminal only when its runtime
identity is verified, termination, capture and the durable launch fence are
confirmed, and no owned root or child execution remains unresolved. A `stop`
response alone is insufficient.
Failed capture or mismatched runtime identity retains the slot reservation.
Stop retries observe and, when needed, resume the original pending operation.
They never signal a known terminal incarnation again. The lifecycle module
never deletes workspaces or artifacts.

## Verification and integration scope

Run:

```bash
python -m pytest tests/unit/test_worker_lifecycle.py tests/unit/test_worker_lifecycle_api.py
python -m pytest tests/unit/test_execution_destination.py tests/unit/test_execution_destination_api.py
python -m pytest tests/unit/test_full_execution_contract.py
```

Destination tests use real local SQLite/filesystem state and explicit fixture
runtime observations. They cover wrong-destination replay, lost replies,
partial initialization, whole-set readiness, member/table/index loss, current
legacy refusal and exact authenticated HTTP shapes. The real Docker test
`test_bound_destination_http_recovery_retains_one_real_runtime_and_capture`
adds actual lost-reply recovery, one container incarnation, Git change/capture
and terminal control under the original resource limits. Its full-mode variant
also binds actual inspected source/image approval, preserves the original
qualification after host closure and executes an admitted root after closure.
It reconstructs the
lifecycle and Docker driver from their original journals within the same test
process; its readiness callback is explicitly a fixture. Neither case alone
claims a fresh supervisor process, remote hosts, a live model provider,
canonical permission or joined ZPM installation qualification.

Full-contract component tests use fixture image/runtime observations, real
SQLite journals and actual dispatcher/child-supervisor paths. They cover
restricted encoding, policy projection, approval loss/reapproval, atomic ceiling
reservation, durable never-admitted replay, admitted-but-unsent uncertainty,
HTTP shapes and closure before/after local root and child admission. They do
not replace the real Docker gate or downstream compatible-version acceptance.

The tests cover concurrent ensure, lost launch/stop replies, recovery after
crash before dispatch, scope isolation, operation conflicts, uncertain launch,
incarnation mismatch, failed child capture, drain/admission races and denied
capability preflight. Two journal instances exercise blocked ensure versus stop
and stale observation versus control. A killed supervisor subprocess proves
that runtime locks are shared across processes and released on process death.
A real subprocess fixture starts a process, reopens its journal, drains it,
captures output and confirms termination. It is a lifecycle fixture, not a real
OpenJules agent or a proof of Docker confinement or Polyphony task coordination.

For managed execution and its integration checks, follow the
[managed service](managed-service.md) and [Docker runtime](managed-docker-runtime.md)
guides. Their implemented adapters do not change the unavailable default above.
ZPM owns [installation configuration and source pins](https://github.com/niklas-olsson/zero-point-modulator/blob/main/docs/single-host-installation.md)
and [joined acceptance](https://github.com/niklas-olsson/zero-point-modulator/issues/3).
Lifecycle fixture results alone do not qualify an installed revision set.
