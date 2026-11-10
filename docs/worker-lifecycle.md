# Worker lifecycle contract for ZPM

This is the first implementation slice of [OpenJules #3](https://github.com/niklas-olsson/OpenJules/issues/3).
It provides a durable capacity journal, runtime adapter interface, local admission
barrier and authenticated HTTP contract. It does not yet provide a production
Polyphony coding worker. The default adapter reports unavailable and rejects
launches. The existing `BackgroundTasks` executor is not a managed fallback.

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

## Verification and remaining integration

Run:

```bash
python -m pytest tests/unit/test_worker_lifecycle.py tests/unit/test_worker_lifecycle_api.py
```

The tests cover concurrent ensure, lost launch/stop replies, recovery after
crash before dispatch, scope isolation, operation conflicts, uncertain launch,
incarnation mismatch, failed child capture, drain/admission races and denied
capability preflight. Two journal instances exercise blocked ensure versus stop
and stale observation versus control. A killed supervisor subprocess proves
that runtime locks are shared across processes and released on process death.
A real subprocess fixture starts a process, reopens its journal, drains it,
captures output and confirms termination. It is a lifecycle fixture, not a real
OpenJules agent or a proof of Docker confinement or Polyphony task coordination.

Production completion still requires the real adapter from
[OpenJules #2](https://github.com/niklas-olsson/OpenJules/issues/2), runtime
enforcement from [#4](https://github.com/niklas-olsson/OpenJules/issues/4), wiring
every managed execution ingress through both authority and local admission, and
the [ZPM installation trial](https://github.com/niklas-olsson/zero-point-modulator/issues/3).
The default fail-closed behavior is intentional until those capabilities exist.
