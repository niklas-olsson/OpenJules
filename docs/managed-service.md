# Managed OpenJules service

The managed service connects ZPM worker capacity to Keystone Polyphony's
authenticated canonical task authority. It runs on a single trusted Linux host
with local Docker and persistent storage. It has its own entry point and never
falls back to the legacy in-memory Polyphony client or background executor.

```sh
python -m src.worker.managed_service --config /private/installation/config/openjules.json
```

Use ZPM's single-host installation package to generate the matching authority,
runtime and controller configuration. Run each application from its own checkout
and Python environment because OpenJules and Polyphony both use a `src` package.
The service listens only on loopback. Remote access requires a deliberately
configured HTTPS reverse proxy and the existing scoped bearer authentication.

## Optional execution destination identity

The first identity slice of [OpenJules #47](https://github.com/niklas-olsson/OpenJules/issues/47)
adds an operator-enrolled execution destination. Existing configurations remain
on the v1 lifecycle contract. This opt-in is an identity and recovery boundary;
it does not qualify distributed placement, publish a portable execution manifest,
or implement a host admission closure or capacity ceiling. ZPM owns placement
and installed qualification. Polyphony still owns canonical task authority.

For a fresh service, add this exact optional configuration object:

```json
"execution_destination": {"destination_id": "execution-host-a"}
```

The destination ID is an operator-selected identifier matching
`[A-Za-z0-9][A-Za-z0-9._-]{0,127}`. State paths must be absolute and canonical.
The state directory must be private to the service UID and otherwise empty;
the configured lifecycle database must not already exist. Initialization also
refuses retained optional model/child state when its feature is omitted from the
new configuration. It does not migrate existing v1 workers or journals.

With the service stopped, run:

```sh
python -m src.worker.managed_service --config /private/installation/config/openjules.json --initialize-destination
python -m src.worker.managed_service --config /private/installation/config/openjules.json --inspect-destination
```

Initialization creates no worker and contacts no Docker daemon, model provider or
canonical authority. It records one random journal incarnation, one random
policy binding ID for each approved scoped profile, and the exact original
journal membership. Inspection is read-only and cannot initialize or repair
state. Its output exposes the scoped IDs and whether application journals are
initialized, without private paths, full policy hashes or credential references.
An operator must transfer these expected values into the consumer's approved
configuration. A remote capabilities response is not enrollment and must never
overwrite an existing reservation's expected identity.

The fixed journal set consists of the configured lifecycle database,
`runtime/journal.sqlite3` and `dispatcher/dispatch.sqlite3` below the state
directory, plus `models/inference.sqlite3` and `children/children.sqlite3` when
those features are enabled. Cold-session and managed public ownership tables
remain inside the child journal. Dynamic public conversation journals retain
their existing separate instance, inode and policy checks; destination identity
does not replace those checks.
Whole-set verification also invokes the existing optional child-schema validator,
so loss of an enabled cold-session or public ownership table blocks readiness
and other members' effects immediately. Bootstrap does not pre-enable those
optional schemas.

Bootstrap first publishes complete member identity markers under a durable
initialization intent. Interrupted bootstrap can finish that same intent with
the same IDs. Effect-free application constructors then create their initial
tables and seal the original table/index definitions, including replay and
uniqueness constraints. Only after every enabled member is sealed does service
construction publish the set's durable `ready` transition. Normal lifecycle,
runtime, dispatcher, model and child connections require that transition and
validate the whole set before work. A partially constructed set cannot launch a
fixture or a real worker through a lifecycle-only object.

Subsequent opens require existing files, matching identities, the original
registry and the sealed application schema. Missing/replaced files, lost tables
or required indexes, changed identities, unsupported formats and unknown required
features fail closed. The SQLite application ID also prevents the current
implementation's legacy constructors from treating loss of only an identity
table as an unbound journal. No normal startup or initialization replay repairs
missing ready-state members. A future required feature must advance the
versioned format/feature floor; an earlier identity-aware binary will refuse
that state instead of silently omitting the new gate.

The opaque policy ID binds the existing complete private `DockerProfile`,
`ModelPolicy` and `ChildPolicy` fingerprints, including the optional public
discussion policy. These fingerprints include host-local paths and credential
reference names. They are not exported and are not portable-policy equivalence,
Polyphony's canonical `profile_digest`, a runtime principal, or task permission.
Different destinations have independently approved IDs. A policy change never
reuses an ID for new input or silently upgrades a retained worker or launch key.

Recovery validates the original binding. A changed current policy closes new
admission, while the original worker/key remains reserved. Actual runtime
recovery still needs its original host configuration and policy material.
Existing Docker/model constructors refuse changed policies under an old profile
name; hashes cannot reconstruct those policies. Retain or restore the original
configuration to recover, capture and fence those workers. This first slice has
no policy-rebinding, active-state migration or replacement-journal adoption
command. Missing original material remains unavailable or unknown, not an empty
destination from which a reservation may be released.

All state maintenance requires a stopped service. Concurrent clones, rollback,
shared/network-filesystem journals, and running a pre-identity OpenJules binary
against bound files are unsupported. The checks do not establish tamper-proof
row history or an atomic fence against a privileged administrator replacing
state between a committed SQL transaction and a runtime effect. Keep the
original journal set and supported service binary together.
An isolated probe of pre-identity commit `247fe1d4647510d158eb564594a406ef33fcafc8`
confirmed that its lifecycle implementation ignores these new markers and can
create an identity-less fixture worker when deliberately given bound files.
The application ID does not constrain code that predates its guard. Deployment
must stop old services and retain matching supported source, configuration and
journals; installed qualification must pin the actual supported revision.

The [v2 HTTP contract](worker-lifecycle.md#http-version-2-destination-identity)
requires the complete expected binding on every operation. A configured bound
service refuses all v1 access and creation; removing the opt-in configuration
does not make its stamped state legacy again. Legacy configurations with
unbound state retain their existing v1 behavior.

The supported entry point mounts only the authenticated worker lifecycle API.
Legacy GitHub/Radicle webhooks, PR-review event dispatch, dashboard task creation
and palette commands return HTTP 404 on this service. It does not import or start
the standalone legacy executor, poller or MCP server, or initialize an in-memory
Polyphony facade. Package exports still load the facade's class definitions.
The separate `openjules run` and `openjules mcp` commands remain trusted host
interfaces. `openjules serve` exposes only harmless health/static content; its
private and effectful operations are unavailable. The managed installation
context below refuses all these commands in the dedicated installed interpreter.
Use canonical managed entrypoints for protected work and an explicitly configured
separate standalone interpreter for trusted local legacy operation.

## Standalone ingress boundary

The first delivery of [#53](https://github.com/niklas-olsson/OpenJules/issues/53)
closes anonymous standalone admission. It does not implement an authenticated
positive adapter. `src.api.webhook:app` constructs only refusal routes and the
status page. Startup, imports and its lifespan do not construct an executor,
reviewer, dashboard store, cohort registry/provisioner, Docker or model client,
forge credential resolver, poller, background queue or WebSocket subscription.
The managed installation selector remains the existing separate refusal check.

Only `GET`/`HEAD` on `/`, `/health` and `/static/standalone.css` are public. The
page contains no script, forms, credentials or retained task data. It states
that work, comments and palette controls are unavailable. No action claims a
verification, commit, push or publication. `/health` reports process liveness
and the disabled ingress state; it is not execution readiness. The old dashboard
JavaScript and broad static directory are not served. Swagger/OpenAPI routes
are disabled.

### Complete standalone route inventory

The ASGI gate refuses every other HTTP request with a fixed HTTP 503 JSON reason
before reading the body, parsing event data or invoking any route. Exact legacy
routes also refuse when their routers are mounted separately. New private routes
cannot gain admission merely by being added to the app.

| Method/path | Private read or effect that remains unavailable |
| --- | --- |
| `POST /api/webhook` | GitHub issue/review dispatch, task records, forge/model/runtime effects |
| `POST /api/radicle/webhook` | Radicle dispatch and runtime/forge effects |
| `GET /api/tasks` | Retained task listing |
| `POST /api/tasks` | Task record creation and execution |
| `GET /api/tasks/{task_id}` | Private task detail |
| `GET /api/tasks/{task_id}/diff` | Retained code diff |
| `POST /api/tasks/{task_id}/comments` | Private task discussion and feedback dispatch |
| `POST /api/tasks/{task_id}/command` | Palette controls, including former verify/commit/push stubs |
| `GET /api/polyphony/state` | Private collaboration state |
| `GET /api/polyphony/cohorts` | Cohort listing |
| `POST /api/polyphony/cohorts` | Cohort creation and provisioning |
| `GET /api/polyphony/cohorts/{swarm_id}` | Cohort detail |
| `DELETE /api/polyphony/cohorts/{swarm_id}` | Worker drain and cohort removal |
| `POST /api/polyphony/cohorts/{swarm_id}/signal` | Resource-control signal dispatch |
| WebSocket `/ws/tasks/{task_id}` | Task subscription and observation |
| WebSocket `/api/polyphony/ws/{swarm_id}` | Cohort subscription and observation |

Both WebSockets close before accept with ASGI close code `1008`; the network
server may render that denied upgrade as an HTTP rejection. They never subscribe,
read private state or emit private events. There is no browser token collection.

### Policy and network configuration

`OPENJULES_INGRESS_POLICY` is classified once when constructing this disabled
app. An absent selector reports `standalone_ingress_unavailable`. An empty,
whitespace-only, over-4096-character or NUL-containing selector reports
`standalone_ingress_policy_invalid`. Every other value reports
`standalone_ingress_policy_unsupported`. No selected file is opened and no policy
content is interpreted or validated. HTTP refusals expose only the fixed reason;
health exposes `state: disabled`, the classification and that reason.

A nonempty value, an existing file, a valid GitHub HMAC, a bearer token, a proxy
header or a caller-supplied approval cannot enable any operation. There is no
HTTP compatibility switch. Positive policy, principal mapping, enrollment,
operation-specific receipts and recovery remain later #53 work; adding them
requires a separate reviewed contract. The pure signature helper rejects an
absent secret, but it is not an admission path in this delivery.

`openjules serve` defaults to literal `127.0.0.1` and accepts only that address or
literal `::1`. Hostnames and wildcard addresses are rejected before Uvicorn starts.
The Docker image still listens on `0.0.0.0:8000` **inside its container**. The
supported Compose file publishes only `127.0.0.1:8000:8000` on the host. Its sole
default service is the status app, with no credentials, source or execution-data
mounts, no execution environment and no privileged DinD dependency. `dind` now
requires the explicit `legacy-runtime` profile. Optional model, broker and Radicle
profiles remain operator-selected infrastructure; none enables HTTP admission.
This is a source/configuration boundary, not a qualification of public hosting or
an arbitrary reverse proxy.

### Upgrade, retained work and validation

Stop admission through the old standalone server before replacing it. Starting
this revision does not erase or migrate dashboard SQLite files, cohort records,
workspaces, Docker volumes or previously started workers. An old already-running
DinD container does not stop merely because its service has gained a profile.
Use the existing trusted host/runtime controls to reconcile retained work and
uncertain effects. Stopping or refusing the HTTP service is not proof that prior
execution completed, stopped or was captured; do not delete state to make the
new status service appear empty.

`openjules run`, the direct reviewer, poller, MCP and swarm CLI remain explicit
trusted host operations outside installed managed context. The host operator
must supply their runtime, model endpoint, forge credentials and state paths;
the status-only Compose service no longer provisions them. This preserves the
existing local execution contract without inventing a network grant.
Repository-qualified dashboard identity and durable legacy keys remain in the
explicit local `DashboardState` component. Its constructor requires an injected
store, and recording data says `recorded`, not that execution began. It is never
imported by the HTTP app.

`test_standalone_ingress.py` exercises the actual app and route inventory. Fresh
processes cover missing, invalid and unsupported policy selectors while sentinels
reject execution/private-storage imports, private reads, writes, background
queues, network connections and subprocess launches. Every private route and
both WebSockets refuse with zero effects while the harmless routes respond;
existing real SQLite bytes remain unchanged. Additional checks cover body-free
refusal, correctly signed fixture events, independently mounted routers, literal
CLI/Compose bindings and explicit trusted CLI dispatch. Managed-context tests
retain import/direct-method refusal and recheck an already constructed app.
These are ASGI/component and configuration checks, not live GitHub delivery,
provider inference, a Docker deployment or implemented positive admission.


## Managed installation context

A new supported ZPM bundle places one private selector at the fixed
`<sys.prefix>/openjules-managed-installation.json` path in its dedicated
OpenJules Python environment. Requests, environment variables, repository YAML
and model output cannot select another path or waive it. The selector is a
blanket refusal of legacy execution in that interpreter. It does not describe
task enrollment, grant execution permission or restrict canonical configuration
to a second repository/profile allowlist.

The selector is a regular non-symlink file with no group/other permissions,
at most 4096 UTF-8 bytes, containing exactly:

```json
{
  "schema_version": 1,
  "managed_config_path": "/private/installation/config/openjules.json",
  "managed_config_sha256": "<64 lowercase hexadecimal characters>"
}
```

The original configuration path must be absolute and canonical. Its actual
private regular-file bytes must match the digest and the existing 1,000,000-byte
configuration limit. Duplicate or extra fields, boolean versions, invalid
paths/digests, symlinks, unreadable state and changed original bytes fail closed.
A malformed marker also refuses legacy work. The reader opens nonblocking
before checking file type, so a FIFO cannot stall inspection while awaiting a
writer. Once a process observes managed context, removing the marker or changing
payload/environment hints cannot make that process standalone.

The actual managed-service command also enters managed process context from
its required host-selected configuration before service construction. Calling
the component `build_app` in an unmarked process does not select that global
mode. Explicit alternate host-supplied managed-service, publication and cleanup
configs remain supported through their existing private-file, scope, credential
and canonical checks. They still validate the original selector binding and
cannot use an alternate config to waive tampering. This allows separate valid
canonical service configurations without granting any legacy execution.

### Refusal and recovery behavior

| Operation/context | Result |
| --- | --- |
| Managed worker HTTP service, legacy webhook/UI routes | HTTP 404, as before. |
| Legacy run/serve/MCP/swarm command in the installed interpreter | Refused before loading its executor, provider or Docker dependencies; CLI exits 2 with `managed_installation_requires_canonical_ingress`. |
| Fresh standalone legacy app import in managed context | Refused before global storage, executor/reviewer or cohort provisioner construction. |
| Previously constructed standalone private route after managed context is observed | HTTP 409 with the same fixed reason before body parsing, HMAC, storage, queue or effects; WebSocket upgrade remains refused. |
| Direct or preconstructed executor/reviewer/MCP/poller/cohort/sandbox object | The shared refusal is rechecked before its effects. Injected dependencies do not waive it. |
| Separate standalone interpreter with no marker or explicit managed context | Trusted direct CLI/components remain available. Standalone HTTP/WS private operations remain unavailable even with supplied policy or credentials. |
| Legacy raw access to an actual managed-labeled container | Read-only ownership inspection is permitted; exec, file write, stop, removal and quarantine are refused. |

Raw legacy container operations require the exact immutable container ID and
inspect its actual Docker `Config.Labels["openjules.managed"] == "1"` creation
metadata. A mutable name/alias, missing ownership metadata or unavailable lookup
does not authorize a mutation. The guard and effect use the same resolved
immutable ID. Ownership inspection consumes the existing operation deadline.
A denied or unresolved inspection is outside execution-failure cleanup, so it
cannot accidentally stop or quarantine a managed worker. Once ordinary legacy
execution is admitted, its existing timeout, uncertain-result and
capture-before-deletion behavior remains in force.

ZPM publishes the complete selector atomically without replacing different
state, validates it, and runs this offline compatibility probe before recording
bootstrap completion:

```sh
<installed-openjules-python> -m src.worker.execution_context --probe-managed-installation
```

The command runs from the pinned OpenJules checkout with a credential-free
environment and a fixed local deadline. It accepts no config/path/mode override,
contacts no provider, Docker or authority, and exercises the actual refusal
predicate. Its successful exit-0 response has exactly three fields:

```json
{
  "schema_version": 1,
  "selector_sha256": "<SHA-256 of the actual selector bytes>",
  "legacy_execution_allowed": false
}
```

Invalid context returns a fixed error and exit 2. An older implementation that
lacks this helper cannot qualify merely because a new installer wrote a marker.
The installer independently checks the exact response and original raw-byte
digest. Repeated bootstrap validates before its completion fast path;
start/doctor validate read-only. An interrupted new bootstrap can resume only
with an absent or byte-identical expected selector. A completed bootstrap with
a missing or changed selector fails without silent repair or standalone
fallback. Pause, target zero, removal, re-enrollment and authority outage retain
this binding.

This initial contract applies to fresh paired source-pinned installations.
Existing pinned bundles are not silently upgraded or adopted. A trusted host
administrator deleting private state, selecting another interpreter, or running
arbitrary Python with Docker authority is outside this network/payload boundary.

The regression suite separates real private-file/fresh-process probe checks,
legacy app/direct-method fixtures, actual HTTP authority plus Docker-preflight
fixtures, and the opt-in actual Docker managed-label case. The latter preserves
a running idle managed worker through refused raw operations and then executes
its original approved command. It does not claim a live provider, live webhook,
new canonical authority or already-active managed task during the refusal.

Authority liveness is not managed readiness. Even when the configured authority
returns HTTP 200 from `/health`, an absent or unsupported managed protocol makes
`/api/workers/capabilities` report `managed_dispatch: false`; `/api/workers/ensure`
returns HTTP 503 without reserving or launching a worker. A previous successful
capability response does not permit later admission after capabilities change.

For an approved `initial-v1` child outcome profile, a valid scoped authority
response that omits `child_initial_outcome` reports the fixed readiness reason
`Canonical managed authority is unsupported: child_initial_outcome=1`. A positive
integer version other than 1 has the same diagnosis. Both also carry the
[typed readiness refusal](worker-lifecycle.md#typed-readiness-refusal), allowing
consumers to classify this case without parsing the human reason. The authority
must first pass
the existing schema, scope, root capability and child policy checks, including
trustworthy policy types. A timeout, HTTP error, wrong scope or malformed response
still reports `Canonical managed authority is unavailable`; arbitrary authority
text is never copied into the diagnostic. Both cases keep admission closed and
`ensure` returns 503. A later observation revalidates the authority rather than
reusing an earlier success. Profiles without the optional outcome protocol keep
their existing behavior. Positive and unclassified capability responses omit the
optional diagnostic field; they never serialize it as null.

## Legacy PR review boundary

The direct, host-invoked `PRReviewHandler` refuses
feedback whose branch ends in a slash followed by exactly 64 lowercase hexadecimal
characters, or whose supplied PR body or feedback contains
`<!-- openjules-publication:`. Every current managed publication policy appends
its operation digest to a slash-terminated prefix, so the branch check also covers
custom prefixes. A `/jules` mention cannot override refusal. The direct handler
raises `ReviewSourceRejected` with `managed_publication_requires_canonical_review`
before reading execution
configuration or credentials or invoking sandbox, model, commit or push operations.
Malformed direct source values raise `ReviewSourceRejected`; missing or null
optional PR bodies remain valid absent context.

The standalone HTTP gate now refuses **all** GitHub events with HTTP 503 before
signature checks or source parsing, including ordinary issues, general PR
conversation commands and review events. The historical event-specific 400/409
and ignored-event responses no longer describe that disabled interface. No
renamed branch, erased marker or correctly signed event restores HTTP admission.
Managed installations retain their earlier blanket legacy refusal and expose
no legacy review route on the canonical service.

Ordinary generated and ad hoc standalone branches remain eligible for the
explicit trusted direct handler. An ordinary branch with the same branch shape, or text quoting
the literal marker, is conservatively refused. These public signals only reject
legacy automation; their absence grants no canonical authority. A renamed branch
with erased provenance is outside this standalone branch/marker check. It does
not waive the managed-installation refusal above. In a separate unmarked
standalone interpreter, explicit legacy component initialization is unchanged.
Direct guard tests use fixture execution/forge clients and branch/marker values
produced by the actual publication component. They do not claim live GitHub
delivery or managed PR iteration.

This boundary does not implement authenticated canonical webhook enrollment.
The managed installation refuses legacy entrypoints. Managed draft
feedback continues to require the canonical task/review path. Issue acceptance
still requires the paired installer and runtime evidence for the delivered set.

## Ownership

ZPM owns repository enrollment and the desired number of workers. OpenJules owns
the container lifecycle and the delivery of canonical work to an admitted
worker. Polyphony owns task requirements, budgets, claims, artifacts, review and
acceptance. The dispatcher journal contains delivery intents and receipts; it is
not a second task ledger.

Each worker incarnation executes at most one root task. The whole container is
then stopped and its workspace captured before capacity can be released. ZPM can
replace that retired incarnation while preserving the operator's selected target.
An independently bounded watchdog inside the container limits execution even
when the trusted service dies. See [the runtime contract](managed-docker-runtime.md)
for confinement, source staging, capture and unresolved launch behavior.

## Installation configuration validation

The producer-owned `openjules-installation-v1` contract validates existing
configuration **schema 1** before credentials, destination state or runtime
construction. Schema 2 remains unsupported. The installed
[static artifact](../src/worker/contracts/openjules-installation-v1.json) describes
the closed input/result vocabulary, defaults, bounds and feature requirements;
the accompanying [conformance vectors](../src/worker/contracts/openjules-installation-v1-vectors.json)
cover root, model, child, initial-outcome, cold-clarification, managed-public and
destination-identity configurations. These are ordinary source data an installer
can inspect without executing OpenJules.

After deliberately bootstrapping an isolated supported Linux/Python interpreter,
run the native validator with the expected digest from the approved pinned
artifact:

```sh
python -B -m src.worker.installation_validation \
  --config /private/installation/config/openjules.json \
  --expected-contract openjules-installation-v1 \
  --expected-contract-digest APPROVED_STATIC_CONTRACT_SHA256
```

`-B` is part of this supported invocation: it prevents interpreter bytecode cache
writes during cold import. The command spawns no subprocess. It reads only its
explicit input files and installed static contract, beyond ordinary interpreter
and dependency code loading. It does not open `credentials_file`, resolve secret
environment references, inspect a checkout/image or public host binding, open or
create journals, construct runtime/authority/provider clients, bind sockets,
perform inference or execute repository code. Docker profile definitions and
shared authority errors have pure import homes; their former component imports
continue to re-export the same classes. This avoids the Docker SDK's dependency
import probing local socket support before policy validation.

### Input and private receipt

Configuration is at most **1,000,000 bytes**, the existing decimal loader limit.
This is below 1 MiB, which is 1,048,576 bytes. The command and startup use this same
cap and strict UTF-8 decoding. Digests bind the exact original bytes, including
whitespace, with no Unicode or JSON normalization. The static contract digest is
SHA-256 of the exact committed UTF-8 artifact bytes, including its final newline.

Optional `--scope-declarations /private/installation/scopes.json` supplies a
token-free structural comparison:

```json
{
  "schema_version": 1,
  "scopes": [
    {"deployment_id": "my-installation", "repository": "github:github.com/example/project"}
  ]
}
```

The scope document has only those fields, at most 65,536 bytes and 256 distinct
scope pairs, and rejects duplicate JSON fields. Every selected profile scope
must occur in the supplied list. Omitting it skips that structural comparison.
The declaration cannot grant authority or prove compatibility with actual worker
credentials. Its count bound applies only to this validation input; actual
credential-scope authority is unchanged.

The deterministic JSON result has exactly ten top-level fields:

| Fields | Meaning |
| --- | --- |
| `schema_version`, `service`, `validation_contract` | Exact receipt version `1`, service `openjules`, contract `openjules-installation-v1` |
| `contract_digest` | Actual installed static contract bytes, including when the caller's expected ID/digest mismatches |
| `configuration_sha256`, `scope_declarations_sha256` | Exact acquired input bytes; null only for omitted scopes or unreadable/oversized input whose complete bounded bytes were not acquired |
| `valid`, `errors` | Boolean static validity and at most one fixed `{code,path}` failure |
| `descriptor` | Complete bounded projection when valid; null on every failure |
| `host_checks_required` | The exact unresolved host-check list published by the static artifact |

Error paths are JSON pointers into a conceptual envelope containing decoded
`configuration`, decoded `scope_declarations`, `expected_contract` and
`expected_contract_digest`. They use known field names and generated indexes.
Errors never include supplied values, private filesystem paths, native exception
text or extracted credentials. An oversized file is never represented by a hash
of its read prefix. A missing or unrecognized installed contract produces no
receipt: the command exits `2` with fixed `installation_contract_unavailable` on
stderr. Malformed command-line arguments also produce no receipt and exit `2`,
with only `installation_arguments_invalid` on stderr. Argument names and values
are never echoed in that diagnostic. `--help` retains its normal help text and
exit status `0`. After successful argument parsing, the command otherwise exits
`0` for valid input or `2` for refusal and emits one ASCII JSON line, at most
8,000,000 bytes including newline.

The descriptor contains configuration schema, selected destination identity
version and sorted scoped profiles. Each profile exposes its name, immutable
base/image, selected model/child/session/public feature versions and required peer
contracts/capabilities. It omits host paths, credential references, private
instructions and policy fingerprints. Public profiles additionally require the
existing `polyphony-public-conversation` profile-v1 service. Canonical child policy
equality and live availability still require their existing host checks.

Keep input and receipt in the host-private installation record. ZPM independently
verifies the pinned producer source/build and binds its receipt to the exact
sealed configuration, optional declarations and static artifact. The receipt
does not self-attest its source revision. Changed bytes, contract or producer
source invalidate consumer composition evidence. This producer delivery does
not activate ZPM's native preflight: [ZPM #56](https://github.com/niklas-olsson/zero-point-modulator/issues/56)
also requires the independently delivered [Polyphony #139](https://github.com/niklas-olsson/keystone-polyphony/issues/139)
validator at exact supported pins. Offline preparation continues to read sibling
source data without running it.

### Startup, compatibility and evidence

`load_configuration` now completes the pure Docker/model/child/public policy,
authority-reference and dispatcher-bound checks before opening worker credentials.
`build_app` repeats that same preparation for direct callers before installed
context checks, destination loading or broker/runtime construction. The managed
command still irreversibly selects its process-wide legacy refusal even when
configuration is invalid; its actual installed-selector host reads occur after
the pure phase. Valid startup retains actual credential scope, filesystem,
destination journal, public executable/scope-key, model transport, Docker/source,
live authority and per-attempt permission checks. Provider qualification remains
separate. Static validity cannot start work, make an installation ready, release
uncertain capacity or authorize publication.

Successful schema-1 bytes retain existing native policy normalization and
fingerprints, including omitted optional fields. Ordinary duplicate JSON fields
retain the previous last-value behavior; the existing destination/public opt-ins
continue to reject any duplicate. Fixed root-helper/socket grammar remains
specific to managed-public profiles. Ordinary model/child profiles retain
operator-approved arbitrary root argv. The direct `build_app` dictionary must now
contain the complete schema-1 configuration, including `credentials_file`, even
when the host passes already loaded credentials; that method does not read the
path again. Invalid policy now raises the fixed `ConfigurationInvalid` code
before creating a model journal, instead of discovering that error afterward.

The shared vectors retain native fingerprint goldens from source
`0dd5bf4e42b3677c3f2f564655bc87a97c4bf973`. Tests run the actual validator and
managed-service CLI under cold-import sentinels, refuse secret/host inspection,
state writes, SQLite, subprocesses, threads and sockets, and verify zero effects
for valid validation and invalid startup. Existing model/child/public/destination
tests still exercise later host checks, journal ownership and recovery. These
are producer/component checks, with no claim of live inference, an installed
paired deployment or completed consumer activation.

## Configuration

The version 1 service object requires `state_directory`, `lifecycle_database`,
`credentials_file`, `authority` and `profiles`. Paths are absolute local paths.
The authority object contains an HTTPS or loopback HTTP service root and an
environment-variable `token_ref`. Profiles are operator-approved immutable
Docker configurations, including an exact source commit and command argv.

The private credential file has this shape; replace the placeholder through the
installation tool or another secret-provisioning mechanism:

```json
{
  "DEDICATED_RANDOM_ZPM_CREDENTIAL_AT_LEAST_32_CHARACTERS": [
    {"deployment_id": "my-installation", "repository": "github:github.com/example/project"}
  ]
}
```

The credential file must have mode `0600`. It authorizes the exact deployment
and repository pair. The Polyphony runtime credential is separate and never
enters a task container. Provider error bodies, credentials and repository
output are not copied into dispatcher diagnostics.

Optional configuration includes `host` (loopback only), `port` (default 8000),
`poll_interval_seconds` (default 1) and `max_parallel` (default 16). The last value
bounds concurrent dispatcher threads, including active commands; size it for the
approved host capacity. Each task also has the smaller of its canonical attempt
allocation and approved runtime limit. A fixed monotonic cutoff covers network,
admission and runtime preparation time; retries cannot extend it.

## Recovery

Optional `models` entries enable the [managed coding agent](managed-model-broker.md)
for explicitly matched profiles. The service keeps provider credentials on the
host and adds only that worker's authenticated read-only socket mount. Model
requests require the original admitted canonical binding and its current
permission. Profiles without this configuration remain command-only.

Optional `children` entries enable [bounded child agents](managed-children.md)
for approved model profiles. They require a matching canonical child policy and
a new immutable runtime profile. The root and children share one worker and one
model allowance. Final child capture and terminal receipts precede root release.

The dispatcher persists an immutable claim request before contacting Polyphony.
A lost reply retains that same request identity. A generic conflict or transport
failure is not evidence that no attempt was allocated. Only the authority's
explicit `claim_not_allocated` response permits choosing a different task.
Duplicate claims recover their original binding even if the approved profile
has changed or been removed; revoked permission permits cleanup, never a new
launch.

Canonical authorization and local lifecycle admission are both required before
repository code runs. Docker receives the original immutable execution identity.
Its durable intent and tombstones prevent replay after a lost response. Unknown
execution, uncertain Docker start and failed capture retain reservations.

A drain or stop response can acknowledge durable intent while another runtime
operation still holds the worker lock. Local admission closes immediately. A
`draining` snapshot does not by itself prove that the runtime or canonical child
authority received the closure. The snapshot reason identifies control intents
that still await runtime confirmation.

The trusted dispatcher reconciles at most one incomplete control per worker in
each pass, reusing the original scoped request key and immutable payload. It
does this even when all execution slots are occupied. An explicit stop takes
priority over pending drains. Confirmed terminal evidence completes an intent
without signaling the runtime again; uncertain delivery remains durable across
restart. Drain preserves existing root and child grants while closing new
admission. Ordinary observation and discovery remain read-only.

After termination, the dispatcher delivers immutable patch, log and manifest
content to Polyphony and verifies the returned content hashes. Only a complete
terminal receipt allows the local execution reference to clear. A successful
command with a nonempty patch may create a candidate for independent review;
that action does not accept the task or authorize a GitHub merge. Stale work is
preserved even when a requirements revision prevents a current candidate.

Confirmed dead idle containers are retired and captured by a separate trusted
daemon recovery operation. Ordinary observation remains read-only. Missing
containers, inaccessible Docker and unconfirmed start intents remain unknown.

## Current supported scope

This release provides an authenticated, recoverable **root execution** path,
with an optional host-owned model broker and opt-in depth-one child execution.
Children use distinct UIDs and canonical grants; a child deadline or cancellation
retires its whole worker. Existing root-only profiles remain unchanged.
The Docker network remains disabled; model traffic goes through the configured
broker. Deterministic model and code-change trials prove transport, execution
and capture, including the separately enabled child Docker qualification. They
do not prove live-provider behavior, model quality, independent review or forge
publication.

Durable archives, stopped containers and volumes are retained by default. An
[explicit host cleanup command](managed-docker-runtime.md#explicit-host-cleanup)
can remove one qualified, fully captured executed worker's owned container and
volume while the service is stopped. Its original archives, journals and launch
tombstones remain. Idle, legacy, uncertain-create and incomplete-capture workers
stay retained. There is no automatic garbage collection or per-volume disk quota;
host storage remains an operational limit. Do not delete recovery evidence to
make an unknown reservation appear terminated.

## Admission qualification

`tests/integration/test_managed_service_admission.py` exercises the actual managed
app, dispatcher, canonical HTTP client, source snapshot and durable journals.
A real loopback HTTP fixture stays health-positive while its managed endpoint
is absent or advertises an incompatible protocol. The test verifies repeated
admission rejection, fresh capability revalidation, disabled legacy HTTP routes
and zero worker, execution or dispatch records. A fresh Python process also
checks that app construction imports no legacy execution entry point and
initializes neither its in-memory facade, Docker nor a model provider.

Docker image/daemon preflight uses an explicit driver fixture. This is admission
and service-composition evidence, not an actual Docker trial or a live authority,
provider or forge outcome. The existing installed three-service trials remain
the interoperability gate. The command-only profile used here configures no
model broker or children.
