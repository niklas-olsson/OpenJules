# Isolated coding agents and model inference

`src/agent/managed_runner.py` is a stdlib coding agent intended to run **inside**
one OpenJules managed container. It performs bounded file operations and
commands, and requests model completions from `src/worker/model_broker.py` on the
trusted host. The container retains `network_mode=none` and receives no model
provider, Polyphony or ZPM credentials.

The managed service wires this boundary when an operator explicitly configures
a `models` entry for an approved runtime profile. Its runtime and dispatcher
perform the mounting, binding, restoration and revocation described below.
Profiles without a model policy retain the ordinary root-command path. Unit
tests do not prove that Docker mounted the intended socket or that a live
provider is qualified.

## Service configuration

Add this optional list to the managed OpenJules service configuration. The scope
must exactly match an existing approved Docker profile, whose immutable image
contains the runner and whose command invokes it as shown below:

```json
{
  "models": [
    {
      "deployment_id": "my-installation",
      "repository": "github:github.com/example/project",
      "profile": "agent-v1",
      "policy": {
        "endpoint": "https://provider.example/v1/chat/completions",
        "model": "operator-approved-model",
        "token_ref": "env:OPENJULES_MODEL_TOKEN",
        "max_calls": 25,
        "max_output_tokens": 2048,
        "max_total_output_tokens": 32768,
        "request_timeout_seconds": 30
      }
    }
  ]
}
```

The endpoint and model above are examples requiring operator replacement. Supply
the referenced credential only to the trusted OpenJules service environment.
Model-backed profiles reject all guest `environment_refs`; provider credentials
cannot also be injected into repository execution. The Docker ownership labels
include the immutable model-policy fingerprint. Unknown scopes, duplicate model
policies and changed policies under an existing name are rejected.

Readiness requires the configured credential and actual local socket transport.
It makes no inference call and does not assert that a remote provider accepted
the configuration. On restart, only unresolved owned worker records with matching
persisted model bindings regain listeners. A missing model journal for a worker
whose creation was dispatched blocks recovery instead of resetting its budget.

## Host-owned policy

Create one immutable `ModelPolicy` for each exact deployment, repository and
runtime profile. For example:

```python
policy = ModelPolicy(
    endpoint="https://provider.example/v1/chat/completions",
    model="operator-approved-model",
    token_ref="env:OPENJULES_MODEL_TOKEN",
    max_calls=25,
    max_output_tokens=2048,
    max_total_output_tokens=32768,
    request_timeout_seconds=30,
)
```

The endpoint is a complete HTTPS chat-completions URL. Loopback HTTP is supported
for local inference and fixtures. URL credentials and redirects are rejected;
proxy environment inheritance is disabled. The provider must support the
configured chat-completions and function-tool schema. `token_parameter` selects
either `max_tokens` or `max_completion_tokens`, according to that provider.
There is no implicit provider or model selection and no fallback inference path.

The broker persists a fingerprint of the model policy and expected peer UID.
Changing a model, endpoint, limits or UID requires a new runtime profile name,
including before any worker has been created. Rotating the value behind an
existing credential reference does not rewrite previous request identities.

The guest can submit only `schema_version`, `request_id` and `messages`. It
cannot choose the provider, model, credentials, token allowance, worker, attempt
or repository. The broker supplies its fixed tool definitions.

## Runtime integration contract

Construct one broker under a private local state directory:

```python
scope = (deployment_id, repository, profile)
broker = ModelBroker(
    state_directory,
    {scope: policy},
    permission=canonical_permission,
    peer_uids={scope: approved_runtime_profile.uid},
)
```

The default peer UID is `65532`; pass the approved runtime UID explicitly when
it differs. The callback receives `ModelBinding(worker_id, attempt_id, spec)`.
It must call the authenticated canonical Polyphony permission endpoint, verify
the returned worker, attempt, deployment, repository and profile against that
binding, and return remaining seconds only when `launch_allowed` is true. Raise
or return zero otherwise. Give that callback a bounded transport timeout. The
broker deducts callback elapsed time and clamps permission to its original
monotonic deadline.

The trusted runtime must perform these operations:

1. Before container creation, call `prepare_worker(worker_id, spec)`. Bind only
   the returned worker directory read-only at `/run/openjules-model`.
2. The constructor does not recreate historical listeners. During recovery,
   pass the runtime's exact approved nonterminal workers to
   `restore_workers({worker_id: spec})`. It accepts only existing, unrevoked,
   unchanged bindings and returns their directories. Mounting the directory
   allows its socket file to be rebound after service restart; mounting an
   individual socket inode would keep the stale listener.
3. After canonical claim and lifecycle admission, call
   `bind_attempt(worker_id, spec, attempt_id, remaining_seconds,
   deadline_monotonic=original_cutoff)` before starting the approved agent
   command. Capture `original_cutoff` when permission is sampled. The broker
   also captures its entry time before socket setup or database waits and takes
   the earliest of those cutoffs and its persisted prior deadline. Binding
   inference does not authorize execution.
4. Keep the runtime's independent watchdog active under its distinct trusted
   UID. The broker cannot supervise or confirm process-tree termination.
5. When the attempt is cancelled or retired, call
   `revoke_attempt(worker_id, attempt_id)`. Call `close()` at service shutdown.

Call `check_ready()` before advertising this profile as available and before
provisioning. It performs an actual private Unix-socket bind/listen probe and
raises `BrokerDenied("model_transport_unavailable")` if the transport is blocked
or an expected running listener has died. Restore the known live workers first;
this check cannot infer that set from historical journal rows. It proves local
transport availability, not canonical permission, provider reachability or the
quality of a model's output.

The state directory is mode `0700`. Each mounted worker directory is mode
`0711`, with a mode `0666` socket. The private parent is never mounted. The guest
can connect to its socket but cannot alter the read-only mount or reach sibling
endpoints through it. Linux `SO_PEERCRED` must report the configured task UID;
the request body cannot select or impersonate that identity. The watchdog UID
does not receive this inference identity.

The initial supported topology is a local Linux host with **rootful Docker**,
local SQLite, procfs and Unix sockets. User-namespace remapping and rootless
Docker require separately qualified UID mappings. A mismatch fails closed;
do not disable the credential check to work around it. Host users with access to
the private state and the Docker daemon remain trusted.

Each model, child-model, child-outcome and root-control endpoint has two fixed
threads: an acceptor and one serialized request handler. The acceptor compares
the kernel peer UID with the immutable endpoint binding before reading a body
or queueing work. It can return the fixed `not_authorized` frame while an
authorized handler is waiting for a provider or control operation. The handler
still performs its existing live identity, canonical permission and budget
checks. Root and child inference retain the same shared per-worker effect gate.

Each endpoint admits at most one active handler and four queued authorized
connections, plus one connection undergoing acceptance or UID rejection.
Thus at most six accepted user-space sockets are owned per endpoint; the
configured kernel listen backlog remains four. Frame reads and response writes
retain their existing five-second bounds. Saturation closes the unadmitted
connection before body parsing or effects. That closure is not a success or a
safe automatic-retry receipt. This is bounded responsiveness under an active
authorized call, not an availability guarantee against connection floods.

Stop and queue-to-active admission share one fence. Stop closes queued sockets
without running their handlers. The already-active handler remains owned, and
the endpoint owner thread does not exit or relinquish its socket path and
directory until that handler ends. Foreground broker shutdown keeps its existing
bounded join; if work remains, the existing deferred release retains the service
lock or child-journal release callback. A new service cannot take ownership
while the old handler can still mutate state. An unexpected handler failure
also stops its acceptor and remains a readiness failure, distinct from an
intentional endpoint revocation.

Endpoint creation remains a trusted runtime operation tied to worker capacity.
Guest requests cannot allocate listeners or additional host threads. Verify
Unix socket availability before advertising this execution profile as ready.

## Durable inference limits and recovery

Before contacting the provider, the broker commits the request identity, input
hash and reserved output-token allowance. An exact completed retry returns the
cached response without another provider call. Changed content under the same
identity conflicts.

A crash, timeout, lost response or incomplete provider reply leaves an uncertain
request. That request is never automatically repeated, including after restart.
Further inference for the same attempt is blocked while it remains uncertain.
The agent stops and the runtime preserves partial work. A later deliberate
canonical attempt has its own identity and approved budget.

Failed and uncertain calls retain their reservations. Completed calls also
retain the full reserved allowance; reported token usage does not refund it.
The final call may receive fewer output tokens when the remaining total is
smaller than the per-call cap. Calls are rejected once either limit is reached.

These are **call and reserved output-token limits, not a financial cost
guarantee**. Input-token billing, reasoning-token behavior, provider prices and
processing after client disconnection remain provider-specific. Limits across
different workers or tasks require separate operator policy.

Deadlines use `time.monotonic()` and the Linux boot identity. Rebinding can
shorten but never extend a deadline. A different host boot invalidates the grant.
Current canonical permission is required before inference, before delivering a
newly generated response and for cached response access. An authority outage
does not authorize local fallback. Revocation does not claim that an already
dispatched provider request stopped processing.

## Image and agent command

### Finite operator-local distribution

`tools/managed_image.py` separates acquisition from a sealed build of this
production recipe. Its initial environment is rootful Linux/amd64 with Python
3.11 or 3.12, Git, Docker CLI and `dockerd` already installed. The tool creates
owned temporary Docker data roots with the `vfs` driver. It never contacts an
ambient Docker context, loads a task, contacts Polyphony or supplies a provider
credential. Rootless Docker, remapped UIDs and other platforms are unsupported.

First acquire one immutable Python platform manifest and one Debian snapshot.
Use full Git commits for the five agent helpers and the separately versioned
production Dockerfile. The acquisition contains the original base config and
compressed layers, signed snapshot metadata, exact selected package bytes and
source hashes. The offline apt solver verifies every snapshot with the original
base's Debian archive keyring; the manifest retains that keyring identity and
signature results. Acquisition does not build an agent image.

```sh
sudo python3 tools/managed_image.py acquire \
  --base-manifest sha256:APPROVED_PLATFORM_MANIFEST \
  --snapshot APPROVED_UTC_SNAPSHOT \
  --source-commit APPROVED_HELPER_COMMIT \
  --recipe-commit APPROVED_RECIPE_COMMIT \
  --output /var/tmp/openjules-image-inputs
```

The uppercase arguments are explicit operator choices, not runnable identifiers.
Review the resulting `inputs.json` and retain its SHA-256. A build accepts that
exact document and hash, reacquires only the declared bytes, verifies their
signed and content-addressed parents, and passes only the recipe, five helpers
and selected packages to Docker. Its rootful test interpreter must already have
the repository's test dependencies installed. The build disables networking,
uses the imported immutable base config ID, and uses only local packages.

```sh
sudo python3 tools/managed_image.py build \
  --approved-inputs /var/tmp/openjules-image-inputs/inputs.json \
  --approved-inputs-sha256 sha256:APPROVED_INPUT_DOCUMENT_HASH \
  --output /var/tmp/openjules-image-output
```

The command exports `managed-agent.docker.tar`, checks every ordered uncompressed
layer against the config, then copies and imports that archive into an empty
owned daemon. Existing managed-agent, model-runtime and child-runtime tests use
the exact imported image ID. These trials use deterministic HTTP model and
canonical-authority fixtures. They do not qualify live model quality, a browser
host, multi-host operation or an installed ZPM deployment. `artifact.json`
retains the image/config identity, archive byte size and SHA-256, layer identities,
source/recipe revisions, test revision and observed costs. No registry manifest
digest is invented from an image ID or archive hash. Rebuilding requires its own
output identities and native qualification; identical rebuild bytes are not promised.

The first-candidate limits are 2 GiB of reserved acquisition/verification-transfer
bytes, a 1 GiB archive, 8 GiB of observed work/daemon storage and 30 minutes per
invocation. Every input size is reserved before its download; failed transfers
remain charged. Public registry authorization and HTTP overhead have separate
bounded reservations. All owned daemon data, context, caches and archive copies
are measured. Storage is sampled during operations and excess stops the
candidate; this is not a filesystem quota. Already installed host tools and test
dependencies are prerequisites, not measured downloads. Resource reports state
that boundary explicitly. The separate acquisition and build reports are not
one combined 30-minute or 2-GiB claim.

After explicitly approving `artifact.json`, transfer that record and exact archive
to another supported host. Verify before using the ordinary image load command:

```sh
python3 tools/managed_image.py verify \
  --archive managed-agent.docker.tar --record artifact.json \
  --record-sha256 sha256:APPROVED_ARTIFACT_RECORD_HASH
docker image load --input managed-agent.docker.tar
docker image inspect sha256:APPROVED_IMAGE_CONFIG_ID
```

Approve the record's origin separately. A hash supplied by an untrusted sender
does not establish permission or provenance. Wrong bytes, platform, config or
layer identities refuse before image import. ZPM continues to receive an already
loaded immutable image ID through its existing contract.

The source declares MIT in `pyproject.toml`, but accompanying source permission
text and distribution notices remain pending under OpenJules #49. The tool has
no binary upload, registry push or release operation. CI retains text metadata
only. Public binary publication requires the recorded applicable source and
base/package notices first. Keep old approved manifests and artifact records
immutable; security updates use a new acquisition, review, build and qualification.
An operator can withdraw an old identity from future installation approval without
rewriting its historical evidence.

### Ordinary operator-built image

Build from an approved base and retain the resulting immutable image ID:

```sh
docker build -f docker/Dockerfile.managed-agent \
  --build-arg PYTHON_BASE='python@sha256:YOUR_APPROVED_BASE_DIGEST' \
  -t openjules-managed-agent:local .
docker image inspect --format '{{.Id}}' openjules-managed-agent:local
```

The base digest above is a placeholder. The Dockerfile compiles the interpreter's
immutable standard library during the build, using checked source hashes and
normal optimization. This lets repeated Python helpers reuse validated bytecode
when the container root is read-only. The build fails if compilation fails;
`site-packages` and `dist-packages` are excluded. Cache files remain root-owned
and readable by the task UID. The image retains `PYTHONDONTWRITEBYTECODE=1`;
the read-only root also protects the standard library for isolated commands.

The managed agent modules are copied as source after that build step, preserving
their source-loading path. Install repository test dependencies in the approved
image beforehand: task execution has no general networking and a read-only
container root. The produced image must be approved and referred to by immutable
ID or digest; a mutable build tag is not a runtime identity.

Use an operator-owned command such as:

```json
[
  "python3", "-I", "-S", "/opt/openjules/managed_runner.py",
  "--socket", "/run/openjules-model/model.sock",
  "--max-turns", "25",
  "--verify-json", "[\"python3\",\"-m\",\"unittest\",\"discover\"]"
]
```

Requirements arrive on stdin. The runner reads root `AGENTS.md` and instructs
the model to inspect applicable nested rules. Its tools are bounded file read,
text write, file listing, command argv and finish. Commands execute only inside
the container. Path checks are convenience guards; Docker provides the actual
isolation boundary. A command returning does not prove all descendants stopped.
The final whole-container retirement receipt supplies that fact.

Finish optionally runs the configured verification argv. Its output is captured
evidence, not independent review, task acceptance or publication. Exhausted
turns, failed verification and uncertain model outcomes return nonzero exit
codes. Partial work remains available for capture.

## Qualification

The logic tests use real localhost HTTP, SQLite persistence, file changes and
subprocess verification. Their clearly labelled listener fixture permits this
subset to run where Unix sockets are blocked:

```sh
python -m pytest tests/unit/test_managed_agent.py
```

The separate socket tests are mandatory in the normal suite. They exercise real
Unix sockets, framing, HTTP and the agent loop. A blocked socket is a failure,
not a skip:

```sh
python -m pytest tests/unit/test_managed_model_socket.py
```

The bounded concurrency tests additionally check queue saturation, serialized
outcome handling, queued-request discard, incomplete frames, startup failures,
unexpected handler death and retained service ownership during active HTTP:

```sh
python -m pytest tests/unit/test_managed_socket_concurrency.py
```

The real Docker responsiveness regression holds an authenticated provider call
and its original SQLite reservation, then requires a different actual UID to
receive denial from that same socket before the provider reply is released.
It checks that provider requests, reservations and permission checks do not
increase. The provider and canonical permission callback are named fixtures;
this is not live provider or Polyphony qualification.

```sh
OPENJULES_MANAGED_DOCKER_TESTS=1 \
  python -m pytest tests/integration/test_managed_socket_responsiveness.py
```

The real Docker test exercises the agent image and its read-only socket mount,
with network access disabled and no provider/authority credentials in the guest:

```sh
OPENJULES_MANAGED_DOCKER_TESTS=1 \
  python -m pytest tests/integration/test_managed_agent_container.py
```

It also starts a fresh isolated interpreter as the task UID, rejects any source
compilation fallback, and imports representative standard-library modules from
their checked-hash caches. This proves cache use under the existing confinement;
it sets no timing threshold and makes no claim about a downstream suite's runtime.

Once explicitly enabled, unavailable Docker is a test failure. The test builds
a minimal test image, or accepts an exact `OPENJULES_MANAGED_AGENT_IMAGE_ID`.
Its default mutable Python base is only a fixture build input. Production image
approval and pinning are separate.

All model replies in these tests are deterministic fixtures. None spends on live
inference or proves the quality of a real model. Production qualification also
requires the actual scoped authority callback, integrated runtime hooks,
configured provider behavior and a real coding task.

## Remaining boundaries

The completion protocol cannot create child identities or delegated budgets.
Opt-in [bounded child execution](managed-children.md) adds a separate root-only
control socket, canonical grants, distinct kernel-checked child UIDs and a final
capture barrier. Every child completion uses the same root allowance. A
child-supplied identifier in a completion request does not select its identity.

The broker does not address the Docker runtime's separate disk quota, retained
container/volume cleanup or ambiguous initial-start recovery limitations. It
cannot turn guest-generated test output into independent review evidence.
