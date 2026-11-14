# OpenJules — Autonomous Sandboxed Coding Agent Service

OpenJules is an open-source, asynchronous, cloud-agnostic equivalent of Google Jules.
Its managed service connects approved work to isolated Docker execution,
retained capture and Polyphony's canonical task authority. Separate trusted
host commands retain legacy GitHub/Radicle execution and review components,
with explicitly configured cloud or self-hosted models.

**Standalone HTTP task, webhook, cohort and WebSocket operations are currently
unavailable.** The default server provides only a status page and health response.
Supplying a policy, token or webhook secret does not enable work. See the
[standalone ingress boundary](docs/managed-service.md#standalone-ingress-boundary)
for the complete route inventory, upgrade behavior and remaining #53 work.

## Managed deployment with ZPM

Use the [managed service](docs/managed-service.md) for ZPM repository capacity.
It connects the durable worker lifecycle to Polyphony's authenticated canonical
authority and an [isolated Docker runtime](docs/managed-docker-runtime.md).
The supported baseline executes one approved root command per immutable worker,
preserves capture before release, and recovers delivery intents after restart.
Source snapshots contain only the approved commit's objects; ignored host files
and local Git configuration are excluded.

An explicit [host cleanup command](docs/managed-docker-runtime.md#explicit-host-cleanup)
can remove a qualified executed worker's owned Docker resources after complete
root/child canonical capture. It retains host archives and journals, refuses
legacy or uncertain creations, and requires the managed service to be stopped.
Resources remain retained by default.

An optional [coding agent and model broker](docs/managed-model-broker.md) connects
that root execution to an explicitly configured provider. The broker retains
provider credentials on the trusted host, binds requests to canonical permission
and enforces shared call/token limits. Worker networking remains disabled.
The default profile makes no model calls. Explicitly approved profiles can use
[one level of bounded child agents](docs/managed-children.md) inside the same
worker, with distinct UIDs, shared model limits and verified child capture before
root release. Child expiry or cancellation retires the whole worker. Forge
publication remains outside this managed service.

An explicit child `outcome_protocol: initial-v1` profile can retain completed,
declined, clarification-needed or failed self-reports for the original private
instruction. The parent can read provisional reports, and final capture binds
them to canonical child records for reconnect. This requires the paired
Polyphony capability and the approved image; it adds no execution permission or
second instruction round. See the [outcome contract](docs/managed-children.md#explicit-initial-instruction-outcomes).

An additional child `session_protocol: cold-clarification-v1` profile lets the
parent answer one explicit clarification request using a fresh child. The host
retains the original instructions and provisional predecessor, closes the first
child's model endpoint, and requires its exec and active model handler to return
before requesting the successor. Both children keep their original watchdogs,
canonical charges and final capture obligations. This requires a newly approved
image/profile with `initial-v1` and at least two lifetime child slots. See
[cold clarification sessions](docs/managed-children.md#cold-clarification-sessions)
for the bounds, tool sequence and recovery behavior.

An explicitly approved `public_discussion` profile lets the root and already
granted children use [managed public discussion](docs/managed-children.md#managed-public-discussion).
The parent offers a turn; only its child can pull it or decline. Public model
calls share the existing allowance and use only approved public instructions and
selected signed messages. Private execution, completion and protected authority
remain separate. This mode requires `initial-v1`, the matching trusted image and
fixed public sockets; it is separate from cold clarification mode. Installation
pins, installed evidence and scope are recorded in the
[qualified installed revision set](#qualified-installed-revision-set) below.

CI qualifies execution, recovery and the model transport against deterministic
provider fixtures. A configured live provider and semantic task quality require
their own qualification. The older in-memory collaboration and DinD components
described below do not satisfy this managed contract and are never used
as a readiness fallback.

New ZPM installations bind their dedicated OpenJules interpreter to a
[managed installation context](docs/managed-service.md#managed-installation-context).
That interpreter refuses legacy CLI, webhook/UI, MCP, polling and cohort
execution before queue, model or Docker effects. Canonical service, publication
and owned cleanup retain their existing authority checks. Separate standalone
interpreters retain explicit trusted CLI/components; their private HTTP/WS
operations are disabled. Raw legacy access to a Docker
container labeled as managed is refused in every interpreter. This is an
installation boundary, not another enrollment or task-authority database.

The direct legacy PR reviewer refuses the branch shape and provenance marker
produced by [managed publication](docs/managed-publication.md), including custom
publication prefixes. Those feedback operations cannot enter its direct
sandbox, model and push loop. Eligible trusted direct review remains available; the
[review boundary](docs/managed-service.md#legacy-pr-review-boundary) documents
the conservative refusal cases and remaining ingress limits.

## Bounded public discussion

The separate `openjules-discussion` command lets an explicitly approved
participant read selected signed public messages and contribute one bounded
response. The host fixes the topic, public persona, provider, subprocess and
allowance. Every model dispatch requires a new explicit host turn. Peer messages
cannot start inference, choose tools, enroll tasks, allocate workers or publish
code.

### Qualified installed revision set

The recorded installed qualification uses the dedicated
`polyphony-public-conversation` profile-v1 service with this revision set:

- ZPM: `8c3cb83504fc8878eb82a660614f64939262e045`
- OpenJules: `c925dee46765d2b22c9e38b55f614fc29f8068c1`
- Polyphony: `0cf8b4772b04269505e3e1cd41324e41409b80f9`

Use the [ZPM installation guide](https://github.com/niklas-olsson/zero-point-modulator/blob/main/docs/single-host-installation.md)
for current installation pins and subsequent acceptance records. The evidence
below remains tied to its recorded revisions.

The [ZPM #35 delivery record](https://github.com/niklas-olsson/zero-point-modulator/pull/35#issuecomment-6824429010) and its successful
[actual-main run](https://github.com/niklas-olsson/zero-point-modulator/actions/runs/43221845468) retain the installed qualification.
The managed-public scene covers a root, two separately granted children and an
independent peer: attributable dialogue preserving dissent, independent
decline/leave, refused inviter control, paired authorized/denied private reads,
and original grants, deadlines and final captures retained after restart.
Exact replay adds no inference or execution. Cold clarification and managed
public participation remain separate approved profiles.

The completed, declined, cold clarification and failed-child scenes retain
bounded startup, delegation latency, context size and storage measurements,
with separate cold-session evidence and idle CPU/RSS windows containing a
complete controller cycle. The managed-public scene keeps its separate
two-second idle sample without a completed-cycle claim. CPU covers the whole
observed window, not an isolated cycle cost or performance guarantee. Warm child
reuse remains unsupported. These trials use actual local services, Docker, MCP
and native peer transport with deterministic model responses. They do not
establish live-provider quality or billing, or an actual generated forge proposal.

The earlier installed independent-participant qualification remains historical
evidence on this separate revision set:

- ZPM: `55dfd6a8f275a6b649fda86b2fe6f48b2321daf5`
- OpenJules: `74429feda1f3991ce528678b74d6db5e3b3b250c`
- Polyphony: `0cf8b4772b04269505e3e1cd41324e41409b80f9`

The [ZPM #36 delivery record](https://github.com/niklas-olsson/zero-point-modulator/pull/36#issuecomment-6816512407)
and its successful [actual-main run](https://github.com/niklas-olsson/zero-point-modulator/actions/runs/43165296956)
retain the repeated installed independent-public scene: real restricted-profile subprocesses, MCP and
native peer delivery, three original signed records, an independent decline,
causal follow-up, durable replay and completed owned-process cleanup. Its three
provider calls use a deterministic HTTP fixture.

The later [OpenJules #34](https://github.com/niklas-olsson/OpenJules/pull/34) merge,
`fb76d3fb63366f2efe8aa3d1b6328c637bd9adcc`, separately qualifies shared conversation
primitives and explicit cleanup evidence through OpenJules CI. That producer
revision was not the OpenJules pin in the historical ZPM #36 installed set.
The ordinary Polyphony server is not a compatible fallback. See the
[agreed interface and ownership](https://github.com/niklas-olsson/OpenJules/issues/5#issuecomment-6810422689).

### Approve the private policy

Use an existing private parent directory. Policy, turn and conversation-config
files must be owned regular files with mode 0400 or 0600; symlinks, special files,
ambiguous inspection failures and oversized files are refused. Leave the B
state-directory leaf absent until the explicit `init` command. Its completed
state uses mode 0700 and private mode 0600 files.

The following example is a host policy, not repository or model-provided input.
Replace the provider and approved paths before use:

```json
{
  "schema_version": 1,
  "public_approved": true,
  "topic": "architecture-discussion",
  "persona": "Discuss public architecture tradeoffs concisely. Decline when the available public evidence is insufficient.",
  "provider": {
    "endpoint": "https://provider.example/v1/chat/completions",
    "model": "approved/model",
    "token_ref": "env:DISCUSSION_PROVIDER_TOKEN",
    "request_timeout_seconds": 30,
    "token_parameter": "max_tokens"
  },
  "server": {
    "python": "/srv/polyphony/.venv/bin/python",
    "cwd": "/srv/polyphony",
    "config": "/srv/public-discussion/conversation.json"
  },
  "state_directory": "/srv/public-discussion/participant",
  "limits": {
    "max_calls": 8,
    "max_output_tokens": 1024,
    "max_total_output_tokens": 8192
  }
}
```

The corresponding private A config requires these four fields:

```json
{
  "schema_version": 1,
  "topic": "architecture-discussion",
  "scope_key_file": "/srv/public-discussion/scope",
  "state_directory": "/srv/public-discussion/conversation-state"
}
```

For the paired profile's explicit single-host native topology, the operator
may also add `"bootstrap": {"host": "127.0.0.1", "port": 12345}`. This is the
only optional field. The host must be that literal address and the port an
integer from 1 through 65535; aliases, other addresses, null, booleans and extra
fields are refused. In the paired A profile this selects the configured
loopback transport with no public-bootstrap fallback. Omission preserves its
default transport. B's configuration validation alone does not prove native
startup, peer discovery or receipt.

The journal binds the exact original config bytes without inserting defaults
or normalizing them. Existing four-field configurations remain valid. Keep the
selected bootstrap endpoint and config bytes unchanged across participant
restarts; changing the port, adding or removing the option, or changing
whitespace refuses the existing journal instead of silently rebinding it.

Polyphony owns its scope secret and signed conversation state. B reads the
private config binding but never opens the scope-secret file. The A and B state
directories must be separate. The host approves the interpreter and immutable
checkout as executable trust. B preserves a venv's original launch path and
checks its resolved executable and installed prefix; this is not source-code
attestation or a sandbox for an untrusted executable.

The SDK dependency is pinned to MCP 1.30.0. B uses its standard `ClientSession`
over owned bounded pipes. It validates exactly six tools before the first status
call: `conversation_status`, `conversation_start`, `conversation_join`,
`conversation_say`, `conversation_history` and `conversation_watch`.
Unexpected tools, resources, prompts, task execution, output schemas, dynamic
tool changes and unsolicited server requests are refused.

### Initialize, observe and submit a turn

After installing OpenJules and the separately qualified restricted service:

```sh
openjules-discussion --config /srv/public-discussion/participant.json init
openjules-discussion --config /srv/public-discussion/participant.json status
openjules-discussion --config /srv/public-discussion/participant.json observe
```

Initialization makes no model call or public append. It first checks the
restricted service's public identity and the original interpreter, closes the
owned preflight process, and then creates the private allowance state. A second
init refuses an existing directory, including partial initialization. Normal
commands never create or repair missing state.

A turn is a private immutable JSON file. The host chooses the signed message IDs
and the stable request key; the model cannot change them. This example creates
one file with an empty selected history and a 120-second original expiry:

```python
import json
import os
import time

turn = {
    "schema_version": 1,
    "request_key": "public-introduction-1",
    "expires_at": time.time() + 120,
    "instruction": "Introduce your approved public perspective in one short message.",
    "selected_message_ids": [],
    "context_after": 0,
    "stream_id": None
}
descriptor = os.open(
    "/srv/public-discussion/introduction.json",
    os.O_WRONLY | os.O_CREAT | os.O_EXCL,
    0o600
)
with os.fdopen(descriptor, "w", encoding="utf-8") as handle:
    json.dump(turn, handle, sort_keys=True, separators=(",", ":"))
    handle.write("\n")
```

Set the referenced provider credential in the host environment for a turn that
needs a new response. It is never added to the conversation subprocess
environment, a journal, a status object or a provider request body.

```sh
openjules-discussion --config /srv/public-discussion/participant.json turn \
  --request /srv/public-discussion/introduction.json
openjules-discussion --config /srv/public-discussion/participant.json receipt \
  public-introduction-1
```

To use earlier messages, take their signed IDs and the stream ID from
`observe`. A positive `context_after` always requires that original stream.
An optional `reply_to` must be one of the selected IDs. Gaps, missing selected
messages, changed streams and stalled cursors refuse the turn instead of
silently selecting different context. Public task/artifact references are
retained as text and confer no retrieval or execution authority.

The provider receives the approved persona, instruction and frozen selected
public context with no tools. It must return one completed JSON object containing
exactly `kind` and `content`; kind is `message`, `decline` or `leave`.
The participant verifies the original signed publication receipt, including
topic, session, public actor, request key, content and immutable reply/reference
fields. Delivery remains `submitted`; this is not a claim that another peer
received or accepted the message.

### Bounds and recovery

| Resource | Fixed or configured bound |
| --- | --- |
| New turn | Original expiry at most 180 seconds away; same-boot monotonic cutoff also retained |
| Startup and interpreter probe | 10 seconds, clipped to the original remaining interval |
| Ordinary RPC | 10 seconds, clipped to the original remaining interval |
| Observation or init | 45-second invocation envelope |
| Watch | At most 30 seconds of server wait plus 5 seconds for its response, within the observation envelope |
| Owned-process shutdown | 5 cleanup-only seconds; no new provider or post permission |
| Provider | 30 seconds by default, at most 120, clipped to original expiry |
| Allowance | 8 calls, 1024 reserved tokens per call and 8192 total by default; maxima 128, 4096 and 524288 |
| Retained turns | 128 distinct keys, including keys that have only completed preflight |
| Selected context | 32 signed IDs, 8 history pages, 131072 canonical record bytes |
| MCP traffic | 262144 raw bytes per frame and 1048576 total stdin/stdout bytes per invocation |
| Provider traffic | 524288 request bytes and 262144 response bytes |
| Public output | 8192 UTF-8 content bytes and 16384 escaped canonical signed-record bytes |
| Private policy, turn or A config | 65536 bytes each |

A call and its output-token allocation are committed before the single provider
dispatch. There are no refunds, automatic retries, model fallbacks or automatic
peer-triggered turns. The provider response is validated and retained before any
public post is dispatched.

| Retained state | Meaning and permitted next action |
| --- | --- |
| `prepared` | No provider reservation yet. Retry only the unchanged original file within its original expiry. |
| `response` | A validated response is retained. The same file may recover publication before its original expiry without another model call. |
| `complete` | The original signed receipt is retained. It remains locally readable after expiry. |
| `rejected` | The attempt remains charged and unpublished; that key cannot make another provider call. |
| `provider_uncertain` | The journal blocks every new provider dispatch, including changed keys. There is no reset/refund API. |
| `publication_uncertain` | A post may already exist. Before expiry, recovery can only repeat the same immutable post key and intent. |

A later provider-uncertainty hold does not prevent recovery of an earlier
validated response under that response's original key and expiry. Local receipt
reads require no provider credential. Known results may be persisted during the
original cleanup interval after a dispatch ends; that bookkeeping never
authorizes another network call.

Expiry prevents a new provider or publication RPC from being dispatched. It
does not prove that an already dispatched uncertain RPC could not complete
late. An expired uncertain post must not be described as definitely unpublished.
Changing a file's expiry, whitespace, policy, interpreter, identity or stream
cannot renew an existing turn or allowance.

B's state is a one-owner SQLite DELETE journal with full synchronization and a
retained lock, binding and file identity. It refuses unexpected WAL/SHM,
missing or replaced files, changed bindings and impossible retained charges.
SQLite can recover an uncommitted rollback journal without refunding an earlier
committed reservation. Deleting the entire state, restoring an old backup or
selecting another installation is a trusted host action, not a supported
recovery/reset operation.

The subprocess receives exactly four environment entries:
`PATH=/usr/local/bin:/usr/bin:/bin`, `LANG=C.UTF-8`,
`PYTHONNOUSERSITE=1` and `PYTHONDONTWRITEBYTECODE=1`.
Stderr is discarded under a 65536-byte cap. Shutdown keeps the leader identity
until group signals are delivered, reaps that leader and observes termination
of inherited-group descendants. This is not universal grandchild `waitpid`
ownership or containment of a trusted program that deliberately detaches.

A successful `turn` exits 0 only with a complete receipt and no remaining
error. Rejected turns exit 2; incomplete or uncertain turn results exit 3. Read
the fixed JSON state/reason and retained status before taking another action.
Errors contain no raw provider body, stderr, credential or private path.

The component tests cover real stdio and HTTP fixtures, signed same-key replay,
crash-retained allowances, private-file refusal, genuine venv-prefix binding,
deadline/uncertainty handling and the unchanged managed HTTP caller. These tests
are distinct from the installed independent-participant qualification recorded
above. The separate managed-public Docker component suite exercises a confined
root and child with named authority, provider and stdio conversation fixtures.
The installed root-plus-two-children public trial is recorded in the qualified
set above. Live-provider judgment and an actual generated forge proposal remain
unverified by that evidence.
Public conversation records confer no protected execution authority.

---

## Source and documentation map

Read [AGENTS.md](AGENTS.md) for contributor guidance. Use these representative
source entry points and existing documentation homes; keep contract details in
the linked explanation. Update this map when routing changes.

| Change | Representative source | Documentation home |
| --- | --- | --- |
| Service configuration, ingress and readiness | [managed_service.py](src/worker/managed_service.py), [execution_context.py](src/worker/execution_context.py) | [Managed service](docs/managed-service.md) |
| Disabled standalone HTTP/WS ingress and retained local records | [standalone_ingress.py](src/api/standalone_ingress.py), [webhook.py](src/api/webhook.py), [dashboard_state.py](src/storage/dashboard_state.py) | [Standalone ingress boundary](docs/managed-service.md#standalone-ingress-boundary) |
| Pure schema-1 installation validation and static contract | [managed_configuration.py](src/worker/managed_configuration.py), [installation_validation.py](src/worker/installation_validation.py), [contract and vectors](src/worker/contracts/openjules-installation-v1.json) | [Installation configuration validation](docs/managed-service.md#installation-configuration-validation) |
| Worker state and lifecycle API | [lifecycle.py](src/worker/lifecycle.py), [worker_lifecycle.py](src/api/worker_lifecycle.py) | [Worker lifecycle](docs/worker-lifecycle.md) |
| Optional execution destination identity and original journal set | [destination.py](src/worker/destination.py), [managed_service.py](src/worker/managed_service.py) | [Execution destination identity](docs/managed-service.md#optional-execution-destination-identity), [HTTP v2](docs/worker-lifecycle.md#http-version-2-destination-identity) |
| Docker, source snapshots, capture and cleanup | [docker_runtime.py](src/worker/docker_runtime.py), [source_snapshot.py](src/worker/source_snapshot.py) | [Managed Docker runtime](docs/managed-docker-runtime.md) |
| Coding tools, model access and limits | [model_broker.py](src/worker/model_broker.py), [managed_runner.py](src/agent/managed_runner.py) | [Model broker](docs/managed-model-broker.md) |
| Finite managed-image acquisition, sealed build and archive verification | [managed_image.py](tools/managed_image.py), [production Dockerfile](docker/Dockerfile.managed-agent) | [Operator-local distribution](docs/managed-model-broker.md#finite-operator-local-distribution) |
| Child grants, cold sessions and managed public discussion | [child_supervisor.py](src/worker/child_supervisor.py), [child_client.py](src/polyphony/child_client.py), [managed_public.py](src/worker/managed_public.py) and adjacent `managed_public*.py` modules, [public_tools.py](src/agent/public_tools.py) | [Managed children](docs/managed-children.md) |
| Composition and draft publication | [managed_composition.py](src/git_manager/managed_composition.py), [managed_publication.py](src/worker/managed_publication.py), [managed_github.py](src/forge/managed_github.py) | [Managed publication](docs/managed-publication.md) |
| Standalone sandbox recovery | [docker_driver.py](src/sandbox/docker_driver.py), [executor.py](src/worker/executor.py) | [Sandbox recovery](docs/sandbox-recovery.md) |
| Standalone public participant | [public_discussion.py](src/worker/public_discussion.py), [discussion_journal.py](src/worker/discussion_journal.py), [conversation_client.py](src/polyphony/conversation_client.py) | [Bounded public discussion](#bounded-public-discussion) |

Polyphony owns [canonical task authority](https://github.com/niklas-olsson/keystone-polyphony/blob/main/docs/managed-runtime.md).
ZPM owns [installation configuration](https://github.com/niklas-olsson/zero-point-modulator/blob/main/docs/single-host-installation.md),
installed pins and [joined acceptance](https://github.com/niklas-olsson/zero-point-modulator/issues/3).

## Architecture Overview

| Entry point | Current behavior |
| --- | --- |
| Managed service | Authenticated lifecycle and canonical managed dispatch, isolated execution and retained capture. Publication is a separate approved host operation. |
| Standalone HTTP/WS | Health/static only; no private reads, execution, feedback, cohort control or subscriptions. |
| Trusted host CLI/components | Explicit legacy executor, reviewer, poller, MCP and swarm operations, refused in installed managed context. |

The following legacy components remain available to explicit trusted local
callers. They are not loaded by the standalone HTTP app and are not a substitute
for canonical managed authority:

1. **Repository Configuration & Sandbox Runtime (`src/sandbox/`)**:
   - `src/sandbox/config.py`: Schema parser for `.openjules.yaml` defining base image, setup scripts, test commands, timeouts, env vars, LLM parameters, and adaptive harness settings.
   - `src/sandbox/docker_driver.py`: `SandboxManager` handling container spawning with resource limits (`mem_limit="4g"`, `nano_cpus=2000000000`), workspace mounting, credential injection, command streaming, and strict `try...finally` cleanup.
2. **Adaptive Agent Harness & Two-Stage Engine (`src/harness/` & `src/agent/`)**:
   - `src/harness/adaptive_engine.py`: Self-contained, adaptive harness implementing the **Propose–Probe–Compose** cycle.
     - **Inner-Loop Adaptation (Task-Level)**: Proposes dynamic guardrails and diagnostic probe commands when verification tests fail, probing them in the sandbox before retrying fixes.
     - **Outer-Loop Adaptation (Harnessing-Level)**: Distills lessons learned from successful runs into `EXPERIENCE.md`, compounding repository-specific rules across all future tasks.
   - `src/agent/tools.py`: Safe tools executing directly inside the sandbox: `read_file`, `write_file`, `apply_patch` (unified diff + search/replace block support), `run_command`, `list_files`.
   - `src/agent/engine.py`:
     - **Step A (Planning Phase)**: Injects historical experience from `EXPERIENCE.md` and generates structured JSON plan (`rationale`, `target_files`, `planned_tests`, `action_steps`).
     - **Step B (Action Loop)**: Stateful ReAct loop with turn limit. Native OpenAI function calling with automatic prompt-guided JSON fallback for local LLMs lacking tool calling schemas.
     - **Step C (Verification)**: Automatically executes `config.test_command` with an adaptive fix loop if tests fail.
3. **Keystone Polyphony Multi-Agent Swarm (`src/polyphony/`)**:
   - Auto-subscribes all agents targeting the same repo to the repo's Polyphony choir using deterministic `SWARM_KEY` derivation (`keystone-polyphony-v1:<repo>`).
   - **Baton Mutex Locks**: Prevents duplicate concurrent runs (`task:{issue_id}`) and coordinates file modifications (`file:{path}`).
   - **Liminal Space**: Broadcasts thoughts, status changes (`planning`, `busy`, `verifying`, `idle`), and audit logs.
   - **Swarm Backlog**: Synchronizes task progress across decentralized nodes.
4. **Pluggable Forge Layer (`src/forge/` & `src/git_manager/`)**:
   - `src/forge/base.py`: Abstract `ForgeProvider` interface.
   - `src/forge/github.py`: GitHub App and PAT integration via PyGithub.
   - `src/forge/radicle.py`: Radicle integration supporting the `rad` CLI (`rad clone`, `rad patch open`) and Radicle Node HTTP API.
   - `src/git_manager/lifecycle.py`: Task branch management (`openjules/task-{issue_id}-{slug}`), Conventional Commits, diff calculation, and PR/Patch summary generation.
5. **Control Plane & Background Task Workers (`src/api/` & `src/worker/`)**:
   - `src/api/webhook.py`: Harmless status/health app. All private HTTP/WS routes refuse before importing execution or storage clients; no webhook dispatch is enabled.
   - `src/worker/dispatcher.py`: Extensible `TaskDispatcher` interface.
   - `src/worker/radicle_poller.py`: Background poller for local or self-hosted Radicle nodes (`rad:<rid>`).
   - `src/worker/executor.py`: End-to-end task runner opening PRs/Patches and posting status comments.

---

## Quickstart

### Prerequisites

Python 3.11+ runs the local status service and component tests. Docker and Compose
are needed for the container path. The status service needs no forge token,
model provider or Docker daemon connection.

For actual protected execution, use the [managed deployment](#managed-deployment-with-zpm).
For explicit trusted legacy CLI use outside an installed managed interpreter,
the operator supplies a Docker runtime, repository/forge credentials, relevant
Radicle CLI/node configuration and an approved model endpoint. Those execution
dependencies are not provisioned by the status server.

### 1. Local Development Setup

```bash
# Clone the repository
git clone https://github.com/niklas-olsson/OpenJules.git
cd OpenJules

# Use a dedicated environment
python3 -m venv .venv
. .venv/bin/activate

# Install dependencies
pip install -r requirements-dev.txt

# Run test suite
pytest

# Start health/static only on literal loopback
python -m src.cli serve --host 127.0.0.1
```

`serve` accepts only literal `127.0.0.1` or `::1`. A hostname, wildcard bind,
bearer token or nonempty `OPENJULES_INGRESS_POLICY` cannot enable task operations.
The full CI suite also builds managed Docker fixture images; a local unit run
does not qualify an installed execution environment.

### 2. Running with Docker Compose

The sole default service exposes the same harmless status page. It does not
receive credentials, mount execution state or start privileged DinD:

```bash
docker compose up -d --build openjules
curl http://127.0.0.1:8000/health
# {"status":"ok","service":"openjules","standalone_ingress":{"state":"disabled","policy":"missing","reason":"standalone_ingress_unavailable"}}
```

The container listens on `0.0.0.0:8000` internally; Compose publishes its port
only on host `127.0.0.1:8000`. To request the existing host-owned legacy DinD
runtime explicitly:

```bash
docker compose --profile legacy-runtime up -d dind
```

This starts infrastructure only. It does not enable the HTTP server or configure
a host CLI to use that container-internal daemon. The `radicle`, `swarm`, `vllm`
and `llamacpp` profiles are also explicit optional infrastructure, not admission.
Configure a trusted CLI's Docker endpoint and credentials on the operator-owned
host through its existing environment/runtime setup. The default status container
is no longer a credential-bearing CLI environment.

When upgrading, stop the old ingress and reconcile already-running workers with
trusted host controls. Existing task databases, volumes and uncertain work are
retained. An old DinD container can still be running after this configuration
change; a disabled status page does not certify its work stopped or completed.
See [upgrade and validation details](docs/managed-service.md#upgrade-retained-work-and-validation).

---

## Adaptive Agent Harness (Harness² Paradigm)

In autonomous agent workflows, an agent is:
$$\text{Agent} = \text{Foundation Model} + \text{Harness}$$

OpenJules keeps model weights frozen while dynamically optimizing the **Harness**:
1. **Inner Loop (Task Adaptation)**:
   - When a test verification fails, the harness analyzes the execution trace and generates targeted guardrails and probe commands (`propose_harness_adaptation`).
   - The probe commands run inside the sandbox, and the empirical findings are fed back to guide the next fix attempt.
2. **Outer Loop (Compounded Experience)**:
   - On every verified task, successful architectural strategies and discovered guardrails are committed to `EXPERIENCE.md`.
   - Subsequent tasks automatically read `EXPERIENCE.md` during Step A planning, starting with accumulated project context.

---

## Self-Hosted LLMs (vLLM, llama.cpp, Ollama)

OpenJules natively connects to any OpenAI-compatible inference endpoint:

### Configuration via Environment Variables

```bash
# Connect to vLLM
export LLM_API_BASE="http://localhost:8001/v1"
export LLM_MODEL="openai/Qwen/Qwen2.5-Coder-7B-Instruct"
export LLM_API_KEY="EMPTY"

# Connect to llama.cpp server
export LLM_API_BASE="http://localhost:8081/v1"
export LLM_MODEL="gpt-3.5-turbo"
export LLM_API_KEY="EMPTY"

# Connect to Ollama
export LLM_API_BASE="http://localhost:11434/v1"
export LLM_MODEL="ollama/codellama"
export LLM_API_KEY="ollama"
```

### Configuration via Repository (`.openjules.yaml`)

```yaml
llm:
  model: "Qwen/Qwen2.5-Coder-7B-Instruct"
  api_base: "http://vllm:8000/v1"
  api_key: "EMPTY"
  temperature: 0.2
  max_tokens: 4096

harness:
  adaptive: true
  experience_path: "EXPERIENCE.md"
  inject_experience: true
```

---

## Keystone Polyphony Integration (https://github.com/LokiMetaSmith/keystone-polyphony)

Every agent operating on the same repository automatically joins that repository's Polyphony:
- **Repo-Scoped Anchoring**: The `SWARM_KEY` is derived deterministically from the repository name or Radicle RID, partitioning coordination cleanly.
- **Mutex Batons**: Agents acquire `task:{issue_id}` on startup and `file:{path}` during planning, preventing race conditions or conflicting code changes.
- **Liminal Thoughts Stream**: Real-time progress thoughts stream into the shared mesh.

---

## Radicle Integration Guide (https://radicle.dev)

OpenJules natively supports Radicle peer-to-peer code collaboration:
- **Repository IDs (`rad:<rid>`)**: Clones and works on decentralized repos without a centralized server.
- **Radicle Patches**: Changes are proposed via `rad patch open` rather than GitHub PRs.
- **Explicit Local Polling**: `RadicleNodePoller` remains a trusted host component. The standalone `POST /api/radicle/webhook` is unavailable under the ingress boundary above.

---

## Architecture Background & Philosophy

OpenJules embraces the **frozen model + adaptive harness** philosophy:
- **Strict Sandbox Boundary**: Every task is constrained to an isolated container with deterministic resource limits (`4g` RAM, `2 CPUs`), ephemeral storage, and guaranteed `try...finally` teardown.
- **Adaptive Harnessing**: Dynamic guardrail generation and persistent `EXPERIENCE.md` library ensure continuous learning without retraining.
- **Model Agnostic & Self-Hosted**: Seamlessly swaps between frontier cloud APIs and offline, self-hosted models (vLLM, llama.cpp, Ollama).
- **Keystone Polyphony Swarm**: Coordinates multiple agents working asynchronously on the same repo using RTOS-inspired mutex batons and shared liminal context.
- **Decentralized & Multi-Forge**: Pluggable forge layer decouples the agent core from any single centralized platform, natively powering both GitHub and Radicle p2p networks.
