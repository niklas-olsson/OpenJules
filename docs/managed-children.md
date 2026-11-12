# Bounded child agents in a managed worker

An explicitly approved model profile can run one level of child coding agents
inside its existing worker container. Rather than implying POSIX process-tree
hierarchies (`fork()`, process trees), this subsystem implements capability
attenuation: a primary lease holder sub-allocates a bounded slice of authority
and budget via a `DelegatedGrant` (or `Subgrant`/`SubLease`). This terminology
communicates capability-based delegation consistent with FencedLedger leases.

The root asks for a canonical child grant (`DelegatedGrant`), the trusted host
admits that exact delegated capability, and the delegate edits its own checkout.
The root can read provisional child patches and logs and compose the result in
its own checkout. Polyphony remains the authority for requirements, grants,
budgets, artifacts and review. ZPM still counts one worker for the entire group.

This is opt-in. Existing command and root model profiles keep their old
configuration and fingerprints. Enabling children or changing their policy
requires a new approved profile name and worker incarnation. The service does
not convert an already running root-only container into a child-enabled worker.

## Configuration and approval

The managed service accepts an optional `children` list. Every entry must match
an existing runtime profile and a `models` entry by the exact deployment,
repository and profile name. For example:

```json
{
  "children": [
    {
      "deployment_id": "my-installation",
      "repository": "github:github.com/example/project",
      "profile": "coding-with-children-v1",
      "policy": {
        "max_children": 2,
        "max_child_seconds": 60,
        "max_child_turns": 5,
        "capabilities": ["python"],
        "uid_start": 60000,
        "command": ["python3", "-I", "-S", "/opt/openjules/managed_runner.py"],
        "verify_argv": ["python3", "-m", "unittest", "discover"],
        "max_result_bytes": 4000000
      }
    }
  ]
}
```

The corresponding Polyphony profile must explicitly approve `max_children`,
`max_child_seconds`, `max_child_turns` and `child_capabilities`. The capability
list and all three limits must match the runtime policy. Canonical preflight
must advertise `child_grants: true` and that exact policy before the runtime
advertises `children: true`. A missing supervisor, unavailable socket transport,
unsupported Docker UID mapping or unavailable canonical authority keeps it
unready.

`max_children` is the total number of grants during the root attempt, from 1 to
64. A finished child does not free its grant slot or UID for reuse.
`max_child_seconds` must fit the root runtime and canonical attempt limits.
`max_child_turns` is from 1 to 1000. Child instructions are bounded to 64 KiB.
The host adds the child socket and granted turn limit to the approved command;
the guest cannot select a command, image, host source path, UID or provider.

Use the trusted root wrapper for the profile's root command:

```json
[
  "python3", "-I", "-S", "/opt/openjules/managed_root_runner.py",
  "--socket", "/run/openjules-model/model.sock",
  "--control-socket", "/run/openjules-model/control.sock",
  "--max-turns", "20"
]
```

The image must contain that wrapper, `child_tools.py`, and `managed_runner.py` at
their approved image paths. `docker/Dockerfile.managed-agent` includes these and
the optional `child_outcome.py` companion.
The root wrapper imports its companions from the trusted image, including when
run with `python3 -I -S`; task checkout modules cannot replace them. Image IDs or
digests, source commits and root command argv retain the existing immutable
profile rules.

Capability names describe an operator-approved runner bundle. The first runtime
supports exactly the configured child bundle and refuses requests for a
different subset. Removing a capability label does not sandbox arbitrary
Python or shell code. Use a separately approved profile when the executable
environment needs a different boundary.

## Shared limits and process identities

Child grants use the root task's existing canonical time budget. Each admitted
child allocation is charged once, with no refund or second task budget. The task
budget must cover the root allocation and all requested child allocations.
Each child deadline is at or before the root deadline, and retries never extend
the original local cutoff.

All root and child model calls share the same durable root call and output-token
allowance. A child also consumes its canonical per-child turn allowance before
the provider request. A lost turn acknowledgement retries the same canonical
turn key without charging another model reservation. A live in-flight request
or recoverable canonical turn returns a bounded retry response to other callers.
An uncertain provider dispatch blocks subsequent inference for the whole root;
it is never automatically sent to the provider again.

The existing root UID is distinct from the protected watchdog UID 65534. Every
child gets a unique nonzero UID from the approved range. No UID is recycled in
that worker. The default range starts at 60000. Overlap with the root or
watchdog is rejected. The baseline requires local rootful Docker without
user-namespace remapping; other UID mappings need separate qualification.

Each child checkout, home and temporary directory is private to its UID. The
shared parent directory is owned by the watchdog with mode 0711, so the root and
children cannot rename another child's directory. Each child has a separate
read-only mounted model socket, with its identity fixed by the host and checked
through Linux `SO_PEERCRED`. The root-only control socket uses the same kernel
check. Supplying another identity in JSON cannot change the caller's authority.
Children receive the ordinary coding tools and cannot request more children.

All descendants share the existing container CPU, memory and process limits.
They receive no provider, authority, worker API or Docker credentials. Container
network access stays disabled. Independent workers and ordinary Polyphony peers
retain their own lifecycle and are outside this child's cancellation scope.

## Root controls and provisional work

The root model receives five additional tools:

| Tool | Behavior |
| --- | --- |
| `spawn_child` | Requests bounded instructions, seconds, turns and the approved capability bundle. The host persists a delivery key before contacting Polyphony. |
| `child_status` | Observes the existing child; it does not allocate or launch again. |
| `child_result` | Reads a bounded patch or log page after the child exec returns. The response is explicitly `final: false` and carries whole-artifact and page hashes. |
| `cancel_child` | Revokes the child and requests retirement of its entire worker. |
| `close_children` | Closes admission for new children. Existing children remain bounded by their original grants. |

The root wrapper also closes child admission when its agent loop exits or fails.
Control requests freeze their bytes and request identity before the first send.
Only explicit `retry_later` or `canonical_pending` replies retry within that
original request's timeout. A transport loss or conflicting retry stops the
guest root so host recovery can reconcile the original intent.

Child results are provisional guest-generated evidence. The host freezes the
first returned version of each artifact so paging and repeated reads have
stable hashes. The root must deliberately inspect and apply a patch in its own
checkout. Reading a child patch does not prove it was composed, tested,
independently reviewed or accepted.

## Explicit initial instruction outcomes

A new approved child profile may add `"outcome_protocol": "initial-v1"` to its
policy. This requires the default trusted `managed_runner.py` command and an
image built with `child_outcome.py`. Approve the new image and profile incarnation
before enabling it. Custom command children and profiles that omit the setting
keep their original command arguments and policy fingerprint. Unsupported
explicit protocol values or commands are rejected. Canonical readiness also
requires the integer capability `child_initial_outcome: 1`; health alone cannot
enable the extension.

An enabled child receives one additional terminal tool:

```json
{"name": "report_outcome", "arguments": {"outcome": "declined", "summary": "The requested approach conflicts with the repository constraints."}}
```

`outcome` is `completed`, `declined`, `needs_clarification`, or `failed`. The
private summary is at most 8192 UTF-8 bytes and cannot contain NUL. The tool must
be the only call in its assistant response and ends that child's loop. A mixed
terminal/tool response performs none of those tool calls. The existing `finish`
tool reports `completed` only in this explicitly enabled child profile. Root
completion behavior is unchanged.

A decline, clarification request, or reported failure preserves partial work
and does not run the optional child verification command. For `completed`, the
semantic report is retained before configured verification; its pass/fail result
is captured separately. Completion is a child claim. It does not prove tests,
composition, termination, task acceptance, independent review, or publication
authority. A process that never sends a report remains explicitly `unreported`,
even if its exit code is zero or its patch is empty.

The host adds `--outcome-socket` with that child's fixed `outcome.sock` path.
The separate socket checks the child UID with `SO_PEERCRED`; model requests keep
their existing exact schema. Callback JSON supplies only schema version,
request identity, outcome and summary. The host derives the child, parent,
original requirement revision and instruction binding from its immutable grant.
The initial logical work-turn identity is separate from inference reservations.
No callback or callback retry consumes another model call or starts another exec.

The host retains one immutable report slot in the existing child journal before
acknowledging. An identical request returns the same report; another key or
changed content conflicts. The image client freezes one request key, body and
overall deadline. It may resend those exact evidence bytes after a lost reply,
and cannot replace the report or renew that deadline. The acknowledgement means
locally retained, with `final: false`, `canonical_committed: false` and
`release_authorized: false`.

`child_status` exposes the typed report to the bound parent under
`initial_outcome`, also explicitly provisional. Service restoration preserves the
same child UID, exec identity and report. Existing protected canonical child
reads recover the committed `initial_outcome` and final artifact references
after final capture. This is client reconnection to retained records, not
automatic restart of a terminated root loop.

The final child manifest contains an optional `work_outcome` object bound to the
original grant and instruction digest. For enabled profiles it contains either
the retained report or an explicit null report with source `unreported`. Report
retention and final capture freezing serialize in the existing journal. If a
report arrives while the archive is being read, freezing retries from the new
report; after freezing, a first or changed report is refused. An already retained
identical retry remains safe. The canonical service validates the extension
before reserving its immutable capture slot and again before terminal release.

The existing whole-worker fence still precedes final capture. A report cannot
disarm a watchdog, extend a deadline, refund a budget, clear an execution
reference or authorize follow-up work. Summaries remain in protected records;
they are not automatically published to public conversation. The outcome protocol
alone supports only the original private instruction. The separate opt-in
session protocol below supports one bounded parent follow-up.

## Cold clarification sessions

An approved model profile can additionally set
`"session_protocol": "cold-clarification-v1"` in its child policy. It requires
`"outcome_protocol": "initial-v1"`, the default trusted child runner and
`max_children >= 2`. Deploy the paired host implementation, build and approve an immutable image
containing the updated guest, and use a new profile name and worker incarnation.
Omitting the setting preserves existing policy serialization, fingerprints and
tools. Explicit null or another protocol value is rejected. Polyphony still
receives the same four canonical child policy fields; this adds no session
authority or separate task budget.

A session retains one original instruction and permits at most one parent
follow-up. Each round uses a distinct canonical child, grant, UID, private
checkout, exec and charged allocation. Each child reports its own original
instruction at ordinal 1. The second round receives a canonical JSON instruction
envelope containing the original instruction, the parent's clarification and
the frozen provisional outcome of the first child. It starts a fresh checkout;
no patch or workspace change is automatically carried forward. The parent
remains responsible for inspecting and composing contributions.

The enabled root receives three additional tools:

| Tool | Required arguments and effect |
| --- | --- |
| `start_child_session` | `instructions`, `seconds`, `max_turns`, `capabilities`. Retains the original session and ordinary child delivery intent before contacting canonical authority. |
| `continue_child_session` | `session_id`, `predecessor_digest`, `instructions`, `seconds`, `max_turns`. Queues the single follow-up against the exact observed predecessor. Capabilities, task, root, base and requirements revision stay fixed. |
| `child_session_status` | `session_id`. Observes retained reports and execution state without granting or launching a successor. |

Start a session, observe its report, then choose whether to continue. Only an
explicit first-round `needs_clarification` report permits the follow-up. A
decline, failure, missing report at exec return, nonzero exit or uncertain
execution closes that opportunity. A second-round clarification request closes
the session; it does not enable a third round or replacement child. Independent
child decisions are retained, including a refusal to proceed.

A follow-up first closes new model-call admission for the predecessor. A call
already admitted under the shared model gate keeps the existing permission,
deadline and charging rules. The original endpoint must finish its active
handler and response write, and the child exec must return successfully, before
the host can establish the fence and promote the queued request. Unresolved or
uncertain root-attempt inference reservations block promotion. Reopening a
journal preserves the closure and never recreates that model endpoint; the
child's separate outcome endpoint remains available for its original report.

The model fence is not an OS process-termination receipt. All previously armed
watchdogs remain armed, including the predecessor's. The successor cannot extend
the earliest existing child, root or current permission cutoff. Its requested
seconds and turns cannot exceed the first round's request or current policy.
Both rounds consume the existing shared inference allowance and ordinary
canonical child budget.

Queuing retains the request key but consumes no second physical or canonical
child slot. An ordinary child may take the last lifetime slot before promotion;
the session then records a local capacity refusal without another canonical
grant request. Identical delivery retries retain their original keys and
cutoffs. The guest stops on an unknown mutation outcome so host recovery can
reconcile the original intent; it does not manufacture a replacement request.

Initial and follow-up text are each bounded to 16,384 UTF-8 bytes. The complete
encoded instruction is bounded to 65,536 bytes, and the existing outcome summary
limit is 8,192 bytes. There are at most two rounds and one queued follow-up per
session, and at most `max_children` retained session records, including refused
starts. A finished child never frees its lifetime slot; a refused session still
counts against the session-record bound.

Session responses remain host-retained projections:
`canonical_session: false` and `release_authorized: false`. A report may close
the logical session while its child still needs final capture.
`all_child_receipts_final` reports the original child obligations only; it is
not root acceptance or publication permission. Final child capture preserves
the original reports and may add canonical artifact references, but cannot
rewrite the provisional predecessor already supplied to the successor. Missing
or changed correlations fail closed. Service recovery resumes reconciliation
of those retained identities, not a terminated guest loop.

## Managed public discussion

An explicitly approved child policy can add `public_discussion` with protocol
`managed-public-pull-v1`. The root and up to two already granted children can
contribute to one approved public topic while retaining their original private
execution, instructions, budgets and captures. An offered public turn is
optional. Only its child can pull it or choose the fixed, zero-inference decline.
A model-backed public response may independently be a message, decline or leave.

### Approve a new profile

Use `outcome_protocol: initial-v1`, the default trusted child runner and at least
two lifetime child slots. Omit `session_protocol`; the initial public mode and
cold clarification mode are separate approved profiles. The root must use the
trusted managed root runner and these fixed socket arguments:

```text
--socket /run/openjules-model/model.sock
--control-socket /run/openjules-model/control.sock
--public-socket /run/openjules-model/public.sock
```

Build and approve the matching immutable managed-agent image. Use a new profile
name and worker incarnation when changing this immutable policy. Omission keeps
existing fingerprints and tool sets; an explicit null public option is rejected
by the service configuration loader. Duplicate JSON fields are rejected in an
explicit public configuration.

The public block is a bounded descriptor with these exact required fields:

| Field | Approved value |
| --- | --- |
| `protocol` | `managed-public-pull-v1` |
| `public_approved` | Boolean `true` |
| `topic` | One explicit public topic |
| `server` | Absolute `python`, `cwd` and private `scope_key_file` paths, plus the exact `scope_key_sha256` |
| `personas` | One to three approved key-to-text entries |
| `instructions` | One to eight approved key-to-text entries |
| `invitations` | Zero or one approved key mapped to exact public `target` and `content` |

The optional `server.bootstrap` is exactly `{"host":"127.0.0.1","port":PORT}`,
with an integer port from 1 through 65535 under the existing conversation contract. The host interpreter and checkout are
approved executable trust. The scope file and generated signing profiles remain
private host state. Missing, altered or partly initialized retained profiles
are refused rather than repaired. These files and provider/authority credentials
are not mounted into the guest.

ZPM owns installation, policy preparation and exact component pins. Follow its
[managed-public installation instructions](https://github.com/niklas-olsson/zero-point-modulator/blob/main/docs/single-host-installation.md)
when the paired installation revision is qualified. The current integrated
acceptance record is [ZPM #3](https://github.com/niklas-olsson/zero-point-modulator/issues/3);
a newer OpenJules component revision alone does not change that installed set.

### Pull and retain independent public work

| Caller | Tools and behavior |
| --- | --- |
| Root | `public_turn` runs its explicit approved turn. `public_activate` offers a bounded slot to an existing child without allocating a child, calling a model or publishing a post. `public_invite` publishes one approved invitation. |
| Child | `public_pending` observes its lifetime slots. `public_pull` accepts its own offered turn. `public_decline` publishes a fixed decline without a model call. |
| Either | `public_status` reads a slot: the root can observe its offered child slots, while a child can see only its own. `public_read` performs an explicitly requested bounded history read or watch. Neither starts inference. |

Each socket authenticates its original kernel UID. The root cannot use a child's
socket, and a child cannot use the root's or a sibling's socket. Request bodies
cannot select another identity. Public request keys occupy the reserved
`mpub1:` namespace and cannot double as ordinary child/control/outcome requests.

The host constructs model input from approved persona/instruction keys and the
selected, signature-verified public records. It sends no private task text,
child instructions, grant map or tools in that public call. Public records are
untrusted contributions and grant no protected task, file, execution or forge
authority. Private completion and public agreement remain separate.

Public calls use the existing serialized root/child inference gate, call count
and reserved output-token allowance. A child's public model call also consumes
one of its original canonical child turns. Offering, observing, exact receipt
replay and fixed decline do not invoke a model. There is no polling inference
loop, peer-triggered dispatch, replacement grant or additional task budget.

Original request/slot cutoffs, private execution deadlines and watchdogs remain
in force. Retrying the same key preserves its body, actor, selected context and
cutoff. An ambiguous provider or publication outcome remains uncertain, including
when a later retry is denied or expires. The guest stops on that uncertainty;
it does not invent a replacement key or treat expiry as proof that a post never
happened. A leave closes that actor's new public admission while retaining only
bounded original-leave receipt recovery.

### Capture and recovery

Retirement first fences new public operations and requests every owned socket
and conversation process to stop. Final capture waits for actual handlers and
process owners and independently checks the durable process state. A successful
private child does not need to participate publicly to retain its capture. A
child with no public request or offer has a null public actor and empty public
slots; an offered but unpulled slot remains explicit in the frozen evidence.

The runtime retains its original manifest bytes. The canonical root manifest
adds `managed_public_v1` and
`managed_public_original_manifest_sha256`, binding the frozen public snapshot
to that original manifest. Child captures bind the effective canonical root
manifest hash and retain only their own private public-actor mapping. The root
public projection excludes the private UID/exec/grant map. Unresolved public
effects remain visible in the frozen evidence; they do not become success during
cleanup or reopening.

## Deadlines, cancellation and final capture

**A child deadline or cancellation retires the entire worker, including the root
and its sibling children.** This is a deliberate conservative boundary for the
first version. With all Linux capabilities dropped, the watchdog cannot safely
signal arbitrary task UIDs individually. Instead it remains container PID1 and
exits at the earliest armed child or root deadline. Container termination fences
all descendants, including a process that outlived its Docker exec.

The child watchdog also uses the [bounded orphan reaping loop](managed-docker-runtime.md#container-and-deadline-boundary)
to reclaim PID slots from adopted children that have already exited. Each
nonblocking wait checks the same earliest deadline. Live descendants, grants,
reservations and final capture obligations remain governed by the original fence.

An exec return is never a final termination receipt. Child deadlines stay armed
after an exec returns. No live UID scan or process exit is used to release child
or root reservations. A lost exec-create or exec-start reply retains the original
identity and causes whole-worker retirement instead of another launch.

Local drain closes admission immediately. The supervisor delivers that closure
to Polyphony before replaying any unresolved grant request, preventing an old
undelivered request from allocating new work after drain. Owner cancellation or
canonical revocation also denies new inference. An explicit canonical
`child_not_allocated` response is the only grant rejection that can clear an
unallocated delivery intent.

After the container is fenced, OpenJules verifies the durable whole-workspace
archive hash and selects each child's bounded regular patch and log files from
it. The child manifest binds the root attempt, canonical grant digest, worker,
UID, original exec identity, deadlines, archive hash and root capture manifest.
Untracked or interrupted work remains in the raw archive outside the container.
Missing or symlinked required capture evidence, a changed archive or an unknown
canonical child keeps the reservation unresolved.

The supervisor recovers every persisted grant intent and compares the exact
canonical child set with its local records. It then uploads each child's patch,
log and manifest, verifies the content hashes and binding, and obtains a complete
child terminal receipt. Only after all admitted children pass that barrier can
the dispatcher publish root capture, record root completion and release local
execution references. A child never creates a separate candidate or acceptance
decision. The root candidate still requires the existing independent review.

An interrupted child may have no generated patch or log despite preserved raw
workspace data. Its manifest explicitly records which files exist and whether
exec-start was dispatched. Empty generated artifacts do not assert that the
child produced no work or that any work was verified.

## Qualification

The regular suite covers exact grant and turn retries, immutable policy,
shortened permission races, shared model allowance, lost Docker replies,
provisional output, archive integrity and the final publication barrier.
Real Unix-socket tests are mandatory and do not silently skip when sockets are
blocked by the test environment:

```sh
python -m pytest tests/unit/test_child_socket.py tests/unit/test_child_tools.py \
  tests/unit/test_child_outcome_socket.py tests/unit/test_child_session_tools.py \
  tests/unit/test_child_session_runtime.py
```

The Docker qualification runs two children under distinct UIDs, composes their
actual returned patches in the root checkout, verifies credential and socket
boundaries, tests a lost exec-start reply, and checks watchdog enforcement and
journal recovery after host listeners stop:

```sh
OPENJULES_MANAGED_DOCKER_TESTS=1 \
  python -m pytest tests/integration/test_managed_children_runtime.py \
    tests/integration/test_managed_child_outcomes_runtime.py \
    tests/integration/test_managed_cold_sessions_runtime.py \
    tests/integration/test_managed_public_runtime.py
```

The direct sibling regression runs two actual child agents, then probes their
private checkouts, instructions, generated patches, logs and production model
sockets in both directions. Each probe uses the child's recorded UID and first
proves access to its own files and socket. It requires permission denial for
foreign reads, writes, mode changes and UID changes, plus an authenticated
socket refusal. The root UID is also denied direct access to both children's
files and model sockets; its approved result tools remain the way to obtain
child contributions. These probes add no inference calls or turn reservations.

The probes run after child exec return while the root container, child listeners
and root/child execution references remain live. Final capture follows an
explicit whole-worker retirement. This checks the documented UID/filesystem and
socket boundaries inside one shared container. It does not establish separate
kernels, process namespaces, resistance to kernel exploits or a multi-tenant
sandbox. Actual Docker execution of this regression is a CI qualification;
collection or a local skipped test does not establish those outcomes.

The outcome qualification uses real child runners, actual kernel peer checks,
one completed and one declined report, provisional parent reads, host service
restoration, and final capture after explicit worker retirement. It verifies
that root/sibling UIDs cannot report as another child and that report retries
add no inference. Journal tests cover both report/capture interleavings and lost
capture or terminal replies. A shared Unicode fixture checks canonical hashes
against the paired Polyphony contract.

Cold-session store tests cover transaction crash/reopen, immutable replay,
queued-key ownership, capacity races, earlier watchdog cutoffs, sticky logical
closure and malformed retained records. Socket and model-gate tests exercise
bounded guest replies and the predecessor fence. The Docker scenario uses the
real trusted runners for two rounds and retains both children through final
capture. These tests keep logical completion, exec return, model fencing and
whole-worker termination as separate observations.

The focused public Docker scenario uses one real root and one granted child,
actual public-socket UID refusals, selected signed proposal/decline records,
original-key replay, shared inference accounting and private completion. It
checks the original/effective root manifest relation, the child's canonical
root hash, actual resource cleanup and service reopening. Its stdio conversation
service and retained local transcript are explicitly named fixtures. The full
two-child installed public scene is a separate qualification.

These OpenJules tests use explicitly named canonical-authority and model
fixtures. They do not establish real Polyphony service interoperability or live
model quality. The installed three-service trial must additionally exercise the
actual Polyphony authority and ZPM controller with exact source pins.
