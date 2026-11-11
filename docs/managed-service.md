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

The supported entry point mounts only the authenticated worker lifecycle API.
Legacy GitHub/Radicle webhooks, PR-review event dispatch, dashboard task creation
and palette commands return HTTP 404 on this service. It does not import or start
the standalone legacy executor, poller or MCP server, or initialize an in-memory
Polyphony facade. Package exports still load the facade's class definitions.
The separate `openjules run`, `openjules serve` and `openjules mcp` commands remain
legacy interfaces. They are not managed task ingress and must not be exposed as
part of this installation. Converging or explicitly gating those standalone
interfaces remains tracked in issues #2 and #3.

Authority liveness is not managed readiness. Even when the configured authority
returns HTTP 200 from `/health`, an absent or unsupported managed protocol makes
`/api/workers/capabilities` report `managed_dispatch: false`; `/api/workers/ensure`
returns HTTP 503 without reserving or launching a worker. A previous successful
capability response does not permit later admission after capabilities change.

## Legacy PR review boundary

The separately enabled standalone webhook and direct `PRReviewHandler` refuse
feedback whose branch ends in a slash followed by exactly 64 lowercase hexadecimal
characters, or whose supplied PR body or feedback contains
`<!-- openjules-publication:`. Every current managed publication policy appends
its operation digest to a slash-terminated prefix, so the branch check also covers
custom prefixes. A `/jules` mention cannot override refusal. The webhook returns
HTTP 409 with `managed_publication_requires_canonical_review` before queuing work;
the direct handler raises `ReviewSourceRejected` before reading execution
configuration or credentials or invoking sandbox, model, commit or push operations.
Malformed review-event source values return a fixed HTTP 400 reason. Missing or
null optional PR bodies remain valid absent context.

GitHub general pull-request conversation comments use the
[`issue_comment` event](https://docs.github.com/en/webhooks/webhook-events-and-payloads#issue_comment),
which identifies the PR through `issue.pull_request` and supplies no actual head
branch for the review guard. A created comment containing `/jules run` or
`/openjules run` with that PR indicator now returns HTTP 409 with
`pull_request_comment_requires_review_event` before constructing a task or
queuing the legacy executor. An empty object is still a PR indicator. Removing
or omitting the publication marker or PR body does not enable this issue-task
path. A null or non-object indicator, or malformed source context consumed by
the triggered path, returns HTTP 400 with `invalid_issue_comment_source`.
Responses contain no supplied body, repository output or credentials.

This deliberately ends the previous behavior where a general PR conversation
run command could start an unrelated legacy issue task. Valid untriggered PR
comments and other comment actions remain ignored. Ordinary issue run commands
keep their existing payload and dispatch behavior. The actual
`pull_request_review` and `pull_request_review_comment` routes retain the branch
and marker guard above; eligible standalone PR feedback uses those existing
review events, while managed feedback requires the canonical review path.

A configured `GITHUB_WEBHOOK_SECRET` is checked before JSON parsing or routing.
The standalone webhook's existing permissive behavior when that secret is empty
is unchanged. This refusal does not turn that interface into authenticated
managed admission, and marker absence grants no managed authority. The guard
tests exercise the actual app with signed payloads and explicit constructor,
executor and forge fixtures; they do not claim a live GitHub webhook delivery.

Ordinary generated and ad hoc standalone branches retain their existing review
event flow. An ordinary branch with the same branch shape, or text quoting
the literal marker, is conservatively refused. These public signals only reject
legacy automation; their absence grants no canonical authority. A renamed branch
with erased provenance is outside this check. Legacy component initialization is
unchanged. The installed managed service still exposes no legacy review route.

This boundary does not implement managed PR iteration, authenticated canonical
webhook enrollment or convergence of other standalone entrypoints. Managed draft
feedback requires the canonical task/review path; issues #2 and #3 remain open
for the remaining ingress criteria.

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
