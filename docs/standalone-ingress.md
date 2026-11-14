# Explicit standalone task ingress

The default `src.api.webhook:app`, ordinary `openjules serve` and default Compose
service remain health/static only. An explicitly selected, enrolled host policy
enables a limited GitHub issue-task API and scoped dispatch-receipt reads. This
is the task-only positive slice of [#53](https://github.com/niklas-olsson/OpenJules/issues/53),
not completion of that issue's broader review, Radicle, cohort or private-UI work.

This API invokes the existing **trusted host legacy executor**. The API service
host owns orchestration, temporary source paths and the private local admission
journal. Guest execution occurs at the selected Docker daemon, and inference at
the explicitly configured model endpoint. The recipe here requires a local Docker
daemon: the legacy sandbox honors `DOCKER_HOST` and uses host temporary bind paths,
so a remote daemon needs separate topology qualification. Providers and other
hosts are explicit configuration choices, with no automatic mode substitution.
Existing legacy Git credentials can enter the guest clone path. This does not
qualify managed confinement, protected-task
authority, browser-local execution, a local model, public deployment or a portable
distribution. Browser/API callers receive an ingress credential with selected
grants, never a forge, model-provider, runtime-owner or journal credential.

## Supported operations

| Route | Required authority | Observed behavior |
| --- | --- | --- |
| `POST /api/tasks` | Dedicated bearer principal, `task.start`, original `Idempotency-Key` | Admits one task against an approved repository binding |
| `POST /api/webhook` | Exact-body GitHub HMAC, approved repository ID/name, allowlisted triggering actor, `task.start` | Admits a recognized issue or explicit issue-comment trigger |
| `GET /api/ingress/receipts/{operation_id}` | Dedicated bearer principal and current `receipt.read` on the original binding | Returns a closed projection of the original dispatch receipt |
| `GET`/`HEAD` `/`, `/health`, `/static/standalone.css` | None | Harmless static notice and process liveness |

All other private/effectful routes remain unavailable, even if a caller supplies
credentials. Review/PR events, Radicle, task listings/details/comments, palette
commands, cohort operations and all WebSockets are unsupported. The page has no
script, forms, bearer-token storage or private task data. It is not a task UI.
The managed installation selector still refuses standalone construction and use.

For GitHub, accepted issue actions are `opened` and `labeled` with an
`openjules` or `openjules:run` label. Both identify the same initial request by
repository numeric ID and issue number. An issue comment must be newly created
and begin with `/jules run` or `/openjules run`; its signed comment ID is the
source identity. The triggering actor is `sender.id` for issue actions and
`comment.user.id` for comments. PR markers, mixed review/event shapes and
incompatible `X-GitHub-Event` values are refused. Event and Delivery headers
cannot create a new operation or reinterpret the signed body.

## Host policy and credentials

Use a private regular policy file owned by the service UID, with no group/other
permissions, links or symlinked parent path. The policy and activation declaration
are each bounded to 256 KiB. Unknown/duplicate fields, unsupported versions,
Boolean integer aliases, malformed text and unsupported capabilities are refused.
There are at most 128 bindings and principals. This slice accepts GitHub bindings,
empty `cohort_profiles`, and only `task.start`/`receipt.read` grants. Empty grants
or operation lists authorize nothing.

The following is a template. Replace the repository name, **actual numeric
repository ID**, paths, journal ID and principal grants before enrollment:

```json
{
  "schema_version": 1,
  "policy_id": "operator-policy-1",
  "mode": "local_only",
  "transport": {"external_origin": "http://127.0.0.1:8000"},
  "receipt_store": {
    "path": "/srv/openjules-ingress/receipts.sqlite3",
    "journal_id": "REPLACE_WITH_INIT_RESULT"
  },
  "bindings": [{
    "binding_id": "approved-repository",
    "forge": "github",
    "repository": "approved-owner/approved-repository",
    "repository_id": 123456,
    "installation_id": null,
    "clone_url": "https://github.com/approved-owner/approved-repository.git",
    "default_branch": "main",
    "cohort_profiles": {}
  }],
  "principals": [{
    "principal_id": "operator",
    "authentication": {
      "kind": "bearer",
      "secret_ref": "env:OPENJULES_INGRESS_BEARER_OPERATOR"
    },
    "grants": [{
      "binding_id": "approved-repository",
      "operations": ["task.start", "receipt.read"]
    }]
  }]
}
```

Create independent cryptographically random ingress secrets in the private
service environment. Bearer references must use `OPENJULES_INGRESS_BEARER_…` and
HMAC references `OPENJULES_INGRESS_HMAC_…`, with a nonempty ASCII environment-name
suffix. These reserved names have no consumer in the qualified legacy credential
paths. A secret equal to another environment value is refused, including an
alias under a different name. Selected execution credentials and App key material
are checked separately. Never reuse, embed or substitute a forge/provider
credential. This separation qualifies the present dependency and execution path;
it is not general secret isolation from arbitrary future host code.
Admission also refuses literal current ingress-secret values in normalized task,
binding and source/key strings before retaining or forwarding that input. JSON
escapes are parsed before this check. It does not identify arbitrary secrets or
decode other representations of a secret.

To add the one supported HMAC principal, use `kind: github_hmac_sha256`, a
dedicated `env:OPENJULES_INGRESS_HMAC_GITHUB` reference, a nonempty
`github_actor_ids` list of approved numeric actor IDs and a `task.start` grant.
Do not add `github_actor_ids` to a bearer principal. Credentials identify the
enrolled principal; body fields cannot supply identity, approval or a new grant.

An explicit `installation_id: null` selects only the host `GITHUB_TOKEN` PAT
route. Missing PAT credentials never switch to App authentication. A positive
integer selects only the host GitHub App route, even if a PAT is also present;
the webhook installation must match. The host supplies `GITHUB_APP_ID` and
`GITHUB_APP_PRIVATE_KEY_PATH`. Caller installation fields cannot select a route.
The same selected execution token is injected into the provider and Git executor.

Startup snapshots credential configuration without minting a token, reading a
remote repository, constructing the executor or dispatching a task. Actual token
minting, remote identity/issue checks and executor construction follow the durable
callback claim. Frozen App key bytes are passed explicitly as raw content and
cannot be reinterpreted as a second file path. Repository numeric ID and exact
name must still match, and the
selected issue must not be a PR. A refusal after those adapter effects preserves
the attempted target fence; it is not a pre-effect refusal.

That identity check is a preflight, not an end-to-end immutable forge-target
guarantee. The legacy executor later addresses comments/proposals by approved
repository name and clones the approved URL. Keep that name and clone target
stable while callbacks or downstream effects are outstanding. A rename, deletion,
recreation or unexpected identity change requires stopping admission and original
producer reconciliation, not rebinding the existing ID or clearing its fences.

## First enrollment and deliberate launch

First activation supports only an attributable **fresh isolated repository
scope**. An empty directory, newly created database or stopped HTTP process is
not proof that old effects are resolved. If prior work is present or unknown,
keep that scope disabled. This slice has no active-state import, reconciliation
override, journal reset or migration command.

Create the private parent directory and the original journal explicitly:

```sh
umask 077
mkdir /srv/openjules-ingress
openjules ingress init --store /srv/openjules-ingress/receipts.sqlite3
```

Record the returned `journal_id` in the policy. `init` is create-only; it refuses
an existing journal or lock. Normal service startup never initializes either.
Compute the validated policy digest with the intended service environment:

```sh
python -c 'from src.api.ingress_policy import load_policy; print(load_policy("/srv/openjules-ingress/policy.json").digest)'
```

After verifying that the repository scope is fresh and isolated, the responsible
host operator writes a private declaration with these exact fields:

```json
{
  "schema_version": 1,
  "declaration_id": "fresh-scope-1",
  "journal_id": "REPLACE_WITH_INIT_RESULT",
  "policy_id": "operator-policy-1",
  "policy_digest": "REPLACE_WITH_VALIDATED_POLICY_DIGEST",
  "repositories": ["github:123456"],
  "operator": "responsible-host-operator",
  "assertion": "fresh_isolated_scope"
}
```

This is an attributed host assertion, not automatic discovery or proof about
other services or hosts. Enrollment stores its digest, operator, UID, time and
repository scope. The declaration and repository activation are create-only.
With all previous service/callback processes stopped:

```sh
openjules ingress enroll-policy \
  --policy /srv/openjules-ingress/policy.json \
  --activation-declaration /srv/openjules-ingress/fresh-scope.json
openjules serve --host 127.0.0.1 --port 8000 \
  --policy /srv/openjules-ingress/policy.json
```

Programmatic hosts select `create_app(policy_path="/absolute/policy.json")`.
The global app and `OPENJULES_INGRESS_POLICY` compatibility selector remain
status-only. A token, environment selector or HTTP flag cannot activate them.
The default Compose container remains credential-free status infrastructure;
this positive host recipe does not silently reconfigure it.

## HTTP transport and task input

`local_only` requires an exact HTTP origin with literal `127.0.0.1` or `::1`
and an explicit port, plus a loopback peer. `remote` requires an exact approved
HTTPS external origin, served directly or through a deliberately configured
authenticated TLS proxy with an isolated backend. The shown CLI is a loopback
backend only. A proxy
must preserve the approved Host and strip Forwarded/X-Forwarded headers; those
headers are not trusted and are refused. A remote policy permits that explicit
HTTP backend or direct HTTPS, but its bytes do not prove deployed TLS or network
isolation. Verify those separately before remote exposure.

Private routes require Host to equal the configured authority. Origin, when
present, must equal the configured origin; `null` is refused. Authentication is
still required. There are no auth cookies, query-string credentials, credentialed
CORS fallback or WebSocket subscriptions. Treat the ingress bearer as a private
scoped capability and send it only to the approved origin.

The operator task body has exactly these five fields:

```json
{
  "schema_version": 1,
  "binding_id": "approved-repository",
  "issue_id": 42,
  "issue_title": "Approved task title",
  "issue_body": "Approved task instructions"
}
```

Send it to `POST /api/tasks` as JSON with `Authorization: Bearer …` and an
original nonempty `Idempotency-Key` of at most 256 bytes. `issue_id` is the issue
**number** within the enrolled repository. The binding supplies the clone URL,
branch and credential route. Bodies are bounded to 1 MiB before parsing;
titles to 1,024 bytes and task bodies to 256 KiB. Duplicate/ambiguous headers,
duplicate JSON keys, malformed UTF-8 and nonfinite numbers are rejected.

## Original receipts, uncertainty and shutdown

The private local SQLite store is an admission journal, not a task ledger. It
retains the normalized admitted task title/body, approved binding and original
source/key data. Scoped HTTP receipt reads expose only the closed operation,
status, code and optional handler-return projection, not that private input.
The journal binds its original random journal ID, file/lock identity, schema and active policy
revision. One process holds the owner lock until its actual callbacks quiesce.
Missing/replaced state is unavailable. Copies, rollback, shared filesystems and
older binaries writing the store are unsupported.

| Dispatch state | What is established |
| --- | --- |
| `reserved` | Immutable admission exists; the durable dispatch fence was not crossed |
| `may_have_started` | The original fence was committed before queue registration or adapter effects |
| `returned` | The actual adapter returned a bounded observed result |
| `reconciliation_required` | Dispatch may have occurred; the original outcome is unknown |
| `refused_before_effect` | The owned wrapper proved it did not enter the adapter and recorded refusal |

Bearer keys are namespaced by stable principal ID. GitHub source identities
exclude unsigned headers and policy, principal or binding aliases. Exact replay
observes the original receipt; changed input under an existing key conflicts.
Queue saturation cannot authorize a new operation or prevent an authorized
original receipt from being observed. A separate canonical repository/issue/action
fence prevents another key or alias from bypassing attempted work.

A handler return, HTTP 2xx or receipt does not establish task completion,
termination, capture, publication, review or acceptance. Returned and unknown
operations keep their target fences. Only a proven `refused_before_effect`
operation can release its own target fence. There is no retry/reset endpoint.
After restart, interrupted dispatch stays unknown and is never automatically
scheduled again. A reserved pre-fence row can be refused safely.

Shutdown closes admission and waits for actual owned callbacks. Cancelling an
ASGI wait does not acknowledge a still-running thread. A duplicate callback
cannot release another invocation's custody. Stopping the HTTP process does not
prove that downstream Docker, model, Git or forge effects stopped. Preserve the
original journal and use the original producer's controls for uncertain work.

## Policy maintenance and validation

Stop admission and all old API/callback processes before changing policy or
rotating credentials. Credential values and the policy are frozen for one owner
epoch. An observed change latches that epoch closed, even if old bytes are
restored. A config edit is not a guarantee of immediate revocation of already
dispatched work; restart and downstream recovery remain explicit.

Use a new `policy_id` for changed policy content and the same principal IDs when
rotating secrets. Existing binding IDs cannot be reassigned to another repository,
clone URL, branch or installation route. Enroll the new policy with the service
stopped, retaining every historical receipt and target fence. A newly added
canonical repository needs its own fresh-scope declaration; an unchanged scope
does not. No maintenance action silently adopts old or unknown work.

Qualification uses real ASGI routes, exact-body HMAC, original SQLite state,
independent owner processes and controlled adapter-effect counters. It exercises
authentication/scope failures, original replay/conflict, queue failure,
process interruption, callback shutdown, rotation and missing/replaced state.
Provider/forge effects are fixtures. These checks do not demonstrate a live
GitHub task, deployed TLS, model quality, installed managed execution or browser
distribution. The ordinary Python/Docker CI suites and the pinned standalone
signal contract remain separate required validation.
