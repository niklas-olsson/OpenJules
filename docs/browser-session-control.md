# Standalone browser session components

`src/browser_session` implements a bounded session interlock, request
authentication, an injected HTTP application and a static same-origin client
for the first standalone [#58 slice](https://github.com/niklas-olsson/OpenJules/issues/58).
It does not launch a browser or HTTP listener, or enable existing standalone
task routes. Component tests use a deterministic adapter and in-process ASGI
requests. The client model also has an optional deterministic Node fixture.
These tests make no browser, website, model or TLS effects and do not qualify
the client's real rendering or browser interaction.

The accepted slice permits source work independently of native qualification.
The selected hosted prerequisite route remains **NO_GO**. The
[browser-engine investigation](browser-engine-investigation.md) records that
route and its limits. No local record, injected adapter, TLS flag or passing
component test substitutes for the required native confinement and egress
qualification. The full #58 issue remains open for its real session and client
journey.

## Ownership and interfaces

The trusted host owns one adapter, one session, one context and one target. It
creates `SessionControl` with a fixed `SessionSpec`, starts `supervise()` in its
own task independently of client polling, and drives the bounded dispatcher
through `execute_next()`. These components are separate from managed execution,
Polyphony authority, ZPM placement and canonical capture. A human correction is
an attributed session note, never task authorization or acceptance.

The core, pairing broker and ASGI application run in the trusted host's Python
process. Journals and retained result bytes live on that host's owned private
filesystem. The operator browser holds the opaque HttpOnly cookie; JavaScript
receives only the CSRF nonce and authorized projections. There is no inference
in this composition. The source
gates cover Linux Python 3.11 and 3.12. Storage uses POSIX locks, no-follow file
opens and private modes; Windows and browser-local Python are not qualified.

| Surface | Responsibility |
| --- | --- |
| `types.py` | Closed identifiers, finite limits, exact original adapter tickets and outcomes. |
| `store.py` | Private local interlock records, exclusive ownership lock, original identity binding and bounded retained bytes. |
| `control.py` | Independent rights, current input ownership, generation fences, action intent, uncertainty, Stop and retained reads. |
| `pairing.py` | Single-use host-prebound pairing codes, opaque browser-cookie aliases and pure HTTPS/Host/Origin/CSRF request validation. |
| `http_app.py` | Fixed routes, raw-header validation, closed public projections, bounded responses and separate owner Stop capacity. |
| `client/` | Same-origin pairing, latest-frame presentation, explicit input/takeover/handback/Stop and original-result reads. |
| Future native adapter | Owned engine connection, real sandbox and egress enforcement, native action implementation, exact quiescence and teardown evidence. |
| Future qualified host composition | Actual verified HTTPS listener, native custody and confinement, independent supervision, and the real client journey. |

The native adapter protocol has three asynchronous effects. `execute()` receives
an `ActionTicket`; its `OperationOutcome` must name the original operation,
backend epoch, control generation and document generation. `quiesce()` receives
a `FenceTicket` containing every original in-flight ticket and must return their
individual outcomes, an explicit quiescence result and a fresh observation for
the new generation. `stop()` receives a `StopTicket` and returns `confirmed`,
`pending`, `failed` or `unknown` for that exact original request.

No public input receives a browser `Page`, engine connection or arbitrary
evaluation handle. Adapter injection is a trusted host seam, not an admission
mechanism. A real adapter must enforce ticket deadlines and retain custody of
native work that has not demonstrably finished.

## Independent authority and fixed deadlines

Only trusted host code calls `issue_grant(actor_id, rights)` or `revoke(token)`.
Each opaque bearer token is scoped to the original session, context, target and
actor. The journal stores its hash, never the secret. Rights are a closed subset
of `observe`, `control` and `stop`, each with its own absolute UTC expiry.

- `observe` permits bounded observations, original operation status and retained
  result reads. It does not grant input ownership.
- `control` belongs to the declared driver or human. Actual input additionally
  requires that actor to hold the current control generation and to have seen
  the exact fresh observation used by the request.
- `stop` belongs to the declared human owner. It can outlast observation and
  control rights and remains usable without either right.

Each process also retains a monotonic cutoff derived once from the absolute
expiry. Observing, reconnecting, reloading, pairing and reading results do not
renew a right, browser lifetime or retention deadline. Clock rollback refuses
ordinary access. An already valid owner Stop can still use its original
monotonic bound. Browser lifetime is at most five minutes; the host must keep
the independent supervisor running. A failed or unknown teardown remains
unknown, not evidence that the browser ended.

`PairingBroker.issue_code()` is also host-only. It binds a short-lived code to
an already issued core token and a host-selected binding right. Redemption
accepts exactly `{"code": "..."}`; it cannot choose identity, rights, target or
expiry. Redemption is serialized and consumes the code once. A lost response
does not permit replay or reissuance.

The browser receives a separate cookie alias with `Secure`, `HttpOnly`,
`SameSite=Strict`, `Path=/` and the `__Host-` prefix, plus a CSRF value. The core
token stays private. The host's future qualified ASGI server must supply the
actual connection's HTTPS scheme and uncombined raw headers, with proxy and
forwarded-header inference disabled. The application never reads forwarded
headers as TLS evidence. Exact Host and Origin, duplicate security headers,
same-origin reads and the CSRF value are checked before a protected operation.
The server chooses the route, method and required right. The returned
`AuthenticatedRequest` is a private input to a core call, not a serializable
response or a continuing authorization lease. The core rechecks authority and
payload generations at the action itself.

Bind an owner's alias through `stop` when Stop expires later than observation
or control. `GET /session` can then return the same CSRF value and original
expiry after reload, without supplying an expired observation right. The
application provides that route but does not install a live listener.

Pairing codes, cookies and local revocation intent are bounded and process-local.
Revoking one alias locally fences all aliases and pending codes for its original
grant before requesting core revocation. An unconfirmed core result keeps that
original grant fenced in the broker. Restart loses every alias and code; it
does not renew a grant or recover a browser connection.

## HTTP application and client composition

`SessionHTTP(core, pairing, origin, notify_pending=...)` receives an already
owned interlock and pairing broker. It creates no grant, adapter or background
worker. The host starts and owns one dispatcher and `core.supervise()` separately
before accepting clients. The fixed no-argument `notify_pending()` callback must
only signal that dispatcher synchronously and return promptly. If signaling fails, the
original durable queued intent remains available by operation ID; the HTTP
application does not execute it, declare it unapplied or substitute another ID.

ASGI startup/shutdown, viewer disconnect and reload do not acquire, reconnect,
resume or stop the browser. Explicit owner Stop uses the original core action.
The host retains native custody until teardown is observed or recorded as
uncertain. Closing the application or interlock alone proves no native cleanup.
There is no launcher in this source unit and no `ready` flag that admits a host.

Use a dedicated HTTPS origin with the broker's exact authority. The broker
accepts only its sole named cookie; unrelated application cookies are outside
this topology. The static client and API share that origin. No CORS, WebSocket,
DevTools, grant issuance, general file server or engine-creation route is exposed.
Query strings, alternate path encodings, ambiguous body framing and duplicate
security headers refuse. Request bodies cannot supply a TLS indicator or choose
the route's required right. Serving this ASGI object in a test scope marked
`https` does not qualify a certificate, browser trust or an actual connection.

| Route | Required right | Result |
| --- | --- | --- |
| `GET /`, `/client/app.js`, `/client/style.css` | Public fixed assets on the declared origin | Bounded reviewed client bytes; no authority or session state. |
| `POST /pair` | Host-prebound single-use code | Opaque Secure/HttpOnly/Strict cookie and CSRF nonce; no core token. |
| `GET /session` | The alias's original binding right | Original nonce/expiry and separately rechecked right availability. |
| `GET /observation` | `observe` | One latest frame, its exact identity/checksum, owner/mode, corrections and result metadata. |
| `POST /actions` | `control`, plus core ownership/freshness | Original queued acknowledgement and host-notification outcome. |
| `POST /takeover`, `/handback` | `control`, plus the core's owner/generation checks | Exact transfer acknowledgement, including unknown outcomes. |
| `POST /stop` | `stop` | Original confirmed, pending, failed or unknown Stop acknowledgement. |
| `GET /operations/<id>` | `observe` | Closed public status of the original operation. |
| `GET /stop-operations/<id>` | `stop` | Only an existing original Stop by that owner; never creates Stop or reads another operation kind. |
| `GET /results/<name>` | `observe` | Only `result.json`, `screenshot.jpg` or `events.json`: original bytes and SHA-256 header. |

Acknowledgements use an explicit field set: original operation/actor, kind,
state, generation and audit-persistence status. Internal tickets, grant digests,
adapter deadlines, request bodies and core bearer tokens are excluded. Errors
use fixed public codes, with no exception messages, private paths or logs.
All responses carry no-store, no-referrer and a restrictive content policy.

The client retains its CSRF nonce only in memory and never writes credentials to
URLs or JavaScript storage. It clears the pairing field before redemption. Each
mutation gets one original ID; a failed reply becomes unknown and is not
automatically repeated. Status reads retain that ID and stop after twenty polls.
A later ordinary reply cannot replace a newer owner Stop identity. No timeout,
reload, frame arrival or reconnect automatically hands back or resumes input.

The UI displays the original session/target, input owner, generations and frame
age. The age conservatively includes request, body-read and hashing time, and a
backwards monotonic clock cannot refresh it. Acknowledgements and observations
advance a control-generation floor; older views or lower same-generation frame
sequences cannot overwrite it. One observation fetch may be outstanding; a
separate display timer marks an old frame stale even while that fetch waits.
Input controls require the current fresh observation and human ownership, while
the server independently
checks both. Stop stays separate from ordinary input waits. Page content,
corrections and retained JSON are rendered as text, never injected HTML. Result
bytes must match both observed metadata and the response checksum before display.
Manual control does not hide input from page scripts or observation; credential
entry and private input remain excluded.

| Application bound | Ceiling |
| --- | --- |
| Raw headers | 64 pairs, 16 KiB total, 128-byte names and 4 KiB values. |
| Request body | 16 KiB, 128 ASGI chunks and one second; pairing further limits its body to 512 bytes. |
| Complete request / final send | 15 seconds total; final send also has a three-second bound within that deadline. |
| Ordinary admitted requests / response bodies | 4,096 requests, four simultaneous responses, 128 MiB total body bytes. |
| Authorized owner Stop mutations | Four requests, one independent slot, 64 KiB response-body allowance. |
| Authorized owner original-Stop reads and Stop-bound session reload | 28 requests, a separate slot, 192 KiB response-body allowance. These cannot consume the mutation reserve. |
| Individual response | 2 MiB for ordinary JSON/assets; up to the core's 16 MiB limit for an explicit retained-result read. |
| Frame retention | The core's one latest frame and one response per admitted reader; no observer queue. |

These are application ceilings, not a network denial-of-service or whole-host
memory qualification. Bounded headers and current purpose are checked before
reserving owner capacity, and the actual route rechecks authority after the body
arrives. A slow or unauthenticated session read, or exhausted ordinary/owner-read
quota, cannot spend the reserved Stop mutation allowance. Request-count exhaustion
does not renew a cookie, create a new allowance or restart the host. The actual listener,
native process-memory/disk ceilings and full transfer measurements remain part
of the unqualified host composition.

## Mediated actions and observation

All mutations use one closed catalog. `navigate` is limited to the two declared
fixture origins. `correction` records a bounded attributed note while the human
owns control. These consume the semantic-action budget. `click`, `key` and
`type` consume a separate raw-input budget and rate limit; text is charged by
submitted Unicode characters. The caller cannot choose a budget class or
relabel a navigation as another action. There is no arbitrary script execution,
storage API or general selector dispatch.

The host fixes a small set of observation field names. The adapter can supply a
bounded URL, title and scalar field projection for deterministic comparison,
along with one bounded JPEG frame. Every observation binds the original
session, context, target and backend epoch, current control generation,
document identity, increasing sequence and capture time. A document change
increments its generation. The core retains only the latest frame and no
per-observer frame queue. Old, oversized, too frequent, foreign or unrecognized
observations are refused. Queued input also rechecks freshness before dispatch.
Known-applied navigation invalidates the old observation immediately. Its
outcome remains `applied`, while further input waits for a new authoritative
observation captured in a strictly later millisecond than completion. A higher
sequence or the same coarse timestamp cannot make a pre-navigation capture
current.

| Default bound | Value |
| --- | --- |
| Sessions / contexts / targets | One of each per core |
| Fixture origins | Exactly two explicitly declared origins |
| Browser lifetime | At most 300 seconds |
| Retention deadline | At most 24 hours from creation |
| Semantic actions | 20 |
| Raw inputs / one-second rate | 200 / 20 |
| Queued intents / in-flight action | 8 / 1 |
| Total operation records, including reserved Stop slots | 256 |
| Events / current grants | 1,024 / 16 |
| JPEG bytes / frame age / frame interval | 524,288 bytes / 2 seconds / 100 milliseconds |
| Each action, fence or Stop wait | 3 seconds |
| Total retained local bytes | 16 MiB, including metadata and replacement headroom |

The typed limits may be reduced or raised only within their hard ceilings.
Session, origin, actor, expiry and resource limits are immutable after creation.
The fixture origins are a source-level action constraint. Actual browser
egress, redirects, subresources, service workers and native engine behavior
still require the independently qualified native route.

## Original operations, transfer and Stop

`submit()` binds an original operation ID to the exact request and durably
records it before dispatch. An exact repeat returns its retained outcome;
reusing the ID for different bytes refuses. Queueing and dispatch are distinct.
Grant revocation, expired deadlines, changed documents or generation fences can
retire queued input as `not_applied` before adapter I/O. Charged budgets are not
refunded by cancellation or failure.

At most one action is in flight. A timeout or cancelled Python waiter records
`unknown` and preserves the original adapter task. It does not cancel that task
as a substitute for quiescence. Late exact completion may improve original
knowledge, but cannot silently restore current ownership.

Dispatch rechecks the original grant, actor, document, control generation and
fresh observation inside the scheduled wrapper immediately before adapter
invocation. Durable intent or task scheduling does not supply permission. Each
ticket carries the earliest original action, grant, frame or browser cutoff.
Expiry before invocation records `not_applied`; faults after invocation may
have effects and retain `unknown`. A late exact result can retain its known
outcome while fencing the old input generation even if a timer callback has
not run yet. Malformed adapter receipts are uncertainty, never authority.

Takeover first increments the control generation, removes queued input and
clears current ownership. The human receives control only after the adapter
confirms quiescence, resolves every original in-flight outcome and supplies a
fresh observation for that generation within the fixed deadline. Wrong,
incomplete, contradictory or late evidence leaves input fenced. A late receipt
cannot finish a timed-out transfer automatically. Handback is explicit and also
requires a fresh observation that the human has actually received. Corrections
remain attributed and readable by the driver after handback.

Stop fences input and records a separate original request. An exact repeat does
not resend it. Only an exact adapter confirmation establishes observed teardown;
unknown, pending and failed outcomes retain that distinction. Stop is still
available to an authenticated existing owner when a journal write fails. In
that case the returned operation records `audit_persisted: false`; the core
does not claim durable teardown and never reopens input because logging failed.
Known in-memory teardown confirmation is also preserved independently of that
audit failure, so a different Stop key cannot send another native Stop to the
already confirmed adapter. A later process still reports LOST when that
confirmation was not durably retained.
Host supervisor operation IDs use a reserved `host.` prefix that clients cannot
claim. Ordinary intents stop two records below the total operation ceiling;
owner Stop requests stop one below it. The final slot is reserved for the fixed
host lifetime Stop. The smallest supported operation ceiling is two, permitting
one owner Stop plus one host Stop and no ordinary actions. These reservations
remain inside the declared total cap.

Confirmed Stop converts still-dispatched actions to `unknown`; teardown alone
does not say whether their earlier effects occurred. An exact late action
outcome can improve its original record without restoring ownership or
rewriting the already sealed event bytes.

`stop_operation(token, operation_id)` is a read-only owner Stop status path. It
requires the still-valid Stop right and an existing original Stop by that owner;
an absent ID or an ordinary action refuses. Polling neither creates nor repeats
an effect, and does not grant observation of other actions or results. Late
teardown evidence is read from the same original record, including when the
owner's observation right expired or durable audit storage failed.

## Retention and restart

The root and result directory must be owned private directories with mode
`0700`. Records and blobs must be owned regular mode `0600` files, without
symlinks or extra hard links. One exclusive local lock is held for the core's
lifetime. A second open refuses while that owner exists. The immutable local
origin record binds the original spec and backend epoch to the original root
and lock file identities. Missing, changed, malformed or replaced ownership
state does not initialize a new session.

The journal uses bounded atomic, fsynced replacement. Its current digest is
checked before replacement. Content-addressed result blobs are published
without replacement and checked by digest when read. Orphaned files and the
atomic journal replacement count against the total retention budget. Exhausted
or unavailable storage prevents new input and grants; owner Stop retains its
separate emergency path.

Trusted host capture may retain exact `result.json` and `screenshot.jpg` bytes.
Names are immutable: identical repetition is allowed, different bytes under an
accepted name refuse. After confirmed Stop, the core also seals bounded
`events.json` bytes. These are session evidence, not canonical task records.
Event capacity reserves space for safety transitions; the original operation
records remain the authority for local uncertainty when emergency event space
is exhausted.

`close()` only releases local custody; it makes no native teardown claim.
`reopen()` acquires the original lock, validates original records and result
digests, revokes old grants, fences prior queued or dispatched intent and records
**LOST**. It never attaches to an engine, infers native death or resumes input.
A deliberate new bounded host `observe` grant is required to read retained
results. Existing sealed event and result bytes remain unchanged. Expired
retention refuses access; these components do not schedule physical deletion.

## Component validation and remaining qualification

Run the source tests with the repository's supported Python environment:

```sh
python -m pytest tests/unit/test_browser_pairing.py tests/unit/test_browser_session_*.py
```

The suites cover exact intent replay, independent rights and deadlines, queue
and budget bounds, stale input, quiescence and late callbacks, human correction,
Stop despite an audit failure, local lock contention, malformed or missing
records, retained-only reopen, single-use pairing, CSRF and the actual core/auth
composition. The composition test uses real core grants and a deterministic
fake adapter. It demonstrates request-auth snapshots being rechecked by the
core, longer owner Stop, revocation and a new observe-only grant after LOST.
The HTTP suite adds actual core/auth routing, closed public serialization,
original queued-intent recovery after a lost reply, takeover/correction/handback,
Stop status after observation expiry, slow-reader separation and exact retained
bytes after reopen. The optional Node fixtures run the actual client model and
renderer with mocked fetch replies and DOM objects. They check stale-input
refusal, transit and clock rollback, bounded original-ID polling, late replies
after owner Stop, old-view generation and sequence rejection, and restoration
of a temporarily hidden frame. They open no browser or socket.

These tests establish source-component behavior only. Native engine
qualification, an actual verified HTTPS listener and real operator client, the
two-fixture autonomous task, live observation/takeover/handback, real Stop and
retained reload remain separately required by #58. This unit does not establish
browser-local execution, a local model path, managed integration, independent
distribution or the Parallax/Terrarium demonstrator.

The installed Python Playwright 1.62.0 API was inspected as source only: its
`Screencast.start(on_frame, quality, size)` callback supplies JPEG bytes,
presentation time and viewport dimensions, but no document/loader identity. It
has no `fps` argument in that version. Delayed callbacks must not be labeled with
whichever document happens to be current on arrival. A native adapter needs an
explicit reviewed interface for the original ordered backend lifecycle, frame
attribution, active-effect custody and actual process teardown. Constructing an
adapter or receiving `Page.close()` alone cannot prove sandbox, egress or process
reaping. No Playwright adapter or launch path is implemented by this HTTP unit.
