# Experimental standalone host signals

OpenJules can consume Polyphony's experimental host-resource advice through an
explicitly injected MCP caller. The first slice of
[#52](https://github.com/niklas-olsson/OpenJules/issues/52) corrects that contract
and refuses unsafe compatibility paths. It does not provide a connected
production MCP transport. `swarm start` and `swarm drain` exit with status 2
before creating a registry, database or Docker client. `swarm status` only
describes an existing in-process controller; it does not reconnect to a service
or recover a previous process.

Polyphony owns signal eligibility and canonical task authority. These signals
remain resource advice. Poll results and controller observations explicitly
carry `managed_authority: false` and `release_authorized: false`. Managed
installations refuse this standalone path before reading controller state or
calling injected dependencies. The standalone HTTP/WS ingress remains disabled
under the [existing ingress boundary](managed-service.md#standalone-ingress-boundary).

## Explicit adapter and bounded results

A trusted local caller supplies `McpOutboxBridge(host_control_key, mcp_caller)`
to `SwarmCohortRegistry.register_cohort(..., outbox_bridge=bridge)`. The injected
caller must implement a bounded transport lifetime and bounded envelope
acquisition before returning. It is responsible for an explicitly selected
endpoint and credentials; the adapter does not discover a server, launch one,
retry another transport or manufacture a missing tool. The host key remains
host-owned and is excluded from worker bootstrap packages.

The consumer accepts the producer's JSON text, either directly or as one MCP
text-content block. FastMCP's optional `structuredContent.result` must repeat
that exact text. Mixed results, multiple blocks, invalid JSON, duplicate members,
nonfinite numbers, implicit success and coerced signal fields fail before any
row is returned. The whole batch is validated before host actions begin.

| Operation | Required producer contract |
| --- | --- |
| Poll | `openjules_poll_outbox(host_key, status_filter="PENDING")`; explicit `success: true`, `data` list and both authority flags exactly false. An empty validated list is a successful empty queue. |
| Acknowledge | `openjules_ack_signal(host_key, signal_id, new_status, response_note)`; preserve the original signal ID and use `new_status`. Only explicit `success: true` confirms acknowledgement. |
| Worker activity | No compatible tool exists at the pinned producer revision. The MCP adapter returns `UNSUPPORTED` without inventing a request. An empty queue proves no worker's idle state. |

Limits are 64 KiB of UTF-8 JSON text, 128 distinct signals, 64 distinct target
IDs per signal, 256 characters per identifier and 4,096 characters per rationale
or note. Producer fields must have their declared types, finite nonnegative
cost/timestamps, a bounded integer delta and `PENDING` status. Unknown or
incompatible payloads do not become an empty queue or a successful acknowledgement.

`OutboxError` exposes safe local classifications: `REFUSED` for explicit
producer refusal, `UNSUPPORTED` for an absent adapter/tool/activity observation,
and `UNKNOWN` for malformed responses or uncertain transport outcomes. Remote
error bodies and credentials are not copied into these errors or controller
results. Error text alone is not evidence that a host action did not happen.

The historical `SQLiteOutboxBridge` name remains importable only to return
`UNSUPPORTED`. Neither that constructor nor any MCP error opens, initializes or
queries a foreign database. A supplied `liminal_db_path` is refused even when
an MCP caller is also present. Existing database files are left untouched.
`InMemoryOutboxBridge` is an explicitly selected test fixture. An unset fixture
activity count is unknown, not zero.

## Attempt correlation and retained uncertainty

Before each host spawn, stop, notification or acknowledgement, the controller
records the original signal ID and a digest of its advice payload. It keeps
those records for the controller's lifetime. A repeated ID with the same payload
returns `ALREADY_ATTEMPTED` without repeating either the host action or its
acknowledgement. A changed payload under an attempted ID requires reconciliation.

If an action may have occurred, or an acknowledgement is missing, refused,
malformed or uncertain, the controller retains `RECONCILIATION_REQUIRED` and
stops processing further signals. Subsequent reconciliation passes return that
retained result. Bootstrap, health healing and registry removal refuse a paused
controller. The registry refuses replacement under the same cohort ID and keeps
the controller when bootstrap becomes uncertain. It does not evict older signal
records to make room: after 4,096 attempted signals, it pauses before the next
effect.

Idle drain observes every candidate burst worker before stopping any of them.
Missing, failed or malformed activity observations cause no stop and no drain
acknowledgement. The MCP adapter therefore cannot automatically drain workers
against the current producer. An explicit fixture may report a known count of
zero; that is fixture evidence only.

These safeguards are in-memory correlation for the existing serial controller
flow. They are not durable operation keys or crash recovery. Trusted callers
must serialize bootstrap, reconciliation, health and removal operations. There
is no automatic unpause, replay or safe process-restart continuation. Inspect
the original signal, actual host state and producer acknowledgement separately
before resolving uncertainty; constructing a fresh controller discards this
evidence and is not a recovery procedure. Durable recovery and a production
transport remain open work in #52. This slice does not qualify the other legacy
health, reviewer scheduling or worker execution paths for production.

## Reproducible producer contract check

The CI job `standalone-signal-contract` runs the real Polyphony registered tool
functions, FastMCP encoding and a temporary producer-owned ledger at commit
`6480e36355bf0d5de4e25a560d40e665fd76038c`, with MCP SDK `1.30.0`. Consumer and
producer use separate Python interpreters and processes so that their distinct
`src` packages cannot collide. The driver checks the producer commit and clean
tracked tree, records consumer and producer source hashes, Python/SDK details,
elapsed time and the observed tool sequence. A dirty consumer checkout is
explicitly identified in its report.

The check creates one ordinary signal and deliberate producer-side historical
managed/malformed rows. It proves that executable polling excludes both
historical rows, acknowledgement refuses them without changing their stored
bytes, and a wrong host key is refused. An ordinary controller pass uses the
actual acknowledgement tool and a mock worker provisioner. Patching consumer
SQLite access to fail establishes that no direct SQL fallback was used.

Run it with environments installed from each repository's requirements:

```sh
consumer/bin/python tests/contracts/check_host_signals.py \
  --polyphony-checkout /absolute/path/to/pinned-keystone-polyphony \
  --polyphony-python /absolute/path/to/producer/bin/python \
  --work-dir /absolute/path/to/new-private-contract-directory
```

The directory must be new. The driver bounds each producer subprocess to at
most 30 seconds and the complete contract to 180 seconds. Requests are limited
to 16 KiB; the producer checks its response before writing it, and the driver
refuses captured stdout above 256 KiB or stderr above 64 KiB. CI uploads only
`report.json`, not the ledger or host key, for 14 days. There are no model calls,
real worker/container actions, production connector, native service-stack or
browser-demonstrator claims. Unit fixtures separately exercise malformed
envelopes, activity uncertainty, attempted-action recovery and managed refusal.
