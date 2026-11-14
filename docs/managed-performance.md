# Finite managed cost investigation

The optional `managed-costs-v1` investigation measures the existing runtime,
capture and publication boundaries. It changes no production algorithm, task
policy, language, permission, deadline, fsync guarantee or supported execution
mode. It is the bounded investigation from issue #55, not a performance service
or a replacement for native correctness and installed acceptance.

## Declared inputs and cases

The reviewed input is
[`tests/fixtures/managed-cost-manifest.json`](../tests/fixtures/managed-cost-manifest.json).
The runner verifies its SHA-256 and refuses changed caps, duplicate cases,
Boolean numeric aliases, a dirty source checkout or changes to production code,
Docker recipes or the existing native fixtures relative to OpenJules
`037fab5d37d2dfc11e2fe212cf2bc409467ee2de`. The report also records the actual
investigation commit and `src` tree. The host is Linux x86-64, CPython 3.12 and
local rootful Docker without user-namespace remapping.

| Case | Fresh-process samples | Declared input and proof |
| --- | ---: | --- |
| Source cold export and admitted snapshot reuse | 5 | Same 4 MiB, 64-file synthetic Git source; reuse is not a full object rehash |
| Root-only and two fresh children | 5 each | Same approved two-file source, instruction and expected final Git tree; two deterministic root calls versus ten root/child calls |
| Root measurement control | 5 | Same root workload with phase hooks disabled; correctness, body counters and passive resource observation remain enabled |
| Root capture sizes | 5 each | Target archives near 256 KiB, 4 MiB and 12 MiB, plus a 4 MiB target with 512 payload files; actual full tar sizes are reported below the unchanged 16 MiB bound |
| Mechanical publication | 5 each | One or 32 changed blobs with a fixed 32 KiB payload; one versus two final child lineages is an explicit topology difference |
| Publication transport sensitivity | 5 each | The 32-blob case with 20 or 100 ms added per request, using the same body pacing as the zero-delay baseline |
| Original publication recovery | 1 | Lost draft reply, exact same operation/commit and read-only recovery; no second draft POST |
| Two active roots | 1 | Two original worker incarnations, simultaneous first provider calls, same resulting tree and no more than two containers |
| Held-provider controls | 1 each | Existing native wrong-UID refusal; separate original task cancellation, capture and acknowledgement before/after fixture release |
| Installed idle | 1 | Three zero-target and three one-ready-worker windows, each containing a witnessed complete ZPM controller cycle |
| Empty hook overhead | 1 | 1,000 empty intervals; this does not replace the paired native root controls |

There are 18 cases and 66 fresh processes. The aggregate declared transfer
reservation is 179,306,496 bytes and temporary-storage reservation is
3,272,605,696 bytes. Five samples support raw values, median and range. They do
not support a p95, a service objective or a claim about production distributions.
Comparison order reverses on alternate repetitions.

The installed idle case alone uses actual sibling services, pinned to ZPM
`e8cb65ea7c1717cc5b49c1a6199960a51ac99b9f` and Polyphony
`6480e36355bf0d5de4e25a560d40e665fd76038c`, with the measured OpenJules source.
It reuses ZPM's installer and passive observation rules, supplies a finite local
dependency plan, enrolls no task and requires zero inference. Other cases use
explicit deterministic authority/model/forge fixtures and do not establish
installed canonical authority, provider quality, a live forge or a browser
execution path.

## Time, resource and custody bounds

Prerequisites use the existing CI requirements and Docker recipes, with an
840-second elapsed limit and a separately sampled 4 GiB filesystem-growth
limit. The existing Python input preparer retains its own narrower limits.
Image acquisition and build are reported separately from measured cases. The
resulting exact image IDs, base digest metadata and dependency versions are
recorded; a mutable build-input tag is not an approved deployment pin.

After prerequisites, the whole investigation has an original 1,800-second
deadline, including 90 seconds reserved for cleanup. It allows two workers,
two children per root, 8 GiB owned temporary storage, 4 GiB sampled owned memory
and 512 MiB fixture-body transfer. Existing smaller execution, HTTP, socket,
artifact and publication limits remain in force.

The per-case fail-safe durations sum to 3,665 seconds. They are conservative
failure bounds, not predicted timings. Before each sample, the runner reserves
that sample's maximum duration plus cleanup time against the original remaining
trial budget. If it cannot fit, the sample remains `NOT_RUN`; an incomplete
investigation does not complete issue #55. It never renews the trial deadline
or silently reduces the declared sample set.

Sampled memory combines the simultaneous approximate RSS of the owned host
process tree with separately observed owned cgroup-v2 memory charges. Container
PIDs are excluded from the host sum. Shared pages can still be counted several
times in host RSS; short-lived processes and allocations between samples can
be missed. The target cadence is 100 ms; actual minimum, median and maximum
observation gaps include observation and Docker-discovery overhead and are
reported separately. Shared Docker-daemon and unrelated kernel costs are excluded.
Original PID/start-time bindings prevent PID reuse from changing ownership.
Unreadable live owned observations are explicit missing data, not zero memory;
persistent inability to observe owned resources closes further admission.
Before an installed acquisition returns an exact container identity, its
512 MiB configured ceiling is reserved for cap enforcement. That reservation
is reported separately and is not a measured cgroup peak.

The parent additionally discovers only managed containers whose source or
model-socket bind mount belongs to the unique private sample directory. This
read-only fallback covers a lost creation reply. Its one-second discovery
cadence is a separate limitation for very short-lived containers. It does not
adopt or remove unrelated resources.

On a cap event the runner closes new admission, requests interruption of its
owned sample and allows original cancellation, capture and cleanup paths to
run. A terminal process is not evidence of task cancellation or release.
Unresolved capture prevents fixture force-removal, keeps the sample censored
and stops subsequent admission. If the owned sample process itself cannot
return, the parent may terminate that process group after its cleanup budget;
original guest watchdogs, journals and uncertainty remain, without a claim of
successful cleanup.

## What the measurements mean

Phase hooks observe source export, Docker ensure/create/execute/retire/capture,
child launch/final capture, capture delivery, composition, publication journal
writes, object upload, requests and fsync. Each interval reports wall and
calling-thread CPU. Intervals are inclusive and may nest or overlap, so their
durations and CPU cannot be added as a phase partition. Whole-process user and
system counters include other threads; reaped-child counters have a separate
scope. Native Git subprocess counts identify dispatches, not isolated Git CPU.
Sample wall time begins after identical recorder/import preparation in enabled
and disabled controls, while the recorder's whole-process observation includes
its own preparation interval. Neither is presented as pure service time.

The root/child comparison fixes source and final result, but deliberately
changes delegation and deterministic model-request count. It does not compare
semantic model quality. Fresh helpers and child processes remain fresh; an
already loaded image or admitted source snapshot is not warm child reuse.
Separate intervals run from dispatcher admission to the first complete model
request body observed at the fixture, and to observed final capture
acknowledgement. The first body is a useful proxy for guest progress; it is not
the timestamp of the guest's first instruction.

Publication uses real local HTTP and native Git behind the existing bounded
forge fixture. Added delay occurs once per HTTP request. Request and response
body consumption is paced at 1,250,000 bytes per second, including the
zero-delay baseline. Recorded bytes are the actual serialized bodies consumed
or written at that boundary, not reconstructed JSON, TLS bytes or wire traffic.
Local HTTP server and fixture Git costs are reported separately from the client
scope where observed. This models sensitivity and does not qualify WAN, TLS,
connection pooling, remote Docker or two-host operation.

Correctness oracles retain the original identities, complete archive hashes,
root and child captures, final result tree, draft-only state and replay behavior.
The root/child cases independently reapply the captured patch and inspect only
named members of the retained tar without extracting guest paths on the host.
No benchmark report includes source content, instructions, private paths,
credential headers, token values or raw journals.

## Run and evidence

The optional workflow admits only the creation of a fresh
`qualification/costs/run/*` branch on the public repository and its first
workflow attempt. Its permission is `contents: read`, with one native trial at
a time. Ordinary owner PR CI continues to use deterministic existing gates and
does not call a model provider.

After the separately bounded setup, the direct command is:

```sh
python -m tools.managed_costs run \
  --manifest tests/fixtures/managed-cost-manifest.json \
  --manifest-sha256 REVIEWED_MANIFEST_SHA256 \
  --runtime-image sha256:EXACT_RUNTIME_FIXTURE_IMAGE \
  --agent-image sha256:EXACT_AGENT_FIXTURE_IMAGE \
  --zpm-checkout /approved/zpm \
  --polyphony-checkout /approved/polyphony \
  --dependency-plan /private/finite-python-inputs/reference.json \
  --work-dir /private/new-cost-investigation
```

Only `report.json`, prerequisite metadata and the named safe acquisition report
are retained as workflow artifacts. Raw sample work, private command logs,
credentials and binary archives remain outside the published artifact list.
`PASS` requires original case assertions, complete measurement hooks, bound
sample identity and a successful child exit. Failed, censored and unrun samples
are preserved. The report's `complete` field is the execution inventory result,
not approval of an optimization or release.

No native measurement result or implementation-language decision is claimed by
this source delivery. After the declared run, record dominant observed costs,
limitations and an evidenced change/no-change decision. A proposed production
optimization requires its own correctness/recovery review and qualification.
