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
Comparison order reverses on alternate repetitions. The one installed idle case
runs last, after all other 65 samples, and no sample can follow its retained
resource disposition.

The installed idle case alone uses actual sibling services, pinned to ZPM
`e8cb65ea7c1717cc5b49c1a6199960a51ac99b9f` and Polyphony
`6480e36355bf0d5de4e25a560d40e665fd76038c`, with the measured OpenJules source.
It reuses ZPM's installer and passive observation rules, supplies a finite local
dependency plan, enrolls no task and requires zero inference. Other cases use
explicit deterministic authority/model/forge fixtures and do not establish
installed canonical authority, provider quality, a live forge or a browser
execution path.

The installed worker has never dispatched a task. The existing runtime cleanup
contract intentionally retains that idle worker's stopped container and volume,
with reason `executed_capture_required`. The investigation requires this exact
native retained receipt, the original stopped container and volume identities,
observed termination/fencing/capture, zero reserved capacity, an empty canonical
task snapshot, zero inference and verified installation state. It does not
dispatch a task merely to make the worker eligible for deletion.

This final known retention is a qualified custody disposition, not physical
removal. Its safe proof and actual volume storage charge remain in the report;
the parent checks the final owned storage total against the original cap. A
missing or changed proof, another nonremoved resource or unresolved execution
still fails the sample and closes admission. No cleanup permission or production
gate changes.

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
When a process exits during a read, an absent original PID or the same PID/start
identity in a terminal state is an explicit departure exclusion. A reused PID
or an unreadable live identity remains missing. Only after an original process
or container read fails, confirmation may recheck at 5 ms spacing, up to eleven
checks per failed read, within one 50 ms recheck window shared by the observation.
For a container, each check performs one fresh Docker inspect using its original
full ID. Only that exact returned ID with explicit `Running: false` and
`Restarting: false`, integer `Pid: 0` and `Status: exited` or `dead`, or `NotFound`
for that full ID, establishes terminal engine state. Created/removing states
do not establish termination of an originally running container. A different ID,
changed running init PID, live, restarting, malformed or
unreadable state remains missing. This establishes a passive resource exclusion,
not task cancellation, capture, acceptance or release.

The original local observation client retains its 3-second request timeout.
An in-flight inspect may exceed the 50 ms recheck window; that window bounds
recheck admission, not network IO. Each failed identity receives one initial
confirmation even if another identity has already spent the shared window.
Every subsequent process or engine recheck verifies the original deadline
immediately before starting, including after scheduling oversleep; no recheck
starts at or after that deadline. Actual sampling gaps include the entire cost.
Bounded diagnostics retain original container/PID/start identity, read stage,
closed error code/errno, first and last process or engine observations, check
count and elapsed time. They contain no paths, engine error bodies or exception
text. Diagnostic truncation is explicit. No terminal confirmation means the read
remains missing.
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
sample identity, resolved original custody and a successful child exit. The
final idle case separately reports its qualified retained resources. Failed,
censored and unrun samples
are preserved. The report's `complete` field is the execution inventory result,
not approval of an optimization or release.

### Incomplete qualification checkpoints

The failed trials remain separate, with compact durable projections and original
ZIP/member digests. None of these trials completes the investigation or supports an
implementation-language or optimization decision.

| Trial | Measured revision | Native result | Retained evidence |
| --- | --- | --- | --- |
| [A, run 43647286746](https://github.com/niklas-olsson/OpenJules/actions/runs/43647286746) | `4652b02a27991666ee609c9089ce7084d953f1c6` | 16 PASS, 1 FAIL, 49 NOT_RUN; 213.939 seconds | [Trial A projection](managed-cost-evidence/trial-a.json) |
| [B, run 43649036330](https://github.com/niklas-olsson/OpenJules/actions/runs/43649036330) | `274d897e65e2615ea1628513f0a5e3fc649fd0c1` | 64 PASS, 2 FAIL; all 66 ran in 372.633 seconds | [Trial B projection](managed-cost-evidence/trial-b.json) |
| [C, run 43650444681](https://github.com/niklas-olsson/OpenJules/actions/runs/43650444681) | `8cce25a810f7319bd870429945842efb9f679e18` | 65 PASS, 1 FAIL; all 66 ran in 441.581 seconds | [Trial C projection](managed-cost-evidence/trial-c.json) |

Trial A reached six installed idle-window spans, but its helper incorrectly
required physical cleanup of a never-dispatched worker. Its failed result did
not retain the detailed window payloads or the cleanup command's response, so
the exact native refusal was not observed in that artifact. The runtime's source
and documented contract deliberately retain such idle resources. The corrected
helper records the actual retained receipt and complete windows before reporting
the final known custody disposition.

Trial B completed that corrected installed lane: all six windows, zero enrolled
tasks, zero inference, zero reserved capacity and the original stopped resources
retained. `two-workers` sample 1 and `publication-delay20` sample 3 each had one
unreadable process observation in the final resource row. Their function-level
correctness and custody checks passed, but resource measurements were incomplete
and both samples remain failed. Those reports did not retain enough diagnostic
detail to establish the exact read-failure cause.

A separate bounded local reproduction with sixteen 64 MiB Python processes
observed `PermissionError`/errno 13 from `/proc/io` while the same PID/start still
reported a running state during exit. Fourteen reported the same-identity zombie
state after 5 ms; two still reported running at that point. This supports the
bounded confirmation correction described above. It does not retrospectively
prove either failed trial's cause or relabel their observations.

Trial C observed two such process departures directly: the same original
PID/start changed from running to zombie after about 5.22 ms and 10.38 ms,
respectively. Those read failures were confirmed without missing process data.
All 66 samples ran, including the complete installed idle lane. The remaining
failure was `held-provider-cancel` sample 1, with one unreadable original-container
observation between a sampled 20,013,056-byte cgroup charge and the following
observation without a sampled container. The artifact contains no container read
stage or engine diagnostic for that failure, so its exact cause is unknown.
The cancellation/capture ordering and final custody checks passed, including
capture before the fixture provider was released; they do not repair the missing
resource measurement. Trial C remains failed. The bounded engine confirmation
and diagnostic correction above applies only to a fresh trial.

A fresh complete trial is still required. Any production optimization needs its own
correctness/recovery review and qualification.

Reproduce recorded trials from their exact investigation revision and inputs,
since later main changes intentionally fail the finite baseline check; standalone
ingress has no dependency on rerunning this investigation or changing downstream
runtime pins. Later main revisions do not inherit performance qualification from
these recorded trials.

### Durable evidence projection

`tools/managed_cost_evidence.py` preserves one original trial as compact JSON
before the workflow artifact expires. It reads only the three named JSON members
without extracting the archive, verifies the expected ZIP digest, and binds the
report's revision, production tree, manifest, recipes, image IDs and component
pins to the local Git objects and prerequisite evidence. The original public
Actions link and exact ZIP/member byte digests remain in the output.

```sh
python -m tools.managed_cost_evidence \
  --archive original-artifact.zip --archive-sha256 VERIFIED_ZIP_SHA256 \
  --source-checkout . --trial trial-a \
  --artifact-url https://github.com/niklas-olsson/OpenJules/actions/runs/RUN_ID \
  --output new-trial-a-evidence.json
```

All 66 sample identities, original ordering and statuses remain. Raw sample wall
and CPU values, counters, correctness/custody facts, capture hashes, environment,
resource maxima, observation gaps and missing evidence remain available for
independent comparison. Individual process timelines are omitted. Phase intervals
become per-phase count/outcome and wall/thread-CPU aggregates; these remain
inclusive and cannot be added into a phase partition. Unknown timing values stay
missing. Trials are never pooled and a failed trial is never relabeled complete.

The command refuses changed structural schemas and common private path or token
markers. Optional `--forbid-literal` checks add review-specific private terms
without retaining them in the output. This screening supplements independent
publication review; it does not establish that arbitrary input is safe. The
projector adds no performance conclusion or acceptance decision.
