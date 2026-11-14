# Managed cost decision: retain the current implementation

The finite investigation in [issue #55](https://github.com/niklas-olsson/OpenJules/issues/55)
is complete for its declared inputs. **Retain the current Python implementation,
source-reuse contract, capture bounds and durable publication protocol.** This
trial establishes a reproducible baseline and identifies costs worth attributing
before any optimization. It does not justify a language rewrite, relaxed
recovery guarantees or a production performance claim.

[Trial D, run 43652475123](https://github.com/niklas-olsson/OpenJules/actions/runs/43652475123)
passed all **18 cases and 66 samples** in **419.541 seconds**, after a separate
70.603-second prerequisite acquisition/build. There were no failed, censored or
unrun samples. The installed idle case ran last and closed admission with
`qualified_idle_retention_closes_admission`. Its original stopped worker and
volume remain in qualified custody; they were not physically removed.

Every result below comes from D alone. The failed A/B/C trials remain unchanged
in the [investigation guide](managed-performance.md#incomplete-qualification-checkpoints).
The [durable D projection](managed-cost-evidence/trial-d.json) contains all raw
sample values, phase aggregates, counters, correctness facts and resource
coverage. The [original artifact](https://github.com/niklas-olsson/OpenJules/actions/runs/43652475123/artifacts/14137026160)
also contains the full recorded observation timelines while it remains available.

## Exact scope and environment

| Input | Qualified value |
| --- | --- |
| Native investigation revision | `04a172b7121c35d492f9ce137ccd4880494cb8d8` |
| Native investigation tree | `9156c2e784ff13ed73dbe8e87c438858849f4f5b` |
| Unchanged production baseline | `037fab5d37d2dfc11e2fe212cf2bc409467ee2de` |
| Production `src` tree | `3ff2ef1cd42cf3c5c394e086eb395be18f3d5795` |
| Installed ZPM | `e8cb65ea7c1717cc5b49c1a6199960a51ac99b9f` |
| Installed Polyphony | `6480e36355bf0d5de4e25a560d40e665fd76038c` |
| Manifest SHA-256 | `a14051cce860ddac43a914cb03dcb8c836e57d43afd41eb8516c63a301856ccb` |

The host was Linux x86-64, four reported CPUs, Intel Xeon Platinum 8573C,
kernel `7.0.0-1017-azure`, CPython 3.12.16 and local rootful Docker 28.0.4,
with cgroup v2, `systemd` cgroup driver and `overlay2` storage. The work filesystem
reported `ext2/ext3`, with 4,096-byte blocks/allocation units. No alternate Docker
host or user-namespace topology was qualified.

The retained agent image ID is
`sha256:9edda28a59adc272d5edf2db377e0273dccffe5e35690dae0ab6c041f4b8176d`;
the runtime fixture image ID is
`sha256:04f40e14bae564b9d44e5fe0b15787b2585c0c70a2473beaa264d073b66f11e5`.
Both unchanged recipes used the explicitly resolved base
`python@sha256:5e2bdb1b0d542d5039cffb8181c65930093949194a65c365dfb1b0fe13a4fa5b`.
Recipe hashes, dependency versions and finite installation inputs are retained
in the projection. These locally built images have no registry `RepoDigests`;
this investigation does not publish a runnable distribution.

Root, child, capture and control cases executed actual Docker workloads on that
host. Model, authority and publication responses were deterministic fixtures;
publication exercised real local HTTP and native Git. Only the idle lane ran
the pinned installed services. No live model inference, browser runtime,
canonical project task journey, live forge or WAN was measured.

## Complete sample inventory

Values are **median [minimum, maximum]**, in milliseconds, over five independent
fresh processes where `n=5`. A single observation has no distribution claim.
Wall time includes the case's fixture setup and cleanup after identical recorder
preparation. User/system CPU below is the case process's own interval, including
its server/broker threads. System CPU is kernel CPU charged to that process;
guest CPU, shared Docker-daemon work and unrelated kernel work are excluded.

| Case | n | Wall ms | Self user CPU ms | Self system CPU ms |
| --- | ---: | ---: | ---: | ---: |
| Source cold/reuse | 5 | 90.791 [89.487, 95.731] | 7.104 [6.193, 7.287] | 3.181 [3.011, 4.010] |
| Root | 5 | 3315.692 [3276.332, 3530.307] | 417.445 [396.263, 514.135] | 81.072 [52.107, 84.194] |
| Root, phase hooks disabled | 5 | 3274.073 [3266.808, 3284.200] | 402.144 [387.616, 428.170] | 83.657 [60.876, 89.753] |
| Two fresh children | 5 | 4302.597 [4253.122, 4359.963] | 1236.493 [1227.464, 1249.405] | 373.793 [366.757, 406.323] |
| Capture small | 5 | 2645.538 [2635.311, 2688.451] | 64.784 [60.146, 71.437] | 17.092 [12.051, 22.127] |
| Capture medium | 5 | 2710.955 [2707.016, 2741.761] | 80.483 [76.827, 81.849] | 34.796 [33.072, 38.310] |
| Capture large | 5 | 2879.439 [2869.133, 2929.251] | 113.421 [108.862, 119.198] | 77.007 [71.761, 79.523] |
| Capture 512 files | 5 | 2929.158 [2893.375, 2967.049] | 132.603 [127.312, 135.102] | 29.041 [26.523, 31.571] |
| Publication, one blob | 5 | 1789.149 [1757.127, 1806.660] | 939.995 [923.683, 958.022] | 46.323 [44.788, 55.257] |
| Publication, 32 blobs | 5 | 2703.000 [2667.751, 2750.771] | 1623.479 [1611.113, 1683.424] | 60.231 [55.517, 64.960] |
| Publication, added 20 ms/request | 5 | 4290.989 [4270.629, 4296.299] | 1657.787 [1639.261, 1668.954] | 70.471 [56.380, 74.773] |
| Publication, added 100 ms/request | 5 | 10600.469 [10584.243, 10617.860] | 1710.307 [1682.515, 1731.412] | 79.124 [70.505, 90.700] |
| Lost draft reply/recovery | 1 | 2552.420 | 1524.102 | 47.605 |
| Two active roots | 1 | 3511.575 | 776.369 | 208.569 |
| Held provider, wrong UID | 1 | 697.206 | 92.880 | 10.103 |
| Held provider, original cancellation | 1 | 3165.370 | 313.802 | 47.740 |
| 1,000 empty hook intervals | 1 | 4.919 | 3.920 | 0.994 |
| Installed preparation, six idle windows and retirement | 1 | 162445.843 | 2050.526 | 599.388 |

The last row's CPU belongs to the harness process, not the installed services;
their idle observations are separated below. Recorder-level self/reaped-child
counters span a broader interval that includes recorder preparation. They remain
raw and separate in the projection. For example, their median reaped-child
user/system CPU is 57.884/18.500 ms for source preparation and 84.005/159.293 ms
for 32-blob publication. These are not isolated Git or guest CPU measurements.

## Boundary comparisons

Phase values below are medians of each sample's aggregate for that phase, with
five-sample ranges where shown. Hooks are **inclusive** and can nest or overlap;
never add them into a phase partition. Calling-thread CPU includes native code
on that thread and does not identify pure Python execution.

### Source, root and children

Cold export of the same 4 MiB/64-file source took **38.902 [38.368, 42.249] ms**;
admitted same-instance reuse took **0.208 [0.207, 0.247] ms**. All five runs bound
the same base, 66 objects, 4,197,193 reported object bytes and pack digest. Reuse
uses the existing manifest admission contract, not another full closure rehash.
It should remain available without expanding the trust given to a cached source.

Root and delegated samples began at source
`35484e0726c7e8d6bf52ee206135ebd0326a98b6` and independently reconstructed the
same final tree `af236a29badca4085d4f2c9ae813c4e1c0406be7`. Root/child capture,
termination, fencing, original replay and patch-reapplication assertions passed.

| Observed boundary, median ms | Root | Two fresh children |
| --- | ---: | ---: |
| Ensure ready worker, including creation | 188.103 | 135.796 |
| Container creation hook | 85.988 | 34.106 |
| Dispatch to first complete model request body | 306.337 | 302.173 |
| Dispatch to final capture acknowledgement | 2586.292 | 3716.943 |
| Aggregate runtime execute hooks | 2208.212 | 2260.152 |
| Retirement hook | 2100.414 | 2115.713 |
| Root archive capture hook | 19.564 | 39.290 |
| Fixture capture delivery | 33.039 | 104.088 |

Dispatch starts after the worker is ready. The first model body is a progress
proxy, not a first-instruction or cold-container-launch timestamp. Children add
two launch intervals totaling 278.488 ms median and two final-capture intervals
totaling 8.035 ms median. Root-only execution used two model requests and
9,335/581 actual request/response body bytes; delegation used ten requests and
45,768–45,773/2,901 bytes. Root archives were 73,216 versus 214,528 bytes. This is
a fixed-result delegation comparison, not a model-quality or parallel speedup
claim. Fixture capture delivery does not measure installed authority HTTP or
its durable-store latency.

Retirement is a substantial inclusive wall interval in both cases. The measured
[runtime source](https://github.com/niklas-olsson/OpenJules/blob/04a172b7121c35d492f9ce137ccd4880494cb8d8/src/worker/docker_runtime.py)
calls `container.stop(timeout=2)`, but this hook also includes other retirement
work. No isolated stop-wait duration was measured, so the result does not prove
that shortening a grace period would save two seconds safely.

### Capture size and file count

| Payload files | Actual archive bytes, every sample | Capture wall ms, median [range] | Calling-thread CPU ms, median | Observed Python fsync wall ms, median |
| ---: | ---: | ---: | ---: | ---: |
| 1, small | 203,264 | 18.966 [17.749, 20.320] | 5.602 | 3.579 |
| 1, medium | 4,135,424 | 39.030 [38.398, 49.083] | 17.728 | 11.221 |
| 1, large | 12,524,032 | 117.788 [107.650, 129.724] | 43.218 | 64.377 |
| 512, medium payload | 4,528,128 | 143.443 [140.084, 150.850] | 45.963 | 16.158 |

The medium variants share 4,063,232 payload bytes; tar overhead makes their
actual archive sizes differ. Their file-count comparison therefore does not
hold archive bytes constant. All remained below 16 MiB, retained the expected
patch/log hashes, replayed the same capture and verified fixture disposal.
The 18 Python-level fsync calls per capture sample cover the whole instrumented
case, not only capture; native Git, SQLite and Docker fsyncs are not counted.
No isolated copy count, compression cost or physical-write amplification was
measured. These results provide no basis for reducing fsync or capture guarantees.

### Publication and request delay

All cases used the same 32 KiB changed payload. One-blob publication has one
final child lineage; 32-blob publication has two. That topology difference is
part of the comparison. Every request/response body, including zero-delay cases,
was paced at 1,250,000 bytes/second by the local fixture.

| Publication input | Actual HTTP requests | Actual request / response bytes | Initial publication median ms | Replay median ms | Object upload median ms |
| --- | ---: | ---: | ---: | ---: | ---: |
| 1 blob, no added delay | 44 | 45,889 / 105,483 | 1068.401 | 156.456 | 116.616 |
| 32 blobs, no added delay | 78 | 50,289 / 135,541 | 1962.261 | 158.654 | 877.815 |
| 32 blobs, 20 ms/request | 78 | 50,289 / 135,541 | 3424.411 | 302.417 | 1571.831 |
| 32 blobs, 100 ms/request | 78 | 50,289 / 135,541 | 9167.002 | 869.308 | 4328.173 |

Compared with the 32-blob zero-delay case, whole-case medians increased by
1.588 and 7.897 seconds. The imposed delay alone accounts for 78 × 20 ms =
1.560 seconds or 78 × 100 ms = 7.800 seconds. This establishes sensitivity of
this local request sequence to that fixture delay. It does not measure WAN
throughput, TLS or connection-pool behavior.

Composition medians were 69.598 and 123.911 ms for one/32 blobs. Nine publication
journal saves totaled 15.129 and 15.989 ms median. The observed Git-start counts
were 100 and 206, including fixture work; the fixture Git helper's own elapsed
totals were 19.674 and 107.029 ms median. These scopes overlap and do not yield
an isolated native-Git CPU or Python hotspot. Each normal publication produced
one draft POST and no replay-created effects. The lost-reply control recovered
the original operation/commit with exactly one draft POST and 159.894 ms of
reconciliation, preserving the unknown outcome until that recovery.

## Observer overhead, controls and installed idle

Matched root pairs with phase hooks enabled versus disabled differed by
**246.107, 5.265, 63.400, 2.259 and 48.883 ms**, a paired median of **48.883 ms**
(1.496% median relative to each disabled pair). Order reversed on alternate
repetitions. Both retained the same fixture counters, import preparation and
passive resource sampler. This measures incremental hook/configuration overhead
plus run variation, not the total cost of observation. The separate 1,000-interval
loop took 4.803 ms versus 0.015 ms for its empty loop. Five noisy pairs do not
support a precise correction factor or a performance percentile.

Two roots overlapped at their first provider calls, kept distinct original
workers and finished with the expected tree. This is not shared installed
authority qualification. The wrong-UID control refused the request while the
authorized provider request remained held; its HTTP body bytes were explicitly
unmeasured, not zero. Original cancellation observed capture after **2.166370
seconds**, before provider release, and final fixture acknowledgement after
**2.170756 seconds**. `provider_connection_closed` was **false**; no provider
connection-termination claim follows from guest cancellation or capture.

Installed idle used unchanged ZPM 5-second and OpenJules 1-second intervals.
Each window retained original process/start identities and a complete controller
cycle witness. There were zero enrolled tasks and zero model-fixture requests.

| Ready target | Window | Observation seconds | OpenJules self user / system CPU seconds | Mean share of one CPU |
| ---: | ---: | ---: | ---: | ---: |
| 0 | 1 | 13.926 | 0.09 / 0.00 | 0.646% |
| 0 | 2 | 15.325 | 0.08 / 0.01 | 0.587% |
| 0 | 3 | 15.226 | 0.10 / 0.00 | 0.657% |
| 1 | 1 | 15.428 | 1.21 / 0.05 | 8.167% |
| 1 | 2 | 15.631 | 1.18 / 0.05 | 7.869% |
| 1 | 3 | 15.528 | 1.17 / 0.06 | 7.921% |

The OpenJules CPU totals are 0.09/0.09/0.10 seconds at target zero and
1.26/1.23/1.23 seconds at target one. Each other service used 0–0.01 seconds
per zero-target window; at target one Polyphony used 0.05–0.06 seconds, while
manager and ZPM each used 0–0.01 seconds. Endpoint OpenJules RSS ranged from
83,243,008 to 92,868,608 bytes across these windows. This is endpoint RSS and
self CPU, not a continuous peak, descendant CPU or attribution to polling,
HTTP, Docker, Python or any individual function.

Offline bootstrap took 41.758 seconds, readiness 16.727 seconds, target-one
convergence 5.536 seconds and retirement 2.524 seconds in this single lane.
Those phases are outside the idle windows. Final canonical task state was empty,
reserved capacity was zero, installation verification passed and the exact
native cleanup receipt retained the stopped never-dispatched worker with reason
`executed_capture_required`. The original volume's Docker-reported storage charge
was zero bytes. Neither that charge nor the released capacity proves deletion.

## Resource observations and decision limits

All **2,926** resource observations were available, with **zero unresolved
resource-read rows** and no omitted diagnostics. Five process departures and 25
container departures were positively confirmed after a read race. Each of those
five process identities retains its failed observation for all four I/O counters;
terminal confirmation does not invent counter values. One container confirmation took
106.898 ms because an admitted inspect outlasted the shared 50 ms recheck window;
the window bounds new recheck admission, not an in-flight request. No unreadable
live resource was converted to zero. Actual observation gaps had a 104.940 ms
median and a 1.650-second maximum despite the 100 ms target cadence.

| Case group | Largest sampled host RSS bytes | Largest sampled container charge bytes | Largest simultaneous mixed bytes |
| --- | ---: | ---: | ---: |
| Root | 92,925,952 | 20,320,256 | 111,247,360 |
| Two fresh children | 97,112,064 | 52,363,264 | 145,944,576 |
| Large capture | 101,511,168 | 49,147,904 | 125,231,104 |
| 32-blob publication, no added delay | 82,358,272 | 0 | 82,358,272 |
| Two active roots | 93,380,608 | 11,476,992 | 103,292,928 |
| Installed lane, including bootstrap | 360,067,072 | 4,497,408 | 360,067,072 |

Independent column maxima must not be added. Container PIDs are excluded from
the host sum, but host RSS can count shared pages repeatedly; allocations and
short-lived processes between observations can be missed. The largest observed
mixed value was 360,067,072 bytes. The installed acquisition separately reserved
536,870,912 bytes until exact ownership was known; that reservation is not a
measured peak. Final owned temporary storage plus retained volume charge was
778,569,465 bytes, within 8 GiB, not a continuous storage peak. Instrumented
HTTP bodies totaled 4,086,201 bytes; this excludes the explicitly unmeasured
wrong-UID fixture and does not equal network or acquisition traffic. The
179,306,496-byte manifest transfer reservation is a separate admission bound.

The projection retains **143 per-sample PID/start identity records**, each with
first/last/maximum observed `rchar`, `wchar`, `read_bytes` and `write_bytes`,
timestamps and missing coverage. As the [Linux proc documentation](https://www.man7.org/linux/man-pages/man5/proc_pid_io.5.html)
specifies, these counters include waited-for children, so identities overlap
and cannot be summed into a total or lower bound. Syscall bytes are not disk
traffic; storage `write_bytes` accounts page dirtying, not completed writeback,
and cancelled writes were not collected. No physical-I/O or write-amplification
estimate is claimed.

**No production optimization is selected.** Source reuse already avoids repeated
export work within its existing admission contract. Larger/file-heavy captures
and request latency have visible costs, but this trial does not isolate a safe
algorithmic improvement. The smallest useful follow-up candidate is function-level
attribution of the one-ready-worker idle process on the same pinned configuration,
if an agreed product CPU budget makes the observed 7.869–8.167% of one CPU
material. That would be an evaluated follow-up, not additional captured closeout
work or evidence that changing a poll interval or implementation language helps.

Investigation acceptance is all 66 declared samples passing their original
correctness/custody checks with complete observations under the finite caps;
it establishes no product service objective. Retaining Python adds no new native
FFI, IPC, build or cross-platform binary maintenance boundary. A Rust, C++ or
Wasm helper would require a separately justified end-to-end gain and a review of
portability and maintenance costs. No production algorithm, configuration or
downstream pin changed, so there is no runtime change to roll back. The optional
investigation may remain uninvoked while its evidence is retained.

This record does not replace the existing [native child and recovery qualification](https://github.com/niklas-olsson/OpenJules/blob/04a172b7121c35d492f9ce137ccd4880494cb8d8/docs/managed-children.md#qualification)
or ZPM's installed task acceptance. Reproduce native trials from their exact
investigation revision and inputs. Later main changes intentionally fail the
finite baseline check and inherit no performance qualification; standalone ingress
has no dependency on rerunning this investigation or changing downstream pins.

## Durable provenance

| Evidence | SHA-256 |
| --- | --- |
| Original artifact ZIP | `7617c60de0a5f8134811e89d1074f2ec3ce68d2cc8226f21667f0ec33010ffaa` |
| Exact investigation member, 3,562,366 bytes | `226a36fd3d9ecdc4f50dca4c75a0a0cae0b142da42256296fb9abd0c1b9e6163` |
| Exact prerequisite member | `bf7e17f57548980b406be5082be175f987398c9ac8c757ce1ff0240517b47eb4` |
| Exact acquisition member | `a595f0771462287fcb669e03c43a7a817a8200caeee9a72ce8bd174a9ac15905` |
| Durable D projection, 820,008 bytes | `4cc44b132088cd8ed0adbc069f874a9014839e074102e0c2679778d546f3aef9` |
| Later postprocessing tool file | `186db2cdb2a91796f8aa468b23d62347b9b3584e180434bfd221cc8be2edf34e` |

The native trial ran `04a172b...`. Its unchanged archive was later projected
using the separately identified tool above, which adds durable per-identity I/O
and separate component-memory summaries. That postprocessing was not native
execution and did not require a new trial. A/B/C projection bytes remain intact.
The [projection instructions](managed-performance.md#durable-evidence-projection)
describe exact archive verification and the limits of privacy screening. No
source payload, credential, private path or binary guest archive is published.
