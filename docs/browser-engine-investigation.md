# Browser engine investigation

This is the bounded standalone investigation from [#56](https://github.com/niklas-olsson/OpenJules/issues/56).
Its result applies to one declared host and confinement route. It adds no browser
service, managed execution permission, browser-local claim or engine fallback.
The distinct live-view and exclusive-input journey remains
[#58](https://github.com/niklas-olsson/OpenJules/issues/58).

## Selected inputs and prerequisite boundary

The [frozen manifest](browser-engine-evidence/2026-11-14-host-1/manifest.json)
binds the source baseline, preflight program bytes, two fixture files, host and
dependency metadata. The baseline commit is the code on which the investigation
was developed, not a claim that it already contained the new tool. The tool
digest identifies the executed preflight. The accompanying receipt binds the
complete manifest bytes. Changing a file requires a new reviewed manifest and
an unused output path; it does not update historical evidence.

| Input | Declared value |
| --- | --- |
| Host | Non-root Linux x86_64, Debian 13, kernel 6.18.57 |
| Interpreter | Python 3.12.14 |
| Python Playwright | 1.62.0, installed metadata inspected without starting its driver |
| Matching browser metadata | Chromium revision 1234, version 151.0.7922.34 |
| Other installed browser | System Chromium 156.0.8078.79, excluded as a substitute |
| Kitesurf source comparison | `4a2903813a22b08d4f3cc64a4b35339d0293a5d1` |
| Camoufox | Not selected; no Firefox-specific requirement was identified |
| Engine confinement route | Additional unprivileged user/network namespace, followed by separately verified enabled Chromium sandbox |

Matching browser metadata does not attest a browser archive or executable. Even
an executable found at the expected cache path is only a presence observation.
The command deliberately reports `browser_artifact_verified: false`. A future
browser trial must freeze and verify the acquired artifact and all dependencies
before launch. It cannot replace the declared browser with a system installation.

The preflight allows zero acquisition bytes, page sessions, page actions and
model calls. It can start exactly one fixed namespace probe, with discarded
stdout/stderr, a five-second wait and a one-second bounded cleanup wait. Its
30-second total envelope reserves two seconds for cleanup and failure evidence.
Reports are at most 64 KiB and use an exclusively created mode-0600 file.
Existing reports cannot be overwritten, including by a concurrent invocation.
A timeout without confirmed child reaping remains unknown; it is never cleanup
success. No Docker executable or alternative confinement route was available
on the selected host. No privileged setup is attempted.

## Reproduce the prerequisite observation

From the reviewed checkout, using the declared interpreter and installed
Playwright metadata:

```sh
python3 tools/browser_engine_preflight.py \
  --manifest docs/browser-engine-evidence/2026-11-14-host-1/manifest.json \
  --output /path/to/new-private-parent/preflight.json
```

The output parent must already exist. The command neither downloads a dependency
nor creates browser state. Exit 3 means a retained selected-host no-go; exit 2
means malformed, changed or unavailable inputs/output, or an incomplete deadline
result. Exit 0 means only that the tested prerequisites were observed. It never
means a browser is ready or that its sandbox, authentication, fixture task or
control flow has passed. A different host fails this manifest; record a new
reviewed input declaration rather than modifying the old receipt.

Component tests use mocked child processes and do not perform the namespace or
browser trial. The real single preflight receipt is recorded separately below.

## Adapter contract for any subsequent trial

This table specifies a future harness seam, not an implemented endpoint or
canonical authority. A backend owns the one original engine connection; a viewer
never receives raw CDP, a Playwright handle, or runtime credentials.

| Operation | Bound inputs and result |
| --- | --- |
| Open | Original synthetic run/session key, exact approved engine and clean disposable profile, two fixture origins, finite deadline/actions/output bounds. Return explicit unsupported or refused when any prerequisite is absent. No automatic engine substitution. |
| Observe | Same original session, target and document generation; bounded frame sequence/time/viewport and stale indication. Observation never grants input. Viewer disconnect preserves backend ownership; backend loss reports lost/unknown. |
| Action | Original request key, actor rights, control and document generations, one allowed bounded action. All mutation routes pass through one gateway. Preserve an unknown dispatched outcome after a lost reply and refuse replay. |
| Stop | Fence further mutations using the original identities, then report confirmed, pending, failed or unknown teardown. Preserve already captured output; a timeout cannot create a replacement session. |
| Result | Return the same retained bounded bytes and checksums after reload, without resuming work or renewing rights. A fixture receipt is not canonical managed capture or acceptance. |

The selected future attachment is one operator-local HTTPS origin serving its
client and authenticated gateway with verified TLS. The engine/fixture network
is separate and restricted to two controlled origins. Before execution, #58's
scoped, expiring, single-use pairing flow, Host/Origin/CSRF checks and all-egress
restriction must be implemented and reviewed. A navigation allowlist alone is
insufficient for redirects, subresources, resolved destinations or WebSockets.
No client attachment, cookie behavior or browser local-network permission was
exercised by this preflight. Same-origin success would not qualify a separately
hosted public client.

The fixture task compares Alpha's standard total 125, its JavaScript-updated
express total 132, and Beta's total 118. The expected differences are 7 and 14.
The two files are inert inputs until a qualified confined harness serves them at
the declared fixture origins. Their source values are an independent expected
oracle, not evidence that a browser visited or computed them. The later journey
allows one session, ten semantic actions, five minutes and 16 MiB output, with
three predeclared attempts per viable candidate. Those journeys remain NOT_RUN
when prerequisites stop the investigation.

## Source comparison and decision rule

| Capability | Pinned Chromium/Playwright | Pinned Kitesurf |
| --- | --- | --- |
| Available in this host preflight | Package/browser metadata can be inspected; actual matching binary and sandbox must be checked separately | Source inspected only; no engine installation, account or Worker runtime started |
| Stable embedding | Playwright is the selected first harness adapter; no production adapter is added here | [`embed.ts`](https://github.com/cloudflare/kitesurf/blob/4a2903813a22b08d4f3cc64a4b35339d0293a5d1/packages/engine/src/embed.ts) exports the host/connection surface, so investigate an adapter before a fork |
| Admission and egress | A separate enforced fixture boundary remains required | [`EngineHost`](https://github.com/cloudflare/kitesurf/blob/4a2903813a22b08d4f3cc64a4b35339d0293a5d1/packages/engine/src/host.ts) admits by default when no hook exists; `requestBlocker` exempts top-level navigation and is not a complete origin policy |
| Observation and connection lifetime | Same-target observation is still untested here | [`connection.ts`](https://github.com/cloudflare/kitesurf/blob/4a2903813a22b08d4f3cc64a4b35339d0293a5d1/packages/engine/src/cdp/connection.ts) owns browser/context/target state per backend WebSocket and tears it down on close/error; a second connection does not establish observation of the original session |
| Input fencing | Gateway generation, queue and in-flight-effect handling belong to #58 | [`input.ts`](https://github.com/cloudflare/kitesurf/blob/4a2903813a22b08d4f3cc64a4b35339d0293a5d1/packages/engine/src/cdp/input.ts) returns success without fencing for `Input.setIgnoreInputEvents`; its acknowledgement cannot establish exclusive input ownership |
| Retention and recovery | Not exercised | Not exercised; no inference from hosted Chrome handoff products |

There is no measured compatibility or cost advantage that justifies a Kitesurf
fork in this investigation. Keep ordinary pinned Chromium as the first proposed
adapter and preserve the current managed runtime's networking prohibition.
Kitesurf remains a source-level embedding candidate. Neither candidate gains
production support from this comparison. No Kitesurf code or binary is copied;
its Apache-2.0 attribution and dependency-notice requirements remain relevant to
any later reuse. No Camoufox/browser binary is distributed by this change.

## Recorded outcome

The [single actual receipt](browser-engine-evidence/2026-11-14-host-1/preflight.json)
has SHA-256 `49e49abaed1af773502be906066a3e9a2790cbb5105a9645d55f5b6d99a41c28`.
Its manifest SHA-256 is
`b75e7064ab6000d2b6b7a65fffa3d19b7ff553cb044feb700adf3fc1141bbb46` and tool SHA-256
is `d0989a7302f39431d0f2c0550e0198e8221754625de1dfe4ca3428b3c21797d6`.

| Observation | Actual result |
| --- | --- |
| Real and effective non-root identity; declared host | Observed |
| Installed Playwright and matching browser metadata | Exact expected metadata observed |
| Expected matching Chromium cache executable | Missing; no system-browser substitution |
| Fixed user/network namespace probe | Exit 0; child reaped; 3.648 ms |
| Complete preflight | 8.505 ms; selected-input no-go, exit 3 |
| Browser acquisition, sessions, actions, inference | Zero |
| Sandbox, fixture journeys, real client attachment, takeover, retained browser result | NOT_RUN |

Independent reviewer `/root/project_journey` reviewed the exact inputs and code,
challenged privilege checks and bounded timeout recovery, and independently ran
all 13 component checks before the one probe. The [review declaration](https://github.com/niklas-olsson/OpenJules/issues/56#issuecomment-6879002690)
precedes the experimental effect. No retry was performed.

**Decision for these inputs: no-go without acquiring the missing browser.** This
is a refusal of this zero-acquisition input set, not a failed Chromium sandbox or
a general host/engine rejection. Namespace creation was observed successfully.
The next concrete step is to declare and independently review a finite matching
browser acquisition and enabled-sandbox probe before any download or page
launch. The current receipt must remain unchanged. Missing installation alone
does not establish an outside blocker when approved acquisition is feasible.
No engine fork is justified, and production managed networking remains unchanged.
The browser investigation and #58 stay open while that next step is assessed.
