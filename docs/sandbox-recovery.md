# Command deadlines and retained sandbox work

This guide describes the standalone `SandboxManager` in
[src/sandbox/docker_driver.py](../src/sandbox/docker_driver.py), originally
introduced as bounded command-exchange and capture-before-cleanup work for
[OpenJules #4](https://github.com/niklas-olsson/OpenJules/issues/4). The procedures
below retain that manager's local accounting and trusted capture acknowledgement.

Managed installations use the separate [managed service](managed-service.md) and
[managed Docker runtime](managed-docker-runtime.md), with durable journals,
profile-specific confinement, capture and explicit host cleanup. Use those
guides for managed workers; the standalone capture flag below is not their
canonical capture or cleanup receipt.

## Command outcomes

`exec_in_sandbox` applies a monotonic deadline to the SDK exchange that creates, starts and inspects a command. A successful result requires an explicit integer exit code and `Running: false`. A missing exit code is an unknown outcome, even if the Docker HTTP request returned successfully.

At deadline expiry the manager attempts to stop the entire sandbox, so descendants are included when the runtime completes that stop. It raises `SandboxExecTimeout` and reports whether a subsequent container observation confirmed termination. A failed or delayed Docker reply, or exhaustion of the pending-exchange limit, can leave termination unknown. The manager never translates that uncertainty to exit code zero or launches a replacement.

The stop/reconciliation exchange has its own bounded wait, `operation_timeout` (five seconds by default). This bounds the client's wait; it cannot force an unavailable Docker daemon to prove termination. Command duration can therefore be followed by this bounded cancellation wait.

Timed-out or uncertain containers are quarantined for that manager's lifetime. Further command requests are denied. Pending SDK calls retain their exchange slots until they actually return; the default cap is sixteen. This prevents repeated failures from accumulating an unbounded number of blocked client threads. The manager uses daemon threads because Python cannot safely interrupt a blocked SDK call. A delayed exec-create reply is checked against both the original deadline and current admission before exec-start. Cleanup closes that admission too. The active-command marker remains held until both the SDK exchange and its caller have handled the outcome, so a second command cannot race uncertainty handling.

An SDK request already submitted before cleanup may still complete later. These checks do not cancel an in-flight Docker HTTP request. The pending-execution receipt therefore remains part of the cleanup barrier even after a stop is observed.

Use immutable Docker container IDs. Container names and shortened aliases do not establish the runtime incarnation required for stop and recovery.

## Cleanup facts and capture acknowledgement

`cleanup_sandbox` returns `CleanupResult` with termination, capture, container removal, workspace removal and pending-execution facts. It stops the container first. It does not remove the container or workspace by default.

A trusted caller may supply `artifact_capture_confirmed=True` only after it has durably saved and validated the necessary work. In `run_sandbox`, the corresponding field is `context.artifact_capture_confirmed`. This acknowledgement is not inferred from an exit code, passing tests, a model response or a successful stop request. The standalone [task executor](../src/worker/executor.py) has no canonical capture receipt and does not set it, so its workspaces and stopped containers are retained, including after successful tasks. Disk usage and the stopped-container count grow until an operator completes capture and cleanup. There is no retention quota or automatic garbage collection in this manager.

Destructive cleanup requires confirmed termination, no pending command exchange, and that explicit capture acknowledgement. Removal uses ordinary Docker removal, not force removal, so a runtime state race cannot silently kill a newly active container. Stop, removal or capture uncertainty retains the workspace. An absent container still does not prove that its work was captured.

`run_sandbox` records the receipt as `context.cleanup_result`. An otherwise successful context raises `SandboxCleanupError` when termination or a command exchange remains unresolved. If the body already failed, its original exception remains primary and the cleanup receipt records the additional uncertainty.

A failed create response may hide a container using the workspace mount. `SandboxLaunchUnknown` therefore exposes the retained workspace path instead of deleting it.

## Radicle publication refusal

The default legacy `RadicleProvider` has no qualified comment or patch write
contract. `post_issue_comment` returns `False` without making an HTTP request or
logging private comment text. `create_proposal` raises
`RadiclePublicationUnsupported("radicle_patch_publication_unsupported")` before
running a CLI command. Missing context, empty output and arbitrary command output
cannot produce a simulated patch ID. There is no alternate write command or
automatic retry after an uncertain outcome. Existing issue-inspection GETs and
their empty-result fallback are unchanged.

This corrects false success reporting; it does not select a replacement
transport, signing profile or Radicle release. The pinned upstream
[Heartwood patch manual](https://github.com/radicle-dev/heartwood/blob/8b053320dc3d5dc2189be3105546ed4d852b0583/rad-patch.1.adoc)
describes a Git-push opening workflow rather than the old `rad patch open`
command. The separately pinned
[HTTP repository router](https://github.com/radicle-dev/radicle-gui/blob/efc6ae961fb4530f3adef68d8bcca61293888d75/explorer/crates/radicle-httpd/src/api/v1/repos.rs)
exposes issue reads, not the old bare comment POST. Neither reference establishes
an installed OpenJules write adapter. No new workflow or response grammar is
adopted here.

The task executor's comment wrapper preserves the provider's boolean result;
its status messages remain best effort. Task execution is not a preflight-only
operation: local model/Git work and the ordinary branch push can already have
occurred when proposal creation refuses. That refusal follows the existing
error path, returns `False`, marks the legacy backlog `error` and releases its
batons. It never announces an opened patch or acknowledges artifact capture.
The sandbox cleanup rules above therefore retain the uncaptured work, including
when termination remains uncertain. Refusal does not roll back earlier effects
or make replay safe. Inspect the original repository and retained workspace
before deciding what to do next; older versions may have attempted publication
even when their output was lost or fabricated.

Regression checks use controlled HTTP reads and the real sandbox lifecycle with
fixture Docker replies. They check write refusal, malformed/lost read replies,
the executor's error result and retained workspace. They do not demonstrate a
live Radicle publication, signing configuration or qualified replacement CLI.

## Operator capture and cleanup

For `run_sandbox` callers, the retained workspace path, immutable container ID and reason are included in a warning log. Failed sandbox initialization also logs those identifiers when a container handle is known, because no context can be returned to that caller. Direct callers must record the `SandboxContext` and `CleanupResult` themselves. Preserve those identifiers until recovery is complete.

1. Stop new work for the affected sandbox. Inspect its full Docker container ID, state and `/workspace` bind mount, using the recorded identifiers. If the create reply was lost, reconcile Docker's mount inventory against `SandboxLaunchUnknown.workspace_dir` before claiming there is no live container.
2. Save the required workspace changes, logs and other outputs to durable storage, then validate that they can be recovered. Decide which evidence the task requires before acknowledging capture. Missing required output means capture remains unconfirmed.
3. Using the same manager while its process is alive, call `cleanup_sandbox(container_id, workspace_dir, artifact_capture_confirmed=True)`. Check the returned facts. A successful cleanup has `termination_confirmed`, `container_removed` and `workspace_removed` all true and `execution_pending` false. A retained workspace or an unconfirmed removal requires investigation and a later retry, not a reported success.

After a manager process restart, the operator must first reconcile outstanding execution with Docker. A fresh manager has no record of old pending exchanges. This API's capture flag is a trusted acknowledgement; it is not a durable artifact manifest or an automatic recovery service.

## Operational limits

This standalone manager's quarantine and pending-call accounting are local process state. Its restart procedure remains the operator reconciliation described above. The managed path has separate [service recovery](managed-service.md#recovery) and [durable runtime reconciliation](managed-docker-runtime.md#crash-and-late-request-handling). An operator must inspect retained work and establish capture before deleting it; this manager has no automatic garbage collection.

Existing clone-command shell interpolation, setup behavior, and configuration being loaded after initial sandbox creation remain limits of this standalone path. This manager does not establish a confined coding profile, validate admission policy, or bound the initial Docker container-create request.

Retaining a container and workspace does not guarantee recovery of an interrupted Docker exec output stream. No durable stdout/artifact capture service is introduced here. The acknowledgement must remain false when the required output is unavailable.

The original standalone component tests exercise deadline races, unknown exits, loss of Docker replies, capture gating and a real local subprocess behind a runtime fixture. That process test is not a Docker containment or sandbox-escape test. The recorded development environment for that slice had no accessible real Docker daemon. For the managed path's separate real-Docker procedure and proof limits, see [managed runtime verification](managed-docker-runtime.md#verification).
