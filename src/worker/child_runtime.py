"""One-level Docker exec supervision under the existing whole-worker fence.

An exec exit is provisional. Only the owning container's final fence establishes
child termination. Every child deadline remains armed until that fence.
"""

from __future__ import annotations

import io
import json
import tarfile
import time

from .child_types import WATCHDOG_UID, canonical, text_hash
from .lifecycle import LifecycleConflict, RuntimeUnavailable

CHILD_WATCHDOG = """import math,os,time
idle_deadline=time.monotonic()+86400
root_deadline=None
while True:
    if root_deadline is None:
        try:
            with open('/control/deadline',encoding='ascii') as source:
                root_deadline=float(source.read(64))
            if not math.isfinite(root_deadline): os._exit(1)
        except FileNotFoundError:
            pass
        except (OSError,ValueError):
            os._exit(1)
    deadline=root_deadline if root_deadline is not None else idle_deadline
    try:
        names=os.listdir('/control/children')
        if len(names)>64: os._exit(1)
        for name in names:
            with open('/control/children/'+name,encoding='ascii') as source:
                child_deadline=float(source.read(64))
            if not math.isfinite(child_deadline): os._exit(1)
            deadline=min(deadline,child_deadline)
    except FileNotFoundError:
        pass
    except (OSError,ValueError):
        os._exit(1)
    if time.monotonic()>=deadline: os._exit(0)
    # Reparented exited children consume the worker's PID allowance until
    # PID 1 reaps them. Live descendants retain their original deadline.
    for _ in range(128):
        if time.monotonic()>=deadline: os._exit(0)
        try:
            exited,_status=os.waitpid(-1,os.WNOHANG)
        except ChildProcessError:
            break
        except InterruptedError:
            continue
        if exited==0:
            break
    time.sleep(.05)
"""

ARM_CHILD = """import os,sys
os.makedirs('/control/children',mode=0o700,exist_ok=True)
path='/control/children/'+sys.argv[1]
fd=os.open(path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
    os.write(fd,sys.argv[2].encode('ascii'))
    os.fsync(fd)
finally:
    os.close(fd)
"""

RUN_CHILD = """import json,os,subprocess,sys
request=json.loads(sys.argv[1])
directory='/workspace/children/'+request['child_id']
run=directory+'/run'
env=dict(os.environ)
env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',GIT_TERMINAL_PROMPT='0',
           HOME=run+'/home',TMPDIR=run+'/tmp')
os.makedirs(env['HOME'],mode=0o700,exist_ok=True)
os.makedirs(env['TMPDIR'],mode=0o700,exist_ok=True)
git=['git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false']
result=1
with open(run+'/output.log','wb') as output:
    try:
        subprocess.run(git+['clone','--no-checkout','--no-hardlinks','--no-local',
            '--upload-pack=git -c safe.directory=/source upload-pack','/source',run+'/repo'],
            check=True,env=env,stdout=output,stderr=subprocess.STDOUT)
        subprocess.run(git+['checkout','--detach',request['base']],cwd=run+'/repo',
            check=True,env=env,stdout=output,stderr=subprocess.STDOUT)
        with open(directory+'/input.txt','rb') as prompt:
            result=subprocess.run(request['command'],cwd=run+'/repo',env=env,
                stdin=prompt,stdout=output,stderr=subprocess.STDOUT).returncode
    except Exception as exc:
        output.write(('Child preparation/command failed: '+type(exc).__name__+'\\n').encode())
    finally:
        try:
            subprocess.run(git+['add','--all'],cwd=run+'/repo',env=env,
                check=True,stdout=output,stderr=subprocess.STDOUT)
            with open(run+'/change.patch','wb') as patch:
                subprocess.run(git+['diff','--cached','--binary',request['base']],cwd=run+'/repo',
                    env=env,check=True,stdout=patch,stderr=output)
        except Exception:
            pass
sys.exit(result if 0<=result<=255 else 1)
"""


class ChildRuntime:
    def __init__(self, runtime, supervisor):
        self.runtime = runtime
        self.supervisor = supervisor

    def check_topology(self):
        info = self.runtime.client.info()
        options = info.get("SecurityOptions")
        if not isinstance(options, list) or any(
            not isinstance(item, str) or "rootless" in item or "userns" in item
            for item in options
        ):
            raise RuntimeUnavailable(
                "child execution requires qualified rootful Docker UID mapping"
            )

    def launch(self, root, child, permission_cutoff):
        runtime, journal = self.runtime, self.supervisor.journal
        with runtime._lock(root.worker_id) as locked:
            if not locked:
                return  # No effect; the original admitted identity remains pending.
            child = journal.child(root.worker_id, child["child_id"])
            if child["phase"] in {"running", "exec_returned", "captured", "completed"}:
                return
            if child["phase"] in {
                "arming",
                "creating",
                "created",
                "dispatching",
                "uncertain",
            }:
                journal.close_admission(
                    root.worker_id, "child dispatch outcome is uncertain", retire=True
                )
                return
            cutoff = min(
                root.monotonic_deadline,
                child["deadline"],
                permission_cutoff,
                self.supervisor.local_cutoff(root.worker_id, child["child_id"]),
            )
            if cutoff <= time.monotonic() or not self.supervisor.local_allowed(
                root, child, admission=True
            ):
                journal.close_admission(
                    root.worker_id, "child admission was revoked", retire=True
                )
                return
            row = runtime._row(root.worker_id, root.spec)
            if (
                row is None
                or row["retired"]
                or row["receipt"]
                or not row["start_confirmed"]
            ):
                journal.close_admission(
                    root.worker_id, "worker admission is closed", retire=True
                )
                return
            try:
                container = runtime._container(root.worker_id, root.spec, row)
                if not container.attrs.get("State", {}).get("Running"):
                    journal.close_admission(
                        root.worker_id, "worker already stopped", retire=True
                    )
                    return
                grant = json.loads(child["grant_json"])
                policy = self.supervisor.policy(root.spec)
                child_id, uid = child["child_id"], child["uid"]
                if child["phase"] in {"admitted", "preparing"}:
                    journal.update(root.worker_id, child_id, phase="preparing")
                    files = {
                        child_id: (None, uid, 0o700),
                        child_id + "/run": (None, uid, 0o700),
                        child_id
                        + "/input.txt": (grant["instructions"].encode(), uid, 0o400),
                    }
                    if not container.put_archive(
                        "/workspace/children", runtime._tar(files)
                    ):
                        raise RuntimeUnavailable("child workspace preparation failed")
                    cutoff = min(
                        cutoff, self.supervisor.local_cutoff(root.worker_id, child_id)
                    )
                    if cutoff <= time.monotonic() or not self.supervisor.local_allowed(
                        root, child, admission=True
                    ):
                        raise RuntimeUnavailable(
                            "child permission expired during workspace preparation"
                        )
                    journal.update(
                        root.worker_id, child_id, phase="arming", armed_deadline=cutoff
                    )
                    control = runtime.client.api.exec_create(
                        container.id,
                        ["python3", "-I", "-S", "-c", ARM_CHILD, child_id, str(cutoff)],
                        user=f"{WATCHDOG_UID}:{WATCHDOG_UID}",
                        workdir="/",
                        environment={},
                        stdin=False,
                        stdout=False,
                        stderr=False,
                        privileged=False,
                    )["Id"]
                    runtime.client.api.exec_start(control, detach=True)
                    while True:
                        state = runtime.client.api.exec_inspect(control)
                        if not state.get("Running"):
                            if state.get("ExitCode") != 0:
                                raise RuntimeUnavailable(
                                    "child watchdog admission failed"
                                )
                            break
                        if time.monotonic() >= cutoff:
                            raise RuntimeUnavailable("child watchdog deadline expired")
                        time.sleep(0.01)
                    journal.update(root.worker_id, child_id, phase="armed")
                    child = journal.child(root.worker_id, child_id)
                if child["phase"] == "armed":
                    cutoff = min(
                        cutoff,
                        child["armed_deadline"] or cutoff,
                        self.supervisor.local_cutoff(root.worker_id, child_id),
                    )
                    if cutoff <= time.monotonic() or not self.supervisor.local_allowed(
                        root, child, admission=True
                    ):
                        raise RuntimeUnavailable(
                            "child permission expired before exec creation"
                        )
                    command = list(policy.command) + [
                        "--socket",
                        f"/run/openjules-model/children/{child_id}/model.sock",
                        "--max-turns",
                        str(grant["binding"]["max_turns"]),
                    ]
                    if policy.outcome_protocol is not None:
                        command += [
                            "--outcome-socket",
                            f"/run/openjules-model/children/{child_id}/outcome.sock",
                        ]
                    if getattr(policy, "public_discussion", None) is not None:
                        command += [
                            "--public-socket",
                            f"/run/openjules-model/children/{child_id}/public.sock",
                        ]
                    if policy.verify_argv:
                        command += ["--verify-json", canonical(policy.verify_argv)]
                    journal.update(root.worker_id, child_id, phase="creating")
                    execution = runtime.client.api.exec_create(
                        container.id,
                        [
                            "python3",
                            "-I",
                            "-S",
                            "-c",
                            RUN_CHILD,
                            canonical(
                                {
                                    "child_id": child_id,
                                    "base": root.base,
                                    "command": command,
                                }
                            ),
                        ],
                        user=f"{uid}:{uid}",
                        workdir=f"/workspace/children/{child_id}/run",
                        environment={"OPENJULES_ATTEMPT_ID": child_id},
                        stdin=False,
                        stdout=False,
                        stderr=False,
                        privileged=False,
                    )["Id"]
                    journal.update(
                        root.worker_id, child_id, exec_id=execution, phase="created"
                    )
                    child = journal.child(root.worker_id, child_id)
                if child["phase"] == "created":
                    cutoff = min(
                        cutoff, self.supervisor.local_cutoff(root.worker_id, child_id)
                    )
                    if cutoff <= time.monotonic() or not self.supervisor.local_allowed(
                        root, child, admission=True
                    ):
                        raise RuntimeUnavailable(
                            "child permission expired before exec start"
                        )
                    journal.update(
                        root.worker_id, child_id, exec_dispatched=1, phase="dispatching"
                    )
                    runtime.client.api.exec_start(child["exec_id"], detach=True)
                    journal.update(root.worker_id, child_id, phase="running")
            except Exception:
                # A lost reply is not permission to create or start another exec.
                journal.update(root.worker_id, child["child_id"], phase="uncertain")
                journal.close_admission(
                    root.worker_id,
                    "child launch requires whole-worker fencing",
                    retire=True,
                )

    def observe(self, root, child):
        if child["phase"] != "running":
            return child
        with self.runtime._lock(root.worker_id) as locked:
            if not locked:
                return child
            try:
                state = self.runtime.client.api.exec_inspect(child["exec_id"])
                if not state.get("Running"):
                    self.supervisor.journal.update(
                        root.worker_id,
                        child["child_id"],
                        phase="exec_returned",
                        exit_code=state.get("ExitCode"),
                    )
            except Exception:
                self.supervisor.journal.close_admission(
                    root.worker_id, "child observation is uncertain", retire=True
                )
        return self.supervisor.journal.child(root.worker_id, child["child_id"])

    def provisional(self, root, child, kind: str) -> str:
        """Read one bounded guest artifact; this never sets a capture receipt."""
        if kind not in {"patch", "log"} or child["phase"] != "exec_returned":
            raise RuntimeUnavailable("child provisional output is not available")
        filename = {"patch": "change.patch", "log": "output.log"}[kind]
        limit = self.supervisor.policy(root.spec).max_result_bytes
        with self.runtime._lock(root.worker_id) as locked:
            if not locked:
                raise RuntimeUnavailable("worker observation is in progress")
            row = self.runtime._row(root.worker_id, root.spec)
            container = self.runtime._container(root.worker_id, root.spec, row)
            chunks, _ = container.get_archive(
                f"/workspace/children/{child['child_id']}/run/{filename}"
            )
            raw = bytearray()
            try:
                for chunk in chunks:
                    raw.extend(chunk)
                    if len(raw) > limit + 1_048_576:
                        raise RuntimeUnavailable(
                            "child provisional artifact exceeds its bound"
                        )
            finally:
                close = getattr(chunks, "close", None)
                if close:
                    close()
        with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
            members = archive.getmembers()
            if (
                len(members) != 1
                or members[0].name != filename
                or not members[0].isfile()
                or members[0].size > limit
            ):
                raise RuntimeUnavailable(
                    "child provisional artifact is not one bounded regular file"
                )
            content = (
                archive.extractfile(members[0]).read().decode("utf-8", errors="replace")
            )
        if len(content.encode()) > limit:
            raise RuntimeUnavailable(
                "child provisional artifact exceeds the text bound"
            )
        return content

    def final_capture(self, root, child, receipt) -> dict[str, str]:
        if not (
            receipt.termination_confirmed
            and receipt.launch_fenced
            and receipt.artifacts_captured
        ):
            raise RuntimeUnavailable(
                "child final capture requires the whole-worker fence"
            )
        policy = self.supervisor.policy(root.spec)
        prefix = f"workspace/children/{child['child_id']}/"
        selected = {}
        workspace_present = False
        if receipt.capture_path:
            from pathlib import Path

            archive_path = Path(receipt.capture_path)
            content = archive_path.read_bytes()
            if text_hash_bytes(content) != receipt.capture_sha256:
                raise RuntimeUnavailable(
                    "whole-worker archive changed before child capture"
                )
            with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
                for member in archive:
                    if member.name.startswith(prefix):
                        workspace_present = True
                    if member.name not in {
                        prefix + "run/change.patch",
                        prefix + "run/output.log",
                    }:
                        continue
                    kind = "patch" if member.name.endswith("change.patch") else "log"
                    if (
                        kind in selected
                        or not member.isfile()
                        or member.size > policy.max_result_bytes
                    ):
                        raise RuntimeUnavailable(
                            "final child artifact is not a bounded regular file"
                        )
                    selected[kind] = (
                        archive.extractfile(member)
                        .read()
                        .decode("utf-8", errors="replace")
                    )
                    if len(selected[kind].encode()) > policy.max_result_bytes:
                        raise RuntimeUnavailable("final child text exceeds its bound")
        if child["exec_dispatched"] and not workspace_present:
            raise RuntimeUnavailable(
                "dispatched child workspace is missing; retain the reservation"
            )
        grant = json.loads(child["grant_json"])
        manifest = {
            "schema_version": 1,
            "child_id": child["child_id"],
            "root_attempt_id": root.attempt_id,
            "worker_id": root.worker_id,
            "grant_digest": grant["binding"]["grant_digest"],
            "profile": root.spec.profile,
            "child_policy": policy.fingerprint,
            "uid": child["uid"],
            "exec_id": child["exec_id"],
            "exec_start_dispatched": bool(child["exec_dispatched"]),
            "not_started": not bool(child["exec_dispatched"]),
            "workspace_present": workspace_present,
            "deadline_monotonic": child["deadline"],
            "armed_deadline_monotonic": child["armed_deadline"],
            "archive_sha256": receipt.capture_sha256,
            "root_manifest_sha256": text_hash(receipt.manifest),
            "patch_present": "patch" in selected,
            "log_present": "log" in selected,
            "termination_confirmed": True,
            "launch_fenced": True,
            "termination_method": "whole-container fence",
            "evidence_source": "guest-generated; not independent review or proof of composition",
        }
        if policy.outcome_protocol is not None:
            from .child_outcomes import work_outcome

            report = (
                json.loads(child["outcome_report"]) if child["outcome_report"] else None
            )
            manifest["work_outcome"] = work_outcome(grant["binding"], report)
        public = getattr(self.supervisor, "public_supervisor", None)
        if public is not None and public.enabled(root.spec):
            manifest = public.child_manifest(root, child["child_id"], manifest)
        return {
            "patch": selected.get("patch", ""),
            "log": selected.get("log", ""),
            "manifest": canonical(manifest),
        }


def text_hash_bytes(value: bytes) -> str:
    import hashlib

    return hashlib.sha256(value).hexdigest()
