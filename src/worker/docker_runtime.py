"""A single-host, one-attempt Docker worker runtime.

The host is trusted. Task processes receive neither its Docker socket nor its
authority credentials. Resources are retained by default. Explicit host cleanup
requires qualified creation, canonical capture and verified termination.
"""

from __future__ import annotations

from contextlib import contextmanager
from dataclasses import asdict, dataclass, field
import hashlib
import io
import json
import math
import os
from pathlib import Path
import re
import sqlite3
import stat
import tarfile
import time
from typing import Callable, Mapping
import fcntl

import docker
from docker.errors import NotFound

from .lifecycle import (
    LifecycleConflict,
    RuntimeCapabilities,
    RuntimeObservation,
    RuntimeUnavailable,
    WorkerScope,
    WorkerSpec,
)
from .source_snapshot import SourceSnapshots

_WATCHDOG_UID = 65534
# Earlier markers did not exclude endpoint adapters or authenticator hooks.
# Preserve those historical rows, but never upgrade their creation proof.
_CLEANUP_TRANSPORT = "v2:docker-7.2.0:stock-unix:retry-0:redirect-0"


class CleanupBlocked(RuntimeUnavailable):
    """A fixed public cleanup condition, never a backend exception message."""


def require_cleanup(condition, reason):
    if not condition:
        raise CleanupBlocked(reason)


_MODEL_ENV = {
    "OPENAI_API_KEY",
    "ANTHROPIC_API_KEY",
    "OPENROUTER_API_KEY",
    "GEMINI_API_KEY",
    "GOOGLE_API_KEY",
    "AZURE_OPENAI_API_KEY",
}
_WATCHDOG = """import os,time
idle_deadline=time.monotonic()+86400
deadline=None
while True:
    if deadline is None:
        try:
            with open('/control/deadline',encoding='ascii') as source:
                deadline=float(source.read(64))
        except (OSError,ValueError):
            pass
    if time.monotonic()>=(deadline if deadline is not None else idle_deadline):
        os._exit(0)
    # PID 1 owns orphaned descendants after their original parent exits.
    # Reap only exited children, without delaying the original deadline.
    for _ in range(128):
        if time.monotonic()>=(deadline if deadline is not None else idle_deadline):
            os._exit(0)
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
_SET_DEADLINE = """import os,sys
fd=os.open('/control/deadline',os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
try:
    os.write(fd,sys.argv[1].encode('ascii'))
    os.fsync(fd)
finally:
    os.close(fd)
"""
_RUN = """import json,os,subprocess,sys
request=json.loads(sys.argv[1])
env=dict(os.environ)
env.update(GIT_CONFIG_NOSYSTEM='1',GIT_CONFIG_GLOBAL='/dev/null',
           GIT_TERMINAL_PROMPT='0',HOME='/workspace/run/home')
os.makedirs(env['HOME'],mode=0o700,exist_ok=True)
git=['git','-c','core.hooksPath=/dev/null','-c','core.fsmonitor=false']
result=1
with open('/workspace/run/output.log','wb') as output:
    try:
        # Local transport starts a separate upload-pack process and removes
        # the caller's command-scoped Git configuration. Trust only this fixed,
        # sanitized read-only source in that process, never all repositories.
        subprocess.run(git+['clone','--no-checkout','--no-hardlinks','--no-local',
            '--upload-pack=git -c safe.directory=/source upload-pack',
            '/source','/workspace/run/repo'],
            check=True,env=env,stdout=output,stderr=subprocess.STDOUT)
        subprocess.run(git+['checkout','--detach',request['base']],
            cwd='/workspace/run/repo',check=True,env=env,stdout=output,stderr=subprocess.STDOUT)
        with open('/workspace/input.txt','rb') as prompt:
            result=subprocess.run(request['command'],cwd='/workspace/run/repo',
                env=env,stdin=prompt,stdout=output,stderr=subprocess.STDOUT).returncode
    except Exception as exc:
        output.write(('Runtime preparation/command failed: '+type(exc).__name__+'\\n').encode())
    finally:
        try:
            subprocess.run(git+['add','--all'],cwd='/workspace/run/repo',env=env,
                check=True,stdout=output,stderr=subprocess.STDOUT)
            with open('/workspace/run/change.patch','wb') as patch:
                subprocess.run(git+['diff','--cached','--binary',request['base']],
                    cwd='/workspace/run/repo',env=env,check=True,stdout=patch,stderr=output)
        except Exception:
            pass
sys.exit(result if 0 <= result <= 255 else 1)
"""


def _json(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"))


def _digest(value: bytes | str) -> str:
    return hashlib.sha256(
        value.encode() if isinstance(value, str) else value
    ).hexdigest()


@dataclass(frozen=True)
class DockerProfile:
    """Operator-owned immutable configuration, never supplied by a task."""

    name: str
    deployment_id: str
    repository: str
    source_path: str
    image: str
    command: tuple[str, ...]
    base_commit: str
    uid: int = 65532
    memory_bytes: int = 536870912
    cpu_quota: int = 100000
    pids_limit: int = 128
    max_seconds: int = 300
    max_archive_bytes: int = 16777216
    environment_refs: tuple[tuple[str, str], ...] | Mapping[str, str] = field(
        default_factory=tuple
    )

    def __post_init__(self) -> None:
        WorkerScope(self.deployment_id, self.repository)
        if not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9._-]{0,127}", self.name):
            raise ValueError("invalid approved profile name")
        if not re.fullmatch(r"(?:sha256:|[^\s]+@sha256:)[0-9a-f]{64}", self.image):
            raise ValueError("profile image must use an immutable image ID or digest")
        if not re.fullmatch(r"[0-9a-f]{40}", self.base_commit):
            raise ValueError("base_commit must be a full Git SHA-1 commit ID")
        if (
            not isinstance(self.source_path, str)
            or not Path(self.source_path).is_absolute()
        ):
            raise ValueError("source_path must be an approved absolute path")
        if not isinstance(self.command, (list, tuple)):
            raise ValueError("command must be an argv list or tuple")
        object.__setattr__(self, "command", tuple(self.command))
        if not self.command or any(
            not isinstance(x, str) or not x or "\0" in x or len(x) > 4096
            for x in self.command
        ):
            raise ValueError("command must be a bounded nonempty argv")
        for name, minimum, maximum in (
            ("uid", 1, 65535),
            ("memory_bytes", 16777216, 1 << 40),
            ("cpu_quota", 1000, 1 << 31),
            ("pids_limit", 8, 65536),
            ("max_seconds", 1, 86400),
            ("max_archive_bytes", 1024, 1 << 30),
        ):
            value = getattr(self, name)
            if type(value) is not int or not minimum <= value <= maximum:
                raise ValueError(f"invalid {name}")
        if self.uid == _WATCHDOG_UID:
            raise ValueError("task uid must differ from the trusted watchdog uid")
        refs = (
            self.environment_refs.items()
            if isinstance(self.environment_refs, Mapping)
            else self.environment_refs
        )
        refs = tuple(sorted(refs))
        if len(dict(refs)) != len(refs):
            raise ValueError("duplicate environment reference")
        for name, reference in refs:
            if (
                name not in _MODEL_ENV
                or not isinstance(reference, str)
                or not re.fullmatch(r"env:[A-Z_][A-Z0-9_]*", reference)
            ):
                raise ValueError(
                    "only explicit model credential environment references are supported"
                )
        object.__setattr__(self, "environment_refs", refs)

    @property
    def scope(self) -> WorkerScope:
        return WorkerScope(self.deployment_id, self.repository)

    @property
    def fingerprint(self) -> str:
        return _digest(_json(asdict(self)))


@dataclass(frozen=True)
class ExecutionReceipt:
    state: str
    termination_confirmed: bool = False
    artifacts_captured: bool = False
    launch_fenced: bool = False
    capture_path: str | None = None
    capture_sha256: str | None = None
    exit_code: int | None = None
    patch: str = ""
    log: str = ""
    manifest: str = ""
    reason: str = ""


class ManagedDockerRuntime:
    """Durable incarnation driver for one local Docker daemon and one host.

    A worker can execute one root attempt. Entire-container termination ends
    that incarnation, including descendants. Admission and canonical authority
    remain the dispatcher's responsibility. Passing a readiness callback does
    not replace those per-attempt authorization checks.
    """

    def __init__(
        self,
        state_directory: str | Path,
        profiles: list[DockerProfile] | tuple[DockerProfile, ...],
        readiness: Callable[[WorkerScope, str], RuntimeCapabilities],
        docker_client=None,
        *,
        model_broker=None,
        child_policies=None,
    ):
        self.root = Path(state_directory).resolve()
        self.root.mkdir(mode=0o700, parents=True, exist_ok=True)
        self.database = self.root / "journal.sqlite3"
        self.profiles = {
            (profile.deployment_id, profile.repository, profile.name): profile
            for profile in profiles
        }
        if len(self.profiles) != len(profiles) or not callable(readiness):
            raise ValueError(
                "unique profiles and a real readiness callback are required"
            )
        self.readiness = readiness
        self.model_broker = model_broker
        self.child_policies = dict(child_policies or {})
        self.child_supervisor = None
        if self.child_policies:
            from .child_types import ChildPolicy

            if model_broker is None or not set(self.child_policies) <= set(
                model_broker.policies
            ):
                raise ValueError(
                    "child policies require approved model-backed profiles"
                )
            for key, policy in self.child_policies.items():
                if key not in self.profiles or not isinstance(policy, ChildPolicy):
                    raise ValueError("child policies require approved runtime profiles")
                policy.validate_root(
                    self.profiles[key].uid, self.profiles[key].max_seconds
                )
        if model_broker is not None:
            if not set(model_broker.policies) <= set(self.profiles):
                raise ValueError("model policies require approved runtime profiles")
            if any(
                self.profiles[key].environment_refs for key in model_broker.policies
            ):
                raise ValueError(
                    "model-backed profiles cannot inject guest credentials"
                )
        self._client = docker_client
        self.sources = SourceSnapshots(self.root / "sources")
        (self.root / "locks").mkdir(mode=0o700, exist_ok=True)
        (self.root / "captures").mkdir(mode=0o700, exist_ok=True)
        with self._db() as db:
            db.executescript("""
                CREATE TABLE IF NOT EXISTS profiles(
                    deployment_id TEXT NOT NULL,repository TEXT NOT NULL,name TEXT NOT NULL,fingerprint TEXT NOT NULL,
                    PRIMARY KEY(deployment_id,repository,name));
                CREATE TABLE IF NOT EXISTS workers(
                    worker_id TEXT PRIMARY KEY,spec TEXT NOT NULL,profile_fingerprint TEXT NOT NULL,
                    container_id TEXT,create_dispatched INTEGER NOT NULL DEFAULT 0,
                    start_dispatched INTEGER NOT NULL DEFAULT 0,start_confirmed INTEGER NOT NULL DEFAULT 0,
                    retired INTEGER NOT NULL DEFAULT 0,receipt TEXT);
                CREATE TABLE IF NOT EXISTS attempts(
                    worker_id TEXT PRIMARY KEY,attempt_id TEXT UNIQUE NOT NULL,input_sha256 TEXT NOT NULL,
                    seconds REAL NOT NULL,deadline REAL NOT NULL,exec_id TEXT,
                    exec_dispatched INTEGER NOT NULL DEFAULT 0,cancelled INTEGER NOT NULL DEFAULT 0,
                    exit_code INTEGER,FOREIGN KEY(worker_id) REFERENCES workers(worker_id));
                CREATE TABLE IF NOT EXISTS child_profiles(
                    deployment_id TEXT NOT NULL,repository TEXT NOT NULL,name TEXT NOT NULL,fingerprint TEXT,
                    PRIMARY KEY(deployment_id,repository,name));
            """)
            # Existing rows have no proof covering volume creation or hidden
            # transport replay. Never infer that proof from retained resources.
            columns = {row[1] for row in db.execute("PRAGMA table_info(workers)")}
            for name, definition in {
                "creation_version": "INTEGER NOT NULL DEFAULT 0",
                "volume_creates": "INTEGER NOT NULL DEFAULT 0",
                "volume_create_acks": "INTEGER NOT NULL DEFAULT 0",
                "volume_transport": "TEXT",
                "volume_identity": "TEXT",
                "container_creates": "INTEGER NOT NULL DEFAULT 0",
                "container_create_acks": "INTEGER NOT NULL DEFAULT 0",
                "container_transport": "TEXT",
                "cleanup": "TEXT",
            }.items():
                if name not in columns:
                    db.execute(f"ALTER TABLE workers ADD COLUMN {name} {definition}")
            for profile in profiles:
                key = (profile.deployment_id, profile.repository, profile.name)
                old = db.execute(
                    "SELECT fingerprint FROM profiles WHERE deployment_id=? AND repository=? AND name=?",
                    key,
                ).fetchone()
                child_policy = self.child_policies.get(key)
                child_digest = child_policy.fingerprint if child_policy else None
                child_old = db.execute(
                    "SELECT fingerprint FROM child_profiles WHERE deployment_id=? AND repository=? AND name=?",
                    key,
                ).fetchone()
                if child_old is None:
                    if old is not None and child_digest is not None:
                        raise LifecycleConflict(
                            "enabling children requires a new approved profile and incarnation"
                        )
                    db.execute(
                        "INSERT INTO child_profiles VALUES(?,?,?,?)",
                        (*key, child_digest),
                    )
                elif child_old[0] != child_digest:
                    raise LifecycleConflict(
                        "child policy changed; use a new profile name"
                    )
                if old and old[0] != profile.fingerprint:
                    raise LifecycleConflict(
                        "approved profile changed; use a new profile name"
                    )
                db.execute(
                    "INSERT OR IGNORE INTO profiles VALUES (?,?,?,?)",
                    (*key, profile.fingerprint),
                )
                if (
                    db.execute(
                        "SELECT fingerprint FROM profiles WHERE deployment_id=? AND repository=? AND name=?",
                        key,
                    ).fetchone()[0]
                    != profile.fingerprint
                ):
                    raise LifecycleConflict(
                        "approved profile changed; use a new profile name"
                    )

    @contextmanager
    def _db(self):
        db = sqlite3.connect(self.database, timeout=10)
        db.row_factory = sqlite3.Row
        db.execute("PRAGMA journal_mode=WAL")
        db.execute("PRAGMA synchronous=FULL")
        db.execute("PRAGMA foreign_keys=ON")
        try:
            with db:
                yield db
        finally:
            db.close()

    @contextmanager
    def _lock(self, worker_id: str):
        with (self.root / "locks" / (_digest(worker_id) + ".lock")).open("a") as handle:
            try:
                fcntl.flock(handle, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                yield False
                return
            try:
                yield True
            finally:
                fcntl.flock(handle, fcntl.LOCK_UN)

    @property
    def client(self):
        if self._client is None:
            host = os.environ.get("DOCKER_HOST", "unix:///var/run/docker.sock")
            if not host.startswith("unix://"):
                raise RuntimeUnavailable(
                    "managed runtime requires a local Docker Unix socket"
                )
            self._client = docker.DockerClient(base_url=host, timeout=5)
            # A redirect could repeat a resource-creating POST inside one SDK
            # invocation. The stock Unix adapter already has zero retries.
            self._client.api.max_redirects = 0
        return self._client

    def _cleanup_transport(self):
        """Qualify the actual transport before creation, not retroactively."""
        from docker.api.client import APIClient
        from docker.transport.unixconn import UnixHTTPAdapter
        from urllib3.util.retry import Retry

        client = self.client
        if type(client) is not docker.DockerClient or docker.__version__ != "7.2.0":
            return None
        api = client.api
        if type(api) is not APIClient or api.base_url != "http+docker://localhost":
            return None
        # Requests selects the longest mounted prefix for each actual URL.
        # A stock base lookup cannot qualify a customized create-endpoint mount.
        if tuple(api.adapters) != ("http+docker://",):
            return None
        adapter = api.get_adapter(api.base_url)
        if (
            api.adapters["http+docker://"] is not adapter
            or type(adapter) is not UnixHTTPAdapter
            or type(adapter.max_retries) is not Retry
            or type(adapter.max_retries.total) is not int
            or adapter.max_retries.total != 0
            or type(api.max_redirects) is not int
            or api.max_redirects != 0
            or api.auth is not None
            or api.hooks != {"response": []}
        ):
            return None
        return _CLEANUP_TRANSPORT

    def _creating(self, worker_id, resource):
        if resource not in {"volume", "container"}:
            raise ValueError("unsupported runtime resource")
        proof = self._cleanup_transport() or ""
        with self._db() as db:
            db.execute(
                f"UPDATE workers SET {resource}_creates={resource}_creates+1,"
                f"{resource}_transport=CASE WHEN {resource}_creates=0 THEN ? "
                f"WHEN {resource}_transport=? THEN {resource}_transport ELSE '' END "
                "WHERE worker_id=?",
                (proof, proof, worker_id),
            )

    def _created(self, worker_id, resource, *, identity):
        if resource not in {"volume", "container"}:
            raise ValueError("unsupported runtime resource")
        field = "volume_identity" if resource == "volume" else "container_id"
        with self._db() as db:
            db.execute(
                f"UPDATE workers SET {resource}_create_acks={resource}_create_acks+1,"
                f"{field}=? WHERE worker_id=?",
                (identity, worker_id),
            )

    @staticmethod
    def _volume_identity(volume):
        fields = ("Name", "CreatedAt", "Driver", "Scope", "Labels", "Options")
        return {key: volume.attrs.get(key) for key in fields}

    def _profile(self, spec: WorkerSpec) -> DockerProfile:
        profile = self.profiles.get((spec.deployment_id, spec.repository, spec.profile))
        if profile is None or profile.scope != spec.scope:
            raise RuntimeUnavailable("profile is not approved for this scope")
        return profile

    def capabilities(self, scope: WorkerScope, profile: str) -> RuntimeCapabilities:
        approved = self.profiles.get((scope.deployment_id, scope.repository, profile))
        if approved is None or approved.scope != scope:
            return RuntimeCapabilities(reason="profile is not approved for this scope")
        try:
            self.sources.prepare(
                approved.source_path, approved.base_commit, approved.max_archive_bytes
            )
            image = self.client.images.get(approved.image)
            if approved.image.startswith("sha256:"):
                if image.id != approved.image:
                    raise ValueError("image ID mismatch")
            elif approved.image not in image.attrs.get("RepoDigests", []):
                raise ValueError("image digest mismatch")
            self.client.ping()
        except Exception:
            return RuntimeCapabilities(
                profile_supported=True,
                reason="approved source/base or local Docker image is unavailable",
            )
        try:
            authority = self.readiness(scope, profile)
        except Exception:
            authority = RuntimeCapabilities(
                reason="canonical authority preflight failed"
            )
        key = (scope.deployment_id, scope.repository, profile)
        if key in self.child_policies:
            from .child_types import ChildCapabilities

            try:
                if self.child_supervisor is None:
                    raise RuntimeUnavailable("child supervisor is not installed")
                self.child_supervisor.driver.check_topology()
                self.child_supervisor.endpoints.check_ready()
            except Exception:
                return ChildCapabilities(
                    profile_supported=True,
                    reason="child runtime transport or UID mapping is unavailable",
                )
            return ChildCapabilities(
                authority.usable,
                authority.profile_supported is True,
                authority.repository_access is True,
                authority.reason,
                children=authority.usable,
            )
        return RuntimeCapabilities(
            managed_dispatch=authority.usable,
            profile_supported=authority.profile_supported is True,
            repository_access=authority.repository_access is True,
            reason=authority.reason,
        )

    def _row(self, worker_id: str, spec: WorkerSpec, *, create: bool = False):
        profile = self._profile(spec)
        payload = _json(asdict(spec))
        with self._db() as db:
            row = db.execute(
                "SELECT * FROM workers WHERE worker_id=?", (worker_id,)
            ).fetchone()
            if row is None and create:
                db.execute(
                    "INSERT INTO workers(worker_id,spec,profile_fingerprint,creation_version) VALUES (?,?,?,1)",
                    (worker_id, payload, profile.fingerprint),
                )
                row = db.execute(
                    "SELECT * FROM workers WHERE worker_id=?", (worker_id,)
                ).fetchone()
            if row is not None and (
                row["spec"] != payload
                or row["profile_fingerprint"] != profile.fingerprint
            ):
                raise LifecycleConflict(
                    "worker identity is bound to another specification"
                )
            return row

    def restore_model_endpoints(self):
        """Restore only model records belonging to unresolved owned workers."""
        if self.model_broker is None:
            return
        approved = {}
        with self._db() as db:
            rows = db.execute("SELECT * FROM workers WHERE receipt IS NULL").fetchall()
        for row in rows:
            spec = WorkerSpec(**json.loads(row["spec"]))
            key = (spec.deployment_id, spec.repository, spec.profile)
            if key not in self.model_broker.policies:
                continue
            self._row(row["worker_id"], spec)  # Verify immutable runtime policy.
            with self.model_broker.connection() as db:
                model = db.execute(
                    "SELECT revoked FROM workers WHERE worker_id=?", (row["worker_id"],)
                ).fetchone()
            if model is None:
                if row["create_dispatched"] or row["container_id"]:
                    raise ValueError(
                        "model recovery journal is missing for an owned worker"
                    )
                continue  # Creation never reached model preparation.
            if not model["revoked"]:
                approved[row["worker_id"]] = spec
        self.model_broker.restore_workers(approved)
        if self.child_supervisor is not None:
            for worker_id, spec in approved.items():
                if self.child_supervisor.enabled(spec):
                    self.child_supervisor.prepare_worker(
                        worker_id, spec, self.model_broker.root / worker_id
                    )
                    try:
                        self.child_supervisor.endpoints.restore(worker_id)
                    except LifecycleConflict:
                        # A prepared container can precede canonical root claim.
                        if (
                            self.child_supervisor.journal.worker(worker_id)["context"]
                            is not None
                        ):
                            raise

    def _update(self, worker_id: str, **values):
        allowed = {
            "container_id",
            "create_dispatched",
            "start_dispatched",
            "start_confirmed",
            "retired",
            "receipt",
            "cleanup",
        }
        if not values.keys() <= allowed:
            raise ValueError("invalid journal update")
        with self._db() as db:
            db.execute(
                "UPDATE workers SET "
                + ",".join(key + "=?" for key in values)
                + " WHERE worker_id=?",
                (*values.values(), worker_id),
            )

    def _labels(self, worker_id: str, spec: WorkerSpec) -> dict[str, str]:
        labels = {
            "openjules.managed": "1",
            "openjules.worker": worker_id,
            "openjules.spec": _digest(_json(asdict(spec))),
            "openjules.profile": self._profile(spec).fingerprint,
        }
        key = (spec.deployment_id, spec.repository, spec.profile)
        if self.model_broker is not None and key in self.model_broker.policies:
            labels["openjules.model_policy"] = self.model_broker.policy_digests[key]
        if key in self.child_policies:
            labels["openjules.child_policy"] = self.child_policies[key].fingerprint
            labels["openjules.child_protocol"] = "bounded-children-v1"
        return labels

    def _name(self, worker_id: str) -> str:
        return "openjules-worker-" + _digest(worker_id)[:40]

    def _container(self, worker_id: str, spec: WorkerSpec, row):
        container = self.client.containers.get(
            row["container_id"] or self._name(worker_id)
        )
        container.reload()
        if any(
            container.attrs.get("Config", {}).get("Labels", {}).get(k) != v
            for k, v in self._labels(worker_id, spec).items()
        ):
            raise LifecycleConflict(
                "container ownership does not match the immutable worker"
            )
        if row["container_id"] and container.id != row["container_id"]:
            raise LifecycleConflict("container identity changed")
        if not row["container_id"]:
            self._update(worker_id, container_id=container.id)
        started = container.attrs.get("State", {}).get("StartedAt", "")
        if row["start_dispatched"] and started and not started.startswith("0001-"):
            self._update(worker_id, start_confirmed=1)
        return container

    @staticmethod
    def _tar(files: Mapping[str, tuple[bytes | None, int, int]]) -> bytes:
        buffer = io.BytesIO()
        with tarfile.open(fileobj=buffer, mode="w") as archive:
            for name, (data, uid, mode) in files.items():
                info = tarfile.TarInfo(name)
                info.uid = info.gid = uid
                info.mode = mode
                if data is None:
                    info.type = tarfile.DIRTYPE
                    archive.addfile(info)
                else:
                    info.size = len(data)
                    archive.addfile(info, io.BytesIO(data))
        return buffer.getvalue()

    def _create(self, worker_id: str, spec: WorkerSpec):
        profile = self._profile(spec)
        source = self.sources.prepare(
            profile.source_path, profile.base_commit, profile.max_archive_bytes
        )
        labels = self._labels(worker_id, spec)
        volume_name = "openjules-work-" + _digest(worker_id)[:40]
        self._creating(worker_id, "volume")
        volume = self.client.volumes.create(name=volume_name, labels=labels)
        volume.reload()
        if any(volume.attrs.get("Labels", {}).get(k) != v for k, v in labels.items()):
            raise LifecycleConflict("workspace volume ownership mismatch")
        self._created(
            worker_id, "volume", identity=_json(self._volume_identity(volume))
        )
        volumes = {
            str(source): {"bind": "/source", "mode": "ro"},
            volume_name: {"bind": "/workspace", "mode": "rw"},
        }
        key = (spec.deployment_id, spec.repository, spec.profile)
        if self.model_broker is not None and key in self.model_broker.policies:
            directory = self.model_broker.prepare_worker(worker_id, spec)
            volumes[str(directory)] = {"bind": "/run/openjules-model", "mode": "ro"}
            if key in self.child_policies:
                if self.child_supervisor is None:
                    raise RuntimeUnavailable("child supervisor is not installed")
                self.child_supervisor.prepare_worker(worker_id, spec, directory)
        watchdog = _WATCHDOG
        if key in self.child_policies:
            from .child_runtime import CHILD_WATCHDOG

            watchdog = CHILD_WATCHDOG
        self._update(worker_id, create_dispatched=1)
        self._creating(worker_id, "container")
        container = self.client.containers.create(
            profile.image,
            name=self._name(worker_id),
            labels=labels,
            entrypoint=["python3", "-I", "-S", "-c", watchdog],
            command=[],
            user=f"{_WATCHDOG_UID}:{_WATCHDOG_UID}",
            working_dir="/",
            detach=True,
            network_mode="none",
            read_only=True,
            cap_drop=["ALL"],
            security_opt=["no-new-privileges:true"],
            privileged=False,
            mem_limit=profile.memory_bytes,
            memswap_limit=profile.memory_bytes,
            cpu_period=100000,
            cpu_quota=profile.cpu_quota,
            pids_limit=profile.pids_limit,
            volumes=volumes,
            tmpfs={
                "/tmp": f"rw,noexec,nosuid,nodev,size=16777216,mode=1777",
                "/control": f"rw,noexec,nosuid,nodev,size=65536,uid={_WATCHDOG_UID},gid={_WATCHDOG_UID},mode=0700",
            },
            restart_policy={"Name": "no"},
            log_config=docker.types.LogConfig(
                type="json-file", config={"max-size": "1m", "max-file": "1"}
            ),
            environment={"PATH": "/usr/local/bin:/usr/bin:/bin", "LANG": "C.UTF-8"},
        )
        self._created(worker_id, "container", identity=container.id)
        return container

    def ensure(self, worker_id: str, spec: WorkerSpec) -> RuntimeObservation:
        with self._lock(worker_id) as locked:
            if not locked:
                return RuntimeObservation(
                    "unknown", reason="runtime operation is in progress"
                )
            row = self._row(worker_id, spec, create=True)
            if row["receipt"]:
                return self._terminal_observation(row)
            if row["retired"]:
                return RuntimeObservation(
                    "draining",
                    runtime_id=self._runtime_id(row),
                    reason="incarnation is retired",
                )
            if not self.capabilities(spec.scope, spec.profile).usable:
                raise RuntimeUnavailable("managed runtime preflight is not ready")
            try:
                try:
                    container = self._container(worker_id, spec, row)
                except NotFound:
                    if row["container_id"]:
                        return RuntimeObservation(
                            "unknown",
                            runtime_id=self._runtime_id(row),
                            reason="owned container is missing",
                        )
                    try:
                        self._create(worker_id, spec)
                    except Exception:
                        # Creation may have succeeded despite a lost response.
                        pass
                    row = self._row(worker_id, spec)
                    container = self._container(worker_id, spec, row)
                row = self._row(worker_id, spec)
                if not row["start_dispatched"]:
                    if container.attrs.get("State", {}).get("Status") != "created":
                        return RuntimeObservation(
                            "unknown",
                            runtime_id="docker:" + container.id,
                            reason="unexpected pre-launch state",
                        )
                    profile = self._profile(spec)
                    workspace = {"run": (None, profile.uid, 0o700)}
                    if (
                        spec.deployment_id,
                        spec.repository,
                        spec.profile,
                    ) in self.child_policies:
                        workspace["children"] = (None, _WATCHDOG_UID, 0o711)
                    if not container.put_archive("/workspace", self._tar(workspace)):
                        raise RuntimeUnavailable("workspace initialization failed")
                    self._update(worker_id, start_dispatched=1)
                    container.start()
                    self._update(worker_id, start_confirmed=1)
                return self._observe_locked(worker_id, spec)
            except LifecycleConflict:
                raise
            except Exception:
                return RuntimeObservation(
                    "unknown",
                    runtime_id=self._runtime_id(self._row(worker_id, spec)),
                    reason="Docker launch outcome is unresolved",
                )

    @staticmethod
    def _runtime_id(row):
        return "docker:" + row["container_id"] if row and row["container_id"] else None

    def _terminal_observation(self, row):
        receipt = ExecutionReceipt(**json.loads(row["receipt"]))
        return RuntimeObservation(
            "stopped",
            runtime_id=self._runtime_id(row),
            termination_confirmed=receipt.termination_confirmed,
            artifacts_captured=receipt.artifacts_captured,
            not_started=not row["start_dispatched"],
            launch_fenced=receipt.launch_fenced,
        )

    def _observe_locked(
        self, worker_id: str, spec: WorkerSpec, runtime_id: str | None = None
    ):
        row = self._row(worker_id, spec)
        if row is None:
            return RuntimeObservation("unknown", reason="runtime has no worker record")
        if runtime_id is not None and runtime_id != self._runtime_id(row):
            return RuntimeObservation(
                "unknown",
                runtime_id=self._runtime_id(row),
                reason="runtime identity mismatch",
            )
        if row["receipt"]:
            return self._terminal_observation(row)
        try:
            container = self._container(worker_id, spec, row)
            row = self._row(worker_id, spec)
            state = container.attrs.get("State", {})
            if state.get("Running") and row["start_confirmed"]:
                with self._db() as db:
                    active = db.execute(
                        "SELECT 1 FROM attempts WHERE worker_id=?", (worker_id,)
                    ).fetchone()
                return RuntimeObservation(
                    "draining" if row["retired"] else "busy" if active else "ready",
                    runtime_id=self._runtime_id(row),
                )
            return RuntimeObservation(
                "unknown",
                runtime_id=self._runtime_id(row),
                reason="worker requires verified retirement and capture",
            )
        except Exception:
            return RuntimeObservation(
                "unknown",
                runtime_id=self._runtime_id(row),
                reason="Docker observation is unresolved",
            )

    def observe(self, worker_id: str, spec: WorkerSpec, runtime_id: str | None):
        with self._lock(worker_id) as locked:
            if not locked:
                return RuntimeObservation(
                    "unknown",
                    runtime_id=runtime_id,
                    reason="runtime operation is in progress",
                )
            return self._observe_locked(worker_id, spec, runtime_id)

    def recover_idle(self, worker_id: str, spec: WorkerSpec) -> RuntimeObservation:
        """Retire a verified stopped idle worker, without stopping live work.

        This is an explicit trusted recovery mutation. Normal observation does
        not capture artifacts or change Docker state.
        """
        with self._lock(worker_id) as locked:
            if not locked:
                return RuntimeObservation(
                    "unknown", reason="runtime operation is in progress"
                )
            row = self._row(worker_id, spec)
            if row is None or self._attempt(worker_id) is not None:
                return RuntimeObservation(
                    "unknown",
                    runtime_id=self._runtime_id(row),
                    reason="idle recovery has no eligible worker",
                )
            if row["receipt"]:
                return self._terminal_observation(row)
            if not row["container_id"] or not row["start_confirmed"]:
                return RuntimeObservation(
                    "unknown",
                    runtime_id=self._runtime_id(row),
                    reason="original Docker start is unresolved",
                )
            try:
                container = self._container(worker_id, spec, row)
                state = container.attrs.get("State", {})
                if state.get("Running") or state.get("Status") not in {
                    "exited",
                    "dead",
                }:
                    return self._observe_locked(worker_id, spec)
                receipt = self._retire_locked(worker_id, spec)
                if (
                    receipt.termination_confirmed
                    and receipt.artifacts_captured
                    and receipt.launch_fenced
                ):
                    return self._terminal_observation(self._row(worker_id, spec))
                return RuntimeObservation(
                    "unknown", runtime_id=self._runtime_id(row), reason=receipt.reason
                )
            except Exception:
                return RuntimeObservation(
                    "unknown",
                    runtime_id=self._runtime_id(row),
                    reason="idle recovery observation is unresolved",
                )

    def drain(self, worker_id: str, spec: WorkerSpec, runtime_id: str | None):
        if self.child_supervisor is not None and self.child_supervisor.enabled(spec):
            self.child_supervisor.close_admission(worker_id)
        with self._lock(worker_id) as locked:
            if not locked:
                return RuntimeObservation(
                    "unknown",
                    runtime_id=runtime_id,
                    reason="runtime operation is in progress",
                )
            row = self._row(worker_id, spec, create=True)
            if runtime_id is not None and runtime_id != self._runtime_id(row):
                return RuntimeObservation(
                    "unknown",
                    runtime_id=self._runtime_id(row),
                    reason="runtime identity mismatch",
                )
            self._update(worker_id, retired=1)
            if row["receipt"]:
                return self._terminal_observation(row)
            return RuntimeObservation(
                "draining",
                runtime_id=self._runtime_id(row),
                reason="new execution is fenced",
            )

    def stop(self, worker_id: str, spec: WorkerSpec, runtime_id: str | None):
        with self._lock(worker_id) as locked:
            if not locked:
                return RuntimeObservation(
                    "unknown",
                    runtime_id=runtime_id,
                    reason="runtime operation is in progress",
                )
            row = self._row(worker_id, spec, create=True)
            if runtime_id is not None and runtime_id != self._runtime_id(row):
                return RuntimeObservation(
                    "unknown",
                    runtime_id=self._runtime_id(row),
                    reason="runtime identity mismatch",
                )
            receipt = self._retire_locked(worker_id, spec)
            row = self._row(worker_id, spec)
            if receipt.launch_fenced and receipt.artifacts_captured:
                return self._terminal_observation(row)
            return RuntimeObservation(
                "unknown",
                runtime_id=self._runtime_id(row),
                reason=receipt.reason,
                termination_confirmed=receipt.termination_confirmed,
                artifacts_captured=receipt.artifacts_captured,
                launch_fenced=receipt.launch_fenced,
            )

    def _attempt(self, worker_id):
        with self._db() as db:
            return db.execute(
                "SELECT * FROM attempts WHERE worker_id=?", (worker_id,)
            ).fetchone()

    def execute_attempt(
        self,
        worker_id: str,
        spec: WorkerSpec,
        attempt_id: str,
        input_text: str,
        seconds: float,
        *,
        deadline_monotonic: float | None = None,
    ) -> ExecutionReceipt:
        entered = time.monotonic()
        if not isinstance(input_text, str) or len(input_text.encode()) > 65536:
            raise ValueError("attempt input exceeds 64 KiB")
        profile = self._profile(spec)
        if (
            isinstance(seconds, bool)
            or not isinstance(seconds, (int, float))
            or not math.isfinite(seconds)
            or not 0 < seconds <= profile.max_seconds
        ):
            raise ValueError("attempt seconds exceed the approved profile")
        deadline = entered + seconds
        if deadline_monotonic is not None:
            if (
                isinstance(deadline_monotonic, bool)
                or not isinstance(deadline_monotonic, (int, float))
                or not math.isfinite(deadline_monotonic)
            ):
                raise ValueError("invalid fixed monotonic deadline")
            deadline = min(deadline, deadline_monotonic)
        if not isinstance(attempt_id, str) or not re.fullmatch(
            r"[A-Za-z0-9_.:-]{1,256}", attempt_id
        ):
            raise ValueError("invalid attempt identity")
        with self._lock(worker_id) as locked:
            if not locked:
                return ExecutionReceipt(
                    "unknown", reason="runtime operation is in progress"
                )
            row = self._row(worker_id, spec)
            if row is None:
                raise LifecycleConflict("worker is not provisioned")
            old = self._attempt(worker_id)
            if old:
                if old["attempt_id"] != attempt_id or old["input_sha256"] != _digest(
                    input_text
                ):
                    raise LifecycleConflict(
                        "worker is already bound to another attempt or input"
                    )
                return self._inspect_attempt_locked(worker_id, spec)
            if row["retired"] or row["receipt"] or not row["start_confirmed"]:
                raise LifecycleConflict(
                    "worker admission is closed or launch is uncertain"
                )
            with self._db() as db:
                db.execute(
                    "INSERT INTO attempts(worker_id,attempt_id,input_sha256,seconds,deadline) VALUES (?,?,?,?,?)",
                    (worker_id, attempt_id, _digest(input_text), seconds, deadline),
                )
            try:
                if time.monotonic() >= deadline:
                    return self._retire_locked(worker_id, spec)
                container = self._container(worker_id, spec, row)
                if not container.attrs.get("State", {}).get("Running"):
                    return self._retire_locked(worker_id, spec)
                if time.monotonic() >= deadline:
                    return self._retire_locked(worker_id, spec)
                # Docker archive upload does not reliably address tmpfs on a
                # read-only root. A fixed helper runs as the protected UID;
                # task-supplied code never runs under that identity.
                control = self.client.api.exec_create(
                    container.id,
                    ["python3", "-I", "-S", "-c", _SET_DEADLINE, str(deadline)],
                    user=f"{_WATCHDOG_UID}:{_WATCHDOG_UID}",
                    workdir="/",
                    environment={},
                    stdin=False,
                    stdout=False,
                    stderr=False,
                    privileged=False,
                )["Id"]
                self.client.api.exec_start(control, detach=True)
                while True:
                    control_state = self.client.api.exec_inspect(control)
                    if not control_state.get("Running"):
                        if control_state.get("ExitCode") != 0:
                            raise RuntimeUnavailable("deadline admission failed")
                        break
                    if time.monotonic() >= deadline:
                        raise RuntimeUnavailable("deadline admission expired")
                    time.sleep(0.01)
                if not container.put_archive(
                    "/workspace",
                    self._tar({"input.txt": (input_text.encode(), profile.uid, 0o400)}),
                ):
                    raise RuntimeUnavailable("input preparation failed")
                environment = {
                    name: os.environ[reference[4:]]
                    for name, reference in profile.environment_refs
                }
                environment.update(
                    OPENJULES_INPUT_FILE="/workspace/input.txt",
                    OPENJULES_ATTEMPT_ID=attempt_id,
                )
                if time.monotonic() >= deadline:
                    return self._retire_locked(worker_id, spec)
                execution = self.client.api.exec_create(
                    container.id,
                    [
                        "python3",
                        "-I",
                        "-S",
                        "-c",
                        _RUN,
                        _json(
                            {"base": profile.base_commit, "command": profile.command}
                        ),
                    ],
                    user=f"{profile.uid}:{profile.uid}",
                    workdir="/workspace/run",
                    environment=environment,
                    stdin=False,
                    stdout=False,
                    stderr=False,
                    privileged=False,
                )
                exec_id = execution["Id"]
                with self._db() as db:
                    db.execute(
                        "UPDATE attempts SET exec_id=?,exec_dispatched=1 WHERE worker_id=?",
                        (exec_id, worker_id),
                    )
                if time.monotonic() >= deadline:
                    return self._retire_locked(worker_id, spec)
                self.client.api.exec_start(exec_id, detach=True)
                if (
                    spec.deployment_id,
                    spec.repository,
                    spec.profile,
                ) in self.child_policies:
                    # Child admission needs the same worker fence while this
                    # root runs. Later dispatcher ticks inspect this exact exec.
                    return ExecutionReceipt(
                        "running",
                        reason="root execution dispatched under its original fence",
                    )
                while time.monotonic() < deadline:
                    observed = self.client.api.exec_inspect(exec_id)
                    if not observed.get("Running"):
                        with self._db() as db:
                            db.execute(
                                "UPDATE attempts SET exit_code=? WHERE worker_id=?",
                                (observed.get("ExitCode"), worker_id),
                            )
                        break
                    time.sleep(min(0.05, max(0, deadline - time.monotonic())))
                return self._retire_locked(worker_id, spec)
            except Exception:
                # The entire container is the execution fence. An exec-start
                # request arriving after confirmed stop cannot restart it.
                return self._retire_locked(worker_id, spec)

    def inspect_attempt(
        self, worker_id: str, spec: WorkerSpec, attempt_id: str
    ) -> ExecutionReceipt:
        with self._lock(worker_id) as locked:
            if not locked:
                return ExecutionReceipt(
                    "unknown", reason="runtime operation is in progress"
                )
            attempt = self._attempt(worker_id)
            if attempt is None or attempt["attempt_id"] != attempt_id:
                raise LifecycleConflict("attempt is not bound to this worker")
            return self._inspect_attempt_locked(worker_id, spec)

    def _inspect_attempt_locked(self, worker_id, spec):
        row = self._row(worker_id, spec)
        if row["receipt"]:
            return ExecutionReceipt(**json.loads(row["receipt"]))
        attempt = self._attempt(worker_id)
        if attempt["cancelled"] or time.monotonic() >= attempt["deadline"]:
            return self._retire_locked(worker_id, spec)
        try:
            container = self._container(worker_id, spec, row)
            if not container.attrs.get("State", {}).get("Running"):
                return self._retire_locked(worker_id, spec)
            if attempt["exec_id"]:
                state = self.client.api.exec_inspect(attempt["exec_id"])
                if not state.get("Running"):
                    # A pending exec-start may still arrive, so stop the entire
                    # incarnation before recording terminal/capture facts.
                    with self._db() as db:
                        db.execute(
                            "UPDATE attempts SET exit_code=? WHERE worker_id=?",
                            (state.get("ExitCode"), worker_id),
                        )
                    return self._retire_locked(worker_id, spec)
            return ExecutionReceipt(
                "running", reason="original execution remains reserved"
            )
        except Exception:
            return ExecutionReceipt(
                "unknown", reason="Docker execution observation is unresolved"
            )

    def cancel_attempt(
        self,
        worker_id: str,
        spec: WorkerSpec,
        attempt_id: str,
        input_text: str = "",
        seconds: float | None = None,
    ):
        with self._lock(worker_id) as locked:
            if not locked:
                return ExecutionReceipt(
                    "unknown", reason="runtime operation is in progress"
                )
            self._row(worker_id, spec, create=True)
            old = self._attempt(worker_id)
            if old is not None and old["attempt_id"] != attempt_id:
                raise LifecycleConflict("attempt is not bound to this worker")
            with self._db() as db:
                db.execute(
                    "INSERT OR IGNORE INTO attempts(worker_id,attempt_id,input_sha256,seconds,deadline,cancelled) VALUES (?,?,?,?,?,1)",
                    (worker_id, attempt_id, _digest(input_text), 0, time.monotonic()),
                )
                db.execute(
                    "UPDATE attempts SET cancelled=1 WHERE worker_id=?", (worker_id,)
                )
            return self._retire_locked(worker_id, spec)

    def _retire_locked(self, worker_id: str, spec: WorkerSpec):
        row = self._row(worker_id, spec, create=True)
        if row["receipt"]:
            return ExecutionReceipt(**json.loads(row["receipt"]))
        if self.child_supervisor is not None and self.child_supervisor.enabled(spec):
            self.child_supervisor.mark_retiring(worker_id)
        self._update(worker_id, retired=1)
        if not row["create_dispatched"] and row["container_id"] is None:
            receipt = ExecutionReceipt(
                "cancelled",
                True,
                True,
                True,
                manifest=_json(
                    {"schema_version": 1, "worker_id": worker_id, "not_started": True}
                ),
            )
            self._update(worker_id, receipt=_json(asdict(receipt)))
            return receipt
        try:
            container = self._container(worker_id, spec, row)
            row = self._row(worker_id, spec)
            if row["start_dispatched"] and not row["start_confirmed"]:
                return ExecutionReceipt(
                    "unknown", reason="original Docker start has not been fenced"
                )
            if container.attrs.get("State", {}).get("Running"):
                container.stop(timeout=2)
            container.reload()
            state = container.attrs.get("State", {})
            if state.get("Running") or state.get("Status") not in {
                "created",
                "exited",
                "dead",
            }:
                return ExecutionReceipt(
                    "unknown", reason="whole-container termination is unresolved"
                )
            return self._capture(worker_id, spec, container)
        except Exception:
            return ExecutionReceipt(
                "unknown", reason="Docker stop or durable capture is unresolved"
            )

    def _capture(self, worker_id, spec, container):
        profile = self._profile(spec)
        attempt = self._attempt(worker_id)
        chunks, _ = container.get_archive("/workspace")
        data = bytearray()
        try:
            for chunk in chunks:
                if len(data) + len(chunk) > profile.max_archive_bytes:
                    return ExecutionReceipt(
                        "unknown",
                        termination_confirmed=True,
                        launch_fenced=True,
                        reason="workspace capture exceeds the approved limit; container retained",
                    )
                data.extend(chunk)
        finally:
            close = getattr(chunks, "close", None)
            if close:
                close()
        content = bytes(data)
        digest = _digest(content)
        capture = self.root / "captures" / (_digest(worker_id) + ".tar")
        temp = capture.with_suffix(".tmp")
        with temp.open("wb") as output:
            output.write(content)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temp, capture)
        with _directory_fd(capture.parent) as directory:
            os.fsync(directory)
        selected: dict[str, str] = {}
        with tarfile.open(fileobj=io.BytesIO(content), mode="r:") as archive:
            for member in archive:
                if member.name not in {
                    "workspace/run/change.patch",
                    "workspace/run/output.log",
                }:
                    continue
                if (
                    member.name in selected
                    or not member.isfile()
                    or member.size > profile.max_archive_bytes
                ):
                    raise RuntimeUnavailable(
                        "capture evidence is not a bounded regular file"
                    )
                selected[member.name] = (
                    archive.extractfile(member).read().decode("utf-8", errors="replace")
                )
        manifest = _json(
            {
                "schema_version": 1,
                "worker_id": worker_id,
                "attempt_id": attempt["attempt_id"] if attempt else None,
                "profile": profile.name,
                "profile_fingerprint": profile.fingerprint,
                "base_commit": profile.base_commit,
                "container_id": container.id,
                "archive_sha256": digest,
                "archive_bytes": len(content),
                "patch_present": "workspace/run/change.patch" in selected,
                "log_present": "workspace/run/output.log" in selected,
                "evidence_source": "guest-generated; retained without asserting test success or review",
                "deadline_monotonic": attempt["deadline"] if attempt else None,
                "termination_confirmed": True,
                "launch_fenced": True,
            }
        )
        receipt = ExecutionReceipt(
            "cancelled" if attempt and attempt["cancelled"] else "completed",
            True,
            True,
            True,
            str(capture),
            digest,
            attempt["exit_code"] if attempt else None,
            selected.get("workspace/run/change.patch", ""),
            selected.get("workspace/run/output.log", ""),
            manifest,
        )
        self._update(worker_id, receipt=_json(asdict(receipt)))
        return receipt

    @staticmethod
    def _cleanup_result(progress=None, reason=""):
        progress = progress or {}
        return {
            "state": "cleaned" if progress.get("completed") is True else "retained",
            "reason": reason,
            "container_removed": progress.get("container_removed") is True,
            "volume_removed": progress.get("volume_removed") is True,
            "archives_retained": True,
        }

    def _cleanup_capture(self, worker_id, spec, row):
        require_cleanup(bool(row["retired"] and row["receipt"]), "capture_unresolved")
        receipt = ExecutionReceipt(**json.loads(row["receipt"]))
        require_cleanup(
            receipt.termination_confirmed is True
            and receipt.artifacts_captured is True
            and receipt.launch_fenced is True
            and (not row["start_dispatched"] or row["start_confirmed"]),
            "termination_unresolved",
        )
        attempt = self._attempt(worker_id)
        require_cleanup(attempt is not None, "executed_capture_required")
        manifest = json.loads(receipt.manifest)
        capture = self.root / "captures" / (_digest(worker_id) + ".tar")
        require_cleanup(
            receipt.capture_path == str(capture)
            and manifest.get("worker_id") == worker_id
            and manifest.get("attempt_id") == attempt["attempt_id"]
            and manifest.get("container_id") == row["container_id"]
            and manifest.get("profile") == spec.profile
            and manifest.get("base_commit") == self._profile(spec).base_commit
            and manifest.get("profile_fingerprint") == row["profile_fingerprint"]
            and manifest.get("termination_confirmed") is True
            and manifest.get("launch_fenced") is True,
            "capture_identity_mismatch",
        )
        maximum = self._profile(spec).max_archive_bytes
        with os.fdopen(
            os.open(capture, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK), "rb"
        ) as source:
            info = os.fstat(source.fileno())
            require_cleanup(
                stat.S_ISREG(info.st_mode) and 0 < info.st_size <= maximum,
                "capture_invalid",
            )
            digest, total = hashlib.sha256(), 0
            for chunk in iter(lambda: source.read(65536), b""):
                total += len(chunk)
                require_cleanup(total <= maximum, "capture_invalid")
                digest.update(chunk)
        require_cleanup(
            digest.hexdigest() == receipt.capture_sha256
            and manifest.get("archive_sha256") == receipt.capture_sha256
            and type(manifest.get("archive_bytes")) is int
            and manifest["archive_bytes"] == total == info.st_size,
            "capture_changed",
        )
        return receipt

    def _cleanup_container(self, worker_id, spec, container_id, volume_name):
        container = self.client.containers.get(container_id)
        container.reload()
        labels = container.attrs.get("Config", {}).get("Labels", {}) or {}
        state = container.attrs.get("State", {})
        require_cleanup(
            container.id == container_id
            and all(
                labels.get(k) == v for k, v in self._labels(worker_id, spec).items()
            ),
            "container_identity_mismatch",
        )
        require_cleanup(
            state.get("Running") is False
            and state.get("Restarting", False) is False
            and state.get("Paused", False) is False
            and state.get("Status") in {"created", "exited", "dead"},
            "container_not_stopped",
        )
        workspace = [
            mount
            for mount in container.attrs.get("Mounts", [])
            if mount.get("Destination") == "/workspace"
        ]
        require_cleanup(
            len(workspace) == 1
            and workspace[0].get("Type") == "volume"
            and workspace[0].get("Name") == volume_name,
            "workspace_identity_mismatch",
        )
        return container

    def _cleanup_volume(self, worker_id, spec, identity):
        volume = self.client.volumes.get(identity["Name"])
        volume.reload()
        labels = volume.attrs.get("Labels", {}) or {}
        require_cleanup(
            self._volume_identity(volume) == identity
            and all(
                labels.get(k) == v for k, v in self._labels(worker_id, spec).items()
            ),
            "volume_identity_mismatch",
        )
        return volume

    def cleanup_worker(self, worker_id, spec, canonical_proof):
        """Remove one qualified incarnation; caller holds service/lifecycle locks.

        The trusted dispatcher supplies a fresh canonical proof callback. No
        task-facing interface accepts cleanup permission or a boolean shortcut.
        """
        with self._lock(worker_id) as locked:
            if not locked:
                return self._cleanup_result(reason="runtime_operation_busy")
            row = self._row(worker_id, spec)
            require_cleanup(row is not None, "runtime_worker_unknown")
            progress = json.loads(row["cleanup"]) if row["cleanup"] else None
            if progress and progress.get("completed") is True:
                return self._cleanup_result(progress)
            try:
                require_cleanup(
                    row["creation_version"] == 1
                    and row["volume_creates"] == row["volume_create_acks"] == 1
                    and row["container_creates"] == row["container_create_acks"] == 1
                    and row["volume_transport"] == _CLEANUP_TRANSPORT
                    and row["container_transport"] == _CLEANUP_TRANSPORT,
                    "resource_creation_unqualified",
                )
                require_cleanup(
                    self._cleanup_transport() == _CLEANUP_TRANSPORT,
                    "cleanup_transport_unqualified",
                )
                receipt = self._cleanup_capture(worker_id, spec, row)
                proof = canonical_proof(receipt)
                require_cleanup(isinstance(proof, dict), "canonical_capture_unresolved")
                identity = json.loads(row["volume_identity"])
                volume_name = "openjules-work-" + _digest(worker_id)[:40]
                require_cleanup(
                    identity.get("Name") == volume_name
                    and isinstance(identity.get("CreatedAt"), str)
                    and bool(identity["CreatedAt"])
                    and identity.get("Driver") == "local"
                    and identity.get("Scope") == "local"
                    and identity.get("Options") in (None, {}),
                    "volume_identity_unqualified",
                )
                target = {
                    "schema_version": 1,
                    "worker_id": worker_id,
                    "spec_sha256": _digest(_json(asdict(spec))),
                    "container_id": row["container_id"],
                    "volume_identity": identity,
                    "archive_sha256": receipt.capture_sha256,
                    "canonical_proof": proof,
                }
                if progress is None:
                    # Before intent, absence is external uncertainty. After
                    # intent, exact absence can reconcile a lost delete reply.
                    try:
                        self._cleanup_container(
                            worker_id, spec, row["container_id"], volume_name
                        )
                        self._cleanup_volume(worker_id, spec, identity)
                    except NotFound:
                        raise CleanupBlocked("owned_resource_missing") from None
                    progress = target | {
                        "container_removed": False,
                        "volume_removed": False,
                        "completed": False,
                    }
                    self._update(worker_id, cleanup=_json(progress))
                else:
                    require_cleanup(
                        all(progress.get(k) == v for k, v in target.items()),
                        "cleanup_proof_changed",
                    )
                try:
                    container = self._cleanup_container(
                        worker_id, spec, row["container_id"], volume_name
                    )
                except NotFound:
                    container = None
                if container is not None:
                    require_cleanup(
                        not progress["container_removed"], "container_reappeared"
                    )
                    container.remove(force=False, v=False)
                    try:
                        self.client.containers.get(row["container_id"])
                    except NotFound:
                        pass
                    else:
                        raise CleanupBlocked("container_removal_unresolved")
                progress = progress | {"container_removed": True}
                self._update(worker_id, cleanup=_json(progress))
                try:
                    volume = self._cleanup_volume(worker_id, spec, identity)
                except NotFound:
                    volume = None
                if volume is not None:
                    volume.remove(force=False)
                    try:
                        self.client.volumes.get(volume_name)
                    except NotFound:
                        pass
                    else:
                        raise CleanupBlocked("volume_removal_unresolved")
                completed = progress | {"volume_removed": True, "completed": True}
                self._update(worker_id, cleanup=_json(completed))
                progress = completed
                return self._cleanup_result(progress)
            except CleanupBlocked as exc:
                return self._cleanup_result(progress, str(exc))
            except Exception:
                # Failure is not an acknowledgement. Keep every original
                # receipt/archive and the exact remaining cleanup target.
                return self._cleanup_result(progress, "cleanup_unresolved")


@contextmanager
def _directory_fd(path: Path):
    descriptor = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        yield descriptor
    finally:
        os.close(descriptor)
