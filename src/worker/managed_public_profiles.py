"""Private profile files and exact process acknowledgements for the host bridge.

This module grants no guest authority. Its owned loop uses the existing bounded
conversation transport and durable lifecycle hooks; a preparing or partially
retained profile is never repaired or adopted.
"""

from __future__ import annotations

import asyncio
from concurrent.futures import TimeoutError as FutureTimeout
from copy import deepcopy
import hashlib
import os
from pathlib import Path
import stat
import threading
import time

import anyio

from src.polyphony.conversation_client import (
    CHILD_ENVIRONMENT, PROBE, CleanupObserver, ConversationClient,
    ProcessLifecycleObserver, connect,
)
from .discussion_types import ConversationLaunch, Deadline, DiscussionError
from .managed_public_types import (
    ManagedPublicError, canonical, digest, object_value, absolute_path,
    _directory_descriptor, _file_facts, finite,
)


def _conflict():
    raise ManagedPublicError("state_conflict")


def _private_directory(descriptor):
    value = os.fstat(descriptor)
    if (
        not stat.S_ISDIR(value.st_mode) or value.st_uid != os.geteuid()
        or stat.S_IMODE(value.st_mode) != 0o700
    ):
        _conflict()
    return value


def _open_directory(path):
    descriptor = _directory_descriptor(absolute_path(str(path)))
    try:
        _private_directory(descriptor)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _child_directory(parent, name, *, create=False, exclusive=False):
    created = False
    if create:
        try:
            os.mkdir(name, 0o700, dir_fd=parent)
            created = True
        except FileExistsError:
            if exclusive:
                _conflict()
    descriptor = os.open(
        name, os.O_RDONLY | os.O_DIRECTORY | os.O_NOFOLLOW | os.O_CLOEXEC,
        dir_fd=parent,
    )
    try:
        _private_directory(descriptor)
        if created:
            os.fsync(descriptor)
            os.fsync(parent)
        return descriptor
    except BaseException:
        os.close(descriptor)
        raise


def _private_file_info(parent, name, *, maximum=None, minimum=0, readonly=False):
    value = os.stat(name, dir_fd=parent, follow_symlinks=False)
    if (
        not stat.S_ISREG(value.st_mode) or value.st_uid != os.geteuid()
        or value.st_nlink != 1
        or stat.S_IMODE(value.st_mode) not in ({0o400, 0o600} if readonly else {0o600})
        or value.st_size < minimum
        or (maximum is not None and value.st_size > maximum)
    ):
        _conflict()
    return value


def _read_file(parent, name, maximum, *, readonly=False):
    supplied = _private_file_info(parent, name, maximum=maximum, readonly=readonly)
    descriptor = os.open(
        name, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK | os.O_CLOEXEC,
        dir_fd=parent,
    )
    try:
        before = os.fstat(descriptor)
        if _file_facts(before) != _file_facts(supplied):
            _conflict()
        value = bytearray()
        while len(value) <= maximum:
            chunk = os.read(descriptor, min(65536, maximum + 1 - len(value)))
            if not chunk:
                break
            value.extend(chunk)
        after = os.fstat(descriptor)
        current = os.stat(name, dir_fd=parent, follow_symlinks=False)
        if (
            len(value) != before.st_size or len(value) > maximum
            or _file_facts(before) != _file_facts(after)
            or _file_facts(before) != _file_facts(current)
        ):
            _conflict()
        return bytes(value)
    finally:
        os.close(descriptor)


class ProfileFiles:
    """Publish one fixed configuration after its durable no-repair intent."""

    def __init__(self, store):
        self.store = store

    def prepare(self, root, policy, who):
        descriptors = []
        try:
            bundle = self.store.view(root, policy)
            actor, approved = bundle["actors"][who], bundle["policy"]
            config = actor["config"]
            if config is not None:
                if config["state"] != "ready":
                    _conflict()
                return self.check(root, policy, who)
            base = (
                self.store.journal.root / "public"
                / digest([root.worker_id, root.attempt_id]) / actor["identity_digest"]
            )
            document = {
                "schema_version": 1, "topic": approved.document["topic"],
                "scope_key_file": approved.server["scope_key_file"],
                "state_directory": str(base / "state"),
            }
            if "bootstrap" in approved.server:
                document["bootstrap"] = approved.server["bootstrap"]
            raw = canonical(document, limit=65536)
            config = {
                "state": "preparing", "path": str(base / "profile.json"),
                "state_directory": str(base / "state"), "document": document,
                "sha256": hashlib.sha256(raw).hexdigest(),
                "server_binding": approved.check_server(),
            }
            if not self.store.configuration_intent(root, policy, who, config):
                _conflict()
            # The intent now owns the absent actor leaf. Every new directory
            # entry is synchronized in its parent before readiness is retained.
            parent = _open_directory(self.store.journal.root)
            descriptors.append(parent)
            parent = _child_directory(parent, "public", create=True)
            descriptors.append(parent)
            parent = _child_directory(parent, digest([root.worker_id, root.attempt_id]), create=True)
            descriptors.append(parent)
            actor_directory = _child_directory(
                parent, actor["identity_digest"], create=True, exclusive=True,
            )
            descriptors.append(actor_directory)
            state = _child_directory(actor_directory, "state", create=True, exclusive=True)
            descriptors.append(state)
            descriptor = os.open(
                "profile.json",
                os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW | os.O_CLOEXEC,
                0o600, dir_fd=actor_directory,
            )
            try:
                offset = 0
                while offset < len(raw):
                    written = os.write(descriptor, raw[offset:])
                    if written <= 0:
                        _conflict()
                    offset += written
                os.fsync(descriptor)
            finally:
                os.close(descriptor)
            os.fsync(actor_directory)
            # A path swapped while we held descriptors cannot become the
            # launch path acknowledged as ready.
            reopened = _open_directory(base)
            try:
                first, second = os.fstat(actor_directory), os.fstat(reopened)
                if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
                    _conflict()
                if _read_file(reopened, "profile.json", 65536, readonly=True) != raw:
                    _conflict()
            finally:
                os.close(reopened)
            self.store.configuration_ready(root, policy, who, config | {"state": "ready"})
            return self.check(root, policy, who)
        except ManagedPublicError:
            raise
        except Exception:
            raise ManagedPublicError("state_conflict") from None
        finally:
            for descriptor in reversed(descriptors):
                os.close(descriptor)

    def check(self, root, policy, who):
        directory = state = reopened = None
        try:
            bundle = self.store.view(root, policy)
            actor, approved = bundle["actors"][who], bundle["policy"]
            config = actor["config"]
            if config is None or config["state"] != "ready":
                _conflict()
            if approved.check_server() != config["server_binding"]:
                _conflict()
            path = absolute_path(config["path"])
            directory = _open_directory(path.parent)
            if set(os.listdir(directory)) != {"profile.json", "state"}:
                _conflict()
            raw = _read_file(directory, "profile.json", 65536, readonly=True)
            if raw != canonical(config["document"]) or hashlib.sha256(raw).hexdigest() != config["sha256"]:
                _conflict()
            state = _child_directory(directory, "state")
            names = set(os.listdir(state))
            allowed = {
                "owner.lock", "identity.pem", "conversation.sqlite3", "binding.json",
                "conversation.sqlite3-journal", "conversation.sqlite3-wal", "conversation.sqlite3-shm",
            }
            if names - allowed:
                _conflict()
            server_started = any(
                item["actor_id"] == who and item["stage"] == "server"
                for item in bundle["processes"].values()
            )
            retained = actor["status"] is not None or server_started
            if retained:
                if not {"owner.lock", "identity.pem", "conversation.sqlite3", "binding.json"} <= names:
                    _conflict()
                for name in names:
                    try:
                        _private_file_info(
                            state, name,
                            maximum=4096 if name in {"identity.pem", "binding.json"} else None,
                            minimum=1 if name in {"identity.pem", "conversation.sqlite3", "binding.json"} else 0,
                        )
                    except FileNotFoundError:
                        # SQLite can remove an optional journal during a
                        # checkpoint. Its immutable required files must remain.
                        if name in {"owner.lock", "identity.pem", "conversation.sqlite3", "binding.json"}:
                            raise
                binding = object_value(
                    _read_file(state, "binding.json", 4096), 4096,
                    code="state_conflict", retained=True,
                )
                if actor["status"] is not None and binding != actor["status"]:
                    _conflict()
            elif names:
                # The actor has never started A. Unexpected retained files
                # cannot be adopted as its first signing identity.
                _conflict()
            reopened = _open_directory(path.parent)
            first, second = os.fstat(directory), os.fstat(reopened)
            if (first.st_dev, first.st_ino) != (second.st_dev, second.st_ino):
                _conflict()
            return ConversationLaunch(
                approved.document["topic"],
                {"python": approved.server["python"], "cwd": approved.server["cwd"], "config": str(path)},
                expected_config_hash=config["sha256"],
            )
        except ManagedPublicError:
            raise
        except Exception:
            raise ManagedPublicError("state_conflict") from None
        finally:
            for descriptor in (reopened, state, directory):
                if descriptor is not None:
                    os.close(descriptor)


class JournalLifecycle(ProcessLifecycleObserver):
    """Acknowledge only facts supplied by the existing owned-process adapter."""

    def __init__(self, store, root, policy, who, deadline, *, recovery_slot=None):
        if not isinstance(deadline, Deadline):
            _conflict()
        self.store, self.root, self.policy = store, root, policy
        self.who, self.deadline = who, deadline
        self.recovery_slot = recovery_slot
        self.files = ProfileFiles(store)

    def before_start(self, stage, argv, cwd, environment, deadline):
        self.deadline.remaining()
        launch = self.files.check(self.root, self.policy, self.who)
        expected = (
            (launch.python, "-I", "-c", PROBE) if stage == "probe"
            else (launch.python, "-m", "src.liminal_bridge.conversation_server", "--config", launch.config)
        )
        if (
            stage not in {"probe", "server"} or argv != expected or cwd != launch.cwd
            or environment != CHILD_ENVIRONMENT
            or deadline.monotonic_cutoff > self.deadline.monotonic_cutoff
            or deadline.expires_at > self.deadline.expires_at
        ):
            _conflict()
        value = self.store.process_intent(
            self.root, self.policy, self.who, stage,
            {
                "schema_version": 1, "stage": stage, "launch_path": launch.python,
                "cwd": cwd, "config_sha256": launch.config_sha256,
                "argv_sha256": digest(list(argv)), "environment_sha256": digest(environment),
                "monotonic_cutoff": deadline.monotonic_cutoff, "boot_id": self.root.boot_id,
            }, recovery_slot=self.recovery_slot,
        )
        # A storage wait cannot authorize Popen after the original deadline.
        self.deadline.remaining()
        deadline.remaining()
        return value["process_id"]

    def started(self, ticket, identity):
        self.store.process_identity(self.root, self.policy, ticket, identity)

    def finished(self, ticket, identity, confirmed):
        cleanup = None
        if confirmed is True and identity is not None:
            cleanup = {
                "identity": identity, "leader_terminated": True,
                "leader_reaped": True, "group_terminated": True,
            }
        self.store.process_finished(self.root, self.policy, ticket, identity, cleanup)


def _fixed(error):
    if isinstance(error, ManagedPublicError):
        return error
    if isinstance(error, DiscussionError) and error.code in {"expired", "state_conflict"}:
        return ManagedPublicError(error.code)
    return ManagedPublicError("transport_unavailable")


def _future():
    future = asyncio.get_running_loop().create_future()
    # A caller can time out while owned cleanup still runs. Always retrieve the
    # bounded fixed error even when nobody remains to await that acknowledgement.
    future.add_done_callback(lambda value: None if value.cancelled() else value.exception())
    return future


class _Profile:
    """One task enters and exits one MCP context, including every child scope."""

    def __init__(self, store, root, policy, who, deadline, recovery_slot):
        self.store, self.root, self.policy, self.who = store, root, policy, who
        self.deadline = Deadline(
            min(deadline.expires_at, root.deadline),
            min(deadline.monotonic_cutoff, root.monotonic_deadline),
        )
        self.recovery_slot = recovery_slot
        self.root_binding = canonical({
            name: value for name, value in root.to_dict().items()
            if name != "monotonic_deadline"
        })
        self.root_cutoff = root.monotonic_deadline
        self.policy_digest = policy.fingerprint
        self.policy_bytes = canonical(policy.public_discussion)
        self.files = ProfileFiles(store)
        self.ready = _future()
        self.commands = asyncio.Queue(maxsize=1)
        self.done = threading.Event()
        self.stopping = threading.Event()
        self.scope = None
        self.lifecycle = None
        self.failure = None
        self.task = None

    def reuse_deadline(self, root, policy, deadline):
        binding = canonical({
            name: value for name, value in root.to_dict().items()
            if name != "monotonic_deadline"
        })
        finite(root.monotonic_deadline, 0, 1e15, code="state_conflict")
        if (
            binding != self.root_binding or policy.fingerprint != self.policy_digest
            or canonical(policy.public_discussion) != self.policy_bytes
            or root.monotonic_deadline > self.root_cutoff
        ):
            _conflict()
        self.root_cutoff = root.monotonic_deadline
        self.deadline = Deadline(
            min(self.deadline.expires_at, root.deadline),
            min(self.deadline.monotonic_cutoff, self.root_cutoff),
        )
        if self.lifecycle is not None:
            self.lifecycle.deadline = self.deadline
        if self.scope is not None:
            self.scope.deadline = min(self.scope.deadline, self.deadline.monotonic_cutoff)
        return Deadline(
            min(deadline.expires_at, self.deadline.expires_at, root.deadline),
            min(deadline.monotonic_cutoff, self.deadline.monotonic_cutoff, self.root_cutoff),
        )

    def stop(self):
        # Called on the owner loop. Cancellation belongs to the outer AnyIO
        # scope, so the transport's existing shielded cleanup remains effective.
        self.stopping.set()
        if self.scope is not None:
            self.scope.cancel()

    def _allowed(self, action, arguments, requested_recovery=None):
        bundle = self.store.view(self.root, self.policy)
        actor = bundle["actors"][self.who]
        if requested_recovery is not None and (
            not actor["closed"] or requested_recovery != actor["leave_slot"]
        ):
            raise ManagedPublicError("not_authorized")
        if bundle["header"]["closed"] or bundle["header"]["frozen"] is not None:
            raise ManagedPublicError("not_authorized")
        if self.recovery_slot is not None or actor["closed"]:
            slot_id = actor["leave_slot"]
            if self.recovery_slot not in {None, slot_id}:
                _conflict()
            slot = bundle["slots"].get(slot_id)
            if (
                slot is None or slot["receipt"] is not None
                or slot["state"] in {"expired", "refused"}
                or slot["publication_intent"] is None
                or slot["publication_intent"]["kind"] != "leave"
                or (action != "ready" and (
                    action != "say" or arguments != {"intent": slot["publication_intent"]}
                ))
            ):
                raise ManagedPublicError("actor_left")

    async def run(self):
        pending = None
        failure = ManagedPublicError("transport_unavailable")
        try:
            with anyio.CancelScope(deadline=self.deadline.monotonic_cutoff) as scope:
                self.scope = scope
                if self.stopping.is_set():
                    return
                self.deadline.remaining()
                self._allowed("ready", {})
                launch = self.files.prepare(self.root, self.policy, self.who)
                if self.stopping.is_set():
                    return
                bundle = self.store.view(self.root, self.policy)
                actor = bundle["actors"][self.who]
                binding = actor["binding"]
                cleanup = CleanupObserver()
                lifecycle = JournalLifecycle(
                    self.store, self.root, self.policy, self.who, self.deadline,
                    recovery_slot=self.recovery_slot,
                )
                self.lifecycle = lifecycle
                async with connect(
                    launch, self.deadline, expected_status=actor["status"],
                    expected_interpreter=None if binding is None else binding["interpreter"],
                    cleanup=cleanup, lifecycle=lifecycle,
                ) as client:
                    bound = self.store.bind_actor(
                        self.root, self.policy, self.who, client.status, client.interpreter,
                    )
                    self.deadline.remaining()
                    self.ready.set_result(deepcopy(bound))
                    while not self.stopping.is_set():
                        try:
                            pending = await asyncio.wait_for(
                                self.commands.get(), timeout=self.deadline.remaining(),
                            )
                        except TimeoutError:
                            break
                        action, arguments, deadline, result = pending
                        deadline = Deadline(
                            min(self.deadline.expires_at, deadline.expires_at),
                            min(self.deadline.monotonic_cutoff, deadline.monotonic_cutoff),
                        )
                        deadline.remaining()
                        self._allowed(action, arguments)
                        self.files.check(self.root, self.policy, self.who)
                        # Same SDK session, wire accounting, immutable status and
                        # owner deadline. Only this operation can shorten its RPC.
                        bounded = ConversationClient(
                            client.session, client.launch, deadline,
                            client.wire, client.interpreter,
                        )
                        bounded.status = client.status
                        if action == "ready":
                            value = self.store.view(self.root, self.policy)["actors"][self.who]
                        elif action == "history":
                            value = await bounded.history(**arguments)
                        elif action == "say":
                            value = await bounded.say(arguments["intent"])
                        else:
                            _conflict()
                        if not result.done():
                            result.set_result(deepcopy(value))
                        pending = None
        except BaseException as error:
            failure = _fixed(error)
        finally:
            # connect has completed cleanup and lifecycle acknowledgement before
            # any failed operation is returned. A durable unknown row still
            # prevents capture even after this in-memory task has ended.
            self.scope = None
            self.failure = failure
            if not self.ready.done():
                self.ready.set_exception(failure)
            if pending is not None and not pending[3].done():
                pending[3].set_exception(failure)
            while not self.commands.empty():
                queued = self.commands.get_nowait()
                if not queued[3].done():
                    queued[3].set_exception(failure)
            self.done.set()

    async def ask(self, action, arguments, deadline):
        try:
            await asyncio.shield(self.ready)
            if self.done.is_set() or self.stopping.is_set():
                raise self.failure or ManagedPublicError("transport_unavailable")
            deadline.remaining()
            result = _future()
            try:
                self.commands.put_nowait((action, arguments, deadline, result))
            except asyncio.QueueFull:
                raise ManagedPublicError("retry_later") from None
            return await asyncio.shield(result)
        except asyncio.CancelledError:
            self.stop()
            raise


class OwnedProfiles:
    """Host-only loop, with one retained task per active worker/actor.

    The caller owns the existing worker-capacity admission and one public
    operation lease. This class never allocates a worker, grants work, invokes a
    model or reconnects within an operation. Completed workers must be released
    after their original process rows and capture barrier are accounted for.
    """

    def __init__(self, store):
        self.store = store
        self.guard = threading.RLock()
        self.entries = {}
        self.blocked = set()
        self.closing = False
        self.loop = None
        self.stop_event = None
        self.started = threading.Event()
        self.ended = threading.Event()
        self.thread = threading.Thread(
            target=self._thread, name="openjules-public-profiles", daemon=True,
        )
        self.thread.start()
        if not self.started.wait(5) or self.ended.is_set():
            self.close()
            raise ManagedPublicError("transport_unavailable")

    def _thread(self):
        try:
            asyncio.run(self._main())
        finally:
            self.started.set()
            self.ended.set()

    async def _main(self):
        self.loop = asyncio.get_running_loop()
        self.stop_event = asyncio.Event()
        self.started.set()
        with self.guard:
            if self.closing:
                self.stop_event.set()
        await self.stop_event.wait()
        with self.guard:
            entries = list(self.entries.values())
        for entry in entries:
            entry.stop()
        if entries:
            await asyncio.gather(*(entry.task for entry in entries), return_exceptions=True)

    async def _ask(self, root, policy, who, deadline, action, arguments, recovery_slot):
        deadline.remaining()
        key = (root.worker_id, who)
        with self.guard:
            if self.closing or root.worker_id in self.blocked:
                raise ManagedPublicError("not_authorized")
            entry = self.entries.get(key)
            fresh = entry is None or entry.done.is_set()
            if entry is None and sum(
                owner == root.worker_id for owner, _actor in self.entries
            ) >= 3:
                raise ManagedPublicError("slot_limit")
        if fresh:
            # The journal, not a discarded task, decides whether a second
            # explicit generation is permitted. There is no reconnect loop.
            entry = _Profile(self.store, root, policy, who, deadline, recovery_slot)
        # No pool mutex is held across a journal transaction. The second guard
        # below rechecks stop before publishing ownership or starting the task.
        deadline = entry.reuse_deadline(root, policy, deadline)
        entry._allowed(action, arguments, recovery_slot)
        with self.guard:
            if self.closing or root.worker_id in self.blocked:
                raise ManagedPublicError("not_authorized")
            if fresh:
                self.entries[key] = entry
                entry.task = asyncio.create_task(entry.run())
            elif entry.stopping.is_set():
                raise ManagedPublicError("retry_later")
        return await entry.ask(action, arguments, deadline)

    def call(self, root, policy, who, deadline, action, arguments=None, *, recovery_slot=None):
        if action not in {"ready", "history", "say"} or not isinstance(deadline, Deadline):
            _conflict()
        if arguments is None:
            arguments = {}
        arguments = object_value(canonical(arguments), retained=True)
        wait = deadline.remaining() + 5
        with self.guard:
            if self.closing or self.ended.is_set() or self.loop is None:
                raise ManagedPublicError("transport_unavailable")
            future = asyncio.run_coroutine_threadsafe(
                self._ask(root, policy, who, deadline, action, arguments, recovery_slot),
                self.loop,
            )
        try:
            return future.result(timeout=wait)
        except FutureTimeout:
            # Cancellation ends only the waiter; ask requests the owned scope
            # to stop. Capture still sees that task until cleanup completes.
            future.cancel()
            raise ManagedPublicError("transport_unavailable") from None
        except (ManagedPublicError, DiscussionError) as error:
            raise _fixed(error) from None
        except BaseException:
            future.cancel()
            raise

    def stop_actor(self, worker_id, who):
        with self.guard:
            entry = self.entries.get((worker_id, who))
            if entry is not None and not entry.done.is_set() and not self.ended.is_set():
                entry.stopping.set()
                self.loop.call_soon_threadsafe(entry.stop)

    def stop_worker(self, worker_id):
        with self.guard:
            self.blocked.add(worker_id)
            for (owner, _who), entry in self.entries.items():
                if owner == worker_id and not entry.done.is_set() and not self.ended.is_set():
                    entry.stopping.set()
                    self.loop.call_soon_threadsafe(entry.stop)

    def quiescent(self, worker_id, *, who=None):
        with self.guard:
            return all(
                entry.done.is_set() for (owner, _who), entry in self.entries.items()
                if owner == worker_id and (who is None or _who == who)
            )

    def release_worker(self, worker_id):
        with self.guard:
            if not self.quiescent(worker_id):
                raise ManagedPublicError("retry_later")
            for key in [key for key in self.entries if key[0] == worker_id]:
                del self.entries[key]
            self.blocked.discard(worker_id)

    def close(self):
        with self.guard:
            self.closing = True
            for entry in self.entries.values():
                entry.stopping.set()
            if self.loop is not None and self.stop_event is not None and not self.ended.is_set():
                self.loop.call_soon_threadsafe(self.stop_event.set)
        # Foreground close is bounded. The actual owner thread remains visible
        # until all contexts exit; callers must retain service ownership for it.
        if self.thread is not threading.current_thread():
            self.thread.join(timeout=1)
