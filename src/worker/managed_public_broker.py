"""Fixed-UID managed public sockets using the existing bounded transport."""

from __future__ import annotations

from pathlib import Path
import stat
import threading
from types import SimpleNamespace

from .lifecycle import RuntimeUnavailable
from .managed_public_types import (
    ManagedPublicError, REQUEST_LIMIT, RESPONSE_LIMIT, canonical,
)
from .model_broker import BrokerDenied, ModelBroker, _Endpoint


class _PublicContext:
    _read = staticmethod(ModelBroker._read)

    def __init__(self, owner, worker_id, child_id, uid):
        self.owner, self.worker_id, self.child_id = owner, worker_id, child_id
        self.uid = uid

    def peer_uid_for_worker(self, _actor_id):
        # Both the acceptor and the original handler revalidate this exact
        # immutable host identity. No body field chooses an actor or UID.
        return self.uid

    def policy_for_worker(self, _actor_id):
        policy = self.owner.model.policy_for_worker(self.worker_id)
        return SimpleNamespace(max_request_bytes=min(REQUEST_LIMIT, policy.max_request_bytes))

    def complete(self, _actor_id, payload):
        try:
            value = self.owner.supervisor.handle(
                self.worker_id, payload, child_id=self.child_id,
            )
            policy = self.owner.model.policy_for_worker(self.worker_id)
            canonical(value, limit=min(RESPONSE_LIMIT, policy.max_response_bytes))
            return value
        except ManagedPublicError as error:
            raise BrokerDenied(error.code) from None
        except RuntimeUnavailable:
            raise BrokerDenied("transport_unavailable") from None


class _ProfileOwner:
    """Keep the original model service lease until the actual owner thread ends."""

    def __init__(self, profiles):
        self.profiles = profiles
        self.thread = profiles.thread
        self.stop_requested = threading.Event()

    def stop(self):
        self.stop_requested.set()
        self.profiles.close()


class PublicBroker:
    def __init__(self, supervisor):
        self.supervisor, self.model = supervisor, supervisor.model
        self.guard = threading.RLock()
        self.endpoints = {}
        self.closed = False
        owner = _ProfileOwner(supervisor.profiles)
        with self.model.guard:
            if self.model.closed or "/public-owner" in self.model.endpoints:
                owner.stop()
                raise RuntimeUnavailable("managed public ownership is unavailable")
            self.model.endpoints["/public-owner"] = owner

    def _prepare(self, worker_id, spec, directory, child_id, uid):
        if not self.supervisor.enabled(spec):
            return
        key = (worker_id, "root" if child_id is None else child_id)
        expected = self.model.root / worker_id
        if child_id is not None:
            expected = expected / "children" / child_id
        directory = Path(directory)
        if (
            directory != expected or directory.is_symlink() or not directory.is_dir()
            or stat.S_IMODE(directory.stat().st_mode) != 0o711
        ):
            raise RuntimeUnavailable("managed public endpoint directory changed")
        with self.guard:
            if self.closed:
                raise RuntimeUnavailable("managed public transport is closed")
            old = self.endpoints.get(key)
            if not self.supervisor.endpoint_allowed(worker_id):
                if old is not None:
                    old.stop()
                return
            if old is not None:
                if old.thread.is_alive():
                    if old.stop_requested.is_set():
                        raise RuntimeUnavailable("managed public endpoint is stopping")
                    return
                # Listener failure is not an implicit replacement generation.
                if not old.stop_requested.is_set():
                    raise RuntimeUnavailable("managed public listener exited")
            context = _PublicContext(self, worker_id, child_id, uid)
            endpoint = _Endpoint(context, key[1], directory, socket_name="public.sock")
            with self.model.guard:
                if self.model.closed:
                    endpoint.stop()
                    raise RuntimeUnavailable("root model broker is closed")
                self.model.endpoints["/public/" + worker_id + "/" + key[1]] = endpoint
            self.endpoints[key] = endpoint

    def prepare_root(self, worker_id, spec, directory):
        self._prepare(
            worker_id, spec, directory, None,
            self.model.peer_uid_for_worker(worker_id),
        )

    def prepare_child(self, root, child, directory):
        self._prepare(
            root.worker_id, root.spec, directory, child["child_id"], child["uid"],
        )

    def stop_worker(self, worker_id):
        with self.guard:
            for (owner, _who), endpoint in self.endpoints.items():
                if owner == worker_id:
                    endpoint.stop()

    def quiescent(self, worker_id):
        with self.guard:
            return all(
                not endpoint.thread.is_alive()
                for (owner, _who), endpoint in self.endpoints.items()
                if owner == worker_id
            )

    def release_worker(self, worker_id):
        with self.guard:
            keys = [key for key in self.endpoints if key[0] == worker_id]
            if any(self.endpoints[key].thread.is_alive() for key in keys):
                raise RuntimeUnavailable("managed public socket owner is active")
            for key in keys:
                endpoint = self.endpoints.pop(key)
                name = "/public/" + worker_id + "/" + key[1]
                with self.model.guard:
                    if self.model.endpoints.get(name) is endpoint:
                        del self.model.endpoints[name]

    def all_quiescent(self):
        with self.guard:
            return all(not endpoint.thread.is_alive() for endpoint in self.endpoints.values())

    def stop_all(self):
        with self.guard:
            self.closed = True
            for endpoint in self.endpoints.values():
                endpoint.stop()

    def join(self):
        with self.guard:
            endpoints = list(self.endpoints.values())
        for endpoint in endpoints:
            endpoint.thread.join()
