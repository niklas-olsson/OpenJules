"""Single-host managed OpenJules service with an approved Docker runtime.

Run: python -m src.worker.managed_service --config /private/openjules.json
Repository code receives neither the Docker socket nor authority credentials.
"""

from __future__ import annotations

import argparse
import asyncio
from contextlib import asynccontextmanager
import json
import os
from pathlib import Path
import stat
import threading

from src.api.worker_lifecycle import create_worker_app
from src.worker.authority_errors import (
    AuthorityUnavailable,
    AuthorityUnsupported,
    UNSUPPORTED_CHILD_OUTCOME_REASON,
)
from src.worker.lifecycle import (
    CapabilityDiagnostic, RuntimeCapabilities, WorkerLifecycle, WorkerScope,
)
from src.worker.execution_context import (
    enter_managed_context, select_managed_context, validate_managed_installation,
)
from src.worker.destination import (
    DestinationState, initialize_destination,
)
from src.worker.managed_configuration import (
    MAX_CONFIGURATION_BYTES, parse_configuration_bytes, prepare_configuration,
)


def _read_object(path: Path, *, private: bool = False) -> dict:
    if path.is_symlink() or not path.is_file():
        raise ValueError("configuration must be a regular file")
    info = path.stat()
    if private and stat.S_IMODE(info.st_mode) & 0o077:
        raise ValueError("credential file must have mode 0600")
    if info.st_size > MAX_CONFIGURATION_BYTES:
        raise ValueError("configuration file is too large")
    with path.open("rb") as source:
        raw = source.read(MAX_CONFIGURATION_BYTES + 1)
    return parse_configuration_bytes(raw)


def load_configuration(path: str | Path, *, managed_context=False):
    config = _read_object(Path(path))
    # Every selected policy and scheduler/authority bound precedes secret reads.
    prepare_configuration(config)
    if managed_context:
        enter_managed_context()
    credentials = _read_object(Path(config["credentials_file"]), private=True)
    scopes = {}
    for token, grants in credentials.items():
        if (
            not isinstance(token, str)
            or len(token) < 32
            or any(c.isspace() for c in token)
            or not isinstance(grants, list)
            or not grants
        ):
            raise ValueError("invalid scoped worker credential configuration")
        scopes[token] = []
        for grant in grants:
            if not isinstance(grant, dict) or set(grant) != {
                "deployment_id",
                "repository",
            }:
                raise ValueError(
                    "worker credentials require explicit deployment/repository scopes"
                )
            scopes[token].append(WorkerScope(**grant))
    if not scopes:
        raise ValueError("explicit scoped worker credentials are required")
    return config, scopes


def build_app(config: dict, credentials: dict, *, cleanup_only=False):
    # Direct callers use exactly the same pure schema-1 phase as file loading.
    # No destination, broker, credential resolver or host check can precede it.
    prepared = prepare_configuration(config)
    validate_managed_installation()
    profiles = prepared.profiles
    profile_by_scope = prepared.profile_by_scope
    model_policies = prepared.model_policies
    child_policies = prepared.child_policies
    authorized_scopes = {scope for grants in credentials.values() for scope in grants}
    if any(
        WorkerScope(p.deployment_id, p.repository) not in authorized_scopes
        for p in profiles
    ):
        raise ValueError("every profile requires an explicit ZPM credential scope")

    destination = DestinationState.load(config)

    def journal_context(member):
        return {"journal_binding": destination.member(member)} if destination else {}

    from src.worker.docker_runtime import ManagedDockerRuntime
    from src.worker.managed_dispatch import ManagedDispatcher
    from src.polyphony.managed_client import ManagedAuthorityClient

    authority = ManagedAuthorityClient(**config["authority"])
    dispatcher = None
    model_broker = None
    child_supervisor = None
    if model_policies:
        from src.worker.model_broker import ModelBroker

        def model_permission(binding):
            return 0 if dispatcher is None else dispatcher.model_permission(binding)

        model_broker = ModelBroker(
            Path(config["state_directory"]) / "models",
            model_policies,
            model_permission,
            peer_uids={key: profile_by_scope[key].uid for key in model_policies},
            **journal_context("models"),
        )
        try:
            if not cleanup_only and destination is None:
                model_broker.check_ready()
        except BaseException:
            model_broker.close()
            raise

    try:
        for public_policy in prepared.public_policies.values():
            public_policy.check_server()
    except BaseException:
        if model_broker is not None:
            model_broker.close()
        raise

    def readiness(scope, name):
        profile = profile_by_scope.get((scope.deployment_id, scope.repository, name))
        if profile is None:
            return RuntimeCapabilities(
                reason="Approved profile is unavailable in this scope"
            )
        if (
            dispatcher is None
            or not dispatcher.running.is_set()
            or dispatcher.stop_requested.is_set()
        ):
            return RuntimeCapabilities(
                profile_supported=True, reason="Managed dispatcher is not running"
            )
        try:
            canonical_capabilities = authority.capabilities(
                scope, name, profile.base_commit
            )
            child_policy = child_policies.get(
                (scope.deployment_id, scope.repository, name)
            )
            if child_policy is not None:
                child_policy.validate_capabilities(canonical_capabilities)
        except AuthorityUnsupported:
            return RuntimeCapabilities(
                profile_supported=True,
                reason=UNSUPPORTED_CHILD_OUTCOME_REASON,
                diagnostic=CapabilityDiagnostic.CHILD_INITIAL_OUTCOME_UNSUPPORTED,
            )
        except AuthorityUnavailable:
            return RuntimeCapabilities(
                profile_supported=True,
                reason="Canonical managed authority is unavailable",
            )
        model_key = (scope.deployment_id, scope.repository, name)
        if model_key in model_policies:
            token = os.environ.get(model_policies[model_key].token_ref[4:])
            if not token or any(character.isspace() for character in token):
                return RuntimeCapabilities(
                    profile_supported=True,
                    reason="Configured model credential is unavailable",
                )
            try:
                model_broker.check_ready()
            except Exception:
                return RuntimeCapabilities(
                    profile_supported=True,
                    reason="Managed model transport is unavailable",
                )
        # Docker/source preflight remains the runtime's responsibility.
        return RuntimeCapabilities(
            True,
            True,
            True,
            (
                "Canonical root and bounded child dispatch are available"
                if model_key in child_policies
                else "Canonical root dispatch is available; child delegation is unsupported"
            ),
        )

    state = Path(config["state_directory"])
    try:
        runtime = ManagedDockerRuntime(
            state / "runtime",
            profiles,
            readiness,
            model_broker=model_broker,
            **({"child_policies": child_policies} if child_policies else {}),
            **journal_context("runtime"),
        )
        lifecycle = WorkerLifecycle(config["lifecycle_database"], runtime, destination=destination)
        if child_policies:
            from src.worker.child_supervisor import ChildSupervisor
            from src.worker.child_broker import ChildBroker
            from src.worker.model_broker import ModelBinding

            def child_root_permission(context):
                return (
                    0
                    if dispatcher is None
                    else dispatcher.model_permission(
                        ModelBinding(
                            context.worker_id, context.attempt_id, context.spec
                        )
                    )
                )

            def child_root_active(context):
                return dispatcher is not None and dispatcher.child_root_active(context)

            child_supervisor = ChildSupervisor(
                state / "children",
                child_policies,
                authority,
                lifecycle,
                runtime,
                model_broker,
                child_root_permission,
                child_root_active,
                **journal_context("children"),
            )
            child_supervisor.endpoints = ChildBroker(child_supervisor, model_broker)
            runtime.child_supervisor = child_supervisor
            model_broker.child_supervisor = child_supervisor
            if any(policy.public_discussion is not None for policy in child_policies.values()):
                from src.worker.managed_public import PublicSupervisor
                from src.worker.managed_public_broker import PublicBroker

                public = PublicSupervisor(child_supervisor)
                child_supervisor.public_supervisor = public
                public.endpoints = PublicBroker(public)
                model_broker.public_supervisor = public
        dispatcher = ManagedDispatcher(
            lifecycle,
            runtime,
            authority,
            profiles,
            state / "dispatcher",
            poll_interval_seconds=config.get("poll_interval_seconds", 1),
            max_parallel=config.get("max_parallel", 16),
            model_broker=model_broker,
            **journal_context("dispatcher"),
            **(
                {"child_supervisor": child_supervisor}
                if child_supervisor is not None
                else {}
            ),
        )
        if destination is not None:
            destination.activate()
            if model_broker is not None and not cleanup_only:
                model_broker.check_ready()
        app = create_worker_app(lifecycle, credentials)
    except BaseException:
        if child_supervisor is not None:
            child_supervisor.close()
        if model_broker is not None:
            model_broker.close()
        raise

    @asynccontextmanager
    async def lifespan(_app):
        if model_broker is not None:
            try:
                runtime.restore_model_endpoints()
                model_broker.check_ready()
            except BaseException:
                if child_supervisor is not None:
                    child_supervisor.close()
                model_broker.close()
                raise
        failed = threading.Event()

        def supervise():
            try:
                dispatcher.run()
            except Exception:
                failed.set()

        thread = threading.Thread(
            target=supervise, name="managed-dispatcher", daemon=True
        )
        thread.start()
        deadline = asyncio.get_running_loop().time() + 5
        while not dispatcher.running.is_set():
            if (
                failed.is_set()
                or not thread.is_alive()
                or asyncio.get_running_loop().time() >= deadline
            ):
                dispatcher.stop()
                if child_supervisor is not None:
                    child_supervisor.close()
                if model_broker is not None:
                    model_broker.close()
                raise RuntimeError(
                    "Managed dispatcher could not acquire its service lock"
                )
            await asyncio.sleep(0.01)
        try:
            yield
        finally:
            dispatcher.stop()
            await asyncio.to_thread(thread.join, 6)
            if child_supervisor is not None:
                await asyncio.to_thread(child_supervisor.close)
            if model_broker is not None:
                await asyncio.to_thread(model_broker.close)

    app.router.lifespan_context = lifespan
    app.state.managed_dispatcher = dispatcher
    app.state.worker_lifecycle = lifecycle
    app.state.model_broker = model_broker
    app.state.child_supervisor = child_supervisor
    return app


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--config", required=True)
    identity = parser.add_mutually_exclusive_group()
    identity.add_argument(
        "--initialize-destination", action="store_true",
        help="initialize a fresh private destination journal set while the service is stopped",
    )
    identity.add_argument(
        "--inspect-destination", action="store_true",
        help="read original destination identifiers without repair or runtime calls",
    )
    parser.add_argument(
        "--cleanup-worker",
        help="explicitly clean one fully captured executed worker while service is stopped",
    )
    parser.add_argument("--deployment-id")
    parser.add_argument("--repository")
    args = parser.parse_args()
    if (args.initialize_destination or args.inspect_destination) and args.cleanup_worker:
        parser.error("destination maintenance and worker cleanup are separate stopped-service operations")
    if bool(args.cleanup_worker) != bool(args.deployment_id and args.repository) or (
        not args.cleanup_worker and (args.deployment_id or args.repository)
    ):
        parser.error("cleanup requires worker, deployment and repository together")
    try:
        # Preserve blanket legacy refusal even if static configuration fails.
        # Actual selector/config host reads occur only after the pure phase.
        select_managed_context()
        config, credentials = load_configuration(args.config, managed_context=True)
        if args.initialize_destination or args.inspect_destination:
            if args.initialize_destination:
                result = initialize_destination(config)
            else:
                destination = DestinationState.load(config)
                if destination is None:
                    raise ValueError("no initialized execution destination is configured")
                result = destination.inspection()
            print(json.dumps(result, sort_keys=True))
            return
        app = build_app(config, credentials, cleanup_only=bool(args.cleanup_worker))
    except (ValueError, TypeError, KeyError, OSError):
        parser.error(
            "managed service configuration is invalid; check schema, private files and runtime prerequisites"
        )
    if args.cleanup_worker:
        try:
            result = app.state.managed_dispatcher.cleanup_worker(
                WorkerScope(args.deployment_id, args.repository), args.cleanup_worker
            )
            print(json.dumps(result, sort_keys=True))
        finally:
            if app.state.child_supervisor is not None:
                app.state.child_supervisor.close()
            if app.state.model_broker is not None:
                app.state.model_broker.close()
            client = app.state.managed_dispatcher.runtime._client
            if client is not None:
                client.close()
        raise SystemExit(0 if result["state"] == "cleaned" else 1)
    import uvicorn

    uvicorn.run(
        app, host=config.get("host", "127.0.0.1"), port=config.get("port", 8000)
    )


if __name__ == "__main__":
    main()
