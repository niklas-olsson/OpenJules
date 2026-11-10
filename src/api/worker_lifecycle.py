"""Opt-in authenticated worker lifecycle API consumed by ZPM.

Construct this app/router with deployment-owned credentials and a trusted
runtime. Importing it does not initialize Docker, an LLM, or a task executor.
The default lifecycle runtime reports unavailable and cannot launch work.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
import hmac

from fastapi import APIRouter, Body, FastAPI, Header, HTTPException

from src.worker.lifecycle import (
    LifecycleConflict,
    RuntimeUnavailable,
    WorkerLifecycle,
    WorkerNotFound,
    WorkerScope,
    WorkerSpec,
)


def create_worker_router(
    lifecycle: WorkerLifecycle,
    credentials: Mapping[str, Collection[WorkerScope]],
) -> APIRouter:
    """Use explicit bearer grants for exact deployment/repository scopes.

    Credentials are deployment configuration. They are never part of a
    repository binding, worker snapshot, model prompt, or runtime journal.
    """
    if not credentials:
        raise ValueError("explicit lifecycle credentials are required")
    grants = []
    for token, scopes in credentials.items():
        if not isinstance(token, str) or len(token) < 32:
            raise ValueError("lifecycle bearer tokens must contain at least 32 characters")
        scopes = frozenset(scopes)
        if not scopes or not all(isinstance(scope, WorkerScope) for scope in scopes):
            raise ValueError("each credential requires explicit worker scopes")
        grants.append((token, scopes))

    router = APIRouter(prefix="/api/workers", tags=["worker-lifecycle-v1"])

    def authorize(deployment_id: str, repository: str, header: str | None) -> WorkerScope:
        try:
            scope = WorkerScope(deployment_id, repository)
        except ValueError as error:
            raise HTTPException(422, detail=str(error)) from None
        scheme, separator, bearer = (header or "").partition(" ")
        if not separator or scheme.lower() != "bearer":
            raise HTTPException(401, detail="Bearer authentication required")
        matching = [
            scopes
            for token, scopes in grants
            if hmac.compare_digest(bearer.encode(), token.encode())
        ]
        if not matching:
            raise HTTPException(401, detail="Invalid lifecycle credential")
        if scope not in matching[0]:
            raise HTTPException(403, detail="Credential does not authorize this worker scope")
        return scope

    def invoke(function, *args):
        try:
            return function(*args)
        except WorkerNotFound as error:
            raise HTTPException(404, detail=str(error)) from None
        except LifecycleConflict as error:
            raise HTTPException(409, detail=str(error)) from None
        except RuntimeUnavailable as error:
            raise HTTPException(503, detail=str(error)) from None
        except (ValueError, TypeError) as error:
            raise HTTPException(422, detail=str(error)) from None

    def validate_body(payload: dict, required: set[str]) -> None:
        if set(payload) != required:
            raise HTTPException(422, detail="Request fields do not match the v1 contract")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != 1:
            raise HTTPException(422, detail="Unsupported schema_version")

    @router.get("/capabilities")
    def capabilities(
        deployment_id: str,
        repository: str,
        profile: str,
        authorization: str | None = Header(None),
    ):
        scope = authorize(deployment_id, repository, authorization)
        return invoke(lifecycle.capabilities, scope, profile)

    @router.post("/ensure")
    def ensure(payload: dict = Body(...), authorization: str | None = Header(None)):
        validate_body(
            payload,
            {
                "schema_version", "deployment_id", "repository", "slot_id",
                "generation", "launch_key", "profile",
            },
        )
        authorize(payload["deployment_id"], payload["repository"], authorization)
        spec = invoke(lambda: WorkerSpec(**payload))
        return invoke(lifecycle.ensure_worker, spec)

    @router.get("")
    def discover(
        deployment_id: str,
        repository: str,
        launch_key: str | None = None,
        authorization: str | None = Header(None),
    ):
        scope = authorize(deployment_id, repository, authorization)
        return {
            "schema_version": 1,
            "workers": invoke(lifecycle.discover_workers, scope, launch_key),
        }

    @router.get("/{worker_id}")
    def observe(
        worker_id: str,
        deployment_id: str,
        repository: str,
        authorization: str | None = Header(None),
    ):
        scope = authorize(deployment_id, repository, authorization)
        return invoke(lifecycle.observe_worker, scope, worker_id)

    def control(action: str, worker_id: str, payload: dict, authorization: str | None):
        validate_body(
            payload, {"schema_version", "deployment_id", "repository", "request_key"}
        )
        scope = authorize(payload["deployment_id"], payload["repository"], authorization)
        return invoke(
            getattr(lifecycle, action + "_worker"), scope, worker_id, payload["request_key"]
        )

    @router.post("/{worker_id}/drain")
    def drain(
        worker_id: str, payload: dict = Body(...), authorization: str | None = Header(None)
    ):
        return control("drain", worker_id, payload, authorization)

    @router.post("/{worker_id}/stop")
    def stop(
        worker_id: str, payload: dict = Body(...), authorization: str | None = Header(None)
    ):
        return control("stop", worker_id, payload, authorization)

    return router


def create_worker_app(
    lifecycle: WorkerLifecycle, credentials: Mapping[str, Collection[WorkerScope]]
) -> FastAPI:
    """Small deployable API surface, also mountable in the existing service."""
    app = FastAPI(title="OpenJules Worker Lifecycle", version="1")
    app.include_router(create_worker_router(lifecycle, credentials))
    return app
