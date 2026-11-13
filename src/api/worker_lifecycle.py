"""Opt-in authenticated worker lifecycle API consumed by ZPM.

Construct this app/router with deployment-owned credentials and a trusted
runtime. Importing it does not initialize Docker, an LLM, or a task executor.
The default lifecycle runtime reports unavailable and cannot launch work.
"""

from __future__ import annotations

from collections.abc import Collection, Mapping
import hmac
import json

from fastapi import APIRouter, Body, Depends, FastAPI, Header, HTTPException, Request

from src.worker.destination import (
    BINDING_FIELDS, DestinationConflict, DestinationUnavailable, parse_binding,
)

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
    *, version: int = 1,
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

    if version not in (1, 2):
        raise ValueError("unsupported worker API version")
    router = APIRouter(
        prefix="/api/v2/workers" if version == 2 else "/api/workers",
        tags=[f"worker-lifecycle-v{version}"],
    )

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
        if version == 1 and lifecycle.destination is not None:
            raise HTTPException(409, detail="Bound destination requires the v2 identity contract")
        return scope

    def invoke(function, *args, **kwargs):
        try:
            return function(*args, **kwargs)
        except WorkerNotFound as error:
            raise HTTPException(404, detail=str(error)) from None
        except (LifecycleConflict, DestinationConflict) as error:
            raise HTTPException(409, detail=str(error)) from None
        except (RuntimeUnavailable, DestinationUnavailable) as error:
            raise HTTPException(503, detail=str(error)) from None
        except (ValueError, TypeError) as error:
            raise HTTPException(422, detail=str(error)) from None

    def validate_body(payload: dict, required: set[str]) -> None:
        if set(payload) != required:
            raise HTTPException(422, detail=f"Request fields do not match the v{version} contract")
        if type(payload["schema_version"]) is not int or payload["schema_version"] != version:
            raise HTTPException(422, detail="Unsupported schema_version")

    if version == 2:
        async def strict_payload(request: Request):
            raw = bytearray()
            async for chunk in request.stream():
                raw.extend(chunk)
                if len(raw) > 65536:
                    raise HTTPException(422, detail="V2 request exceeds its bound")

            def pairs(items):
                result = {}
                for key, value in items:
                    if key in result:
                        raise ValueError("duplicate JSON field")
                    result[key] = value
                return result

            try:
                value = json.loads(raw, object_pairs_hook=pairs)
                if not isinstance(value, dict):
                    raise ValueError("request must be an object")
                return value
            except (ValueError, UnicodeError, RecursionError):
                raise HTTPException(422, detail="Invalid unambiguous v2 JSON object") from None

        def projection(result, binding):
            return {**result, "schema_version": 2, "destination_binding": dict(binding)}

        def query(request, required, *, optional=frozenset()):
            pairs = list(request.query_params.multi_items())
            values = dict(pairs)
            required = set(required) | BINDING_FIELDS | {"schema_version", "deployment_id", "repository"}
            if len(pairs) != len(values) or not required <= set(values) or not set(values) <= required | optional:
                raise HTTPException(422, detail="Query fields do not match the v2 contract")
            if values["schema_version"] != "2" or values["policy_binding_version"] != "1":
                raise HTTPException(422, detail="Unsupported identity contract version")
            binding = {key: values[key] for key in BINDING_FIELDS}
            binding["policy_binding_version"] = 1
            return values, invoke(parse_binding, binding)

        @router.get("/capabilities")
        def bound_capabilities(
            request: Request, deployment_id: str, repository: str,
            authorization: str | None = Header(None),
        ):
            scope = authorize(deployment_id, repository, authorization)
            values, binding = query(request, {"profile"})
            invoke(lifecycle.validate_binding, scope, binding, values["profile"])
            result = invoke(lifecycle.capabilities, scope, values["profile"])
            return projection(result | {
                "identity_binding": 1, "portable_manifest": False, "local_admission": False,
            }, binding)

        @router.post("/ensure")
        def bound_ensure(payload: dict = Depends(strict_payload), authorization: str | None = Header(None)):
            validate_body(payload, {
                "schema_version", "deployment_id", "repository", "slot_id",
                "generation", "launch_key", "profile", "destination_binding",
            })
            scope = authorize(payload["deployment_id"], payload["repository"], authorization)
            binding = invoke(parse_binding, payload["destination_binding"])
            invoke(lifecycle.validate_binding, scope, binding, payload["profile"])
            spec = invoke(lambda: WorkerSpec(**{
                **{key: value for key, value in payload.items() if key != "destination_binding"},
                "schema_version": 1,
            }))
            return projection(invoke(lifecycle.ensure_worker, spec, binding), binding)

        @router.get("")
        def bound_discover(
            request: Request, deployment_id: str, repository: str,
            authorization: str | None = Header(None),
        ):
            scope = authorize(deployment_id, repository, authorization)
            values, binding = query(request, {"profile"}, optional={"launch_key"})
            invoke(lifecycle.validate_binding, scope, binding, values["profile"])
            workers = invoke(
                lifecycle.discover_workers, scope, values.get("launch_key"), profile=values["profile"],
            )
            return projection({"workers": [projection(worker, binding) for worker in workers]}, binding)

        @router.get("/{worker_id}")
        def bound_observe(
            worker_id: str, request: Request, deployment_id: str, repository: str,
            authorization: str | None = Header(None),
        ):
            scope = authorize(deployment_id, repository, authorization)
            _, binding = query(request, set())
            invoke(lifecycle.validate_worker_binding, scope, worker_id, binding)
            return projection(invoke(lifecycle.observe_worker, scope, worker_id), binding)

        def bound_control(action, worker_id, payload, authorization):
            validate_body(payload, {
                "schema_version", "deployment_id", "repository", "request_key", "destination_binding",
            })
            scope = authorize(payload["deployment_id"], payload["repository"], authorization)
            binding = invoke(parse_binding, payload["destination_binding"])
            invoke(lifecycle.validate_worker_binding, scope, worker_id, binding)
            return projection(invoke(
                getattr(lifecycle, action + "_worker"), scope, worker_id, payload["request_key"],
            ), binding)

        @router.post("/{worker_id}/drain")
        def bound_drain(worker_id: str, payload: dict = Depends(strict_payload), authorization: str | None = Header(None)):
            return bound_control("drain", worker_id, payload, authorization)

        @router.post("/{worker_id}/stop")
        def bound_stop(worker_id: str, payload: dict = Depends(strict_payload), authorization: str | None = Header(None)):
            return bound_control("stop", worker_id, payload, authorization)

        return router

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
    app.include_router(create_worker_router(lifecycle, credentials, version=2))
    return app
