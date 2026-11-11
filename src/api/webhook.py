"""GitHub and Radicle Webhook handler and FastAPI control plane."""

import hashlib
import hmac
import json
import logging
import os
from pathlib import Path
from typing import Any, Dict, Optional

from fastapi import BackgroundTasks, FastAPI, Header, HTTPException, Request, Response
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, Field, ValidationError

from src.worker.execution_context import LegacyExecutionRefused, require_legacy_execution

# Refuse before importing routers that create legacy storage/provisioners.
require_legacy_execution()

from src.api.polyphony_routes import polyphony_router
from src.api.ui_routes import record_ui_task, ui_router
from src.api.ws import ws_manager, ws_router
from src.worker.dispatcher import BackgroundTasksDispatcher, TaskDispatcher, TaskPayload
from src.worker.executor import TaskExecutor
from src.worker.pr_reviewer import (
    PRReviewHandler,
    ReviewComment,
    ReviewSourceRejected,
    require_legacy_review_source,
)

pr_review_handler = PRReviewHandler()

logger = logging.getLogger(__name__)

app = FastAPI(
    title="OpenJules Control Plane & Dashboard",
    description="Autonomous Sandboxed Coding Agent Service API & 3-Pane UI for GitHub and Radicle",
    version="0.3.0",
)

executor = TaskExecutor()


@app.exception_handler(LegacyExecutionRefused)
async def legacy_execution_refused(_request, exc):
    return JSONResponse(status_code=409, content={"detail": exc.reason})


# Include dashboard, UI, and Polyphony endpoints
app.include_router(ui_router)
app.include_router(ws_router)
app.include_router(polyphony_router)

# Mount static files
static_dir = Path(__file__).parent.parent / "ui" / "static"
if static_dir.is_dir():
    app.mount("/static", StaticFiles(directory=str(static_dir)), name="static")


@app.get("/")
def serve_dashboard():
    """Serves the intuitive 3-pane web interface."""
    index_file = static_dir / "index.html"
    if index_file.is_file():
        return FileResponse(str(index_file))
    return {"message": "OpenJules Dashboard"}


def verify_github_signature(payload_body: bytes, signature_header: Optional[str], secret: str) -> bool:
    """Verifies that the webhook payload was sent from GitHub using HMAC-SHA256."""
    if not secret:
        return True
    if not signature_header:
        return False
    parts = signature_header.split("=", 1)
    if len(parts) != 2 or parts[0] != "sha256":
        return False
    expected_hash = hmac.new(secret.encode("utf-8"), payload_body, hashlib.sha256).hexdigest()
    return hmac.compare_digest(expected_hash, parts[1])


def _dispatch_review_event(payload, event, background_tasks):
    """Validate only the legacy review event before selecting or queuing work."""
    require_legacy_execution()
    try:
        if not isinstance(payload, dict) or not isinstance(payload.get("action"), str):
            raise ReviewSourceRejected("invalid_legacy_review_source")
        expected_action = (
            "created" if event == "pull_request_review_comment" else "submitted"
        )
        if payload["action"] != expected_action:
            return {
                "status": "ignored",
                "reason": "No relevant OpenJules review action",
            }
        pr_data = payload.get("pull_request")
        comment = payload.get(
            "comment" if event == "pull_request_review_comment" else "review"
        )
        repository = payload.get("repository")
        if not all(isinstance(value, dict) for value in (pr_data, comment, repository)):
            raise ReviewSourceRejected("invalid_legacy_review_source")
        head = pr_data.get("head")
        author = comment.get("user", {})
        if not isinstance(head, dict) or not isinstance(author, dict):
            raise ReviewSourceRejected("invalid_legacy_review_source")
        branch = head.get("ref")
        body = comment.get("body")
        # Missing/null PR body is valid absent context.
        source_body = pr_data.get("body")
        clone_url = repository.get("clone_url")
        login = author.get("login", "")
        comment_id = comment.get("id", 0)
        path, line = comment.get("path"), comment.get("line")
        if (
            not isinstance(body, str)
            or not isinstance(clone_url, str)
            or not clone_url
            or not isinstance(login, str)
            or type(comment_id) not in {int, str}
            or (path is not None and not isinstance(path, str))
            or (line is not None and type(line) is not int)
        ):
            raise ReviewSourceRejected("invalid_legacy_review_source")
        require_legacy_review_source(branch, source_body, body)
    except ReviewSourceRejected as exc:
        status = (
            409
            if exc.reason == "managed_publication_requires_canonical_review"
            else 400
        )
        raise HTTPException(status_code=status, detail=exc.reason) from None

    if "/jules" not in body and not branch.startswith("openjules/"):
        return {
            "status": "ignored",
            "reason": "No relevant OpenJules trigger in webhook payload",
        }
    review_comment = ReviewComment(
        id=comment_id,
        body=body,
        path=path,
        line=line,
        author=login,
    )
    background_tasks.add_task(
        pr_review_handler.address_review_feedback,
        repo_clone_url=clone_url,
        branch_name=branch,
        comments=[review_comment],
        source_body=source_body,
    )
    return {
        "status": "review_iteration_dispatched",
        "branch": branch,
        "comment_id": comment_id,
    }


def _dispatch_issue_comment(payload, background_tasks):
    """Keep PR conversation commands out of the legacy issue-task executor."""
    require_legacy_execution()
    invalid = "invalid_issue_comment_source"
    ignored = {
        "status": "ignored",
        "reason": "No relevant OpenJules trigger in webhook payload",
    }
    if not isinstance(payload, dict):
        raise HTTPException(status_code=400, detail=invalid)
    action = payload.get("action", "")
    if not isinstance(action, str):
        raise HTTPException(status_code=400, detail=invalid)
    if action != "created":
        return ignored
    comment = payload.get("comment", {})
    if not isinstance(comment, dict):
        raise HTTPException(status_code=400, detail=invalid)
    body = comment.get("body", "")
    if not isinstance(body, str):
        raise HTTPException(status_code=400, detail=invalid)
    if "/jules run" not in body and "/openjules run" not in body:
        return ignored

    issue = payload.get("issue", {})
    if not isinstance(issue, dict):
        raise HTTPException(status_code=400, detail=invalid)
    repository = payload.get("repository", {})
    installation = payload.get("installation", {})
    author = comment.get("user", {})
    if not all(isinstance(value, dict) for value in (repository, installation, author)):
        raise HTTPException(status_code=400, detail=invalid)
    if "pull_request" in issue:
        if not isinstance(issue["pull_request"], dict):
            raise HTTPException(status_code=400, detail=invalid)
        # issue_comment has no actual PR head identity. A missing or removed
        # publication marker cannot make its issue-task execution path safe.
        raise HTTPException(
            status_code=409,
            detail="pull_request_comment_requires_review_event",
        )

    try:
        task_payload = TaskPayload(
            forge="github",
            issue_id=issue.get("number"),
            issue_title=issue.get("title", ""),
            issue_body=issue.get("body", "") or "",
            repo_full_name=repository.get("full_name", ""),
            repo_clone_url=repository.get("clone_url", ""),
            default_branch=repository.get("default_branch", "main"),
            installation_id=installation.get("id"),
            sender=author.get("login", ""),
        )
    except ValidationError:
        raise HTTPException(status_code=400, detail=invalid) from None
    dispatcher = BackgroundTasksDispatcher(
        background_tasks=background_tasks,
        task_handler=executor.execute_task,
    )
    dispatcher.dispatch(task_payload)
    return {
        "status": "dispatched",
        "forge": "github",
        "issue_id": task_payload.issue_id,
        "repo": task_payload.repo_full_name,
    }


@app.get("/health")
def health_check():
    """Service health probe."""
    return {"status": "ok", "service": "openjules", "forges": ["github", "radicle"]}


@app.post("/api/webhook")
async def github_webhook(
    request: Request,
    background_tasks: BackgroundTasks,
    x_github_event: Optional[str] = Header(None, alias="X-GitHub-Event"),
    x_hub_signature_256: Optional[str] = Header(None, alias="X-Hub-Signature-256"),
):
    """Processes incoming GitHub webhooks for issues and comments."""
    body_bytes = await request.body()
    webhook_secret = os.environ.get("GITHUB_WEBHOOK_SECRET", "")

    if not verify_github_signature(body_bytes, x_hub_signature_256, webhook_secret):
        raise HTTPException(status_code=401, detail="Invalid signature")

    require_legacy_execution()

    try:
        payload: Dict[str, Any] = json.loads(body_bytes)
    except Exception:
        raise HTTPException(status_code=400, detail="Malformed JSON")

    if x_github_event in ("pull_request_review_comment", "pull_request_review"):
        return _dispatch_review_event(payload, x_github_event, background_tasks)

    if x_github_event == "issue_comment":
        return _dispatch_issue_comment(payload, background_tasks)

    action = payload.get("action", "")
    repository = payload.get("repository", {})
    repo_full_name = repository.get("full_name", "")
    clone_url = repository.get("clone_url", "")
    default_branch = repository.get("default_branch", "main")
    installation = payload.get("installation", {})
    installation_id = installation.get("id")

    task_payload: Optional[TaskPayload] = None

    # Case 1: Issue labeled (e.g., openjules:run)
    if x_github_event == "issues" and action in ("labeled", "opened"):
        issue = payload.get("issue", {})
        labels = [l.get("name", "") for l in issue.get("labels", [])]
        label_triggered = "openjules:run" in labels or "openjules" in labels

        if label_triggered:
            task_payload = TaskPayload(
                forge="github",
                issue_id=issue.get("number"),
                issue_title=issue.get("title", ""),
                issue_body=issue.get("body", "") or "",
                repo_full_name=repo_full_name,
                repo_clone_url=clone_url,
                default_branch=default_branch,
                installation_id=installation_id,
                sender=payload.get("sender", {}).get("login", ""),
            )

    if task_payload:
        dispatcher = BackgroundTasksDispatcher(
            background_tasks=background_tasks,
            task_handler=executor.execute_task,
        )
        dispatcher.dispatch(task_payload)
        return {
            "status": "dispatched",
            "forge": "github",
            "issue_id": task_payload.issue_id,
            "repo": task_payload.repo_full_name,
        }

    return {"status": "ignored", "reason": "No relevant OpenJules trigger in webhook payload"}


class RadicleWebhookPayload(BaseModel):
    """Payload model for Radicle event webhooks / proxy."""

    event_type: str = Field(default="issue.created", description="Type of Radicle event")
    rid: str = Field(description="Radicle Repository ID (e.g. rad:z4V1sJY...)")
    issue_id: str | int = Field(description="Radicle issue ID or hash")
    issue_title: str
    issue_body: Optional[str] = ""
    labels: list[str] = Field(default_factory=list)
    default_branch: str = "master"


@app.post("/api/radicle/webhook")
async def radicle_webhook(
    event: RadicleWebhookPayload,
    background_tasks: BackgroundTasks,
):
    """Webhook adapter for self-hosted or local Radicle node events."""
    require_legacy_execution()
    label_triggered = any("openjules" in str(l).lower() for l in event.labels) or event.event_type == "openjules:run"

    clean_rid = event.rid if event.rid.startswith("rad:") else f"rad:{event.rid}"

    if label_triggered or event.event_type in ("openjules:run", "issue.labeled"):
        task_payload = TaskPayload(
            forge="radicle",
            issue_id=event.issue_id,
            issue_title=event.issue_title,
            issue_body=event.issue_body or "",
            repo_full_name=clean_rid,
            repo_clone_url=clean_rid,
            default_branch=event.default_branch,
        )
        dispatcher = BackgroundTasksDispatcher(
            background_tasks=background_tasks,
            task_handler=executor.execute_task,
        )
        dispatcher.dispatch(task_payload)
        return {
            "status": "dispatched",
            "forge": "radicle",
            "rid": clean_rid,
            "issue_id": event.issue_id,
        }

    return {"status": "ignored", "reason": "No openjules label in Radicle event"}
