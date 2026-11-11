"""OpenJules CLI — Run autonomous agent tasks and manage swarms from the terminal."""

import argparse
import os
import sys
from pathlib import Path

# Ensure repo root is on sys.path
sys.path.insert(0, str(Path(__file__).parent.parent))

from src.worker.execution_context import LegacyExecutionRefused, require_legacy_execution


def run_cli_task(prompt: str, repo: str, branch: str = "main", test_cmd: str = None):
    """Executes an agent task directly in the specified repository."""
    require_legacy_execution()
    from src.sandbox.config import OpenJulesConfig
    from src.worker.dispatcher import TaskPayload
    from src.worker.executor import TaskExecutor

    print(f"🚀 OpenJules CLI: Launching task on '{repo}'...")
    print(f"Prompt: {prompt}\n")

    cfg = OpenJulesConfig()
    if test_cmd:
        cfg.test_command = test_cmd

    # Build task payload
    is_radicle = repo.startswith("rad:")
    forge = "radicle" if is_radicle else "github"
    clone_url = repo if is_radicle else (repo if repo.startswith("http") else f"https://github.com/{repo}.git")

    payload = TaskPayload(
        forge=forge,
        issue_id=1,
        issue_title=prompt[:80],
        issue_body=prompt,
        repo_full_name=repo,
        repo_clone_url=clone_url,
        default_branch=branch,
    )

    executor = TaskExecutor()
    success = executor.execute_task(payload)
    if success:
        print("\n🎉 Task completed and verified successfully!")
        return 0
    else:
        print("\n❌ Task execution or verification failed.")
        return 1


def serve_dashboard(host: str = "0.0.0.0", port: int = 8000):
    """Starts the OpenJules API server and 3-pane web interface."""
    require_legacy_execution()
    import uvicorn

    print(f"🌐 Starting OpenJules Control Plane & Dashboard on http://{host}:{port}")
    uvicorn.run("src.api.webhook:app", host=host, port=port, reload=False)


def inspect_polyphony(repo: str):
    """Inspects the Keystone Polyphony swarm status for a repository."""
    from src.polyphony.client import PolyphonyClient, derive_repo_swarm_key

    swarm_key = derive_repo_swarm_key(repo)
    client = PolyphonyClient(repo, swarm_key=swarm_key)
    print(f"📡 Keystone Polyphony Swarm for '{repo}':")
    print(f"  - Swarm Key (SHA-256): {swarm_key}")
    print(f"  - Swarm Topic: {client.topic}")
    print(f"  - Node ID: {client.node_id}")
    print(f"  - Status: {client.status}")
    print(f"  - Active Batons: {list(client.batons.keys())}")


def handle_swarm_cli(args):
    """Handles 'openjules swarm' subcommands."""
    require_legacy_execution()
    from src.polyphony.models import PolyphonyCohortConfig, HostTelemetrySignal, SignalType
    from src.polyphony.registry import cohort_registry

    action = getattr(args, "swarm_action", None)
    if action == "start":
        swarm_id = args.swarm_id or f"swarm-{os.urandom(4).hex()}"
        cfg = PolyphonyCohortConfig(
            swarm_id=swarm_id,
            repo_url=args.repo,
            base_worker_count=args.workers,
            max_burst_workers=args.max_burst,
            max_host_budget=args.budget,
        )
        ctrl = cohort_registry.register_cohort(cfg, bootstrap=True)
        active = ctrl.provisioner.list_active_workers(swarm_id=swarm_id)
        print(f"🐝 Started Polyphony Cohort '{swarm_id}'")
        print(f"  - Target Repo: {args.repo}")
        print(f"  - Base Workers: {len(active)} / {args.workers}")
        print(f"  - Max Burst Cap: {args.max_burst}")
        print(f"  - Budget Ceiling: ${args.budget:.2f}")

    elif action == "status":
        ctrl = cohort_registry.get_controller(args.swarm_id)
        if not ctrl:
            print(f"❌ Cohort '{args.swarm_id}' not found.")
            return 1
        active = ctrl.provisioner.list_active_workers(swarm_id=args.swarm_id)
        base = [w for w in active if not w.is_burst]
        burst = [w for w in active if w.is_burst]
        print(f"🐝 Polyphony Cohort Status: {args.swarm_id}")
        print(f"  - Active Workers: {len(active)} ({len(base)} base, {len(burst)} burst)")
        print(f"  - Metered Cost: ${ctrl.internal_metered_cost:.2f} / ${ctrl.config.max_host_budget:.2f}")
        for w in active:
            role_badge = f"[{w.role.upper()}]"
            burst_badge = "(burst)" if w.is_burst else "(base)"
            print(f"    • {w.actor_id} {role_badge} {burst_badge} cid={w.container_id[:12]}")

    elif action == "drain":
        ctrl = cohort_registry.get_controller(args.swarm_id)
        if not ctrl:
            print(f"❌ Cohort '{args.swarm_id}' not found.")
            return 1
        sig = HostTelemetrySignal(
            signal_id=f"sig-cli-drain-{os.urandom(4).hex()}",
            emitted_by_actor="cli",
            signal_type=SignalType.IDLE_DRAIN,
            requested_worker_delta=args.delta,
            rationale="CLI triggered idle drain",
        )
        if hasattr(ctrl.outbox_bridge, "emit_signal"):
            ctrl.outbox_bridge.emit_signal(sig)
        elif hasattr(ctrl.outbox_bridge, "add_signal"):
            ctrl.outbox_bridge.add_signal(sig)
        results = ctrl.reconcile_signals()
        print(f"🧹 Drained cohort '{args.swarm_id}': {results}")
    else:
        print("Usage: openjules swarm [start|status|drain]")


def main():
    parser = argparse.ArgumentParser(
        prog="openjules",
        description="OpenJules — Autonomous Sandboxed Coding Agent CLI",
    )
    subparsers = parser.add_subparsers(dest="command", help="Available subcommands")

    # Command: run
    run_parser = subparsers.add_parser("run", help="Run an autonomous coding task directly")
    run_parser.add_argument("prompt", type=str, help="Instruction or bug report prompt")
    run_parser.add_argument(
        "--repo",
        type=str,
        default=os.environ.get("OPENJULES_REPO", "owner/repo"),
        help="Repository identifier (owner/repo or rad:z4V1sJY...)",
    )
    run_parser.add_argument("--branch", type=str, default="main", help="Target branch name")
    run_parser.add_argument("--test-cmd", type=str, default=None, help="Custom test command override")

    # Command: serve
    serve_parser = subparsers.add_parser("serve", help="Start the FastAPI control plane and web dashboard")
    serve_parser.add_argument("--host", type=str, default="0.0.0.0", help="Host address")
    serve_parser.add_argument("--port", type=int, default=8000, help="Port number")

    # Command: polyphony
    poly_parser = subparsers.add_parser("polyphony", help="Inspect repository Polyphony swarm key and state")
    poly_parser.add_argument("repo", type=str, help="Repository identifier")

    # Command: swarm
    swarm_parser = subparsers.add_parser("swarm", help="Manage Polyphony Swarm Resource Cohorts")
    swarm_sub = swarm_parser.add_subparsers(dest="swarm_action", help="Swarm action (start, status, drain)")

    swarm_start = swarm_sub.add_parser("start", help="Start a new managed swarm cohort")
    swarm_start.add_argument("--repo", type=str, required=True, help="Target repository URL or owner/repo")
    swarm_start.add_argument("--swarm-id", type=str, default=None, help="Custom swarm ID")
    swarm_start.add_argument("--workers", type=int, default=1, help="Base worker count")
    swarm_start.add_argument("--max-burst", type=int, default=18, help="Max burst workers ceiling")
    swarm_start.add_argument("--budget", type=float, default=100.0, help="Max host budget ceiling")

    swarm_status = swarm_sub.add_parser("status", help="Inspect status of a managed swarm cohort")
    swarm_status.add_argument("swarm_id", type=str, help="Cohort swarm ID")

    swarm_drain = swarm_sub.add_parser("drain", help="Trigger IDLE_DRAIN or stop cohort")
    swarm_drain.add_argument("swarm_id", type=str, help="Cohort swarm ID")
    swarm_drain.add_argument("--delta", type=int, default=0, help="Number of workers to drain (0 = all idle burst)")

    # Command: mcp
    mcp_parser = subparsers.add_parser("mcp", help="Run OpenJules Model Context Protocol (MCP) server")

    args = parser.parse_args()
    if args.command in {"run", "serve", "mcp", "swarm"}:
        try:
            require_legacy_execution()
        except LegacyExecutionRefused as exc:
            parser.error(exc.reason)

    if args.command == "run":
        sys.exit(run_cli_task(args.prompt, args.repo, args.branch, args.test_cmd))
    elif args.command == "serve":
        serve_dashboard(args.host, args.port)
    elif args.command == "polyphony":
        inspect_polyphony(args.repo)
    elif args.command == "swarm":
        handle_swarm_cli(args)
    elif args.command == "mcp":
        from src.mcp.server import OpenJulesMCPServer

        mcp = OpenJulesMCPServer()
        print(f"OpenJules MCP Server active with {len(mcp.get_tool_list())} tools.")
    else:
        parser.print_help()


if __name__ == "__main__":
    main()
