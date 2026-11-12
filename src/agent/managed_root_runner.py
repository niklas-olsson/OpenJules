"""Trusted-image root runner with bounded child controls.

Run this fixed image path with ``python3 -I -S``. Sibling modules are loaded from
the same image directory, never from the task checkout or PYTHONPATH. Children
continue to use managed_runner.py and its completion-only interface.
"""

from __future__ import annotations

import argparse
import importlib.util
import json
from pathlib import Path
import signal
import sys


def _load_sibling(name):
    if name not in {"child_tools", "managed_runner", "public_tools"}:
        raise ValueError("unsupported trusted image module")
    path = Path(__file__).resolve().with_name(name + ".py")
    specification = importlib.util.spec_from_file_location(
        "_openjules_root_" + name, path
    )
    if specification is None or specification.loader is None:
        raise ValueError("trusted image module is unavailable")
    module = importlib.util.module_from_spec(specification)
    previous = sys.modules.get(specification.name)
    sys.modules[specification.name] = module
    try:
        specification.loader.exec_module(module)
    except BaseException:
        if previous is None:
            sys.modules.pop(specification.name, None)
        else:
            sys.modules[specification.name] = previous
        raise
    return module


if __package__:
    from . import child_tools as _child
else:
    _child = _load_sibling("child_tools")
ControlClient = _child.ControlClient
ControlError = _child.ControlError
RootTools = _child.RootTools
_public = None


def _public_extension():
    global _public
    if _public is None:
        if __package__:
            from . import public_tools
            _public = public_tools
        else:
            _public = _load_sibling("public_tools")
    return _public


def run_root(
    model_client,
    local_tools,
    control,
    requirements,
    *,
    max_turns=25,
    verify_argv=None,
    legacy=None,
    public_client=None,
):
    """Compose the existing agent loop; explicit dependencies support tests."""
    legacy = legacy if legacy is not None else _load_sibling("managed_runner")
    tools = RootTools(local_tools, control)
    try:
        active_tools = (
            _public_extension().PublicTools(tools, public_client)
            if public_client is not None else tools
        )
        return legacy.run_agent(
            model_client,
            active_tools,
            requirements,
            max_turns=max_turns,
            verify_argv=verify_argv,
        )
    finally:
        active_error = sys.exc_info()[0] is not None
        try:
            tools.close()
        except (ControlError, ValueError, OSError):
            # Preserve the original agent failure if both boundaries failed.
            # A close failure after an otherwise successful run is fatal.
            if not active_error:
                raise


def _terminate(_signum, _frame):
    raise KeyboardInterrupt


def main(argv=None):
    parser = argparse.ArgumentParser(description=__doc__, allow_abbrev=False)
    parser.add_argument("--socket", required=True)
    parser.add_argument("--control-socket", required=True)
    parser.add_argument("--public-socket")
    parser.add_argument("--max-turns", type=int, default=25)
    parser.add_argument("--control-timeout-seconds", type=float, default=30)
    parser.add_argument("--verify-json")
    args = parser.parse_args(argv)
    legacy = _load_sibling("managed_runner")
    previous = signal.signal(signal.SIGTERM, _terminate)
    control = None
    entered_runner = False
    boundary_errors = (legacy.BrokerError, ControlError, ValueError, OSError)
    try:
        public_client = None
        if args.public_socket:
            public = _public_extension()
            boundary_errors += (public.PublicError,)
            public_client = public.PublicClient(args.public_socket, role="root")
        control = ControlClient(
            args.control_socket, timeout_seconds=args.control_timeout_seconds
        )
        requirements = sys.stdin.buffer.read(131073).decode("utf-8")
        verification = json.loads(args.verify_json) if args.verify_json else None
        model_client = legacy.BrokerClient(args.socket)
        local_tools = legacy.LocalTools(Path.cwd())
        entered_runner = True
        return run_root(
            model_client,
            local_tools,
            control,
            requirements,
            max_turns=args.max_turns,
            verify_argv=verification,
            legacy=legacy,
            public_client=public_client,
        )
    except KeyboardInterrupt:
        print(json.dumps({"event": "root_agent_interrupted"}), flush=True)
        return 130
    except boundary_errors:
        print(
            json.dumps(
                {
                    "event": "root_agent_failed",
                    "reason": "Model or child control boundary unavailable; preserve captured work",
                }
            ),
            flush=True,
        )
        return 4
    finally:
        try:
            if control is not None and not entered_runner:
                try:
                    control.request("close", reason="root runner setup failed")
                except (ControlError, ValueError, OSError):
                    pass  # Setup already failed; host recovery retains authority.
        finally:
            signal.signal(signal.SIGTERM, previous)


if __name__ == "__main__":
    raise SystemExit(main())
