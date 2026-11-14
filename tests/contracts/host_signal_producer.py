"""Test-only Polyphony subprocess. Never imported by the OpenJules runtime.

The explicit temporary ledger is producer-owned fixture state. Direct SQL below
creates otherwise impossible historical rows for native refusal tests only.
"""
from __future__ import annotations

import asyncio
import hashlib
import importlib.metadata
import json
import os
from pathlib import Path
import sqlite3
import sys


def main():
    checkout = Path(sys.argv[1]).resolve(strict=True)
    work = Path(sys.argv[2]).resolve(strict=True)
    request = json.loads(sys.stdin.buffer.read(16385))
    if not isinstance(request, dict) or len(json.dumps(request).encode()) > 16384:
        raise ValueError("fixture request exceeds bound")
    sys.path.insert(0, str(checkout))
    assert importlib.metadata.version("mcp") == "1.30.0"
    from src.liminal_bridge import server
    from src.core.collaboration.models import TaskObjective, TaskStatus, HostSignalType
    from mcp.types import CallToolResult

    assert Path(server.collab_ledger.db_path).resolve() == work / "producer.sqlite3"
    assert server.mesh is None and server.architect.client is None
    ledger = server.collab_ledger
    operation = request["operation"]
    if operation == "setup":
        ledger.create_task(TaskObjective(task_id="ordinary", title="fixture", description="",
                                        baseline_sha="fixture-base", acceptance_criteria=[], status=TaskStatus.INTEGRATING))
        assert ledger.acquire_conductor_lease("fixture-conductor", force_for_solo_deadlock=True)[0]
        identities = {}
        for label in ("ordinary", "managed-history", "malformed-history"):
            ok, value, _ = ledger.emit_host_signal("fixture-conductor", HostSignalType.SCALE_UP, 1,
                                                   [label], "native tool fixture")
            assert ok
            identities[label] = value.signal_id
        # Deliberate fixture construction is not a consumer compatibility path.
        with sqlite3.connect(ledger.db_path) as connection:
            connection.execute("UPDATE host_signal_outbox SET target_task_ids=? WHERE signal_id=?",
                               ('["task_v2_historical"]', identities["managed-history"]))
            connection.execute("UPDATE host_signal_outbox SET target_task_ids=? WHERE signal_id=?",
                               ('not-json', identities["malformed-history"]))
        response = {"signal_ids": identities, "mcp_version": importlib.metadata.version("mcp"),
                    "python": sys.version, "source": str(Path(server.__file__).relative_to(checkout))}
    elif operation == "call":
        assert request["name"] in {"openjules_poll_outbox", "openjules_ack_signal"}
        converted = asyncio.run(server.mcp.call_tool(request["name"], request["arguments"]))
        # Use actual registered FastMCP conversion and its SDK envelope. No fake
        # success/data serializer substitutes for the producer's tool function.
        if isinstance(converted, tuple):
            content, structured = converted
            response = CallToolResult(content=content, structuredContent=structured)
        else:
            assert isinstance(converted, list)
            response = CallToolResult(content=converted)
        response = response.model_dump(mode="json", by_alias=True, exclude_none=True)
    elif operation == "inspect":
        with sqlite3.connect(ledger.db_path) as connection:
            rows = connection.execute("SELECT * FROM host_signal_outbox ORDER BY signal_id").fetchall()
        response = {"rows_sha256": hashlib.sha256(json.dumps(rows, separators=(",", ":")).encode()).hexdigest(),
                    "statuses": {row[0]: row[7] for row in rows},
                    "historical_rows": {row[0]: hashlib.sha256(json.dumps(row).encode()).hexdigest()
                                        for row in rows if row[4] in ('["task_v2_historical"]', 'not-json')}}
    else:
        raise ValueError("unsupported fixture operation")
    encoded = json.dumps(response, separators=(",", ":")).encode()
    if len(encoded) > 262144:
        raise ValueError("fixture response exceeds bound")
    sys.stdout.buffer.write(encoded + b"\n")


if __name__ == "__main__":
    main()
