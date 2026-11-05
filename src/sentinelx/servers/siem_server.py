"""SIEM MCP server: lets an AI search Arclight Logistics' login logs.

Run with the MCP Inspector (from the project folder):
  uv run mcp dev src/sentinelx/servers/siem_server.py
"""

import json
from pathlib import Path

from mcp.server import MCPServer

# Find the log file relative to THIS file, so it works from any folder.
# This file is at <project>/src/sentinelx/servers/siem_server.py,
# so parents[3] is the project folder.
PROJECT_ROOT = Path(__file__).resolve().parents[3]
LOG_FILE = PROJECT_ROOT / "data" / "siem" / "auth_events.jsonl"

mcp = MCPServer("sentinelx-siem")


def load_events() -> list[dict]:
    """Read every event from the log file (one JSON object per line)."""
    with open(LOG_FILE) as f:
        return [json.loads(line) for line in f if line.strip()]


@mcp.tool()
def count_events() -> dict:
    """Count all login events in the SIEM, split by outcome (success/failure)."""
    events = load_events()
    failures = sum(1 for e in events if e["outcome"] == "failure")
    return {
        "total": len(events),
        "success": len(events) - failures,
        "failure": failures,
    }


@mcp.tool()
def get_events_by_ip(ip: str) -> dict:
    """Return all login events whose source IP address equals `ip`.

    Use this to see everything a single IP address did: which users it
    tried, when, and whether the logins succeeded.
    """
    matches = [e for e in load_events() if e["src_ip"] == ip]
    return {"ip": ip, "count": len(matches), "events": matches}


if __name__ == "__main__":
    mcp.run()  # no argument = stdio transport