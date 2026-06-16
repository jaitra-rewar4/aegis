"""
Aegis MCP server.

Exposes the real Aegis policy engine over the Model Context Protocol, so any MCP client
(Claude Code, Claude Desktop, other agents) can ask the gate to judge a proposed tool call
before it runs. The verdict is the same deterministic decide() the gateway uses: no model in
the decision path.

The folder is named `mcp_server` (not `mcp`) on purpose, so it does not shadow the installed
`mcp` library.

Run:
    pip install -r mcp_server/requirements.txt
    python mcp_server/server.py
Register with Claude Code (stdio):
    claude mcp add aegis -- python /absolute/path/to/aegis/mcp_server/server.py
"""

from __future__ import annotations

import sys
from pathlib import Path
from typing import Any

# Make the repo root importable so `policy` resolves no matter where this is launched from.
sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from policy.engine import decide  # noqa: E402
from policy.loader import DEFAULT_PACK_PATH, load  # noqa: E402

from mcp.server.fastmcp import FastMCP  # noqa: E402

_PACK = load(DEFAULT_PACK_PATH)
mcp = FastMCP("aegis")


@mcp.tool()
def aegis_check(
    tool: str,
    params: dict[str, Any] | None = None,
    trajectory: list[dict[str, str]] | None = None,
) -> dict[str, str]:
    """Judge a proposed tool call against the Aegis policy pack.

    Call this BEFORE executing a tool, so an agent can gate its own actions. The result is
    deterministic: the same inputs always return the same verdict.

    Args:
        tool: the tool the agent wants to call, for example "send_email".
        params: the concrete parameters of that call, for example {"to": "x@partner.com"}.
        trajectory: prior actions this run, each {"tool": ..., "decision": "ALLOW"|"DENY"}.
            Only an ALLOWed prior action can taint a later one, because a denied action never ran.

    Returns:
        {"decision": "ALLOW" | "DENY", "rule": "<rule id that fired>"}.
    """
    result = decide(_PACK, tool, params or {}, trajectory or [])
    return {"decision": result.decision.value, "rule": result.rule_id}


@mcp.resource("aegis://pack")
def policy_pack() -> str:
    """The active policy pack: its posture and every rule, in order. First match wins."""
    lines = [
        f"version: {_PACK.version}",
        f"default: {_PACK.default}",
        "",
        "rules (first match wins):",
    ]
    for rule in _PACK.rules:
        after = f" after={rule.after}" if rule.after else ""
        when = f" when={dict(rule.when)}" if rule.when else ""
        lines.append(f"  {rule.id}  [{rule.effect}]  tool={rule.tool}{after}{when}")
    return "\n".join(lines)


if __name__ == "__main__":
    mcp.run()
