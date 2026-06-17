"""
mcp_gateway.server — the MCP transport adapter around the Aegis gateway.

FastMCP exposes four governed tools (lookup_customer, send_email, execute_sql,
calculator). Each handler is a thin wrapper that delegates to a single Gateway instance,
so every call runs the same governed path: decide() at the boundary, an audit record,
then the body only on ALLOW. The MCP layer is pure transport — it adds no decision logic
and never inspects the verdict. See docs/adr/0005-mcp-gateway.md.

STDOUT IS RESERVED FOR THE PROTOCOL. Under stdio transport the JSON-RPC stream owns
stdout; a single stray print there corrupts the framing and the client cannot connect.
All diagnostics therefore go to stderr (logging is configured to a stderr stream below,
and the tool bodies return data rather than printing it).
"""

from __future__ import annotations

import logging
import sys
from typing import Any

from mcp.server.fastmcp import FastMCP

from mcp_gateway.gateway import Gateway

# Logging to STDERR only — never stdout (see module docstring).
logging.basicConfig(
    stream=sys.stderr,
    level=logging.INFO,
    format="aegis-mcp %(levelname)s %(message)s",
)
_log = logging.getLogger("aegis.mcp_gateway")

mcp = FastMCP("aegis-gateway")

# One session per process. stdio transport is one client per process, so a single
# module-level Gateway is exactly "the per-session trajectory" the spec asks for.
_gateway = Gateway()


@mcp.tool()
def lookup_customer(customer_id: str = "") -> dict[str, Any]:
    """Look up a customer record by id. Governed by Aegis before it runs.

    Read-only on its own, but in the default pack an allowed lookup taints later sends to
    outside domains (the read-then-send exfil rule), so calling this changes how a
    subsequent send_email is judged.
    """
    return _gateway.call("lookup_customer", {"customer_id": customer_id})


@mcp.tool()
def send_email(to: str, subject: str = "", body: str = "") -> dict[str, Any]:
    """Send an email to ``to``. Aegis governs it on the recipient domain and trajectory.

    Allowed to internal/partner domains on its own; denied to an outside domain once a
    customer record has been looked up earlier this session.
    """
    return _gateway.call("send_email", {"to": to, "subject": subject, "body": body})


@mcp.tool()
def execute_sql(sql: str) -> dict[str, Any]:
    """Run a SQL statement. Aegis denies destructive statements (DROP/DELETE/TRUNCATE/ALTER)
    and allows the rest."""
    return _gateway.call("execute_sql", {"sql": sql})


@mcp.tool()
def calculator(expression: str) -> dict[str, Any]:
    """Evaluate an arithmetic expression. Always allowed — pure, no side effects."""
    return _gateway.call("calculator", {"expression": expression})


def main() -> None:
    """Run the server over stdio. Launchable as ``python -m mcp_gateway``.

    FastMCP's default transport is stdio, which is what MCP clients (Kiln, Claude Desktop)
    spawn and speak over the process's stdin/stdout. Diagnostics go to stderr only.
    """
    _log.info("starting Aegis MCP gateway over stdio (default policy pack)")
    mcp.run()


if __name__ == "__main__":
    main()
