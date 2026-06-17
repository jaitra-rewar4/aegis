"""
Aegis MCP gateway — a transport adapter exposing Aegis-governed tools over MCP.

Importing the package pulls in only the transport-independent core (``Gateway``), which
has no MCP dependency, so tests and other callers can use it without the SDK installed.
The FastMCP server lives in ``mcp_gateway.server`` and is reached via ``python -m
mcp_gateway``.
"""

from mcp_gateway.gateway import Gateway, TOOLS

__all__ = ["Gateway", "TOOLS"]
