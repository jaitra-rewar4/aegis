# Aegis MCP gateway

A Model Context Protocol server that exposes four Aegis-governed tools. Any MCP client
(Kiln, Claude Desktop, Claude Code) can connect to it and get the real gate on every call:
each proposed action is judged by the same deterministic `decide()` the rest of Aegis uses,
before the tool body runs, and every call is written to the append-only audit trail.

This is a transport adapter, not a new policy engine. The decision logic is untouched. See
`docs/adr/0005-mcp-gateway.md`.

## The tools

All four match the default policy pack (`policy/packs/default.yaml`):

| Tool | Param the gate inspects | Behavior |
| --- | --- | --- |
| `lookup_customer` | (none; always allowed) | Returns a mock customer record. In the default pack this read taints later sends to outside domains. |
| `send_email` | `to` | Allowed to internal/partner domains. Denied to an outside domain once a customer record has been looked up this session. |
| `execute_sql` | `sql` | Denied for destructive statements (DROP/DELETE/TRUNCATE/ALTER). Allowed otherwise. Returns mock rows. |
| `calculator` | (none; always allowed) | Evaluates an arithmetic expression with a safe AST walker and returns the result. |

The tool bodies are mock: no real database, mailbox, or network is touched. The point is
to exercise the gate from a real MCP client, not to produce real side effects.

## Run it

```
pip install -r mcp_gateway/requirements.txt
python -m mcp_gateway
```

If pip fails on certificates:

```
pip install mcp --trusted-host pypi.org --trusted-host files.pythonhosted.org
```

The server speaks stdio. Standard output is reserved for the protocol; all logging goes to
standard error, so the client can connect cleanly.

## Connect it

Register the stdio command with any MCP client. For Claude Code:

```
claude mcp add aegis-gateway -- python -m mcp_gateway
```

(run from the repo root, or give an absolute path to the package). For a GUI client such as
Kiln or Claude Desktop, set the command to your Python interpreter and the argument to
`-m mcp_gateway`, with the working directory set to the repo root.

## Tests

```
py -m pytest tests/test_mcp_gateway.py -q
```

The suite exercises the governed path directly through `Gateway` (no SDK needed) and, where
the MCP SDK is installed, through the registered FastMCP handlers.
