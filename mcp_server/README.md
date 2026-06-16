# Aegis MCP server

A custom Model Context Protocol server that exposes the Aegis policy engine, so any MCP client (Claude Code, Claude Desktop, other agents) can ask the gate to judge a proposed tool call before running it. The verdict is the same deterministic `decide()` the gateway uses, with no model in the decision path.

The folder is named `mcp_server` rather than `mcp` so it does not shadow the installed `mcp` library.

## Run

```
pip install -r mcp_server/requirements.txt
python mcp_server/server.py
```

## Register with Claude Code (stdio)

```
claude mcp add aegis -- python /absolute/path/to/aegis/mcp_server/server.py
```

In a new session an agent can then call the tool before it acts:

```
aegis_check(
  tool="send_email",
  params={"to": "ops@partner.example.com"},
  trajectory=[{"tool": "lookup_customer", "decision": "ALLOW"}],
)
-> {"decision": "DENY", "rule": "email.deny_exfil_after_read"}
```

The resource `aegis://pack` returns the active pack and its rules in order.
