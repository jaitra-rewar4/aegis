# 0005 — The MCP gateway: a transport adapter, not a second engine

- Status: Accepted
- Date: 2026-06-16
- Deciders: gateway-engineer (builds the adapter and the four governed tools); architect (confirms both invariants survive the new transport); red-team and reviewer pass after.
- Supersedes: — (composes with ADR 0002's write-ahead audit ordering, ADR 0003's pure `decide`, and ADR 0004's trajectory). It adds a transport; it changes no decision.

## Problem

Aegis governs tool calls, but until now the only thing wired to the gate was Aegis's own demo loop. Other agents — Kiln, Claude Desktop, anything that speaks the Model Context Protocol — cannot ask the gate to judge an action before they take it. The Model Context Protocol is the obvious seam: an MCP client already calls out to a server for `tools/list` and `tools/call`. If a server sits on the other end of that call and runs every proposed action through `decide()` before executing it, then any MCP client gets Aegis governance for free, at the exact boundary where the action becomes concrete.

The risk in building that is subtle and worth naming: a new transport is a new place for non-determinism and for "gate on text" to creep back in. A naive MCP server might let the model's stated intent, the connection, or the SDK's request ordering leak into the verdict. This ADR pins a design where the transport is *only* transport — it carries (tool, params) to the gate and the result back, and nothing about the wire ever reaches `decide()`.

## Decision

Add a new top-level package `mcp_gateway/` that exposes a FastMCP (official Python MCP SDK) server with four tools matching the default pack — `lookup_customer`, `send_email`, `execute_sql`, `calculator` — each of which is governed by the existing engine before its body runs.

### a) It is an adapter, not a new decision-maker

`decide(pack, tool, params, trajectory)` from `policy.engine` stays the sole decision-maker, imported and called unchanged. The gateway adds zero policy logic. It does three things, all of them plumbing:

1. supplies concrete **mock tool bodies** (a fake customer record, fake rows, a sent confirmation, a real arithmetic computation) so there is something to govern;
2. threads a **per-session trajectory** in the exact shape `decide()` reads, so the read-then-send exfil rule (ADR 0004) fires across calls;
3. records **every evaluated call** through the existing `core.audit.append_record`, in the existing JSONL format — no new audit format is invented.

The transport-independent core lives in `mcp_gateway/gateway.py` and carries **no MCP dependency**, which is the structural proof that the SDK is not in the decision path: you can import and exercise the whole governed path without the SDK installed. `mcp_gateway/server.py` is the only file that imports `mcp`, and it does nothing but map four FastMCP tool handlers onto `Gateway.call`.

### b) Both invariants, preserved not reinterpreted

- **Invariant 1 (enforcement at the tool-call boundary, on concrete actions + parameters).** Each handler calls `Gateway.call(tool, params)`, which calls `decide` on the concrete tool name and its concrete parameters *before* the body runs. The body executes only on `ALLOW`; on any non-`ALLOW` verdict it does not run at all and a structured refusal naming the rule/marker is returned. The model's natural-language intent never enters the call — only the tool and its params do. The param names the handlers pass (`sql` for `execute_sql`, `to` for `send_email`) are exactly the names the pack's rules inspect; a mismatch would make `decide` blind to the value and silently default-deny, so they are matched deliberately and pinned by tests.

  The param contract is **enforced, not merely conventional** (added after red-team review). Each tool declares the exact set of param keys it accepts, and a call to a known tool carrying any key outside that set is refused as a malformed call (`aegis.malformed_call`) before `decide` runs. This closes a whole class structurally: a destructive value smuggled under an unexpected key — `{"query": "DROP TABLE ..."}` instead of `{"sql": ...}` — can no longer be invisible to a rule that inspects `sql` while reaching a body that might read `query`. The typed FastMCP handlers pass exactly the declared keys, so legitimate transport traffic never trips this; only a direct or future-proxy caller smuggling a key is refused.

### b2) Fail-closed on an unwritable audit trail

The audit write is wrapped: if `append_record` raises (disk full, bad path, permissions), the call fails closed — the body does not run, nothing enters the trajectory, a warning is surfaced, and a structured refusal with marker `aegis.audit_unavailable` is returned (the same marker and contract `core.loop` uses, ADR 0002). An audit outage can only turn `ALLOW` into a refusal, never a `DENY` into an `ALLOW` — monotonic — and the session self-heals because the next call re-attempts a fresh append. Hostile inputs to the adapter (a non-dict `params`, a deeply nested or astronomically large `calculator` expression) are likewise refused deterministically rather than allowed to crash the adapter, because a crash in the gate is a denial-of-decision.

- **Invariant 2 (deterministic gate).** The verdict is `decide()`'s and only `decide()`'s — pure in (pack, tool, params, trajectory). Nothing about the MCP transport (the connection, request ordering, client identity, timing) is read by the gate. Same inputs, same verdict, proven by a determinism test that runs the same call through two fresh sessions.

### c) The trajectory is per-session, ALLOW-only, and never sees the current call

A `Gateway` instance holds an ordered list of the **allowed** concrete calls this session, each `{tool, params, decision: "ALLOW"}` — the shape `_after_holds` reads. Only allowed calls are appended: a denied call never executed, so it must not taint a later one, mirroring the engine's ALLOW-only `after` matching (ADR 0004 §e). The append happens *after* `decide` returns, so the current proposal is never part of its own history. stdio transport is one process per client, so a single per-process `Gateway` is exactly one session; tests construct a fresh `Gateway` each, which is why this is instance state and not a module global.

### d) stdout is the protocol; diagnostics go to stderr

Under stdio transport the JSON-RPC stream owns stdout. A single stray write there corrupts the framing and the client cannot connect. So logging is configured to a stderr stream and the tool bodies return data rather than printing it. `python -m mcp_gateway` is the launch entry point and runs FastMCP's default stdio transport.

## Honest scope

- The tool bodies are **mock**. They touch no real database, mailbox, or network. This server is a governed surface for exercising the gate from a real MCP client, not a production integration. The point it proves is the *gate's* behavior on real MCP traffic, not real side effects.
- The `calculator` body does a genuine computation, but via a small AST walker restricted to numeric literals and arithmetic operators (no `eval`, no names, no calls), with a capped exponent. It is real arithmetic, not a sandbox; it is deliberately incapable of running code.
- This is a **fixed-tool** adapter: it governs four named tools whose param keys it knows and enforces. It is **not** yet a transparent proxy. A Phase 2 generalization would forward `tools/list` and `tools/call` to an arbitrary upstream MCP server and govern whatever passes through, with no hardcoded tool list. That is explicitly out of scope here, and the param-key enforcement above is exactly why: a proxy cannot lean on a hardcoded per-tool key set, so it needs a general mapping of which params carry the governed values (so `decide` sees them under the names the pack expects) plus a policy story for unknown upstream tools — both deserve their own ADR. The carryover gaps from ADR 0003 (the SQL keyword-scan classes 7a/7c/7d) are unchanged — this transport neither widens nor closes them.

## Consequences

- Any MCP client can now consult Aegis at the action boundary by adding one stdio server. The headline behaviors hold over the real transport: a `DROP TABLE` is refused, a `SELECT` runs, and a partner send flips from `ALLOW` to `DENY` once a customer record has been read in the same session.
- Every governed call leaves one audit record in the existing format, so the dashboard and any log consumer see MCP-driven actions identically to loop-driven ones.
- The decision path gained no new dependency: `mcp_gateway/gateway.py` imports only `core` and `policy`. The SDK is confined to the transport file, the same way `yaml` is confined to the loader (ADR 0003 §a).
