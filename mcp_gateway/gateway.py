"""
mcp_gateway.gateway — the governed-execution core, independent of any transport.

This is the engine BEHIND the MCP adapter, deliberately split out so it carries no MCP
dependency and can be unit-tested without a transport. It is NOT a second policy engine:
every decision is the existing pure ``decide()`` from ``policy.engine``. This module only

  1. supplies concrete mock tool bodies (a demo surface to exercise the gate),
  2. threads a per-session trajectory in the exact shape ``decide()`` reads, and
  3. records every evaluated call through the existing audit writer.

Both LAW invariants are preserved, not reinterpreted:
  - Enforcement stays at the tool-call boundary, on the concrete (tool, params) — the body
    runs only after ``decide()`` returns ALLOW, never before.
  - ``decide()`` stays the sole, deterministic decision-maker. No model sits in this path;
    this adapter never second-guesses or post-processes the verdict.

See docs/adr/0005-mcp-gateway.md.
"""

from __future__ import annotations

import ast
import operator
import sys
import warnings
from pathlib import Path
from typing import Any, Callable

# Make the repo root importable so core/ and policy/ resolve no matter where this is
# launched from (python -m mcp_gateway, a test runner, or an MCP client spawning it).
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from core.audit import append_record  # noqa: E402
from core.decision import Decision  # noqa: E402
from policy.engine import decide  # noqa: E402
from policy.loader import DEFAULT_PACK_PATH, load  # noqa: E402
from policy.schema import Pack  # noqa: E402

__all__ = ["Gateway", "TOOLS"]


# --- mock tool bodies --------------------------------------------------------------
# Each body runs ONLY after decide() returns ALLOW (see Gateway.call). They return
# plausible mock data and touch no real datastore, mailbox, or network — this is a
# surface for exercising the gate, not a production integration. The param names below
# match what the default pack's rules actually inspect, or decide() would never see the
# value: execute_sql -> "sql", send_email -> "to" (default.yaml rules 1 and 5).


def _body_lookup_customer(params: dict[str, Any]) -> dict[str, Any]:
    """A fake customer record. In default.yaml this read is the first half of the
    read-then-send exfil chain a trajectory rule guards."""
    customer_id = str(params.get("customer_id") or "cust_00417")
    return {
        "customer_id": customer_id,
        "name": "Dana Whitfield",
        "email": "dana.whitfield@example.com",
        "plan": "enterprise",
        "mrr_usd": 4200,
        "_note": "mock record; no datastore was read",
    }


def _body_send_email(params: dict[str, Any]) -> dict[str, Any]:
    """A fake send confirmation. No mail leaves the process."""
    return {
        "status": "sent",
        "to": params.get("to"),
        "subject": params.get("subject") or "(no subject)",
        "message_id": "msg_mock_5f3c91",
        "_note": "mock send; no mail was actually delivered",
    }


def _body_execute_sql(params: dict[str, Any]) -> dict[str, Any]:
    """A fake result set. Reached only for non-destructive SQL (destructive verbs are
    denied by default.yaml rule 1 before this body runs)."""
    return {
        "query": params.get("sql", ""),
        "rows": [
            {"id": 1, "name": "Dana Whitfield", "plan": "enterprise"},
            {"id": 2, "name": "Ravi Anand", "plan": "team"},
        ],
        "row_count": 2,
        "_note": "mock result set; no database was queried",
    }


# A genuinely real computation, evaluated with a small AST walker rather than eval():
# only numeric literals and the arithmetic operators below are permitted, so no names,
# calls, attribute access, or comprehensions can run. This keeps "calculator" honest
# (it actually computes) without opening a code-execution hole in a tool body.
_CALC_BINOPS: dict[type, Callable[[Any, Any], Any]] = {
    ast.Add: operator.add,
    ast.Sub: operator.sub,
    ast.Mult: operator.mul,
    ast.Div: operator.truediv,
    ast.FloorDiv: operator.floordiv,
    ast.Mod: operator.mod,
    ast.Pow: operator.pow,
}
_CALC_UNARY: dict[type, Callable[[Any], Any]] = {
    ast.UAdd: operator.pos,
    ast.USub: operator.neg,
}
# Three deterministic guards keep the calculator from being turned into a denial-of-
# service against its own process (a crash or hang in a tool body is a denial-of-decision):
#   - _MAX_EXPONENT caps a single `**` exponent (9 ** 9999 ...).
#   - _MAX_RESULT_BITS caps the magnitude of any integer result, so a CHAIN like
#     (2 ** 999) ** 999 — whose every literal exponent reads as a harmless 999 — cannot
#     build a multi-megabyte integer one level at a time. We pre-check the projected size
#     of a `**` before building it, and post-check every result, so the monster is never
#     even constructed.
#   - _MAX_DEPTH caps AST recursion depth, so a deeply nested expression (1+1+1+... a
#     thousand times) raises a clean ValueError well before it would exhaust the Python
#     stack and surface as an uncatchable RecursionError.
# None of this is real sandboxing; the AST walker already makes code execution impossible.
_MAX_EXPONENT = 1000
_MAX_RESULT_BITS = 4096
_MAX_DEPTH = 100


def _calc_capped(value: Any) -> Any:
    """Reject an integer whose magnitude exceeds the result cap; pass anything else through."""
    if isinstance(value, int) and value.bit_length() > _MAX_RESULT_BITS:
        raise ValueError(f"result too large (>{_MAX_RESULT_BITS} bits)")
    return value


def _calc_eval(node: ast.AST, depth: int = 0) -> float:
    if depth > _MAX_DEPTH:
        raise ValueError(f"expression nested too deeply (>{_MAX_DEPTH})")
    if isinstance(node, ast.Expression):
        return _calc_eval(node.body, depth + 1)
    if isinstance(node, ast.Constant) and isinstance(node.value, (int, float)) and not isinstance(node.value, bool):
        return node.value
    if isinstance(node, ast.UnaryOp) and type(node.op) in _CALC_UNARY:
        return _calc_capped(_CALC_UNARY[type(node.op)](_calc_eval(node.operand, depth + 1)))
    if isinstance(node, ast.BinOp) and type(node.op) in _CALC_BINOPS:
        left = _calc_eval(node.left, depth + 1)
        right = _calc_eval(node.right, depth + 1)
        if isinstance(node.op, ast.Pow):
            if abs(right) > _MAX_EXPONENT:
                raise ValueError(f"exponent too large (>{_MAX_EXPONENT})")
            # Project the result size BEFORE building it: an int ** positive-int has about
            # left.bit_length() * right bits. This catches the chained-exponent DoS where
            # `right` is a small literal but `left` is already a huge prior result.
            if isinstance(left, int) and isinstance(right, int) and right > 0 and left not in (0, 1, -1):
                if left.bit_length() * right > _MAX_RESULT_BITS:
                    raise ValueError(f"result too large (>{_MAX_RESULT_BITS} bits)")
        return _calc_capped(_CALC_BINOPS[type(node.op)](left, right))
    raise ValueError("only numbers and + - * / // % ** are allowed")


def _body_calculator(params: dict[str, Any]) -> dict[str, Any]:
    expression = str(params.get("expression") or "").strip()
    try:
        value = _calc_eval(ast.parse(expression, mode="eval"))
    except (ValueError, SyntaxError, TypeError, ZeroDivisionError, OverflowError, RecursionError, MemoryError) as exc:
        return {
            "expression": expression,
            "error": f"could not evaluate: {exc}",
            "_note": "real arithmetic; names, calls, and attribute access are rejected",
        }
    return {
        "expression": expression,
        "result": value,
        "_note": "real arithmetic, evaluated with a safe AST walker (no eval)",
    }


# The four tools this gateway exposes, matched to the default pack. The keys ARE the tool
# names decide() keys on; do not rename one without renaming the matching pack rule.
TOOLS: dict[str, Callable[[dict[str, Any]], dict[str, Any]]] = {
    "lookup_customer": _body_lookup_customer,
    "send_email": _body_send_email,
    "execute_sql": _body_execute_sql,
    "calculator": _body_calculator,
}

# Operational markers in the reserved aegis.* namespace. These are NOT policy decisions:
# they mark adapter-level refusals (the trail is unwritable, or the call itself was
# malformed), kept distinct from the engine's policy.* markers and from pack rule ids so
# one glance at the audit `rule` field says which world refused. AUDIT_UNAVAILABLE_MARKER
# is the same string core.loop uses (ADR 0002), so the fail-closed signal reads identically
# whoever wrote the record.
AUDIT_UNAVAILABLE_MARKER = "aegis.audit_unavailable"
MALFORMED_CALL_MARKER = "aegis.malformed_call"

# The exact parameter keys each tool accepts. A call to a known tool carrying any key
# outside its set is refused as malformed BEFORE it reaches decide() — this is the
# param-name contract made ENFORCED rather than conventional. Without it, a destructive
# value smuggled under an unexpected key (e.g. {"query": "DROP ..."} instead of
# {"sql": ...}) would be invisible to a rule that inspects `sql`, yet could reach a body
# that reads `query`. Rejecting unexpected keys closes that whole class structurally. The
# FastMCP handlers pass exactly these keys, so legitimate transport traffic never trips it;
# only a direct caller (or a future transparent-proxy mode) smuggling a key gets refused.
_TOOL_PARAM_KEYS: dict[str, frozenset[str]] = {
    "lookup_customer": frozenset({"customer_id"}),
    "send_email": frozenset({"to", "subject", "body"}),
    "execute_sql": frozenset({"sql"}),
    "calculator": frozenset({"expression"}),
}


class Gateway:
    """One governed session: the loaded pack, the running trajectory, the audit sink.

    The server creates exactly one Gateway per process (stdio transport = one client per
    process, so one session). Tests create a fresh Gateway each, which is why trajectory
    and log path live on the instance and not as module globals — instance state gives
    test isolation for free while still being "a per-session list" for the real server.
    """

    def __init__(self, pack: Pack | None = None, log_path: Path | str | None = None) -> None:
        # Load the default pack once, via the existing loader (the only YAML/disk path).
        # A failed load raises PolicyError up front rather than silently default-denying,
        # so a broken pack surfaces at startup instead of as a wall of mysterious DENYs.
        self._pack: Pack = pack if pack is not None else load(DEFAULT_PACK_PATH)
        self._log_path = log_path
        # Per-session trajectory: the ALLOWED concrete calls so far, in the exact shape
        # _after_holds reads — dicts carrying at least {"tool", "decision"}. ONLY allowed
        # calls are appended: a denied call never executed, so it must not taint a later
        # one (this mirrors the engine's ALLOW-only `after` matching).
        self._trajectory: list[dict[str, Any]] = []

    @property
    def trajectory(self) -> list[dict[str, Any]]:
        """A copy of the session trajectory, for inspection in tests/diagnostics."""
        return [dict(entry) for entry in self._trajectory]

    @staticmethod
    def _refusal(tool: str, decision: str, rule: str, reason: str) -> dict[str, Any]:
        """A structured refusal: no body ran, and the rule/marker that stopped it is named."""
        return {
            "ok": False,
            "decision": decision,
            "rule": rule,
            "tool": tool,
            "error": f"Aegis refused {tool}: {reason}",
        }

    def _write_audit(self, tool: str, params: dict[str, Any], decision: str, rule: str) -> bool:
        """Append one audit record; return True on success, False (with a warning) on failure.

        Mirrors core.loop's ADR 0002 fail-closed contract: if the trail cannot be written,
        the action must NOT proceed — an unlogged executed action is the exact failure the
        audit trail exists to prevent. The caller turns a False here into a refusal. The
        except is environmental, not evaluative: an outage can only turn ALLOW into a
        refusal, never DENY into ALLOW (monotonic), and the run self-heals because the next
        call re-attempts a fresh append.
        """
        try:
            append_record(tool=tool, params=params, decision=decision, rule=rule, log_path=self._log_path)
            return True
        except Exception as exc:  # noqa: BLE001 — refuse on ANY write failure, never allow.
            warnings.warn(
                f"[AEGIS] MCP gateway audit log unavailable for tool {tool!r} ({exc!r}); "
                f"action refused (fail-closed, marker={AUDIT_UNAVAILABLE_MARKER!r}).",
                stacklevel=2,
            )
            return False

    def call(self, tool: str, params: dict[str, Any] | None = None) -> dict[str, Any]:
        """Govern one proposed tool call, then run its body only if Aegis allows it.

        The order is the whole point of the adapter:
          1. DECIDE at the boundary — decide(pack, tool, params, trajectory). The
             trajectory is passed on every call so the read-then-send exfil rule can fire.
          2. RECORD one audit entry (ALLOW or DENY) via the existing writer, before any
             body runs (write-ahead). If the record cannot be written, fail closed.
          3. ACT: on a non-ALLOW verdict the body does NOT run and a structured refusal
             naming the rule/marker is returned; on ALLOW the body runs and the completed
             call joins the trajectory.

        Total on hostile input: a non-dict `params` is a malformed call with nothing
        well-formed to decide on, so it is refused deterministically rather than crashing
        the adapter (a crash is a denial-of-decision) — and rather than coerced to {},
        which would let a broad ALLOW rule fire on a call that was never well-formed.
        """
        if params is None:
            params = {}
        elif not isinstance(params, dict):
            recorded = {"_malformed_params": repr(params)[:200]}
            if not self._write_audit(tool, recorded, "DENY", MALFORMED_CALL_MARKER):
                return self._refusal(tool, "DENY", AUDIT_UNAVAILABLE_MARKER, "audit log unavailable; action refused")
            return self._refusal(
                tool, "DENY", MALFORMED_CALL_MARKER, f"params must be a mapping, got {type(params).__name__}"
            )

        # Enforce the tool's declared param contract: a known tool carrying an unexpected
        # key is refused before decide() ever sees it, so a payload cannot be smuggled past
        # a rule by riding under a key the rule does not inspect. Unknown tools are left to
        # decide()'s default-deny floor (no schema to check, and they match no rule).
        allowed_keys = _TOOL_PARAM_KEYS.get(tool)
        if allowed_keys is not None and not set(params) <= allowed_keys:
            extra = sorted(set(params) - allowed_keys)
            if not self._write_audit(tool, params, "DENY", MALFORMED_CALL_MARKER):
                return self._refusal(tool, "DENY", AUDIT_UNAVAILABLE_MARKER, "audit log unavailable; action refused")
            return self._refusal(tool, "DENY", MALFORMED_CALL_MARKER, f"unexpected parameter(s) {extra} for {tool}")

        result = decide(self._pack, tool, params, self._trajectory)
        decision = result.decision.value

        # Write-ahead, fail-closed: no body runs unless the call is durably recorded first.
        if not self._write_audit(tool, params, decision, result.rule_id):
            return self._refusal(tool, "DENY", AUDIT_UNAVAILABLE_MARKER, "audit log unavailable; action refused")

        if result.decision is not Decision.ALLOW:
            # Refuse without running the body. Name the rule/marker that denied it.
            return self._refusal(tool, decision, result.rule_id, f"denied by {result.rule_id}")

        body = TOOLS.get(tool)
        if body is None:
            # Defense in depth: the default pack only ALLOWs the four known tools, so this
            # is unreachable with that pack. An ALLOW for a tool we have no body for is a
            # wiring error, not something to fake a result for. The audit record above
            # truthfully shows the policy ALLOW; the adapter simply cannot execute it.
            return self._refusal(tool, decision, result.rule_id, "allowed by policy but this gateway exposes no such tool")

        # Run the body BEFORE recording the call in the trajectory, so a body that raises
        # never leaves a phantom ALLOW in the session history — an incomplete call must not
        # taint later trajectory-aware decisions.
        body_result = body(params)
        self._trajectory.append({"tool": tool, "params": params, "decision": "ALLOW"})
        return {
            "ok": True,
            "decision": decision,
            "rule": result.rule_id,
            "tool": tool,
            "result": body_result,
        }
