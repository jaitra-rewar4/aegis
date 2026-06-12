"""
gateway.py — the single enforcement chokepoint, now a thin adapter (ADR 0003 §b).

evaluate(tool, params, context) -> GatewayResult

INVARIANT 1: this function receives concrete tool name + concrete parameters.
It NEVER receives model text or tool outputs — those are routed around it by the loop.
The `context` argument (the trajectory) is a list of prior CONCRETE tool-call audit records
— never model text and never tool outputs (ADR 0002 froze the record shape to decision-only,
carrying no output field; ADR 0004 §b). Invariant 1 holds because the trajectory IS prior
concrete actions.

INVARIANT 2: this is a pure function. Given the same (pack, tool, params, trajectory) it
returns the same GatewayResult, every time. There is no LLM call, no random, no clock,
no network, no I/O inside it. decide() is a pure function of four data inputs (ADR 0004 §g).

WHAT CHANGED IN 2a: the decision is no longer a hardcoded Python rule. The DECIDER is now
the declarative policy engine (policy/engine.py) running over a validated YAML pack. This
module became a THIN ADAPTER: it holds the configured pack and delegates to
engine.decide(pack, tool, params, trajectory=...). The pack reaches here out-of-band via
configure(), NOT through context.

WHAT CHANGED IN 2b: context is no longer unread. It now carries the recorded trajectory
(the loop's live audit_trail list — a list of write-ahead audit records threaded by the
loop, ADR 0004 §b/§d). The extraction is TOTAL over every possible Python value (ADR 0004
§d): list -> trajectory, anything else -> None -> exact 2a behavior. One predicate,
isinstance(context, list), no KeyError, no attribute access that can raise, no type it
fails to classify. Reviewing one line predicts the trajectory for every context value.

IMPORT DIRECTION: core importing policy is intended — the gateway CONSUMES the engine.
policy/ never imports core.loop or core.audit; engine.py imports core.decision only (the
shared decision vocabulary), which keeps the dependency acyclic and the purity boundary clean.
"""

from __future__ import annotations

from typing import Any

from core.decision import GatewayResult
from policy import engine
from policy.schema import Pack

# ---------------------------------------------------------------------------
# Run-scoped active pack (ADR 0003 §b)
# ---------------------------------------------------------------------------

# WHY module-level and not threaded through context: the pack is "what the rules ARE"
# (set once, at startup, by an operator) — a different lifecycle and trust origin from
# "what has happened this session" (the trajectory, which 2b will carry in context).
# Keeping them in different handles keeps each one's determinism story clean. An
# unconfigured module (_ACTIVE_PACK is None) is default-deny: evaluate returns
# policy.no_pack DENY (engine.decide handles the None case).
_ACTIVE_PACK: Pack | None = None


def configure(pack: Pack | None) -> None:
    """Set the active policy pack for the run.

    WHY this is startup wiring, NOT part of the decision path: configure is called
    once at startup (fed by loader.load(...)); the pack is then immutable for the run.
    Because decide is pure in (pack, tool, params) and the pack is fixed, evaluate
    stays a pure function of its inputs for that run — exactly as in Phase 1. configure
    carries no per-call nondeterminism; it is the policy equivalent of setting the audit
    log path.

    Passing None DECONFIGURES the gateway (back to default-deny / policy.no_pack). This
    is useful for tests that need to assert the unconfigured posture and for fixture
    cleanup so module-level state never leaks between tests.
    """
    global _ACTIVE_PACK
    _ACTIVE_PACK = pack


def evaluate(
    tool: str,
    params: dict[str, Any],
    context: Any,
) -> GatewayResult:
    """Evaluate a proposed tool call and return a GatewayResult.

    Delegates to the pure decision function engine.decide(_ACTIVE_PACK, tool, params,
    trajectory=...). The signature is byte-for-byte the pinned three-argument form
    (ADR 0001 §1a) so the loop's call site does not change.

    The `context` argument now carries the recorded trajectory: the loop's live
    audit_trail list of write-ahead audit records for this run, threaded through here on
    every call (ADR 0004 §d). It is NOT unread anymore.

    EXTRACTION SEMANTICS (ADR 0004 §d) — total over every Python value:
      - context IS a list  ->  it IS the trajectory; pass it as trajectory=context.
      - context is ANYTHING ELSE (None, str, int, float, an object, ...) -> trajectory=None
        -> exact 2a behavior (the engine's `after` clause does-not-hold on None, so every
        2a pack rule decides identically whether trajectory is None or a real list).

    WHY isinstance(context, list) and no other shape: one predicate, total, obvious,
    fail-toward-2a. A single isinstance check classifies every Python value unambiguously
    — no KeyError, no attribute lookup that can raise, no type that fails to fall into
    one branch. The 2a determinism tests assert identical decisions for seven non-list
    context values; this branch handles them all in the else arm with zero special-casing.
    (ADR 0004 §d)

    WHY invariant 1 holds with the trajectory: the trajectory is prior concrete tool
    calls as logged audit records — {tool, params, decision, rule, ...} — never model
    text and never tool outputs (the record shape carries no output field, ADR 0002).
    The loop still routes only tool_use blocks to evaluate(); text blocks are ignored.

    WHY invariant 2 holds: decide() is a pure function of (pack, tool, params,
    trajectory) — no LLM, no random, no clock, no network, no I/O (ADR 0004 §g).
    Same four data inputs -> same GatewayResult, every time.

    WHY decision-before-execution is structural, not conventional:
    evaluate() is a pure computation. The loop (loop.py) calls it and inspects the
    returned Decision *before* it ever calls the tool function. execute() is reachable
    only through the ALLOW branch; there is no other path to it.
    """
    # WHY this exact, totally-pinned branch and no other (ADR 0004 §d):
    # list -> trajectory so the engine can scan prior ALLOWed actions;
    # anything else -> None -> exact 2a behavior, no crash, no KeyError.
    trajectory = context if isinstance(context, list) else None
    return engine.decide(_ACTIVE_PACK, tool, params, trajectory=trajectory)
