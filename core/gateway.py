"""
gateway.py — the single enforcement chokepoint, now a thin adapter (ADR 0003 §b).

evaluate(tool, params, context) -> GatewayResult

INVARIANT 1: this function receives concrete tool name + concrete parameters.
It NEVER receives model text or tool outputs — those are routed around it by the loop.

INVARIANT 2: this is a pure function. Given the same (tool, params) it returns the same
GatewayResult, every time. There is no LLM call, no random, no clock, no network, no I/O
inside it. The context argument is accepted but deliberately unread in 2a (see WHY below).

WHAT CHANGED IN 2a: the decision is no longer a hardcoded Python rule. The DECIDER is now
the declarative policy engine (policy/engine.py) running over a validated YAML pack. This
module became a THIN ADAPTER: it holds the configured pack and delegates to
engine.decide(pack, tool, params). The pack reaches here out-of-band via configure(), NOT
through context (context is reserved for session trajectory — ADR 0003 §b).

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
    context: Any,  # noqa: ARG001  (accepted, intentionally unread in 2a)
) -> GatewayResult:
    """Evaluate a proposed tool call and return a GatewayResult.

    Delegates to the pure decision function engine.decide(_ACTIVE_PACK, tool, params).
    The signature is byte-for-byte the pinned three-argument form (ADR 0001 §1a) so the
    loop's call site does not change.

    WHY the context parameter exists but is unread (2a):
    2b introduces trajectory-aware rules (read->send exfiltration chains) that need the
    session history. Stabilising the three-argument signature now means 2b adds
    *behaviour* without touching the enforcement path's call sites. Nothing in 2a reads
    context, so it carries zero nondeterminism today. When 2b reads it, it will read
    prior concrete tool calls — never model text — so invariant 1 still holds then.

    WHY decision-before-execution is structural, not conventional:
    evaluate() is a pure computation. The loop (loop.py) calls it and inspects the
    returned Decision *before* it ever calls the tool function. execute() is reachable
    only through the ALLOW branch; there is no other path to it.
    """
    return engine.decide(_ACTIVE_PACK, tool, params)
