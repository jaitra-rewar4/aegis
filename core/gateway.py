"""
gateway.py — the single enforcement chokepoint.

evaluate(tool, params, context) -> GatewayResult

INVARIANT 1: this function receives concrete tool name + concrete parameters.
It NEVER receives model text or tool outputs — those are routed around it by
the loop.

INVARIANT 2: this is a pure function.  Given the same (tool, params) it returns
the same GatewayResult, every time.  There is no LLM call, no random, no clock,
no network, no I/O inside it.  The context argument is accepted but deliberately
unread in Phase 1 (see WHY below).
"""

from __future__ import annotations

import re
from typing import Any

from core.decision import Decision, GatewayResult

# ---------------------------------------------------------------------------
# Phase 1 rule configuration
# ---------------------------------------------------------------------------

# WHY a frozenset of exact uppercase keywords and not a regex:
# - The set is the spec; it is easy to audit at a glance.
# - Normalization (uppercase + whitespace collapse) happens before the check,
#   so the set members stay clean single words.
# - The keyword set is deliberately minimal and frozen here; expanding it to
#   chase obfuscation is out of Phase 1 scope (see ADR 0001 §2 and §7).
_DESTRUCTIVE_KEYWORDS: frozenset[str] = frozenset({"DROP", "DELETE", "TRUNCATE", "ALTER"})

_RULE_DENY = "phase1.deny_destructive_sql"
_RULE_ALLOW = "phase1.default_allow"


def _normalize_sql(sql: str) -> str:
    """Uppercase and collapse all internal whitespace to single spaces.

    WHY both transforms: case variation and extra whitespace are the two
    cheapest obfuscation moves an agent can make.  Collapsing them before
    keyword matching closes those trivial evasions without adding any
    nondeterminism — the same input always produces the same normalized string.
    """
    return re.sub(r"\s+", " ", sql.upper()).strip()


def evaluate(
    tool: str,
    params: dict[str, Any],
    context: Any,  # noqa: ARG001  (accepted, intentionally unread in Phase 1)
) -> GatewayResult:
    """Evaluate a proposed tool call and return a GatewayResult.

    WHY the context parameter exists but is unread:
    Phase 2 introduces trajectory-aware rules (e.g. read→send exfiltration
    chains) that need the session history.  Stabilising the three-argument
    signature now means Phase 2 adds *behaviour* without touching the
    enforcement path's call sites.  Nothing in Phase 1 reads context, so it
    carries zero nondeterminism today.  When Phase 2 does read it, it will
    read prior concrete tool calls — never model text — so invariant 1 still
    holds then too.

    WHY decision-before-execution is structural, not conventional:
    evaluate() is a pure computation.  The loop (loop.py) calls it and
    inspects the returned Decision *before* it ever calls the tool function.
    There is no async path, no optimistic execute-then-check.  A reader can
    follow the control flow in loop.py top to bottom and see that execute()
    is reachable only through the ALLOW branch.
    """
    if tool == "execute_sql":
        sql_raw = params.get("sql", "")
        if not isinstance(sql_raw, str):
            # Coerce to str defensively; non-strings cannot be SQL but we must
            # not crash — returning DENY is safe.
            sql_raw = str(sql_raw)

        normalized = _normalize_sql(sql_raw)

        # WHY split on whitespace and check membership rather than substring:
        # A keyword appearing as a substring (e.g. "ALTERED" containing "ALTER")
        # would be a false positive with a bare 'in' string check.
        # Word-boundary splitting is still imperfect (comments, quoted strings),
        # but it is more precise than substring search for the Phase 1 stopgap.
        # Known remaining evasions are documented in red-team scope; the fix is
        # the real policy engine, not an expanded keyword list here.
        tokens = set(normalized.split())
        if tokens & _DESTRUCTIVE_KEYWORDS:
            return GatewayResult(decision=Decision.DENY, rule_id=_RULE_DENY)

    # Everything else — including all other tools and safe SQL — is allowed.
    return GatewayResult(decision=Decision.ALLOW, rule_id=_RULE_ALLOW)
