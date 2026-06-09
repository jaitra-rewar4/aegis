"""
decision.py — the vocabulary the gateway speaks.

WHY carry all four values from the start: later phases add RATE_LIMIT and
REQUIRE_APPROVAL behaviour without touching the type.  In Phase 1 only ALLOW
and DENY are ever produced; the other two are defined but unreachable, and the
loop treats any non-ALLOW as non-executable (see loop.py).
"""

from __future__ import annotations

import enum
from dataclasses import dataclass


class Decision(enum.Enum):
    ALLOW = "ALLOW"
    DENY = "DENY"
    # defined now so the runtime speaks the full vocabulary; no behaviour yet
    RATE_LIMIT = "RATE_LIMIT"
    REQUIRE_APPROVAL = "REQUIRE_APPROVAL"


@dataclass(frozen=True)
class GatewayResult:
    """Carries the decision and the rule that produced it.

    WHY a small result type rather than a bare enum value: the rule_id is
    load-bearing for the audit log and for the denial message sent back to the
    model, so it must travel with the decision as a single unit — no risk of
    the two getting out of sync across different call sites.
    """

    decision: Decision
    rule_id: str
