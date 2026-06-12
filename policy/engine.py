"""
engine.py — the pure policy decision function (ADR 0003 §b, §c, §d, §f).

    decide(pack, tool, params, trajectory=None) -> GatewayResult

PURITY BOUNDARY (ADR 0003 §a/§b — a module boundary, not a discipline):
this module imports NO loader, NO yaml, and touches NO clock, random, network, or
file I/O. The only stdlib pulled in is `re`, used solely for the FIXED whitespace-
collapse normalizer reproduced from ADR 0001 §2 (a non-backtracking `\\s+` substitution,
the same one already proven deterministic in Phase 1). No pack- or user-supplied pattern
ever reaches a regex engine. A reviewer confirms the decision path is pure by reading the
imports of this one file: core.decision is the shared decision vocabulary, and
policy.schema supplies the Pack/Rule input types — schema.py itself performs no I/O
(that is the boundary that matters; loader.py is the only module that touches disk).

DETERMINISM (invariant 2): decide is a pure function of (pack, tool, params, trajectory).
First-match-wins over a stably-ordered rule list (ADR 0003 §d). Operators are
arithmetic / membership / prefix / split only — total on missing and wrong-typed
params (ADR 0003 §c). The 2b `after` clause (ADR 0004 §e) adds a fourth DATA input,
the trajectory: a pure sequence/membership scan over recorded prior actions — "does an
ALLOWed record with this tool exist earlier in the list" — NEVER time-based (no clock,
no `ts` comparison, no "within N seconds"; ADR 0004 §g). Adding a data input adds no
nondeterminism (it is input exactly like `params`). Same inputs -> same GatewayResult,
every time.
"""

from __future__ import annotations

import re
from typing import Any

from core.decision import Decision, GatewayResult
from policy.schema import Pack, Rule

__all__ = [
    "decide",
    "RULE_NO_PACK",
    "RULE_DEFAULT_DENY",
    "RULE_DEFAULT_ALLOW",
]

# --- engine markers (ADR 0003 §f) -------------------------------------------------
# These live in the reserved `policy.*` namespace (packs are forbidden from minting
# ids here — schema.py). They mark the non-rule decisions: an engine default fired,
# or there was no pack to consult. `no_pack` is kept distinct from `default_deny`
# even though both DENY — they mean different things to an operator reading the log
# ("no pack at all, check your wiring" vs "pack loaded, this matched nothing").
RULE_NO_PACK = "policy.no_pack"
RULE_DEFAULT_DENY = "policy.default_deny"
RULE_DEFAULT_ALLOW = "policy.default_allow"


# WHY this normalizer lives here (not in gateway.py anymore): contains_keyword reuses
# ADR 0001 §2's EXACT normalization so the migrated SQL rule behaves identically to the
# Phase-1 hardcoded one — same behavior, same documented gaps. The decision path owns it.
def _normalize_keyword_text(value: str) -> str:
    """Uppercase and collapse all internal whitespace to single spaces, then strip.

    Identical to ADR 0001 §2 / the deleted gateway._normalize_sql. The regex is a
    fixed `\\s+` collapse: non-backtracking, deterministic, no user-supplied pattern.
    """
    return re.sub(r"\s+", " ", value.upper()).strip()


# --- operator evaluators ----------------------------------------------------------
# Each returns True iff the constraint HOLDS for the given param value.
#
# TOTALITY (ADR 0003 §c): every operator is total — it returns a bool for ANY input,
# including a wrong-typed param. A MISSING param never reaches these functions; the
# caller (_constraint_holds) returns False for an absent param before dispatching.
# A constraint on a missing-or-wrong-typed param therefore does NOT hold, the rule
# does NOT match, evaluation falls through, and default-deny converts not-matching
# into denying.
#
# WHY "does not hold" is the fail-safe direction for BOTH effects (ADR 0003 §c):
#   - DENY rule: a missing param won't trigger the DENY, but fallthrough lands on
#     default-deny, so the malformed call still ends at DENY.
#   - ALLOW rule (the case that bites hardest if inverted): a missing/wrong-typed
#     param CANNOT satisfy an ALLOW guard. "allow wire_transfer when amount max:1000"
#     must NEVER fire for a call with no amount — that would allow an unbounded
#     transfer because a field was omitted. So the omission denies (via fallthrough),
#     never allows.


def _is_real_number(value: Any) -> bool:
    """True for int/float but NOT bool.

    WHY exclude bool here too: `True <= 1000` is valid Python arithmetic (bool is an
    int subclass), so a boolean param would otherwise be silently compared as 1/0.
    A bool is not a numeric amount; treating it as one is a surprise we refuse. The
    constraint simply does-not-hold on a bool, exactly like any other wrong type.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _op_max(param: Any, operand: Any) -> bool:
    return _is_real_number(param) and param <= operand


def _op_min(param: Any, operand: Any) -> bool:
    return _is_real_number(param) and param >= operand


def _op_one_of(param: Any, operand: list) -> bool:
    """param equals one of the listed scalars, with NO type coercion.

    WHY type-aware equality (`type(param) is type(v)`): `1 != "1"` must hold, and
    YAML parses bare `true`/`1` to bool/int — we do not want a param of `1` to match
    a list entry of `True` (or vice versa) via Python's `1 == True`. Requiring the
    types to match makes membership exact and predictable: a non-author reads the
    allowlist and the param and predicts the result without knowing Python's
    bool/int identity quirk. Simplest deterministic rule, pinned and commented.
    """
    return any(param == v and type(param) is type(v) for v in operand)


def _op_prefix_one_of(param: Any, operand: list) -> bool:
    return isinstance(param, str) and any(param.startswith(p) for p in operand)


def _op_domain_in(param: Any, operand: list) -> bool:
    """param is `local@domain` with exactly one '@', and domain (case-insensitive)
    is in the allowlist."""
    if not isinstance(param, str):
        return False
    if param.count("@") != 1:
        # Exactly one '@' — "" , "a@b@c", "no-at" all fail. WHY exact: a malformed
        # address has no well-defined domain to check, so the constraint does-not-hold.
        return False
    domain = param.split("@", 1)[1].lower()
    return any(domain == d.lower() for d in operand)


def _op_contains_keyword(param: Any, operand: list) -> bool:
    """param normalizes/tokenizes to a set that INTERSECTS the keyword list.

    Defensive coercion: if param is not a str, coerce via str() — this preserves the
    Phase-1 gateway behavior (a non-string sql param was str()'d, not crashed). After
    coercion the value is always a string, so the keyword scan is total.

    Keywords are uppercased at COMPARISON time here (pinned choice) so a pack may list
    them in any case; the normalizer already uppercases the param.
    """
    text = param if isinstance(param, str) else str(param)
    tokens = set(_normalize_keyword_text(text).split())
    keywords = {k.upper() for k in operand}
    return bool(tokens & keywords)


def _op_not_contains_keyword(param: Any, operand: list) -> bool:
    """True only when the param IS present and contains NONE of the keywords.

    THE NEGATION TRAP (ADR 0003 §c, pinned): for a MISSING param, "not contains" must
    still NOT hold. This function is only ever called by _constraint_holds AFTER the
    missing-param check, so a missing param never reaches here and the negation can
    never accidentally make an absent param satisfy the rule. Given a present param,
    "not contains" is the honest logical negation of contains_keyword.
    """
    return not _op_contains_keyword(param, operand)


def _op_domain_not_in(param: Any, operand: list) -> bool:
    """True only when param IS a well-formed address whose domain is NOT in the list.

    Holds iff param is a string with EXACTLY one '@' AND its lowercased domain is NOT in
    the lowercased operand list (ADR 0004 §f). It follows the EXACT pattern of
    not_contains_keyword: it is only ever reached AFTER the missing-param chokepoint in
    _constraint_holds, so a MISSING `to` param returns False there before this runs — the
    negation trap from 2a is already structurally closed, no new trap is opened.

    THE TRAP, pinned explicitly (ADR 0004 §f): this is NOT `not _op_domain_in(...)`.
    A malformed address — two '@' ("a@b@evil.com"), zero '@' ("no-at"), "", or a
    non-string — has NO parseable domain, so `_op_domain_in` returns False for it, and
    `not False` would be True: a garbage recipient would WRONGLY satisfy domain_not_in
    (and, on the exfil DENY rule, get DENYed for the wrong reason — or worse, satisfy an
    ALLOW guard phrased this way). The honest answer for "a string whose PARSEABLE domain
    is outside the list" when there is no parseable domain is False. So we reuse
    _op_domain_in's EXACT parsing discipline (one '@', split, lowercase) and return False
    on anything malformed — fail toward not-matching, the same direction as every other
    totality rule. Under default-deny a malformed `to` then falls through both send rules
    to the floor (ADR 0004 §f): denied by the floor, not by the operator pretending to
    understand it.
    """
    if not isinstance(param, str):
        return False
    if param.count("@") != 1:
        # Same exact-one-'@' discipline as _op_domain_in: no parseable domain -> not such
        # a string -> does-not-hold (NOT "its nonexistent domain isn't listed, so true").
        return False
    domain = param.split("@", 1)[1].lower()
    return not any(domain == d.lower() for d in operand)


_OPERATOR_EVALUATORS = {
    "max": _op_max,
    "min": _op_min,
    "one_of": _op_one_of,
    "prefix_one_of": _op_prefix_one_of,
    "domain_in": _op_domain_in,
    "domain_not_in": _op_domain_not_in,
    "contains_keyword": _op_contains_keyword,
    "not_contains_keyword": _op_not_contains_keyword,
}


def _constraint_holds(params: dict, param_name: str, operator: str, operand: Any) -> bool:
    """Return True iff the single constraint holds for the call's params.

    A MISSING param -> False here, BEFORE any operator runs. This is the single
    chokepoint that makes "constraint-on-missing-param does not hold" total across
    every operator, including the negation (not_contains_keyword) — see its docstring.
    """
    if param_name not in params:
        return False
    evaluator = _OPERATOR_EVALUATORS[operator]  # operator validated at load time.
    return evaluator(params[param_name], operand)


def _after_holds(after_tool: str | None, trajectory: Any) -> bool:
    """True iff the rule's `after` clause holds against the recorded trajectory (ADR 0004 §e).

    - `after_tool is None` -> True, WITHOUT touching the trajectory. WHY: a 2a rule has no
      `after` clause, so it must never read the trajectory at all — this is what makes a
      None/[]/junk trajectory byte-for-byte identical to 2a for any pack with no `after`
      rule (ADR 0004 §c). The clause being absent is a vacuous True, not a scan.
    - trajectory is None or empty -> False. A missing/empty trajectory means there is
      nothing to match against, so the predicate is honestly False (the same fail-safe
      direction as a missing param, ADR 0004 §e): default-deny converts not-matching into
      the safe outcome.
    - otherwise: True iff SOME entry is a dict AND entry.get("tool") == after_tool AND
      entry.get("decision") == "ALLOW" (ADR 0004 §e open-call (a): ALLOW-only — a DENYed
      read never executed, so no data was read; matching it would fire on a ghost).

    TOTALITY (ADR 0004 §e review-added build requirement): the scan is total over WHATEVER
    the list contains. `trajectory` is an externally-reachable input — a caller can hand
    `evaluate` any list — and the gate must NEVER be crashable from its inputs (a crash in
    evaluate is a denial-of-decision, and an exception path nobody reasoned about). So a
    non-dict entry (int, str, None, arbitrary object) is classified not-a-match BEFORE any
    field access (isinstance check first), and field access uses .get(...) with safe
    defaults — NEVER entry["tool"] / entry.decision, which would KeyError / AttributeError
    on junk. Junk entries fail toward not-matching, the same direction as every other
    totality rule in this design.
    """
    if after_tool is None:
        return True
    if not trajectory:  # None or empty list -> nothing recorded -> does-not-hold.
        return False
    for entry in trajectory:
        # isinstance gate FIRST: a non-dict entry is not-a-match before any field access,
        # so .get below is only ever called on a real dict (no AttributeError on junk).
        if isinstance(entry, dict) and entry.get("tool") == after_tool and entry.get("decision") == "ALLOW":
            return True
    return False


def _rule_matches(rule: Rule, tool: str, params: dict, trajectory: Any) -> bool:
    """A rule matches iff tool equals the call's tool AND `after` holds AND every `when` holds.

    The three are conjunctive (ADR 0004 §e: `after` is conjunctive with tool and when).
    WHY iteration order over `when` does not affect the outcome: the result is an AND of
    predicates, so dict iteration order changes only short-circuit timing, never the
    decision (ADR 0003 §d, determinism). For a rule with `after is None`, _after_holds
    returns True without reading the trajectory, so a 2a rule never touches it.
    """
    if rule.tool != tool:
        return False
    if not _after_holds(rule.after, trajectory):
        return False
    for param_name, (operator, operand) in rule.when.items():
        if not _constraint_holds(params, param_name, operator, operand):
            return False
    return True


def decide(
    pack: Pack | None, tool: str, params: dict, trajectory: Any = None
) -> GatewayResult:
    """Evaluate one proposed action against the pack and return a GatewayResult.

    Pure in (pack, tool, params, trajectory): no I/O, no clock, no random, no network
    (invariant 2). `trajectory` is the recorded list of prior concrete actions (ADR 0004
    §b/§c) — input DATA exactly like `params`.

    ADDITIVE signature (ADR 0004 §c): `trajectory` defaults to None, so every existing
    2a call site `decide(pack, tool, params)` is byte-for-byte unchanged. A None/empty
    trajectory reproduces 2a behavior EXACTLY: it is only ever read by the `after` clause
    (via _after_holds), a pack with no `after` rule never touches it, and None/[] makes
    every `after` clause not-hold — so a 2a pack decides identically whether trajectory is
    None, [], or a full history.

    Order (ADR 0003 §b/§d/§f, ADR 0004 §e):
      1. No pack configured -> DENY / policy.no_pack (the literal default of an
         unconfigured engine — default-deny without a spec).
      2. First-match-wins, top to bottom: the first rule whose tool matches, whose
         `after` holds, and whose `when` holds returns its effect + id immediately.
      3. No rule matched -> the pack's declared default: deny -> DENY/policy.default_deny,
         allow -> ALLOW/policy.default_allow.
    """
    if pack is None:
        return GatewayResult(decision=Decision.DENY, rule_id=RULE_NO_PACK)

    for rule in pack.rules:
        if _rule_matches(rule, tool, params, trajectory):
            decision = Decision.ALLOW if rule.effect == "ALLOW" else Decision.DENY
            return GatewayResult(decision=decision, rule_id=rule.id)

    if pack.default == "deny":
        return GatewayResult(decision=Decision.DENY, rule_id=RULE_DEFAULT_DENY)
    return GatewayResult(decision=Decision.ALLOW, rule_id=RULE_DEFAULT_ALLOW)
