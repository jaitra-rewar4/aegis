"""
schema.py — the strict, fail-closed policy validator (ADR 0003 §c).

dict-in -> validated Pack / Rule objects, or raise PolicyError.

PURITY: this module performs NO file I/O and imports NO yaml. It validates plain
Python dicts (already parsed by loader.py). Keeping validation here, separate from
loader.py, means every rejection class is testable on in-memory dicts with no
filesystem (ADR 0003 §a).

ALL-OR-NOTHING (ADR 0003 §c, the strict-validation mandate): ANY violation rejects
the WHOLE pack — never partial, never "load the rules we understood and skip the rest."
WHY: a partially-loaded pack is a policy nobody wrote and nobody reviewed; its real
behavior would be the intersection of author intent and parser tolerance. Rejecting the
whole pack keeps the predicate "a non-author can read the pack and predict the decision"
true — the pack either IS the spec, or there is no spec (and the engine default-denies).
"""

from __future__ import annotations

from dataclasses import dataclass
from types import MappingProxyType
from typing import Any, Mapping

__all__ = ["PolicyError", "Rule", "Pack", "validate"]


class PolicyError(Exception):
    """Raised on ANY validation failure.

    The message names exactly what was wrong (which rule, which field, which
    operator) so a non-author reading the failure can fix the pack without
    guessing. loader.py chains the underlying cause for I/O / YAML failures.
    """


# WHY frozen dataclasses: a validated pack is the spec for the whole run; making it
# immutable means nothing downstream (the gateway adapter, the engine) can mutate a
# rule after validation and silently change behavior. Immutability is part of the
# determinism story (ADR 0003 §b: the pack is fixed for the run).
#
# WHY the immutability is DEEP, not just frozen=True: frozen only blocks attribute
# reassignment; a plain dict `when` and list operands could still be mutated in
# place (rule.when["p"] = ..., operand.append(...)), silently changing policy after
# validation — and the test suite shares one cached Pack across all tests, so a
# single in-place mutation would corrupt every later test. So `when` is wrapped in
# MappingProxyType (a read-only view) and list operands are stored as tuples.
@dataclass(frozen=True)
class Rule:
    id: str
    rationale: str
    tool: str
    # `when` is normalized to a read-only mapping param -> (operator, operand),
    # or an empty mapping. List operands are stored as tuples.
    # WHY pre-normalized rather than the raw {param: {op: operand}} nesting: the
    # engine then reads a flat (operator, operand) pair per param with no further
    # structural unpacking in the decision path (ADR 0003 §c).
    when: Mapping[str, tuple[str, Any]]
    effect: str  # exactly "ALLOW" or "DENY" in 2a.
    # `after`: the validated 2b trajectory clause (ADR 0004 §e). Stored as the BARE
    # validated tool name (a str), or None when the clause is absent.
    # WHY storing just the tool name is enough: the entire 2b `after` shape is exactly
    # {tool: <non-empty string>} (ADR 0004 §e open-call (b), pinned) — a single tool
    # identity to scan the trajectory for. There is no operand, count, or nested
    # constraint to carry, so a bare string fully captures the validated clause. A
    # richer frozen structure (a dataclass/MappingProxy) is the natural shape only when
    # `after` widens to param constraints / multiple tools / counts — explicitly future
    # work, not 2b (ADR 0004 §e Out of scope). A plain str is also trivially immutable,
    # so it needs no MappingProxy/tuple wrapping to stay deeply frozen like `when`.
    after: str | None  # the tool name a prior ALLOWed record must carry, or None.


@dataclass(frozen=True)
class Pack:
    version: int
    default: str  # "deny" or "allow"
    rules: tuple[Rule, ...]


# --- reserved id namespaces (ADR 0003 §c, §f) -------------------------------------
# WHY reserve BOTH: the audit `rule` field distinguishes three worlds at a glance:
#   aegis.*  = an OPERATIONAL refusal the loop made because infrastructure failed
#              (ADR 0002, e.g. aegis.audit_unavailable),
#   policy.* = an ENGINE decision via its default / no-pack path (ADR 0003 §f),
#   anything else = a named rule the author wrote.
# A pack that could mint an id in either reserved namespace would blur the one
# boundary ADR 0002 told us to keep clean, so we forbid it at load.
_RESERVED_ID_PREFIXES: tuple[str, ...] = ("aegis.", "policy.")

# The only top-level keys a pack may contain. Anything else -> reject (unknown field).
_ALLOWED_PACK_KEYS: frozenset[str] = frozenset({"version", "default", "rules"})

# The only keys a rule may contain. Anything else -> reject.
# `after` joins the set in 2b (ADR 0004 §e): the optional trajectory clause.
_ALLOWED_RULE_KEYS: frozenset[str] = frozenset({"id", "rationale", "tool", "when", "effect", "after"})

# The only keys an `after` mapping may contain in 2b — exactly the one key `tool`.
# WHY a named constant for a single-element set: it makes the 2b `after` shape
# (ADR 0004 §e open-call (b): exactly {tool: <non-empty string>}, nothing else)
# a reviewable datum, and gives _normalize_after one place to widen when `after`
# grows param constraints / multiple tools later (explicitly future work).
_ALLOWED_AFTER_KEYS: frozenset[str] = frozenset({"tool"})

# The only effect values 2a accepts. RATE_LIMIT / REQUIRE_APPROVAL are rejected at
# load (ADR 0003 Out of scope): the loop treats every non-ALLOW as a blunt refusal
# with no approval ever solicited, so accepting REQUIRE_APPROVAL would ship a rule
# that lies about itself. Refusing it here makes the gap loud. Widening later is
# backward-compatible; narrowing is not — so we start narrow.
_ALLOWED_EFFECTS: frozenset[str] = frozenset({"ALLOW", "DENY"})

# Operators that take a numeric operand (int/float, NOT bool — see below).
_NUMERIC_OPERATORS: frozenset[str] = frozenset({"max", "min"})

# Operators whose operand is a non-empty list of strings.
# `domain_not_in` joins the set in 2b (ADR 0004 §f): it is the negation of `domain_in`
# and takes the IDENTICAL operand — a non-empty list of strings (recipient domains).
# Validating it here, identically to `domain_in`, means a wrong operand type rejects
# the whole pack by the same mechanism (ADR 0003 §c all-or-nothing).
_STRING_LIST_OPERATORS: frozenset[str] = frozenset(
    {"prefix_one_of", "domain_in", "domain_not_in", "contains_keyword", "not_contains_keyword"}
)

# Every recognized operator. Unknown operator -> reject (ADR 0003 §c).
_ALLOWED_OPERATORS: frozenset[str] = (
    _NUMERIC_OPERATORS | _STRING_LIST_OPERATORS | frozenset({"one_of"})
)


def _is_real_number(value: Any) -> bool:
    """True for int/float but NOT bool.

    WHY exclude bool: in Python `bool` is a subclass of `int`, so `True` would pass
    a naive `isinstance(value, (int, float))` and `True <= 5` is valid arithmetic.
    A numeric operand of `true`/`false` in a pack is almost certainly an authoring
    mistake (YAML `yes`/`no`/`true` parse to bool), and silently treating it as 1/0
    would be an un-reviewable surprise. We reject it at load.
    """
    return isinstance(value, (int, float)) and not isinstance(value, bool)


def _validate_operand(rule_id: str, param: str, operator: str, operand: Any) -> None:
    """Raise PolicyError if `operand` has the wrong type for `operator`."""
    if operator in _NUMERIC_OPERATORS:
        # max/min: operand must be a real number (not bool).
        if not _is_real_number(operand):
            raise PolicyError(
                f"rule '{rule_id}': operator '{operator}' on param '{param}' "
                f"requires a number operand, got {operand!r}"
            )
        return

    if operator == "one_of":
        # Non-empty list of scalars (str/int/float/bool/None). No nested lists/dicts.
        if not isinstance(operand, list) or not operand:
            raise PolicyError(
                f"rule '{rule_id}': operator 'one_of' on param '{param}' "
                f"requires a non-empty list, got {operand!r}"
            )
        for item in operand:
            if isinstance(item, (list, dict)):
                raise PolicyError(
                    f"rule '{rule_id}': operator 'one_of' on param '{param}' "
                    f"requires scalar list items, got {item!r}"
                )
        return

    if operator in _STRING_LIST_OPERATORS:
        # Non-empty list of strings.
        if not isinstance(operand, list) or not operand:
            raise PolicyError(
                f"rule '{rule_id}': operator '{operator}' on param '{param}' "
                f"requires a non-empty list of strings, got {operand!r}"
            )
        for item in operand:
            # bool is excluded explicitly: isinstance(True, str) is already False,
            # but we keep the message precise about what is required.
            if not isinstance(item, str):
                raise PolicyError(
                    f"rule '{rule_id}': operator '{operator}' on param '{param}' "
                    f"requires list items to be strings, got {item!r}"
                )
        return

    # Unreachable: operator membership is checked before _validate_operand is called.
    raise PolicyError(f"rule '{rule_id}': unknown operator '{operator}' on param '{param}'")


def _normalize_when(rule_id: str, raw_when: Any) -> dict[str, tuple[str, Any]]:
    """Validate and flatten a raw `when` mapping to param -> (operator, operand).

    Accepts only: a dict of param-name -> single-key {operator: operand} dict.
    Any other shape -> PolicyError (the whole pack is then rejected by the caller).
    """
    if not isinstance(raw_when, dict):
        raise PolicyError(
            f"rule '{rule_id}': 'when' must be a mapping of param -> "
            f"{{operator: operand}}, got {raw_when!r}"
        )

    normalized: dict[str, tuple[str, Any]] = {}
    for param, constraint in raw_when.items():
        if not isinstance(param, str) or not param:
            raise PolicyError(
                f"rule '{rule_id}': 'when' parameter names must be non-empty "
                f"strings, got {param!r}"
            )
        if not isinstance(constraint, dict):
            raise PolicyError(
                f"rule '{rule_id}': 'when' constraint for param '{param}' must be a "
                f"single-key {{operator: operand}} dict, got {constraint!r}"
            )
        # Exactly one operator per param. A multi-key dict (e.g. {max: 5, min: 1})
        # is ambiguous about precedence and dict iteration order, so we reject it;
        # an author who wants two constraints on one param writes two rules or we
        # add a compound operator later.
        if len(constraint) != 1:
            raise PolicyError(
                f"rule '{rule_id}': 'when' constraint for param '{param}' must have "
                f"exactly one operator, got {len(constraint)} keys: "
                f"{sorted(constraint.keys())!r}"
            )
        (operator, operand), = constraint.items()
        if operator not in _ALLOWED_OPERATORS:
            raise PolicyError(
                f"rule '{rule_id}': unknown operator '{operator}' on param '{param}' "
                f"(allowed: {sorted(_ALLOWED_OPERATORS)!r})"
            )
        _validate_operand(rule_id, param, operator, operand)
        # Store list operands as tuples: deep immutability (see the Rule docstring
        # WHY). The engine only iterates/membership-tests operands, so a tuple is a
        # drop-in replacement for a list there.
        frozen_operand = tuple(operand) if isinstance(operand, list) else operand
        normalized[param] = (operator, frozen_operand)

    return normalized


def _normalize_after(rule_id: str, raw_after: Any) -> str:
    """Validate a raw `after` clause and return the bare tool name, or raise PolicyError.

    Mirrors _normalize_when's discipline (ADR 0004 §e): `after`, when present, must be a
    dict with EXACTLY one key `tool` whose value is a non-empty string. Anything else
    rejects the WHOLE pack (the 2a all-or-nothing mandate, ADR 0003 §c, unchanged):
      - non-dict (list, str, int, None-was-handled-by-caller),
      - missing / unknown / multi-key set (e.g. {tool, x}, {when: ...}),
      - `tool` empty or non-string.
    WHY exactly this one shape and nothing else (ADR 0004 §e open-call (b), pinned):
    {tool: <non-empty string>} is the minimal, TOTAL, OBVIOUS expression of the read->send
    pattern — a list scan for a tool name + ALLOW is defined for every trajectory including
    the empty one, and a non-author reads `after: {tool: lookup_customer}` and predicts
    "fires only once a lookup_customer was allowed earlier." Param constraints, multiple
    tools, counts, ordering, and negative forms inside `after` are deliberately future
    extensions (ADR 0004 §e Out of scope) — we start narrow because widening is
    backward-compatible and narrowing is not.

    Returns the bare validated tool name (a str). The caller stores it on Rule.after; a
    None `after` clause is handled by the caller (absent -> Rule.after = None).
    """
    if not isinstance(raw_after, dict):
        raise PolicyError(
            f"rule '{rule_id}': 'after' must be a mapping {{tool: <non-empty string>}}, "
            f"got {raw_after!r}"
        )

    unknown = set(raw_after.keys()) - _ALLOWED_AFTER_KEYS
    if unknown:
        raise PolicyError(
            f"rule '{rule_id}': 'after' has unknown key(s): {sorted(unknown)!r} "
            f"(the only allowed key in 2b is 'tool')"
        )

    # Exactly the one key `tool`. After the unknown-key check above, the only remaining
    # way to fail the count is an EMPTY `after` ({}), which has no `tool` at all. A
    # multi-key set like {tool, x} is already rejected by the unknown-key check.
    if len(raw_after) != 1:
        raise PolicyError(
            f"rule '{rule_id}': 'after' must have exactly the one key 'tool', "
            f"got {sorted(raw_after.keys())!r}"
        )

    after_tool = raw_after.get("tool")
    if not isinstance(after_tool, str) or not after_tool:
        raise PolicyError(
            f"rule '{rule_id}': 'after.tool' must be a non-empty string, got {after_tool!r}"
        )

    return after_tool


def _validate_rule(raw: Any, seen_ids: set[str]) -> Rule:
    """Validate one raw rule dict and return a frozen Rule, or raise PolicyError."""
    if not isinstance(raw, dict):
        raise PolicyError(f"each rule must be a mapping, got {raw!r}")

    unknown = set(raw.keys()) - _ALLOWED_RULE_KEYS
    if unknown:
        raise PolicyError(
            f"rule has unknown field(s): {sorted(unknown)!r} "
            f"(allowed: {sorted(_ALLOWED_RULE_KEYS)!r})"
        )

    rule_id = raw.get("id")
    if not isinstance(rule_id, str) or not rule_id:
        raise PolicyError(f"rule 'id' is required and must be a non-empty string, got {rule_id!r}")

    for prefix in _RESERVED_ID_PREFIXES:
        if rule_id.startswith(prefix):
            raise PolicyError(
                f"rule id '{rule_id}' is in the reserved '{prefix}*' namespace; "
                f"these ids are owned by the engine/operational layer and may not "
                f"be used by packs (ADR 0003 §c/§f)"
            )

    if rule_id in seen_ids:
        raise PolicyError(f"duplicate rule id '{rule_id}'")
    seen_ids.add(rule_id)

    rationale = raw.get("rationale")
    if not isinstance(rationale, str) or not rationale:
        raise PolicyError(
            f"rule '{rule_id}': 'rationale' is required and must be a non-empty "
            f"string (ADR 0003 §c: rationale is first-class data, not a comment)"
        )

    tool = raw.get("tool")
    if not isinstance(tool, str) or not tool:
        raise PolicyError(f"rule '{rule_id}': 'tool' is required and must be a non-empty string")

    effect = raw.get("effect")
    if effect not in _ALLOWED_EFFECTS:
        raise PolicyError(
            f"rule '{rule_id}': 'effect' must be exactly one of {sorted(_ALLOWED_EFFECTS)!r}, "
            f"got {effect!r} (RATE_LIMIT / REQUIRE_APPROVAL are rejected in 2a — ADR 0003)"
        )

    # `when` is optional; absent means the rule matches any call to that tool.
    raw_when = raw.get("when")
    when = {} if raw_when is None else _normalize_when(rule_id, raw_when)

    # `after` is optional (ADR 0004 §e); absent means the rule never consults the
    # trajectory and behaves exactly like a 2a rule. Stored as the bare tool name or None.
    raw_after = raw.get("after")
    after = None if raw_after is None else _normalize_after(rule_id, raw_after)

    # MappingProxyType: a read-only view, so the validated constraint set cannot be
    # mutated in place after validation (deep immutability — see the Rule docstring).
    # `after` is a bare str (or None), already deeply immutable, so it needs no wrapper.
    return Rule(
        id=rule_id,
        rationale=rationale,
        tool=tool,
        when=MappingProxyType(when),
        effect=effect,
        after=after,
    )


def validate(raw: dict) -> Pack:
    """Validate a raw policy dict and return a frozen Pack, or raise PolicyError.

    Strict, fail-closed, all-or-nothing (ADR 0003 §c): the first violation found
    raises and rejects the whole pack. There is no partial Pack.
    """
    if not isinstance(raw, dict):
        raise PolicyError(f"policy pack must be a mapping at the top level, got {type(raw).__name__}")

    unknown = set(raw.keys()) - _ALLOWED_PACK_KEYS
    if unknown:
        raise PolicyError(
            f"policy pack has unknown top-level field(s): {sorted(unknown)!r} "
            f"(allowed: {sorted(_ALLOWED_PACK_KEYS)!r})"
        )

    version = raw.get("version")
    # bool excluded: isinstance(True, int) is True, and `version: true` is a mistake.
    if not isinstance(version, int) or isinstance(version, bool) or version != 1:
        raise PolicyError(f"policy pack 'version' must be the integer 1, got {version!r}")

    default = raw.get("default")
    if default not in ("deny", "allow"):
        raise PolicyError(f"policy pack 'default' must be 'deny' or 'allow', got {default!r}")

    rules_raw = raw.get("rules")
    if not isinstance(rules_raw, list):
        raise PolicyError(f"policy pack 'rules' must be a list, got {rules_raw!r}")
    # NOTE: an EMPTY rules list is deliberately accepted. `rules: []` with
    # `default: deny` is a valid, explicit all-deny configuration (and with
    # `default: allow` an explicit all-allow one). The pack still states its
    # posture in `default`, so the behavior is declared, not accidental.

    seen_ids: set[str] = set()
    rules = tuple(_validate_rule(r, seen_ids) for r in rules_raw)

    return Pack(version=version, default=default, rules=rules)
