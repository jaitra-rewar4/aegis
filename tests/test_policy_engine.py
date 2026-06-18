"""
test_policy_engine.py — unit tests pinning every part of the 2a policy engine.

Charter (CLAUDE.md): a rule without a test that pins its decision does not ship.
Coverage: schema validation (valid pack + every rejection class), engine decisions
(no-pack, first-match-wins, default fallthroughs, every operator's holds / does-not-hold
/ missing-param / wrong-type semantics, the negation trap, bool-vs-number, determinism),
loader (real pack + malformed/invalid/non-dict YAML), the gateway adapter, and the
default pack's end-to-end behavior.
"""

from __future__ import annotations

import pytest

from core import gateway
from core.decision import Decision
from policy import engine, loader
from policy.engine import RULE_DEFAULT_ALLOW, RULE_DEFAULT_DENY, RULE_NO_PACK
from policy.schema import Pack, PolicyError, Rule, validate

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _minimal_pack_dict(**overrides):
    """A valid raw pack dict; override individual keys for rejection tests."""
    base = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "demo.allow_calc",
                "rationale": "calculator is pure arithmetic",
                "tool": "calculator",
                "effect": "ALLOW",
            }
        ],
    }
    base.update(overrides)
    return base


# ===========================================================================
# SCHEMA — valid pack
# ===========================================================================

def test_valid_pack_validates_and_preserves_fields():
    raw = {
        "version": 1,
        "default": "deny",
        "rules": [
            {
                "id": "sql.deny_destructive",
                "rationale": "stopgap keyword scan pending a real SQL parser",
                "tool": "execute_sql",
                "when": {"sql": {"contains_keyword": ["DROP", "DELETE"]}},
                "effect": "DENY",
            },
            {
                "id": "sql.allow_other",
                "rationale": "non-destructive SQL is permitted",
                "tool": "execute_sql",
                "effect": "ALLOW",
            },
        ],
    }
    pack = validate(raw)
    assert isinstance(pack, Pack)
    assert pack.version == 1
    assert pack.default == "deny"
    # Order preserved.
    assert [r.id for r in pack.rules] == ["sql.deny_destructive", "sql.allow_other"]
    # Rationale preserved as data.
    assert pack.rules[0].rationale == "stopgap keyword scan pending a real SQL parser"
    # `when` normalized to param -> (operator, operand).
    # List operands are frozen to tuples at validation (deep immutability).
    assert pack.rules[0].when == {"sql": ("contains_keyword", ("DROP", "DELETE"))}
    # Absent `when` -> empty mapping.
    assert pack.rules[1].when == {}
    assert isinstance(pack.rules[0], Rule)


def test_valid_pack_default_allow_accepted():
    pack = validate(_minimal_pack_dict(default="allow"))
    assert pack.default == "allow"


@pytest.mark.parametrize(
    "operator,operand",
    [
        ("max", 1000),
        ("max", 9.99),
        ("min", 0),
        ("one_of", ["a", 1, 2.5]),
        ("prefix_one_of", ["/safe/"]),
        ("domain_in", ["example.com"]),
        ("contains_keyword", ["DROP"]),
        ("not_contains_keyword", ["DROP"]),
    ],
)
def test_valid_operands_accepted(operator, operand):
    raw = _minimal_pack_dict(
        rules=[
            {
                "id": "r.one",
                "rationale": "ok",
                "tool": "t",
                "when": {"p": {operator: operand}},
                "effect": "ALLOW",
            }
        ]
    )
    pack = validate(raw)
    # List operands are frozen to tuples at validation (deep immutability).
    expected = tuple(operand) if isinstance(operand, list) else operand
    assert pack.rules[0].when == {"p": (operator, expected)}


# ===========================================================================
# SCHEMA — rejection classes (each -> PolicyError, whole pack rejected)
# ===========================================================================

def test_non_dict_root_rejected():
    with pytest.raises(PolicyError):
        validate(["not", "a", "dict"])  # type: ignore[arg-type]


@pytest.mark.parametrize("version", [0, 2, "1", 1.0, True, None])
def test_bad_version_rejected(version):
    with pytest.raises(PolicyError):
        validate(_minimal_pack_dict(version=version))


@pytest.mark.parametrize("default", ["DENY", "Allow", "block", "", None, 1])
def test_bad_default_rejected(default):
    with pytest.raises(PolicyError):
        validate(_minimal_pack_dict(default=default))


@pytest.mark.parametrize("rules", [None, {}, "rules", 5])
def test_non_list_rules_rejected(rules):
    with pytest.raises(PolicyError):
        validate(_minimal_pack_dict(rules=rules))


def test_unknown_top_level_field_rejected():
    raw = _minimal_pack_dict()
    raw["extra"] = "nope"
    with pytest.raises(PolicyError):
        validate(raw)


def test_unknown_rule_field_rejected():
    raw = _minimal_pack_dict(
        rules=[
            {
                "id": "r.one",
                "rationale": "ok",
                "tool": "t",
                "effect": "ALLOW",
                "priority": 5,  # unknown
            }
        ]
    )
    with pytest.raises(PolicyError):
        validate(raw)


@pytest.mark.parametrize("rule_id", ["", None, 5, "aegis.audit_unavailable", "policy.no_pack", "aegis.x", "policy.y"])
def test_bad_or_reserved_id_rejected(rule_id):
    raw = _minimal_pack_dict(
        rules=[{"id": rule_id, "rationale": "ok", "tool": "t", "effect": "ALLOW"}]
    )
    with pytest.raises(PolicyError):
        validate(raw)


def test_duplicate_rule_ids_rejected():
    raw = _minimal_pack_dict(
        rules=[
            {"id": "dup", "rationale": "a", "tool": "t", "effect": "ALLOW"},
            {"id": "dup", "rationale": "b", "tool": "t2", "effect": "DENY"},
        ]
    )
    with pytest.raises(PolicyError):
        validate(raw)


@pytest.mark.parametrize("rationale", ["", None, 5])
def test_empty_or_bad_rationale_rejected(rationale):
    raw = _minimal_pack_dict(
        rules=[{"id": "r.one", "rationale": rationale, "tool": "t", "effect": "ALLOW"}]
    )
    with pytest.raises(PolicyError):
        validate(raw)


@pytest.mark.parametrize("tool", ["", None, 5])
def test_empty_or_bad_tool_rejected(tool):
    raw = _minimal_pack_dict(
        rules=[{"id": "r.one", "rationale": "ok", "tool": tool, "effect": "ALLOW"}]
    )
    with pytest.raises(PolicyError):
        validate(raw)


@pytest.mark.parametrize("effect", ["allow", "Deny", "Allow", "MAYBE", "", None, 5])
def test_bad_effect_rejected(effect):
    # All four Decision values are valid effects in Phase 3 (ADR 0006 §b). What stays
    # rejected: wrong case ("allow"/"Deny"/"Allow"), an unknown effect ("MAYBE"), empty,
    # None, and non-strings. RATE_LIMIT / REQUIRE_APPROVAL are now accepted (tested below).
    raw = _minimal_pack_dict(
        rules=[{"id": "r.one", "rationale": "ok", "tool": "t", "effect": effect}]
    )
    with pytest.raises(PolicyError):
        validate(raw)


@pytest.mark.parametrize("effect", ["ALLOW", "DENY", "RATE_LIMIT", "REQUIRE_APPROVAL"])
def test_all_four_effects_accepted(effect):
    # Phase 3 widened _ALLOWED_EFFECTS to all four Decision values (ADR 0006 §b).
    raw = _minimal_pack_dict(
        rules=[{"id": "r.one", "rationale": "ok", "tool": "t", "effect": effect}]
    )
    pack = validate(raw)
    assert pack.rules[0].effect == effect


@pytest.mark.parametrize("when", ["nope", 5, ["a"], {"p": "string"}, {"p": 5}])
def test_non_dict_when_or_constraint_rejected(when):
    raw = _minimal_pack_dict(
        rules=[{"id": "r.one", "rationale": "ok", "tool": "t", "when": when, "effect": "ALLOW"}]
    )
    with pytest.raises(PolicyError):
        validate(raw)


def test_multi_key_operator_dict_rejected():
    raw = _minimal_pack_dict(
        rules=[
            {
                "id": "r.one",
                "rationale": "ok",
                "tool": "t",
                "when": {"amount": {"max": 1000, "min": 1}},  # two operators -> reject
                "effect": "ALLOW",
            }
        ]
    )
    with pytest.raises(PolicyError):
        validate(raw)


def test_unknown_operator_rejected():
    raw = _minimal_pack_dict(
        rules=[
            {
                "id": "r.one",
                "rationale": "ok",
                "tool": "t",
                "when": {"p": {"regex": ".*"}},  # not in the operator set
                "effect": "ALLOW",
            }
        ]
    )
    with pytest.raises(PolicyError):
        validate(raw)


@pytest.mark.parametrize(
    "operator,operand",
    [
        ("max", "ten"),       # numeric op, string operand
        ("max", True),        # numeric op, bool operand (bool is int subclass)
        ("min", False),       # numeric op, bool operand
        ("max", [1, 2]),      # numeric op, list operand
        ("one_of", 5),        # one_of needs a list
        ("one_of", []),       # one_of needs a NON-empty list
        ("one_of", [[1]]),    # one_of items must be scalars
        ("prefix_one_of", "x"),       # needs a list
        ("prefix_one_of", []),        # needs non-empty
        ("prefix_one_of", [1]),       # items must be strings
        ("domain_in", []),            # needs non-empty
        ("domain_in", [1]),           # items must be strings
        ("contains_keyword", []),     # needs non-empty
        ("contains_keyword", [1]),    # items must be strings
        ("not_contains_keyword", []), # needs non-empty
        ("not_contains_keyword", [True]),  # items must be strings
    ],
)
def test_wrong_operand_type_rejected(operator, operand):
    raw = _minimal_pack_dict(
        rules=[
            {
                "id": "r.one",
                "rationale": "ok",
                "tool": "t",
                "when": {"p": {operator: operand}},
                "effect": "ALLOW",
            }
        ]
    )
    with pytest.raises(PolicyError):
        validate(raw)


# ===========================================================================
# ENGINE — no pack
# ===========================================================================

def test_decide_none_pack_denies_no_pack():
    result = engine.decide(None, "anything", {"x": 1})
    assert result.decision is Decision.DENY
    assert result.rule_id == RULE_NO_PACK


# ===========================================================================
# ENGINE — first-match-wins (ADR 0003 §d)
# ===========================================================================

def _two_rule_pack(first_effect, second_effect):
    return validate(
        _minimal_pack_dict(
            rules=[
                {"id": "first", "rationale": "a", "tool": "execute_sql",
                 "when": {"sql": {"contains_keyword": ["DROP"]}}, "effect": first_effect},
                {"id": "second", "rationale": "b", "tool": "execute_sql", "effect": second_effect},
            ]
        )
    )


def test_first_match_wins_deny_above_allow():
    pack = _two_rule_pack("DENY", "ALLOW")
    r = engine.decide(pack, "execute_sql", {"sql": "DROP TABLE t"})
    assert r.decision is Decision.DENY
    assert r.rule_id == "first"


def test_first_match_wins_reversed_allow_above_deny():
    # Reverse the order: a broad ALLOW first now shadows the DENY (author's visible
    # mistake on the page — proves order, not scoring, decides).
    pack = validate(
        _minimal_pack_dict(
            rules=[
                {"id": "broad_allow", "rationale": "a", "tool": "execute_sql", "effect": "ALLOW"},
                {"id": "deny_drop", "rationale": "b", "tool": "execute_sql",
                 "when": {"sql": {"contains_keyword": ["DROP"]}}, "effect": "DENY"},
            ]
        )
    )
    r = engine.decide(pack, "execute_sql", {"sql": "DROP TABLE t"})
    assert r.decision is Decision.ALLOW
    assert r.rule_id == "broad_allow"


def test_non_destructive_sql_falls_to_allow():
    pack = _two_rule_pack("DENY", "ALLOW")
    r = engine.decide(pack, "execute_sql", {"sql": "SELECT * FROM t"})
    assert r.decision is Decision.ALLOW
    assert r.rule_id == "second"


# ===========================================================================
# ENGINE — default fallthroughs (ADR 0003 §f)
# ===========================================================================

def test_default_deny_fallthrough():
    pack = validate(_minimal_pack_dict(default="deny"))
    r = engine.decide(pack, "unknown_tool", {})
    assert r.decision is Decision.DENY
    assert r.rule_id == RULE_DEFAULT_DENY


def test_default_allow_fallthrough():
    pack = validate(_minimal_pack_dict(default="allow"))
    r = engine.decide(pack, "unknown_tool", {})
    assert r.decision is Decision.ALLOW
    assert r.rule_id == RULE_DEFAULT_ALLOW


# ===========================================================================
# ENGINE — per-operator semantics
# Each: holds / does-not-hold / missing-param-does-not-hold / wrong-type-does-not-hold.
# A rule built as an ALLOW guard under default-deny, so "holds" -> ALLOW(by rule id),
# everything else -> DENY(policy.default_deny). This proves the ALLOW-guard-with-missing
# -param case lands on default deny.
# ===========================================================================

def _guard_pack(operator, operand, *, default="deny"):
    return validate(
        _minimal_pack_dict(
            default=default,
            rules=[
                {"id": "guard", "rationale": "guarded allow", "tool": "act",
                 "when": {"p": {operator: operand}}, "effect": "ALLOW"},
            ],
        )
    )


def _decide_guard(operator, operand, params):
    pack = _guard_pack(operator, operand)
    return engine.decide(pack, "act", params)


def _assert_holds(operator, operand, params):
    r = _decide_guard(operator, operand, params)
    assert r.decision is Decision.ALLOW and r.rule_id == "guard", (operator, params)


def _assert_not_holds(operator, operand, params):
    # Falls through the ALLOW guard to default-deny.
    r = _decide_guard(operator, operand, params)
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY, (operator, params)


# --- max ---
def test_max_holds_does_not_hold_missing_wrong_type():
    _assert_holds("max", 1000, {"p": 1000})        # boundary: equal holds
    _assert_holds("max", 1000, {"p": 999})         # just under
    _assert_not_holds("max", 1000, {"p": 1001})    # just over
    _assert_not_holds("max", 1000, {})             # missing -> default deny (ALLOW guard never fires)
    _assert_not_holds("max", 1000, {"p": "999"})   # wrong type (string)
    _assert_not_holds("max", 1000, {"p": True})    # bool excluded even though True<=1000


# --- min ---
def test_min_holds_does_not_hold_missing_wrong_type():
    _assert_holds("min", 100, {"p": 100})          # boundary
    _assert_holds("min", 100, {"p": 101})
    _assert_not_holds("min", 100, {"p": 99})
    _assert_not_holds("min", 100, {})
    _assert_not_holds("min", 100, {"p": "200"})
    _assert_not_holds("min", 100, {"p": False})    # bool excluded


# --- one_of ---
def test_one_of_holds_does_not_hold_missing_type_aware():
    _assert_holds("one_of", ["a", "b", 3], {"p": "a"})
    _assert_holds("one_of", ["a", "b", 3], {"p": 3})
    _assert_not_holds("one_of", ["a", "b", 3], {"p": "c"})
    _assert_not_holds("one_of", ["a", "b", 3], {})
    # type-aware: param int 1 must NOT match a list that does not contain int 1.
    _assert_not_holds("one_of", ["1"], {"p": 1})    # 1 != "1"
    # type-aware bool/int: param True must not match list entry int 1.
    _assert_not_holds("one_of", [1], {"p": True})


# --- prefix_one_of ---
def test_prefix_one_of_holds_does_not_hold_missing_wrong_type():
    _assert_holds("prefix_one_of", ["/safe/", "/tmp/"], {"p": "/safe/file"})
    _assert_not_holds("prefix_one_of", ["/safe/"], {"p": "/etc/passwd"})
    _assert_not_holds("prefix_one_of", ["/safe/"], {})
    _assert_not_holds("prefix_one_of", ["/safe/"], {"p": 123})  # non-string


# --- domain_in ---
def test_domain_in_holds_does_not_hold_missing_wrong_type():
    _assert_holds("domain_in", ["example.com"], {"p": "alice@example.com"})
    _assert_holds("domain_in", ["example.com"], {"p": "alice@EXAMPLE.COM"})  # case-insensitive
    _assert_not_holds("domain_in", ["example.com"], {"p": "alice@evil.com"})
    _assert_not_holds("domain_in", ["example.com"], {"p": "no-at-sign"})     # no '@'
    _assert_not_holds("domain_in", ["example.com"], {"p": "a@b@example.com"})  # two '@'
    _assert_not_holds("domain_in", ["example.com"], {})
    _assert_not_holds("domain_in", ["example.com"], {"p": 5})  # non-string


# --- contains_keyword ---
def test_contains_keyword_holds_does_not_hold_missing():
    _assert_holds("contains_keyword", ["DROP"], {"p": "drop table t"})   # case-insensitive
    _assert_holds("contains_keyword", ["DROP"], {"p": "DROP   TABLE"})   # whitespace collapse
    _assert_not_holds("contains_keyword", ["DROP"], {"p": "SELECT * FROM t"})
    _assert_not_holds("contains_keyword", ["DROP"], {"p": "ALTERED"})    # token, not substring
    _assert_not_holds("contains_keyword", ["DROP"], {})                  # missing -> default deny


def test_contains_keyword_coerces_non_string():
    # Defensive Phase-1 coercion: a non-string param is str()'d, not crashed.
    _assert_not_holds("contains_keyword", ["DROP"], {"p": 12345})
    _assert_holds("contains_keyword", ["123"], {"p": 123})  # str(123) tokenizes to "123"


# --- not_contains_keyword (the negation trap) ---
def test_not_contains_keyword_present_holds_when_clean():
    _assert_holds("not_contains_keyword", ["DROP"], {"p": "SELECT * FROM t"})
    _assert_not_holds("not_contains_keyword", ["DROP"], {"p": "DROP TABLE t"})


def test_not_contains_keyword_missing_param_does_not_hold():
    # THE TRAP: a missing param must NOT satisfy "not contains" — it falls through
    # to default-deny, NOT to the ALLOW guard. Negation must not make absence match.
    _assert_not_holds("not_contains_keyword", ["DROP"], {})


# ===========================================================================
# ENGINE — conjunctive `when` (ALL constraints must hold)
# ===========================================================================

def test_multiple_constraints_all_must_hold():
    pack = validate(
        _minimal_pack_dict(
            rules=[
                {"id": "guard", "rationale": "two guards", "tool": "wire",
                 "when": {"amount": {"max": 1000}, "to": {"domain_in": ["example.com"]}},
                 "effect": "ALLOW"},
            ]
        )
    )
    # Both hold -> ALLOW.
    r = engine.decide(pack, "wire", {"amount": 500, "to": "a@example.com"})
    assert r.decision is Decision.ALLOW and r.rule_id == "guard"
    # One fails (amount over) -> fall to default deny.
    r = engine.decide(pack, "wire", {"amount": 5000, "to": "a@example.com"})
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY
    # One fails (missing domain param) -> fall to default deny.
    r = engine.decide(pack, "wire", {"amount": 500})
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


# ===========================================================================
# ENGINE — determinism (invariant 2): repeated decide is identical
# ===========================================================================

@pytest.mark.parametrize(
    "operator,operand,params",
    [
        ("max", 1000, {"p": 1000}),
        ("max", 1000, {"p": 1001}),
        ("max", 1000, {}),
        ("min", 100, {"p": 100}),
        ("one_of", ["a", 3], {"p": 3}),
        ("one_of", ["1"], {"p": 1}),
        ("prefix_one_of", ["/safe/"], {"p": "/safe/x"}),
        ("domain_in", ["example.com"], {"p": "a@example.com"}),
        ("contains_keyword", ["DROP"], {"p": "DROP TABLE"}),
        ("not_contains_keyword", ["DROP"], {}),
        ("not_contains_keyword", ["DROP"], {"p": "SELECT 1"}),
    ],
)
def test_determinism_repeated_decisions_identical(operator, operand, params):
    pack = _guard_pack(operator, operand)
    first = engine.decide(pack, "act", params)
    for _ in range(50):
        again = engine.decide(pack, "act", params)
        assert again.decision is first.decision
        assert again.rule_id == first.rule_id


def test_determinism_no_pack_repeated():
    first = engine.decide(None, "t", {"x": 1})
    for _ in range(50):
        again = engine.decide(None, "t", {"x": 1})
        assert again.decision is first.decision and again.rule_id == first.rule_id


# ===========================================================================
# LOADER
# ===========================================================================

def test_loader_loads_default_pack():
    pack = loader.load(loader.DEFAULT_PACK_PATH)
    assert isinstance(pack, Pack)
    assert pack.default == "deny"
    assert [r.id for r in pack.rules] == [
        "sql.deny_destructive",
        "sql.allow_other",
        "customers.allow_lookup",
        "math.allow_calculator",
        "email.deny_exfil_after_read",
        "email.allow_known_domains",
        # Phase 3 (ADR 0006): a counted RATE_LIMIT pair and an approval-gated tool.
        "refunds.rate_limit",
        "refunds.allow",
        "exports.require_approval",
    ]
    # The destructive-SQL rule's rationale states it is a documented-gap stopgap.
    deny_rule = pack.rules[0]
    assert "STOPGAP" in deny_rule.rationale.upper()
    assert deny_rule.when == {"sql": ("contains_keyword", ("DROP", "DELETE", "TRUNCATE", "ALTER"))}


def test_loader_malformed_yaml_raises(tmp_path):
    bad = tmp_path / "bad.yaml"
    bad.write_text("version: 1\n  bad: : indentation:\n   - [", encoding="utf-8")
    with pytest.raises(PolicyError):
        loader.load(bad)


def test_loader_valid_yaml_failing_schema_raises(tmp_path):
    # Parses fine as YAML, but version is wrong -> schema rejects -> PolicyError.
    # The rules list carries a fully valid rule so the version mismatch is the
    # ONLY violation — the test keeps catching its intended case even if other
    # validation rules change.
    p = tmp_path / "schema_fail.yaml"
    p.write_text(
        "version: 2\n"
        "default: deny\n"
        "rules:\n"
        "  - id: t.ok\n"
        "    rationale: valid rule, invalid version\n"
        "    tool: t\n"
        "    effect: ALLOW\n",
        encoding="utf-8",
    )
    with pytest.raises(PolicyError):
        loader.load(p)


def test_loader_non_dict_yaml_raises(tmp_path):
    p = tmp_path / "list.yaml"
    p.write_text("- a\n- b\n- c\n", encoding="utf-8")
    with pytest.raises(PolicyError):
        loader.load(p)


def test_loader_missing_file_raises(tmp_path):
    with pytest.raises(PolicyError):
        loader.load(tmp_path / "does_not_exist.yaml")


# ===========================================================================
# GATEWAY ADAPTER
# State hygiene: gateway._ACTIVE_PACK is module-level state, and conftest.py's
# autouse `configure_default_pack` fixture already snapshots it, configures the
# default pack for every test, and restores the previous value afterwards.
# WHY there is deliberately NO second autouse fixture here: a redundant inner
# snapshot/restore would capture the conftest-configured pack (not None) and
# mislead a future author into thinking _ACTIVE_PACK starts as None in this file.
# The contract is: every test here starts with the DEFAULT PACK configured; a test
# that needs a different posture (None or a custom pack) calls gateway.configure()
# explicitly in its own body, and conftest's restore cleans up after it.
# ===========================================================================


def test_gateway_unconfigured_denies_no_pack():
    gateway.configure(None)
    r = gateway.evaluate("anything", {"x": 1}, context=None)
    assert r.decision is Decision.DENY
    assert r.rule_id == RULE_NO_PACK


def test_gateway_configure_matches_engine_decide():
    pack = loader.load(loader.DEFAULT_PACK_PATH)
    gateway.configure(pack)
    tool, params = "execute_sql", {"sql": "DROP TABLE customers"}
    via_gateway = gateway.evaluate(tool, params, context=None)
    via_engine = engine.decide(pack, tool, params)
    assert via_gateway.decision is via_engine.decision
    assert via_gateway.rule_id == via_engine.rule_id


@pytest.mark.parametrize("context", [None, {}, {"trajectory": []}, [1, 2, 3], "anything", object()])
def test_gateway_context_does_not_affect_no_after_rules(context):
    # Since 2b (ADR 0004 §d), context is NOT ignored: a list context is extracted
    # as the trajectory and passed to engine.decide; any non-list context yields
    # trajectory=None (exact 2a behavior). The decision is still invariant here
    # because rules WITHOUT an `after` clause never read the trajectory — which
    # is precisely what this test pins for every context shape, list or not.
    gateway.configure(loader.load(loader.DEFAULT_PACK_PATH))
    r = gateway.evaluate("calculator", {"expression": "1+1"}, context)
    assert r.decision is Decision.ALLOW
    assert r.rule_id == "math.allow_calculator"


# ===========================================================================
# DEFAULT PACK — end-to-end behavior (ADR 0003 §e)
# ===========================================================================

@pytest.fixture()
def default_pack():
    return loader.load(loader.DEFAULT_PACK_PATH)


def test_default_pack_drop_table_denied(default_pack):
    r = engine.decide(default_pack, "execute_sql", {"sql": "DROP TABLE customers"})
    assert r.decision is Decision.DENY
    assert r.rule_id == "sql.deny_destructive"


def test_default_pack_select_allowed(default_pack):
    r = engine.decide(default_pack, "execute_sql", {"sql": "SELECT * FROM customers"})
    assert r.decision is Decision.ALLOW
    assert r.rule_id == "sql.allow_other"


def test_default_pack_lookup_allowed(default_pack):
    r = engine.decide(default_pack, "lookup_customer", {"customer_id": "C001"})
    assert r.decision is Decision.ALLOW
    assert r.rule_id == "customers.allow_lookup"


def test_default_pack_calculator_allowed(default_pack):
    r = engine.decide(default_pack, "calculator", {"expression": "350 * 1.15"})
    assert r.decision is Decision.ALLOW
    assert r.rule_id == "math.allow_calculator"


def test_default_pack_unknown_tool_denied(default_pack):
    # send_email became a KNOWN tool in 2b (ADR 0004), so a genuinely un-named tool is
    # used here to keep this test pinning the default-deny floor for unknown tools.
    r = engine.decide(default_pack, "delete_database", {"target": "all"})
    assert r.decision is Decision.DENY
    assert r.rule_id == RULE_DEFAULT_DENY


@pytest.mark.parametrize("verb", ["DELETE", "TRUNCATE", "ALTER"])
def test_default_pack_all_destructive_verbs_denied(default_pack, verb):
    r = engine.decide(default_pack, "execute_sql", {"sql": f"{verb} FROM customers"})
    assert r.decision is Decision.DENY
    assert r.rule_id == "sql.deny_destructive"


# ===========================================================================
# 2b SCHEMA — the `after` clause (ADR 0004 §e)
# ===========================================================================

def _after_rule_pack(after, **rule_overrides):
    """A valid pack whose single rule carries the given `after` clause."""
    rule = {
        "id": "r.after",
        "rationale": "trajectory-gated rule",
        "tool": "send_email",
        "after": after,
        "effect": "DENY",
    }
    rule.update(rule_overrides)
    return _minimal_pack_dict(rules=[rule])


def test_after_valid_clause_accepted_stores_bare_tool_name():
    pack = validate(_after_rule_pack({"tool": "lookup_customer"}))
    rule = pack.rules[0]
    # ADR 0004 §e: `after` is stored as the bare validated tool name (str), None when absent.
    assert rule.after == "lookup_customer"
    assert isinstance(rule.after, str)


def test_rule_without_after_has_none():
    # Every existing-style rule (no `after` key) must have Rule.after is None so it never
    # consults the trajectory (2a behavior preserved).
    pack = validate(_minimal_pack_dict())
    assert pack.rules[0].after is None


@pytest.mark.parametrize(
    "after",
    [
        "lookup_customer",            # non-dict: a bare string
        5,                            # non-dict: an int
        ["lookup_customer"],          # non-dict: a list
        [],                           # non-dict: an empty list
        {},                           # dict, but zero keys (no `tool`)
        {"reader": "lookup_customer"},  # single but UNKNOWN key
        {"tool": "lookup_customer", "x": 1},  # multi-key {tool, x}
        {"tool": ""},                 # empty `tool` string
        {"tool": None},               # non-string `tool`
        {"tool": 5},                  # non-string `tool`
        {"tool": ["lookup_customer"]},  # non-string `tool` (list)
        {"tool": "a", "tool2": "b"},  # multi-key, both unknown-ish
    ],
)
def test_after_rejection_classes(after):
    # Any malformed `after` rejects the WHOLE pack (ADR 0003 §c all-or-nothing, ADR 0004 §e).
    with pytest.raises(PolicyError):
        validate(_after_rule_pack(after))


# ===========================================================================
# 2b SCHEMA — the `domain_not_in` operand validation (ADR 0004 §f)
# ===========================================================================

def test_domain_not_in_valid_operand_accepted():
    raw = _minimal_pack_dict(
        rules=[
            {
                "id": "r.dni",
                "rationale": "ok",
                "tool": "send_email",
                "when": {"to": {"domain_not_in": ["internal.example.com"]}},
                "effect": "DENY",
            }
        ]
    )
    pack = validate(raw)
    # Validated identically to domain_in: list operand frozen to a tuple.
    assert pack.rules[0].when == {"to": ("domain_not_in", ("internal.example.com",))}


@pytest.mark.parametrize("operand", [[], "internal.example.com", 5, [1], [True], [None]])
def test_domain_not_in_bad_operand_rejected(operand):
    # Empty list, non-list, and non-string items all reject the whole pack — same as domain_in.
    raw = _minimal_pack_dict(
        rules=[
            {
                "id": "r.dni",
                "rationale": "ok",
                "tool": "send_email",
                "when": {"to": {"domain_not_in": operand}},
                "effect": "DENY",
            }
        ]
    )
    with pytest.raises(PolicyError):
        validate(raw)


# ===========================================================================
# 2b ENGINE — `_after_holds` via decide (ADR 0004 §e)
# A DENY rule guarded only by `after` (no `when`): when `after` holds -> DENY by rule id;
# when it does not -> falls through to default-deny (policy.default_deny). The taint
# tool is lookup_customer; the gated tool is send_email.
# ===========================================================================

def _after_only_pack():
    return validate(_after_rule_pack({"tool": "lookup_customer"}))


def _rec(tool, decision):
    """A minimal well-formed trajectory record (the audit-record shape: {tool, decision, ...})."""
    return {"tool": tool, "params": {}, "decision": decision, "rule": "x"}


def _decide_after(trajectory):
    return engine.decide(_after_only_pack(), "send_email", {"to": "x@evil.com"}, trajectory)


def test_after_with_none_trajectory_does_not_match():
    # after present + trajectory None -> after does-not-hold -> rule falls through.
    r = _decide_after(None)
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


def test_after_with_empty_trajectory_does_not_match():
    r = _decide_after([])
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


def test_after_with_allowed_matching_record_matches():
    r = _decide_after([_rec("lookup_customer", "ALLOW")])
    assert r.decision is Decision.DENY and r.rule_id == "r.after"


def test_after_with_denied_matching_record_only_does_not_match():
    # ALLOW-only pinned (ADR 0004 §e open-call (a)): a DENYed read never executed, no data
    # was read, so it must NOT taint a later send.
    r = _decide_after([_rec("lookup_customer", "DENY")])
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


def test_after_with_different_tool_record_does_not_match():
    r = _decide_after([_rec("calculator", "ALLOW")])
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


# ===========================================================================
# 2b ENGINE — TOTALITY probes: arbitrary junk in the trajectory (ADR 0004 §e)
# The scan must be total over whatever the list contains — junk must NOT crash and
# must NOT match (isinstance gate + .get with safe defaults, never entry["tool"]).
# ===========================================================================

_JUNK_TRAJECTORY = [
    42,                              # non-dict: int
    "string",                        # non-dict: str
    None,                            # non-dict: None
    object(),                        # non-dict: arbitrary object
    {"no_tool_field": 1},            # dict missing both tool and decision
    {"tool": "lookup_customer"},     # dict missing decision
    {"decision": "ALLOW"},           # dict missing tool
]


def test_after_totality_pure_junk_does_not_crash_and_does_not_match():
    # No well-formed ALLOWed lookup_customer record -> must not match, must not raise.
    r = _decide_after(list(_JUNK_TRAJECTORY))
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


def test_after_totality_junk_plus_real_record_matches():
    # Same junk PLUS one well-formed ALLOW record -> junk skipped, real record found -> match.
    r = _decide_after(list(_JUNK_TRAJECTORY) + [_rec("lookup_customer", "ALLOW")])
    assert r.decision is Decision.DENY and r.rule_id == "r.after"


# ===========================================================================
# 2b ENGINE — `domain_not_in` semantics (ADR 0004 §f)
# A DENY guard on send_email keyed only on `to`'s domain_not_in: holds -> DENY by rule id,
# does-not-hold -> falls to default-deny. (No `after`, so the trajectory is irrelevant.)
# ===========================================================================

def _domain_not_in_pack():
    return validate(
        _minimal_pack_dict(
            rules=[
                {
                    "id": "dni.guard",
                    "rationale": "deny non-internal",
                    "tool": "send_email",
                    "when": {"to": {"domain_not_in": ["internal.example.com"]}},
                    "effect": "DENY",
                }
            ]
        )
    )


def _decide_dni(params):
    return engine.decide(_domain_not_in_pack(), "send_email", params)


def test_domain_not_in_holds_for_external_domain():
    r = _decide_dni({"to": "spy@evil.com"})
    assert r.decision is Decision.DENY and r.rule_id == "dni.guard"


def test_domain_not_in_does_not_hold_for_listed_domain_case_insensitive():
    # Listed domain -> NOT in the negation set -> does-not-hold -> falls through.
    r = _decide_dni({"to": "alice@internal.example.com"})
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY
    r = _decide_dni({"to": "alice@INTERNAL.EXAMPLE.COM"})  # case-insensitive
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


@pytest.mark.parametrize(
    "params",
    [
        {"to": "a@b@evil.com"},   # two '@' -> malformed -> does NOT hold (not `not domain_in`)
        {"to": "no-at-sign"},     # zero '@'
        {"to": ""},               # empty string
        {"to": 5},                # non-string
        {},                       # missing param (chokepoint) -> does NOT hold
    ],
)
def test_domain_not_in_malformed_does_not_hold(params):
    # THE TRAP (ADR 0004 §f): malformed/missing must NOT satisfy domain_not_in — it has no
    # parseable domain, so the honest answer is False. Falls through to default-deny.
    r = _decide_dni(params)
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


# ===========================================================================
# 2b REGRESSION — the additive signature reproduces 2a byte-for-byte (ADR 0004 §c)
# ===========================================================================

def test_decide_still_callable_with_no_trajectory_arg():
    # The signature is additive: every 2a call site decide(pack, tool, params) works
    # positionally and unchanged.
    pack = validate(_minimal_pack_dict())
    r = engine.decide(pack, "calculator", {"x": 1})
    assert r.decision is Decision.ALLOW and r.rule_id == "demo.allow_calc"


@pytest.mark.parametrize(
    "tool,params",
    [
        ("calculator", {"x": 1}),
        ("execute_sql", {"sql": "DROP TABLE t"}),
        ("execute_sql", {"sql": "SELECT 1"}),
        ("unknown_tool", {}),
    ],
)
def test_2a_pack_ignores_trajectory_none_vs_junk(tool, params):
    # A pack with NO `after` rule must decide IDENTICALLY for trajectory=None vs an
    # arbitrary junk trajectory — proving 2a rules never read the trajectory (ADR 0004 §c).
    pack = loader.load(loader.DEFAULT_PACK_PATH)  # default pack's non-email rules have no `after`
    junk = list(_JUNK_TRAJECTORY) + [_rec("lookup_customer", "ALLOW"), _rec("anything", "DENY")]
    without = engine.decide(pack, tool, params)
    with_none = engine.decide(pack, tool, params, None)
    with_junk = engine.decide(pack, tool, params, junk)
    assert without.decision is with_none.decision is with_junk.decision
    assert without.rule_id == with_none.rule_id == with_junk.rule_id


# ===========================================================================
# 2b DEFAULT PACK — the proof-of-worth pair (ADR 0004): same call, two histories
# ===========================================================================

def test_default_pack_partner_send_allowed_with_empty_trajectory(default_pack):
    # No lookup_customer earlier -> exfil DENY does-not-hold -> falls to domain_in ALLOW.
    r = engine.decide(default_pack, "send_email",
                      {"to": "ceo@partner.example.com", "subject": "s", "body": "b"}, [])
    assert r.decision is Decision.ALLOW and r.rule_id == "email.allow_known_domains"


def test_default_pack_partner_send_denied_after_allowed_read(default_pack):
    # SAME call, but an ALLOWed lookup_customer is now earlier in the run -> exfil DENY fires.
    tainted = [_rec("lookup_customer", "ALLOW")]
    r = engine.decide(default_pack, "send_email",
                      {"to": "ceo@partner.example.com", "subject": "s", "body": "b"}, tainted)
    assert r.decision is Decision.DENY and r.rule_id == "email.deny_exfil_after_read"


def test_default_pack_internal_send_allowed_even_when_tainted(default_pack):
    # internal.example.com is the one domain NOT in the exfil set -> domain_not_in
    # does-not-hold -> exfil rule does not match even with the tainted trajectory ->
    # falls to email.allow_known_domains.
    tainted = [_rec("lookup_customer", "ALLOW")]
    r = engine.decide(default_pack, "send_email", {"to": "team@internal.example.com"}, tainted)
    assert r.decision is Decision.ALLOW and r.rule_id == "email.allow_known_domains"


def test_default_pack_evil_send_denied_by_floor_not_exfil(default_pack):
    # No read earlier, recipient not allowlisted -> exfil rule does-not-hold (after fails),
    # allow rule does-not-hold (domain not listed) -> DENIED BY THE FLOOR, not the exfil rule.
    r = engine.decide(default_pack, "send_email", {"to": "spy@evil.com"}, [])
    assert r.decision is Decision.DENY and r.rule_id == RULE_DEFAULT_DENY


# ===========================================================================
# 2b DETERMINISM (invariant 2): 50 repeats with a fixed tainted trajectory
# ===========================================================================

def test_2b_determinism_repeated_decisions_identical(default_pack):
    tainted = list(_JUNK_TRAJECTORY) + [_rec("lookup_customer", "ALLOW")]
    params = {"to": "ceo@partner.example.com", "subject": "s", "body": "b"}
    first = engine.decide(default_pack, "send_email", params, tainted)
    assert first.decision is Decision.DENY and first.rule_id == "email.deny_exfil_after_read"
    for _ in range(50):
        again = engine.decide(default_pack, "send_email", params, tainted)
        assert again.decision is first.decision
        assert again.rule_id == first.rule_id
