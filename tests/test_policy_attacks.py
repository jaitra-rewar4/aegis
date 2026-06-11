"""
test_policy_attacks.py — adversarial attack suite for the Phase 2 policy engine.

Red-team charter: try to make Aegis fail on the 2a policy engine.
Coverage: yaml injection, partial-load, reserved-namespace minting, shadowing,
operator boundary abuse, ALLOW-guard omission, determinism under hostility,
and loop integration proofs.

DOES NOT duplicate coverage already in test_policy_engine.py (read before
writing). Covers adversarial scenarios not present there.

For each attack:
  - Scenario is named in the class/test docstring.
  - Expected Aegis decision is stated in the assertion.
  - A divergence (attack succeeds) is a bug: the test documents exactly what
    slipped, the decision it gave, and the decision it should have given.

ADR refs: ADR 0003 §c (schema), §d (first-match-wins), §f (markers), §b
(purity / configure).
"""

from __future__ import annotations

import os
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

import core.gateway as gw
from core import gateway
from core.decision import Decision
from core.loop import run_loop
from demos.tools import TOOL_REGISTRY, TOOL_SCHEMAS
from policy import engine, loader
from policy.engine import RULE_DEFAULT_DENY, RULE_NO_PACK
from policy.schema import Pack, PolicyError, validate


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _stub_turns(*turns):
    """Return a model_turn_fn that replays the given turns in order."""
    turns_list = list(turns)
    idx = {"n": 0}

    def _fn(_messages):
        if idx["n"] < len(turns_list):
            result = turns_list[idx["n"]]
        else:
            result = [{"type": "text", "text": "Done."}]
        idx["n"] += 1
        return result

    return _fn


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
# ATTACK 1 — yaml.safe_load proof (ADR 0003 §user-decided constraints)
#
# Scenario: an attacker crafts a pack file using YAML tags that would cause
# yaml.load() to execute arbitrary Python code. Under yaml.safe_load() this
# must raise a YAML parse error (loader.PolicyError), and the os.system spy
# must never be called.
#
# Expected: PolicyError raised; no side-effect executed.
# ===========================================================================

class TestYamlSafeLoadProof:
    """Prove that YAML code-construction tags are dead on arrival."""

    def test_python_object_apply_tag_raises_policy_error(self, tmp_path):
        """
        !!python/object/apply:os.system ["echo pwned"] would execute a shell
        command under yaml.load().  Under yaml.safe_load() it must be rejected
        with a PolicyError — and os.system must never be called.

        Expected: PolicyError; no shell execution.
        """
        evil_pack = tmp_path / "evil1.yaml"
        # Write a YAML document with the arbitrary-code-execution tag.
        evil_pack.write_text(
            '!!python/object/apply:os.system ["echo pwned"]\n',
            encoding="utf-8",
        )

        side_effect_file = tmp_path / "pwned.txt"

        # Spy: if os.system actually ran, it might write a file; we also patch
        # it directly to be sure we detect any call.
        with patch("os.system") as spy:
            with pytest.raises(PolicyError):
                loader.load(evil_pack)
            spy.assert_not_called()

        # Belt-and-suspenders: the side-effect file must not exist.
        assert not side_effect_file.exists(), (
            "BUG: YAML code-construction tag executed despite yaml.safe_load!"
        )

    def test_python_object_tag_raises_policy_error(self, tmp_path):
        """
        !!python/object:builtins.dict {} would construct an arbitrary Python
        object under yaml.load().  Under yaml.safe_load() it must be rejected.

        Expected: PolicyError.
        """
        evil_pack = tmp_path / "evil2.yaml"
        evil_pack.write_text(
            "!!python/object:builtins.dict {}\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyError):
            loader.load(evil_pack)

    def test_yaml_safe_load_cannot_construct_arbitrary_class(self, tmp_path):
        """
        A YAML document that attempts to construct a custom class via
        !!python/object must be rejected, not partially loaded.

        Expected: PolicyError; pack never reaches schema validation.
        """
        evil_pack = tmp_path / "evil3.yaml"
        evil_pack.write_text(
            "!!python/object:pathlib.Path\nargs: ['/etc/passwd']\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyError):
            loader.load(evil_pack)

    def test_safe_load_rejects_nested_code_tag_in_rule(self, tmp_path):
        """
        A pack that is structurally valid at the top level but embeds a YAML
        code tag inside the rules list must also be rejected.

        Expected: PolicyError; the whole pack is rejected.
        """
        evil_pack = tmp_path / "evil4.yaml"
        # Valid YAML structure but the rationale field uses a code-tag.
        evil_pack.write_text(
            "version: 1\n"
            "default: deny\n"
            "rules:\n"
            "  - id: bad.rule\n"
            "    rationale: !!python/object/apply:os.system [\"echo pwned\"]\n"
            "    tool: calculator\n"
            "    effect: ALLOW\n",
            encoding="utf-8",
        )
        with patch("os.system") as spy:
            with pytest.raises(PolicyError):
                loader.load(evil_pack)
            spy.assert_not_called()


# ===========================================================================
# ATTACK 2 — Partial-load forbidden (ADR 0003 §c all-or-nothing)
#
# Scenario: a pack with 3 valid rules and 1 unknown-operator rule is loaded.
# The loader must reject the WHOLE pack (PolicyError). After the failed load
# attempt, configure() must never have been called — the gateway remains in
# its pre-load state (policy.no_pack or the autouse default).
#
# Expected: PolicyError; pack has no effect on the gateway.
# ===========================================================================

class TestPartialLoadForbidden:
    """Prove a malformed pack takes effect as nothing, not as partial rules."""

    def test_pack_with_one_bad_rule_rejected_entirely(self, tmp_path):
        """
        3 valid rules + 1 unknown-operator rule -> PolicyError.

        Expected: PolicyError from loader.load(); no pack loaded.
        """
        bad_pack = tmp_path / "partial.yaml"
        bad_pack.write_text(
            "version: 1\n"
            "default: deny\n"
            "rules:\n"
            "  - id: r.one\n"
            "    rationale: first valid rule\n"
            "    tool: calculator\n"
            "    effect: ALLOW\n"
            "  - id: r.two\n"
            "    rationale: second valid rule\n"
            "    tool: lookup_customer\n"
            "    effect: ALLOW\n"
            "  - id: r.three\n"
            "    rationale: third valid rule\n"
            "    tool: execute_sql\n"
            "    effect: ALLOW\n"
            "  - id: r.bad\n"
            "    rationale: bad rule with unknown operator\n"
            "    tool: wire_transfer\n"
            "    when:\n"
            "      amount:\n"
            "        fuzzy_match: 1000\n"  # unknown operator
            "    effect: DENY\n",
            encoding="utf-8",
        )
        with pytest.raises(PolicyError):
            loader.load(bad_pack)

    def test_failed_load_leaves_gateway_unconfigured(self, tmp_path):
        """
        After a failed load attempt, configure() is never called.
        The gateway remains in its existing state (here: deconfigure to None
        explicitly to prove no_pack behavior after a load failure).

        Expected: gateway.evaluate returns DENY/policy.no_pack after failed load.
        """
        bad_pack = tmp_path / "partial2.yaml"
        bad_pack.write_text(
            "version: 1\n"
            "default: deny\n"
            "rules:\n"
            "  - id: r.good\n"
            "    rationale: would allow calculator\n"
            "    tool: calculator\n"
            "    effect: ALLOW\n"
            "  - id: r.bad\n"
            "    rationale: unknown operator\n"
            "    tool: calculator\n"
            "    when:\n"
            "      p:\n"
            "        not_a_real_operator: 5\n"
            "    effect: DENY\n",
            encoding="utf-8",
        )

        # Explicitly deconfigure to probe the no_pack state after failure.
        gw.configure(None)

        # Attempt to load the bad pack — must raise, must NOT call configure.
        with pytest.raises(PolicyError):
            pack = loader.load(bad_pack)
            # If load somehow returned, we'd configure here — but it must raise.
            gw.configure(pack)  # never reached

        # Gateway must still be unconfigured: evaluate returns policy.no_pack.
        result = gw.evaluate("calculator", {}, context=None)
        assert result.decision is Decision.DENY
        assert result.rule_id == RULE_NO_PACK, (
            f"BUG: failed pack load leaked rules into the gateway! "
            f"Got rule_id={result.rule_id!r} — expected {RULE_NO_PACK!r}"
        )

    def test_partial_load_is_all_or_nothing_not_three_of_four(self, tmp_path):
        """
        After a rejected pack, NOT EVEN THE 3 VALID RULES take effect.
        The gateway must not partially honour any rule from the bad pack.

        Expected: DENY/policy.no_pack for all three tools that had valid rules.
        """
        bad_pack = tmp_path / "partial3.yaml"
        bad_pack.write_text(
            "version: 1\n"
            "default: deny\n"
            "rules:\n"
            "  - id: r.calc\n"
            "    rationale: would allow calculator\n"
            "    tool: calculator\n"
            "    effect: ALLOW\n"
            "  - id: r.lookup\n"
            "    rationale: would allow lookup\n"
            "    tool: lookup_customer\n"
            "    effect: ALLOW\n"
            "  - id: r.bad\n"
            "    rationale: effect value unsupported in 2a\n"
            "    tool: execute_sql\n"
            "    effect: REQUIRE_APPROVAL\n",  # rejected effect
            encoding="utf-8",
        )

        gw.configure(None)

        with pytest.raises(PolicyError):
            pack = loader.load(bad_pack)
            gw.configure(pack)

        # None of the three tools should be allowed — the whole pack was rejected.
        for tool in ("calculator", "lookup_customer", "execute_sql"):
            result = gw.evaluate(tool, {}, context=None)
            assert result.decision is Decision.DENY
            assert result.rule_id == RULE_NO_PACK, (
                f"BUG: partial pack took effect for tool {tool!r}! "
                f"rule_id={result.rule_id!r}"
            )


# ===========================================================================
# ATTACK 3 — Reserved-namespace minting (ADR 0003 §c/§f)
#
# Scenario: a pack attempts to mint rule ids in the reserved aegis.* and
# policy.* namespaces.  These must be rejected at load.
# Ids that merely LOOK similar (aegisx.*, my.aegis.*) must be accepted —
# the check must be an exact prefix match, not substring paranoia.
#
# Expected: reserved-prefix ids -> PolicyError; look-alike ids -> accepted.
# ===========================================================================

class TestReservedNamespaceMinting:
    """Prove reserved namespaces cannot be minted by a pack."""

    @pytest.mark.parametrize("rule_id", [
        "aegis.audit_unavailable",
        "aegis.x",
        "aegis.",
        "aegis.anything.at.all",
        "policy.no_pack",
        "policy.default_deny",
        "policy.default_allow",
        "policy.x",
        "policy.",
        "policy.anything",
    ])
    def test_reserved_id_rejected(self, rule_id):
        """
        ids in the aegis.* and policy.* namespaces must be rejected at load.

        Expected: PolicyError for any reserved-prefix id.
        """
        raw = _minimal_pack_dict(
            rules=[{"id": rule_id, "rationale": "trying to impersonate engine",
                    "tool": "t", "effect": "ALLOW"}]
        )
        # A non-raise here means a pack minted a reserved id — blurring the
        # boundary between pack rules and engine/operational markers
        # (ADR 0003 §c/§f). pytest.raises reports DID NOT RAISE in that case.
        with pytest.raises(PolicyError, match="reserved"):
            validate(raw)

    @pytest.mark.parametrize("rule_id", [
        "aegisx.y",
        "policyx.y",
        "my.aegis.z",
        "notaegis.test",
        "the.policy.holds",
        "aegis_extended.rule",
        "policy_check.allow",
        "xaegis.anything",
    ])
    def test_look_alike_ids_accepted(self, rule_id):
        """
        ids that merely LOOK SIMILAR to reserved prefixes must be accepted.
        The prefix check must be exact ("aegis." / "policy."), not substring.

        Expected: no error; pack validates successfully.
        """
        raw = _minimal_pack_dict(
            rules=[{"id": rule_id, "rationale": "legitimate id that resembles a prefix",
                    "tool": "t", "effect": "ALLOW"}]
        )
        pack = validate(raw)
        assert pack.rules[0].id == rule_id, (
            f"BUG: id {rule_id!r} was rejected as if it were a reserved prefix — "
            "substring paranoia detected; only exact 'aegis.' and 'policy.' prefixes "
            "should be reserved."
        )


# ===========================================================================
# ATTACK 4 — Shadowing attack (first-match-wins abuse)
#
# Scenario: the pack author places a broad ALLOW before a DENY for the same
# tool.  Per ADR 0003 §d (first-match-wins in file order), the ALLOW fires
# even for inputs the DENY was intended to block.  This is the documented
# sharp edge of first-match-wins (visible-on-the-page author mistake).
# The test documents it: the ALLOW fires AND the reverse order DENYs.
#
# Expected (broad-allow-first): ALLOW / "broad_allow"
# Expected (deny-first):        DENY  / "deny_drop"
# ===========================================================================

class TestShadowingAttack:
    """Document the first-match-wins sharp edge: order controls outcome."""

    def test_broad_allow_above_deny_shadows_the_deny(self):
        """
        Author mistake: a tool-wide ALLOW placed above a more-specific DENY.
        The ALLOW fires, the DENY is unreachable — visible-on-the-page risk
        (ADR 0003 §d Consequences).

        Expected: ALLOW with rule id "broad_allow".
        This IS the documented behavior; document it, do not suppress it.
        """
        pack = validate({
            "version": 1,
            "default": "deny",
            "rules": [
                {"id": "broad_allow", "rationale": "too broad — shadows the deny below",
                 "tool": "execute_sql", "effect": "ALLOW"},
                {"id": "deny_drop", "rationale": "this deny can never fire",
                 "tool": "execute_sql",
                 "when": {"sql": {"contains_keyword": ["DROP"]}},
                 "effect": "DENY"},
            ],
        })
        result = engine.decide(pack, "execute_sql", {"sql": "DROP TABLE customers"})
        # ADR 0003 §d: first matching rule wins; the broad ALLOW fires.
        assert result.decision is Decision.ALLOW, (
            "Unexpected: the broad ALLOW did not shadow the DENY. "
            "If the engine now has DENY-override semantics, update the ADR and test."
        )
        assert result.rule_id == "broad_allow", (
            f"Expected rule 'broad_allow' to fire, got {result.rule_id!r}."
        )

    def test_deny_above_allow_correctly_blocks(self):
        """
        Correct order: the DENY is placed above the broad ALLOW.
        The DENY fires for destructive SQL; the ALLOW is unreachable for it.

        Expected: DENY with rule id "deny_drop".
        """
        pack = validate({
            "version": 1,
            "default": "deny",
            "rules": [
                {"id": "deny_drop", "rationale": "DENY placed first — correct",
                 "tool": "execute_sql",
                 "when": {"sql": {"contains_keyword": ["DROP"]}},
                 "effect": "DENY"},
                {"id": "broad_allow", "rationale": "ALLOW after deny — unreachable for DROP",
                 "tool": "execute_sql", "effect": "ALLOW"},
            ],
        })
        result = engine.decide(pack, "execute_sql", {"sql": "DROP TABLE customers"})
        assert result.decision is Decision.DENY
        assert result.rule_id == "deny_drop"

    def test_reverse_order_allows_benign_sql(self):
        """
        With DENY first, benign SQL falls through to the ALLOW.

        Expected: ALLOW with rule id "broad_allow".
        """
        pack = validate({
            "version": 1,
            "default": "deny",
            "rules": [
                {"id": "deny_drop",
                 "rationale": "DENY for destructive SQL only",
                 "tool": "execute_sql",
                 "when": {"sql": {"contains_keyword": ["DROP"]}},
                 "effect": "DENY"},
                {"id": "broad_allow",
                 "rationale": "ALLOW everything else on execute_sql",
                 "tool": "execute_sql", "effect": "ALLOW"},
            ],
        })
        result = engine.decide(pack, "execute_sql", {"sql": "SELECT * FROM t"})
        assert result.decision is Decision.ALLOW
        assert result.rule_id == "broad_allow"


# ===========================================================================
# ATTACK 5 — Operator boundary abuse (ADR 0003 §c operator semantics)
#
# Scenario: probe operator edge cases not in test_policy_engine.py — exact
# boundary equality, float/int cross, bool smuggling against max, huge strings
# against contains_keyword, one_of type-confusion, domain_in malformed input,
# case-insensitive domain match.
#
# Expected: each case asserted below.
# ===========================================================================

class TestOperatorBoundaryAbuse:
    """Edge-case operator probes to find semantic surprises."""

    def _pack_with_guard(self, operator, operand, *, default="deny"):
        """Build a pack with one ALLOW guard on param 'p' for tool 'act'."""
        return validate(_minimal_pack_dict(
            default=default,
            rules=[
                {"id": "guard", "rationale": "guarded allow", "tool": "act",
                 "when": {"p": {operator: operand}}, "effect": "ALLOW"},
            ],
        ))

    # --- max boundary: exact equal holds, just over does not ---

    def test_max_exact_boundary_holds(self):
        """param == operand exactly must HOLD for max.

        Expected: ALLOW (param == 50, operand == 50).
        """
        pack = self._pack_with_guard("max", 50)
        result = engine.decide(pack, "act", {"p": 50})
        assert result.decision is Decision.ALLOW
        assert result.rule_id == "guard"

    def test_max_one_over_boundary_does_not_hold(self):
        """param == operand + 1 must NOT hold for max.

        Expected: DENY/default_deny (param == 51, operand == 50).
        """
        pack = self._pack_with_guard("max", 50)
        result = engine.decide(pack, "act", {"p": 51})
        assert result.decision is Decision.DENY
        assert result.rule_id == RULE_DEFAULT_DENY

    def test_max_float_int_cross_holds(self):
        """float param 50.0 against int operand 50 must hold (both real numbers).

        Expected: ALLOW (50.0 <= 50 is True in Python float/int comparison).
        """
        pack = self._pack_with_guard("max", 50)
        result = engine.decide(pack, "act", {"p": 50.0})
        assert result.decision is Decision.ALLOW
        assert result.rule_id == "guard"

    def test_max_bool_true_must_not_hold(self):
        """bool param True against max: 1 must NOT hold — bool excluded.

        WHY: bool is a subclass of int, so True==1 in arithmetic. But the
        engine's _is_real_number excludes bool explicitly (ADR 0003 §c:
        a bool is not a numeric amount). bool param must not satisfy max.

        Expected: DENY/default_deny (param True, operand 1).
        """
        pack = self._pack_with_guard("max", 1)
        result = engine.decide(pack, "act", {"p": True})
        assert result.decision is Decision.DENY, (
            "BUG: bool True satisfied max:1 constraint — bool exclusion broken!"
        )
        assert result.rule_id == RULE_DEFAULT_DENY

    def test_max_bool_false_must_not_hold(self):
        """bool param False against max: 1 must NOT hold.

        Expected: DENY/default_deny (param False, operand 1, bool excluded).
        """
        pack = self._pack_with_guard("max", 1)
        result = engine.decide(pack, "act", {"p": False})
        assert result.decision is Decision.DENY
        assert result.rule_id == RULE_DEFAULT_DENY

    # --- contains_keyword: huge strings (no length short-circuit) ---

    def test_contains_keyword_huge_string_still_evaluated(self):
        """A huge string containing DROP must still DENY — no length short-circuit.

        Expected: DENY/guard (the keyword is present in the huge string).
        """
        # Build a pack that DENYs if contains_keyword includes "DROP".
        pack = validate(_minimal_pack_dict(
            default="allow",
            rules=[
                {"id": "deny_kw",
                 "rationale": "deny when keyword present",
                 "tool": "act",
                 "when": {"p": {"contains_keyword": ["DROP"]}},
                 "effect": "DENY"},
            ],
        ))
        big = ("SELECT 1; " * 10000) + "DROP TABLE t"
        result = engine.decide(pack, "act", {"p": big})
        assert result.decision is Decision.DENY
        assert result.rule_id == "deny_kw"

    def test_contains_keyword_huge_string_without_keyword_allows(self):
        """A huge string NOT containing the keyword must not trigger the DENY.

        Expected: ALLOW/default_allow (keyword absent in huge string).
        """
        pack = validate(_minimal_pack_dict(
            default="allow",
            rules=[
                {"id": "deny_kw",
                 "rationale": "deny when keyword present",
                 "tool": "act",
                 "when": {"p": {"contains_keyword": ["DROP"]}},
                 "effect": "DENY"},
            ],
        ))
        big = "SELECT 1; " * 10000
        result = engine.decide(pack, "act", {"p": big})
        assert result.decision is Decision.ALLOW

    # --- one_of type-confusion ---

    def test_one_of_int_vs_string_does_not_match(self):
        """int param 1 must NOT match a list entry "1" (string).

        Expected: DENY/default_deny (type mismatch: 1 != "1").
        """
        pack = self._pack_with_guard("one_of", ["1", "2"])
        result = engine.decide(pack, "act", {"p": 1})
        assert result.decision is Decision.DENY, (
            "BUG: int 1 matched string '1' in one_of — type-aware equality broken!"
        )

    def test_one_of_true_vs_int_one_does_not_match(self):
        """bool True must NOT match int 1 in one_of (type-aware equality).

        Expected: DENY/default_deny (type(True) is bool, not int).
        """
        pack = self._pack_with_guard("one_of", [1, 2, 3])
        result = engine.decide(pack, "act", {"p": True})
        assert result.decision is Decision.DENY, (
            "BUG: bool True matched int 1 in one_of — bool/int type confusion!"
        )

    def test_one_of_exact_int_match(self):
        """int param 1 must match int 1 in the list.

        Expected: ALLOW (same type, same value).
        """
        pack = self._pack_with_guard("one_of", [1, 2, 3])
        result = engine.decide(pack, "act", {"p": 1})
        assert result.decision is Decision.ALLOW
        assert result.rule_id == "guard"

    # --- domain_in: malformed input ---

    def test_domain_in_two_at_signs_does_not_hold(self):
        """Email with two @ signs ("a@b@evil.com") must NOT hold for domain_in.

        Expected: DENY/default_deny (exactly one @ required).
        """
        pack = self._pack_with_guard("domain_in", ["evil.com"])
        result = engine.decide(pack, "act", {"p": "a@b@evil.com"})
        assert result.decision is Decision.DENY, (
            "BUG: malformed email 'a@b@evil.com' satisfied domain_in — "
            "the two-@ rejection is broken!"
        )

    def test_domain_in_no_at_sign_does_not_hold(self):
        """Email with no @ sign must NOT hold for domain_in.

        Expected: DENY/default_deny.
        """
        pack = self._pack_with_guard("domain_in", ["evil.com"])
        result = engine.decide(pack, "act", {"p": "noemail.evil.com"})
        assert result.decision is Decision.DENY

    def test_domain_in_uppercase_domain_matches_case_insensitive(self):
        """domain_in check is case-insensitive.

        "user@EVIL.com" against allowlist ["evil.com"] must HOLD.

        Expected: ALLOW (domain "EVIL.com".lower() == "evil.com").
        """
        pack = self._pack_with_guard("domain_in", ["evil.com"])
        result = engine.decide(pack, "act", {"p": "user@EVIL.com"})
        assert result.decision is Decision.ALLOW, (
            "BUG: domain_in case-insensitive match failed for 'user@EVIL.com' "
            "against ['evil.com']!"
        )
        assert result.rule_id == "guard"

    def test_domain_in_mixed_case_allowlist_matches(self):
        """domain_in allowlist entry is also case-folded.

        "user@example.com" against allowlist ["Example.COM"] must HOLD.

        Expected: ALLOW (both sides lowercased).
        """
        pack = self._pack_with_guard("domain_in", ["Example.COM"])
        result = engine.decide(pack, "act", {"p": "user@example.com"})
        assert result.decision is Decision.ALLOW
        assert result.rule_id == "guard"


# ===========================================================================
# ATTACK 6 — ALLOW-guard omission attack (ADR 0003 §c missing-param semantics)
#
# Scenario: a pack allows "wire_transfer" only when amount max: 1000.
#   (a) Call with NO amount param -> must DENY (omission cannot unlock ALLOW).
#   (b) Call with amount "9999999" (string, wrong type) -> must DENY.
#   (c) Call with amount 999 (valid) -> must ALLOW.
#
# WHY this attack matters: if "missing param -> vacuously true", an attacker
# omits the amount to bypass the cap and execute an unbounded transfer.
#
# Expected: (a) DENY/default_deny, (b) DENY/default_deny, (c) ALLOW/guard.
# ===========================================================================

class TestAllowGuardOmissionAttack:
    """Prove that omitting a guarded param cannot unlock an ALLOW rule."""

    @pytest.fixture()
    def wire_pack(self):
        """A pack that allows wire_transfer only when amount max: 1000."""
        return validate({
            "version": 1,
            "default": "deny",
            "rules": [
                {
                    "id": "wire.allow_small",
                    "rationale": "allow small wire transfers only",
                    "tool": "wire_transfer",
                    "when": {"amount": {"max": 1000}},
                    "effect": "ALLOW",
                }
            ],
        })

    def test_missing_amount_denies(self, wire_pack):
        """No amount param -> DENY (omission cannot satisfy the ALLOW guard).

        Expected: DENY/policy.default_deny (the ALLOW rule did not match,
        fallthrough to default:deny).
        """
        result = engine.decide(wire_pack, "wire_transfer", {})
        assert result.decision is Decision.DENY, (
            "BUG: missing amount param unlocked the ALLOW guard — "
            "a call with no amount was permitted an unbounded wire_transfer!"
        )
        assert result.rule_id == RULE_DEFAULT_DENY, (
            f"Expected {RULE_DEFAULT_DENY!r}, got {result.rule_id!r}"
        )

    def test_string_amount_denies(self, wire_pack):
        """amount='9999999' (string) -> DENY (wrong type does not hold for max).

        Expected: DENY/policy.default_deny.
        """
        result = engine.decide(wire_pack, "wire_transfer", {"amount": "9999999"})
        assert result.decision is Decision.DENY, (
            "BUG: string amount '9999999' satisfied max:1000 — "
            "type check on numeric operator broken!"
        )
        assert result.rule_id == RULE_DEFAULT_DENY

    def test_valid_amount_allows(self, wire_pack):
        """amount=999 (int, within cap) -> ALLOW.

        Expected: ALLOW/wire.allow_small.
        """
        result = engine.decide(wire_pack, "wire_transfer", {"amount": 999})
        assert result.decision is Decision.ALLOW
        assert result.rule_id == "wire.allow_small"

    def test_exact_cap_allows(self, wire_pack):
        """amount=1000 (exactly at cap) -> ALLOW (max is inclusive).

        Expected: ALLOW/wire.allow_small.
        """
        result = engine.decide(wire_pack, "wire_transfer", {"amount": 1000})
        assert result.decision is Decision.ALLOW
        assert result.rule_id == "wire.allow_small"

    def test_one_over_cap_denies(self, wire_pack):
        """amount=1001 (one over cap) -> DENY.

        Expected: DENY/policy.default_deny.
        """
        result = engine.decide(wire_pack, "wire_transfer", {"amount": 1001})
        assert result.decision is Decision.DENY
        assert result.rule_id == RULE_DEFAULT_DENY

    def test_none_amount_denies(self, wire_pack):
        """amount=None (present but None) -> DENY (None is not a real number).

        Expected: DENY/policy.default_deny.
        """
        result = engine.decide(wire_pack, "wire_transfer", {"amount": None})
        assert result.decision is Decision.DENY
        assert result.rule_id == RULE_DEFAULT_DENY


# ===========================================================================
# ATTACK 7 — Determinism under hostility (invariant 2)
#
# Scenario: for a sample of adversarial calls, repeat 50 times and confirm
# identical GatewayResult every time.
#
# Expected: same decision + rule_id on every repetition.
# ===========================================================================

class TestDeterminismUnderHostility:
    """Prove invariant 2 holds for adversarial call patterns."""

    @pytest.fixture()
    def wire_pack(self):
        return validate({
            "version": 1,
            "default": "deny",
            "rules": [
                {"id": "wire.allow_small",
                 "rationale": "allow small wire transfers",
                 "tool": "wire_transfer",
                 "when": {"amount": {"max": 1000}},
                 "effect": "ALLOW"},
            ],
        })

    @pytest.mark.parametrize("tool,params", [
        # ALLOW-guard omission: missing amount
        ("wire_transfer", {}),
        # ALLOW-guard type confusion: string amount
        ("wire_transfer", {"amount": "9999999"}),
        # ALLOW-guard bool smuggling
        ("wire_transfer", {"amount": True}),
        # one_of type confusion: int vs string
        ("wire_transfer", {"amount": 1}),
    ])
    def test_repeated_calls_with_wire_pack_are_identical(self, wire_pack, tool, params):
        """50 repeated decisions for the wire_transfer pack are identical.

        Expected: all 50 results share the same decision and rule_id.
        """
        first = engine.decide(wire_pack, tool, params)
        for _ in range(49):
            again = engine.decide(wire_pack, tool, params)
            assert again.decision is first.decision, (
                f"Non-determinism: decision changed from {first.decision} "
                f"to {again.decision} for tool={tool!r}, params={params!r}"
            )
            assert again.rule_id == first.rule_id, (
                f"Non-determinism: rule_id changed from {first.rule_id!r} "
                f"to {again.rule_id!r} for tool={tool!r}, params={params!r}"
            )

    @pytest.mark.parametrize("tool,params", [
        # Reserved-namespace returns (with no pack)
        ("anything", {}),
        # Default pack: destructive SQL
        ("execute_sql", {"sql": "DROP TABLE customers"}),
        # Default pack: benign SQL
        ("execute_sql", {"sql": "SELECT 1"}),
        # Default pack: lookup
        ("lookup_customer", {"customer_id": "C001"}),
        # Default pack: unknown tool
        ("rm_rf_everything", {"path": "/"}),
        # domain_in malformed
        ("act", {"to": "a@b@evil.com"}),
    ])
    def test_repeated_calls_default_pack_are_identical(self, tool, params):
        """50 repeated decisions for the default pack are identical.

        Uses the autouse-configured default pack (no fixture override needed).

        Expected: all 50 results share the same decision and rule_id.
        """
        first = gw.evaluate(tool, params, context=None)
        for _ in range(49):
            again = gw.evaluate(tool, params, context=None)
            assert again.decision is first.decision
            assert again.rule_id == first.rule_id


# ===========================================================================
# ATTACK 8 — Loop integration (default pack configured, run_loop + stub)
#
# Scenario A: DROP TABLE -> DENY with rule "sql.deny_destructive"; the tool
#             function is never called (spy confirms).
# Scenario B: unknown tool "rm_rf_everything" proposed -> DENY "policy.default_deny";
#             never executes; audit record is written (write-ahead still holds for
#             engine-default denials).
#
# Expected: as stated in each test.
# ===========================================================================

class TestLoopIntegration:
    """Prove loop-level enforcement with the default pack (via autouse fixture)."""

    def test_drop_table_denied_with_correct_rule_id(self, audit_log: Path):
        """DROP TABLE via the loop produces DENY / sql.deny_destructive.

        Expected: DENY, rule "sql.deny_destructive", spy never called.
        """
        spy = MagicMock(return_value="should not be called")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["execute_sql"] = spy

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "li1", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="attack",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        spy.assert_not_called()
        assert len(trail) == 1
        assert trail[0]["decision"] == "DENY"
        assert trail[0]["rule"] == "sql.deny_destructive", (
            f"Expected rule 'sql.deny_destructive', got {trail[0]['rule']!r}"
        )
        assert trail[0]["tool"] == "execute_sql"

    def test_unknown_tool_denied_with_default_deny_and_audited(self, audit_log: Path):
        """An unknown tool "rm_rf_everything" is denied by default-deny.

        Expected: DENY, rule "policy.default_deny", never executes,
        audit record written (write-ahead holds for engine-default denials).
        """
        # The tool is not in TOOL_REGISTRY — add a spy just in case.
        spy = MagicMock(return_value="should never be called")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["rm_rf_everything"] = spy

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "li2", "name": "rm_rf_everything",
              "input": {"path": "/"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="wipe everything",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        spy.assert_not_called()
        assert len(trail) == 1
        assert trail[0]["decision"] == "DENY"
        assert trail[0]["rule"] == "policy.default_deny", (
            f"Expected rule 'policy.default_deny' for unknown tool, "
            f"got {trail[0]['rule']!r}"
        )
        assert trail[0]["tool"] == "rm_rf_everything"

        # Write-ahead: the audit record must also be on disk.
        import json
        lines = [
            json.loads(l.strip())
            for l in audit_log.read_text(encoding="utf-8").splitlines()
            if l.strip()
        ]
        assert len(lines) == 1
        assert lines[0]["tool"] == "rm_rf_everything"
        assert lines[0]["decision"] == "DENY"
        assert lines[0]["rule"] == "policy.default_deny"

    def test_unknown_tool_denial_message_names_rule(self, audit_log: Path):
        """The denial tool_result message for the unknown tool names the rule id.

        Expected: the model receives a tool_result containing 'policy.default_deny'.
        """
        turn_fn_calls = []
        captured_tool_results = []

        def model_fn(messages):
            turn_fn_calls.append(len(messages))
            if len(turn_fn_calls) == 1:
                return [{"type": "tool_use", "id": "li3",
                         "name": "rm_rf_everything", "input": {"path": "/"}}]
            last_msg = messages[-1]
            if isinstance(last_msg.get("content"), list):
                captured_tool_results.extend(last_msg["content"])
            return [{"type": "text", "text": "done"}]

        patched_registry = dict(TOOL_REGISTRY)
        run_loop(
            system_prompt="test",
            initial_user_message="wipe",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=model_fn,
        )

        assert len(captured_tool_results) >= 1
        denial = captured_tool_results[0]
        assert denial.get("is_error") is True
        assert "policy.default_deny" in denial.get("content", ""), (
            f"Expected 'policy.default_deny' in denial content, got: "
            f"{denial.get('content')!r}"
        )

    def test_benign_tools_still_allowed_after_attack(self, audit_log: Path, db_reset):
        """After a DENY for an unknown tool, benign tools still ALLOW normally.

        Proves the default-deny posture does not latch state — next tool call
        is evaluated fresh.

        Expected: turn 1 DENY (unknown tool), turn 2 ALLOW (calculator).
        """
        spy_calc = MagicMock(return_value="4")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["calculator"] = spy_calc

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "li4", "name": "rm_rf_everything",
              "input": {"path": "/"}}],
            [{"type": "tool_use", "id": "li5", "name": "calculator",
              "input": {"expression": "2+2"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="attack then benign",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 2
        assert trail[0]["decision"] == "DENY"
        assert trail[0]["rule"] == "policy.default_deny"
        assert trail[1]["decision"] == "ALLOW"
        assert trail[1]["rule"] == "math.allow_calculator"
        spy_calc.assert_called_once_with(expression="2+2")
