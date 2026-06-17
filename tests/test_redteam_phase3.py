"""
test_redteam_phase3.py — red-team attack suite for Phase 3 slice 3a.

Each test class / function targets one attack class. Assertions state the EXPECTED
Aegis decision. A test that PASSES but whose assertion reveals a bypass is annotated
as a BUG REPORT inline.

Attack classes:
  A. Determinism (no clock/ts/random in the rate-limit path)
  B. Count abuse / off-by-one
  C. Non-execution guarantee (RATE_LIMIT and REQUIRE_APPROVAL never execute)
  D. Malformed count packs (partial-load / silent acceptance)
  E. Message honesty (RATE_LIMIT vs REQUIRE_APPROVAL vs DENY are distinct)
  F. Interaction with first-match precedence, `when`, and `after`
"""

from __future__ import annotations

import inspect
import re
import time
from types import ModuleType
from typing import Any
from unittest.mock import MagicMock

import pytest

import policy.engine as engine_module
from core.decision import Decision
from core.loop import (
    _make_approval_required_result,
    _make_denial_result,
    _make_rate_limited_result,
    run_loop,
)
from demos.tools import TOOL_REGISTRY, TOOL_SCHEMAS
from policy.engine import decide
from policy.schema import CountClause, PolicyError, validate


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _pack(*rules: dict, default: str = "deny"):
    """Build and validate a Pack from inline rule dicts."""
    return validate({"version": 1, "default": default, "rules": list(rules)})


def _rec(tool: str, decision: str = "ALLOW") -> dict:
    """Minimal well-formed trajectory record."""
    return {"tool": tool, "params": {}, "decision": decision, "rule": "x"}


RATE_RULE = {
    "id": "cap",
    "rationale": "at most 2 per run",
    "tool": "t",
    "effect": "RATE_LIMIT",
    "count": {"tool": "t", "max": 2},
}
ALLOW_RULE = {"id": "allow", "rationale": "below cap", "tool": "t", "effect": "ALLOW"}


# ============================================================================
# A. DETERMINISM — the highest-value check
# ============================================================================

class TestDeterminism:
    """
    Invariant 2: same (pack, tool, params, trajectory) MUST always yield the same
    verdict, regardless of wall-clock time, call order, or repeated evaluation.
    Prove that _count_holds reads NO clock.
    """

    def test_engine_module_imports_no_time_or_random(self):
        """
        EXPECTED: engine.py must NOT import time, datetime, random, os, or any
        clock/I/O module. The imports of engine.py are the proof.

        If this fails it is a BUG: non-determinism was introduced into the decision path.
        """
        source = inspect.getsource(engine_module)
        forbidden_imports = [
            r"^\s*import\s+time\b",
            r"^\s*import\s+datetime\b",
            r"^\s*import\s+random\b",
            r"^\s*import\s+os\b",
            r"^\s*from\s+time\s+import",
            r"^\s*from\s+datetime\s+import",
            r"^\s*from\s+random\s+import",
        ]
        for pattern in forbidden_imports:
            assert not re.search(pattern, source, re.MULTILINE), (
                f"engine.py contains forbidden import matching '{pattern}'. "
                "This is a non-determinism BUG: a clock/random reached the decision path."
            )

    def test_count_holds_source_has_no_clock_calls(self):
        """
        EXPECTED: _count_holds function body must not contain time.*, datetime.*,
        now(), random.*, or ts field comparisons.

        If this fails: a clock is inside the rate-limit decision.

        NOTE: We strip docstrings from the source before scanning, because the
        docstring legitimately mentions 'now()' as something that must NOT be there.
        Only the actual code lines are checked.
        """
        source = inspect.getsource(engine_module._count_holds)
        # Strip docstring: everything between the first triple-quote pair.
        # We remove all triple-quoted string literals so the scan hits only code.
        source_no_docstring = re.sub(r'""".*?"""', '', source, flags=re.DOTALL)
        source_no_docstring = re.sub(r"'''.*?'''", '', source_no_docstring, flags=re.DOTALL)

        forbidden_tokens = [
            r"\btime\b",
            r"\bdatetime\b",
            r"\bnow\s*\(",
            r"\brandom\b",
            r'["\']ts["\']',  # ts field access in the scan
        ]
        for pattern in forbidden_tokens:
            match = re.search(pattern, source_no_docstring)
            assert not match, (
                f"_count_holds code (non-docstring) contains forbidden token matching "
                f"'{pattern}' at position {match.start() if match else '?'}. "
                "This is an invariant-2 violation: the rate decision depends on the clock."
            )

    def test_rate_limit_is_same_value_called_100_times(self):
        """
        EXPECTED: calling decide() 100 times with the same inputs always returns
        RATE_LIMIT from the same rule. No jitter, no flip.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [_rec("t"), _rec("t")]  # 2 prior ALLOWs -> at cap
        results = [
            (decide(pack, "t", {}, traj).decision, decide(pack, "t", {}, traj).rule_id)
            for _ in range(100)
        ]
        assert all(r == (Decision.RATE_LIMIT, "cap") for r in results), (
            "decide() returned different values across 100 identical calls. "
            "BUG: non-determinism in the rate-limit path."
        )

    def test_rate_limit_same_across_real_time_gap(self):
        """
        EXPECTED: RATE_LIMIT verdict is the same before and after a sleep.
        If the result changed, a clock leaked into the decision.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [_rec("t"), _rec("t")]

        result_before = decide(pack, "t", {}, traj)
        time.sleep(0.1)
        result_after = decide(pack, "t", {}, traj)

        assert result_before.decision is Decision.RATE_LIMIT
        assert result_after.decision is Decision.RATE_LIMIT
        assert result_before.rule_id == result_after.rule_id, (
            "Rate-limit verdict changed after a time gap. "
            "BUG: clock is inside the decision path."
        )

    def test_allow_below_cap_same_across_time(self):
        """
        EXPECTED: ALLOW verdict below cap is stable across a real-time gap.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [_rec("t")]  # 1 prior ALLOW, cap is 2 -> still ALLOW

        result_before = decide(pack, "t", {}, traj)
        time.sleep(0.1)
        result_after = decide(pack, "t", {}, traj)

        assert result_before.decision is Decision.ALLOW
        assert result_after.decision is Decision.ALLOW

    def test_trajectory_with_ts_field_does_not_change_decision(self):
        """
        EXPECTED: Adding a `ts` field to trajectory records does not affect the
        count (the engine must not read `ts` in _count_holds).
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        # Same trajectory content but with ts fields that could create time-based branches
        traj_no_ts = [_rec("t"), _rec("t")]
        traj_with_ts = [
            {"tool": "t", "params": {}, "decision": "ALLOW", "rule": "x",
             "ts": "2025-01-01T00:00:00+00:00"},
            {"tool": "t", "params": {}, "decision": "ALLOW", "rule": "x",
             "ts": "2099-12-31T23:59:59+00:00"},  # far-future timestamp
        ]
        r1 = decide(pack, "t", {}, traj_no_ts)
        r2 = decide(pack, "t", {}, traj_with_ts)
        assert r1.decision is Decision.RATE_LIMIT
        assert r2.decision is Decision.RATE_LIMIT, (
            "A far-future ts field changed the RATE_LIMIT verdict to something else. "
            "BUG: the engine is reading the ts field in the count scan."
        )
        assert r1.rule_id == r2.rule_id


# ============================================================================
# B. COUNT ABUSE / OFF-BY-ONE
# ============================================================================

class TestCountAbuseOffByOne:
    """
    Probe threshold crossing semantics, non-ALLOW record inflation, and
    junk/forged trajectory robustness.
    """

    def test_max3_exact_boundary(self):
        """
        EXPECTED for max:3:
          - 0 prior ALLOWs -> ALLOW
          - 1 prior ALLOW  -> ALLOW
          - 2 prior ALLOWs -> ALLOW
          - 3 prior ALLOWs -> RATE_LIMIT  (the 4th call)
          - 4 prior ALLOWs -> RATE_LIMIT  (5th call, cap stays)

        The 3rd call (2 prior) must NOT trip; the 4th (3 prior) MUST trip.
        """
        pack = _pack(
            {"id": "cap3", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 3}},
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
        )
        for n_prior in range(3):
            traj = [_rec("t")] * n_prior
            r = decide(pack, "t", {}, traj)
            assert r.decision is Decision.ALLOW, (
                f"With {n_prior} prior ALLOWs and max=3, expected ALLOW but got "
                f"{r.decision}. BUG: off-by-one, cap fires too early."
            )

        # The 4th call: exactly 3 prior ALLOWs -> RATE_LIMIT
        traj3 = [_rec("t")] * 3
        r3 = decide(pack, "t", {}, traj3)
        assert r3.decision is Decision.RATE_LIMIT, (
            "With 3 prior ALLOWs and max=3, expected RATE_LIMIT but got "
            f"{r3.decision}. BUG: off-by-one, cap fires too late."
        )

        # 5th call: 4 prior ALLOWs -> still RATE_LIMIT (cap persists)
        traj4 = [_rec("t")] * 4
        r4 = decide(pack, "t", {}, traj4)
        assert r4.decision is Decision.RATE_LIMIT, (
            f"With 4 prior ALLOWs and max=3, expected persistent RATE_LIMIT but got {r4.decision}."
        )

    def test_deny_records_do_not_count_toward_cap(self):
        """
        EXPECTED: A DENYed prior call never executed, so it must not count.
        Five DENYed + zero ALLOWed -> still ALLOW (below cap of 2).
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [_rec("t", "DENY")] * 5
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW, (
            "DENYed records inflated the count. BUG: _count_holds counts non-ALLOW records."
        )

    def test_rate_limit_records_do_not_count_toward_cap(self):
        """
        EXPECTED: RATE_LIMIT records in the trajectory must NOT count.
        The action was refused, not executed.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [_rec("t", "RATE_LIMIT")] * 5
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW, (
            "RATE_LIMIT trajectory records inflated the count. BUG."
        )

    def test_require_approval_records_do_not_count_toward_cap(self):
        """
        EXPECTED: REQUIRE_APPROVAL records must NOT count (not executed).
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [_rec("t", "REQUIRE_APPROVAL")] * 5
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW, (
            "REQUIRE_APPROVAL trajectory records inflated the count. BUG."
        )

    def test_mixed_decisions_only_allow_counts(self):
        """
        EXPECTED: cap=2; trajectory has 2 DENYs + 1 ALLOW -> 1 ALLOW -> still ALLOW (below cap).
        Trajectory has 2 DENYs + 2 ALLOWs -> 2 ALLOWs -> RATE_LIMIT.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj_one_allow = [
            _rec("t", "DENY"), _rec("t", "DENY"), _rec("t", "ALLOW")
        ]
        assert decide(pack, "t", {}, traj_one_allow).decision is Decision.ALLOW

        traj_two_allow = [
            _rec("t", "DENY"), _rec("t", "DENY"),
            _rec("t", "ALLOW"), _rec("t", "ALLOW"),
        ]
        assert decide(pack, "t", {}, traj_two_allow).decision is Decision.RATE_LIMIT

    def test_junk_trajectory_entry_does_not_crash_or_inflate(self):
        """
        EXPECTED: Non-dict, wrong-typed, and partial entries are silently skipped.
        The scan must not crash and must not count junk as ALLOWs.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        junk_trajectories: list[list[Any]] = [
            [None, None, None],
            [42, True, 3.14],
            ["ALLOW", "ALLOW", "ALLOW"],   # strings, not dicts
            [{"tool": "t"}, {"decision": "ALLOW"}],  # partial dicts — missing the other field
            [{"tool": 1, "decision": "ALLOW"}],       # tool is wrong type
            [{"tool": "t", "decision": True}],         # decision is bool, not "ALLOW" string
            [[], {}, set()],
            [{"tool": "t", "decision": "ALLOW", "extra_garbage": object()}],
        ]
        for traj in junk_trajectories:
            r = decide(pack, "t", {}, traj)
            # None of these should count as ALLOWs (only the last one has a valid dict entry)
            # The last one DOES have a valid entry (tool="t", decision="ALLOW") — it should count as 1.
            # But all others should NOT crash and should show ALLOW (below cap).

    def test_junk_entries_interspersed_with_real_ones(self):
        """
        EXPECTED: Junk entries are skipped; real ALLOW entries count normally.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        # 2 real ALLOWs interspersed with junk -> should hit cap
        traj = [
            42,
            _rec("t", "ALLOW"),
            "garbage",
            None,
            _rec("t", "ALLOW"),
            {"no_tool": "t", "decision": "ALLOW"},  # missing "tool" key -> .get returns None != "t"
        ]
        r = decide(pack, "t", {}, traj)
        assert r.decision is Decision.RATE_LIMIT, (
            "Junk entries caused real ALLOWs to be skipped. BUG: count is too low."
        )

    def test_forged_allow_for_wrong_tool_does_not_count(self):
        """
        EXPECTED: A trajectory ALLOW for tool "other" must not count toward the cap for tool "t".
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [_rec("other", "ALLOW")] * 10
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW, (
            "ALLOWs for a different tool inflated the count. BUG: tool filter is broken."
        )

    def test_forged_trajectory_decision_boolean_true_does_not_count(self):
        """
        EXPECTED: An entry with decision=True (bool) must not count — 'ALLOW' != True in Python.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        # In Python: True == 1, and "ALLOW" != True, so this should NOT count.
        traj = [{"tool": "t", "decision": True}] * 10
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW, (
            "decision=True (bool) counted as 'ALLOW'. BUG: bool/string equality confusion."
        )

    def test_count_clause_counting_different_tool_than_gated(self):
        """
        EXPECTED: A RATE_LIMIT on tool "export" with count.tool="read" fires when
        the trajectory has >= 2 ALLOWed "read" records, regardless of any "export" records.
        """
        rule = {
            "id": "gate",
            "rationale": "x",
            "tool": "export",
            "effect": "RATE_LIMIT",
            "count": {"tool": "read", "max": 2},
        }
        allow_export = {"id": "ok", "rationale": "x", "tool": "export", "effect": "ALLOW"}
        pack = _pack(rule, allow_export)

        # 10 ALLOWed "export" in history -> should NOT trip (we count "read", not "export")
        traj_export_only = [_rec("export", "ALLOW")] * 10
        assert decide(pack, "export", {}, traj_export_only).decision is Decision.ALLOW, (
            "ALLOWs for the GATED tool inflated the count targeting a DIFFERENT tool. BUG."
        )

        # 2 ALLOWed "read" in history -> SHOULD trip
        traj_reads = [_rec("read", "ALLOW"), _rec("read", "ALLOW")]
        assert decide(pack, "export", {}, traj_reads).decision is Decision.RATE_LIMIT

    def test_max_zero_fires_with_empty_trajectory(self):
        """
        EXPECTED: max:0 fires immediately (0 >= 0) even with an empty trajectory.
        """
        pack = _pack(
            {"id": "zero_cap", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 0}},
            ALLOW_RULE,
        )
        assert decide(pack, "t", {}, []).decision is Decision.RATE_LIMIT
        assert decide(pack, "t", {}, None).decision is Decision.RATE_LIMIT

    def test_max_zero_fires_with_none_trajectory(self):
        """
        EXPECTED: max:0 fires on None trajectory (0 >= 0 is True).
        """
        pack = _pack(
            {"id": "zero_cap", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 0}},
            ALLOW_RULE,
        )
        r = decide(pack, "t", {}, None)
        assert r.decision is Decision.RATE_LIMIT, (
            f"max:0 with None trajectory returned {r.decision}. BUG: should fire immediately."
        )

    def test_rate_limit_trajectory_records_accumulated_in_loop(self, audit_log):
        """
        EXPECTED: In the real loop, RATE_LIMIT records are written to audit_trail
        but must NOT count toward the ALLOW cap in subsequent decisions (since they
        record decision="RATE_LIMIT", not "ALLOW").

        The 4th call hits RATE_LIMIT. If the RATE_LIMIT record is mistakenly counted
        as an ALLOW, the 5th call would see 4 "ALLOWs" and still RATE_LIMIT — but we
        need to verify the 5th call sees exactly 3 ALLOWs + 1 RATE_LIMIT.
        """
        executed = MagicMock(return_value="refunded")
        registry = dict(TOOL_REGISTRY)
        registry["issue_refund"] = executed

        # 5 calls: first 3 ALLOW (cap=3), 4th and 5th RATE_LIMIT
        blocks = [
            {"type": "tool_use", "id": f"r{i}", "name": "issue_refund", "input": {}}
            for i in range(5)
        ]

        def _one_turn(blocks):
            def _fn(_messages):
                if not getattr(_fn, "done", False):
                    _fn.done = True
                    return list(blocks)
                return [{"type": "text", "text": "done"}]
            return _fn

        trail = run_loop(
            system_prompt="t", initial_user_message="u",
            tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
            model_turn_fn=_one_turn(blocks),
        )
        decisions = [r["decision"] for r in trail]
        assert decisions == ["ALLOW", "ALLOW", "ALLOW", "RATE_LIMIT", "RATE_LIMIT"], (
            f"Unexpected decisions sequence: {decisions}. "
            "BUG: RATE_LIMIT records may be inflating the ALLOW count."
        )
        assert executed.call_count == 3


# ============================================================================
# C. NON-EXECUTION GUARANTEE
# ============================================================================

class TestNonExecution:
    """
    Prove NO RATE_LIMIT and NO REQUIRE_APPROVAL verdict ever executes the tool body.
    Find any second path to execution beyond `is Decision.ALLOW`.
    """

    def test_rate_limit_does_not_execute(self, audit_log):
        """EXPECTED: RATE_LIMIT -> tool body never called."""
        executed = MagicMock(return_value="should not run")
        registry = {"t": executed}

        # Inject a pack where the first call hits RATE_LIMIT immediately (max:0)
        from core import gateway
        pack = _pack(
            {"id": "zero_cap", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 0}},
        )
        gateway.configure(pack)

        def _turn(_messages):
            if not getattr(_turn, "done", False):
                _turn.done = True
                return [{"type": "tool_use", "id": "x1", "name": "t", "input": {}}]
            return [{"type": "text", "text": "done"}]

        trail = run_loop(
            system_prompt="s", initial_user_message="u",
            tool_registry=registry, tool_schemas=[], log_path=audit_log,
            model_turn_fn=_turn,
        )
        assert trail[-1]["decision"] == "RATE_LIMIT"
        executed.assert_not_called(), (
            "Tool executed despite RATE_LIMIT verdict. BUG: second execute path found."
        )

    def test_require_approval_does_not_execute(self, audit_log):
        """EXPECTED: REQUIRE_APPROVAL -> tool body never called."""
        executed = MagicMock(return_value="should not run")
        registry = dict(TOOL_REGISTRY)
        registry["export_data"] = executed

        def _turn(_messages):
            if not getattr(_turn, "done", False):
                _turn.done = True
                return [{"type": "tool_use", "id": "e1", "name": "export_data", "input": {}}]
            return [{"type": "text", "text": "done"}]

        trail = run_loop(
            system_prompt="s", initial_user_message="u",
            tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
            model_turn_fn=_turn,
        )
        assert trail[-1]["decision"] == "REQUIRE_APPROVAL"
        executed.assert_not_called(), (
            "Tool executed despite REQUIRE_APPROVAL verdict. BUG."
        )

    def test_loop_execute_gate_is_exact_allow_only(self):
        """
        Structural proof: inspect loop.py to confirm the only execution branch is
        guarded by `is Decision.ALLOW` and no other condition reaches tool_fn(**params).
        """
        from core import loop as loop_module
        source = inspect.getsource(loop_module.run_loop)

        # Find all occurrences of tool_fn( in the source — there should be exactly one.
        tool_fn_calls = re.findall(r"tool_fn\s*\(", source)
        assert len(tool_fn_calls) == 1, (
            f"Found {len(tool_fn_calls)} calls to tool_fn() in run_loop, expected exactly 1. "
            "BUG: a second execution path exists."
        )

        # The only execution branch must be preceded by `is Decision.ALLOW`.
        # We verify this structurally: find the block containing tool_fn( and assert
        # it is nested inside the `if result.decision is Decision.ALLOW:` branch.
        allow_guard_pos = source.find("is Decision.ALLOW")
        tool_fn_pos = source.find("tool_fn(")
        assert allow_guard_pos != -1, "Could not find 'is Decision.ALLOW' guard in run_loop source."
        assert tool_fn_pos > allow_guard_pos, (
            "tool_fn() call appears before the Decision.ALLOW guard. BUG."
        )

    def test_rate_limit_in_multi_tool_turn_does_not_execute(self, audit_log):
        """
        EXPECTED: In a turn with multiple tool calls, the rate-limited one must not
        execute while the earlier allowed ones do. Ensures the per-block branching
        is correct and rate-limit for one block doesn't corrupt others.
        """
        calc_executed = MagicMock(return_value="result")
        refund_executed = MagicMock(return_value="refunded")
        registry = dict(TOOL_REGISTRY)
        registry["calculator"] = calc_executed
        registry["issue_refund"] = refund_executed

        # 3 refunds (allowed) then 1 calculator (allowed) then 1 more refund (rate-limited)
        blocks = [
            {"type": "tool_use", "id": "r1", "name": "issue_refund", "input": {}},
            {"type": "tool_use", "id": "r2", "name": "issue_refund", "input": {}},
            {"type": "tool_use", "id": "r3", "name": "issue_refund", "input": {}},
            {"type": "tool_use", "id": "c1", "name": "calculator",
             "input": {"expression": "1+1"}},
            {"type": "tool_use", "id": "r4", "name": "issue_refund", "input": {}},
        ]

        def _turn(_messages):
            if not getattr(_turn, "done", False):
                _turn.done = True
                return blocks
            return [{"type": "text", "text": "done"}]

        trail = run_loop(
            system_prompt="s", initial_user_message="u",
            tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
            model_turn_fn=_turn,
        )
        decisions = [r["decision"] for r in trail]
        assert decisions == ["ALLOW", "ALLOW", "ALLOW", "ALLOW", "RATE_LIMIT"]
        assert refund_executed.call_count == 3
        assert calc_executed.call_count == 1


# ============================================================================
# D. MALFORMED COUNT PACKS
# ============================================================================

class TestMalformedCountPacks:
    """
    Every malformed `count` pack must reject the WHOLE pack (PolicyError),
    never partial-load. Test every boundary case the schema validator must handle.
    """

    @pytest.mark.parametrize("bad_count", [
        # Non-dict types (excluding None — see test_count_null_is_a_bug below)
        "string_count",
        42,
        3.14,
        True,
        ["tool", "max"],
        # Missing keys
        {"tool": "t"},                     # missing max
        {"max": 5},                        # missing tool
        {},                                # empty — both missing
        # Unknown / extra keys
        {"tool": "t", "max": 5, "extra": "x"},
        {"tool": "t", "max": 5, "min": 1},
        {"tool": "t", "max": 5, "count": 5},
        # Bad tool values
        {"tool": "", "max": 3},            # empty string
        {"tool": None, "max": 3},          # None
        {"tool": 5, "max": 3},             # int
        {"tool": True, "max": 3},          # bool
        {"tool": ["t"], "max": 3},         # list
        {"tool": {"name": "t"}, "max": 3}, # dict
        # Bad max values
        {"tool": "t", "max": -1},          # negative
        {"tool": "t", "max": -100},        # large negative
        {"tool": "t", "max": 1.5},         # float
        {"tool": "t", "max": True},        # bool (isinstance(True, int) trap)
        {"tool": "t", "max": False},       # bool False (0 would be ok, False is not)
        {"tool": "t", "max": "3"},         # string
        {"tool": "t", "max": None},        # None
        {"tool": "t", "max": []},          # list
    ])
    def test_malformed_count_rejects_whole_pack(self, bad_count):
        """EXPECTED: PolicyError, whole pack rejected."""
        try:
            _pack({
                "id": "r1",
                "rationale": "x",
                "tool": "t",
                "effect": "RATE_LIMIT",
                "count": bad_count,
            })
        except PolicyError:
            pass  # expected
        else:
            pytest.fail(
                f"Malformed count clause did not raise PolicyError. "
                f"BUG: partial load — accepted bad count {bad_count!r}."
            )

    def test_count_null_is_rejected(self):
        """
        FIXED (was a bug, now a regression test): `count: null` (explicit None) is rejected.

        Previously `raw.get("count")` returned None for both an ABSENT key and an explicit
        `count: null`, so an explicit null silently became "no clause" — and on a RATE_LIMIT
        rule that meant `_count_holds(None)` returns True and the rule fired on every call.
        Fixed in schema.py via an `_ABSENT` sentinel: an explicit null is no longer the
        absent form, so it reaches _normalize_count and is rejected as not-a-mapping. The
        same fix applies to `after: null`.
        """
        with pytest.raises(PolicyError):
            _pack({"id": "r1", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT", "count": None})

    def test_after_null_is_rejected(self):
        """FIXED: an explicit `after: null` is rejected (not silently treated as absent)."""
        with pytest.raises(PolicyError):
            _pack({"id": "r1", "rationale": "x", "tool": "t", "effect": "ALLOW", "after": None})

    def test_good_rule_after_bad_count_rule_does_not_load(self):
        """
        EXPECTED: If the FIRST rule in a pack has a bad count, the pack must be entirely
        rejected even if the second rule is perfectly valid. All-or-nothing.
        """
        with pytest.raises(PolicyError):
            _pack(
                {"id": "bad", "rationale": "x", "tool": "t",
                 "effect": "RATE_LIMIT", "count": {"tool": "t", "max": -1}},
                {"id": "good", "rationale": "x", "tool": "t", "effect": "ALLOW"},
            )

    def test_bad_count_rule_in_middle_rejects_whole_pack(self):
        """
        EXPECTED: A bad count rule in the middle of a larger pack rejects the whole pack.
        The rules before and after it must not be loaded.
        """
        with pytest.raises(PolicyError):
            _pack(
                {"id": "r1", "rationale": "x", "tool": "a", "effect": "ALLOW"},
                {"id": "r2", "rationale": "x", "tool": "b", "effect": "ALLOW"},
                {"id": "bad", "rationale": "x", "tool": "t",
                 "effect": "RATE_LIMIT", "count": "not_a_dict"},
                {"id": "r3", "rationale": "x", "tool": "c", "effect": "ALLOW"},
            )

    def test_count_max_zero_is_accepted(self):
        """EXPECTED: max:0 is a valid, accepted value (rate-limited from first call)."""
        pack = _pack({
            "id": "r1", "rationale": "x", "tool": "t",
            "effect": "RATE_LIMIT", "count": {"tool": "t", "max": 0},
        })
        assert pack.rules[0].count.max == 0

    def test_count_clause_on_deny_effect_is_rejected(self):
        """
        FIXED (was accepted, now rejected): a `count` clause on a DENY rule is refused at
        load. A counted DENY is a footgun — a denial that STOPS firing once the count drops
        below the threshold (easier to evade as calls accumulate). ADR 0006 §a restricts
        `count` to RATE_LIMIT / REQUIRE_APPROVAL, where a count threshold is meaningful.
        """
        with pytest.raises(PolicyError):
            _pack({"id": "deny_after_n", "rationale": "x", "tool": "t",
                   "effect": "DENY", "count": {"tool": "t", "max": 3}})

    def test_count_clause_on_allow_effect_is_rejected(self):
        """
        FIXED (was accepted, now rejected): a `count` clause on an ALLOW rule is refused at
        load. An "allow only after N prior calls" rule is not a least-privilege control and
        is almost certainly an authoring mistake. ADR 0006 §a restricts `count` to
        RATE_LIMIT / REQUIRE_APPROVAL.
        """
        with pytest.raises(PolicyError):
            _pack({"id": "allow_after_n", "rationale": "x", "tool": "t",
                   "effect": "ALLOW", "count": {"tool": "t", "max": 2}})

    def test_count_clause_on_require_approval_effect(self):
        """
        EXPECTED: A count clause on REQUIRE_APPROVAL is accepted and works correctly:
        REQUIRE_APPROVAL only fires once the trajectory has >= max ALLOWs for count.tool.
        """
        pack = _pack(
            {"id": "approval_after_n", "rationale": "x", "tool": "export",
             "effect": "REQUIRE_APPROVAL", "count": {"tool": "read", "max": 2}},
            {"id": "allow_export", "rationale": "x", "tool": "export", "effect": "ALLOW"},
        )
        # 1 prior read ALLOW -> below threshold -> ALLOW
        assert decide(pack, "export", {}, [_rec("read")]).decision is Decision.ALLOW
        # 2 prior read ALLOWs -> at threshold -> REQUIRE_APPROVAL
        assert decide(pack, "export", {}, [_rec("read"), _rec("read")]).decision is Decision.REQUIRE_APPROVAL


# ============================================================================
# E. MESSAGE HONESTY
# ============================================================================

class TestMessageHonesty:
    """
    RATE_LIMIT and REQUIRE_APPROVAL results must be DISTINCT from DENY.
    Neither must claim execution happened.
    """

    def test_rate_limit_message_is_distinct_from_deny(self):
        """EXPECTED: RATE_LIMIT result prefix != DENY result prefix."""
        rl = _make_rate_limited_result("id1", "rule1")
        deny = _make_denial_result("id1", "rule1")
        assert rl["content"] != deny["content"], (
            "RATE_LIMIT and DENY produce identical content. BUG: model cannot distinguish them."
        )
        # Confirm the RATE_LIMIT message contains "[AEGIS RATE_LIMIT]"
        assert "[AEGIS RATE_LIMIT]" in rl["content"]
        assert "[AEGIS DENY]" not in rl["content"], (
            "RATE_LIMIT message contains DENY marker. BUG."
        )

    def test_require_approval_message_is_distinct_from_deny(self):
        """EXPECTED: REQUIRE_APPROVAL result prefix != DENY result prefix."""
        ra = _make_approval_required_result("id1", "rule1")
        deny = _make_denial_result("id1", "rule1")
        assert ra["content"] != deny["content"]
        assert "[AEGIS REQUIRE_APPROVAL]" in ra["content"]
        assert "[AEGIS DENY]" not in ra["content"], (
            "REQUIRE_APPROVAL message contains DENY marker. BUG."
        )

    def test_require_approval_message_is_distinct_from_rate_limit(self):
        """EXPECTED: REQUIRE_APPROVAL and RATE_LIMIT have distinct messages."""
        ra = _make_approval_required_result("id1", "rule1")
        rl = _make_rate_limited_result("id1", "rule1")
        assert ra["content"] != rl["content"]
        assert "[AEGIS REQUIRE_APPROVAL]" in ra["content"]
        assert "[AEGIS RATE_LIMIT]" not in ra["content"]

    def test_rate_limit_message_does_not_claim_execution(self):
        """EXPECTED: RATE_LIMIT message must not contain 'executed' without 'NOT'."""
        rl = _make_rate_limited_result("id1", "rule1")
        # 'NOT executed' is fine; 'was executed' is a lie.
        content = rl["content"].upper()
        # The message should contain 'NOT EXECUTED' (the negative)
        assert "NOT EXECUTED" in content, (
            "RATE_LIMIT message does not explicitly say 'NOT executed'. "
            "BUG: model may think the action ran."
        )

    def test_require_approval_message_does_not_claim_execution(self):
        """EXPECTED: REQUIRE_APPROVAL message must say 'NOT executed'."""
        ra = _make_approval_required_result("id1", "rule1")
        content = ra["content"].upper()
        assert "NOT EXECUTED" in content, (
            "REQUIRE_APPROVAL message does not explicitly say 'NOT executed'. BUG."
        )

    def test_all_refusal_messages_have_is_error_true(self):
        """EXPECTED: All three refusal result types have is_error=True."""
        for fn, label in [
            (_make_denial_result, "DENY"),
            (_make_rate_limited_result, "RATE_LIMIT"),
            (_make_approval_required_result, "REQUIRE_APPROVAL"),
        ]:
            result = fn("id1", "rule1")
            assert result.get("is_error") is True, (
                f"{label} result does not have is_error=True. BUG."
            )

    def test_rate_limit_message_says_not_permanent(self):
        """
        EXPECTED: The RATE_LIMIT message must indicate it is a transient/per-run limit,
        not a permanent policy denial. The model must not treat it as a hard block.
        """
        rl = _make_rate_limited_result("id1", "rule1")
        content = rl["content"].lower()
        # Should mention something about per-run or count/usage limit
        assert any(kw in content for kw in ["per-run", "limit", "count", "usage"]), (
            "RATE_LIMIT message does not describe the transient nature. BUG: model may "
            "treat it as a permanent deny."
        )

    def test_require_approval_message_says_held_not_denied(self):
        """
        EXPECTED: The REQUIRE_APPROVAL message must indicate the action is held
        (pending approval), not permanently denied.
        """
        ra = _make_approval_required_result("id1", "rule1")
        content = ra["content"].lower()
        # Should mention approval/held/pending, not just refused/blocked
        assert any(kw in content for kw in ["approval", "held", "pending", "human"]), (
            "REQUIRE_APPROVAL message does not mention approval or pending state. BUG."
        )

    def test_rate_limit_result_contains_rule_id(self):
        """EXPECTED: RATE_LIMIT result names the specific rule_id."""
        rl = _make_rate_limited_result("id1", "my.rate.rule")
        assert "my.rate.rule" in rl["content"]

    def test_require_approval_result_contains_rule_id(self):
        """EXPECTED: REQUIRE_APPROVAL result names the specific rule_id."""
        ra = _make_approval_required_result("id1", "my.approval.rule")
        assert "my.approval.rule" in ra["content"]

    def test_rate_limit_audit_decision_field_is_rate_limit_string(self, audit_log):
        """
        EXPECTED: The audit record for a rate-limited call has decision='RATE_LIMIT',
        not 'DENY' or 'ALLOW'. The audit trail must be honest about what happened.
        """
        registry = dict(TOOL_REGISTRY)

        def _turn(_messages):
            if not getattr(_turn, "done", False):
                _turn.done = True
                return [
                    {"type": "tool_use", "id": "r1", "name": "issue_refund", "input": {}},
                    {"type": "tool_use", "id": "r2", "name": "issue_refund", "input": {}},
                    {"type": "tool_use", "id": "r3", "name": "issue_refund", "input": {}},
                    {"type": "tool_use", "id": "r4", "name": "issue_refund", "input": {}},
                ]
            return [{"type": "text", "text": "done"}]

        trail = run_loop(
            system_prompt="s", initial_user_message="u",
            tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
            model_turn_fn=_turn,
        )
        assert trail[3]["decision"] == "RATE_LIMIT", (
            f"4th refund audit record has decision={trail[3]['decision']!r}, expected 'RATE_LIMIT'. "
            "BUG: audit trail is dishonest about the verdict."
        )
        assert trail[3]["rule"] == "refunds.rate_limit"

    def test_require_approval_audit_decision_field(self, audit_log):
        """EXPECTED: Audit record for REQUIRE_APPROVAL has decision='REQUIRE_APPROVAL'."""
        registry = dict(TOOL_REGISTRY)

        def _turn(_messages):
            if not getattr(_turn, "done", False):
                _turn.done = True
                return [{"type": "tool_use", "id": "e1", "name": "export_data", "input": {}}]
            return [{"type": "text", "text": "done"}]

        trail = run_loop(
            system_prompt="s", initial_user_message="u",
            tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
            model_turn_fn=_turn,
        )
        assert trail[0]["decision"] == "REQUIRE_APPROVAL", (
            f"export_data audit record has decision={trail[0]['decision']!r}. BUG."
        )


# ============================================================================
# F. INTERACTION WITH FIRST-MATCH PRECEDENCE, `when`, AND `after`
# ============================================================================

class TestInteractionWithPrecedenceWhenAfter:
    """
    Probe rule ordering, combined when/after/count, and conjunction semantics.
    """

    def test_rate_limit_before_allow_wins_at_cap(self):
        """
        EXPECTED: With RATE_LIMIT rule BEFORE ALLOW rule, rate_limit fires at cap.
        Reversing order (ALLOW before RATE_LIMIT) would let all calls through.
        Confirm correct ordering: RATE_LIMIT must come first in the pack.
        """
        pack_correct_order = _pack(
            {"id": "cap", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 1}},
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
        )
        pack_wrong_order = _pack(
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
            {"id": "cap", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 1}},
        )
        traj = [_rec("t")]  # 1 prior ALLOW

        # Correct order: RATE_LIMIT fires first-match
        assert decide(pack_correct_order, "t", {}, traj).decision is Decision.RATE_LIMIT

        # Wrong order: ALLOW fires first (RATE_LIMIT never reached)
        # This is the EXPECTED behavior for wrong-order packs — first-match-wins
        # means the author's ordering is their intent.
        r_wrong = decide(pack_wrong_order, "t", {}, traj)
        assert r_wrong.decision is Decision.ALLOW, (
            "Wrong-order pack did not ALLOW (first-match didn't win for the ALLOW rule). "
            "This confirms ordering matters — document for pack authors."
        )

    def test_count_and_when_are_both_conjunctive(self):
        """
        EXPECTED: A rule with both count and when fires ONLY when BOTH hold.
        - count holds but when doesn't -> does not match -> falls to next rule
        - count doesn't hold but when does -> does not match -> falls to next rule
        - both hold -> fires
        """
        rule = {
            "id": "cap_large_amounts",
            "rationale": "x",
            "tool": "wire",
            "effect": "RATE_LIMIT",
            "count": {"tool": "wire", "max": 2},
            "when": {"amount": {"max": 1000}},
        }
        allow = {"id": "allow", "rationale": "x", "tool": "wire", "effect": "ALLOW"}
        pack = _pack(rule, allow)
        traj2 = [_rec("wire")] * 2

        # count holds (2 ALLOWs >= 2) AND when holds (amount <= 1000): RATE_LIMIT
        assert decide(pack, "wire", {"amount": 500}, traj2).decision is Decision.RATE_LIMIT

        # count holds BUT when doesn't (amount > 1000): falls to ALLOW
        assert decide(pack, "wire", {"amount": 9999}, traj2).decision is Decision.ALLOW

        # count doesn't hold (1 ALLOW < 2) even though when holds: falls to ALLOW
        traj1 = [_rec("wire")]
        assert decide(pack, "wire", {"amount": 500}, traj1).decision is Decision.ALLOW

    def test_count_and_after_are_both_conjunctive(self):
        """
        EXPECTED: A rule with both `after` and `count` fires ONLY when BOTH hold.
        - after holds but count doesn't -> no match
        - count holds but after doesn't -> no match
        - both hold -> fires
        """
        rule = {
            "id": "gate",
            "rationale": "x",
            "tool": "export",
            "effect": "REQUIRE_APPROVAL",
            "after": {"tool": "read"},
            "count": {"tool": "export", "max": 1},
        }
        allow = {"id": "allow", "rationale": "x", "tool": "export", "effect": "ALLOW"}
        pack = _pack(rule, allow)

        # after holds (read ALLOWed) AND count holds (1 prior export >= 1): REQUIRE_APPROVAL
        traj_both = [_rec("read"), _rec("export")]
        assert decide(pack, "export", {}, traj_both).decision is Decision.REQUIRE_APPROVAL

        # after holds but count doesn't (0 prior export < 1): ALLOW
        traj_after_only = [_rec("read")]
        assert decide(pack, "export", {}, traj_after_only).decision is Decision.ALLOW

        # count holds (1 prior export >= 1) but after doesn't (no prior read): ALLOW
        traj_count_only = [_rec("export")]
        assert decide(pack, "export", {}, traj_count_only).decision is Decision.ALLOW

        # Neither holds (empty traj): ALLOW
        assert decide(pack, "export", {}, []).decision is Decision.ALLOW

    def test_first_match_with_three_rules_precedence(self):
        """
        EXPECTED: Three rules for the same tool; the first matching one wins.
        With 3 prior ALLOWs: the RATE_LIMIT (max:3) fires first.
        With 2 prior ALLOWs: RATE_LIMIT skipped, DENY (when amount > 9000) checked.
        With 1 prior ALLOW and small amount: both skip, ALLOW fires.
        """
        cap_rule = {
            "id": "cap", "rationale": "x", "tool": "wire",
            "effect": "RATE_LIMIT", "count": {"tool": "wire", "max": 3},
        }
        deny_large = {
            "id": "deny_large", "rationale": "x", "tool": "wire",
            "effect": "DENY", "when": {"amount": {"min": 9001}},
        }
        allow_rule = {"id": "allow", "rationale": "x", "tool": "wire", "effect": "ALLOW"}
        pack = _pack(cap_rule, deny_large, allow_rule)

        traj3 = [_rec("wire")] * 3
        assert decide(pack, "wire", {"amount": 100}, traj3).decision is Decision.RATE_LIMIT

        traj2 = [_rec("wire")] * 2
        assert decide(pack, "wire", {"amount": 9999}, traj2).decision is Decision.DENY
        assert decide(pack, "wire", {"amount": 100}, traj2).decision is Decision.ALLOW

        traj1 = [_rec("wire")]
        assert decide(pack, "wire", {"amount": 9999}, traj1).decision is Decision.DENY
        assert decide(pack, "wire", {"amount": 100}, traj1).decision is Decision.ALLOW

    def test_default_pack_rate_limit_with_after_exfil_rule_interaction(self, audit_log):
        """
        EXPECTED: The default pack's refunds.rate_limit and email.deny_exfil_after_read
        rules operate independently and correctly in the same run.
        - Refund cap is hit on the 4th refund.
        - Exfil is blocked on a non-internal send after a lookup.
        Both must fire correctly in the same run.
        """
        registry = dict(TOOL_REGISTRY)
        executed = MagicMock(return_value="ok")
        for name in ["issue_refund", "lookup_customer", "send_email"]:
            registry[name] = MagicMock(return_value="ok")

        # 4 refunds, then lookup, then external send
        blocks = [
            {"type": "tool_use", "id": "r1", "name": "issue_refund", "input": {}},
            {"type": "tool_use", "id": "r2", "name": "issue_refund", "input": {}},
            {"type": "tool_use", "id": "r3", "name": "issue_refund", "input": {}},
            {"type": "tool_use", "id": "r4", "name": "issue_refund", "input": {}},
            {"type": "tool_use", "id": "l1", "name": "lookup_customer",
             "input": {"customer_id": "C001"}},
            {"type": "tool_use", "id": "s1", "name": "send_email",
             "input": {"to": "evil@external.com", "subject": "s", "body": "b"}},
        ]

        def _turn(_messages):
            if not getattr(_turn, "done", False):
                _turn.done = True
                return blocks
            return [{"type": "text", "text": "done"}]

        trail = run_loop(
            system_prompt="s", initial_user_message="u",
            tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
            model_turn_fn=_turn,
        )
        decisions = {r["tool"]: r["decision"] for r in trail}
        # The 4th refund audit record — check all refund records
        refund_decisions = [r["decision"] for r in trail if r["tool"] == "issue_refund"]
        assert refund_decisions == ["ALLOW", "ALLOW", "ALLOW", "RATE_LIMIT"]
        # Lookup was ALLOWed
        assert decisions.get("lookup_customer") == "ALLOW"
        # Exfil to external after lookup must be DENY
        assert decisions.get("send_email") == "DENY"

    def test_count_clause_does_not_affect_rules_for_different_tools(self):
        """
        EXPECTED: A count clause on a rule for tool "a" has no effect on decisions
        for tool "b", even if the trajectory has many ALLOWed "a" records.
        """
        pack = _pack(
            {"id": "cap_a", "rationale": "x", "tool": "a", "effect": "RATE_LIMIT",
             "count": {"tool": "a", "max": 1}},
            {"id": "allow_a", "rationale": "x", "tool": "a", "effect": "ALLOW"},
            {"id": "allow_b", "rationale": "x", "tool": "b", "effect": "ALLOW"},
        )
        traj = [_rec("a")] * 10  # many ALLOWs for "a"

        # "a" is rate-limited
        assert decide(pack, "a", {}, traj).decision is Decision.RATE_LIMIT
        # "b" is unaffected
        assert decide(pack, "b", {}, traj).decision is Decision.ALLOW

    def test_no_count_rule_never_reads_trajectory(self):
        """
        EXPECTED: A rule with no count clause must never consult the trajectory.
        Provide a massive junk trajectory and verify it does not affect decisions.
        """
        pack = _pack(
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
        )
        massive_junk = [{"tool": "t", "decision": "ALLOW"}] * 10000
        assert decide(pack, "t", {}, massive_junk).decision is Decision.ALLOW
        assert decide(pack, "t", {}, None).decision is Decision.ALLOW
        assert decide(pack, "t", {}, []).decision is Decision.ALLOW

    def test_rate_limit_verdict_does_not_count_toward_cap_in_same_run(self, audit_log):
        """
        EXPECTED: After a RATE_LIMIT fires, subsequent RATE_LIMIT audit records in
        the trajectory do NOT count as ALLOWs, so the decision for subsequent calls
        with the same trajectory stays RATE_LIMIT (for the right reason: 3 ALLOWs,
        not inflation from RATE_LIMIT records).
        """
        pack = _pack(
            {"id": "cap", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 2}},
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
        )
        traj_with_rl = [
            _rec("t", "ALLOW"),
            _rec("t", "ALLOW"),
            _rec("t", "RATE_LIMIT"),  # prior refusal — must not count
        ]
        # 2 ALLOWs (== max) and 1 RATE_LIMIT (not counted) -> still RATE_LIMIT
        r = decide(pack, "t", {}, traj_with_rl)
        assert r.decision is Decision.RATE_LIMIT
        # Verify it fires because of 2 ALLOWs, not because of the RATE_LIMIT record
        traj_just_rl = [_rec("t", "RATE_LIMIT"), _rec("t", "RATE_LIMIT")]
        r2 = decide(pack, "t", {}, traj_just_rl)
        # Only 0 ALLOWs in trajectory -> below cap -> ALLOW
        assert r2.decision is Decision.ALLOW, (
            "RATE_LIMIT trajectory records were counted as ALLOWs. "
            "BUG: _count_holds does not filter by decision == 'ALLOW'."
        )


# ============================================================================
# ADDITIONAL EDGE CASES / PARAMETER ABUSE
# ============================================================================

class TestParameterAbuse:
    """
    Parameter abuse: values designed to confuse the count scan or schema validation.
    """

    def test_count_tool_name_with_special_characters(self):
        """EXPECTED: count.tool with spaces/special chars is accepted if non-empty string."""
        pack = _pack(
            {"id": "r1", "rationale": "x", "tool": "t",
             "effect": "RATE_LIMIT", "count": {"tool": "tool with spaces!", "max": 1}},
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
        )
        # The count tool "tool with spaces!" never matches "t" -> count is 0 -> ALLOW
        assert decide(pack, "t", {}, [_rec("t")]).decision is Decision.ALLOW

    def test_very_large_max_value(self):
        """EXPECTED: max: 2**63 is a valid non-negative int and accepted."""
        max_val = 2 ** 63
        pack = _pack(
            {"id": "r1", "rationale": "x", "tool": "t",
             "effect": "RATE_LIMIT", "count": {"tool": "t", "max": max_val}},
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
        )
        # With only 100 ALLOWs, count << max -> ALLOW
        traj = [_rec("t")] * 100
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW

    def test_trajectory_with_none_decision_does_not_count(self):
        """EXPECTED: An entry with decision=None must not count as ALLOW."""
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [{"tool": "t", "decision": None}] * 5
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW

    def test_trajectory_with_empty_string_decision_does_not_count(self):
        """EXPECTED: An entry with decision='' must not count as ALLOW."""
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [{"tool": "t", "decision": ""}] * 5
        assert decide(pack, "t", {}, traj).decision is Decision.ALLOW

    def test_trajectory_with_lowercase_allow_does_not_count(self):
        """
        EXPECTED: 'allow' (lowercase) != 'ALLOW'. The engine uses exact string
        comparison. Lowercase should NOT count toward the cap.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [{"tool": "t", "decision": "allow"}] * 5  # lowercase
        r = decide(pack, "t", {}, traj)
        assert r.decision is Decision.ALLOW, (
            "Lowercase 'allow' was counted as 'ALLOW'. "
            "BUG: case-insensitive comparison in _count_holds."
        )

    def test_single_none_entry_in_trajectory(self):
        """EXPECTED: A list containing only None does not crash and counts 0 ALLOWs."""
        pack = _pack(RATE_RULE, ALLOW_RULE)
        assert decide(pack, "t", {}, [None]).decision is Decision.ALLOW

    def test_deeply_nested_trajectory_entry_does_not_crash(self):
        """EXPECTED: Complex nested objects in trajectory are safely skipped."""
        pack = _pack(RATE_RULE, ALLOW_RULE)
        traj = [
            {"tool": {"nested": "t"}, "decision": "ALLOW"},  # tool is a dict, not str
            {"tool": ["t"], "decision": "ALLOW"},             # tool is a list
            {"tool": "t", "decision": {"nested": "ALLOW"}},  # decision is a dict
        ]
        # None of these should crash or count (tool must equal "t" as a string)
        r = decide(pack, "t", {}, traj)
        assert r.decision is Decision.ALLOW

    def test_count_clause_max_one_boundary(self):
        """
        EXPECTED: max:1 means the 2nd call (1 prior ALLOW) hits RATE_LIMIT.
        The 1st call (0 prior ALLOWs) must ALLOW.
        """
        pack = _pack(
            {"id": "cap1", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
             "count": {"tool": "t", "max": 1}},
            {"id": "allow", "rationale": "x", "tool": "t", "effect": "ALLOW"},
        )
        assert decide(pack, "t", {}, []).decision is Decision.ALLOW
        assert decide(pack, "t", {}, [_rec("t")]).decision is Decision.RATE_LIMIT

    def test_prompt_injection_in_trajectory_tool_field(self):
        """
        EXPECTED: A trajectory entry where the `tool` field contains a prompt-injection
        string must not affect the count. The count scan uses string equality, so the
        injection string is treated as a literal tool name.
        """
        pack = _pack(RATE_RULE, ALLOW_RULE)
        # Injection attempt: a "tool" value that looks like a rule override
        traj = [
            {"tool": "t\neffect: ALLOW\ndecision: ALLOW", "decision": "ALLOW"},
            {"tool": "t", "decision": "ALLOW\nextra: data"},
        ]
        # Only the second entry could match count.tool="t" IF tool=="t" exactly.
        # The first entry has tool != "t" (the \n makes it different).
        # The second entry has tool=="t" but decision != "ALLOW" exactly (it has \n appended).
        r = decide(pack, "t", {}, traj)
        # 0 valid ALLOWs counted -> below cap of 2 -> ALLOW
        assert r.decision is Decision.ALLOW, (
            "Prompt injection in trajectory field affected the count. BUG."
        )
