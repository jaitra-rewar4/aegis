"""
test_phase3_engine.py — slice 3a proof suite (ADR 0006 §a/§b).

Covers the two newly-real verdicts at the engine and loop layers:
  - RATE_LIMIT as a COUNT over the recorded trajectory (never a clock): totality on
    missing/empty/junk trajectories, threshold crossing, ALLOW-only counting, counting a
    different tool than the one gated, first-match precedence, conjunction with when/after,
    and a determinism replay.
  - The total effect->Decision mapping (all four effects).
  - The loop's verdict split: RATE_LIMIT and REQUIRE_APPROVAL each produce a DISTINCT,
    non-executing refusal; only ALLOW executes.

Engine verdicts are taken from decide(); nothing is hardcoded.
"""

from __future__ import annotations

from unittest.mock import MagicMock

import pytest

from core.decision import Decision
from core.loop import run_loop
from policy.engine import decide
from policy.schema import PolicyError, validate
from demos.tools import TOOL_REGISTRY, TOOL_SCHEMAS


# --- helpers -----------------------------------------------------------------------


def _pack(*rules: dict, default: str = "deny"):
    return validate({"version": 1, "default": default, "rules": list(rules)})


def _rec(tool: str, decision: str = "ALLOW") -> dict:
    """A minimal well-formed trajectory record (matches the audit shape)."""
    return {"tool": tool, "params": {}, "decision": decision, "rule": "x"}


RATE_RULE = {
    "id": "cap",
    "rationale": "at most 2 issue_refund per run",
    "tool": "issue_refund",
    "effect": "RATE_LIMIT",
    "count": {"tool": "issue_refund", "max": 2},
}
ALLOW_REFUND = {"id": "allow", "rationale": "below cap", "tool": "issue_refund", "effect": "ALLOW"}


# --- schema: the count clause ------------------------------------------------------


def test_count_clause_accepted_and_stored():
    pack = _pack(RATE_RULE, ALLOW_REFUND)
    clause = pack.rules[0].count
    assert clause is not None
    assert (clause.tool, clause.max) == ("issue_refund", 2)
    assert pack.rules[1].count is None  # a rule without the clause


@pytest.mark.parametrize(
    "bad_count",
    [
        "nope",                                   # non-dict
        5,                                        # non-dict
        {"tool": "t"},                            # missing max
        {"max": 3},                               # missing tool
        {"tool": "t", "max": 3, "extra": 1},      # unknown key
        {"tool": "", "max": 3},                   # empty tool
        {"tool": 5, "max": 3},                    # non-string tool
        {"tool": "t", "max": -1},                 # negative max
        {"tool": "t", "max": 1.5},                # non-int max
        {"tool": "t", "max": True},               # bool max (isinstance(True,int) trap)
        {"tool": "t", "max": "3"},                # string max
    ],
)
def test_malformed_count_rejects_whole_pack(bad_count):
    with pytest.raises(PolicyError):
        _pack({"id": "r", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT", "count": bad_count})


def test_count_max_zero_is_accepted():
    # max:0 is allowed (rate-limited from the very first call) — pinned in ADR 0006 §a.
    pack = _pack({"id": "r", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
                  "count": {"tool": "t", "max": 0}})
    assert pack.rules[0].count.max == 0


# --- engine: count totality and semantics ------------------------------------------


def test_below_cap_allows_at_cap_rate_limits():
    pack = _pack(RATE_RULE, ALLOW_REFUND)
    # 0 prior -> ALLOW, 1 prior -> ALLOW, 2 prior -> RATE_LIMIT (the 3rd call).
    assert decide(pack, "issue_refund", {}, []).decision is Decision.ALLOW
    assert decide(pack, "issue_refund", {}, [_rec("issue_refund")]).decision is Decision.ALLOW
    traj2 = [_rec("issue_refund"), _rec("issue_refund")]
    out = decide(pack, "issue_refund", {}, traj2)
    assert out.decision is Decision.RATE_LIMIT
    assert out.rule_id == "cap"


@pytest.mark.parametrize("non_allow", ["DENY", "RATE_LIMIT", "REQUIRE_APPROVAL", "allow", True])
def test_only_allowed_records_count(non_allow):
    # Any non-ALLOW prior record (a DENY, or a real RATE_LIMIT / REQUIRE_APPROVAL record now
    # that those verdicts exist, or a lowercase/bool forgery) must NOT count toward the cap —
    # only an exact "ALLOW" string does. Two non-counting records + one real ALLOW = 1 < cap 2.
    pack = _pack(RATE_RULE, ALLOW_REFUND)
    traj = [_rec("issue_refund", non_allow), _rec("issue_refund", non_allow), _rec("issue_refund")]
    assert decide(pack, "issue_refund", {}, traj).decision is Decision.ALLOW


def test_count_can_target_a_different_tool():
    # REQUIRE_APPROVAL on export_data once read_customer has been ALLOWed >= 2 times.
    rule = {"id": "gate", "rationale": "x", "tool": "export_data", "effect": "REQUIRE_APPROVAL",
            "count": {"tool": "read_customer", "max": 2}}
    allow_export = {"id": "ok", "rationale": "x", "tool": "export_data", "effect": "ALLOW"}
    pack = _pack(rule, allow_export)
    assert decide(pack, "export_data", {}, [_rec("read_customer")]).decision is Decision.ALLOW
    two = [_rec("read_customer"), _rec("read_customer")]
    assert decide(pack, "export_data", {}, two).decision is Decision.REQUIRE_APPROVAL


@pytest.mark.parametrize("trajectory", [None, [], [123, "junk", None, {"no": "fields"}, {"tool": 1}]])
def test_count_total_on_missing_and_junk_trajectory(trajectory):
    # max>=1 over a None/empty/junk trajectory counts 0 ALLOWs -> below cap -> ALLOW.
    pack = _pack(RATE_RULE, ALLOW_REFUND)
    assert decide(pack, "issue_refund", {}, trajectory).decision is Decision.ALLOW


def test_count_max_zero_fires_on_first_call():
    pack = _pack({"id": "r", "rationale": "x", "tool": "t", "effect": "RATE_LIMIT",
                  "count": {"tool": "t", "max": 0}})
    # 0 >= 0 holds immediately, even with no history.
    assert decide(pack, "t", {}, []).decision is Decision.RATE_LIMIT


def test_pack_without_count_is_unchanged_by_trajectory():
    # A rule with no count clause must never consult the trajectory (2a/2b unchanged).
    pack = _pack({"id": "a", "rationale": "x", "tool": "t", "effect": "ALLOW"})
    big = [_rec("t") for _ in range(100)]
    assert decide(pack, "t", {}, big).decision is Decision.ALLOW
    assert decide(pack, "t", {}, None).decision is Decision.ALLOW


def test_count_conjunctive_with_when():
    # The rate rule also carries a when; both must hold for it to fire.
    rule = {"id": "cap", "rationale": "x", "tool": "wire", "effect": "RATE_LIMIT",
            "count": {"tool": "wire", "max": 1}, "when": {"amount": {"max": 100}}}
    allow = {"id": "ok", "rationale": "x", "tool": "wire", "effect": "ALLOW"}
    pack = _pack(rule, allow)
    traj = [_rec("wire")]
    # over cap AND amount<=100 -> RATE_LIMIT
    assert decide(pack, "wire", {"amount": 50}, traj).decision is Decision.RATE_LIMIT
    # over cap BUT amount>100 -> rate rule's when fails -> falls to ALLOW
    assert decide(pack, "wire", {"amount": 500}, traj).decision is Decision.ALLOW


def test_count_conjunctive_with_after():
    # A rule carrying BOTH after and count: it fires only when a prior export_data was ALLOWed
    # AND issue_refund has been ALLOWed >= 2 times. All four combinations checked.
    rule = {"id": "gate", "rationale": "x", "tool": "issue_refund", "effect": "REQUIRE_APPROVAL",
            "after": {"tool": "export_data"}, "count": {"tool": "issue_refund", "max": 2}}
    allow = {"id": "ok", "rationale": "x", "tool": "issue_refund", "effect": "ALLOW"}
    pack = _pack(rule, allow)
    two_refunds = [_rec("issue_refund"), _rec("issue_refund")]
    # after holds + count holds -> REQUIRE_APPROVAL
    assert decide(pack, "issue_refund", {}, [_rec("export_data"), *two_refunds]).decision is Decision.REQUIRE_APPROVAL
    # after holds, count does NOT (only 1 refund) -> falls to ALLOW
    assert decide(pack, "issue_refund", {}, [_rec("export_data"), _rec("issue_refund")]).decision is Decision.ALLOW
    # count holds, after does NOT (no export_data) -> falls to ALLOW
    assert decide(pack, "issue_refund", {}, two_refunds).decision is Decision.ALLOW
    # neither holds -> falls to ALLOW
    assert decide(pack, "issue_refund", {}, []).decision is Decision.ALLOW


# --- engine: total effect mapping --------------------------------------------------


@pytest.mark.parametrize(
    "effect,expected",
    [
        ("ALLOW", Decision.ALLOW),
        ("DENY", Decision.DENY),
        ("RATE_LIMIT", Decision.RATE_LIMIT),
        ("REQUIRE_APPROVAL", Decision.REQUIRE_APPROVAL),
    ],
)
def test_effect_maps_to_its_decision(effect, expected):
    pack = _pack({"id": "r", "rationale": "x", "tool": "t", "effect": effect})
    assert decide(pack, "t", {}, []).decision is expected


# --- determinism -------------------------------------------------------------------


def test_rate_limit_is_deterministic_across_replays():
    pack = _pack(RATE_RULE, ALLOW_REFUND)
    traj = [_rec("issue_refund"), _rec("issue_refund")]
    results = {(decide(pack, "issue_refund", {}, traj).decision,
                decide(pack, "issue_refund", {}, traj).rule_id) for _ in range(50)}
    assert results == {(Decision.RATE_LIMIT, "cap")}


def test_require_approval_is_deterministic_across_replays():
    rule = {"id": "gate", "rationale": "x", "tool": "export_data", "effect": "REQUIRE_APPROVAL"}
    pack = _pack(rule)
    results = {(decide(pack, "export_data", {}, []).decision,
                decide(pack, "export_data", {}, []).rule_id) for _ in range(50)}
    assert results == {(Decision.REQUIRE_APPROVAL, "gate")}


# --- loop: the verdict split (uses the default pack via the autouse fixture) --------


def _one_turn(*blocks: dict):
    def _fn(_messages):
        if not getattr(_fn, "done", False):
            _fn.done = True
            return list(blocks)
        return [{"type": "text", "text": "done"}]
    return _fn


def test_require_approval_is_held_not_executed(audit_log):
    # export_data -> REQUIRE_APPROVAL in the default pack. The tool must NOT run, and the
    # result message must be the distinct approval message (not a DENY).
    executed = MagicMock(return_value="should not run")
    registry = dict(TOOL_REGISTRY)
    registry["export_data"] = executed
    trail = run_loop(
        system_prompt="t", initial_user_message="u",
        tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
        model_turn_fn=_one_turn({"type": "tool_use", "id": "e1", "name": "export_data", "input": {}}),
    )
    assert trail[-1]["decision"] == "REQUIRE_APPROVAL"
    assert trail[-1]["rule"] == "exports.require_approval"
    executed.assert_not_called()


def _capture_turn(*blocks: dict):
    """A stub that emits `blocks` on the first turn, then captures the messages it receives
    on the second turn (which carry the tool_result content the model sees) and stops."""
    state = {"done": False, "messages": None}

    def _fn(messages):
        if not state["done"]:
            state["done"] = True
            return list(blocks)
        state["messages"] = messages
        return [{"type": "text", "text": "done"}]

    _fn.state = state
    return _fn


def _last_tool_result_text(turn_fn) -> str:
    # The tool_results are fed back as a user message before the 2nd model turn. Stringify the
    # whole captured message structure and search it — robust to the exact nesting.
    return str(turn_fn.state["messages"])


def test_rate_limit_message_is_distinct_from_deny(audit_log):
    # The model must see a RATE_LIMIT-specific message, not a DENY, so it does not read a
    # transient cap as a permanent block. max:0 makes the default refund rule... no — use a
    # direct 4th-call crossing on issue_refund (cap 3 in the default pack).
    registry = dict(TOOL_REGISTRY)
    registry["issue_refund"] = MagicMock(return_value="ok")
    blocks = [{"type": "tool_use", "id": f"r{i}", "name": "issue_refund", "input": {}} for i in range(4)]
    turn = _capture_turn(*blocks)
    run_loop(system_prompt="t", initial_user_message="u", tool_registry=registry,
             tool_schemas=TOOL_SCHEMAS, log_path=audit_log, model_turn_fn=turn)
    text = _last_tool_result_text(turn)
    assert "[AEGIS RATE_LIMIT]" in text
    assert "[AEGIS DENY]" not in text


def test_require_approval_message_is_distinct_from_deny(audit_log):
    registry = dict(TOOL_REGISTRY)
    registry["export_data"] = MagicMock(return_value="ok")
    turn = _capture_turn({"type": "tool_use", "id": "e1", "name": "export_data", "input": {}})
    run_loop(system_prompt="t", initial_user_message="u", tool_registry=registry,
             tool_schemas=TOOL_SCHEMAS, log_path=audit_log, model_turn_fn=turn)
    text = _last_tool_result_text(turn)
    assert "[AEGIS REQUIRE_APPROVAL]" in text
    assert "[AEGIS DENY]" not in text


def test_rate_limit_crossing_in_a_real_run(audit_log):
    # Four issue_refund calls in one turn: 1-3 ALLOW (and execute), the 4th RATE_LIMIT (and
    # does not execute). The default pack caps at 3.
    executed = MagicMock(return_value="refunded")
    registry = dict(TOOL_REGISTRY)
    registry["issue_refund"] = executed
    blocks = [{"type": "tool_use", "id": f"r{i}", "name": "issue_refund", "input": {}} for i in range(4)]
    trail = run_loop(
        system_prompt="t", initial_user_message="u",
        tool_registry=registry, tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
        model_turn_fn=_one_turn(*blocks),
    )
    decisions = [r["decision"] for r in trail]
    assert decisions == ["ALLOW", "ALLOW", "ALLOW", "RATE_LIMIT"]
    # The body ran exactly for the three ALLOWs, never for the rate-limited 4th.
    assert executed.call_count == 3
