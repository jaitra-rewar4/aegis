"""
test_write_ahead_audit.py — ADR 0002 write-ahead / fail-closed audit proof suite.

Red-team target: the new invariant "no action executes that was not first durably
logged."  This suite attacks both the happy path (proving the ordering) and the
adversarial path (forcing audit failure and verifying fail-closed behaviour).

Expected Aegis decisions per test (ADR 0002, chosen Option 3):
  - Normal ALLOW:             action executes, record on disk before execution.
  - Normal DENY:              action refused, record on disk (still write-ahead).
  - Audit failure + ALLOW:    action NOT executed, is_error result with marker.
  - Audit failure + DENY:     action NOT executed, is_error result with marker
                               (NOT the policy denial text — operational precedes policy).
  - Self-healed run:          first action refused/unlogged, second executes and is logged.

Test inventory (7 test classes, 16 individual tests):
  1. TestWriteAheadOrdering         — executed => already logged structural proof.
  2. TestFailClosedOnAuditFailure   — forced OSError blocks execution.
  3. TestDenyPlusAuditFailure       — DENY + audit failure => operational refusal wins.
  4. TestSurfacing                  — AuditUnavailableWarning emitted + escalatable.
  5. TestSelfHealing                — run recovers when log becomes writable again.
  6. TestDurabilitySmoke            — record json-parseable from disk immediately.
  7. TestRegressionNoDuplication    — file record count == returned trail length.
"""

from __future__ import annotations

import json
import warnings
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock

import pytest

# conftest.py puts the repo root on sys.path.
import core.audit as audit_mod
import core.loop as loop_mod
from core.loop import (
    AUDIT_UNAVAILABLE_MARKER,
    AuditUnavailableWarning,
    run_loop,
)
from demos.tools import TOOL_REGISTRY, TOOL_SCHEMAS


# ---------------------------------------------------------------------------
# Shared helpers  (match style in test_core_proofs.py)
# ---------------------------------------------------------------------------

def _stub_turns(*turns: list[dict]) -> Any:
    """Return a model_turn_fn that replays the given turns in order, then stops."""
    turns_list = list(turns)
    idx: dict[str, int] = {"n": 0}

    def _fn(_messages: list[dict]) -> list[dict]:
        if idx["n"] < len(turns_list):
            result = turns_list[idx["n"]]
        else:
            result = [{"type": "text", "text": "Done."}]
        idx["n"] += 1
        return result

    return _fn


def _read_records(log_path: Path) -> list[dict]:
    """Parse every JSONL line in the log and return as a list of dicts."""
    if not log_path.exists():
        return []
    records = []
    for line in log_path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if line:
            records.append(json.loads(line))
    return records


# ---------------------------------------------------------------------------
# Test 1 — Write-ahead ordering: executed => already logged
# ---------------------------------------------------------------------------

class TestWriteAheadOrdering:
    """
    Structural proof that the audit record lands on disk BEFORE the tool
    function is entered.  We register a spy tool that, during its own
    execution, reads the audit file and asserts its own ALLOW record is
    already present.  If the record were appended AFTER execution (the old
    bug), the spy would see an empty or missing file.

    Expected Aegis decision: ALLOW (lookup_customer is a benign tool).
    """

    def test_record_on_disk_before_tool_executes(self, audit_log: Path):
        """
        The spy tool opens the audit log from inside its own body and asserts
        that its ALLOW record already exists.  This is a structural proof of
        write-ahead ordering — it cannot be gamed by reading the code.
        """
        spy_saw_its_own_record: dict[str, Any] = {}

        def spy_lookup(*, customer_id: str) -> str:
            # This function body runs DURING tool execution.
            # Under write-ahead ordering the record should already be on disk.
            records = _read_records(audit_log)
            # Capture what we see so the outer scope can assert on it.
            spy_saw_its_own_record["count"] = len(records)
            spy_saw_its_own_record["records"] = records
            if records:
                spy_saw_its_own_record["last"] = records[-1]
            return f"spy result for {customer_id}"

        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["lookup_customer"] = spy_lookup

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "wa1", "name": "lookup_customer",
              "input": {"customer_id": "C001"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="write-ahead proof",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        # Outer assertion: trail has one record after the run.
        assert len(trail) == 1, (
            f"Expected 1 audit record in trail, got {len(trail)}"
        )
        assert trail[0]["decision"] == "ALLOW"
        assert trail[0]["tool"] == "lookup_customer"

        # KEY assertion: the spy saw its own record WHILE executing.
        assert spy_saw_its_own_record.get("count", 0) >= 1, (
            "BUG (ADR 0002 violation): audit record was NOT on disk when the "
            "tool function began executing — write-ahead ordering is broken."
        )
        last = spy_saw_its_own_record.get("last", {})
        assert last.get("tool") == "lookup_customer", (
            f"BUG: the most recent on-disk record at execution time was for "
            f"tool '{last.get('tool')}', not 'lookup_customer'.  "
            "Write-ahead ordering may be broken or the wrong record was written."
        )
        assert last.get("decision") == "ALLOW", (
            f"BUG: the on-disk record at execution time had decision "
            f"'{last.get('decision')}' — expected 'ALLOW'."
        )

    def test_deny_record_on_disk_before_any_execute_branch(self, audit_log: Path):
        """
        Even for a DENY, the record is written write-ahead (before any branch
        executes).  We spy on the tool registry to confirm the tool was never
        called, and separately confirm the DENY record is on disk in the trail.

        Expected Aegis decision: DENY (DROP TABLE).
        """
        mock_execute = MagicMock(return_value="should not be called")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["execute_sql"] = mock_execute

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "wa2", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="deny write-ahead proof",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        # Tool must not have executed.
        mock_execute.assert_not_called()

        # But the DENY record must still be on disk (write-ahead means logged
        # before the deny branch, which doesn't call the tool).
        disk_records = _read_records(audit_log)
        assert len(disk_records) == 1
        assert disk_records[0]["decision"] == "DENY"
        assert disk_records[0]["tool"] == "execute_sql"

        # In-memory trail must match disk.
        assert len(trail) == 1
        assert trail[0]["decision"] == "DENY"


# ---------------------------------------------------------------------------
# Test 2 — Forced audit failure blocks execution (fail-closed)
# ---------------------------------------------------------------------------

class TestFailClosedOnAuditFailure:
    """
    Monkeypatch core.loop.append_record to raise OSError.
    A benign ALLOW-candidate tool call must be refused entirely.

    Expected Aegis decision (after audit failure): operational refusal
    (AUDIT_UNAVAILABLE_MARKER) — NOT an ALLOW.  The tool must never execute.
    """

    def test_tool_not_called_when_audit_fails(self, audit_log: Path, monkeypatch):
        """
        (a) Spy tool receives ZERO calls.

        Expected: no execution.  ASSERT DIRECTION: DENY / refuse because the
        audit is unavailable — this is a forced audit-failure scenario.
        """
        spy = MagicMock(return_value="should not be called")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["lookup_customer"] = spy

        monkeypatch.setattr(loop_mod, "append_record", MagicMock(
            side_effect=OSError("disk full — simulated for test")
        ))

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "fc1", "name": "lookup_customer",
              "input": {"customer_id": "C001"}}],
        )

        with pytest.warns(AuditUnavailableWarning):
            run_loop(
                system_prompt="test",
                initial_user_message="audit failure test",
                tool_registry=patched_registry,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=turn_fn,
            )

        spy.assert_not_called()

    def test_trail_is_empty_when_audit_fails(self, audit_log: Path, monkeypatch):
        """
        (b) run_loop returns an EMPTY audit trail — no partial records.

        Expected: empty trail (the audit append raised before the record was
        added to the in-memory trail).
        """
        monkeypatch.setattr(loop_mod, "append_record", MagicMock(
            side_effect=OSError("disk full — simulated for test")
        ))

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "fc2", "name": "lookup_customer",
              "input": {"customer_id": "C002"}}],
        )

        with pytest.warns(AuditUnavailableWarning):
            trail = run_loop(
                system_prompt="test",
                initial_user_message="audit failure trail test",
                tool_registry=TOOL_REGISTRY,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=turn_fn,
            )

        assert trail == [], (
            f"BUG (ADR 0002 violation): run_loop returned a non-empty trail "
            f"({trail}) despite audit failure — a record was counted as written "
            "when it was not."
        )

    def test_tool_result_contains_audit_unavailable_marker(
        self, audit_log: Path, monkeypatch
    ):
        """
        (c) The tool_result fed back to messages is is_error=True and its
        content contains AUDIT_UNAVAILABLE_MARKER.

        We intercept the messages list to inspect the tool_result that the
        loop synthesises.  Expected: marker present in the error content.
        """
        monkeypatch.setattr(loop_mod, "append_record", MagicMock(
            side_effect=OSError("disk full — simulated for test")
        ))

        # We capture the messages list by intercepting the second call to
        # model_turn_fn — by then, run_loop has fed the tool_results back as a
        # user message (messages[-1].content is the list of tool_result dicts).
        captured_tool_results: list[dict] = []
        turns = [
            [{"type": "tool_use", "id": "fc3", "name": "lookup_customer",
              "input": {"customer_id": "C003"}}],
        ]
        turn_iter = {"n": 0}

        def model_fn(messages: list[dict]) -> list[dict]:
            if turn_iter["n"] < len(turns):
                result = turns[turn_iter["n"]]
            else:
                # Turn 2: messages[-1] is the user message containing tool_results
                # (run_loop appended it before calling us again).
                result = [{"type": "text", "text": "done"}]
                last_msg = messages[-1]
                if isinstance(last_msg.get("content"), list):
                    captured_tool_results.extend(last_msg["content"])
            turn_iter["n"] += 1
            return result

        with pytest.warns(AuditUnavailableWarning):
            run_loop(
                system_prompt="test",
                initial_user_message="marker test",
                tool_registry=TOOL_REGISTRY,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=model_fn,
            )

        # There must be at least one tool_result with is_error=True containing the marker.
        assert len(captured_tool_results) >= 1, (
            "No tool_results were captured — the loop may not have fed the error back."
        )
        error_results = [r for r in captured_tool_results if r.get("is_error")]
        assert len(error_results) >= 1, (
            f"BUG: no is_error=True tool_result captured; got: {captured_tool_results}"
        )
        marker_results = [
            r for r in error_results
            if AUDIT_UNAVAILABLE_MARKER in r.get("content", "")
        ]
        assert len(marker_results) >= 1, (
            f"BUG (ADR 0002 'Fail-closed semantics'): the is_error tool_result does "
            f"not contain AUDIT_UNAVAILABLE_MARKER='{AUDIT_UNAVAILABLE_MARKER}'. "
            f"Captured error results: {error_results}"
        )

    def test_run_loop_returns_normally_despite_audit_failure(
        self, audit_log: Path, monkeypatch
    ):
        """
        (d) run_loop does NOT crash — it returns normally (refuse + continue).

        Expected: no exception raised.  The loop continues and returns the
        (empty) trail.
        """
        monkeypatch.setattr(loop_mod, "append_record", MagicMock(
            side_effect=OSError("disk full — simulated for test")
        ))

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "fc4", "name": "calculator",
              "input": {"expression": "1+1"}}],
        )

        # Must NOT raise — run_loop should refuse + continue.
        with pytest.warns(AuditUnavailableWarning):
            trail = run_loop(
                system_prompt="test",
                initial_user_message="no crash test",
                tool_registry=TOOL_REGISTRY,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=turn_fn,
            )

        # Returned normally (no exception).  Trail is empty (nothing was logged).
        assert isinstance(trail, list)


# ---------------------------------------------------------------------------
# Test 3 — DENY + audit failure: operational refusal wins over policy denial
# ---------------------------------------------------------------------------

class TestDenyPlusAuditFailure:
    """
    ADR 0002: "where a decision did exist it is overridden by the operational
    failure."  When the audit log is down AND the policy would DENY, the
    tool_result must contain AUDIT_UNAVAILABLE_MARKER, NOT the policy denial
    text (not [AEGIS DENY] with the rule_id).

    This is the monotonicity check: an outage can only turn ALLOW into refusal;
    it can never turn DENY into ALLOW.  We verify the outage also doesn't flip
    DENY into a different kind of error — the operational refusal is the one
    that fires because it sits in the except branch, which wraps the append
    that happens BEFORE the ALLOW/DENY branch.
    """

    def test_deny_plus_audit_failure_gives_operational_refusal(
        self, audit_log: Path, monkeypatch
    ):
        """
        Stub proposes DROP TABLE customers (would be DENY under policy).
        Audit append is patched to raise.
        Assert: zero executions and result is audit_unavailable, NOT policy denial.

        Expected Aegis decision: AUDIT_UNAVAILABLE (operational), not DENY.
        """
        mock_execute = MagicMock(return_value="should never run")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["execute_sql"] = mock_execute

        monkeypatch.setattr(loop_mod, "append_record", MagicMock(
            side_effect=OSError("disk full — simulated for DENY+failure test")
        ))

        captured_tool_results: list[dict] = []
        turns = [
            [{"type": "tool_use", "id": "df1", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        ]
        turn_iter = {"n": 0}

        def model_fn(messages: list[dict]) -> list[dict]:
            if turn_iter["n"] < len(turns):
                result = turns[turn_iter["n"]]
            else:
                result = [{"type": "text", "text": "done"}]
                last_msg = messages[-1]
                if isinstance(last_msg.get("content"), list):
                    captured_tool_results.extend(last_msg["content"])
            turn_iter["n"] += 1
            return result

        with pytest.warns(AuditUnavailableWarning):
            run_loop(
                system_prompt="test",
                initial_user_message="deny + audit failure",
                tool_registry=patched_registry,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=model_fn,
            )

        # Zero executions — tool must never run.
        mock_execute.assert_not_called()

        # The error result must contain the audit_unavailable marker.
        error_results = [r for r in captured_tool_results if r.get("is_error")]
        assert len(error_results) >= 1, (
            f"No is_error tool_result captured; captured: {captured_tool_results}"
        )
        marker_results = [
            r for r in error_results
            if AUDIT_UNAVAILABLE_MARKER in r.get("content", "")
        ]
        assert len(marker_results) >= 1, (
            f"BUG (ADR 0002 'operational refusal overrides policy branch'): "
            f"expected AUDIT_UNAVAILABLE_MARKER='{AUDIT_UNAVAILABLE_MARKER}' "
            f"in the tool_result but found policy denial text instead. "
            f"Captured error results: {error_results}"
        )

        # Also assert the policy denial text is NOT present — the operational
        # refusal must REPLACE it, not appear alongside it.
        policy_denial_results = [
            r for r in error_results
            if "[AEGIS DENY]" in r.get("content", "")
        ]
        assert len(policy_denial_results) == 0, (
            f"BUG: policy denial text '[AEGIS DENY]' appeared in the result "
            f"alongside AUDIT_UNAVAILABLE_MARKER — the operational refusal "
            "should completely replace the policy denial. "
            f"Captured: {policy_denial_results}"
        )


# ---------------------------------------------------------------------------
# Test 4 — Surfacing: AuditUnavailableWarning emitted and escalatable
# ---------------------------------------------------------------------------

class TestSurfacing:
    """
    ADR 0002 "Surfacing": the failure must reach the caller, never be silently
    swallowed.  Two sub-properties:
      (a) pytest.warns(AuditUnavailableWarning) catches the warning; it carries
          the tool name and the underlying exception text.
      (b) A caller that wants halt-the-run semantics CAN opt in by escalating
          the warning to an error.
    """

    def test_warning_emitted_with_tool_name_and_exception(
        self, audit_log: Path, monkeypatch
    ):
        """
        The AuditUnavailableWarning must be emitted and must contain:
          - the tool name  ("lookup_customer")
          - the underlying exception text ("disk full — simulated")

        Expected: warning raised, containing tool name and exception detail.
        """
        monkeypatch.setattr(loop_mod, "append_record", MagicMock(
            side_effect=OSError("disk full — simulated surfacing test")
        ))

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "sf1", "name": "lookup_customer",
              "input": {"customer_id": "C001"}}],
        )

        with pytest.warns(AuditUnavailableWarning) as warning_list:
            run_loop(
                system_prompt="test",
                initial_user_message="surfacing test",
                tool_registry=TOOL_REGISTRY,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=turn_fn,
            )

        assert len(warning_list) >= 1, (
            "BUG (ADR 0002 'Surfacing'): AuditUnavailableWarning was NOT emitted "
            "when audit append failed — the failure was silently swallowed."
        )

        # The warning message must contain the tool name.
        warning_text = str(warning_list[0].message)
        assert "lookup_customer" in warning_text, (
            f"BUG: AuditUnavailableWarning does not name the tool. "
            f"Warning text: {warning_text!r}"
        )

        # The warning message must contain the underlying exception text.
        assert "disk full" in warning_text, (
            f"BUG: AuditUnavailableWarning does not include the underlying "
            f"exception text. Warning text: {warning_text!r}"
        )

    def test_warning_escalatable_to_error(self, audit_log: Path, monkeypatch):
        """
        A caller that installs warnings.simplefilter("error", AuditUnavailableWarning)
        must see the warning raised as an exception.  This proves the warning is
        a real warning (not swallowed) and that halt-the-run semantics are achievable
        without modifying the loop code.

        Expected: raises AuditUnavailableWarning (promoted to error).
        """
        monkeypatch.setattr(loop_mod, "append_record", MagicMock(
            side_effect=OSError("disk full — simulated escalation test")
        ))

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "sf2", "name": "calculator",
              "input": {"expression": "2+2"}}],
        )

        with warnings.catch_warnings():
            warnings.simplefilter("error", AuditUnavailableWarning)
            with pytest.raises(AuditUnavailableWarning):
                run_loop(
                    system_prompt="test",
                    initial_user_message="escalation test",
                    tool_registry=TOOL_REGISTRY,
                    tool_schemas=TOOL_SCHEMAS,
                    log_path=audit_log,
                    model_turn_fn=turn_fn,
                )


# ---------------------------------------------------------------------------
# Test 5 — Self-healing: run recovers when logging recovers
# ---------------------------------------------------------------------------

class TestSelfHealing:
    """
    ADR 0002 "Self-healing": there is no latched 'log is down' state.  The
    append is attempted fresh for every action.

    Attack scenario:
      Turn 1 — benign call during outage → refused, not executed, not logged.
      Turn 2 — benign call after recovery → executes, logged on disk.

    Expected decisions:
      Turn 1: operational refusal (audit unavailable).
      Turn 2: ALLOW — executed and on disk.
    """

    def test_recovery_after_single_failure(self, audit_log: Path, monkeypatch):
        """
        A stateful monkeypatched append_record raises on the first call, then
        delegates to the real core.audit.append_record.  One run_loop invocation
        spanning two turns proves no latched state.

        Expected:
          - Action 1: refused, not executed, NOT in returned trail.
          - Action 2: executed, record IS in returned trail and on disk.
        """
        real_append = audit_mod.append_record
        call_count: dict[str, int] = {"n": 0}

        def flaky_append(**kwargs):
            call_count["n"] += 1
            if call_count["n"] <= 1:
                raise OSError("transient disk error — simulated first call only")
            return real_append(**kwargs)

        monkeypatch.setattr(loop_mod, "append_record", flaky_append)

        spy_turn2 = MagicMock(return_value="recovered result")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["calculator"] = spy_turn2

        # Turn 1: outage — calculator call during failure.
        # Turn 2: recovery — same calculator call but now the log is up.
        # We use two separate tool_use turns.
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "sh1", "name": "calculator",
              "input": {"expression": "1+1"}}],
            [{"type": "tool_use", "id": "sh2", "name": "calculator",
              "input": {"expression": "2+2"}}],
        )

        with pytest.warns(AuditUnavailableWarning):
            trail = run_loop(
                system_prompt="test",
                initial_user_message="self-healing test",
                tool_registry=patched_registry,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=turn_fn,
            )

        # Action 1: refused, not in trail.
        # Action 2: allowed, in trail.
        assert len(trail) == 1, (
            f"BUG (ADR 0002 'Self-healing'): expected trail length 1 (one refused, "
            f"one allowed), got {len(trail)}.  Trail: {trail}"
        )
        assert trail[0]["decision"] == "ALLOW"
        assert trail[0]["tool"] == "calculator"

        # Action 2 must have executed, and ONLY action 2 — action 1 was refused
        # before the execute branch, so the spy must show exactly one call.
        # (assert_called_once, not assert_called: a regression where the refused
        # action also executed would slip past a weaker at-least-once check.)
        spy_turn2.assert_called_once()

        # The record must also be on disk.
        disk_records = _read_records(audit_log)
        assert len(disk_records) == 1, (
            f"BUG: expected 1 disk record after recovery, got {len(disk_records)}.  "
            f"Records: {disk_records}"
        )
        assert disk_records[0]["decision"] == "ALLOW"
        assert disk_records[0]["tool"] == "calculator"

    def test_no_latched_state_after_multiple_failures(self, audit_log: Path, monkeypatch):
        """
        Raise on the first N=3 calls, then recover.  The N+1th call must
        succeed normally — proves the outage counter is not latched.

        Expected: first 3 actions refused/unlogged, 4th executes and is logged.
        """
        real_append = audit_mod.append_record
        call_count: dict[str, int] = {"n": 0}
        FAIL_COUNT = 3

        def flaky_append(**kwargs):
            call_count["n"] += 1
            if call_count["n"] <= FAIL_COUNT:
                raise OSError(f"simulated failure {call_count['n']}")
            return real_append(**kwargs)

        monkeypatch.setattr(loop_mod, "append_record", flaky_append)

        spy_calc = MagicMock(return_value="ok")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["calculator"] = spy_calc

        # Four turns: first three during outage, fourth after recovery.
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "sh3a", "name": "calculator",
              "input": {"expression": "1+1"}}],
            [{"type": "tool_use", "id": "sh3b", "name": "calculator",
              "input": {"expression": "2+2"}}],
            [{"type": "tool_use", "id": "sh3c", "name": "calculator",
              "input": {"expression": "3+3"}}],
            [{"type": "tool_use", "id": "sh3d", "name": "calculator",
              "input": {"expression": "4+4"}}],
        )

        with pytest.warns(AuditUnavailableWarning):
            trail = run_loop(
                system_prompt="test",
                initial_user_message="multi-failure self-healing",
                tool_registry=patched_registry,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=turn_fn,
            )

        # Only the 4th call (after recovery) should be in the trail.
        assert len(trail) == 1, (
            f"BUG (ADR 0002 'Self-healing'): expected exactly 1 record in trail "
            f"(the recovered one), got {len(trail)}.  Trail: {trail}"
        )
        assert trail[0]["decision"] == "ALLOW"

        # The 4th call must have actually executed — and ONLY the 4th.  The
        # three refused actions must never reach the tool, so exactly one call.
        # (== 1, not >= 1: an at-least-once check would pass even if the refused
        # actions executed — the precise regression this test exists to catch.)
        assert spy_calc.call_count == 1, (
            f"BUG: expected exactly 1 calculator execution (the recovered 4th "
            f"action), got {spy_calc.call_count}."
        )

        disk_records = _read_records(audit_log)
        assert len(disk_records) == 1


# ---------------------------------------------------------------------------
# Test 6 — Durability smoke check
# ---------------------------------------------------------------------------

class TestDurabilitySmoke:
    """
    After a normal allowed run, the record must be immediately readable from
    disk as valid JSON.  This confirms flush+fsync delivered durable storage
    (not just an OS buffer).

    NOTE: True fsync verification requires a crash harness (crash the process
    between append and execute and verify the record survived).  That is
    out of scope per ADR 0002 "Out of scope."  This smoke test only proves
    the file is readable and parseable immediately — which catches the "forgot
    to flush" regression without needing a crash harness.
    """

    def test_record_json_parseable_immediately_after_allow(self, audit_log: Path, db_reset):
        """
        After a successful ALLOW run, the JSONL file must exist, have at
        least one line, and each line must json.loads() cleanly.

        Expected: ALLOW decision logged durably.
        """
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "dur1", "name": "lookup_customer",
              "input": {"customer_id": "C001"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="durability smoke",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert audit_log.exists(), (
            "BUG: audit log file does not exist after a successful run."
        )

        raw_lines = [
            line.strip()
            for line in audit_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(raw_lines) >= 1, (
            "BUG: audit log file is empty after a successful run."
        )

        for i, line in enumerate(raw_lines):
            try:
                parsed = json.loads(line)
            except json.JSONDecodeError as exc:
                pytest.fail(
                    f"BUG: audit log line {i} is not valid JSON: {exc}.  "
                    f"Line content: {line!r}"
                )
            assert "tool" in parsed, f"Parsed record missing 'tool' field: {parsed}"
            assert "decision" in parsed, (
                f"Parsed record missing 'decision' field: {parsed}"
            )

        # Trail and disk must agree.
        assert len(raw_lines) == len(trail), (
            f"BUG: disk has {len(raw_lines)} lines but trail has {len(trail)} records."
        )

    def test_record_fields_complete_after_deny(self, audit_log: Path, db_reset):
        """
        DENY records must also be durably stored with all required fields.

        Expected: DENY record json-parseable immediately from disk.

        db_reset requested for consistency with the sibling test: the DROP is
        expected to be DENYed (never executed), but if that expectation ever
        broke, the fixture keeps the damage from leaking into other tests.
        """
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "dur2", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        )

        run_loop(
            system_prompt="test",
            initial_user_message="deny durability smoke",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        raw_lines = [
            line.strip()
            for line in audit_log.read_text(encoding="utf-8").splitlines()
            if line.strip()
        ]
        assert len(raw_lines) == 1

        record = json.loads(raw_lines[0])
        required_fields = {
            "ts", "session_id", "agent_id", "tool", "params",
            "decision", "rule", "approver", "prev_hash", "hash",
        }
        missing = required_fields - set(record.keys())
        assert not missing, (
            f"BUG: DENY record is missing required fields: {missing}. "
            f"Record: {record}"
        )
        assert record["decision"] == "DENY"


# ---------------------------------------------------------------------------
# Test 7 — Regression guard: no records lost or duplicated by the reorder
# ---------------------------------------------------------------------------

class TestRegressionNoDuplication:
    """
    The old bug was execute-then-append.  The fix (write-ahead) reorders the
    append before execute.  The regression guard confirms:
      - No record is lost (disk count == trail length).
      - No record is duplicated (each tool_use produces exactly one record).

    We use a mixed ALLOW+DENY run to exercise both branches.
    """

    def test_disk_count_equals_trail_length_mixed_run(self, audit_log: Path, db_reset):
        """
        A mixed sequence (ALLOW + DENY) must produce exactly one disk record
        per tool_use block — no duplicates, no missing records.

        Expected: 2 records on disk, 2 in trail, in order (ALLOW first, DENY second).
        """
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "rg1", "name": "calculator",
              "input": {"expression": "7*7"}}],
            [{"type": "tool_use", "id": "rg2", "name": "execute_sql",
              "input": {"sql": "DROP TABLE orders"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="regression guard",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        disk_records = _read_records(audit_log)

        assert len(disk_records) == len(trail), (
            f"BUG (regression — reorder duplication/loss): disk has "
            f"{len(disk_records)} records but trail has {len(trail)}.  "
            f"A write-ahead reorder bug may have introduced duplication or loss."
        )
        assert len(trail) == 2, (
            f"Expected exactly 2 records (one ALLOW, one DENY), got {len(trail)}."
        )
        assert trail[0]["decision"] == "ALLOW"
        assert trail[1]["decision"] == "DENY"

        # Cross-check disk order matches trail order.
        for i, (disk_r, trail_r) in enumerate(zip(disk_records, trail)):
            assert disk_r["tool"] == trail_r["tool"], (
                f"BUG: disk record {i} tool '{disk_r['tool']}' != "
                f"trail record {i} tool '{trail_r['tool']}'"
            )
            assert disk_r["decision"] == trail_r["decision"], (
                f"BUG: disk record {i} decision '{disk_r['decision']}' != "
                f"trail record {i} decision '{trail_r['decision']}'"
            )

    def test_no_duplicates_single_allow(self, audit_log: Path):
        """
        A single ALLOW must produce exactly one record on disk, not two
        (which would happen if the old append-after-execute code also ran).

        Expected: exactly 1 record on disk.
        """
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "rg3", "name": "calculator",
              "input": {"expression": "3*3"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="no duplicate test",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        disk_records = _read_records(audit_log)

        assert len(disk_records) == 1, (
            f"BUG: expected exactly 1 disk record for 1 ALLOW, "
            f"got {len(disk_records)}.  Records: {disk_records}"
        )
        assert len(trail) == 1
        assert disk_records[0]["tool"] == "calculator"
        assert disk_records[0]["decision"] == "ALLOW"

    def test_no_duplicates_single_deny(self, audit_log: Path):
        """
        A single DENY must produce exactly one record on disk, not two.

        Expected: exactly 1 record on disk.
        """
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "rg4", "name": "execute_sql",
              "input": {"sql": "DELETE FROM customers"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="no duplicate deny test",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        disk_records = _read_records(audit_log)

        assert len(disk_records) == 1, (
            f"BUG: expected exactly 1 disk record for 1 DENY, "
            f"got {len(disk_records)}.  Records: {disk_records}"
        )
        assert len(trail) == 1
        assert disk_records[0]["decision"] == "DENY"
