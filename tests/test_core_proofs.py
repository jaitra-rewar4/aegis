"""
test_core_proofs.py — Phase 1 acceptance criteria (MUST ALL PASS).

These tests prove the load-bearing claims of the Phase 1 walking skeleton:
  1. DROP TABLE is DENYed and the destructive side effect never executes.
  2. Benign tools (lookup_customer, calculator) are ALLOWed and actually execute.
  3. gateway.evaluate() is deterministic across repeated calls and is unaffected
     by the context argument.
  4. Every evaluated action (ALLOW and DENY) produces exactly one JSONL audit
     record with the expected fields and decision.
  5. Invariant 1: a text block + a tool_use block in the same turn audits ONLY
     the tool_use; model text is never evaluated.

No ANTHROPIC_API_KEY is required — all tests use the model_turn_fn stub path.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any
from unittest.mock import MagicMock, patch

import pytest

# Import paths are made importable by conftest.py (repo root on sys.path).
from core.decision import Decision
from core.gateway import evaluate
from core.loop import run_loop
from demos.tools import TOOL_REGISTRY, TOOL_SCHEMAS, _reset_db


# ---------------------------------------------------------------------------
# Helpers
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
# Test 1 — DROP TABLE is DENYed; destructive side effect never executes
# ---------------------------------------------------------------------------

class TestDropTableDenied:
    """Prove that a DROP TABLE proposal is DENYed before the tool executes."""

    def test_gateway_evaluate_denies_drop_table(self):
        """evaluate() returns DENY with the correct rule_id for DROP TABLE SQL."""
        result = evaluate("execute_sql", {"sql": "DROP TABLE customers"}, context=None)
        assert result.decision is Decision.DENY
        assert result.rule_id == "sql.deny_destructive"

    def test_run_loop_denies_drop_table_and_audits(self, audit_log: Path, db_reset):
        """run_loop yields DENY in the audit trail for a DROP TABLE turn."""
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "t1", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        )

        trail = run_loop(
            system_prompt="test",
            initial_user_message="drop it",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 1
        record = trail[0]
        assert record["decision"] == "DENY"
        assert record["rule"] == "sql.deny_destructive"
        assert record["tool"] == "execute_sql"

    def test_drop_table_does_not_execute_proven_by_row_survival(
        self, audit_log: Path, db_reset
    ):
        """
        Seed assertion: customers table starts populated.
        After a DENYed DROP TABLE, the table still exists and the rows survive.
        This proves decision-before-execution structurally — if execution had
        happened, the subsequent SELECT would return no rows.
        """
        import demos.tools as t

        # Verify seed is in place
        row_count_before = t._db_conn.execute(
            "SELECT COUNT(*) FROM customers"
        ).fetchone()[0]
        assert row_count_before > 0, "Seed did not populate customers table"

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "t2", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        )
        run_loop(
            system_prompt="test",
            initial_user_message="drop it",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        # Table must still exist and contain the original rows
        row_count_after = t._db_conn.execute(
            "SELECT COUNT(*) FROM customers"
        ).fetchone()[0]
        assert row_count_after == row_count_before, (
            f"BUG: customers table was modified despite DENY — "
            f"before={row_count_before}, after={row_count_after}"
        )

    def test_drop_table_does_not_execute_proven_by_monkeypatch(
        self, audit_log: Path, monkeypatch
    ):
        """
        Spy-based proof: monkeypatch execute_sql in the TOOL_REGISTRY and assert
        it was NEVER called.  Complementary to the row-survival test — proves
        decision-before-execution even if the DB state check were somehow flaky.
        """
        mock_fn = MagicMock(return_value="should not be called")
        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["execute_sql"] = mock_fn

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "t3", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        )
        run_loop(
            system_prompt="test",
            initial_user_message="drop it",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        mock_fn.assert_not_called()


# ---------------------------------------------------------------------------
# Test 2 — Benign run proceeds (lookup_customer + calculator)
# ---------------------------------------------------------------------------

class TestBenignRunProceeds:
    """Prove ALLOWed tools actually execute and return results."""

    def test_lookup_customer_allowed(self, audit_log: Path, db_reset):
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "b1", "name": "lookup_customer",
              "input": {"customer_id": "C001"}}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="look up C001",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 1
        record = trail[0]
        assert record["decision"] == "ALLOW"
        assert record["rule"] == "customers.allow_lookup"
        assert record["tool"] == "lookup_customer"

    def test_calculator_allowed(self, audit_log: Path):
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "b2", "name": "calculator",
              "input": {"expression": "2 + 2"}}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="calculate 2+2",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 1
        record = trail[0]
        assert record["decision"] == "ALLOW"
        assert record["rule"] == "math.allow_calculator"
        assert record["tool"] == "calculator"

    def test_benign_tools_actually_execute_and_return_results(
        self, audit_log: Path, db_reset
    ):
        """
        Prove tools actually ran: inject a spy registry and confirm calls were made
        with the expected parameters and returned plausible output.
        """
        mock_lookup = MagicMock(
            return_value="id=C001, name=Alice, email=alice@example.com, status=active"
        )
        mock_calc = MagicMock(return_value="402")

        patched_registry = dict(TOOL_REGISTRY)
        patched_registry["lookup_customer"] = mock_lookup
        patched_registry["calculator"] = mock_calc

        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "b3", "name": "lookup_customer",
              "input": {"customer_id": "C001"}}],
            [{"type": "tool_use", "id": "b4", "name": "calculator",
              "input": {"expression": "350 * 1.15"}}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="lookup and calculate",
            tool_registry=patched_registry,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 2
        assert all(r["decision"] == "ALLOW" for r in trail)
        mock_lookup.assert_called_once_with(customer_id="C001")
        mock_calc.assert_called_once_with(expression="350 * 1.15")

    def test_full_benign_sequence_no_deny(self, audit_log: Path, db_reset):
        """Full benign sequence (mirrors run_benign.py) produces only ALLOW records."""
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "f1", "name": "lookup_customer",
              "input": {"customer_id": "C001"}}],
            [{"type": "tool_use", "id": "f2", "name": "calculator",
              "input": {"expression": "350 * 1.15"}}],
            [{"type": "text", "text": "All done."}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="do benign work",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 2
        assert all(r["decision"] == "ALLOW" for r in trail)
        assert not any(r["decision"] == "DENY" for r in trail)


# ---------------------------------------------------------------------------
# Test 3 — Determinism
# ---------------------------------------------------------------------------

class TestDeterminism:
    """Prove evaluate() is a pure function: same input -> same output, always."""

    DESTRUCTIVE_CASES = [
        ("execute_sql", {"sql": "DROP TABLE customers"}),
        ("execute_sql", {"sql": "DELETE FROM orders"}),
        ("execute_sql", {"sql": "TRUNCATE orders"}),
        ("execute_sql", {"sql": "ALTER TABLE customers ADD COLUMN x TEXT"}),
    ]

    ALLOW_CASES = [
        ("execute_sql", {"sql": "SELECT * FROM customers"}),
        ("lookup_customer", {"customer_id": "C001"}),
        ("calculator", {"expression": "1 + 1"}),
    ]

    @pytest.mark.parametrize("tool,params", DESTRUCTIVE_CASES)
    def test_repeated_calls_deny_same_result(self, tool, params):
        """DENY is stable across 50 repeated calls."""
        results = [evaluate(tool, params, context=None) for _ in range(50)]
        decisions = {r.decision for r in results}
        rule_ids = {r.rule_id for r in results}
        assert decisions == {Decision.DENY}
        assert rule_ids == {"sql.deny_destructive"}

    # Per-tool expected rule ids for ALLOW cases (ADR 0003 §e: each allowed
    # tool now has its own named rule, not a catch-all default_allow).
    _ALLOW_RULE_IDS = {
        "execute_sql": "sql.allow_other",
        "lookup_customer": "customers.allow_lookup",
        "calculator": "math.allow_calculator",
    }

    @pytest.mark.parametrize("tool,params", ALLOW_CASES)
    def test_repeated_calls_allow_same_result(self, tool, params):
        """ALLOW is stable across 50 repeated calls, with the correct pack rule id."""
        results = [evaluate(tool, params, context=None) for _ in range(50)]
        decisions = {r.decision for r in results}
        rule_ids = {r.rule_id for r in results}
        expected_rule_id = self._ALLOW_RULE_IDS[tool]
        assert decisions == {Decision.ALLOW}
        assert rule_ids == {expected_rule_id}

    def test_context_argument_does_not_affect_decision(self):
        """
        The context argument is accepted but unread in Phase 1.
        Passing wildly different context values must not change the decision.
        """
        tool = "execute_sql"
        params = {"sql": "DROP TABLE customers"}

        contexts = [
            None,
            {},
            {"session_id": "abc123"},
            {"prior_calls": ["lookup_customer", "calculator"]},
            "arbitrary string context",
            42,
            object(),
        ]
        results = [evaluate(tool, params, context=ctx) for ctx in contexts]
        assert all(r.decision is Decision.DENY for r in results)
        assert all(r.rule_id == "sql.deny_destructive" for r in results)

        # Same for ALLOW
        allow_tool = "lookup_customer"
        allow_params = {"customer_id": "C001"}
        allow_results = [
            evaluate(allow_tool, allow_params, context=ctx) for ctx in contexts
        ]
        assert all(r.decision is Decision.ALLOW for r in allow_results)


# ---------------------------------------------------------------------------
# Test 4 — Audit integrity
# ---------------------------------------------------------------------------

class TestAuditIntegrity:
    """Every evaluated action produces exactly one JSONL record with expected fields."""

    REQUIRED_FIELDS = {
        "ts", "session_id", "agent_id", "tool", "params", "decision", "rule",
        "approver", "prev_hash", "hash",
    }

    def test_deny_record_written_with_correct_fields(self, audit_log: Path, db_reset):
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "a1", "name": "execute_sql",
              "input": {"sql": "DROP TABLE customers"}}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="deny me",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 1
        record = trail[0]

        # All required fields must be present
        assert self.REQUIRED_FIELDS <= set(record.keys()), (
            f"Missing fields: {self.REQUIRED_FIELDS - set(record.keys())}"
        )
        assert record["tool"] == "execute_sql"
        assert record["params"] == {"sql": "DROP TABLE customers"}
        assert record["decision"] == "DENY"
        assert record["rule"] == "sql.deny_destructive"
        # Phase 3 slice 3d: the hash chain is live. This is the first record in a fresh log,
        # so prev_hash is None (nothing before it); hash is its real sha256.
        assert record["prev_hash"] is None
        assert isinstance(record["hash"], str) and len(record["hash"]) == 64
        # Phase 1: identity/approver fields are reserved nulls (CLAUDE.md binding)
        assert record["session_id"] is None
        assert record["agent_id"] is None
        assert record["approver"] is None
        # ts must be a non-empty string (we don't parse it; just confirm presence)
        assert isinstance(record["ts"], str) and len(record["ts"]) > 0

    def test_allow_record_written_with_correct_fields(self, audit_log: Path, db_reset):
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "a2", "name": "lookup_customer",
              "input": {"customer_id": "C002"}}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="allow me",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 1
        record = trail[0]
        assert self.REQUIRED_FIELDS <= set(record.keys())
        assert record["tool"] == "lookup_customer"
        assert record["decision"] == "ALLOW"
        assert record["rule"] == "customers.allow_lookup"
        assert record["prev_hash"] is None
        assert isinstance(record["hash"], str) and len(record["hash"]) == 64

    def test_one_record_per_tool_use_both_decisions(self, audit_log: Path, db_reset):
        """
        A mixed turn sequence (ALLOW + DENY) produces exactly one record per
        tool_use block, in order.
        """
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "a3", "name": "calculator",
              "input": {"expression": "1+1"}}],
            [{"type": "tool_use", "id": "a4", "name": "execute_sql",
              "input": {"sql": "DROP TABLE orders"}}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="mixed",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 2
        assert trail[0]["decision"] == "ALLOW"
        assert trail[1]["decision"] == "DENY"

    def test_audit_records_written_to_jsonl_file(self, audit_log: Path, db_reset):
        """Audit records written in-memory also appear on disk as valid JSONL."""
        turn_fn = _stub_turns(
            [{"type": "tool_use", "id": "a5", "name": "calculator",
              "input": {"expression": "7*6"}}],
            [{"type": "tool_use", "id": "a6", "name": "execute_sql",
              "input": {"sql": "DELETE FROM customers"}}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="write to file",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        disk_records = _read_records(audit_log)
        assert len(disk_records) == 2
        assert disk_records[0]["decision"] == "ALLOW"
        assert disk_records[1]["decision"] == "DENY"
        # Returned trail must match disk records
        assert disk_records[0]["tool"] == trail[0]["tool"]
        assert disk_records[1]["tool"] == trail[1]["tool"]

    def test_audit_appends_not_overwrites(self, audit_log: Path, db_reset):
        """Running run_loop twice appends to the log; earlier records survive."""
        turn_fn_1 = _stub_turns(
            [{"type": "tool_use", "id": "app1", "name": "calculator",
              "input": {"expression": "1+1"}}],
        )
        run_loop(
            system_prompt="test",
            initial_user_message="first run",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn_1,
        )

        turn_fn_2 = _stub_turns(
            [{"type": "tool_use", "id": "app2", "name": "calculator",
              "input": {"expression": "2+2"}}],
        )
        run_loop(
            system_prompt="test",
            initial_user_message="second run",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn_2,
        )

        disk_records = _read_records(audit_log)
        assert len(disk_records) == 2, (
            "Expected 2 records (one per run); log may have been overwritten."
        )


# ---------------------------------------------------------------------------
# Test 5 — Invariant 1: text blocks never reach evaluate()
# ---------------------------------------------------------------------------

class TestInvariant1TextBlocksNotEvaluated:
    """
    Invariant 1: the gate operates on tool_use blocks only.
    A text block in the same turn as a tool_use must not produce an extra
    audit record, and must not be passed to evaluate().
    """

    def test_text_block_does_not_produce_audit_record(self, audit_log: Path):
        """
        Turn with one text block + one tool_use block.
        Exactly one audit record must be written (for the tool_use only).
        """
        turn_fn = _stub_turns(
            [
                {"type": "text", "text": "I am going to look up the customer."},
                {"type": "tool_use", "id": "inv1", "name": "lookup_customer",
                 "input": {"customer_id": "C001"}},
            ],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="go",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        # Only the tool_use contributes a record
        assert len(trail) == 1
        assert trail[0]["tool"] == "lookup_customer"
        assert trail[0]["decision"] == "ALLOW"

    def test_text_only_turn_produces_no_audit_records(self, audit_log: Path):
        """A turn with only text blocks must produce no audit records."""
        turn_fn = _stub_turns(
            [{"type": "text", "text": "I will not use any tools."}],
        )
        trail = run_loop(
            system_prompt="test",
            initial_user_message="just talk",
            tool_registry=TOOL_REGISTRY,
            tool_schemas=TOOL_SCHEMAS,
            log_path=audit_log,
            model_turn_fn=turn_fn,
        )

        assert len(trail) == 0

    def test_evaluate_never_called_for_text_blocks(self, audit_log: Path):
        """
        Spy on gateway.evaluate() directly: it must not be called for text blocks.
        Uses monkeypatching at the loop module level.
        """
        call_log: list[str] = []
        real_evaluate = evaluate

        def spy_evaluate(tool, params, context):
            call_log.append(tool)
            return real_evaluate(tool, params, context)

        import core.loop as loop_mod
        original = loop_mod.evaluate
        loop_mod.evaluate = spy_evaluate

        try:
            turn_fn = _stub_turns(
                [
                    {"type": "text", "text": "This is model speech, not an action."},
                    {"type": "text", "text": "Nor is this."},
                ],
            )
            trail = run_loop(
                system_prompt="test",
                initial_user_message="just text",
                tool_registry=TOOL_REGISTRY,
                tool_schemas=TOOL_SCHEMAS,
                log_path=audit_log,
                model_turn_fn=turn_fn,
            )
        finally:
            loop_mod.evaluate = original

        assert call_log == [], (
            f"BUG: evaluate() was called for text block(s): {call_log}"
        )
        assert len(trail) == 0
