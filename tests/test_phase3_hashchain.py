"""
test_phase3_hashchain.py — slice 3d: the SHA-256 hash-chained, tamper-evident audit log
(ADR 0006 §d).

Proves: a clean log verifies; each record commits to the one before it; altering, re-hashing,
deleting, or reordering any record makes `verify_chain` report a break at exactly that point;
the loop and the approval store chain together on one log; and the hash never enters the
decision path (it is written downstream of the decision, like `ts`).
"""

from __future__ import annotations

import ast
import json
from pathlib import Path

import pytest

from core.audit import _record_hash, append_record, verify_chain
from core.loop import run_loop
from demos.tools import TOOL_REGISTRY, TOOL_SCHEMAS


def _records(log: Path) -> list[dict]:
    return [json.loads(l) for l in log.read_text(encoding="utf-8").splitlines() if l.strip()]


def _rewrite(log: Path, records: list[dict]) -> None:
    log.write_text("".join(json.dumps(r) + "\n" for r in records), encoding="utf-8")


def _seed(log: Path, n: int = 4) -> None:
    for i in range(n):
        append_record(tool="t", params={"i": i}, decision="ALLOW", rule="r", log_path=log)


# --- the clean chain ---------------------------------------------------------------


def test_fresh_chain_verifies(audit_log):
    _seed(audit_log)
    assert verify_chain(audit_log) == (True, None)


def test_empty_or_missing_log_verifies(audit_log):
    assert verify_chain(audit_log) == (True, None)  # missing file
    audit_log.write_text("", encoding="utf-8")
    assert verify_chain(audit_log) == (True, None)


def test_each_record_links_to_the_previous(audit_log):
    r0 = append_record(tool="t", params={}, decision="ALLOW", rule="r", log_path=audit_log)
    r1 = append_record(tool="t", params={}, decision="DENY", rule="r", log_path=audit_log)
    r2 = append_record(tool="t", params={}, decision="ALLOW", rule="r", log_path=audit_log)
    assert r0["prev_hash"] is None
    assert r1["prev_hash"] == r0["hash"]
    assert r2["prev_hash"] == r1["hash"]
    assert len({r0["hash"], r1["hash"], r2["hash"]}) == 3  # distinct


# --- tamper detection --------------------------------------------------------------


def test_altering_a_record_breaks_the_chain_there(audit_log):
    _seed(audit_log)
    records = _records(audit_log)
    records[1]["params"] = {"i": 999}  # alter record 1, leave its stale hash
    _rewrite(audit_log, records)
    assert verify_chain(audit_log) == (False, 1)


def test_altering_and_rehashing_breaks_the_next_link(audit_log):
    # A smarter tamper: alter record 1 AND recompute its hash. Now record 1 self-verifies, but
    # record 2's prev_hash still points at the OLD hash -> the break surfaces at record 2.
    _seed(audit_log)
    records = _records(audit_log)
    records[1]["params"] = {"i": 999}
    records[1]["hash"] = _record_hash(records[1])
    _rewrite(audit_log, records)
    assert verify_chain(audit_log) == (False, 2)


def test_deleting_a_record_breaks_the_chain(audit_log):
    _seed(audit_log)
    records = _records(audit_log)
    del records[1]
    _rewrite(audit_log, records)
    ok, idx = verify_chain(audit_log)
    assert ok is False and idx == 1


def test_reordering_records_breaks_the_chain(audit_log):
    _seed(audit_log)
    records = _records(audit_log)
    records[1], records[2] = records[2], records[1]
    _rewrite(audit_log, records)
    assert verify_chain(audit_log)[0] is False


def test_a_non_record_line_is_a_break(audit_log):
    _seed(audit_log, 2)
    with open(audit_log, "a", encoding="utf-8") as fh:
        fh.write("not json\n")
    assert verify_chain(audit_log) == (False, 2)


def test_forged_non_none_genesis_is_a_break(audit_log):
    # A log whose FIRST record has a non-None prev_hash (a fake genesis) is broken at index 0:
    # verify starts from prev=None, so any prev_hash on the first record fails the link.
    rec = {"ts": "T", "tool": "t", "params": {}, "decision": "ALLOW", "rule": "r",
           "approver": None, "pending_id": None, "prev_hash": "deadbeef"}
    rec["hash"] = _record_hash(rec)
    _rewrite(audit_log, [rec])
    assert verify_chain(audit_log) == (False, 0)


# --- determinism of the hash, and absence from the decision path -------------------


def test_record_hash_is_key_order_independent():
    a = {"ts": "T", "tool": "t", "params": {"x": 1, "y": 2}, "decision": "ALLOW", "prev_hash": None}
    b = {"prev_hash": None, "decision": "ALLOW", "params": {"y": 2, "x": 1}, "tool": "t", "ts": "T"}
    assert _record_hash(a) == _record_hash(b)


def test_hash_excludes_the_hash_field_itself():
    rec = {"tool": "t", "decision": "ALLOW", "prev_hash": None}
    h = _record_hash(rec)
    rec_with_hash = {**rec, "hash": "anything at all"}
    assert _record_hash(rec_with_hash) == h  # the hash field is not part of the digest


def test_engine_does_not_import_audit():
    # The hash lives in core.audit, downstream of the decision. The engine must not import it,
    # proving the hash can never reach decide() (it is metadata, like ts).
    import policy.engine as eng

    tree = ast.parse(Path(eng.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
        elif isinstance(node, ast.Import):
            imported.update(n.name for n in node.names)
    assert not any("audit" in m for m in imported), imported


# --- the chain spans writers (the loop and the approval store) ---------------------


def _one_turn(*blocks):
    state = {"done": False}

    def _fn(_messages):
        if not state["done"]:
            state["done"] = True
            return list(blocks)
        return [{"type": "text", "text": "x"}]

    return _fn


def test_loop_and_approval_resolution_chain_together(audit_log):
    from core.approvals import resolve

    # The loop holds an export_data (REQUIRE_APPROVAL) -> record 0.
    run_loop(
        system_prompt="t", initial_user_message="u",
        tool_registry=dict(TOOL_REGISTRY), tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
        model_turn_fn=_one_turn({"type": "tool_use", "id": "e", "name": "export_data", "input": {}}),
    )
    pid = _records(audit_log)[-1]["pending_id"]
    # A human approval appends a resolution -> record 1, chained onto record 0.
    resolve(pid, approve=True, approver="alice", log_path=audit_log)
    assert verify_chain(audit_log) == (True, None)
    recs = _records(audit_log)
    assert recs[1]["prev_hash"] == recs[0]["hash"]


def test_full_hold_approve_resume_chain_verifies(audit_log):
    # The three-writer sequence (held REQUIRE_APPROVAL -> ALLOW resolution -> EXECUTED marker)
    # stays on one valid chain.
    from core.approvals import resolve, resume_execute

    run_loop(
        system_prompt="t", initial_user_message="u",
        tool_registry=dict(TOOL_REGISTRY), tool_schemas=TOOL_SCHEMAS, log_path=audit_log,
        model_turn_fn=_one_turn({"type": "tool_use", "id": "e", "name": "export_data", "input": {}}),
    )
    pid = _records(audit_log)[-1]["pending_id"]
    resolve(pid, approve=True, approver="alice", log_path=audit_log)
    resume_execute(pid, {"export_data": lambda **kw: "done"}, audit_log)
    recs = _records(audit_log)
    assert [r["decision"] for r in recs] == ["REQUIRE_APPROVAL", "ALLOW", "EXECUTED"]
    assert verify_chain(audit_log) == (True, None)


# --- the API verify endpoint -------------------------------------------------------


def test_api_verify_reports_clean_and_tampered(audit_log):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from api.server import create_app

    _seed(audit_log)
    client = TestClient(create_app(log_path=audit_log))
    assert client.get("/audit/verify").json() == {"ok": True, "first_broken_index": None}

    records = _records(audit_log)
    records[2]["decision"] = "DENY"
    _rewrite(audit_log, records)
    body = client.get("/audit/verify").json()
    assert body["ok"] is False and body["first_broken_index"] == 2
