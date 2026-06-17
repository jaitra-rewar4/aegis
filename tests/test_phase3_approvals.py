"""
test_phase3_approvals.py — slice 3b: the REQUIRE_APPROVAL hold, the approval store, and the
FastAPI surface (ADR 0006 §c).

Proves: a held action becomes a pending entry derived from the log; a human's approve/deny is
recorded as a resolution carrying the approver; an approved action executes only on resume (in
the runtime, never in the API); and the HTTP layer records a verdict without ever re-deciding
policy (it imports no engine and calls no decide).
"""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from core.approvals import (
    ApprovalError,
    get_pending,
    list_pending,
    resolve,
    resume_execute,
)
from core.loop import run_loop
from demos.tools import TOOL_REGISTRY, TOOL_SCHEMAS


# --- helpers -----------------------------------------------------------------------


def _one_turn(*blocks: dict):
    state = {"done": False}

    def _fn(_messages):
        if not state["done"]:
            state["done"] = True
            return list(blocks)
        return [{"type": "text", "text": "done"}]

    return _fn


def _hold_export(log_path: Path, **input_) -> str:
    """Run a loop that proposes export_data (REQUIRE_APPROVAL in the default pack) and return
    the pending_id of the held request."""
    trail = run_loop(
        system_prompt="t", initial_user_message="u",
        tool_registry=dict(TOOL_REGISTRY), tool_schemas=TOOL_SCHEMAS, log_path=log_path,
        model_turn_fn=_one_turn({"type": "tool_use", "id": "e1", "name": "export_data", "input": input_}),
    )
    assert trail[-1]["decision"] == "REQUIRE_APPROVAL"
    return trail[-1]["pending_id"]


# --- the store: derive-on-read -----------------------------------------------------


def test_held_action_appears_as_pending(audit_log):
    pid = _hold_export(audit_log)
    pending = list_pending(audit_log)
    assert len(pending) == 1
    assert pending[0]["pending_id"] == pid
    assert pending[0]["tool"] == "export_data"
    assert pending[0]["status"] == "pending"
    assert pending[0]["approver"] is None


def test_approve_records_resolution_and_clears_pending(audit_log):
    pid = _hold_export(audit_log)
    rec = resolve(pid, approve=True, approver="alice", log_path=audit_log)
    assert rec["decision"] == "ALLOW"
    assert rec["approver"] == "alice"
    assert rec["pending_id"] == pid
    # The resolution carries the originating rule, so the trail traces why approval was needed.
    assert rec["rule"] == "exports.require_approval"
    # No longer pending; visible as approved when resolved ones are included.
    assert list_pending(audit_log) == []
    view = get_pending(pid, audit_log)
    assert view["status"] == "approved" and view["approver"] == "alice"


def test_deny_records_resolution(audit_log):
    pid = _hold_export(audit_log)
    rec = resolve(pid, approve=False, approver="bob", log_path=audit_log)
    assert rec["decision"] == "DENY"
    assert get_pending(pid, audit_log)["status"] == "denied"


def test_resolve_unknown_id_raises(audit_log):
    with pytest.raises(ApprovalError):
        resolve("nope", approve=True, approver="alice", log_path=audit_log)


def test_double_resolution_is_refused(audit_log):
    pid = _hold_export(audit_log)
    resolve(pid, approve=True, approver="alice", log_path=audit_log)
    with pytest.raises(ApprovalError):
        resolve(pid, approve=False, approver="mallory", log_path=audit_log)


@pytest.mark.parametrize("approver", ["", "   ", None])
def test_resolve_requires_an_approver(audit_log, approver):
    pid = _hold_export(audit_log)
    with pytest.raises(ApprovalError):
        resolve(pid, approve=True, approver=approver, log_path=audit_log)


# --- resume-execute: execution stays in the runtime --------------------------------


def test_resume_executes_only_after_approval(audit_log):
    pid = _hold_export(audit_log, dataset="customers")
    registry = {"export_data": lambda **kw: f"exported {kw.get('dataset')}"}
    # Not yet approved -> refuse to execute.
    with pytest.raises(ApprovalError):
        resume_execute(pid, registry, audit_log)
    # Approve, then resume executes the body.
    resolve(pid, approve=True, approver="alice", log_path=audit_log)
    assert resume_execute(pid, registry, audit_log) == "exported customers"


def test_denied_action_never_executes(audit_log):
    pid = _hold_export(audit_log)
    resolve(pid, approve=False, approver="bob", log_path=audit_log)
    registry = {"export_data": lambda **kw: "should not run"}
    with pytest.raises(ApprovalError):
        resume_execute(pid, registry, audit_log)


def test_resume_unknown_id_raises(audit_log):
    with pytest.raises(ApprovalError):
        resume_execute("nope", {"export_data": lambda **kw: "x"}, audit_log)


def test_store_is_total_over_a_junk_log(audit_log, tmp_path):
    # A corrupt / hand-edited log (a non-JSON line, a bare-string line, a request missing its
    # tool) must not crash the store; the well-formed pending request is still surfaced.
    pid = _hold_export(audit_log)
    with open(audit_log, "a", encoding="utf-8") as fh:
        fh.write("this is not json\n")
        fh.write('"a bare json string"\n')
        fh.write("42\n")
        fh.write(json.dumps({"decision": "REQUIRE_APPROVAL", "pending_id": "no_tool_here"}) + "\n")
    pending = list_pending(audit_log)
    ids = {p["pending_id"] for p in pending}
    assert pid in ids  # the real one survives
    # The tool-less forged request can be listed but cannot be resolved (no tool to act on).
    with pytest.raises(ApprovalError):
        resolve("no_tool_here", approve=True, approver="alice", log_path=audit_log)


def test_approval_record_is_on_disk_before_resume(audit_log):
    # Write-ahead: the ALLOW authorization is durably logged before resume executes.
    pid = _hold_export(audit_log)
    resolve(pid, approve=True, approver="alice", log_path=audit_log)
    records = [json.loads(l) for l in audit_log.read_text(encoding="utf-8").splitlines() if l.strip()]
    auth = [r for r in records if r.get("pending_id") == pid and r["decision"] == "ALLOW"]
    assert len(auth) == 1 and auth[0]["approver"] == "alice"


# --- the FastAPI surface -----------------------------------------------------------


def _client(log_path: Path):
    pytest.importorskip("fastapi")
    from fastapi.testclient import TestClient
    from api.server import create_app

    return TestClient(create_app(log_path=log_path))


def test_api_lists_and_approves(audit_log):
    pid = _hold_export(audit_log)
    client = _client(audit_log)

    r = client.get("/pending")
    assert r.status_code == 200
    assert [p["pending_id"] for p in r.json()] == [pid]

    r = client.post(f"/pending/{pid}/approve", json={"approver": "alice"})
    assert r.status_code == 200
    assert r.json()["decision"] == "ALLOW" and r.json()["approver"] == "alice"

    # No longer pending.
    assert client.get("/pending").json() == []


def test_api_deny(audit_log):
    pid = _hold_export(audit_log)
    client = _client(audit_log)
    r = client.post(f"/pending/{pid}/deny", json={"approver": "bob"})
    assert r.status_code == 200 and r.json()["decision"] == "DENY"


def test_api_unknown_id_404(audit_log):
    client = _client(audit_log)
    assert client.post("/pending/nope/approve", json={"approver": "a"}).status_code == 404


def test_api_double_resolution_409(audit_log):
    pid = _hold_export(audit_log)
    client = _client(audit_log)
    client.post(f"/pending/{pid}/approve", json={"approver": "alice"})
    r = client.post(f"/pending/{pid}/deny", json={"approver": "mallory"})
    assert r.status_code == 409


def test_api_missing_approver_400(audit_log):
    pid = _hold_export(audit_log)
    client = _client(audit_log)
    assert client.post(f"/pending/{pid}/approve", json={"approver": "  "}).status_code == 400


def test_api_audit_filter(audit_log):
    _hold_export(audit_log)
    client = _client(audit_log)
    r = client.get("/audit", params={"decision": "REQUIRE_APPROVAL"})
    assert r.status_code == 200
    assert all(rec["decision"] == "REQUIRE_APPROVAL" for rec in r.json())
    assert len(r.json()) >= 1


def test_api_layer_does_not_import_decide():
    # The HTTP layer must never be a second decision-maker (ADR 0006 §c): it records a human's
    # verdict, it does not re-judge policy. Assert via the AST (not prose) that the module
    # imports no policy engine and has no `decide` symbol in its namespace.
    import ast

    import api.server as srv

    tree = ast.parse(Path(srv.__file__).read_text(encoding="utf-8"))
    imported: set[str] = set()
    for node in ast.walk(tree):
        if isinstance(node, ast.ImportFrom):
            imported.add(node.module or "")
            imported.update(n.name for n in node.names)
        elif isinstance(node, ast.Import):
            imported.update(n.name for n in node.names)
    assert not any("engine" in m or "decide" in m for m in imported), imported
    assert not hasattr(srv, "decide")
