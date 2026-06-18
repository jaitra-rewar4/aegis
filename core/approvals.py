"""
approvals.py — the human-approval store and resume-execute, DERIVED from the audit log.

REQUIRE_APPROVAL is decided by the deterministic gate (`engine.decide`); HOLDING the action
and recording a human's verdict is runtime, and lives here — this module NEVER re-decides
policy (it imports no engine, calls no `decide`). The audit log is the single source of truth
(ADR 0006 §c):

  - a HELD request is a record with `decision == "REQUIRE_APPROVAL"` and a `pending_id`
    (written write-ahead by the loop);
  - a RESOLUTION is a LATER record with the same `pending_id`, `decision` ALLOW or DENY, and
    an `approver` — the human's verdict, recorded via the existing `append_record`.

Pending state is a MATERIALIZED VIEW over the log: a held request whose `pending_id` has no
later resolution. There is no parallel database of record to drift; everything here is
rebuilt by scanning the log. The decision the human makes is an AUTHORIZATION of an action
the engine already tagged REQUIRE_APPROVAL — it can never turn a DENY into an ALLOW, because
only REQUIRE_APPROVAL requests are ever in the store.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Callable

from core.audit import DEFAULT_LOG_PATH, append_record

__all__ = [
    "ApprovalError",
    "read_log",
    "list_pending",
    "get_pending",
    "resolve",
    "resume_execute",
]


class ApprovalError(Exception):
    """Raised when a resolution or resume is not valid (unknown id, already resolved, denied).

    WHY a distinct exception (not a bare ValueError): the API layer maps it to a clean HTTP
    status, and a caller can tell an approval-flow problem from a programming error. The
    subclasses below let the HTTP layer dispatch on type rather than on message text (which
    would silently break the status mapping if a message were ever reworded).
    """


class UnknownPendingError(ApprovalError):
    """No held action exists for the given pending_id (-> HTTP 404)."""


class AlreadyResolvedError(ApprovalError):
    """The held action was already approved or denied (-> HTTP 409)."""


class ApproverRequiredError(ApprovalError):
    """A resolution was attempted with no approver identity (-> HTTP 400)."""


def _log_path(log_path: Path | str | None) -> Path:
    return Path(log_path) if log_path is not None else DEFAULT_LOG_PATH


def read_log(log_path: Path | str | None = None) -> list[dict[str, Any]]:
    """Parse the JSONL audit log into a list of dict records (oldest first). Missing log -> [].

    TOTAL over a corrupt / hand-edited log: a malformed JSON line is skipped, and a well-formed
    but non-dict line (a bare string/number/list/null) is NOT a record and is dropped. This is
    the same fail-toward-not-a-record discipline the engine uses for junk trajectory entries —
    a single bad line must never crash the whole approval surface (which reads the log on every
    request). Every downstream consumer can then assume dicts.
    """
    path = _log_path(log_path)
    if not path.exists():
        return []
    out: list[dict[str, Any]] = []
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            continue  # a corrupt line is not a record; skip it rather than crash.
        if isinstance(rec, dict):
            out.append(rec)
    return out


def _resolutions_by_pending_id(records: list[dict[str, Any]]) -> dict[str, dict[str, Any]]:
    """Map pending_id -> its FIRST resolution record (decision ALLOW/DENY carrying that id).

    WHY first-wins: `resolve` refuses to write a second resolution for an already-resolved id,
    so in a well-formed log there is at most one. If a log were hand-edited to contain two, the
    earliest is authoritative and the view is still deterministic.
    """
    resolutions: dict[str, dict[str, Any]] = {}
    for rec in records:
        if not isinstance(rec, dict):  # defense-in-depth; read_log already drops non-dicts.
            continue
        pid = rec.get("pending_id")
        if pid and rec.get("decision") in ("ALLOW", "DENY") and pid not in resolutions:
            resolutions[pid] = rec
    return resolutions


def _pending_view(request: dict[str, Any], resolution: dict[str, Any] | None) -> dict[str, Any]:
    """Shape one held action for the API/dashboard, stitching request + optional resolution."""
    if resolution is None:
        status, approver, resolved_ts = "pending", None, None
    else:
        status = "approved" if resolution.get("decision") == "ALLOW" else "denied"
        approver, resolved_ts = resolution.get("approver"), resolution.get("ts")
    return {
        "pending_id": request.get("pending_id"),
        "tool": request.get("tool"),
        "params": request.get("params"),
        "rule": request.get("rule"),
        "requested_ts": request.get("ts"),
        "status": status,
        "approver": approver,
        "resolved_ts": resolved_ts,
    }


def _requests(records: list[dict[str, Any]]) -> list[dict[str, Any]]:
    """All held REQUIRE_APPROVAL request records (decision REQUIRE_APPROVAL with a pending_id)."""
    return [
        r for r in records
        if isinstance(r, dict) and r.get("decision") == "REQUIRE_APPROVAL" and r.get("pending_id")
    ]


def list_pending(log_path: Path | str | None = None, *, include_resolved: bool = False) -> list[dict[str, Any]]:
    """Return the held actions as views. By default only still-pending ones (ADR 0006 §c)."""
    records = read_log(log_path)
    resolutions = _resolutions_by_pending_id(records)
    views = []
    for req in _requests(records):
        pid = req["pending_id"]
        resolution = resolutions.get(pid)
        if resolution is not None and not include_resolved:
            continue
        views.append(_pending_view(req, resolution))
    return views


def get_pending(pending_id: str, log_path: Path | str | None = None) -> dict[str, Any] | None:
    """Return the view for one held action (pending or resolved), or None if no such id."""
    records = read_log(log_path)
    request = next((r for r in _requests(records) if r["pending_id"] == pending_id), None)
    if request is None:
        return None
    return _pending_view(request, _resolutions_by_pending_id(records).get(pending_id))


def resolve(pending_id: str, *, approve: bool, approver: str, log_path: Path | str | None = None) -> dict[str, Any]:
    """Record a human's approve/deny verdict for a held action. Returns the resolution record.

    This is the human AUTHORIZATION, not a policy re-evaluation: it appends an audit record
    carrying the human's decision (ALLOW on approve, DENY on deny), the `approver`, and the
    same `pending_id` and originating `rule` as the request. It calls no engine and re-judges
    nothing. Raises ApprovalError on an unknown id, an already-resolved id, or a missing
    approver — fail-closed: an action is never silently executed on a malformed resolution.
    """
    if not isinstance(approver, str) or not approver.strip():
        raise ApproverRequiredError("an approver identity is required to resolve a held action")

    records = read_log(log_path)
    request = next((r for r in _requests(records) if r["pending_id"] == pending_id), None)
    if request is None:
        raise UnknownPendingError(f"no held action with pending_id {pending_id!r}")
    if pending_id in _resolutions_by_pending_id(records):
        raise AlreadyResolvedError(f"held action {pending_id!r} is already resolved")

    tool = request.get("tool")
    if not isinstance(tool, str) or not tool:
        # A hand-edited request missing its tool is not a resolvable action — refuse cleanly
        # rather than KeyError into a 500.
        raise UnknownPendingError(f"held action {pending_id!r} is malformed (no tool)")

    return append_record(
        tool=tool,
        params=request.get("params") or {},
        decision="ALLOW" if approve else "DENY",
        rule=request.get("rule"),
        approver=approver.strip(),
        pending_id=pending_id,
        log_path=log_path,
    )


# An execution EVENT (distinct from the four policy verdicts) and its operational rule marker,
# written when an approved action is resumed. Using a non-ALLOW/DENY decision keeps it out of
# the resolution scan, and the aegis.* rule namespace marks it as runtime, not a policy rule.
EXECUTED_DECISION = "EXECUTED"
RESUMED_RULE = "aegis.resumed"


def _already_executed(records: list[dict[str, Any]], pending_id: str) -> bool:
    return any(
        isinstance(r, dict) and r.get("pending_id") == pending_id and r.get("decision") == EXECUTED_DECISION
        for r in records
    )


def resume_execute(
    pending_id: str,
    tool_registry: dict[str, Callable[..., Any]],
    log_path: Path | str | None = None,
) -> Any:
    """Execute a held action that a human APPROVED, exactly once. Returns the tool's result.

    WHY execution lives here (the runtime), never in the API: the approval endpoint records a
    verdict; a single execution site keeps the surface that runs governed actions small (ADR
    0006 §c, execute-on-resume). Write-ahead is preserved twice over: the ALLOW authorization
    record was durably written by `resolve`, and an EXECUTED marker is appended (fsync'd) here
    BEFORE the tool runs — so the execution is logged before it happens, and a second call sees
    that marker and refuses (idempotent: an approved action executes once, not once-per-call).
    Raises ApprovalError if the action is unknown, not yet approved, denied, or already executed.
    """
    records = read_log(log_path)
    request = next((r for r in _requests(records) if r["pending_id"] == pending_id), None)
    if request is None:
        raise UnknownPendingError(f"no held action with pending_id {pending_id!r}")
    resolution = _resolutions_by_pending_id(records).get(pending_id)
    if resolution is None:
        raise ApprovalError(f"held action {pending_id!r} is not yet approved")
    if resolution.get("decision") != "ALLOW":
        raise ApprovalError(f"held action {pending_id!r} was denied; it will not execute")
    if _already_executed(records, pending_id):
        raise AlreadyResolvedError(f"held action {pending_id!r} has already been executed")

    tool = request.get("tool")
    params = request.get("params") or {}
    tool_fn = tool_registry.get(tool)
    if tool_fn is None:
        raise ApprovalError(f"no tool {tool!r} in the registry to resume")

    # Write-ahead the execution event before running the body (no unlogged execution).
    append_record(
        tool=tool, params=params, decision=EXECUTED_DECISION, rule=RESUMED_RULE,
        approver=resolution.get("approver"), pending_id=pending_id, log_path=log_path,
    )
    return tool_fn(**params)
