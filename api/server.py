"""
api/server.py — the Aegis approval HTTP surface (FastAPI), the first network layer.

These endpoints record a HUMAN's approve/deny verdict on actions the gate ALREADY tagged
REQUIRE_APPROVAL, and serve read-only views of the audit trail. This layer is NOT a second
decision-maker (ADR 0006 §c): it imports no policy engine and calls no `decide`. It only
reads the log and appends resolution records via `core.approvals`. An approve cannot
manufacture an ALLOW for an action the engine DENYed, because only REQUIRE_APPROVAL requests
are ever in the pending store.

Run:
    pip install -r api/requirements.txt
    uvicorn api.server:app --reload          # or: python -m api.server
The audit log it serves defaults to core.audit's default path; override with the
AEGIS_AUDIT_LOG env var or by constructing create_app(log_path=...).
"""

from __future__ import annotations

import os
import sys
from pathlib import Path
from typing import Any, Optional

# Make the repo root importable so `core` resolves no matter where this is launched from.
_REPO_ROOT = Path(__file__).resolve().parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

from fastapi import FastAPI, HTTPException  # noqa: E402
from pydantic import BaseModel  # noqa: E402

from core.approvals import (  # noqa: E402
    AlreadyResolvedError,
    ApprovalError,
    ApproverRequiredError,
    UnknownPendingError,
    get_pending,
    list_pending,
    read_log,
    resolve,
)
from core.audit import verify_chain  # noqa: E402


class Resolution(BaseModel):
    """The body of an approve/deny call: who is recording the verdict."""

    approver: str


def _status_for(exc: ApprovalError) -> int:
    """Map an approval-flow failure to an HTTP status by TYPE (not message text, which could
    be reworded and silently break the mapping). No policy logic here."""
    if isinstance(exc, UnknownPendingError):
        return 404
    if isinstance(exc, AlreadyResolvedError):
        return 409
    if isinstance(exc, ApproverRequiredError):
        return 400
    return 400


def create_app(log_path: Path | str | None = None) -> FastAPI:
    """Build the approval API bound to a specific audit log (a factory so tests inject a temp log).

    log_path resolution: the explicit argument wins; then the AEGIS_AUDIT_LOG env var; then
    core.audit's default path.
    """
    resolved_log = log_path or os.environ.get("AEGIS_AUDIT_LOG") or None
    app = FastAPI(title="Aegis approvals", version="3.0", description="Human approval + audit view")

    def _do_resolve(pending_id: str, approve: bool, approver: str) -> dict[str, Any]:
        try:
            rec = resolve(pending_id, approve=approve, approver=approver, log_path=resolved_log)
        except ApprovalError as exc:
            raise HTTPException(status_code=_status_for(exc), detail=str(exc))
        return {
            "pending_id": pending_id,
            "decision": rec["decision"],
            "approver": rec["approver"],
            "ts": rec["ts"],
        }

    @app.get("/health")
    def health() -> dict[str, Any]:
        return {"ok": True, "log": str(resolved_log) if resolved_log else "default"}

    @app.get("/pending")
    def pending(include_resolved: bool = False) -> list[dict[str, Any]]:
        return list_pending(resolved_log, include_resolved=include_resolved)

    @app.get("/pending/{pending_id}")
    def pending_one(pending_id: str) -> dict[str, Any]:
        view = get_pending(pending_id, resolved_log)
        if view is None:
            raise HTTPException(status_code=404, detail=f"no held action {pending_id!r}")
        return view

    @app.post("/pending/{pending_id}/approve")
    def approve(pending_id: str, body: Resolution) -> dict[str, Any]:
        return _do_resolve(pending_id, True, body.approver)

    @app.post("/pending/{pending_id}/deny")
    def deny(pending_id: str, body: Resolution) -> dict[str, Any]:
        return _do_resolve(pending_id, False, body.approver)

    @app.get("/audit")
    def audit(
        tool: Optional[str] = None,
        decision: Optional[str] = None,
        limit: int = 200,
    ) -> list[dict[str, Any]]:
        """Read-only, filterable view of the audit trail (oldest -> newest), most-recent `limit`."""
        records = read_log(resolved_log)
        if tool:
            records = [r for r in records if r.get("tool") == tool]
        if decision:
            records = [r for r in records if r.get("decision") == decision]
        # Clamp to [1, 1000] so a negative/zero/huge limit can never dump the whole trail.
        n = max(1, min(int(limit), 1000))
        return records[-n:]

    @app.get("/audit/verify")
    def audit_verify() -> dict[str, Any]:
        """Verify the audit log's hash chain. Reports the first broken record, if any."""
        ok, broken = verify_chain(resolved_log)
        return {"ok": ok, "first_broken_index": broken}

    return app


# A module-level app for `uvicorn api.server:app`. Tests use create_app(log_path=...).
app = create_app()


def main() -> None:
    """Run the API with uvicorn (python -m api.server)."""
    import uvicorn

    uvicorn.run(app, host="127.0.0.1", port=8000)


if __name__ == "__main__":
    main()
