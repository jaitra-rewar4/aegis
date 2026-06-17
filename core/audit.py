"""
audit.py — append-only JSONL audit log (Phase 1 form).

One record per evaluated action, written AFTER the decision is made and
BEFORE the action is executed (write-ahead ordering per ADR 0002).
The timestamp is stamped here, not passed in from evaluate(), so it is
never an input to the enforcement decision.

Record shape (stable across phases):
    {
        "ts":         "<ISO-8601 UTC>",
        "session_id": null,  # reserved — per-session partitioning lands later
        "agent_id":   null,  # reserved — multi-agent attribution lands later
        "tool":       "<tool name>",
        "params":     { ... },
        "decision":   "ALLOW" | "DENY" | ...,
        "rule":       "<rule_id>",
        "approver":   null,  # set by the REQUIRE_APPROVAL resolution (Phase 3 slice 3b)
        "pending_id": null,  # links a held REQUIRE_APPROVAL request to its later resolution
        "prev_hash":  null,  # reserved — hash-chaining lands in Phase 3 slice 3d
        "hash":       null   # reserved — hash-chaining lands in Phase 3 slice 3d
    }

WHY reserve prev_hash / hash as null now: Phase 3 makes the log append-only
and hash-chained.  Consumers and future chain code inherit a stable schema —
no migration needed when the real values arrive.

WHY reserve session_id / agent_id / approver as null now: CLAUDE.md binds the
audit trail to "the action, the decision, the policy that fired, and the
approver", and later phases add sessions, multi-agent attribution, and the
human approval flow.  Reserving them null on the same rationale as the hash
fields means those phases populate values without a record-shape migration.
They are accepted as optional kwargs (defaulting to None) so a caller can set
them the moment the feature exists; nothing in the enforcement path reads them.

WHY ts is stamped here and not passed in from the loop or evaluate:
The timestamp is audit metadata.  If it were passed into evaluate() it could
theoretically create a time-of-day branch in the decision path, violating
invariant 2.  Stamping it after the decision, inside append_record, keeps the
enforcement path clock-free.
"""

from __future__ import annotations

import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default log path; callers may override by passing log_path explicitly.
DEFAULT_LOG_PATH = Path(__file__).parent.parent / "demos" / "audit.log.jsonl"


def append_record(
    *,
    tool: str,
    params: dict[str, Any],
    decision: str,
    rule: str,
    log_path: Path | str | None = None,
    session_id: str | None = None,
    agent_id: str | None = None,
    approver: str | None = None,
    pending_id: str | None = None,
) -> dict[str, Any]:
    """Build an audit record, append it to the JSONL log, and return it.

    Returns the record dict so callers (loop.py, tests) can inspect it without
    re-reading the file.

    WHY return the record: tests need to assert on the shape without parsing
    the log file; returning it is cheaper and avoids a second I/O round-trip.
    """
    path = Path(log_path) if log_path is not None else DEFAULT_LOG_PATH

    # Ensure parent directory exists (relevant when running from a temp dir
    # during tests with a custom log_path).
    path.parent.mkdir(parents=True, exist_ok=True)

    record: dict[str, Any] = {
        "ts": datetime.now(tz=timezone.utc).isoformat(timespec="seconds"),
        # Reserved identity/attribution fields — null in Phase 1 (see module docstring).
        "session_id": session_id,
        "agent_id": agent_id,
        "tool": tool,
        "params": params,
        "decision": decision,
        "rule": rule,
        # The human approval flow (Phase 3 slice 3b): `approver` is set on a resolution
        # record; `pending_id` is set on a held REQUIRE_APPROVAL request AND on its
        # resolution, so the two records link without a join to anything outside the log.
        "approver": approver,
        "pending_id": pending_id,
        # Phase 3 slice 3d will populate these with real SHA-256 values.
        "prev_hash": None,
        "hash": None,
    }

    # WHY "a" (append) not "w": the file is append-only by design.  Opening in
    # write mode would silently destroy prior records — exactly what the audit
    # trail must prevent.  Phase 3 will add OS-level append-only enforcement;
    # for now, "a" is both correct and the right semantic signal.
    with open(path, "a", encoding="utf-8") as fh:
        fh.write(json.dumps(record) + "\n")
        # WHY flush + fsync before the `with` block closes:
        # Write-ahead ordering (ADR 0002) only delivers the guarantee "no
        # unlogged executed action" if the record survives a crash in the
        # window between append_record returning and the tool executing.
        # A Python write() lands in a userspace buffer; fh.flush() drains that
        # to the OS page cache, and os.fsync() forces the OS to commit the
        # page to durable storage before we return.  Without fsync the record
        # could be lost in a crash even though append_record "succeeded."
        # Cost: one fsync per action — accepted per ADR 0002 Tradeoff 3.
        fh.flush()
        os.fsync(fh.fileno())

    return record
