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

import hashlib
import json
import os
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

# Default log path; callers may override by passing log_path explicitly.
DEFAULT_LOG_PATH = Path(__file__).parent.parent / "demos" / "audit.log.jsonl"


def _record_hash(record: dict[str, Any]) -> str:
    """SHA-256 over the record's CANONICAL form, excluding the `hash` field itself (Phase 3
    slice 3d, ADR 0006 §d). Canonical = sorted keys, compact separators, ASCII-escaped — a
    single deterministic byte string for a given record, so the same record always hashes the
    same regardless of on-disk whitespace or key order. The hash covers `prev_hash`, so each
    record commits to the entire chain before it; altering any earlier record changes every
    later hash, and a verifier detects the break at exactly the altered record.
    """
    payload = {k: v for k, v in record.items() if k != "hash"}
    canonical = json.dumps(payload, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(canonical.encode("utf-8")).hexdigest()


def _last_hash(path: Path) -> str | None:
    """Return the `hash` of the last record already in the log, or None for a new/empty log.

    WHY read the tail rather than track state: append_record is stateless; the previous hash
    lives in the file, which is the single source of truth. A corrupt last line returns None,
    so the next record anchors a fresh sub-chain from None — `verify_chain` still reports the
    break at the CORRUPT line's index (the new record is not itself a second break).

    SINGLE-WRITER assumption (ADR 0006 §d): this read-tail-then-append is not concurrency-safe.
    Two processes appending to the same log at once (e.g. the loop and the API) can both read
    the same tail and write the same prev_hash, forking the chain — `verify_chain` then flags
    it. A cross-process lock / single append broker is deferred with multi-session support.
    """
    if not path.exists():
        return None
    last = None
    with open(path, "r", encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if line:
                last = line
    if last is None:
        return None
    try:
        parsed = json.loads(last)
    except json.JSONDecodeError:
        return None
    return parsed.get("hash") if isinstance(parsed, dict) else None


def verify_chain(log_path: Path | str | None = None) -> tuple[bool, int | None]:
    """Verify the hash chain. Return (ok, first_broken_index).

    Walks the log oldest-first: each record's `prev_hash` must equal the previous record's
    `hash`, and each record's `hash` must equal its recomputed value. The first record whose
    linkage or hash fails is returned as `first_broken_index` (and ok=False); a clean log
    returns (True, None). A malformed/non-dict line is itself a break. WHY this is sound: the
    hash never enters `decide` (it is written downstream of the decision, like `ts`), so adding
    it changes no verdict; it only makes after-the-fact tampering detectable.
    """
    path = Path(log_path) if log_path is not None else DEFAULT_LOG_PATH
    if not path.exists():
        return (True, None)
    prev: str | None = None
    index = 0
    for line in path.read_text(encoding="utf-8").splitlines():
        line = line.strip()
        if not line:
            continue
        try:
            rec = json.loads(line)
        except json.JSONDecodeError:
            return (False, index)
        if not isinstance(rec, dict):
            return (False, index)
        if rec.get("prev_hash") != prev:
            return (False, index)
        if rec.get("hash") != _record_hash(rec):
            return (False, index)
        prev = rec.get("hash")
        index += 1
    return (True, None)


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
        # Hash chain (Phase 3 slice 3d): prev_hash links to the last record already on disk;
        # hash is this record's SHA-256 over its canonical form (set just below, after the
        # whole record — including prev_hash — exists). Computed here, AFTER the decision and
        # on the way to disk, so the chain never touches the deterministic gate.
        "prev_hash": _last_hash(path),
        "hash": None,
    }
    record["hash"] = _record_hash(record)

    # WHY "a" (append) not "w": the file is append-only by design.  Opening in
    # write mode would silently destroy prior records — exactly what the audit
    # trail must prevent.  Phase 3 will add OS-level append-only enforcement;
    # for now, "a" is both correct and the right semantic signal.
    with open(path, "a", encoding="utf-8") as fh:
        # sort_keys so the on-disk form matches the hash's canonical key order (purely
        # cosmetic — verify_chain re-hashes via _record_hash regardless of on-disk order).
        fh.write(json.dumps(record, sort_keys=True) + "\n")
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
