/**
 * console.ts — the in-browser demo runtime. A faithful, client-side port of the Aegis
 * gateway runtime (core/loop.py + core/approvals.py), built on the REAL ported engine
 * (lib/engine/decide) and the REAL ported hash chain (lib/demo/chain).
 *
 * NOTHING here fakes a verdict (Aegis law: every ALLOW/DENY/RATE_LIMIT/REQUIRE_APPROVAL comes
 * from calling decide()). The only difference from the Python runtime is the substrate: records
 * live in browser memory for the session instead of an append-only JSONL file, and the tool
 * bodies are trivial mocks (the demo governs the CALL, which is the whole point — Aegis gates
 * what an action IS, not what a tool returns).
 *
 * Record shape mirrors core/audit.append_record exactly so the same AuditTrail/derived-pending
 * code renders it, and the same chain verifies it.
 */
import { decide } from "../engine/engine";
import { defaultPack } from "../engine/packs/default";
import type { AuditRecord } from "../aegis-api";
import { recordHash } from "./chain";

// The demo record IS the audit record shape (so AuditTrail renders it unchanged).
export type DemoRecord = AuditRecord;

// Execution-event marker + rule, mirrored from core/approvals.py. A non-ALLOW/DENY decision so
// the EXECUTED record never counts as a resolution or as trajectory; aegis.* marks it runtime.
const EXECUTED_DECISION = "EXECUTED";
const RESUMED_RULE = "aegis.resumed";

export interface DemoPending {
  pending_id: string;
  tool: string;
  params: Record<string, unknown>;
  rule: string | null;
  requested_ts: string;
  status: "pending" | "approved" | "denied";
  approver: string | null;
  resolved_ts: string | null;
}

// Seconds-precision ISO stamp matching the Python writer's isoformat(timespec="seconds") for a
// UTC-aware datetime: "YYYY-MM-DDTHH:MM:SS+00:00" (Python emits the explicit +00:00 offset, not
// "Z"). Matching it keeps the canonical record bytes — and thus the hash — identical to what the
// gateway would produce for the same record. ts is audit metadata, never an input to decide().
function nowStamp(): string {
  return new Date().toISOString().replace(/\.\d{3}Z$/, "+00:00");
}

// Append one record: prev_hash = last record's hash, then hash = SHA-256 of the canonical
// record. The exact order core/audit.append_record uses (build record, set prev_hash from the
// tail, then compute hash over the whole thing). Returns a NEW array (records are immutable
// here so React state updates cleanly).
async function appendRecord(
  records: DemoRecord[],
  fields: {
    tool: string;
    params: Record<string, unknown>;
    decision: DemoRecord["decision"];
    rule: string | null;
    approver?: string | null;
    pending_id?: string | null;
  },
): Promise<DemoRecord[]> {
  const prev_hash = records.length > 0 ? records[records.length - 1].hash : null;
  const record: DemoRecord = {
    ts: nowStamp(),
    session_id: null,
    agent_id: null,
    tool: fields.tool,
    params: fields.params,
    decision: fields.decision,
    rule: fields.rule,
    approver: fields.approver ?? null,
    pending_id: fields.pending_id ?? null,
    prev_hash,
    hash: "",
  };
  record.hash = await recordHash(record);
  return [...records, record];
}

/**
 * Run one proposed action through the gate. Calls decide() with the session's prior records as
 * the trajectory (decide only ever counts ALLOWed entries, so EXECUTED/REQUIRE_APPROVAL records
 * are inert) — the same write-ahead trajectory the loop passes. The verdict is recorded; only an
 * ALLOW would "execute" (the mock body is a no-op so there's nothing to show but the record).
 * A REQUIRE_APPROVAL mints a pending_id and is HELD — never executed here.
 */
export async function runAction(
  records: DemoRecord[],
  tool: string,
  params: Record<string, unknown>,
): Promise<DemoRecord[]> {
  const { decision, ruleId } = decide(defaultPack, tool, params, records);
  const pending_id = decision === "REQUIRE_APPROVAL" ? crypto.randomUUID() : null;
  return appendRecord(records, { tool, params, decision, rule: ruleId, pending_id });
}

// ---- derived-on-read pending view (port of core/approvals.py) ----

function requests(records: DemoRecord[]): DemoRecord[] {
  return records.filter((r) => r.decision === "REQUIRE_APPROVAL" && !!r.pending_id);
}

function resolutionsByPendingId(records: DemoRecord[]): Map<string, DemoRecord> {
  const map = new Map<string, DemoRecord>();
  for (const rec of records) {
    const pid = rec.pending_id;
    if (pid && (rec.decision === "ALLOW" || rec.decision === "DENY") && !map.has(pid)) {
      map.set(pid, rec);
    }
  }
  return map;
}

function alreadyExecuted(records: DemoRecord[], pendingId: string): boolean {
  return records.some((r) => r.pending_id === pendingId && r.decision === EXECUTED_DECISION);
}

/** Held actions as views; pending-only by default, like list_pending(include_resolved=False). */
export function listPending(records: DemoRecord[], includeResolved = false): DemoPending[] {
  const resolutions = resolutionsByPendingId(records);
  const out: DemoPending[] = [];
  for (const req of requests(records)) {
    const pid = req.pending_id as string;
    const resolution = resolutions.get(pid);
    if (resolution && !includeResolved) continue;
    const status = !resolution ? "pending" : resolution.decision === "ALLOW" ? "approved" : "denied";
    out.push({
      pending_id: pid,
      tool: req.tool,
      params: req.params,
      rule: req.rule,
      requested_ts: req.ts,
      status,
      approver: resolution?.approver ?? null,
      resolved_ts: resolution?.ts ?? null,
    });
  }
  return out;
}

export class DemoApprovalError extends Error {}

/**
 * Record a human's approve/deny verdict for a held action, then (on approve) resume-execute it
 * exactly once. Port of approvals.resolve + resume_execute: the resolution is an AUTHORIZATION
 * record (ALLOW/DENY + approver + same pending_id/rule), never a policy re-evaluation — decide()
 * is NOT called here. On approve, an EXECUTED marker is appended (write-ahead, idempotent via the
 * already-executed guard) before the mock body would run. Throws on unknown/already-resolved id
 * or a missing approver — fail-closed.
 */
export async function resolvePending(
  records: DemoRecord[],
  pendingId: string,
  approver: string,
  approve: boolean,
): Promise<DemoRecord[]> {
  if (!approver.trim()) {
    throw new DemoApprovalError("an approver identity is required to resolve a held action");
  }
  const request = requests(records).find((r) => r.pending_id === pendingId);
  if (!request) throw new DemoApprovalError(`no held action with pending_id ${pendingId}`);
  if (resolutionsByPendingId(records).has(pendingId)) {
    throw new DemoApprovalError(`held action ${pendingId} is already resolved`);
  }

  let next = await appendRecord(records, {
    tool: request.tool,
    params: request.params,
    decision: approve ? "ALLOW" : "DENY",
    rule: request.rule,
    approver: approver.trim(),
    pending_id: pendingId,
  });

  // Execute-on-resume: only an approved action runs, and only once.
  if (approve && !alreadyExecuted(next, pendingId)) {
    next = await appendRecord(next, {
      tool: request.tool,
      params: request.params,
      decision: EXECUTED_DECISION,
      rule: RESUMED_RULE,
      approver: approver.trim(),
      pending_id: pendingId,
    });
  }
  return next;
}
