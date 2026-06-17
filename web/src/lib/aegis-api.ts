/**
 * aegis-api.ts — typed fetch wrappers for the Aegis FastAPI backend.
 *
 * Base URL comes from NEXT_PUBLIC_AEGIS_API (set in .env.local or the environment),
 * defaulting to http://localhost:8000. All functions throw AegisApiError on a non-2xx
 * response or a network failure, so callers can catch one error type and render
 * the appropriate state rather than silently falling back to stale/fake data.
 *
 * WHY a typed client rather than inline fetch calls: the dashboard has three panels
 * each making distinct calls; a shared client keeps the base URL, error type, and
 * response shapes in one place, making contract drift with the Python backend easy
 * to catch and fix without hunting across component files.
 */

const BASE_URL =
  (typeof process !== "undefined" && process.env.NEXT_PUBLIC_AEGIS_API) ||
  "http://localhost:8000";

// ---------- wire types (match api/server.py exactly) ----------

export interface HealthResponse {
  ok: boolean;
  log: string;
}

/** A held REQUIRE_APPROVAL action, as returned by GET /pending. */
export interface PendingItem {
  pending_id: string;
  tool: string;
  params: Record<string, unknown>;
  rule: string | null;
  requested_ts: string;
  status: "pending" | "approved" | "denied";
  approver: string | null;
  resolved_ts: string | null;
}

/** Resolution confirmation returned by POST /pending/{id}/approve|deny. */
export interface Resolution {
  pending_id: string;
  decision: "ALLOW" | "DENY";
  approver: string;
  ts: string;
}

/** One audit-trail record, as returned by GET /audit. */
export interface AuditRecord {
  ts: string;
  tool: string;
  params: Record<string, unknown>;
  decision: "ALLOW" | "DENY" | "RATE_LIMIT" | "REQUIRE_APPROVAL" | "EXECUTED";
  rule: string | null;
  approver: string | null;
  pending_id: string | null;
  prev_hash: string | null;
  hash: string;
  session_id: string | null;
  agent_id: string | null;
}

/** Chain verification result from GET /audit/verify. */
export interface ChainVerifyResponse {
  ok: boolean;
  first_broken_index: number | null;
}

// ---------- error type ----------

export class AegisApiError extends Error {
  constructor(
    public readonly status: number,
    message: string,
  ) {
    super(message);
    this.name = "AegisApiError";
  }
}

/** Sentinel for network-level failures (API unreachable). */
export class AegisUnreachableError extends Error {
  constructor(message = "API unreachable") {
    super(message);
    this.name = "AegisUnreachableError";
  }
}

// ---------- internal helpers ----------

async function _get<T>(path: string, params?: Record<string, string | number | boolean>): Promise<T> {
  let url = `${BASE_URL}${path}`;
  if (params && Object.keys(params).length > 0) {
    const qs = new URLSearchParams(
      Object.entries(params).map(([k, v]) => [k, String(v)]),
    );
    url = `${url}?${qs}`;
  }
  let res: Response;
  try {
    res = await fetch(url, { cache: "no-store" });
  } catch {
    throw new AegisUnreachableError(`Cannot reach Aegis API at ${BASE_URL}`);
  }
  if (!res.ok) {
    const text = await res.text().catch(() => res.statusText);
    throw new AegisApiError(res.status, text);
  }
  return res.json() as Promise<T>;
}

async function _post<T>(path: string, body: Record<string, unknown>): Promise<T> {
  let res: Response;
  try {
    res = await fetch(`${BASE_URL}${path}`, {
      method: "POST",
      headers: { "Content-Type": "application/json" },
      body: JSON.stringify(body),
      cache: "no-store",
    });
  } catch {
    throw new AegisUnreachableError(`Cannot reach Aegis API at ${BASE_URL}`);
  }
  if (!res.ok) {
    // Surface the FastAPI detail string so callers can render it inline (e.g. "already resolved").
    let detail = res.statusText;
    try {
      const payload = await res.json();
      if (typeof payload?.detail === "string") detail = payload.detail;
    } catch {
      // leave detail as statusText
    }
    throw new AegisApiError(res.status, detail);
  }
  return res.json() as Promise<T>;
}

// ---------- public API ----------

export function health(): Promise<HealthResponse> {
  return _get<HealthResponse>("/health");
}

/** List pending (or all, if include_resolved) approval requests. */
export function listPending(includeResolved = false): Promise<PendingItem[]> {
  return _get<PendingItem[]>("/pending", { include_resolved: includeResolved });
}

/** Approve a held action. Throws AegisApiError(409) if already resolved, 400 if no approver. */
export function approve(pendingId: string, approver: string): Promise<Resolution> {
  return _post<Resolution>(`/pending/${pendingId}/approve`, { approver });
}

/** Deny a held action. Throws AegisApiError(409) if already resolved, 400 if no approver. */
export function deny(pendingId: string, approver: string): Promise<Resolution> {
  return _post<Resolution>(`/pending/${pendingId}/deny`, { approver });
}

/**
 * Fetch the audit trail, newest records last (the API returns oldest->newest).
 * Optional filter params: tool name, decision value, record limit.
 */
export function getAudit(opts?: {
  tool?: string;
  decision?: string;
  limit?: number;
}): Promise<AuditRecord[]> {
  const params: Record<string, string | number> = {};
  if (opts?.tool) params.tool = opts.tool;
  if (opts?.decision) params.decision = opts.decision;
  if (opts?.limit != null) params.limit = opts.limit;
  return _get<AuditRecord[]>("/audit", params);
}

/** Verify the audit log's hash chain. */
export function verifyChain(): Promise<ChainVerifyResponse> {
  return _get<ChainVerifyResponse>("/audit/verify");
}
