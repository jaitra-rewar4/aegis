"use client";

/**
 * pending-queue.tsx — the human approval surface.
 *
 * Lists GET /pending and renders approve/deny controls for each held action.
 * An approver name input is shown at the top of the panel; both buttons send it
 * as the `approver` field. API errors (409 already-resolved, 400 bad approver)
 * are rendered inline per-card — they never silently vanish.
 *
 * The component receives callbacks rather than mutating state itself so the parent
 * page can coordinate the audit-trail refresh and chain-badge refresh after actions.
 *
 * WHY no re-deciding: this component calls only /approve and /deny — both of which
 * merely record a human verdict on an action the gate already held. No engine import,
 * no decide() call, no policy re-evaluation (ADR 0006 §c).
 */

import { useState } from "react";
import {
  approve,
  deny,
  AegisApiError,
  AegisUnreachableError,
} from "@/lib/aegis-api";
import type { PendingItem } from "@/lib/aegis-api";

interface PendingQueueProps {
  items: PendingItem[];
  loading: boolean;
  error: string | null;
  onAction: () => void; // called after a successful approve/deny to trigger parent refresh
}

function formatTs(ts: string): string {
  try {
    return new Date(ts).toLocaleString(undefined, {
      month: "short",
      day: "numeric",
      hour: "2-digit",
      minute: "2-digit",
      second: "2-digit",
    });
  } catch {
    return ts;
  }
}

function ParamDisplay({ params }: { params: Record<string, unknown> }) {
  const entries = Object.entries(params);
  if (entries.length === 0) return <span className="text-paper-dim/60">—</span>;
  return (
    <dl className="flex flex-col gap-0.5">
      {entries.map(([k, v]) => (
        <div key={k} className="flex items-baseline gap-2 min-w-0">
          <dt className="shrink-0 font-mono text-[11px] text-paper-dim">{k}:</dt>
          <dd className="font-mono text-[11px] text-paper break-all">
            {typeof v === "object" ? JSON.stringify(v) : String(v)}
          </dd>
        </div>
      ))}
    </dl>
  );
}

interface CardState {
  busy: boolean;
  error: string | null;
}

function PendingCard({
  item,
  approver,
  onAction,
}: {
  item: PendingItem;
  approver: string;
  onAction: () => void;
}) {
  const [state, setState] = useState<CardState>({ busy: false, error: null });

  async function act(fn: typeof approve) {
    const name = approver.trim();
    if (!name) {
      setState({ busy: false, error: "Enter your name above before approving or denying." });
      return;
    }
    setState({ busy: true, error: null });
    try {
      await fn(item.pending_id, name);
      onAction();
    } catch (err) {
      let msg = "Unexpected error";
      if (err instanceof AegisApiError) msg = `${err.status}: ${err.message}`;
      else if (err instanceof AegisUnreachableError) msg = err.message;
      else if (err instanceof Error) msg = err.message;
      setState({ busy: false, error: msg });
    }
  }

  return (
    <article className="rounded border border-line bg-ink-raised p-4 flex flex-col gap-3">
      {/* header row */}
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <span className="font-mono text-[13px] font-medium text-paper break-all">
            {item.tool}
          </span>
          <span className="font-mono text-[10.5px] text-paper-dim">
            {formatTs(item.requested_ts)}
          </span>
        </div>
        <span className="shrink-0 rounded bg-deny-soft px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.16em] text-deny">
          held
        </span>
      </div>

      {/* params */}
      <div className="border-t border-line pt-2.5">
        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-paper-dim">
          params
        </p>
        <ParamDisplay params={item.params} />
      </div>

      {/* rule that required approval */}
      {item.rule && (
        <div className="border-t border-line pt-2.5">
          <p className="mb-1 font-mono text-[10px] uppercase tracking-[0.16em] text-paper-dim">
            rule
          </p>
          <code className="font-mono text-[11px] text-paper-dim">{item.rule}</code>
        </div>
      )}

      {/* inline error */}
      {state.error && (
        <p className="rounded bg-deny-soft px-3 py-2 font-mono text-[11px] text-deny">
          {state.error}
        </p>
      )}

      {/* action buttons */}
      <div className="flex gap-2 pt-1">
        <button
          onClick={() => act(approve)}
          disabled={state.busy}
          className="flex-1 rounded border border-allow/40 bg-allow-soft px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.14em] text-allow transition-colors hover:bg-allow/20 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {state.busy ? "…" : "Approve"}
        </button>
        <button
          onClick={() => act(deny)}
          disabled={state.busy}
          className="flex-1 rounded border border-deny/40 bg-deny-soft px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.14em] text-deny transition-colors hover:bg-deny/20 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          {state.busy ? "…" : "Deny"}
        </button>
      </div>
    </article>
  );
}

export function PendingQueue({ items, loading, error, onAction }: PendingQueueProps) {
  const [approver, setApprover] = useState("");

  return (
    <div className="flex flex-col gap-4">
      {/* approver name — one field for the whole panel */}
      <div className="flex flex-col gap-1.5">
        <label htmlFor="approver-name" className="font-mono text-[10px] uppercase tracking-[0.18em] text-paper-dim">
          Your name (approver)
        </label>
        <input
          id="approver-name"
          type="text"
          value={approver}
          onChange={(e) => setApprover(e.target.value)}
          placeholder="e.g. alice"
          className="w-full max-w-xs rounded border border-line bg-ink-high px-3 py-1.5 font-mono text-[12px] text-paper placeholder:text-paper-dim/40 outline-none focus:border-line-strong transition-colors"
        />
      </div>

      {/* content states */}
      {loading && (
        <p className="font-mono text-[12px] text-paper-dim">Loading…</p>
      )}

      {!loading && error && (
        <p className="font-mono text-[12px] text-deny">{error}</p>
      )}

      {!loading && !error && items.length === 0 && (
        <p className="font-mono text-[12px] text-paper-dim">
          No actions awaiting approval.
        </p>
      )}

      {!loading && !error && items.length > 0 && (
        <ul className="flex flex-col gap-3">
          {items.map((item) => (
            <li key={item.pending_id}>
              <PendingCard item={item} approver={approver} onAction={onAction} />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
