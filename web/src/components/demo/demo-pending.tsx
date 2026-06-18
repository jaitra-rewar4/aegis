"use client";

/**
 * demo-pending.tsx — the human approval surface for the in-browser console.
 *
 * Same UX as the API-bound PendingQueue (one approver field for the panel, approve/deny per
 * card), but it calls the local demo runtime's resolve instead of POST /pending/{id}/...
 * Approve records an ALLOW authorization and resume-executes once; deny records a DENY. No
 * decide() is called here — a human authorizes an action the gate already held.
 */
import { useState } from "react";
import type { DemoPending } from "@/lib/demo/console";

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

function PendingCard({
  item,
  approver,
  busy,
  onResolve,
}: {
  item: DemoPending;
  approver: string;
  busy: boolean;
  onResolve: (pendingId: string, approve: boolean) => void;
}) {
  return (
    <article className="rounded border border-line bg-ink-raised p-4 flex flex-col gap-3">
      <div className="flex items-start justify-between gap-3">
        <div className="flex flex-col gap-1 min-w-0">
          <span className="font-mono text-[13px] font-medium text-paper break-all">{item.tool}</span>
          <span className="font-mono text-[10.5px] text-paper-dim">{item.requested_ts}</span>
        </div>
        <span className="shrink-0 rounded bg-deny-soft px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.16em] text-deny">
          held
        </span>
      </div>

      <div className="border-t border-line pt-2.5">
        <p className="mb-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-paper-dim">params</p>
        <ParamDisplay params={item.params} />
      </div>

      {item.rule && (
        <div className="border-t border-line pt-2.5">
          <p className="mb-1 font-mono text-[10px] uppercase tracking-[0.16em] text-paper-dim">rule</p>
          <code className="font-mono text-[11px] text-paper-dim">{item.rule}</code>
        </div>
      )}

      <div className="flex gap-2 pt-1">
        <button
          onClick={() => onResolve(item.pending_id, true)}
          disabled={busy || !approver.trim()}
          className="flex-1 rounded border border-allow/40 bg-allow-soft px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.14em] text-allow transition-colors hover:bg-allow/20 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Approve
        </button>
        <button
          onClick={() => onResolve(item.pending_id, false)}
          disabled={busy || !approver.trim()}
          className="flex-1 rounded border border-deny/40 bg-deny-soft px-3 py-1.5 font-mono text-[11px] uppercase tracking-[0.14em] text-deny transition-colors hover:bg-deny/20 disabled:opacity-40 disabled:cursor-not-allowed"
        >
          Deny
        </button>
      </div>
    </article>
  );
}

export function DemoPendingQueue({
  items,
  busy,
  error,
  onResolve,
}: {
  items: DemoPending[];
  busy: boolean;
  error: string | null;
  onResolve: (pendingId: string, approver: string, approve: boolean) => void;
}) {
  const [approver, setApprover] = useState("");

  return (
    <div className="flex flex-col gap-4">
      <div className="flex flex-col gap-1.5">
        <label htmlFor="demo-approver" className="font-mono text-[10px] uppercase tracking-[0.18em] text-paper-dim">
          Your name (approver)
        </label>
        <input
          id="demo-approver"
          type="text"
          value={approver}
          onChange={(e) => setApprover(e.target.value)}
          placeholder="e.g. alice"
          className="w-full max-w-xs rounded border border-line bg-ink-high px-3 py-1.5 font-mono text-[12px] text-paper placeholder:text-paper-dim/40 outline-none focus:border-line-strong transition-colors"
        />
      </div>

      {error && (
        <p className="rounded bg-deny-soft px-3 py-2 font-mono text-[11px] text-deny">{error}</p>
      )}

      {items.length === 0 ? (
        <p className="font-mono text-[12px] text-paper-dim">No actions awaiting approval.</p>
      ) : (
        <ul className="flex flex-col gap-3">
          {items.map((item) => (
            <li key={item.pending_id}>
              <PendingCard
                item={item}
                approver={approver}
                busy={busy}
                onResolve={(pid, approve) => onResolve(pid, approver, approve)}
              />
            </li>
          ))}
        </ul>
      )}
    </div>
  );
}
