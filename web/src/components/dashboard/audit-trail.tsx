"use client";

/**
 * audit-trail.tsx — read-only, searchable view of the real audit log.
 *
 * Renders the records from GET /audit newest-first, with client-side filter
 * by tool name (text) and decision (chip selector). Each row shows:
 *   - timestamp  · tool name  · short hash (first 8 chars)
 *   - decision badge (verdict color language)
 *   - rule that fired (if any)
 *   - approver (if the record carries one)
 *
 * WHY newest-first in the UI when the API returns oldest-first: operators care about
 * what just happened; scrolling down to see the most recent action is ergonomically
 * wrong for a live console. We reverse in the component, not the API (the API contract
 * is append-order for replay).
 *
 * No mock data. If the parent passes an empty array and no error, we show an empty
 * state. The parent (dashboard page) owns fetching.
 */

import { useState, useMemo } from "react";
import type { AuditRecord } from "@/lib/aegis-api";

const DECISIONS = ["ALLOW", "DENY", "RATE_LIMIT", "REQUIRE_APPROVAL", "EXECUTED"] as const;
type DecisionFilter = (typeof DECISIONS)[number] | "";

function decisionColor(d: AuditRecord["decision"]): string {
  switch (d) {
    case "ALLOW":
      return "text-allow bg-allow-soft border-allow/30";
    case "DENY":
      return "text-deny bg-deny-soft border-deny/30";
    case "RATE_LIMIT":
      return "text-[#c9a14a] bg-[#c9a14a1a] border-[#c9a14a30]";
    case "REQUIRE_APPROVAL":
      return "text-paper bg-ink-high border-line-strong";
    case "EXECUTED":
      return "text-paper-dim bg-ink-high border-line";
    default:
      return "text-paper-dim bg-ink-high border-line";
  }
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

function shortHash(hash: string): string {
  return hash.slice(0, 8);
}

function AuditRow({ record }: { record: AuditRecord }) {
  const [expanded, setExpanded] = useState(false);
  const hasParams = Object.keys(record.params ?? {}).length > 0;

  return (
    <li className="border-b border-line/50 py-3 flex flex-col gap-1.5">
      {/* primary row */}
      <div className="flex flex-wrap items-center justify-between gap-x-4 gap-y-1.5">
        <div className="flex flex-wrap items-center gap-x-3 gap-y-1 min-w-0">
          <span className="font-mono text-[12px] text-paper-dim shrink-0">
            {formatTs(record.ts)}
          </span>
          <code className="font-mono text-[12.5px] text-paper break-all">{record.tool}</code>
          <code className="font-mono text-[10px] text-paper-dim/60 shrink-0">
            #{shortHash(record.hash)}
          </code>
        </div>
        <span
          className={`shrink-0 rounded border px-2 py-0.5 font-mono text-[10px] uppercase tracking-[0.14em] ${decisionColor(record.decision)}`}
        >
          {record.decision}
        </span>
      </div>

      {/* secondary row: rule, approver */}
      <div className="flex flex-wrap gap-x-4 gap-y-0.5">
        {record.rule && (
          <span className="font-mono text-[10.5px] text-paper-dim">
            <span className="text-paper-dim/50">rule </span>
            {record.rule}
          </span>
        )}
        {record.approver && (
          <span className="font-mono text-[10.5px] text-paper-dim">
            <span className="text-paper-dim/50">approver </span>
            {record.approver}
          </span>
        )}
      </div>

      {/* expandable params */}
      {hasParams && (
        <button
          onClick={() => setExpanded((v) => !v)}
          className="self-start font-mono text-[10px] uppercase tracking-[0.14em] text-paper-dim/60 hover:text-paper-dim transition-colors"
        >
          {expanded ? "hide params" : "show params"}
        </button>
      )}
      {expanded && (
        <pre className="rounded bg-ink-high px-3 py-2 font-mono text-[10.5px] text-paper-dim overflow-x-auto whitespace-pre-wrap break-all">
          {JSON.stringify(record.params, null, 2)}
        </pre>
      )}
    </li>
  );
}

interface AuditTrailProps {
  records: AuditRecord[];
  loading: boolean;
  error: string | null;
}

export function AuditTrail({ records, loading, error }: AuditTrailProps) {
  const [toolFilter, setToolFilter] = useState("");
  const [decisionFilter, setDecisionFilter] = useState<DecisionFilter>("");

  // Client-side filtering on top of the API's server-side filter.
  // The API already accepts ?tool and ?decision; this secondary filter lets the user
  // refine further without a round-trip (the full 200-record window is already loaded).
  const filtered = useMemo(() => {
    const tool = toolFilter.trim().toLowerCase();
    return [...records]
      .reverse() // newest first
      .filter((r) => {
        if (tool && !r.tool.toLowerCase().includes(tool)) return false;
        if (decisionFilter && r.decision !== decisionFilter) return false;
        return true;
      });
  }, [records, toolFilter, decisionFilter]);

  return (
    <div className="flex flex-col gap-4">
      {/* filter controls */}
      <div className="flex flex-wrap items-center gap-3">
        <input
          type="text"
          value={toolFilter}
          onChange={(e) => setToolFilter(e.target.value)}
          placeholder="filter by tool…"
          className="rounded border border-line bg-ink-high px-3 py-1.5 font-mono text-[12px] text-paper placeholder:text-paper-dim/40 outline-none focus:border-line-strong transition-colors w-44"
        />
        <div className="flex flex-wrap gap-1.5" role="group" aria-label="Filter by decision">
          <button
            onClick={() => setDecisionFilter("")}
            className={`rounded border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] transition-colors ${
              decisionFilter === ""
                ? "border-line-strong bg-ink-high text-paper"
                : "border-line bg-transparent text-paper-dim hover:text-paper"
            }`}
          >
            all
          </button>
          {DECISIONS.map((d) => (
            <button
              key={d}
              onClick={() => setDecisionFilter(decisionFilter === d ? "" : d)}
              className={`rounded border px-2.5 py-1 font-mono text-[10px] uppercase tracking-[0.14em] transition-colors ${
                decisionFilter === d
                  ? decisionColor(d)
                  : "border-line bg-transparent text-paper-dim hover:text-paper"
              }`}
            >
              {d}
            </button>
          ))}
        </div>
      </div>

      {/* content */}
      {loading && (
        <p className="font-mono text-[12px] text-paper-dim">Loading…</p>
      )}

      {!loading && error && (
        <p className="font-mono text-[12px] text-deny">{error}</p>
      )}

      {!loading && !error && filtered.length === 0 && (
        <p className="font-mono text-[12px] text-paper-dim">No records match the current filter.</p>
      )}

      {!loading && !error && filtered.length > 0 && (
        <ul>
          {filtered.map((rec, i) => (
            <AuditRow key={`${rec.hash}-${i}`} record={rec} />
          ))}
        </ul>
      )}
    </div>
  );
}
