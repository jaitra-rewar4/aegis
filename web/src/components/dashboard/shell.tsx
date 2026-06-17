"use client";

/**
 * shell.tsx — the full dashboard client shell.
 *
 * Owns:
 *   - the /health probe and the API-disconnected banner
 *   - fetching /pending and /audit on mount and after actions
 *   - passing data down to PendingQueue, AuditTrail, and ChainBadge
 *   - the refreshKey counter that tells ChainBadge to re-verify after actions
 *
 * Layout: a fixed header bar, then a two-column grid on large screens
 * (pending queue left, audit trail right), with the chain badge in the header.
 *
 * WHY shell owns all fetches rather than each panel fetching independently:
 * an approve/deny action should refresh BOTH the pending list and the audit
 * trail atomically. If each panel held its own fetch interval they would
 * drift out of sync. The shell keeps a single `refresh` counter and passes
 * it as a prop so every panel re-fetches together.
 */

import { useCallback, useEffect, useRef, useState } from "react";
import {
  health,
  listPending,
  getAudit,
  AegisUnreachableError,
} from "@/lib/aegis-api";
import type { PendingItem, AuditRecord } from "@/lib/aegis-api";
import { PendingQueue } from "@/components/dashboard/pending-queue";
import { AuditTrail } from "@/components/dashboard/audit-trail";
import { ChainBadge } from "@/components/dashboard/chain-badge";
import { Logo } from "@/components/logo";

const POLL_MS = 15_000; // background poll interval

type ApiState = "checking" | "connected" | "disconnected";

interface DataState {
  pending: PendingItem[];
  pendingLoading: boolean;
  pendingError: string | null;
  audit: AuditRecord[];
  auditLoading: boolean;
  auditError: string | null;
}

const INITIAL_DATA: DataState = {
  pending: [],
  pendingLoading: true,
  pendingError: null,
  audit: [],
  auditLoading: true,
  auditError: null,
};

export function DashboardShell() {
  const [apiState, setApiState] = useState<ApiState>("checking");
  const [data, setData] = useState<DataState>(INITIAL_DATA);
  const [refreshKey, setRefreshKey] = useState(0);

  // Probe /health once on mount to show the disconnected banner early.
  useEffect(() => {
    health()
      .then(() => setApiState("connected"))
      .catch(() => setApiState("disconnected"));
  }, []);

  const fetchAll = useCallback(async () => {
    // Fetch pending and audit in parallel; record errors per-panel.
    const [pendingResult, auditResult] = await Promise.allSettled([
      listPending(),
      getAudit({ limit: 200 }),
    ]);

    setData({
      pending:
        pendingResult.status === "fulfilled" ? pendingResult.value : [],
      pendingLoading: false,
      pendingError:
        pendingResult.status === "rejected"
          ? errorMessage(pendingResult.reason)
          : null,
      audit:
        auditResult.status === "fulfilled" ? auditResult.value : [],
      auditLoading: false,
      auditError:
        auditResult.status === "rejected"
          ? errorMessage(auditResult.reason)
          : null,
    });
  }, []);

  // Initial fetch and background poll (only when connected).
  const pollRef = useRef<ReturnType<typeof setInterval> | null>(null);

  useEffect(() => {
    if (apiState !== "connected") return;
    fetchAll();
    pollRef.current = setInterval(fetchAll, POLL_MS);
    return () => {
      if (pollRef.current) clearInterval(pollRef.current);
    };
  }, [apiState, fetchAll]);

  // Called by PendingQueue after a successful approve/deny.
  const handleAction = useCallback(() => {
    fetchAll();
    setRefreshKey((k) => k + 1);
  }, [fetchAll]);

  // ---------- render ----------

  return (
    <div className="min-h-screen flex flex-col bg-ink text-paper">
      {/* ---- console header ---- */}
      <header className="sticky top-0 z-30 border-b border-line bg-ink/90 backdrop-blur-sm">
        <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-6 py-4">
          <div className="flex items-center gap-4">
            <a
              href="/"
              aria-label="Aegis home"
              className="rounded text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-4 focus-visible:ring-offset-ink"
            >
              <Logo />
            </a>
            <span className="hidden sm:block font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
              / operator console
            </span>
          </div>
          <div className="flex items-center gap-4">
            <ChainBadge refreshKey={refreshKey} />
            {apiState === "connected" && (
              <span className="hidden sm:flex items-center gap-1.5 font-mono text-[10.5px] text-paper-dim/60">
                <span className="size-1.5 rounded-full bg-allow" aria-hidden />
                API connected
              </span>
            )}
          </div>
        </div>
      </header>

      {/* ---- API disconnected banner ---- */}
      {apiState === "disconnected" && (
        <div
          role="alert"
          className="mx-auto w-full max-w-7xl px-6 pt-8"
        >
          <div className="rounded border border-deny/40 bg-deny-soft px-6 py-5 flex flex-col gap-3">
            <div className="flex items-center gap-2">
              <span className="size-2 rounded-full bg-deny shrink-0" aria-hidden />
              <p className="font-mono text-[13px] font-medium text-deny uppercase tracking-[0.12em]">
                API not connected
              </p>
            </div>
            <p className="font-mono text-[12px] text-paper-dim leading-relaxed">
              The Aegis backend is not reachable at{" "}
              <code className="text-paper">
                {process.env.NEXT_PUBLIC_AEGIS_API ?? "http://localhost:8000"}
              </code>
              . Start it from the repo root:
            </p>
            <pre className="rounded bg-ink px-4 py-3 font-mono text-[11.5px] text-paper overflow-x-auto">
              {`# Install dependencies once\npip install -r api/requirements.txt\n\n# Start the API\nuvicorn api.server:app --reload\n# or: python -m api.server`}
            </pre>
            <p className="font-mono text-[11px] text-paper-dim/60">
              Then reload this page. No mock data is shown while the API is down.
            </p>
          </div>
        </div>
      )}

      {/* ---- checking state ---- */}
      {apiState === "checking" && (
        <div className="mx-auto w-full max-w-7xl px-6 pt-12">
          <p className="font-mono text-[12px] text-paper-dim">
            Connecting to API…
          </p>
        </div>
      )}

      {/* ---- main content (only when connected) ---- */}
      {apiState === "connected" && (
        <main className="flex-1 mx-auto w-full max-w-7xl px-6 py-8">
          <div className="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_1.6fr] lg:gap-10 items-start">

            {/* ---- pending approvals ---- */}
            <section>
              <div className="mb-5 flex items-baseline gap-3">
                <span className="font-mono text-[12px] tracking-[0.1em] text-paper">§01</span>
                <h2 className="font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
                  Pending approvals
                </h2>
                {!data.pendingLoading && (
                  <span className="ml-auto font-mono text-[10px] text-paper-dim/50 tabular-nums">
                    {data.pending.length}
                  </span>
                )}
              </div>
              <PendingQueue
                items={data.pending}
                loading={data.pendingLoading}
                error={data.pendingError}
                onAction={handleAction}
              />
            </section>

            {/* ---- audit trail ---- */}
            <section>
              <div className="mb-5 flex items-baseline gap-3">
                <span className="font-mono text-[12px] tracking-[0.1em] text-paper">§02</span>
                <h2 className="font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
                  Audit trail
                </h2>
                {!data.auditLoading && (
                  <span className="ml-auto font-mono text-[10px] text-paper-dim/50 tabular-nums">
                    {data.audit.length} records
                  </span>
                )}
              </div>
              <AuditTrail
                records={data.audit}
                loading={data.auditLoading}
                error={data.auditError}
              />
            </section>

          </div>
        </main>
      )}

      {/* ---- footer ---- */}
      <footer className="border-t border-line">
        <div className="mx-auto max-w-7xl px-6 py-5 flex items-center justify-between gap-4">
          <span className="font-mono text-[10.5px] text-paper-dim/50 uppercase tracking-[0.16em]">
            Aegis operator console
          </span>
          <a
            href="/"
            className="font-mono text-[10.5px] text-paper-dim/50 hover:text-paper-dim uppercase tracking-[0.16em] transition-colors"
          >
            ← site
          </a>
        </div>
      </footer>
    </div>
  );
}

// ---------- helpers ----------

function errorMessage(reason: unknown): string {
  if (reason instanceof AegisUnreachableError) return "API unreachable";
  if (reason instanceof Error) return reason.message;
  return String(reason);
}
