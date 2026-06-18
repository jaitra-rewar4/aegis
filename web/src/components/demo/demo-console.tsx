"use client";

/**
 * demo-console.tsx — the public, self-contained operator console.
 *
 * Runs the REAL ported engine (lib/engine/decide) and the REAL ported hash chain
 * (lib/demo/chain) entirely in the browser: click an action, the gate decides, the verdict and
 * a hash-chained record land in the trail, REQUIRE_APPROVAL holds in the queue for a human, and
 * the chain re-verifies after every step. No backend, no network, no faked verdicts.
 *
 * This is deliberately DISTINCT from /dashboard, which is the real operator console bound to a
 * live FastAPI audit log (the local tool). The banner makes the difference explicit so nothing
 * here is mistaken for a multi-user, server-backed trail.
 */
import { useDemoConsole } from "@/lib/demo/use-demo-console";
import { ActionLauncher } from "@/components/demo/action-launcher";
import { DemoPendingQueue } from "@/components/demo/demo-pending";
import { DemoChainBadge } from "@/components/demo/demo-chain-badge";
import { AuditTrail } from "@/components/dashboard/audit-trail";
import { Logo } from "@/components/logo";

export function DemoConsole() {
  const { records, pending, chain, busy, lastError, run, resolve, reset } = useDemoConsole();

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
              / live console
            </span>
          </div>
          <DemoChainBadge chain={chain} />
        </div>
      </header>

      {/* ---- live-demo explainer ---- */}
      <div className="mx-auto w-full max-w-7xl px-6 pt-6">
        <div className="rounded border border-line bg-ink-raised px-5 py-4 flex flex-col gap-1.5">
          <p className="font-mono text-[11px] uppercase tracking-[0.14em] text-paper">
            Live demo — runs entirely in your browser
          </p>
          <p className="font-mono text-[11.5px] leading-relaxed text-paper-dim">
            Every verdict below comes from the real Aegis engine (the same{" "}
            <code className="text-paper">decide()</code> logic as the Python gateway, ported to
            TypeScript and checked against it by parity tests). The audit records are linked with a
            real SHA-256 hash chain computed here, this session — nothing is faked or pre-recorded.
            For a real audit trail over your own agent, run the{" "}
            <a href="/dashboard" className="text-paper underline decoration-line-strong underline-offset-2 hover:text-paper">
              local operator console
            </a>{" "}
            against the FastAPI backend.
          </p>
        </div>
      </div>

      {/* ---- main content ---- */}
      <main className="flex-1 mx-auto w-full max-w-7xl px-6 py-8">
        <div className="grid grid-cols-1 gap-8 lg:grid-cols-[1fr_1.6fr] lg:gap-10 items-start">
          {/* left column: launcher + pending */}
          <div className="flex flex-col gap-10">
            <section>
              <div className="mb-5 flex items-baseline gap-3">
                <span className="font-mono text-[12px] tracking-[0.1em] text-paper">§01</span>
                <h2 className="font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
                  Propose an action
                </h2>
              </div>
              <ActionLauncher onRun={run} onReset={reset} busy={busy} hasRecords={records.length > 0} />
            </section>

            <section>
              <div className="mb-5 flex items-baseline gap-3">
                <span className="font-mono text-[12px] tracking-[0.1em] text-paper">§02</span>
                <h2 className="font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
                  Pending approvals
                </h2>
                <span className="ml-auto font-mono text-[10px] text-paper-dim/50 tabular-nums">
                  {pending.length}
                </span>
              </div>
              <DemoPendingQueue items={pending} busy={busy} error={lastError} onResolve={resolve} />
            </section>
          </div>

          {/* right column: audit trail */}
          <section>
            <div className="mb-5 flex items-baseline gap-3">
              <span className="font-mono text-[12px] tracking-[0.1em] text-paper">§03</span>
              <h2 className="font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
                Audit trail
              </h2>
              <span className="ml-auto font-mono text-[10px] text-paper-dim/50 tabular-nums">
                {records.length} records
              </span>
            </div>
            {records.length === 0 ? (
              <p className="font-mono text-[12px] text-paper-dim">
                No actions yet. Propose one on the left to see the gate decide and the chain grow.
              </p>
            ) : (
              <AuditTrail records={records} loading={false} error={null} />
            )}
          </section>
        </div>
      </main>

      {/* ---- footer ---- */}
      <footer className="border-t border-line">
        <div className="mx-auto max-w-7xl px-6 py-5 flex items-center justify-between gap-4">
          <span className="font-mono text-[10.5px] text-paper-dim/50 uppercase tracking-[0.16em]">
            Aegis live console · in-browser demo
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
