"use client";

/**
 * demo-chain-badge.tsx — chain-integrity badge for the in-browser console. Same visual language
 * as the API-bound ChainBadge, but driven by props (the demo verifies the chain locally after
 * every action) rather than a GET /audit/verify round-trip.
 */
import type { ChainStatus } from "@/lib/demo/use-demo-console";

export function DemoChainBadge({ chain }: { chain: ChainStatus }) {
  return (
    <div className="inline-flex items-center gap-2">
      {chain.phase === "verifying" && (
        <>
          <span className="size-2 rounded-full bg-paper-dim/40 animate-pulse" aria-hidden />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
            verifying chain…
          </span>
        </>
      )}
      {chain.phase === "ok" && (
        <>
          <span className="size-2 rounded-full bg-allow" aria-hidden />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-allow">
            chain intact
          </span>
        </>
      )}
      {chain.phase === "broken" && (
        <>
          <span className="size-2 rounded-full bg-deny" aria-hidden />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-deny">
            chain broken at #{chain.index}
          </span>
        </>
      )}
    </div>
  );
}
