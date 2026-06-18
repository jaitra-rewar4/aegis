"use client";

/**
 * chain-badge.tsx — shows the hash-chain integrity status from GET /audit/verify.
 *
 * WHY this is a dedicated component: the chain status must be visible and impossible
 * to miss if it breaks. It lives outside the audit table so it can't be scrolled past.
 * On error or API unreachability it shows an explicit degraded state — it never hides
 * tampered data behind a loader.
 */

import { useEffect, useState } from "react";
import { verifyChain, AegisUnreachableError } from "@/lib/aegis-api";
import type { ChainVerifyResponse } from "@/lib/aegis-api";

interface ChainBadgeProps {
  /** Increment to trigger a re-fetch (e.g. after an approve/deny action). */
  refreshKey?: number;
}

type State =
  | { phase: "loading" }
  | { phase: "ok" }
  | { phase: "broken"; index: number }
  | { phase: "error"; message: string };

export function ChainBadge({ refreshKey = 0 }: ChainBadgeProps) {
  const [state, setState] = useState<State>({ phase: "loading" });

  useEffect(() => {
    let cancelled = false;
    setState({ phase: "loading" });

    verifyChain()
      .then((data: ChainVerifyResponse) => {
        if (cancelled) return;
        if (data.ok) {
          setState({ phase: "ok" });
        } else {
          setState({ phase: "broken", index: data.first_broken_index ?? 0 });
        }
      })
      .catch((err: unknown) => {
        if (cancelled) return;
        if (err instanceof AegisUnreachableError) {
          setState({ phase: "error", message: "API unreachable" });
        } else {
          setState({ phase: "error", message: String((err as Error).message ?? err) });
        }
      });

    return () => {
      cancelled = true;
    };
  }, [refreshKey]);

  return (
    <div className="inline-flex items-center gap-2">
      {state.phase === "loading" && (
        <>
          <span className="size-2 rounded-full bg-paper-dim/40 animate-pulse" aria-hidden />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
            verifying chain…
          </span>
        </>
      )}
      {state.phase === "ok" && (
        <>
          <span className="size-2 rounded-full bg-allow" aria-hidden />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-allow">
            chain intact
          </span>
        </>
      )}
      {state.phase === "broken" && (
        <>
          <span className="size-2 rounded-full bg-deny" aria-hidden />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-deny">
            chain broken at #{state.index}
          </span>
        </>
      )}
      {state.phase === "error" && (
        <>
          <span className="size-2 rounded-full bg-paper-dim/40" aria-hidden />
          <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
            {state.message}
          </span>
        </>
      )}
    </div>
  );
}
