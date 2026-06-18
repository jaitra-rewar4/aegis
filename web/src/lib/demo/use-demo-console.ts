"use client";

/**
 * use-demo-console.ts — React state for the in-browser console.
 *
 * Holds the session's records, derives the pending queue and chain status, and exposes
 * run / resolve / reset. Mutations are async (Web Crypto hashing) so they are SERIALIZED
 * through a promise queue: rapid clicks can't interleave and fork the chain off a stale tail
 * (the same single-writer discipline the Python writer assumes, enforced here in one tab).
 * After every mutation the chain is re-verified from scratch, so the badge always reflects the
 * actual records on screen.
 */
import { useCallback, useMemo, useRef, useState } from "react";
import {
  runAction,
  resolvePending,
  listPending,
  DemoApprovalError,
  type DemoRecord,
  type DemoPending,
} from "./console";
import { verifyChain } from "./chain";

export type ChainStatus =
  | { phase: "ok" }
  | { phase: "broken"; index: number }
  | { phase: "verifying" };

export interface DemoConsole {
  records: DemoRecord[];
  pending: DemoPending[];
  chain: ChainStatus;
  busy: boolean;
  lastError: string | null;
  run: (tool: string, params: Record<string, unknown>) => void;
  resolve: (pendingId: string, approver: string, approve: boolean) => void;
  reset: () => void;
}

export function useDemoConsole(): DemoConsole {
  const [records, setRecords] = useState<DemoRecord[]>([]);
  const [chain, setChain] = useState<ChainStatus>({ phase: "ok" });
  const [busy, setBusy] = useState(false);
  const [lastError, setLastError] = useState<string | null>(null);

  // recordsRef tracks the latest committed records so a queued async op reads the true tail
  // (not a stale closure). queueRef serializes ops so the chain never forks within the tab.
  // inFlightRef counts queued-but-unfinished ops: busy stays true until the LAST one drains, so
  // the controls don't flicker enabled between two rapidly-queued ops (which would let a click
  // land mid-batch).
  const recordsRef = useRef<DemoRecord[]>([]);
  const queueRef = useRef<Promise<void>>(Promise.resolve());
  const inFlightRef = useRef(0);

  const enqueue = useCallback((fn: () => Promise<DemoRecord[]>) => {
    inFlightRef.current += 1;
    setBusy(true);
    queueRef.current = queueRef.current
      .then(async () => {
        try {
          const next = await fn();
          recordsRef.current = next;
          setRecords(next);
          setChain({ phase: "verifying" });
          const v = await verifyChain(next);
          setChain(v.ok ? { phase: "ok" } : { phase: "broken", index: v.firstBrokenIndex ?? 0 });
          setLastError(null);
        } catch (err) {
          // A guarded failure (already-resolved, missing approver) leaves records untouched.
          setLastError(err instanceof DemoApprovalError || err instanceof Error ? err.message : String(err));
        }
      })
      .finally(() => {
        inFlightRef.current -= 1;
        if (inFlightRef.current === 0) setBusy(false);
      });
  }, []);

  const run = useCallback(
    (tool: string, params: Record<string, unknown>) => {
      enqueue(() => runAction(recordsRef.current, tool, params));
    },
    [enqueue],
  );

  const resolve = useCallback(
    (pendingId: string, approver: string, approve: boolean) => {
      enqueue(() => resolvePending(recordsRef.current, pendingId, approver, approve));
    },
    [enqueue],
  );

  const reset = useCallback(() => {
    // The Reset button is disabled while busy (inFlightRef === 0 here), so no queued op is
    // mid-write. Re-anchor the queue to a fresh resolved promise as belt-and-suspenders so no
    // stale continuation can later overwrite the cleared session.
    queueRef.current = Promise.resolve();
    recordsRef.current = [];
    setRecords([]);
    setChain({ phase: "ok" });
    setLastError(null);
  }, []);

  const pending = useMemo(() => listPending(records), [records]);

  return { records, pending, chain, busy, lastError, run, resolve, reset };
}
