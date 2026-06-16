"use client";

/**
 * audit-log.tsx — a live decision record. It streams the canonical sequence in once (the
 * line-2-vs-line-6 send_email flip story), then LISTENS for `aegis:verdict` events that the
 * background gate dispatches whenever you judge an action yourself (sweep or click). Those
 * append in real time, highlighted, capped to the most recent rows. Every verdict, seed or
 * live, is real decide() output.
 */

import { useEffect, useRef, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";
import type { Decision } from "@/lib/engine/types";
import { EASE } from "@/lib/motion";

const SEQUENCE = [
  { tool: "calculator", params: { expression: "0.0825 * 2400" }, call: 'calculator("0.0825 * 2400")' },
  { tool: "send_email", params: { to: "ops@partner.example.com" }, call: 'send_email("ops@partner…")' },
  { tool: "execute_sql", params: { sql: "SELECT plan FROM accounts" }, call: 'execute_sql("SELECT plan …")' },
  { tool: "lookup_customer", params: { customer_id: 4012 }, call: "lookup_customer(4012)" },
  { tool: "execute_sql", params: { sql: "DROP TABLE audit_log" }, call: 'execute_sql("DROP TABLE …")' },
  { tool: "send_email", params: { to: "ops@partner.example.com" }, call: 'send_email("ops@partner…")' },
  { tool: "send_email", params: { to: "oncall@internal.example.com" }, call: 'send_email("oncall@internal…")' },
];

const REASONS: Record<string, string> = {
  "math.allow_calculator": "pure arithmetic",
  "sql.allow_other": "non-destructive query",
  "customers.allow_lookup": "read-only lookup",
  "email.allow_known_domains": "known recipient",
  "sql.deny_destructive": "destructive SQL",
  "email.deny_exfil_after_read": "send after a read",
  "policy.default_deny": "no rule matched",
  "policy.no_pack": "no policy loaded",
};

type Seed = { call: string; decision: Decision; rule: string; reason: string };
type Row = Seed & { id: number; live: boolean };

function seedRows(): Seed[] {
  const traj: { tool: string; decision: string }[] = [];
  const out: Seed[] = [];
  for (const it of SEQUENCE) {
    const r = decide(defaultPack, it.tool, it.params, traj);
    out.push({ call: it.call, decision: r.decision, rule: r.ruleId, reason: REASONS[r.ruleId] ?? r.ruleId });
    if (r.decision === "ALLOW") traj.push({ tool: it.tool, decision: "ALLOW" });
  }
  return out;
}

const SEED = seedRows();
const MAX = 8;

function Verdict({
  decision,
  reason,
  reduce,
}: {
  decision: Decision;
  reason: string;
  reduce: boolean | null;
}) {
  const allow = decision === "ALLOW";
  return (
    <motion.span
      initial={reduce ? false : { scale: 0.8, opacity: 0 }}
      animate={reduce ? { opacity: 1 } : { scale: 1, opacity: 1 }}
      transition={{ delay: reduce ? 0 : 0.16, duration: reduce ? 0 : 0.22, ease: EASE }}
      className={`inline-flex shrink-0 items-center gap-2 rounded-md px-2.5 py-1 font-mono text-[11px] font-medium tracking-wide ${
        allow ? "bg-allow-soft text-allow" : "bg-deny-soft text-deny"
      }`}
    >
      <span className={`size-1.5 rounded-full ${allow ? "bg-allow" : "bg-deny"}`} aria-hidden />
      {decision}
      <span className="text-paper-dim/70">· {reason}</span>
    </motion.span>
  );
}

export function AuditLog({ className }: { className?: string }) {
  const reduce = useReducedMotion();
  const [rows, setRows] = useState<Row[]>([]);
  const idRef = useRef(0);

  useEffect(() => {
    let i = 0;
    let timer: number;
    const tick = () => {
      if (i >= SEED.length) return;
      const s = SEED[i];
      i += 1;
      setRows((prev) => [...prev, { id: idRef.current++, ...s, live: false }].slice(-MAX));
      timer = window.setTimeout(tick, 720);
    };
    timer = window.setTimeout(tick, 350);
    return () => clearTimeout(timer);
  }, []);

  useEffect(() => {
    const onVerdict = (e: Event) => {
      const d = (e as CustomEvent).detail as
        | { call: string; decision: Decision; rule: string }
        | undefined;
      if (!d) return;
      setRows((prev) =>
        [
          ...prev,
          {
            id: idRef.current++,
            call: d.call,
            decision: d.decision,
            rule: d.rule,
            reason: REASONS[d.rule] ?? d.rule,
            live: true,
          },
        ].slice(-MAX),
      );
    };
    window.addEventListener("aegis:verdict", onVerdict as EventListener);
    return () => window.removeEventListener("aegis:verdict", onVerdict as EventListener);
  }, []);

  return (
    <div
      className={`overflow-hidden rounded-xl border border-line-strong bg-ink-raised ${className ?? ""}`}
    >
      <div className="flex items-center gap-2 border-b border-line px-4 py-3">
        <span className="size-2 rounded-full bg-paper-dim/40" aria-hidden />
        <span className="size-2 rounded-full bg-paper-dim/40" aria-hidden />
        <span className="size-2 rounded-full bg-paper-dim/40" aria-hidden />
        <span className="ml-2 font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
          decision record
        </span>
        <span className="ml-auto inline-flex items-center gap-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-paper-dim/70">
          <span className="size-1.5 rounded-full bg-allow/80" aria-hidden />
          append-only
        </span>
      </div>

      <ul className="flex min-h-[19rem] flex-col gap-2 p-4">
        <AnimatePresence mode="popLayout" initial={false}>
          {rows.map((row) => (
            <motion.li
              key={row.id}
              layout={!reduce}
              initial={reduce ? { opacity: 0 } : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={reduce ? { opacity: 0 } : { opacity: 0, y: -6 }}
              transition={{ duration: 0.34, ease: EASE }}
              className={`flex flex-wrap items-center justify-between gap-x-3 gap-y-2 rounded-lg border px-3 py-2.5 ${
                row.live
                  ? "border-paper/25 bg-ink-high/70"
                  : "border-line/60 bg-ink-high/40"
              }`}
            >
              <code className="min-w-0 break-all font-mono text-[12.5px] leading-relaxed text-paper">
                {row.live ? "› " : ""}
                {row.call}
              </code>
              <Verdict decision={row.decision} reason={row.reason} reduce={reduce} />
            </motion.li>
          ))}
        </AnimatePresence>
      </ul>
    </div>
  );
}
