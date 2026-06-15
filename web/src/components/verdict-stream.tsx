"use client";

import { useEffect, useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";
import type { Decision } from "@/lib/engine/types";
import { EASE } from "@/lib/motion";

interface VerdictRow {
  call: string;
  decision: Decision;
  ruleId: string;
  reason: string;
}

// The verified hero sequence (see engine parity check). Order matters: every ALLOWed call
// is appended to a running ALLOW-only trajectory, so the SAME partner send flips from
// ALLOW (line 2, before the read) to DENY (line 6, after it).
const SEQUENCE: Array<{ tool: string; params: Record<string, unknown>; call: string }> = [
  {
    tool: "calculator",
    params: { expression: "0.0825 * 2400" },
    call: 'calculator(expression: "0.0825 * 2400")',
  },
  {
    tool: "send_email",
    params: { to: "ops@partner.example.com", subject: "Q3 figures" },
    call: 'send_email(to: "ops@partner.example.com")',
  },
  {
    tool: "execute_sql",
    params: { sql: "SELECT plan FROM accounts WHERE id = 4012" },
    call: 'execute_sql("SELECT plan FROM accounts …")',
  },
  {
    tool: "lookup_customer",
    params: { customer_id: 4012 },
    call: "lookup_customer(customer_id: 4012)",
  },
  {
    tool: "execute_sql",
    params: { sql: "DROP TABLE audit_log" },
    call: 'execute_sql("DROP TABLE audit_log")',
  },
  {
    tool: "send_email",
    params: { to: "ops@partner.example.com", subject: "Q3 figures" },
    call: 'send_email(to: "ops@partner.example.com")',
  },
  {
    tool: "send_email",
    params: { to: "oncall@internal.example.com", subject: "nightly digest" },
    call: 'send_email(to: "oncall@internal.example.com")',
  },
];

const REASONS: Record<string, string> = {
  "math.allow_calculator": "pure arithmetic",
  "sql.allow_other": "non-destructive query",
  "customers.allow_lookup": "read-only lookup",
  "email.allow_known_domains": "known recipient",
  "sql.deny_destructive": "destructive SQL",
  "email.deny_exfil_after_read": "send after customer read",
  "policy.default_deny": "no rule matched",
  "policy.no_pack": "no policy loaded",
};

// Compute verdicts ONCE from the real engine. This is the same logic the gateway runs.
function computeVerdicts(): VerdictRow[] {
  const trajectory: Array<{ tool: string; decision: string }> = [];
  const rows: VerdictRow[] = [];
  for (const item of SEQUENCE) {
    const result = decide(defaultPack, item.tool, item.params, trajectory);
    rows.push({
      call: item.call,
      decision: result.decision,
      ruleId: result.ruleId,
      reason: REASONS[result.ruleId] ?? result.ruleId,
    });
    if (result.decision === "ALLOW") {
      trajectory.push({ tool: item.tool, decision: "ALLOW" });
    }
  }
  return rows;
}

const ROWS = computeVerdicts();

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
      // A restrained scale "stamp" that lands just after the row settles (the row's own
      // entrance runs ~0.34s; this waits, then pops). Rows appear one at a time, so the
      // stamps read as sequenced down the stream. Reduced motion -> plain appearance.
      initial={reduce ? false : { scale: 0.8, opacity: 0 }}
      animate={reduce ? { opacity: 1 } : { scale: 1, opacity: 1 }}
      transition={{ delay: reduce ? 0 : 0.26, duration: reduce ? 0 : 0.22, ease: EASE }}
      className={`inline-flex shrink-0 items-center gap-2 rounded-md px-2.5 py-1 font-mono text-[11px] font-medium tracking-wide ${
        allow ? "bg-allow-soft text-allow" : "bg-deny-soft text-deny"
      }`}
    >
      <span
        className={`size-1.5 rounded-full ${allow ? "bg-allow" : "bg-deny"}`}
        aria-hidden
      />
      {decision}
      <span className="text-paper-dim/70">· {reason}</span>
    </motion.span>
  );
}

export function VerdictStream() {
  const reduce = useReducedMotion();
  const [count, setCount] = useState(0);

  useEffect(() => {
    if (count < ROWS.length) {
      const t = setTimeout(() => setCount((c) => c + 1), 950);
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => setCount(0), 2800);
    return () => clearTimeout(t);
  }, [count]);

  const visible = ROWS.slice(0, count);

  return (
    <div className="w-full overflow-hidden rounded-xl border border-line bg-ink-raised shadow-2xl shadow-black/40">
      <div className="flex items-center gap-2 border-b border-line px-4 py-3">
        <span className="size-2.5 rounded-full bg-paper-dim/30" aria-hidden />
        <span className="size-2.5 rounded-full bg-paper-dim/30" aria-hidden />
        <span className="size-2.5 rounded-full bg-paper-dim/30" aria-hidden />
        <span className="ml-2 font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
          agent · tool calls
        </span>
      </div>

      <ul className="flex min-h-[19rem] flex-col gap-2 p-4 sm:min-h-[20rem]">
        <AnimatePresence mode="popLayout" initial={false}>
          {visible.map((row, i) => (
            <motion.li
              key={i}
              layout={!reduce}
              initial={reduce ? false : { opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              exit={reduce ? { opacity: 0 } : { opacity: 0, y: -6 }}
              transition={{ duration: 0.34, ease: EASE }}
              className="flex flex-wrap items-center justify-between gap-x-3 gap-y-2 rounded-lg border border-line/60 bg-ink-high/40 px-3 py-2.5"
            >
              <code className="min-w-0 break-all font-mono text-[12.5px] leading-relaxed text-paper">
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
