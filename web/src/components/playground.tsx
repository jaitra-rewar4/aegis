"use client";

/**
 * playground.tsx — a real interactive harness over the SAME engine the gateway runs.
 *
 * Compose a tool call (one of the four real tools, or an unknown tool to see the default-deny
 * floor) and a trajectory of prior actions this run, and the verdict + matched rule come
 * straight from decide(defaultPack, tool, params, trajectory). Nothing here is faked — every
 * ALLOW/DENY is the engine's, recomputed on every keystroke. The default state reproduces the
 * exfil story: send_email to a partner is ALLOWed until a lookup_customer is added to the run.
 */

import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";
import type { Rule } from "@/lib/engine/types";
import { EASE } from "@/lib/motion";

type Decision = "ALLOW" | "DENY";
type TrajItem = { tool: string; decision: Decision };
type Field = { key: string; initial: string };
type ToolDef = { name: string; label: string; fields: Field[]; custom?: boolean };

const TOOL_FIELD = "__tool"; // synthetic field holding the name for the unknown-tool option

const TOOLS: ToolDef[] = [
  {
    name: "send_email",
    label: "send_email",
    fields: [
      { key: "to", initial: "ops@partner.example.com" },
      { key: "subject", initial: "Q3 figures" },
    ],
  },
  {
    name: "execute_sql",
    label: "execute_sql",
    fields: [{ key: "sql", initial: "DROP TABLE audit_log" }],
  },
  {
    name: "lookup_customer",
    label: "lookup_customer",
    fields: [{ key: "customer_id", initial: "4012" }],
  },
  {
    name: "calculator",
    label: "calculator",
    fields: [{ key: "expression", initial: "0.0825 * 2400" }],
  },
  {
    name: "",
    label: "unknown tool",
    custom: true,
    fields: [{ key: TOOL_FIELD, initial: "delete_everything" }],
  },
];

const REASONS: Record<string, string> = {
  "sql.deny_destructive": "destructive SQL keyword — DROP / DELETE / TRUNCATE / ALTER",
  "sql.allow_other": "non-destructive query",
  "customers.allow_lookup": "read-only customer lookup",
  "math.allow_calculator": "pure arithmetic, no side effects",
  "email.allow_known_domains": "recipient domain is allow-listed",
  "email.deny_exfil_after_read":
    "egress to a non-internal recipient after a customer record was read this run",
  "policy.default_deny": "no rule matched — default deny",
  "policy.default_allow": "no rule matched — default allow",
  "policy.no_pack": "no policy pack loaded",
};

// Humanise the engine's operator tokens so the pack reads as designed copy, not a debug dump.
const OP_TEXT: Record<string, string> = {
  max: "≤",
  min: "≥",
  one_of: "in",
  prefix_one_of: "starts with",
  domain_in: "domain in",
  domain_not_in: "domain not in",
  contains_keyword: "contains",
  not_contains_keyword: "excludes",
};

function ruleCondition(rule: Rule): string {
  const parts: string[] = [];
  if (rule.after) parts.push(`after ${rule.after}`);
  for (const [param, [op, operand]] of Object.entries(rule.when)) {
    const val = Array.isArray(operand)
      ? `[${(operand as unknown[]).join(", ")}]`
      : String(operand);
    parts.push(`${param} ${OP_TEXT[op] ?? op} ${val}`);
  }
  return parts.length ? parts.join(" · ") : "any call to this tool";
}

const inputCls =
  "w-full rounded-md border border-line bg-ink px-3 py-2 font-mono text-[13px] text-paper placeholder:text-paper-dim/40 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink-raised";

export function Playground() {
  const reduce = useReducedMotion();
  const [toolIdx, setToolIdx] = useState(0);
  const [inputs, setInputs] = useState<Record<string, string>>(() =>
    Object.fromEntries(TOOLS[0].fields.map((f) => [f.key, f.initial])),
  );
  const [trajectory, setTrajectory] = useState<TrajItem[]>([]);

  const tool = TOOLS[toolIdx];
  const toolName = tool.custom ? inputs[TOOL_FIELD] || "unknown_tool" : tool.name;
  const paramFields = tool.fields.filter((f) => f.key !== TOOL_FIELD);
  const params: Record<string, unknown> = Object.fromEntries(
    paramFields.map((f) => [f.key, inputs[f.key] ?? ""]),
  );

  // The real decision, recomputed every render. This is the whole point.
  const result = decide(defaultPack, toolName, params, trajectory);
  const allow = result.decision === "ALLOW";

  function selectTool(i: number) {
    setToolIdx(i);
    setInputs(Object.fromEntries(TOOLS[i].fields.map((f) => [f.key, f.initial])));
  }

  const callStr = `${toolName}(${paramFields
    .map((f) => `${f.key}: "${inputs[f.key] ?? ""}"`)
    .join(", ")})`;

  return (
    <div className="mx-auto max-w-6xl px-6 py-12 sm:py-16">
      <header className="flex items-center justify-between">
        <a
          href="/"
          className="font-mono text-[12px] uppercase tracking-[0.18em] text-paper-dim transition-colors hover:text-paper"
        >
          ← Aegis
        </a>
        <span className="font-mono text-[11px] uppercase tracking-[0.2em] text-paper-dim">
          Playground
        </span>
      </header>

      <div className="mt-10 max-w-2xl">
        <h1 className="font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          Run the gate yourself.
        </h1>
        <p className="mt-4 text-[15px] leading-relaxed text-paper-dim sm:text-base">
          Compose a tool call and the actions taken before it. The verdict is live from{" "}
          <span className="font-mono text-paper">decide()</span> with the default pack — the
          same pure function the gateway runs. No model in the loop; the same inputs always
          give the same verdict.
        </p>
      </div>

      <div className="mt-10 grid gap-px overflow-hidden rounded-2xl border border-line-strong bg-line-strong lg:grid-cols-2">
        {/* ---- compose ---- */}
        <div className="flex flex-col gap-7 bg-ink-raised p-6 sm:p-8">
          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
              1 · the action
            </p>
            <div className="mt-3 flex flex-wrap gap-2">
              {TOOLS.map((t, i) => (
                <button
                  key={t.label}
                  type="button"
                  onClick={() => selectTool(i)}
                  className={`rounded-md border px-2.5 py-1.5 font-mono text-[12px] transition-colors focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink-raised ${
                    i === toolIdx
                      ? "border-paper text-paper"
                      : "border-line text-paper-dim hover:border-line-strong hover:text-paper"
                  }`}
                >
                  {t.label}
                </button>
              ))}
            </div>

            <div className="mt-4 space-y-3">
              {tool.fields.map((f) => (
                <label key={f.key} className="block">
                  <span className="mb-1.5 block font-mono text-[11px] tracking-[0.1em] text-paper-dim">
                    {f.key === TOOL_FIELD ? "tool name" : f.key}
                  </span>
                  <input
                    value={inputs[f.key] ?? ""}
                    onChange={(e) =>
                      setInputs((prev) => ({ ...prev, [f.key]: e.target.value }))
                    }
                    placeholder={f.initial}
                    spellCheck={false}
                    autoComplete="off"
                    className={inputCls}
                  />
                </label>
              ))}
            </div>
          </div>

          <div>
            <div className="flex items-center justify-between">
              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
                2 · the trajectory
              </p>
              {trajectory.length > 0 && (
                <button
                  type="button"
                  onClick={() => setTrajectory([])}
                  className="font-mono text-[11px] text-paper-dim transition-colors hover:text-paper"
                >
                  clear
                </button>
              )}
            </div>
            <p className="mt-2 font-mono text-[11px] leading-relaxed text-paper-dim/80">
              Prior actions this run. Only an <span className="text-allow">ALLOW</span>ed
              read can taint a later send — a denied action never executed.
            </p>

            <div className="mt-3 min-h-[2.25rem]">
              {trajectory.length === 0 ? (
                <p className="font-mono text-[12px] text-paper-dim/60">
                  [ ] empty — nothing has run yet
                </p>
              ) : (
                <ul className="flex flex-wrap gap-2">
                  {trajectory.map((item, i) => (
                    <li
                      key={i}
                      className="inline-flex items-center gap-2 rounded-md border border-line px-2.5 py-1 font-mono text-[12px] text-paper"
                    >
                      {item.tool}
                      <span
                        className={item.decision === "ALLOW" ? "text-allow" : "text-deny"}
                      >
                        {item.decision}
                      </span>
                      <button
                        type="button"
                        onClick={() =>
                          setTrajectory((t) => t.filter((_, j) => j !== i))
                        }
                        aria-label={`remove ${item.tool}`}
                        className="text-paper-dim transition-colors hover:text-paper"
                      >
                        ×
                      </button>
                    </li>
                  ))}
                </ul>
              )}
            </div>

            <div className="mt-3 flex flex-wrap gap-2">
              <button
                type="button"
                onClick={() =>
                  setTrajectory((t) => [
                    ...t,
                    { tool: "lookup_customer", decision: "ALLOW" },
                  ])
                }
                className="rounded-md border border-line px-2.5 py-1.5 font-mono text-[12px] text-paper-dim transition-colors hover:border-line-strong hover:text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink-raised"
              >
                + lookup_customer (ALLOW)
              </button>
              <button
                type="button"
                onClick={() =>
                  setTrajectory((t) => [
                    ...t,
                    { tool: toolName, decision: result.decision },
                  ])
                }
                className="rounded-md border border-line px-2.5 py-1.5 font-mono text-[12px] text-paper-dim transition-colors hover:border-line-strong hover:text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink-raised"
              >
                + append this result
              </button>
            </div>
          </div>
        </div>

        {/* ---- verdict ---- */}
        <div className="flex flex-col gap-6 bg-ink-raised p-6 sm:p-8">
          <div className="flex items-start justify-between gap-4">
            <div>
              <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
                verdict
              </p>
              <code className="mt-3 block break-all font-mono text-[13px] leading-relaxed text-paper">
                {callStr}
              </code>
            </div>
            <AnimatePresence mode="popLayout" initial={false}>
              <motion.div
                key={result.decision}
                initial={reduce ? { opacity: 0 } : { opacity: 0, scale: 0.9 }}
                animate={
                  reduce ? { opacity: 1 } : { opacity: 1, scale: [0.9, 1.06, 1] }
                }
                exit={reduce ? { opacity: 0 } : { opacity: 0, scale: 0.98 }}
                transition={{ duration: reduce ? 0 : 0.34, ease: EASE, times: [0, 0.65, 1] }}
                className={`inline-flex shrink-0 items-center gap-2.5 rounded-lg px-4 py-2.5 font-mono text-sm font-semibold tracking-wide ${
                  allow ? "bg-allow-soft text-allow" : "bg-deny-soft text-deny"
                }`}
              >
                <span
                  className={`size-2 rounded-full ${allow ? "bg-allow" : "bg-deny"}`}
                  aria-hidden
                />
                {result.decision}
              </motion.div>
            </AnimatePresence>
          </div>

          <div className="rounded-lg border border-line bg-ink p-4">
            <p className="font-mono text-[12px] text-paper">
              <span className="text-paper-dim">rule</span> {result.ruleId}
            </p>
            <p className="mt-1.5 text-[13px] leading-relaxed text-paper-dim">
              {REASONS[result.ruleId] ?? "—"}
            </p>
          </div>

          <div>
            <p className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
              the pack · first-match-wins
            </p>
            <ol className="mt-3 space-y-px overflow-hidden rounded-lg border border-line">
              {defaultPack.rules.map((rule) => {
                const matched = rule.id === result.ruleId;
                return (
                  <li
                    key={rule.id}
                    className={`px-3.5 py-2.5 transition-colors ${
                      matched ? "bg-ink-high" : "bg-ink"
                    }`}
                  >
                    <div className="flex items-center justify-between gap-3">
                      <span
                        className={`font-mono text-[12px] ${matched ? "text-paper" : "text-paper-dim"}`}
                      >
                        {rule.id}
                      </span>
                      <span
                        className={`font-mono text-[11px] ${
                          rule.effect === "ALLOW"
                            ? matched
                              ? "text-allow"
                              : "text-paper-dim"
                            : matched
                              ? "text-deny"
                              : "text-paper-dim"
                        }`}
                      >
                        {rule.effect}
                      </span>
                    </div>
                    <p
                      className={`mt-1 font-mono text-[11px] leading-relaxed ${
                        matched ? "text-paper-dim" : "text-paper-dim/50"
                      }`}
                    >
                      {rule.tool} · {ruleCondition(rule)}
                    </p>
                  </li>
                );
              })}
              <li
                className={`px-3.5 py-2.5 ${
                  result.ruleId.startsWith("policy.") ? "bg-ink-high" : "bg-ink"
                }`}
              >
                <div className="flex items-center justify-between gap-3">
                  <span
                    className={`font-mono text-[12px] ${
                      result.ruleId.startsWith("policy.")
                        ? "text-paper"
                        : "text-paper-dim/50"
                    }`}
                  >
                    {result.ruleId.startsWith("policy.")
                      ? result.ruleId
                      : "policy.default_deny"}
                  </span>
                  <span className="font-mono text-[11px] text-paper-dim">
                    default deny
                  </span>
                </div>
                <p className="mt-1 font-mono text-[11px] leading-relaxed text-paper-dim/50">
                  no rule matched — the floor catches it
                </p>
              </li>
            </ol>
          </div>
        </div>
      </div>
    </div>
  );
}
