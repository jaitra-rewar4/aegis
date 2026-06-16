"use client";

/**
 * Same call, two verdicts — the interactive centerpiece.
 *
 * One send_email(to: "ops@partner.example.com") call. A toggle decides whether a customer
 * record was read earlier this run. BOTH verdicts come from the REAL engine:
 *   OFF -> decide(pack, "send_email", params, [])                       -> ALLOW
 *   ON  -> decide(pack, "send_email", params, [lookup_customer ALLOW])  -> DENY (exfil rule)
 * Nothing here is hardcoded; flipping the toggle re-runs decide() and the chip animates
 * (colour + a small scale pop) on the flip.
 */

import { useState } from "react";
import { AnimatePresence, motion, useReducedMotion } from "framer-motion";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";
import { Reveal } from "@/components/reveal";
import { EASE } from "@/lib/motion";
import { Section } from "@/components/section";

const CALL_TOOL = "send_email";
const CALL_PARAMS = { to: "ops@partner.example.com", subject: "Q3 figures" };

// The "a customer record was read earlier" trajectory: a single ALLOWed lookup_customer.
const PRIOR_READ = [{ tool: "lookup_customer", decision: "ALLOW" }];

const REASONS: Record<string, string> = {
  "email.allow_known_domains": "partner.example.com is an allow-listed recipient",
  "email.deny_exfil_after_read":
    "egress to a non-internal recipient after a customer record was read",
};

export function SameCall() {
  const reduce = useReducedMotion();
  const [readEarlier, setReadEarlier] = useState(false);

  // The real decision. Recomputed on every render from the toggle's trajectory.
  const trajectory = readEarlier ? PRIOR_READ : [];
  const result = decide(defaultPack, CALL_TOOL, CALL_PARAMS, trajectory);
  const allow = result.decision === "ALLOW";

  return (
    <Section index="03" label="Same call, two verdicts">
      <Reveal className="max-w-2xl">
        <h2 className="font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          The call doesn’t change. The history does.
        </h2>
        <p className="mt-5 text-[15px] leading-relaxed text-paper-dim sm:text-base">
          One identical <span className="text-paper">send_email</span> to an allow-listed
          partner. Flip whether a customer record was read earlier this run — the verdict
          comes straight from the engine.
        </p>
      </Reveal>

      <Reveal className="mt-12" delay={0.05}>
        <div className="overflow-hidden rounded-2xl border border-line-strong bg-ink-raised">
          {/* The call under test */}
          <div className="border-b border-line px-5 py-4 sm:px-7">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-paper-dim">
              The action under test
            </p>
            <code className="mt-2 block break-all font-mono text-[13.5px] leading-relaxed text-paper">
              send_email(to:{" "}
              <span className="text-paper">&quot;ops@partner.example.com&quot;</span>)
            </code>
          </div>

          <div className="grid gap-6 p-5 sm:grid-cols-[1fr_auto] sm:items-center sm:gap-8 sm:p-7">
            {/* The toggle */}
            <div>
              <button
                type="button"
                role="switch"
                aria-checked={readEarlier}
                onClick={() => setReadEarlier((v) => !v)}
                className="group flex w-full items-center gap-4 rounded-xl border border-line bg-ink-high/40 px-4 py-3.5 text-left transition-colors hover:border-line-strong focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink-raised"
              >
                <span
                  className={`relative inline-block h-6 w-11 shrink-0 rounded-full transition-colors duration-300 ${
                    readEarlier ? "bg-paper-dim/40" : "bg-line-strong"
                  }`}
                  aria-hidden
                >
                  <motion.span
                    initial={false}
                    animate={{ x: readEarlier ? 20 : 0 }}
                    transition={{ duration: reduce ? 0 : 0.25, ease: EASE }}
                    className="absolute left-0.5 top-0.5 size-5 rounded-full bg-paper shadow-sm"
                  />
                </span>
                <span className="text-[14px] leading-snug text-paper">
                  A customer record was read earlier this run
                  <span className="mt-0.5 block font-mono text-[11.5px] text-paper-dim">
                    trajectory:{" "}
                    {readEarlier
                      ? "[ lookup_customer → ALLOW ]"
                      : "[ ] (empty)"}
                  </span>
                </span>
              </button>
            </div>

            {/* The live verdict */}
            <div className="flex flex-col items-start gap-3 sm:items-end">
              <AnimatePresence mode="popLayout" initial={false}>
                <motion.div
                  key={result.decision}
                  initial={reduce ? { opacity: 0 } : { opacity: 0, scale: 0.9 }}
                  animate={
                    reduce ? { opacity: 1 } : { opacity: 1, scale: [0.9, 1.05, 1] }
                  }
                  exit={reduce ? { opacity: 0 } : { opacity: 0, scale: 0.98 }}
                  transition={{
                    duration: reduce ? 0 : 0.34,
                    ease: EASE,
                    times: [0, 0.65, 1],
                  }}
                  className={`inline-flex items-center gap-2.5 rounded-lg px-4 py-2.5 font-mono text-sm font-semibold tracking-wide ${
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
              <p className="font-mono text-[11.5px] text-paper-dim sm:text-right">
                <span className="text-paper-dim/80">rule</span> {result.ruleId}
              </p>
            </div>
          </div>

          {/* The reason, from the rule that fired */}
          <div className="border-t border-line px-5 py-4 sm:px-7">
            <AnimatePresence mode="wait" initial={false}>
              <motion.p
                key={result.ruleId}
                initial={reduce ? false : { opacity: 0, y: 4 }}
                animate={{ opacity: 1, y: 0 }}
                exit={reduce ? { opacity: 0 } : { opacity: 0, y: -4 }}
                transition={{ duration: 0.24, ease: EASE }}
                className="text-[13.5px] leading-relaxed text-paper-dim"
              >
                {REASONS[result.ruleId] ?? result.ruleId}
              </motion.p>
            </AnimatePresence>
          </div>
        </div>
        <p className="mt-4 font-mono text-[11.5px] leading-relaxed text-paper-dim">
          Live, from <span className="text-paper">decide()</span> — the same function the
          gateway runs. No model in the loop; flip it as many times as you like.
        </p>
      </Reveal>
    </Section>
  );
}
