"use client";

/**
 * §01 Problem — "Action-layer blindness", with a text-filter scan.
 *
 * The left card holds the model's words; a scan beam sweeps it (the filter inspecting, then
 * passing). The right card is the action those words actually emit, marked "not inspected".
 * The scan runs when the section enters view and re-runs when you hover the left card. The ✓/✕
 * are the only colour and they carry meaning (pass / dangerous), not an Aegis verdict.
 */

import { useState } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { Section } from "@/components/section";
import { Reveal } from "@/components/reveal";

function Check() {
  return (
    <svg viewBox="0 0 12 12" className="size-3.5" aria-hidden>
      <path d="M2.5 6.2 5 8.5 9.5 3.5" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" strokeLinejoin="round" />
    </svg>
  );
}

function Cross() {
  return (
    <svg viewBox="0 0 12 12" className="size-3.5" aria-hidden>
      <path d="M3.2 3.2 8.8 8.8M8.8 3.2 3.2 8.8" fill="none" stroke="currentColor" strokeWidth="1.5" strokeLinecap="round" />
    </svg>
  );
}

export function Problem() {
  const reduce = useReducedMotion();
  const [scan, setScan] = useState(0);
  const rescan = () => {
    if (!reduce) setScan((s) => s + 1);
  };

  return (
    <Section index="01" label="The problem" id="problem">
      <Reveal className="max-w-2xl">
        <h2 className="font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          Action-layer blindness.
        </h2>
        <p className="mt-5 text-[15px] leading-relaxed text-paper-dim sm:text-base">
          A guardrail reads what an agent <span className="text-paper">says</span>. The harm is
          in what it <span className="text-paper">does</span>, and the words clear the filter
          long before the action runs.
        </p>
      </Reveal>

      <div className="mt-10 grid items-stretch gap-4 sm:grid-cols-2">
        {/* the words, scanned by a text filter */}
        <motion.div
          onViewportEnter={rescan}
          viewport={{ once: true, margin: "-80px" }}
          onMouseEnter={rescan}
          className="group relative flex h-full flex-col overflow-hidden rounded-xl border border-line bg-ink-raised p-5"
        >
          {!reduce && (
            <motion.div
              key={scan}
              initial={{ y: "-40%" }}
              animate={{ y: "150%" }}
              transition={{ duration: 1.15, ease: "linear" }}
              className="pointer-events-none absolute inset-x-0 top-0 h-12 bg-gradient-to-b from-transparent via-paper/12 to-transparent"
            />
          )}
          <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-paper-dim">
            Text filter · model output
          </p>
          <p className="mt-4 flex-1 font-mono text-[13px] leading-relaxed text-paper">
            “Shared the Q3 summary with the partner ops team — all set.”
          </p>
          <span className="mt-5 inline-flex w-fit items-center gap-2 font-mono text-[11px] uppercase tracking-[0.12em] text-allow">
            <Check />
            filter passed
          </span>
        </motion.div>

        {/* the action the filter never inspected */}
        <Reveal className="h-full" delay={0.15}>
          <div className="flex h-full flex-col rounded-xl border border-line bg-ink-raised p-5">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-paper-dim">
              Actual tool call · not inspected
            </p>
            <code className="mt-4 flex-1 font-mono text-[13px] leading-relaxed text-paper">
              <span className="block">send_email(</span>
              <span className="block pl-4 text-paper">
                to: &quot;ops@partner.example.com&quot;,
              </span>
              <span className="block pl-4 text-paper-dim">body: 1,204 customer records,</span>
              <span className="block">)</span>
            </code>
            <span className="mt-5 inline-flex w-fit items-center gap-2 font-mono text-[11px] uppercase tracking-[0.12em] text-deny">
              <Cross />
              egress to an outside domain, after the read
            </span>
          </div>
        </Reveal>
      </div>

      <Reveal className="mt-6">
        <p className="font-mono text-[12.5px] leading-relaxed text-paper-dim">
          The words were fine. The action wasn’t.{" "}
          <span className="text-paper-dim/60">Hover the left card to re-scan.</span>
        </p>
      </Reveal>
    </Section>
  );
}
