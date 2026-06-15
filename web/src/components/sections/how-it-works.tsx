"use client";

/**
 * How the gate works — a real 01–04 sequence with a connecting line that draws in on scroll.
 *
 * Client component: it uses Framer Motion for the line draw (scaleY 0 -> 1, origin top) and
 * the staggered step reveals. prefers-reduced-motion: the line renders fully drawn and the
 * steps render in place (RevealGroup/RevealItem handle that degradation themselves).
 */

import { motion, useReducedMotion } from "framer-motion";
import { Reveal, RevealGroup, RevealItem } from "@/components/reveal";
import { EASE } from "@/lib/motion";

const STEPS = [
  {
    n: "01",
    title: "The agent proposes a tool call",
    body: "A concrete action with concrete parameters — not a sentence, an instruction to do something.",
  },
  {
    n: "02",
    title: "Parameters are checked against policy",
    body: "Total, regex-free operators evaluate the arguments — numeric thresholds, allow-lists, recipient domains, keyword scans. Declarative and reviewable.",
  },
  {
    n: "03",
    title: "The trajectory is checked",
    body: "The prior actions taken this run, not the call in isolation. A send after a customer read is not the same as a send alone.",
  },
  {
    n: "04",
    title: "Allow or deny — then append",
    body: "First-match-wins, default deny. A single verdict at the tool-call boundary, written to a replayable audit trail.",
  },
];

export function HowItWorks() {
  const reduce = useReducedMotion();

  return (
    <section
      id="how"
      className="relative mx-auto max-w-6xl px-6 py-24 sm:py-32"
    >
      <Reveal className="max-w-2xl">
        <p className="font-mono text-[12px] uppercase tracking-[0.2em] text-paper-dim">
          How the gate works
        </p>
        <h2 className="mt-4 font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          Four steps, every action, no exceptions.
        </h2>
      </Reveal>

      <div className="relative mt-14">
        {/* The connecting line, drawn through the centre of the number column. */}
        <motion.div
          aria-hidden
          className="absolute left-7 top-4 bottom-4 w-px origin-top bg-line-strong"
          initial={reduce ? false : { scaleY: 0 }}
          whileInView={reduce ? undefined : { scaleY: 1 }}
          viewport={{ once: true, margin: "-100px" }}
          transition={{ duration: 1, ease: EASE }}
        />

        <RevealGroup className="space-y-9">
          {STEPS.map((step) => (
            <RevealItem key={step.n}>
              <div className="grid grid-cols-[56px_1fr] items-start gap-5 sm:gap-7">
                {/* Number node — opaque ground so the line reads as passing behind it. */}
                <div className="relative z-10 grid size-14 place-items-center rounded-full border border-line-strong bg-ink font-mono text-[13px] font-medium text-paper">
                  {step.n}
                </div>
                <div className="pt-2.5">
                  <h3 className="font-display text-lg font-semibold tracking-tight text-paper">
                    {step.title}
                  </h3>
                  <p className="mt-2 max-w-xl text-[14.5px] leading-relaxed text-paper-dim">
                    {step.body}
                  </p>
                </div>
              </div>
            </RevealItem>
          ))}
        </RevealGroup>
      </div>
    </section>
  );
}
