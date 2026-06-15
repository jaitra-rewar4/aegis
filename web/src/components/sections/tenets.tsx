"use client";

/**
 * Three tenets — cards that lift slightly on hover. RevealGroup staggers them in; each card
 * is a motion element with a small hover lift. prefers-reduced-motion: no lift, no reveal
 * transform (RevealItem degrades; the hover is gated on `reduce`).
 */

import { motion, useReducedMotion } from "framer-motion";
import { RevealGroup, RevealItem } from "@/components/reveal";
import { EASE } from "@/lib/motion";

const TENETS = [
  {
    title: "Deterministic",
    body: "No model sits in the decision path. The same inputs produce the same verdict, every time — auditable, testable, replayable.",
  },
  {
    title: "Action-layer",
    body: "Aegis governs tool calls and their parameters, not model text. It judges what the agent does, never what it says.",
  },
  {
    title: "Trajectory-aware",
    body: "A call is judged by the sequence that led to it. A read and then a send reads differently than a send on its own.",
  },
];

export function Tenets() {
  const reduce = useReducedMotion();

  return (
    <section className="relative mx-auto max-w-6xl px-6 py-24 sm:py-32">
      <RevealGroup className="grid gap-4 sm:grid-cols-3">
        {TENETS.map((tenet, i) => (
          <RevealItem key={tenet.title} className="h-full">
            <motion.div
              whileHover={reduce ? undefined : { y: -4 }}
              transition={{ duration: 0.3, ease: EASE }}
              className="flex h-full flex-col rounded-xl border border-line bg-ink-raised p-6 transition-colors hover:border-line-strong"
            >
              <span className="font-mono text-[12px] tracking-[0.1em] text-paper-dim">
                {String(i + 1).padStart(2, "0")}
              </span>
              <h3 className="mt-5 font-display text-xl font-semibold tracking-tight text-paper">
                {tenet.title}
              </h3>
              <p className="mt-3 text-[14.5px] leading-relaxed text-paper-dim">
                {tenet.body}
              </p>
            </motion.div>
          </RevealItem>
        ))}
      </RevealGroup>
    </section>
  );
}
