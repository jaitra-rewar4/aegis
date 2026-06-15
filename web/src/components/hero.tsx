"use client";

/**
 * hero.tsx — the hero, with its elements staggered in on page load.
 *
 * Order (eyebrow → headline → subhead → buttons → verdict panel) is driven by explicit
 * per-element delays rather than container stagger, so the sequence is exact even though the
 * panel lives in a different grid column from the copy. This is a LOAD animation
 * (initial → animate), not a scroll reveal.
 *
 * prefers-reduced-motion: every element renders in place with no transform (fade() returns
 * no motion props, so the motion elements are inert).
 */

import { motion, useReducedMotion } from "framer-motion";
import { VerdictStream } from "@/components/verdict-stream";
import { EASE } from "@/lib/motion";

const REPO_URL = "https://github.com/jaitra-rewar4/aegis";

export function Hero() {
  const reduce = useReducedMotion();

  // Per-element load animation. Reduced motion -> no props -> the element is static.
  const fade = (delay: number) =>
    reduce
      ? {}
      : {
          initial: { opacity: 0, y: 16 },
          animate: { opacity: 1, y: 0 },
          transition: { duration: 0.6, ease: EASE, delay },
        };

  return (
    <section className="relative mx-auto grid max-w-6xl grid-cols-1 items-center gap-12 px-6 pb-24 pt-10 lg:grid-cols-[1.05fr_1fr] lg:gap-16 lg:pt-16">
      <div>
        <motion.p
          {...fade(0)}
          className="mb-6 font-mono text-[12px] uppercase tracking-[0.2em] text-paper-dim"
        >
          Action-layer policy for AI agents
        </motion.p>

        <motion.h1
          {...fade(0.08)}
          className="font-display text-4xl font-bold leading-[1.05] tracking-[-0.02em] text-paper sm:text-5xl lg:text-[3.35rem]"
        >
          <span className="text-paper-dim">
            Guardrails check what an agent says.
          </span>{" "}
          Aegis governs what it does.
        </motion.h1>

        <motion.p
          {...fade(0.16)}
          className="mt-6 max-w-xl text-[15px] leading-relaxed text-paper-dim sm:text-base"
        >
          A deterministic gate at the tool-call boundary. Every action is allowed or denied
          on its parameters — and the sequence of actions before it — then written to an
          audit trail you can replay. No model sits in the decision path.
        </motion.p>

        <motion.div
          {...fade(0.24)}
          className="mt-9 flex flex-wrap items-center gap-3"
        >
          <a
            href="/playground"
            className="inline-flex items-center gap-2 rounded-lg bg-paper px-5 py-3 text-sm font-semibold text-ink transition hover:bg-paper/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink"
          >
            Open the playground →
          </a>
          <a
            href={REPO_URL}
            className="inline-flex items-center gap-2 rounded-lg border border-line-strong px-5 py-3 text-sm font-medium text-paper transition hover:bg-ink-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink"
          >
            View the source
          </a>
        </motion.div>
      </div>

      <motion.div {...fade(0.32)}>
        <VerdictStream />
        <p className="mt-4 font-mono text-[11.5px] leading-relaxed text-paper-dim">
          Live, from the real engine. Lines 2 and 6 are the same{" "}
          <span className="text-paper">send_email</span> — allowed before the customer
          record was read, <span className="text-deny">denied</span> after.
        </p>
      </motion.div>
    </section>
  );
}
