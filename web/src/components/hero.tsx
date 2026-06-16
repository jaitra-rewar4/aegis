"use client";

/**
 * hero.tsx — the hero. The headline does a per-word mask reveal (each word rises out of a
 * clipped line) — the signature typographic moment. The rest staggers in after it on load.
 * The primary CTA is magnetic (cursor-reactive). prefers-reduced-motion: words render in
 * place, fades are inert, the magnet is disabled.
 */

import { Fragment } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { VerdictStream } from "@/components/verdict-stream";
import { useMagnetic } from "@/lib/use-magnetic";
import { EASE } from "@/lib/motion";

const REPO_URL = "https://github.com/jaitra-rewar4/aegis";

// dim = the "what it says" half (muted); the rest is the "what it does" half (full paper).
const HEADLINE: { t: string; dim?: boolean }[] = [
  { t: "Guardrails", dim: true },
  { t: "check", dim: true },
  { t: "what", dim: true },
  { t: "an", dim: true },
  { t: "agent", dim: true },
  { t: "says.", dim: true },
  { t: "Aegis" },
  { t: "governs" },
  { t: "what" },
  { t: "it" },
  { t: "does." },
];

export function Hero() {
  const reduce = useReducedMotion();
  const magnet = useMagnetic<HTMLAnchorElement>(0.4);

  // Per-element load fade. Reduced motion -> no props -> static.
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

        <h1 className="font-display text-4xl font-bold leading-[1.05] tracking-[-0.02em] sm:text-5xl lg:text-[3.35rem]">
          {HEADLINE.map((w, i) => (
            <Fragment key={i}>
              <span className="inline-block overflow-hidden pb-[0.18em] -mb-[0.18em] align-bottom">
                <motion.span
                  className={`inline-block ${w.dim ? "text-paper-dim" : "text-paper"}`}
                  initial={reduce ? false : { y: "110%" }}
                  animate={reduce ? false : { y: 0 }}
                  transition={{ duration: 0.7, ease: EASE, delay: 0.12 + i * 0.045 }}
                >
                  {w.t}
                </motion.span>
              </span>{" "}
            </Fragment>
          ))}
        </h1>

        <motion.p
          {...fade(0.66)}
          className="mt-6 max-w-xl text-[15px] leading-relaxed text-paper-dim sm:text-base"
        >
          A deterministic gate at the tool-call boundary. Every action is allowed or denied
          on its parameters — and the sequence of actions before it — then written to an
          audit trail you can replay. No model sits in the decision path.
        </motion.p>

        <motion.div
          {...fade(0.76)}
          className="mt-9 flex flex-wrap items-center gap-3"
        >
          <motion.a
            ref={magnet.ref}
            onMouseMove={magnet.onMouseMove}
            onMouseLeave={magnet.onMouseLeave}
            style={{ x: magnet.x, y: magnet.y }}
            href="/playground"
            className="inline-flex items-center gap-2 rounded-lg bg-paper px-5 py-3 text-sm font-semibold text-ink transition-colors hover:bg-paper/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink"
          >
            Open the playground →
          </motion.a>
          <a
            href={REPO_URL}
            className="inline-flex items-center gap-2 rounded-lg border border-line-strong px-5 py-3 text-sm font-medium text-paper transition hover:bg-ink-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink"
          >
            View the source
          </a>
        </motion.div>
      </div>

      <motion.div {...fade(0.86)}>
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
