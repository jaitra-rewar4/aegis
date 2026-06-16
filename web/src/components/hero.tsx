"use client";

/**
 * hero.tsx — the first screen is a live, operable decision gate.
 *
 * The background field (decision-field) is the gate: real tool calls stream through it and get
 * judged. This hero puts a banner headline over it and, below, a LIVE decision record. The
 * record streams the canonical story, and then every action you catch by sweeping or clicking
 * the field appends to it in real time. You operate a real deterministic gate and watch it
 * write its own append-only audit log.
 *
 * The headline does a per-word mask reveal on load; the rest staggers in. The primary CTA is
 * magnetic. prefers-reduced-motion: words render in place, fades inert, magnet off (and the
 * field stops, so the log just shows its seeded sequence).
 */

import { Fragment } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { AuditLog } from "@/components/audit-log";
import { useMagnetic } from "@/lib/use-magnetic";
import { EASE } from "@/lib/motion";

const REPO_URL = "https://github.com/jaitra-rewar4/aegis";

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

  const fade = (delay: number) =>
    reduce
      ? {}
      : {
          initial: { opacity: 0, y: 16 },
          animate: { opacity: 1, y: 0 },
          transition: { duration: 0.6, ease: EASE, delay },
        };

  return (
    <section className="relative mx-auto flex min-h-[92svh] max-w-6xl flex-col justify-center px-6 py-24">
      <motion.p
        {...fade(0)}
        className="mb-6 font-mono text-[12px] uppercase tracking-[0.2em] text-paper-dim"
      >
        Action-layer policy for AI agents
      </motion.p>

      <h1 className="max-w-4xl font-display text-4xl font-bold leading-[1.04] tracking-[-0.02em] text-paper sm:text-5xl lg:text-6xl">
        {HEADLINE.map((w, i) => (
          <Fragment key={i}>
            <span className="inline-block overflow-hidden pb-[0.16em] -mb-[0.16em] align-bottom">
              <motion.span
                className={`inline-block ${w.dim ? "text-paper-dim" : "text-paper"}`}
                initial={reduce ? false : { y: "110%" }}
                animate={reduce ? false : { y: 0 }}
                transition={{ duration: 0.7, ease: EASE, delay: 0.1 + i * 0.04 }}
              >
                {w.t}
              </motion.span>
            </span>{" "}
          </Fragment>
        ))}
      </h1>

      <motion.p
        {...fade(0.62)}
        className="mt-6 max-w-xl text-[15px] leading-relaxed text-paper-dim sm:text-base"
      >
        A deterministic gate at the tool-call boundary. Every action is allowed or denied on its
        parameters and the sequence before it, then written to an audit trail you can replay. No
        model sits in the decision path.
      </motion.p>

      <motion.div {...fade(0.74)} className="mt-10 w-full max-w-5xl">
        <AuditLog />
        <p className="mt-3 font-mono text-[11.5px] leading-relaxed text-paper-dim">
          Live, from <span className="text-paper">decide()</span>. Sweep your cursor through the
          field behind this, or click it, to judge actions yourself. Every verdict you catch
          appends here.
        </p>
      </motion.div>

      <motion.div {...fade(0.84)} className="mt-9 flex flex-wrap items-center gap-3">
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
    </section>
  );
}
