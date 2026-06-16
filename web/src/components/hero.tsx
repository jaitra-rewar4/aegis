"use client";

/**
 * hero.tsx — minimalist, and the first screen is a live, operable decision gate.
 *
 * The background field (decision-field) is the gate: real tool calls stream through it, you
 * stir the flow with your cursor, and judging an action (sweep or click) appends it to the
 * live decision record below the headline. Spare type, quiet links, no marketing buttons; the
 * interaction carries it. Headline does a per-word mask reveal on load; the rest staggers in.
 */

import { Fragment } from "react";
import { motion, useReducedMotion } from "framer-motion";
import { AuditLog } from "@/components/audit-log";
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
        parameters and the sequence before it, then written to a record you can replay.
      </motion.p>

      <motion.div {...fade(0.74)} className="mt-12 w-full max-w-4xl">
        <AuditLog />
        <p className="mt-3 font-mono text-[11.5px] leading-relaxed text-paper-dim">
          Stir the field with your cursor. Sweep over an action, or click, to judge it. Every
          verdict you catch appends here, live from <span className="text-paper">decide()</span>.
        </p>
      </motion.div>

      <motion.div
        {...fade(0.84)}
        className="mt-10 flex flex-wrap items-center gap-x-7 gap-y-3 font-mono text-[12px] uppercase tracking-[0.16em]"
      >
        <a
          href="/playground"
          className="group inline-flex items-center gap-2 text-paper transition-colors"
        >
          <span className="border-b border-paper/30 pb-0.5 transition-colors group-hover:border-paper">
            Playground
          </span>
          <span aria-hidden className="text-paper-dim transition-transform group-hover:translate-x-0.5">
            ↗
          </span>
        </a>
        <a
          href={REPO_URL}
          target="_blank"
          rel="noreferrer"
          className="group inline-flex items-center gap-2 text-paper-dim transition-colors hover:text-paper"
        >
          <span className="border-b border-transparent pb-0.5 transition-colors group-hover:border-paper">
            Source
          </span>
          <span aria-hidden>↗</span>
        </a>
      </motion.div>
    </section>
  );
}
