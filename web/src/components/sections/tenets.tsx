"use client";

/**
 * §04 Principles — each principle proves itself with the real engine.
 *
 * Deterministic: the same call returns the same verdict, every run. Action-layer: the words
 * are ignored, the action is judged. Trajectory-aware: the same send flips ALLOW to DENY by
 * the order it arrives in. The verdict chips are live decide() output, not assertions.
 */

import { motion, useReducedMotion } from "framer-motion";
import { Section } from "@/components/section";
import { Reveal, RevealGroup, RevealItem } from "@/components/reveal";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";
import type { Decision } from "@/lib/engine/types";
import { EASE } from "@/lib/motion";

const READ = [{ tool: "lookup_customer", decision: "ALLOW" }];
const V_AFTER = decide(defaultPack, "send_email", { to: "ops@partner.example.com" }, READ).decision;
const V_ALONE = decide(defaultPack, "send_email", { to: "ops@partner.example.com" }, []).decision;
const V_DROP = decide(defaultPack, "execute_sql", { sql: "DROP TABLE audit_log" }, []).decision;

function Chip({
  decision,
  reduce,
  delay = 0,
}: {
  decision: Decision;
  reduce: boolean | null;
  delay?: number;
}) {
  const allow = decision === "ALLOW";
  return (
    <motion.span
      initial={reduce ? false : { scale: 0.7, opacity: 0 }}
      whileInView={reduce ? undefined : { scale: 1, opacity: 1 }}
      viewport={{ once: true, margin: "-40px" }}
      transition={{ delay, duration: 0.26, ease: EASE }}
      className={`inline-flex items-center gap-1.5 rounded px-1.5 py-0.5 font-mono text-[10px] font-semibold ${
        allow ? "bg-allow-soft text-allow" : "bg-deny-soft text-deny"
      }`}
    >
      <span className={`size-1 rounded-full ${allow ? "bg-allow" : "bg-deny"}`} aria-hidden />
      {decision}
    </motion.span>
  );
}

type Kind = "repeat" | "saysdoes" | "order";

const TENETS: { title: string; body: string; kind: Kind }[] = [
  {
    title: "Deterministic",
    body: "No model sits in the decision path. The same inputs produce the same verdict, every time.",
    kind: "repeat",
  },
  {
    title: "Action-layer",
    body: "Aegis governs tool calls and their parameters, not model text. It judges what the agent does, never what it says.",
    kind: "saysdoes",
  },
  {
    title: "Trajectory-aware",
    body: "A call is judged by the sequence that led to it. A read and then a send reads differently than a send on its own.",
    kind: "order",
  },
];

function Proof({ kind, reduce }: { kind: Kind; reduce: boolean | null }) {
  if (kind === "repeat") {
    return (
      <div className="mt-4 flex flex-wrap items-center gap-2 font-mono text-[11px] text-paper-dim">
        <span>decide(send_email · after a read)</span>
        <span aria-hidden>→</span>
        <Chip decision={V_AFTER} reduce={reduce} delay={0} />
        <Chip decision={V_AFTER} reduce={reduce} delay={0.12} />
        <Chip decision={V_AFTER} reduce={reduce} delay={0.24} />
        <span className="text-paper-dim/60">every run</span>
      </div>
    );
  }
  if (kind === "saysdoes") {
    return (
      <div className="mt-4 space-y-1.5 font-mono text-[11px]">
        <div className="flex flex-wrap items-center gap-2">
          <span className="text-paper-dim">says</span>
          <span className="text-paper-dim/70">“I’ll tidy the logging table”</span>
          <span className="text-paper-dim/50">not evaluated</span>
        </div>
        <div className="flex flex-wrap items-center gap-2 text-paper-dim">
          <span className="text-paper-dim">does</span>
          <span className="text-paper">execute_sql(&quot;DROP TABLE …&quot;)</span>
          <span aria-hidden>→</span>
          <Chip decision={V_DROP} reduce={reduce} />
        </div>
      </div>
    );
  }
  return (
    <div className="mt-4 space-y-1.5 font-mono text-[11px] text-paper-dim">
      <div className="flex flex-wrap items-center gap-2">
        <span className="text-paper">send_email(partner)</span>
        <span>alone</span>
        <span aria-hidden>→</span>
        <Chip decision={V_ALONE} reduce={reduce} />
      </div>
      <div className="flex flex-wrap items-center gap-2">
        <span>after</span>
        <span className="text-paper">lookup_customer</span>
        <span aria-hidden>→</span>
        <Chip decision={V_AFTER} reduce={reduce} delay={0.1} />
      </div>
    </div>
  );
}

export function Tenets() {
  const reduce = useReducedMotion();
  return (
    <Section index="04" label="Principles">
      <Reveal className="max-w-2xl">
        <h2 className="font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          Three properties, no exceptions.
        </h2>
        <p className="mt-5 text-[15px] leading-relaxed text-paper-dim sm:text-base">
          The whole design follows from these. Each one proves itself below, with the real
          engine.
        </p>
      </Reveal>

      <RevealGroup className="mt-10 border-t border-line">
        {TENETS.map((tenet, i) => (
          <RevealItem key={tenet.title}>
            <div className="group grid grid-cols-[2.5rem_1fr] items-baseline gap-4 border-b border-line py-7 sm:grid-cols-[3.5rem_1fr] sm:gap-8">
              <span className="font-mono text-[13px] tabular-nums text-paper-dim transition-colors group-hover:text-paper">
                0{i + 1}
              </span>
              <div>
                <h3 className="font-display text-xl font-semibold tracking-tight text-paper">
                  {tenet.title}
                </h3>
                <p className="mt-2 max-w-xl text-[14.5px] leading-relaxed text-paper-dim">
                  {tenet.body}
                </p>
                <Proof kind={tenet.kind} reduce={reduce} />
              </div>
            </div>
          </RevealItem>
        ))}
      </RevealGroup>
    </Section>
  );
}
