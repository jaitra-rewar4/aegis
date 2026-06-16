"use client";

/**
 * §02 How the gate works — the page behaves like the gate.
 *
 * On a capable desktop it PINS and is scroll-SCRUBBED: as you scroll the ~230vh container the
 * 01–04 steps light in sequence AND a live evaluation console on the right builds up, line by
 * line, ending on a REAL verdict from decide(). So the longest scroll stretch is also the most
 * "integrated" — the right half is never empty and the frame never looks frozen.
 *
 * Fallback (pre-mount, reduced-motion, or below lg): a plain stacked Section with the steps and
 * the full console, no pin, no giant scroll area. The swap is post-hydration so SSR matches the
 * first client render.
 */

import { useEffect, useRef, useState } from "react";
import {
  motion,
  useMotionValueEvent,
  useReducedMotion,
  useScroll,
  useTransform,
} from "framer-motion";
import { Section } from "@/components/section";
import { Reveal } from "@/components/reveal";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";
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
    body: "Total, regex-free operators evaluate the arguments — thresholds, allow-lists, recipient domains, keyword scans.",
  },
  {
    n: "03",
    title: "The trajectory is checked",
    body: "The prior actions taken this run, not the call in isolation. A send after a customer read is not a send alone.",
  },
  {
    n: "04",
    title: "Allow or deny — then append",
    body: "First-match-wins, default deny. One verdict at the tool-call boundary, written to a replayable audit trail.",
  },
];

// The worked example the console evaluates — the verdict is REAL, from decide().
const EXAMPLE = decide(
  defaultPack,
  "send_email",
  { to: "ops@partner.example.com" },
  [{ tool: "lookup_customer", decision: "ALLOW" }],
);

const LINES: { k: string; v: string; verdict?: boolean }[] = [
  { k: "propose", v: 'send_email(to: "ops@partner.example.com")' },
  { k: "params", v: "to → domain_not_in [internal.example.com] · external" },
  { k: "trajectory", v: "lookup_customer → ALLOW · earlier this run" },
  { k: "verdict", v: `${EXAMPLE.decision} · ${EXAMPLE.ruleId}`, verdict: true },
];

function Header() {
  return (
    <>
      <p className="font-mono text-[12px] uppercase tracking-[0.2em] text-paper-dim">
        <span className="text-paper">§02</span> · How the gate works
      </p>
      <h2 className="mt-4 max-w-2xl font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
        Four steps, every action, no exceptions.
      </h2>
    </>
  );
}

function StepRow({
  step,
  active,
  done,
}: {
  step: (typeof STEPS)[number];
  active: boolean;
  done: boolean;
}) {
  const lit = active || done;
  return (
    <div className="grid grid-cols-[56px_1fr] items-start gap-5 sm:gap-7">
      <motion.div
        animate={{ scale: active ? 1.08 : 1 }}
        transition={{ duration: 0.3, ease: EASE }}
        className={`relative z-10 grid size-14 place-items-center rounded-full border bg-ink font-mono text-[13px] font-medium transition-colors duration-300 ${
          lit ? "border-paper text-paper" : "border-line-strong text-paper-dim"
        }`}
      >
        {step.n}
      </motion.div>
      <div
        className={`pt-2.5 transition-opacity duration-300 ${
          lit ? "opacity-100" : "opacity-40"
        }`}
      >
        <h3 className="font-display text-lg font-semibold tracking-tight text-paper">
          {step.title}
        </h3>
        <p className="mt-2 max-w-md text-[14.5px] leading-relaxed text-paper-dim">
          {step.body}
        </p>
      </div>
    </div>
  );
}

/** The live evaluation console — reveals `shown` lines; the verdict line is real decide() output. */
function EvalConsole({ shown, reduce }: { shown: number; reduce: boolean | null }) {
  const denied = EXAMPLE.decision === "DENY";
  return (
    <div className="rounded-xl border border-line-strong bg-ink p-5 sm:p-6">
      <div className="flex items-center gap-2 border-b border-line pb-3">
        <span className="size-1.5 rounded-full bg-paper-dim/40" aria-hidden />
        <span className="font-mono text-[11px] uppercase tracking-[0.18em] text-paper-dim">
          evaluate · send_email
        </span>
      </div>
      <div className="mt-4 space-y-2.5">
        {LINES.slice(0, Math.max(0, shown)).map((line) => (
          <motion.div
            key={line.k}
            initial={reduce ? false : { opacity: 0, y: 6 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.3, ease: EASE }}
            className="flex gap-3 font-mono text-[12.5px] leading-relaxed"
          >
            <span className="w-[4.5rem] shrink-0 text-paper-dim">{line.k}</span>
            <span
              className={
                line.verdict
                  ? denied
                    ? "text-deny"
                    : "text-allow"
                  : "text-paper"
              }
            >
              {line.v}
            </span>
          </motion.div>
        ))}
        {shown >= LINES.length && (
          <motion.p
            initial={reduce ? false : { opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.3, ease: EASE }}
            className="pt-1 font-mono text-[11.5px] text-paper-dim/70"
          >
            appended → audit.log · immutable
          </motion.p>
        )}
      </div>
    </div>
  );
}

/** Plain, non-pinned version: server render, reduced-motion, mobile/tablet. */
function StaticGate() {
  const reduce = useReducedMotion();
  return (
    <Section index="02" label="How the gate works" id="how">
      <Reveal className="max-w-2xl">
        <h2 className="font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          Four steps, every action, no exceptions.
        </h2>
      </Reveal>
      <div className="mt-10 grid gap-10 lg:grid-cols-[1fr_1fr] lg:gap-12">
        <div className="relative">
          <motion.div
            aria-hidden
            className="absolute left-7 top-4 bottom-4 w-px origin-top bg-line-strong"
            initial={reduce ? false : { scaleY: 0 }}
            whileInView={reduce ? undefined : { scaleY: 1 }}
            viewport={{ once: true, margin: "-100px" }}
            transition={{ duration: 1, ease: EASE }}
          />
          <div className="space-y-9">
            {STEPS.map((step) => (
              <StepRow key={step.n} step={step} active={false} done />
            ))}
          </div>
        </div>
        <Reveal className="lg:pt-2">
          <EvalConsole shown={LINES.length} reduce={reduce} />
        </Reveal>
      </div>
    </Section>
  );
}

/** Pinned, scroll-scrubbed version (desktop only). */
function ScrubGate() {
  const ref = useRef<HTMLElement>(null);
  const { scrollYProgress } = useScroll({
    target: ref,
    offset: ["start start", "end end"],
  });
  // Land the spine exactly as step 04 lights (active flips at p >= 0.75).
  const lineScale = useTransform(scrollYProgress, [0.02, 0.75], [0, 1]);
  const [active, setActive] = useState(0);

  useMotionValueEvent(scrollYProgress, "change", (p) => {
    const idx = Math.min(STEPS.length - 1, Math.max(0, Math.floor(p * STEPS.length)));
    setActive((prev) => (prev === idx ? prev : idx));
  });

  return (
    <section id="how" ref={ref} className="relative h-[190vh]">
      <div className="sticky top-0 flex min-h-[100svh] items-start">
        <div className="mx-auto w-full max-w-6xl px-6 py-16">
          <Header />
          <div className="mt-12 grid grid-cols-[1fr_1fr] gap-12 lg:gap-16">
            <div className="relative">
              <div
                aria-hidden
                className="absolute left-7 top-4 bottom-4 w-px bg-line"
              />
              <motion.div
                aria-hidden
                className="absolute left-7 top-4 bottom-4 w-px origin-top bg-paper"
                style={{ scaleY: lineScale }}
              />
              <div className="space-y-9">
                {STEPS.map((step, i) => (
                  <StepRow
                    key={step.n}
                    step={step}
                    active={i === active}
                    done={i < active}
                  />
                ))}
              </div>
            </div>
            <div className="self-center">
              <EvalConsole shown={active + 1} reduce={false} />
              <p className="mt-5 font-mono text-[11px] uppercase tracking-[0.16em] text-paper-dim">
                {active < STEPS.length - 1
                  ? `evaluating · step ${String(active + 1).padStart(2, "0")} / 04`
                  : "verdict reached · appended to audit log"}
              </p>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

export function HowItWorks() {
  const reduce = useReducedMotion();
  const [enhance, setEnhance] = useState(false);

  useEffect(() => {
    const mq = window.matchMedia("(min-width: 1024px)");
    const update = () => setEnhance(mq.matches);
    update();
    mq.addEventListener("change", update);
    return () => mq.removeEventListener("change", update);
  }, []);

  // Pin+scrub only on capable, motion-allowing, wide clients. Everything else gets the
  // plain stacked Section (which still shows the steps and the full evaluation console).
  if (!enhance || reduce) return <StaticGate />;
  return <ScrubGate />;
}
