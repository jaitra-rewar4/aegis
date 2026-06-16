/**
 * §04 Principles — the three properties, as a numbered editorial list (hanging mono numbers,
 * hairline rules between rows), not a 3-card hover grid. The list form reads as a spec sheet,
 * which fits the instrument concept far better than floating cards. Server component.
 */

import { Section } from "@/components/section";
import { Reveal, RevealGroup, RevealItem } from "@/components/reveal";

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
  return (
    <Section index="04" label="Principles">
      <Reveal className="max-w-2xl">
        <h2 className="font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          Three properties, no exceptions.
        </h2>
        <p className="mt-5 text-[15px] leading-relaxed text-paper-dim sm:text-base">
          The whole design follows from these. Each one is a constraint the gate can never
          quietly break.
        </p>
      </Reveal>

      <RevealGroup className="mt-10 border-t border-line">
        {TENETS.map((tenet, i) => (
          <RevealItem key={tenet.title}>
            <div className="group grid grid-cols-[2.5rem_1fr] items-baseline gap-4 border-b border-line py-6 sm:grid-cols-[3.5rem_1fr] sm:gap-8 sm:py-7">
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
              </div>
            </div>
          </RevealItem>
        ))}
      </RevealGroup>
    </Section>
  );
}
