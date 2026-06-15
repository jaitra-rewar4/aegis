/**
 * Problem — "Action-layer blindness."
 *
 * Two side-by-side mono cards. LEFT: the agent's words, which a text filter waves through
 * (a green ✓ — a TEXT-filter pass, not an Aegis verdict). RIGHT: the action those words
 * actually emit — a send_email to an outside domain carrying records read this run (a coral
 * ✕ marking the danger). No ALLOW/DENY label appears here: the Aegis verdict is the next
 * section's job; this one just shows the gap between saying and doing.
 *
 * Server component: copy + <Reveal> wrappers (client leaves). The ✓/✕ are the only colour
 * on the section, and they carry meaning (pass / dangerous) — per the colour-as-meaning rule.
 */

import { Reveal, RevealGroup, RevealItem } from "@/components/reveal";

function Check() {
  return (
    <svg viewBox="0 0 12 12" className="size-3.5" aria-hidden>
      <path
        d="M2.5 6.2 5 8.5 9.5 3.5"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
        strokeLinejoin="round"
      />
    </svg>
  );
}

function Cross() {
  return (
    <svg viewBox="0 0 12 12" className="size-3.5" aria-hidden>
      <path
        d="M3.2 3.2 8.8 8.8M8.8 3.2 3.2 8.8"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.5"
        strokeLinecap="round"
      />
    </svg>
  );
}

export function Problem() {
  return (
    <section
      id="problem"
      className="relative mx-auto max-w-6xl px-6 py-24 sm:py-32"
    >
      <Reveal className="max-w-2xl">
        <p className="font-mono text-[12px] uppercase tracking-[0.2em] text-paper-dim">
          The problem
        </p>
        <h2 className="mt-4 font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
          Action-layer blindness.
        </h2>
        <p className="mt-5 text-[15px] leading-relaxed text-paper-dim sm:text-base">
          A guardrail reads what an agent <span className="text-paper">says</span>. The harm
          is in what it <span className="text-paper">does</span> — and the words clear the
          filter long before the action runs.
        </p>
      </Reveal>

      <RevealGroup className="mt-12 grid items-stretch gap-4 sm:mt-14 sm:grid-cols-2">
        {/* LEFT — what the text filter sees */}
        <RevealItem className="h-full">
          <div className="flex h-full flex-col rounded-xl border border-line bg-ink-raised p-5">
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
          </div>
        </RevealItem>

        {/* RIGHT — what actually executes */}
        <RevealItem className="h-full">
          <div className="flex h-full flex-col rounded-xl border border-line bg-ink-raised p-5">
            <p className="font-mono text-[11px] uppercase tracking-[0.16em] text-paper-dim">
              Actual tool call
            </p>
            <code className="mt-4 flex-1 font-mono text-[13px] leading-relaxed text-paper">
              <span className="block">send_email(</span>
              <span className="block pl-4 text-paper">
                to: &quot;ops@partner.example.com&quot;,
              </span>
              <span className="block pl-4 text-paper-dim">
                body: 1,204 customer records,
              </span>
              <span className="block">)</span>
            </code>
            <span className="mt-5 inline-flex w-fit items-center gap-2 font-mono text-[11px] uppercase tracking-[0.12em] text-deny">
              <Cross />
              egress to an outside domain, after the read
            </span>
          </div>
        </RevealItem>
      </RevealGroup>

      <Reveal className="mt-6">
        <p className="font-mono text-[12.5px] leading-relaxed text-paper-dim">
          The words were fine. The action wasn’t.
        </p>
      </Reveal>
    </section>
  );
}
