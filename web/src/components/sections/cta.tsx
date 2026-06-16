/**
 * CTA — the closing call to action: a deliberate centred break after the left-aligned record
 * sections, hairline-topped, with the unified H2 scale. Server component (links only).
 */

import { Reveal } from "@/components/reveal";

const REPO_URL = "https://github.com/jaitra-rewar4/aegis";

export function CTA() {
  return (
    <section className="relative border-t border-line">
      <div className="mx-auto max-w-6xl px-6 py-24 sm:py-28">
        <Reveal className="mx-auto max-w-2xl text-center">
          <h2 className="font-display text-3xl font-bold tracking-[-0.02em] text-paper sm:text-4xl">
            Govern what your agent does.
          </h2>
          <p className="mx-auto mt-5 max-w-xl text-[15px] leading-relaxed text-paper-dim sm:text-base">
            Run the real engine in the playground, or read every line of the gate, the policy
            packs, and the audit log on GitHub.
          </p>
          <div className="mt-9 flex flex-wrap items-center justify-center gap-3">
            <a
              href="/playground"
              className="inline-flex items-center gap-2 rounded-lg bg-paper px-5 py-3 text-sm font-semibold text-ink transition hover:bg-paper/90 focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink"
            >
              Try the playground →
            </a>
            <a
              href={REPO_URL}
              className="inline-flex items-center gap-2 rounded-lg border border-line-strong px-5 py-3 text-sm font-medium text-paper transition hover:bg-ink-high focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-2 focus-visible:ring-offset-ink"
            >
              Read the source
            </a>
          </div>
        </Reveal>
      </div>
    </section>
  );
}
