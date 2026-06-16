/**
 * Footer — closes the "decision record" metaphor: the page ends on an audit-log line rather
 * than a hard cut to bare ink. Hairline-topped, mono, quiet.
 */

const REPO_URL = "https://github.com/jaitra-rewar4/aegis";

const link =
  "rounded transition-colors hover:text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-4 focus-visible:ring-offset-ink";

export function Footer() {
  return (
    <footer className="relative border-t border-line">
      <div className="mx-auto flex max-w-6xl flex-col gap-6 px-6 py-12 sm:flex-row sm:items-center sm:justify-between">
        <div className="flex items-baseline gap-3">
          <span className="font-display text-base font-bold tracking-tight text-paper">
            Aegis
          </span>
          <span className="font-mono text-[11px] text-paper-dim">
            deterministic action-layer policy
          </span>
        </div>
        <nav className="flex items-center gap-6 font-mono text-[11px] uppercase tracking-[0.16em] text-paper-dim">
          <a href="/playground" className={link}>
            Playground
          </a>
          <a href={REPO_URL} target="_blank" rel="noreferrer" className={link}>
            GitHub
          </a>
          <a
            href={`${REPO_URL}/blob/main/LICENSE`}
            target="_blank"
            rel="noreferrer"
            className={link}
          >
            MIT
          </a>
        </nav>
      </div>
      <div className="mx-auto max-w-6xl px-6 pb-10">
        <p className="font-mono text-[11px] leading-relaxed text-paper-dim/60">
          record · every action allowed or denied at the tool-call boundary ·
          first-match-wins, default deny · appended to an immutable audit trail
        </p>
      </div>
    </footer>
  );
}
