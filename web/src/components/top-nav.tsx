"use client";

/**
 * top-nav.tsx — the header. Client component so the in-page "How it works" link can drive
 * Lenis directly (lenis.scrollTo); a native hash jump fights Lenis's hijacked scroll and
 * often does nothing. The #how target moves far down the page once the pinned gate mounts,
 * so we resolve it live via the selector rather than caching an offset.
 */

import { useLenis } from "lenis/react";

const REPO_URL = "https://github.com/jaitra-rewar4/aegis";

const link =
  "rounded transition-colors hover:text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-4 focus-visible:ring-offset-ink";

export function TopNav() {
  const lenis = useLenis();

  return (
    <header className="relative z-40 mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
      <a
        href="/"
        className="font-display text-lg font-bold tracking-tight text-paper"
      >
        Aegis
      </a>
      <nav className="flex items-center gap-6 font-mono text-[12px] uppercase tracking-[0.14em] text-paper-dim">
        <a
          href="#how"
          onClick={(e) => {
            if (lenis) {
              e.preventDefault();
              lenis.scrollTo("#how");
            }
          }}
          className={link}
        >
          How it works
        </a>
        <a href="/playground" className={link}>
          Playground
        </a>
        <a href={REPO_URL} target="_blank" rel="noreferrer" className={link}>
          GitHub
        </a>
      </nav>
    </header>
  );
}
