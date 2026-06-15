import { ParallaxGlow } from "@/components/parallax-glow";
import { Hero } from "@/components/hero";
import { Problem } from "@/components/sections/problem";
import { HowItWorks } from "@/components/sections/how-it-works";
import { SameCall } from "@/components/sections/same-call";
import { Tenets } from "@/components/sections/tenets";
import { CTA } from "@/components/sections/cta";

const REPO_URL = "https://github.com/jaitra-rewar4/aegis";

export default function Home() {
  return (
    <main className="relative flex-1 overflow-hidden">
      {/* atmospheric glow — first child of main so it sits behind everything */}
      <ParallaxGlow />

      <header className="relative mx-auto flex max-w-6xl items-center justify-between px-6 py-6">
        <span className="font-display text-lg font-bold tracking-tight text-paper">
          Aegis
        </span>
        <nav className="flex items-center gap-6 font-mono text-[12px] uppercase tracking-[0.14em] text-paper-dim">
          <a
            href="#how"
            className="rounded transition-colors hover:text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-4 focus-visible:ring-offset-ink"
          >
            How it works
          </a>
          <a
            href="/playground"
            className="rounded transition-colors hover:text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-4 focus-visible:ring-offset-ink"
          >
            Playground
          </a>
          <a
            href={REPO_URL}
            className="rounded transition-colors hover:text-paper focus-visible:outline-none focus-visible:ring-2 focus-visible:ring-paper focus-visible:ring-offset-4 focus-visible:ring-offset-ink"
          >
            GitHub
          </a>
        </nav>
      </header>

      <Hero />
      <Problem />
      <HowItWorks />
      <SameCall />
      <Tenets />
      <CTA />
    </main>
  );
}
