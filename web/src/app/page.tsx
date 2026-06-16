import { TopNav } from "@/components/top-nav";
import { ParallaxGlow } from "@/components/parallax-glow";
import { Hero } from "@/components/hero";
import { Problem } from "@/components/sections/problem";
import { HowItWorks } from "@/components/sections/how-it-works";
import { SameCall } from "@/components/sections/same-call";
import { Tenets } from "@/components/sections/tenets";
import { CTA } from "@/components/sections/cta";

export default function Home() {
  return (
    // No overflow-hidden here: the section rails and the pinned gate use position: sticky,
    // which an overflow-hidden ancestor silently breaks. overflow-x-clip guards against any
    // horizontal bleed (e.g. a magnetic button) without establishing a scroll container.
    <main className="relative flex-1 overflow-x-clip">
      <ParallaxGlow />
      <TopNav />
      <Hero />
      <Problem />
      <HowItWorks />
      <SameCall />
      <Tenets />
      <CTA />
    </main>
  );
}
