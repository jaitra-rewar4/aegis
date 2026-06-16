"use client";

/**
 * scroll-rail.tsx — a thin scroll-position instrument on the right edge (desktop only):
 * a hairline track with an off-white fill driven by scroll progress, plus a mono percentage
 * readout. It fits the "decision record / instrument" concept and reflects real position
 * rather than adding gratuitous motion. Green is reserved for verdicts, so the fill is paper.
 */

import { motion, useScroll, useTransform } from "framer-motion";

export function ScrollRail() {
  const { scrollYProgress } = useScroll();
  const pct = useTransform(scrollYProgress, (v) =>
    Math.round(v * 100)
      .toString()
      .padStart(2, "0"),
  );

  return (
    <div
      aria-hidden
      className="pointer-events-none fixed right-6 top-1/2 z-40 hidden -translate-y-1/2 flex-col items-center gap-3 lg:flex"
    >
      <span className="font-mono text-[10px] uppercase tracking-[0.18em] text-paper-dim/70">
        scroll
      </span>
      <div className="relative h-40 w-px overflow-hidden bg-line-strong">
        <motion.div
          className="absolute inset-x-0 top-0 h-full origin-top bg-paper"
          style={{ scaleY: scrollYProgress }}
        />
      </div>
      <motion.span className="font-mono text-[10px] tabular-nums tracking-[0.1em] text-paper-dim">
        {pct}
      </motion.span>
    </div>
  );
}
