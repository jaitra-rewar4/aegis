"use client";

/**
 * parallax-glow.tsx — the hero's atmospheric glow, drifting slower than the page scroll.
 *
 * useScroll() tracks the window scroll (Lenis drives the real scroll, so this stays in sync);
 * useTransform maps 0–700px of scroll to 0–140px of downward drift — roughly 0.2× scroll
 * speed, so the glow lags behind the content for a subtle parallax. Rendered as the first
 * child of <main> so it sits behind everything; pointer-events-none so it never intercepts.
 *
 * prefers-reduced-motion: no transform is applied — the glow is simply static.
 */

import { motion, useReducedMotion, useScroll, useTransform } from "framer-motion";

const GLOW =
  "radial-gradient(60% 70% at 70% 0%, rgba(84,198,140,0.10), transparent 70%)";

export function ParallaxGlow() {
  const reduce = useReducedMotion();
  const { scrollY } = useScroll();
  const y = useTransform(scrollY, [0, 700], [0, 140]);

  return (
    <motion.div
      aria-hidden
      className="pointer-events-none absolute inset-x-0 top-0 h-[36rem] opacity-50"
      style={{ background: GLOW, ...(reduce ? {} : { y }) }}
    />
  );
}
