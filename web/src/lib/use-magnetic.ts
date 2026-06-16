"use client";

/**
 * useMagnetic — a cursor-reactive "magnet" for a single element. While the pointer is over it,
 * the element eases toward the cursor (a fraction of the offset); on leave it springs back to
 * centre. Returns spring-backed motion values to bind to `style={{ x, y }}` plus the handlers.
 * Disabled under prefers-reduced-motion (the values stay pinned at 0).
 */

import { useRef } from "react";
import type { MouseEvent } from "react";
import { useMotionValue, useReducedMotion, useSpring } from "framer-motion";

export function useMagnetic<T extends HTMLElement>(strength = 0.35) {
  const ref = useRef<T>(null);
  const reduce = useReducedMotion();
  const x = useMotionValue(0);
  const y = useMotionValue(0);
  const sx = useSpring(x, { stiffness: 220, damping: 18, mass: 0.6 });
  const sy = useSpring(y, { stiffness: 220, damping: 18, mass: 0.6 });

  function onMouseMove(e: MouseEvent<T>) {
    if (reduce) return;
    const el = ref.current;
    if (!el) return;
    const r = el.getBoundingClientRect();
    x.set((e.clientX - (r.left + r.width / 2)) * strength);
    y.set((e.clientY - (r.top + r.height / 2)) * strength);
  }

  function onMouseLeave() {
    x.set(0);
    y.set(0);
  }

  return { ref, x: sx, y: sy, onMouseMove, onMouseLeave };
}
