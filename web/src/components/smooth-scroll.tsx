"use client";

/**
 * smooth-scroll.tsx — global Lenis smooth scroll, the "flowing" feel.
 *
 * Wraps the whole app (mounted once in the root layout). In `root` mode Lenis drives the
 * window scroll and renders NO wrapper element, so it doesn't disturb the body's flex layout.
 * Lenis self-drives its rAF (autoRaf default); Framer Motion's useScroll reads the resulting
 * window scroll, so the pinned/scrubbed sections stay in sync without any extra wiring.
 *
 * prefers-reduced-motion: lerp 1 + smoothWheel off → instant, native-feeling scroll.
 */

import { ReactLenis } from "lenis/react";
import { useReducedMotion } from "framer-motion";
import type { ReactNode } from "react";

export function SmoothScroll({ children }: { children: ReactNode }) {
  const reduce = useReducedMotion();

  return (
    <ReactLenis
      root
      options={{
        lerp: reduce ? 1 : 0.1,
        duration: 1.1,
        smoothWheel: !reduce,
      }}
    >
      {children}
    </ReactLenis>
  );
}
