"use client";

/**
 * smooth-scroll.tsx — global Lenis smooth scroll, the "flowing" feel.
 *
 * Wraps the whole app (mounted once in the root layout). In `root` mode Lenis drives the
 * window scroll and renders NO wrapper element, so it doesn't disturb the body's flex layout.
 *
 * prefers-reduced-motion: when reduced motion is requested we hand Lenis a `lerp` of 1 and
 * turn smoothWheel off — every frame snaps straight to the target, i.e. native, un-eased
 * scrolling. We keep the same component mounted (no markup difference) so there's no
 * hydration mismatch; only Lenis's runtime behavior changes.
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
        // lerp 1 = no interpolation = instant (reduced motion); 0.1 = smooth follow.
        lerp: reduce ? 1 : 0.1,
        duration: 1.1,
        smoothWheel: !reduce,
      }}
    >
      {children}
    </ReactLenis>
  );
}
