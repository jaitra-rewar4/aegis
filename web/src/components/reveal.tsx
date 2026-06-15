"use client";

/**
 * reveal.tsx — scroll-into-view reveal primitives, used by every section.
 *
 * <Reveal>      one element: fades + rises 24px into place when it scrolls into view.
 * <RevealGroup> a container that staggers its <RevealItem> children ~0.08s apart.
 * <RevealItem>  a child of RevealGroup; consumes the group's stagger.
 *
 * viewport={{ once: true, margin: "-100px" }} — animate a single time, and start a little
 * before the element's top edge reaches the viewport so it's already settling as it appears.
 *
 * prefers-reduced-motion: we drop the transform/opacity animation entirely and render the
 * content in its final state (a plain element). No motion, no layout shift, fully visible.
 */

import { motion, useReducedMotion } from "framer-motion";
import type { ReactNode } from "react";
import {
  EASE,
  REVEAL_DISTANCE,
  REVEAL_DURATION,
  revealGroupVariants,
  revealItemVariants,
} from "@/lib/motion";

const VIEWPORT = { once: true, margin: "-100px" } as const;

export function Reveal({
  children,
  className,
  delay = 0,
}: {
  children: ReactNode;
  className?: string;
  delay?: number;
}) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div
      className={className}
      initial={{ opacity: 0, y: REVEAL_DISTANCE }}
      whileInView={{ opacity: 1, y: 0 }}
      viewport={VIEWPORT}
      transition={{ duration: REVEAL_DURATION, ease: EASE, delay }}
    >
      {children}
    </motion.div>
  );
}

export function RevealGroup({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div
      className={className}
      variants={revealGroupVariants}
      initial="hidden"
      whileInView="show"
      viewport={VIEWPORT}
    >
      {children}
    </motion.div>
  );
}

export function RevealItem({
  children,
  className,
}: {
  children: ReactNode;
  className?: string;
}) {
  const reduce = useReducedMotion();

  if (reduce) {
    return <div className={className}>{children}</div>;
  }

  return (
    <motion.div className={className} variants={revealItemVariants}>
      {children}
    </motion.div>
  );
}
