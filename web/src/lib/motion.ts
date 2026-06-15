/**
 * motion.ts — shared motion primitives.
 *
 * ONE easing curve across the whole site (design rule): a soft "expo-out" cubic-bezier
 * that decelerates into rest. Importing EASE everywhere keeps every transition cohesive —
 * change it here and the whole site re-tunes together.
 */
import type { Variants } from "framer-motion";

/** The single cubic-bezier used for every transition on the site. */
export const EASE: [number, number, number, number] = [0.22, 1, 0.36, 1];

/** Reveal timing, shared by <Reveal> and <RevealGroup>. */
export const REVEAL_DURATION = 0.6;
export const REVEAL_DISTANCE = 24; // px of upward travel on reveal
export const STAGGER = 0.08; // seconds between staggered children

/** A child item inside a <RevealGroup>: starts low + faded, settles into place. */
export const revealItemVariants: Variants = {
  hidden: { opacity: 0, y: REVEAL_DISTANCE },
  show: {
    opacity: 1,
    y: 0,
    transition: { duration: REVEAL_DURATION, ease: EASE },
  },
};

/** The group container: orchestrates a gentle stagger over its children. */
export const revealGroupVariants: Variants = {
  hidden: {},
  show: { transition: { staggerChildren: STAGGER } },
};
