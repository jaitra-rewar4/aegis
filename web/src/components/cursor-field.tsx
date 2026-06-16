"use client";

/**
 * cursor-field.tsx — the interactive background.
 *
 * A fixed blueprint dot-grid (the instrument paper) plus a soft light that follows the
 * cursor and brightens the grid beneath it (screen blend). The light moves via transform
 * only (GPU-composited, rAF-throttled), so there is no per-frame layout or mask repaint and
 * nothing to jitter. The single grid layer means the dots never shift, so there is no
 * shimmer; the light just lifts whatever is under it.
 *
 * Fine-pointer only. On touch or prefers-reduced-motion the light never activates and the
 * static grid is all that shows.
 */

import { useEffect, useRef } from "react";
import { useReducedMotion } from "framer-motion";

const DOTS =
  "radial-gradient(circle, rgba(231,239,233,0.08) 1px, transparent 1.5px)";
const EDGE_FADE = "radial-gradient(120% 80% at 50% 0%, #000 28%, transparent 80%)";

export function CursorField() {
  const reduce = useReducedMotion();
  const lightRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (reduce || !window.matchMedia("(pointer: fine)").matches) return;
    const light = lightRef.current;
    if (!light) return;

    let raf = 0;
    let x = window.innerWidth / 2;
    let y = window.innerHeight / 2;

    const apply = () => {
      raf = 0;
      light.style.transform = `translate3d(${x - 350}px, ${y - 350}px, 0)`;
    };
    const onMove = (e: PointerEvent) => {
      x = e.clientX;
      y = e.clientY;
      if (!raf) raf = requestAnimationFrame(apply);
    };
    // Keep the light on-screen if the viewport shrinks before the next pointer move.
    const onResize = () => {
      x = Math.min(x, window.innerWidth);
      y = Math.min(y, window.innerHeight);
      if (!raf) raf = requestAnimationFrame(apply);
    };

    apply();
    light.style.opacity = "1";
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("resize", onResize, { passive: true });
    return () => {
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("resize", onResize);
      if (raf) cancelAnimationFrame(raf);
    };
  }, [reduce]);

  return (
    <div aria-hidden className="pointer-events-none fixed inset-0 -z-10">
      <div
        className="absolute inset-0"
        style={{
          backgroundImage: DOTS,
          backgroundSize: "32px 32px",
          maskImage: EDGE_FADE,
          WebkitMaskImage: EDGE_FADE,
        }}
      />
      <div
        ref={lightRef}
        className="absolute left-0 top-0 size-[700px] opacity-0 transition-opacity duration-700 will-change-transform"
        style={{
          background:
            "radial-gradient(circle, rgba(231,239,233,0.16), transparent 55%)",
          mixBlendMode: "screen",
        }}
      />
    </div>
  );
}
