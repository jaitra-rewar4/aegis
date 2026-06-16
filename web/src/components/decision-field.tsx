"use client";

/**
 * decision-field.tsx — the interactive background, and it IS the product.
 *
 * Real tool-call tokens drift slowly across the page over the blueprint grid. At rest they
 * are dim and monochrome. As the cursor sweeps near one, it brightens and reveals its verdict
 * straight from decide() with the default pack: green ALLOW or coral DENY. So the only colour
 * in the background is a real gate verdict, and moving the cursor "inspects" the actions
 * flowing through the gate. A soft scan light follows the cursor underneath it all.
 *
 * Everything animates via transform/opacity in one rAF loop driven by refs (no React state
 * per frame), so it stays smooth. Fine-pointer only; on touch or reduced-motion the tokens
 * never activate and only the static grid shows.
 */

import { useEffect, useRef } from "react";
import { useReducedMotion } from "framer-motion";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";

const DOTS =
  "radial-gradient(circle, rgba(231,239,233,0.08) 1px, transparent 1.5px)";
const EDGE_FADE = "radial-gradient(120% 80% at 50% 0%, #000 28%, transparent 80%)";

type Spec = {
  call: string;
  tool: string;
  params: Record<string, unknown>;
  traj: { tool: string; decision: string }[];
};

// Each token is a real call; its verdict is computed once from the real engine, so what you
// see judged on screen is exactly what the gateway would decide for that action.
const SPECS: Spec[] = [
  { call: "lookup_customer(4012)", tool: "lookup_customer", params: { customer_id: "4012" }, traj: [] },
  { call: 'calculator("0.0825 * 2400")', tool: "calculator", params: { expression: "0.0825 * 2400" }, traj: [] },
  { call: 'execute_sql("SELECT plan …")', tool: "execute_sql", params: { sql: "SELECT plan FROM accounts" }, traj: [] },
  { call: 'execute_sql("DROP TABLE …")', tool: "execute_sql", params: { sql: "DROP TABLE audit_log" }, traj: [] },
  { call: 'send_email("audit@internal…")', tool: "send_email", params: { to: "audit@internal.example.com" }, traj: [] },
  { call: 'send_email("ops@partner…")', tool: "send_email", params: { to: "ops@partner.example.com" }, traj: [{ tool: "lookup_customer", decision: "ALLOW" }] },
  { call: 'send_email("x@unknown.io")', tool: "send_email", params: { to: "x@unknown.io" }, traj: [] },
  { call: "lookup_customer(7781)", tool: "lookup_customer", params: { customer_id: "7781" }, traj: [] },
];

const TOKENS = SPECS.map((s) => ({
  call: s.call,
  decision: decide(defaultPack, s.tool, s.params, s.traj).decision,
}));

export function DecisionField() {
  const reduce = useReducedMotion();
  const lightRef = useRef<HTMLDivElement>(null);
  const tokenRefs = useRef<(HTMLDivElement | null)[]>([]);

  useEffect(() => {
    if (reduce || !window.matchMedia("(pointer: fine)").matches) return;

    let W = window.innerWidth;
    let H = window.innerHeight;
    const REVEAL = 150;
    const light = lightRef.current;

    const T = TOKENS.map(() => ({
      x: Math.random() * W,
      y: 70 + Math.random() * Math.max(120, H - 140),
      vx: 22 + Math.random() * 26, // px per second, gentle rightward drift
      vy: (Math.random() - 0.5) * 10,
      op: 0,
    }));
    let px = W / 2;
    let py = H / 2;
    let raf = 0;
    let last = performance.now();

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;

      if (light) light.style.transform = `translate3d(${px - 350}px, ${py - 350}px, 0)`;

      for (let i = 0; i < T.length; i++) {
        const el = tokenRefs.current[i];
        if (!el) continue;
        const t = T[i];

        t.x += t.vx * dt;
        t.y += t.vy * dt;
        if (t.x > W + 160) {
          t.x = -240;
          t.y = 70 + Math.random() * Math.max(120, H - 140);
        }
        if (t.y < 60 || t.y > H - 40) {
          t.vy = -t.vy;
          t.y = Math.max(60, Math.min(H - 40, t.y));
        }

        const dx = t.x - px;
        const dy = t.y - py;
        const near = dx * dx + dy * dy < REVEAL * REVEAL;
        const target = near ? 0.78 : 0.14;
        t.op += (target - t.op) * 0.12;

        el.style.transform = `translate3d(${t.x}px, ${t.y}px, 0)`;
        el.style.opacity = String(t.op);
        const tag = el.querySelector<HTMLElement>("[data-v]");
        if (tag) tag.style.opacity = near ? "1" : "0";
      }

      raf = requestAnimationFrame(frame);
    };

    const onMove = (e: PointerEvent) => {
      px = e.clientX;
      py = e.clientY;
    };
    const onResize = () => {
      W = window.innerWidth;
      H = window.innerHeight;
    };

    if (light) light.style.opacity = "1";
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("resize", onResize, { passive: true });
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("resize", onResize);
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

      {TOKENS.map((t, i) => (
        <div
          key={i}
          ref={(el) => {
            tokenRefs.current[i] = el;
          }}
          className="absolute left-0 top-0 flex items-center gap-2 whitespace-nowrap font-mono text-[11px] opacity-0 will-change-transform"
        >
          <span className="text-paper-dim">{t.call}</span>
          <span
            data-v
            className={`text-[10px] font-semibold uppercase tracking-wide opacity-0 transition-opacity duration-300 ${
              t.decision === "ALLOW" ? "text-allow" : "text-deny"
            }`}
          >
            {t.decision}
          </span>
        </div>
      ))}

      <div
        ref={lightRef}
        className="absolute left-0 top-0 size-[700px] opacity-0 transition-opacity duration-700 will-change-transform"
        style={{
          background:
            "radial-gradient(circle, rgba(231,239,233,0.14), transparent 55%)",
          mixBlendMode: "screen",
        }}
      />
    </div>
  );
}
