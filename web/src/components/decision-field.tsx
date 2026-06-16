"use client";

/**
 * decision-field.tsx — the interactive background, and it IS the product: your cursor is the gate.
 *
 * Real tool-call tokens drift across the blueprint grid. A vertical gate line tracks the
 * cursor, and the instant a token passes THROUGH the gate it is judged by the real engine
 * (decide() with the default pack): it flashes, stamps its verdict (green ALLOW / coral DENY),
 * then settles back to dim and drifts on. Hold the cursor still and the stream flows through
 * and gets judged; sweep it and you actively run actions through the gate. The only colour in
 * the background is a real gate verdict.
 *
 * One rAF loop, transform/opacity only, driven by refs (no React state per frame), so it is
 * smooth. Fine-pointer only; on touch or reduced-motion the tokens never activate and only the
 * static grid shows.
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

// Each token's verdict is the real engine's, computed once, so what gets stamped on screen is
// exactly what the gateway would decide for that action.
const TOKENS = SPECS.map((s) => ({
  call: s.call,
  decision: decide(defaultPack, s.tool, s.params, s.traj).decision,
}));

export function DecisionField() {
  const reduce = useReducedMotion();
  const gateRef = useRef<HTMLDivElement>(null);
  const tokenRefs = useRef<(HTMLDivElement | null)[]>([]);

  useEffect(() => {
    if (reduce || !window.matchMedia("(pointer: fine)").matches) return;

    let W = window.innerWidth;
    let H = window.innerHeight;
    const gate = gateRef.current;

    const T = TOKENS.map(() => {
      const x = Math.random() * W;
      return {
        x,
        prev: x,
        y: 70 + Math.random() * Math.max(120, H - 150),
        vx: 24 + Math.random() * 26, // gentle rightward drift, px/sec
        vy: (Math.random() - 0.5) * 8,
        op: 0,
        flash: 0,
      };
    });
    let px = W * 0.5;
    let raf = 0;
    let last = performance.now();

    const frame = (now: number) => {
      const dt = Math.min(0.05, (now - last) / 1000);
      last = now;

      if (gate) gate.style.transform = `translate3d(${px}px, 0, 0)`;

      for (let i = 0; i < T.length; i++) {
        const el = tokenRefs.current[i];
        if (!el) continue;
        const t = T[i];

        t.prev = t.x;
        t.x += t.vx * dt;
        t.y += t.vy * dt;
        if (t.x > W + 160) {
          t.x = -260;
          t.prev = t.x;
          t.y = 70 + Math.random() * Math.max(120, H - 150);
        }
        if (t.y < 60 || t.y > H - 40) {
          t.vy = -t.vy;
          t.y = Math.max(60, Math.min(H - 40, t.y));
        }

        // Crossed the gate this frame? (sign of x - gateX flipped)
        if ((t.prev - px) * (t.x - px) < 0) t.flash = 1;
        t.flash *= 0.978;

        const nearGate = Math.max(0, 1 - Math.abs(t.x - px) / 220);
        const target = 0.13 + 0.6 * t.flash + 0.15 * nearGate;
        t.op += (target - t.op) * 0.14;

        el.style.transform = `translate3d(${t.x}px, ${t.y}px, 0) scale(${1 + 0.07 * t.flash})`;
        el.style.opacity = String(t.op);
        const tag = el.querySelector<HTMLElement>("[data-v]");
        if (tag) tag.style.opacity = String(Math.min(1, t.flash * 1.4));
      }

      raf = requestAnimationFrame(frame);
    };

    const onMove = (e: PointerEvent) => {
      px = e.clientX;
    };
    const onResize = () => {
      W = window.innerWidth;
      H = window.innerHeight;
    };

    if (gate) gate.style.opacity = "1";
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
          className="absolute left-0 top-0 flex origin-left items-center gap-2 whitespace-nowrap font-mono text-[11px] opacity-0 will-change-transform"
        >
          <span className="text-paper-dim">{t.call}</span>
          <span
            data-v
            className={`text-[10px] font-semibold uppercase tracking-wide opacity-0 ${
              t.decision === "ALLOW" ? "text-allow" : "text-deny"
            }`}
          >
            {t.decision}
          </span>
        </div>
      ))}

      {/* The gate: a vertical line that tracks the cursor and judges what passes through it. */}
      <div
        ref={gateRef}
        className="absolute inset-y-0 left-0 w-px opacity-0 transition-opacity duration-700 will-change-transform"
        style={{
          background:
            "linear-gradient(to bottom, transparent, rgba(231,239,233,0.22) 16%, rgba(231,239,233,0.22) 84%, transparent)",
        }}
      >
        <div
          className="absolute inset-y-0 -left-5 w-10"
          style={{
            background:
              "linear-gradient(to right, transparent, rgba(231,239,233,0.035), transparent)",
          }}
        />
        <span className="absolute left-2 top-28 font-mono text-[9px] uppercase tracking-[0.22em] text-paper-dim/70">
          gate
        </span>
      </div>
    </div>
  );
}
