"use client";

/**
 * decision-field.tsx — the interactive background, and it IS the product.
 *
 * A live stream of real tool calls flows rightward toward a fixed gate. Two ways an action
 * gets judged by the real engine (decide() with the default pack):
 *   - it reaches the gate (ambient), or
 *   - you sweep your cursor over it (you are a roving inspector).
 * On judging it POPS: a ring snaps out, it scales, and an ALLOW (green) or DENY (coral) is
 * stamped. ALLOW keeps flowing and sails off; DENY is caught and dissolves on the spot. The
 * field also brightens and parts around the moving cursor, and clicking launches a labelled
 * action from your pointer at the gate.
 *
 * Canvas, DPR-scaled, one rAF loop, transparent so the blueprint grid shows through.
 * Top-weighted mask so it lives in the hero. Fine-pointer only; touch and reduced-motion get
 * the static grid alone.
 */

import { useEffect, useRef } from "react";
import { useReducedMotion } from "framer-motion";
import { decide } from "@/lib/engine/engine";
import { defaultPack } from "@/lib/engine/packs/default";

const DOTS =
  "radial-gradient(circle, rgba(231,239,233,0.08) 1px, transparent 1.5px)";
const EDGE_FADE = "radial-gradient(120% 85% at 50% 0%, #000 30%, transparent 82%)";
const TAU = Math.PI * 2;

const ALLOW = "84,198,140";
const DENY = "227,106,80";
const DIM = "157,180,168";
const PAPER = "231,239,233";

type Spec = {
  call: string;
  tool: string;
  params: Record<string, unknown>;
  traj: { tool: string; decision: string }[];
};

const SPECS: Spec[] = [
  { call: "lookup_customer(4012)", tool: "lookup_customer", params: { customer_id: "4012" }, traj: [] },
  { call: "calculator(0.0825*2400)", tool: "calculator", params: { expression: "0.0825 * 2400" }, traj: [] },
  { call: "execute_sql(SELECT …)", tool: "execute_sql", params: { sql: "SELECT plan FROM accounts" }, traj: [] },
  { call: "execute_sql(DROP TABLE …)", tool: "execute_sql", params: { sql: "DROP TABLE audit_log" }, traj: [] },
  { call: "send_email(audit@internal…)", tool: "send_email", params: { to: "audit@internal.example.com" }, traj: [] },
  { call: "send_email(ops@partner…)", tool: "send_email", params: { to: "ops@partner.example.com" }, traj: [{ tool: "lookup_customer", decision: "ALLOW" }] },
  { call: "send_email(x@unknown.io)", tool: "send_email", params: { to: "x@unknown.io" }, traj: [] },
  { call: "lookup_customer(7781)", tool: "lookup_customer", params: { customer_id: "7781" }, traj: [] },
];

const VERDICTS = SPECS.map((s) => decide(defaultPack, s.tool, s.params, s.traj).decision);

type P = {
  x: number;
  y: number;
  vx: number;
  vy: number;
  base: number;
  spec: number;
  labeled: boolean;
  state: 0 | 1 | 2; // 0 flow, 1 allowed, 2 denied
  t: number;
  pop: number; // 1 -> 0 snap on judging
  byCursor: boolean;
};

export function DecisionField() {
  const reduce = useReducedMotion();
  const canvasRef = useRef<HTMLCanvasElement>(null);

  useEffect(() => {
    if (reduce || !window.matchMedia("(pointer: fine)").matches) return;
    const canvas = canvasRef.current;
    const ctx = canvas?.getContext("2d");
    if (!canvas || !ctx) return;

    let W = 0;
    let H = 0;
    let gateX = 0;
    let dpr = 1;
    const N = 70;
    const LABELS = 6;

    const resize = () => {
      dpr = Math.min(2, window.devicePixelRatio || 1);
      W = window.innerWidth;
      H = window.innerHeight;
      canvas.width = Math.floor(W * dpr);
      canvas.height = Math.floor(H * dpr);
      canvas.style.width = `${W}px`;
      canvas.style.height = `${H}px`;
      ctx.setTransform(dpr, 0, 0, dpr, 0, 0);
      gateX = Math.round(W * 0.6);
    };

    const spawn = (p: P, i: number) => {
      p.x = -40 - Math.random() * 260;
      p.y = 40 + Math.random() * (H - 80);
      p.base = 0.42 + Math.random() * 0.4;
      p.vx = p.base;
      p.vy = (Math.random() - 0.5) * 0.2;
      p.spec = Math.floor(Math.random() * SPECS.length);
      p.labeled = i < LABELS;
      p.state = 0;
      p.t = 0;
      p.pop = 0;
      p.byCursor = false;
    };

    const judge = (p: P, byCursor: boolean) => {
      const allow = VERDICTS[p.spec] === "ALLOW";
      p.state = allow ? 1 : 2;
      p.t = 0;
      p.pop = 1;
      p.byCursor = byCursor;
      if (!allow) {
        if (!byCursor) p.x = gateX; // caught at the gate; cursor-caught stays where you got it
        p.vx = 0;
      }
    };

    const ps: P[] = Array.from({ length: N }, (_, i) => {
      const p: P = { x: 0, y: 0, vx: 0, vy: 0, base: 0.5, spec: 0, labeled: false, state: 0, t: 0, pop: 0, byCursor: false };
      spawn(p, i);
      p.x = Math.random() * gateX; // spread across the field on first paint
      return p;
    });

    let mx = -9999;
    let my = -9999;
    let raf = 0;

    const onMove = (e: PointerEvent) => {
      mx = e.clientX;
      my = e.clientY;
    };
    const onLeave = () => {
      mx = -9999;
      my = -9999;
    };
    const onDown = (e: PointerEvent) => {
      let target = ps.find((p) => p.state === 1 && p.x > W);
      if (!target) target = ps[Math.floor(Math.random() * ps.length)];
      target.x = e.clientX;
      target.y = e.clientY;
      target.vx = 3.4;
      target.vy = (Math.random() - 0.5) * 0.3;
      target.base = 1.2;
      target.spec = Math.floor(Math.random() * SPECS.length);
      target.labeled = true;
      target.state = 0;
      target.t = 0;
      target.pop = 0;
      target.byCursor = true;
    };

    const drawGate = () => {
      const g = ctx.createLinearGradient(0, 0, 0, H);
      g.addColorStop(0, `rgba(${PAPER},0)`);
      g.addColorStop(0.16, `rgba(${PAPER},0.22)`);
      g.addColorStop(0.84, `rgba(${PAPER},0.22)`);
      g.addColorStop(1, `rgba(${PAPER},0)`);
      ctx.fillStyle = g;
      ctx.fillRect(gateX, 0, 1, H);
      ctx.font = "600 9px ui-monospace, SFMono-Regular, monospace";
      ctx.fillStyle = `rgba(${DIM},0.6)`;
      ctx.fillText("GATE", gateX + 7, 96);
    };

    const frame = () => {
      ctx.clearRect(0, 0, W, H);
      drawGate();
      ctx.textBaseline = "middle";

      for (let i = 0; i < N; i++) {
        const p = ps[i];

        const dx = p.x - mx;
        const dy = p.y - my;
        const d2 = dx * dx + dy * dy;
        let near = 0;
        if (d2 < 160 * 160) {
          const d = Math.sqrt(d2) || 1;
          near = 1 - d / 160;
          if (p.state === 0) {
            const f = near * 0.9; // part the flow around the cursor
            p.vx += (dx / d) * f;
            p.vy += (dy / d) * f;
          }
        }

        p.x += p.vx;
        p.y += p.vy;
        p.vx += (p.base - p.vx) * 0.045;
        p.vy *= 0.94;

        // judged by a cursor sweep, or by reaching the gate
        if (p.state === 0 && d2 < 30 * 30) judge(p, true);
        if (p.state === 0 && p.x >= gateX) judge(p, false);

        if (p.state === 2) {
          p.t++;
          p.vx = 0;
          p.vy *= 0.8;
          if (p.t > 64) spawn(p, i);
        } else if (p.state === 1) {
          p.t++;
          if (p.x > W + 60) spawn(p, i);
        }
        if (p.x < -320 || p.y < -80 || p.y > H + 80) spawn(p, i);
        p.pop *= 0.88;

        let color = DIM;
        let alpha = 0.42 + near * 0.45;
        let r = 1.7;
        if (p.state === 1) {
          color = ALLOW;
          alpha = Math.max(0, 0.9 - p.t / 90);
          r = 2;
        } else if (p.state === 2) {
          color = DENY;
          const k = Math.max(0, 1 - p.t / 64);
          alpha = 0.9 * k;
          r = 2 + (1 - k) * 4;
        }
        const scale = 1 + p.pop * 0.7;

        ctx.strokeStyle = `rgba(${color},${alpha * 0.4})`;
        ctx.lineWidth = 1;
        ctx.beginPath();
        ctx.moveTo(p.x - p.vx * 5, p.y);
        ctx.lineTo(p.x, p.y);
        ctx.stroke();

        ctx.beginPath();
        ctx.fillStyle = `rgba(${color},${alpha})`;
        ctx.arc(p.x, p.y, r * scale, 0, TAU);
        ctx.fill();

        // the pop: a ring that snaps outward on judging
        if (p.pop > 0.04) {
          ctx.strokeStyle = `rgba(${color},${p.pop * 0.7})`;
          ctx.lineWidth = 1.4;
          ctx.beginPath();
          ctx.arc(p.x, p.y, r * scale + (1 - p.pop) * 16, 0, TAU);
          ctx.stroke();
        }

        // your cursor-judged actions stamp their verdict; ambient gate judging stays quiet
        if (p.byCursor && p.pop > 0.04) {
          ctx.font = "600 11px ui-monospace, SFMono-Regular, monospace";
          ctx.fillStyle = `rgba(${color},${Math.min(1, p.pop * 1.3)})`;
          ctx.fillText(p.state === 1 ? "ALLOW" : "DENY", p.x + 10, p.y - 9 - (1 - p.pop) * 8);
        }

        if (p.labeled) {
          const a = p.state === 0 ? 0.3 + near * 0.4 : alpha;
          const c = p.state === 0 ? DIM : color;
          ctx.font = "11px ui-monospace, SFMono-Regular, monospace";
          ctx.fillStyle = `rgba(${c},${a})`;
          ctx.fillText(SPECS[p.spec].call, p.x + 7, p.y);
        }
      }

      raf = requestAnimationFrame(frame);
    };

    resize();
    window.addEventListener("resize", resize, { passive: true });
    window.addEventListener("pointermove", onMove, { passive: true });
    window.addEventListener("pointerleave", onLeave, { passive: true });
    window.addEventListener("pointerdown", onDown, { passive: true });
    raf = requestAnimationFrame(frame);
    return () => {
      cancelAnimationFrame(raf);
      window.removeEventListener("resize", resize);
      window.removeEventListener("pointermove", onMove);
      window.removeEventListener("pointerleave", onLeave);
      window.removeEventListener("pointerdown", onDown);
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
      <canvas
        ref={canvasRef}
        className="absolute inset-0 h-full w-full"
        style={{ maskImage: EDGE_FADE, WebkitMaskImage: EDGE_FADE }}
      />
    </div>
  );
}
