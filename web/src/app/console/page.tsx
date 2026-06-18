/**
 * console/page.tsx — the public, self-contained Aegis console.
 *
 * A server component wrapper (static chrome + metadata) around the DemoConsole client
 * component, mirroring the dashboard route's server/client split. Unlike /dashboard (which
 * binds to a live FastAPI audit log), this runs the real ported engine and hash chain in the
 * browser, so it works as a zero-backend public demo.
 */
import type { Metadata } from "next";
import { DemoConsole } from "@/components/demo/demo-console";

export const metadata: Metadata = {
  title: "Live console — Aegis",
  description:
    "Propose agent actions and watch the real Aegis engine decide ALLOW, DENY, RATE_LIMIT, or REQUIRE_APPROVAL — with a live SHA-256 hash-chained audit trail, running entirely in your browser.",
};

export default function ConsolePage() {
  return <DemoConsole />;
}
