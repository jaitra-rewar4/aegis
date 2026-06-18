/**
 * dashboard/page.tsx — the Aegis operator console.
 *
 * Three panels driven by the real FastAPI backend:
 *   1. Pending-approval queue (GET /pending, POST /pending/{id}/approve|deny)
 *   2. Audit trail (GET /audit, client-side search/filter)
 *   3. Chain-integrity badge (GET /audit/verify)
 *
 * The page itself is a server component; the three data-driven panels are
 * client components that fetch independently on mount so they can refresh
 * after actions without a full page reload.
 *
 * If GET /health fails, a full-page API-disconnected banner is shown and
 * none of the panels attempt further fetches — the dashboard degrades
 * gracefully rather than crashing or showing stale/fake data.
 *
 * WHY a server layout wrapper around client panels rather than one big
 * client component: the static chrome (header, section labels) renders on
 * the server and reaches the browser instantly; only the live data sections
 * are client-rendered, keeping hydration surface small.
 */

import type { Metadata } from "next";
import { DashboardShell } from "@/components/dashboard/shell";

export const metadata: Metadata = {
  title: "Operator console — Aegis",
  description: "Pending-approval queue, searchable audit trail, and chain-integrity status for the Aegis policy gateway.",
};

export default function DashboardPage() {
  return <DashboardShell />;
}
