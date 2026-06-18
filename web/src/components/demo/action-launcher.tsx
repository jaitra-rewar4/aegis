"use client";

/**
 * action-launcher.tsx — the buttons that propose governed actions to the in-browser gate.
 *
 * Each preset is a real (tool, params) pair from the default pack. The verdict is NEVER encoded
 * here — clicking a button only PROPOSES the action; decide() in the demo runtime returns the
 * verdict. The descriptions explain the EXPECTED outcome so a visitor knows what to watch for,
 * but the badge that lands in the trail is whatever the engine actually decided.
 *
 * Two presets are sequence-sensitive on purpose, to show trajectory-aware enforcement:
 *  - "Email partner" is ALLOWed normally but DENIED after a customer lookup (exfil-after-read);
 *  - "Issue refund" is ALLOWed up to the cap, then RATE_LIMITed on the 4th in a session.
 */

interface Preset {
  label: string;
  tool: string;
  params: Record<string, unknown>;
  note: string;
}

const PRESETS: Preset[] = [
  {
    label: "Look up customer",
    tool: "lookup_customer",
    params: { id: 4842 },
    note: "Read-only → ALLOW. Also arms the exfil rule for the next email.",
  },
  {
    label: "Safe query",
    tool: "execute_sql",
    params: { sql: "SELECT id, status FROM orders LIMIT 10" },
    note: "Non-destructive SQL → ALLOW.",
  },
  {
    label: "Drop table",
    tool: "execute_sql",
    params: { sql: "DROP TABLE users" },
    note: "Destructive keyword → DENY.",
  },
  {
    label: "Email partner",
    tool: "send_email",
    params: { to: "ops@partner.example.com" },
    note: "ALLOW on its own — but DENY if a customer lookup happened earlier this session.",
  },
  {
    label: "Issue refund",
    tool: "issue_refund",
    params: { amount: 50 },
    note: "ALLOW up to 3 per session, then RATE_LIMIT on the 4th.",
  },
  {
    label: "Export data",
    tool: "export_data",
    params: { dataset: "customers" },
    note: "REQUIRE_APPROVAL → held for a human sign-off in the queue.",
  },
];

export function ActionLauncher({
  onRun,
  onReset,
  busy,
  hasRecords,
}: {
  onRun: (tool: string, params: Record<string, unknown>) => void;
  onReset: () => void;
  busy: boolean;
  hasRecords: boolean;
}) {
  return (
    <div className="flex flex-col gap-3">
      <ul className="flex flex-col gap-2">
        {PRESETS.map((p) => (
          <li key={p.label}>
            <button
              onClick={() => onRun(p.tool, p.params)}
              disabled={busy}
              className="group w-full rounded border border-line bg-ink-raised px-3.5 py-2.5 text-left transition-colors hover:border-line-strong disabled:opacity-40 disabled:cursor-not-allowed"
            >
              <div className="flex items-center justify-between gap-2">
                <span className="font-mono text-[12.5px] text-paper">{p.label}</span>
                <code className="font-mono text-[10px] text-paper-dim/60 group-hover:text-paper-dim">
                  {p.tool}
                </code>
              </div>
              <p className="mt-1 font-mono text-[10.5px] leading-relaxed text-paper-dim/70">
                {p.note}
              </p>
            </button>
          </li>
        ))}
      </ul>

      <button
        onClick={onReset}
        disabled={busy || !hasRecords}
        className="self-start rounded border border-line px-3 py-1.5 font-mono text-[10px] uppercase tracking-[0.16em] text-paper-dim transition-colors hover:text-paper disabled:opacity-30 disabled:cursor-not-allowed"
      >
        Reset session
      </button>
    </div>
  );
}
