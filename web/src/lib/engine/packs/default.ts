/**
 * packs/default.ts — the example policy pack, a direct translation of
 * policy/packs/default.yaml into the schema-normalized shape engine.ts consumes.
 *
 * Rule ORDER is load-bearing (first-match-wins): the destructive-SQL DENY sits above the
 * broad execute_sql ALLOW, and the send_email exfil DENY sits above the known-domains ALLOW.
 * Rationales are carried verbatim so the dashboard/playground can show the same reasoning
 * the Python pack documents.
 */

import type { Pack } from "../types";

export const defaultPack: Pack = {
  version: 1,
  default: "deny",
  rules: [
    // 1. Destructive SQL — DENY. First, so it wins over sql.allow_other below.
    {
      id: "sql.deny_destructive",
      tool: "execute_sql",
      after: null,
      when: {
        sql: ["contains_keyword", ["DROP", "DELETE", "TRUNCATE", "ALTER"]],
      },
      effect: "DENY",
    },
    // 2. Any other execute_sql — ALLOW. Reached only when rule 1 did not match.
    {
      id: "sql.allow_other",
      tool: "execute_sql",
      after: null,
      when: {},
      effect: "ALLOW",
    },
    // 3. lookup_customer — ALLOW. Read-only.
    {
      id: "customers.allow_lookup",
      tool: "lookup_customer",
      after: null,
      when: {},
      effect: "ALLOW",
    },
    // 4. calculator — ALLOW. Pure arithmetic, no side effects.
    {
      id: "math.allow_calculator",
      tool: "calculator",
      after: null,
      when: {},
      effect: "ALLOW",
    },
    // 5. send_email exfil — DENY. The 2b trajectory rule: a non-internal send AFTER an
    //    ALLOWed lookup_customer earlier in the run. Placed above email.allow_known_domains.
    {
      id: "email.deny_exfil_after_read",
      tool: "send_email",
      after: "lookup_customer",
      when: {
        to: ["domain_not_in", ["internal.example.com"]],
      },
      effect: "DENY",
    },
    // 6. send_email to known domains — ALLOW. Reached only when rule 5 did not match.
    {
      id: "email.allow_known_domains",
      tool: "send_email",
      after: null,
      when: {
        to: ["domain_in", ["internal.example.com", "partner.example.com"]],
      },
      effect: "ALLOW",
    },
  ],
};
