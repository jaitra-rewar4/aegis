/**
 * engine.test.ts — parity vectors traced by hand from policy/engine.py + default.yaml.
 * Each case asserts the (decision, ruleId) the Python engine produces for the same input.
 * Run: npx tsx engine.test.ts   (exits non-zero on any mismatch)
 */

import { decide } from "./engine";
import { defaultPack } from "./packs/default";
import type { Pack } from "./types";

let passed = 0;
let failed = 0;

function check(
  name: string,
  got: { decision: string; ruleId: string },
  wantDecision: string,
  wantRule: string,
): void {
  const ok = got.decision === wantDecision && got.ruleId === wantRule;
  if (ok) {
    passed++;
  } else {
    failed++;
    console.log(
      `  FAIL  ${name}\n        want ${wantDecision}/${wantRule}\n        got  ${got.decision}/${got.ruleId}`,
    );
  }
}

const P = defaultPack;
const allowedRead = [{ tool: "lookup_customer", decision: "ALLOW" }];

// --- execute_sql -----------------------------------------------------------------
check("sql select -> allow_other", decide(P, "execute_sql", { sql: "SELECT * FROM users" }), "ALLOW", "sql.allow_other");
check("sql DROP -> deny_destructive", decide(P, "execute_sql", { sql: "DROP TABLE users" }), "DENY", "sql.deny_destructive");
check("sql lowercase drop -> deny (case-insensitive)", decide(P, "execute_sql", { sql: "drop table users" }), "DENY", "sql.deny_destructive");
check("sql multi-space DELETE -> deny (whitespace collapse)", decide(P, "execute_sql", { sql: "DELETE   FROM   t" }), "DENY", "sql.deny_destructive");
check("sql missing param -> allow_other (deny guard cannot fire on missing)", decide(P, "execute_sql", {}), "ALLOW", "sql.allow_other");
check("sql substring-not-token (DROPLET) -> allow_other", decide(P, "execute_sql", { sql: "SELECT droplet FROM t" }), "ALLOW", "sql.allow_other");

// --- read-only + calculator + unknown --------------------------------------------
check("lookup_customer -> allow_lookup", decide(P, "lookup_customer", { id: 7 }), "ALLOW", "customers.allow_lookup");
check("calculator -> allow_calculator", decide(P, "calculator", { expr: "2+2" }), "ALLOW", "math.allow_calculator");
check("unknown tool -> default_deny", decide(P, "delete_database", {}), "DENY", "policy.default_deny");

// --- send_email: THE HEADLINE (same call, two verdicts) --------------------------
check("send to partner, NO read -> allow_known_domains", decide(P, "send_email", { to: "x@partner.example.com" }), "ALLOW", "email.allow_known_domains");
check("send to partner, AFTER read -> deny_exfil", decide(P, "send_email", { to: "x@partner.example.com" }, allowedRead), "DENY", "email.deny_exfil_after_read");

// --- send_email: the boundaries --------------------------------------------------
check("send to internal, AFTER read -> allow (internal exempt)", decide(P, "send_email", { to: "x@internal.example.com" }, allowedRead), "ALLOW", "email.allow_known_domains");
check("send to evil, AFTER read -> deny_exfil", decide(P, "send_email", { to: "x@evil.com" }, allowedRead), "DENY", "email.deny_exfil_after_read");
check("send to evil, NO read -> default_deny (floor, not exfil)", decide(P, "send_email", { to: "x@evil.com" }), "DENY", "policy.default_deny");
check("send malformed (a@@b), AFTER read -> default_deny (NOT exfil; anti-trap)", decide(P, "send_email", { to: "a@@evil.com" }, allowedRead), "DENY", "policy.default_deny");
check("send malformed (no @), AFTER read -> default_deny", decide(P, "send_email", { to: "no-at-sign" }, allowedRead), "DENY", "policy.default_deny");
check("send to partner, AFTER a DENIED read -> allow (denied read does not taint)", decide(P, "send_email", { to: "x@partner.example.com" }, [{ tool: "lookup_customer", decision: "DENY" }]), "ALLOW", "email.allow_known_domains");
check("send to partner, junk+real trajectory -> deny_exfil (totality)", decide(P, "send_email", { to: "x@partner.example.com" }, [42, "foo", null, ...allowedRead] as unknown[]), "DENY", "email.deny_exfil_after_read");
check("send to partner, junk-only trajectory -> allow (junk does not match/crash)", decide(P, "send_email", { to: "x@partner.example.com" }, [42, "foo", null] as unknown[]), "ALLOW", "email.allow_known_domains");
check("send missing 'to', AFTER read -> default_deny (missing param)", decide(P, "send_email", {}, allowedRead), "DENY", "policy.default_deny");

// --- no pack ---------------------------------------------------------------------
check("no pack -> no_pack", decide(null, "calculator", {}), "DENY", "policy.no_pack");

// --- operator coverage the default pack doesn't exercise -------------------------
// (max, min, one_of, prefix_one_of, not_contains_keyword)
const opsPack: Pack = {
  version: 1,
  default: "deny",
  rules: [
    { id: "t.max", tool: "t_max", after: null, when: { amount: ["max", 1000] }, effect: "ALLOW" },
    { id: "t.min", tool: "t_min", after: null, when: { amount: ["min", 10] }, effect: "ALLOW" },
    { id: "t.one_of", tool: "t_one", after: null, when: { x: ["one_of", [1, "a", true]] }, effect: "ALLOW" },
    { id: "t.prefix", tool: "t_pre", after: null, when: { p: ["prefix_one_of", ["/safe/", "/ok/"]] }, effect: "ALLOW" },
    { id: "t.nc", tool: "t_nc", after: null, when: { s: ["not_contains_keyword", ["BAD", "EVIL"]] }, effect: "ALLOW" },
  ],
};
const Q = opsPack;

check("max 500<=1000 -> allow", decide(Q, "t_max", { amount: 500 }), "ALLOW", "t.max");
check("max 1000<=1000 (boundary) -> allow", decide(Q, "t_max", { amount: 1000 }), "ALLOW", "t.max");
check("max 1001 -> default_deny", decide(Q, "t_max", { amount: 1001 }), "DENY", "policy.default_deny");
check("max missing amount -> default_deny", decide(Q, "t_max", {}), "DENY", "policy.default_deny");
check("max amount=true (bool excluded) -> default_deny", decide(Q, "t_max", { amount: true }), "DENY", "policy.default_deny");
check("max amount='500' (string) -> default_deny", decide(Q, "t_max", { amount: "500" }), "DENY", "policy.default_deny");
check("min 10>=10 (boundary) -> allow", decide(Q, "t_min", { amount: 10 }), "ALLOW", "t.min");
check("min 9 -> default_deny", decide(Q, "t_min", { amount: 9 }), "DENY", "policy.default_deny");
check("one_of 1 (number) -> allow", decide(Q, "t_one", { x: 1 }), "ALLOW", "t.one_of");
check("one_of true (bool) -> allow", decide(Q, "t_one", { x: true }), "ALLOW", "t.one_of");
check("one_of 'a' -> allow", decide(Q, "t_one", { x: "a" }), "ALLOW", "t.one_of");
check("one_of '1' (string, no coercion) -> default_deny", decide(Q, "t_one", { x: "1" }), "DENY", "policy.default_deny");
check("one_of 2 -> default_deny", decide(Q, "t_one", { x: 2 }), "DENY", "policy.default_deny");
check("prefix '/safe/x' -> allow", decide(Q, "t_pre", { p: "/safe/x" }), "ALLOW", "t.prefix");
check("prefix '/bad/x' -> default_deny", decide(Q, "t_pre", { p: "/bad/x" }), "DENY", "policy.default_deny");
check("prefix non-string -> default_deny", decide(Q, "t_pre", { p: 123 }), "DENY", "policy.default_deny");
check("not_contains clean -> allow", decide(Q, "t_nc", { s: "hello world" }), "ALLOW", "t.nc");
check("not_contains 'this is BAD' -> default_deny", decide(Q, "t_nc", { s: "this is BAD" }), "DENY", "policy.default_deny");
check("not_contains missing param -> default_deny (negation trap closed)", decide(Q, "t_nc", {}), "DENY", "policy.default_deny");

// --- default: allow path (a pack whose default is allow) -------------------------
const allowDefaultPack: Pack = { version: 1, default: "allow", rules: [] };
check("empty allow-default pack, any tool -> default_allow", decide(allowDefaultPack, "whatever", {}), "ALLOW", "policy.default_allow");

console.log(`\n${passed} passed, ${failed} failed`);
if (failed > 0) throw new Error(`${failed} parity check(s) failed`);
