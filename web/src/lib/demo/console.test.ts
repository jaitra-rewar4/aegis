/**
 * console.test.ts — behavior + chain tests for the in-browser demo runtime.
 *
 * Asserts the demo runtime produces the SAME verdicts as the Python engine (it shares the
 * ported decide()), builds a verifiable SHA-256 chain, holds/approves/denies correctly, and
 * detects tampering. Run: npx tsx console.test.ts   (exits non-zero on any failure)
 *
 * Uses relative imports and Node's global Web Crypto so it runs under tsx with no bundler.
 */
import {
  runAction,
  resolvePending,
  listPending,
  DemoApprovalError,
  type DemoRecord,
} from "./console";
import { verifyChain } from "./chain";

let passed = 0;
let failed = 0;

function check(name: string, cond: boolean): void {
  if (cond) {
    passed++;
  } else {
    failed++;
    console.log(`  FAIL  ${name}`);
  }
}

function last(records: DemoRecord[]): DemoRecord {
  return records[records.length - 1];
}

async function expectThrows(name: string, fn: () => Promise<unknown>): Promise<void> {
  try {
    await fn();
    failed++;
    console.log(`  FAIL  ${name} (expected throw, none thrown)`);
  } catch (err) {
    check(name, err instanceof DemoApprovalError);
  }
}

async function main(): Promise<void> {
  // --- empty chain ---
  check("empty chain verifies ok", (await verifyChain([])).ok);

  // --- single ALLOW, first record anchors with prev_hash null ---
  let r: DemoRecord[] = await runAction([], "lookup_customer", { id: 7 });
  check("lookup_customer -> ALLOW", last(r).decision === "ALLOW");
  check("lookup_customer rule", last(r).rule === "customers.allow_lookup");
  check("first record prev_hash null", last(r).prev_hash === null);
  check("first record real 64-hex hash", /^[0-9a-f]{64}$/.test(last(r).hash));
  check("chain verifies after 1", (await verifyChain(r)).ok);

  // --- trajectory: email partner DENIED after a customer read (exfil-after-read) ---
  r = await runAction(r, "send_email", { to: "ops@partner.example.com" });
  check("email partner AFTER read -> DENY", last(r).decision === "DENY");
  check("email deny rule", last(r).rule === "email.deny_exfil_after_read");
  check("record 2 links to record 1", last(r).prev_hash === r[0].hash);
  check("chain verifies after 2", (await verifyChain(r)).ok);

  // --- fresh session: same email is ALLOWed with no prior read ---
  let s: DemoRecord[] = await runAction([], "send_email", { to: "ops@partner.example.com" });
  check("email partner, NO read -> ALLOW", last(s).decision === "ALLOW");
  check("email allow rule", last(s).rule === "email.allow_known_domains");

  // --- destructive vs safe SQL ---
  s = await runAction(s, "execute_sql", { sql: "DROP TABLE users" });
  check("DROP -> DENY", last(s).decision === "DENY" && last(s).rule === "sql.deny_destructive");
  s = await runAction(s, "execute_sql", { sql: "SELECT 1" });
  check("SELECT -> ALLOW", last(s).decision === "ALLOW" && last(s).rule === "sql.allow_other");

  // --- RATE_LIMIT: 3 refunds ALLOW, 4th trips the cap ---
  let t: DemoRecord[] = [];
  for (let i = 0; i < 3; i++) t = await runAction(t, "issue_refund", { amount: 50 });
  check("refunds 1-3 -> ALLOW", t.every((x) => x.decision === "ALLOW"));
  t = await runAction(t, "issue_refund", { amount: 50 });
  check("refund 4 -> RATE_LIMIT", last(t).decision === "RATE_LIMIT");
  check("rate limit rule", last(t).rule === "refunds.rate_limit");
  check("chain verifies after rate limit", (await verifyChain(t)).ok);

  // --- REQUIRE_APPROVAL hold -> approve -> execute ---
  let a: DemoRecord[] = await runAction([], "export_data", { dataset: "customers" });
  check("export_data -> REQUIRE_APPROVAL", last(a).decision === "REQUIRE_APPROVAL");
  check("export_data rule", last(a).rule === "exports.require_approval");
  const pid = last(a).pending_id as string;
  check("held request has pending_id", !!pid);
  check("one pending listed", listPending(a).length === 1);

  a = await resolvePending(a, pid, "alice", true);
  check("approval records ALLOW + EXECUTED", a.some((x) => x.decision === "ALLOW" && x.pending_id === pid) && a.some((x) => x.decision === "EXECUTED" && x.pending_id === pid));
  check("approver recorded", a.find((x) => x.decision === "ALLOW" && x.pending_id === pid)?.approver === "alice");
  check("pending clears after approve", listPending(a).length === 0);
  check("chain verifies after approve+execute", (await verifyChain(a)).ok);

  // --- double-resolve and missing approver are rejected ---
  await expectThrows("double-resolve throws", () => resolvePending(a, pid, "bob", true));
  let d: DemoRecord[] = await runAction([], "export_data", { dataset: "logs" });
  const dpid = last(d).pending_id as string;
  await expectThrows("missing approver throws", () => resolvePending(d, dpid, "  ", true));

  // --- deny path: DENY recorded, NO execution ---
  d = await resolvePending(d, dpid, "carol", false);
  check("deny records DENY", d.some((x) => x.decision === "DENY" && x.pending_id === dpid));
  check("deny does NOT execute", !d.some((x) => x.decision === "EXECUTED" && x.pending_id === dpid));

  // --- tamper detection: editing a record breaks the chain at that index ---
  const tampered = t.map((x) => ({ ...x }));
  tampered[1] = { ...tampered[1], params: { amount: 999999 } };
  const v = await verifyChain(tampered);
  check("tampered chain detected", !v.ok);
  check("break reported at edited index", v.firstBrokenIndex === 1);

  // ============================================================
  // RED-TEAM ATTACK SUITE (added by red-team agent)
  // ============================================================

  // --- [RT-01] VERDICT SOURCE: no preset encodes a verdict; decide() is sole source ---
  // The ActionLauncher only passes (tool, params) to onRun — no verdict field.
  // runAction() always calls decide() and uses its return value.
  // Verify decide() is the verdict source by confirming contradictory presets still get
  // the REAL verdict, not any label baked into the button.
  {
    // "Drop table" preset: params encode no verdict field — engine must return DENY
    const dropRec = await runAction([], "execute_sql", { sql: "DROP TABLE users" });
    check("[RT-01a] DROP TABLE verdict comes from decide() -> DENY", last(dropRec).decision === "DENY");
    check("[RT-01b] DROP TABLE rule is sql.deny_destructive", last(dropRec).rule === "sql.deny_destructive");
    // "Safe query" preset must get ALLOW from decide(), not from any label
    const safeRec = await runAction([], "execute_sql", { sql: "SELECT 1" });
    check("[RT-01c] SELECT verdict comes from decide() -> ALLOW", last(safeRec).decision === "ALLOW");
  }

  // --- [RT-02] KNOWN LIMITATION: keyword matching is not a SQL parser ---
  // 'DR/**/OP TABLE users' is valid SQL in many dialects (the DB strips the inline comment),
  // but contains_keyword tokenizes on whitespace, so 'DR/**/OP' is one token that does not match
  // 'DROP' — decide() returns ALLOW. This is an inherent property of TEXT-LEVEL keyword matching
  // in BOTH the Python engine and this TS port (engine.ts documents the same class of limitation
  // for contains_keyword), NOT a demo bug and NOT reachable through the fixed UI presets. A real
  // deployment that needs to catch obfuscated SQL pairs keyword rules with a proper parser. We
  // pin the ACTUAL engine verdict so a future change to the operator is caught, and so the
  // documented gap is explicit rather than hidden.
  {
    const commentBypass = await runAction([], "execute_sql", { sql: "DR/**/OP TABLE users" });
    check("[RT-02a] KNOWN LIMITATION: comment-obfuscated DROP is ALLOWed by keyword matching", last(commentBypass).decision === "ALLOW");
  }

  // --- [RT-03] KNOWN LIMITATION: Unicode homoglyphs evade keyword matching ---
  // 'DRОP' with a Cyrillic О (U+041E) is not the ASCII token 'DROP', so the keyword scan does not
  // match and decide() returns ALLOW. Same class of text-matching limitation as RT-02; same
  // mitigation (a parser / homoglyph-normalization upstream of the rule). Pinned to the real
  // verdict, not silently hidden.
  {
    const cyrDrop = await runAction([], "execute_sql", { sql: "DRОP TABLE users" }); // Cyrillic О
    check("[RT-03a] KNOWN LIMITATION: Cyrillic-O homoglyph DROP is ALLOWed by keyword matching", last(cyrDrop).decision === "ALLOW");
  }

  // --- [RT-04] CHAIN FORGERY: NaN/Infinity/undefined canonicalize identically to null ---
  // canonicalize() delegates numbers to JSON.stringify(), which serializes NaN and Infinity
  // as "null" (per JSON spec). undefined also maps to "null" in the fallback branch.
  // Therefore a record with params:{amount:null} and one with params:{amount:NaN} produce
  // IDENTICAL canonical bytes -> IDENTICAL SHA-256.
  // Attack: write a legitimate record with amount:null, then replace amount with NaN.
  // verifyChain() recomputes the hash over the tampered record and gets the SAME hash.
  // The tampered chain passes. This is a hash collision enabling silent param tampering.
  // Expected: verifyChain detects the tamper (ok=false). Actual: ok=true — BUG
  {
    let nanChain = await runAction([], "issue_refund", { amount: null as unknown as number });
    nanChain = await runAction(nanChain, "execute_sql", { sql: "SELECT 1" });
    const nanOrigV = await verifyChain(nanChain);
    check("[RT-04a] original chain with amount:null is valid", nanOrigV.ok);

    // Tamper record[0]: amount:null -> amount:NaN
    const nanForged = nanChain.map((x) => ({ ...x }));
    nanForged[0] = { ...nanForged[0], params: { amount: NaN } };
    const nanForgedV = await verifyChain(nanForged);
    check("[RT-04b] null->NaN tamper MUST be detected (chain should break)", !nanForgedV.ok);
    // EXPECTED TO FAIL — NaN canonicalizes to "null" just like null

    // Tamper record[0]: amount:null -> amount:Infinity
    const infForged = nanChain.map((x) => ({ ...x }));
    infForged[0] = { ...infForged[0], params: { amount: Infinity } };
    const infForgedV = await verifyChain(infForged);
    check("[RT-04c] null->Infinity tamper MUST be detected (chain should break)", !infForgedV.ok);
    // EXPECTED TO FAIL

    // Tamper record[0]: amount:null -> amount:undefined
    const undefForged = nanChain.map((x) => ({ ...x }));
    undefForged[0] = { ...undefForged[0], params: { amount: undefined } };
    const undefForgedV = await verifyChain(undefForged);
    check("[RT-04d] null->undefined tamper MUST be detected (chain should break)", !undefForgedV.ok);
    // EXPECTED TO FAIL
  }

  // --- [RT-05] CHAIN FORGERY: encodeString regex [-￿] matches hyphen (U+002D) ---
  // The regex /[-￿]/g: '-' at position 0 of a character class is a LITERAL hyphen,
  // not a range start. So the class matches only U+002D (hyphen) OR U+FFFF — NOT the
  // full U+002D..U+FFFF range intended. This has two divergences from Python:
  //
  //   Bug A: Hyphens ARE escaped by TS (-> -) but Python json.dumps does NOT escape them.
  //          Since the ISO timestamp "2026-06-18T..." contains hyphens, EVERY record's TS
  //          canonical bytes differ between Python and TypeScript. Cross-language verification
  //          of any record will always fail.
  //
  //   Bug B: Non-ASCII chars U+0080..U+FFFE are NOT escaped by TS (regex doesn't match them)
  //          but Python ensure_ascii=True escapes all of them. Any record with non-ASCII in
  //          params (e.g. customer names, SQL text) will hash differently between systems.
  //
  // Browser-only sessions are internally consistent (same encoder writes and verifies), so
  // verifyChain passes within the session. The bugs surface when comparing hashes produced
  // by the Python gateway against hashes produced by the TS chain, or when auditing a
  // Python-written log via the TS verifier.
  {
    // Demonstrate Bug A: hyphen in ts causes TS<->Python divergence
    // The ts field always contains ISO hyphens (e.g. "2026-06-18T00:00:00Z").
    // We cannot run Python here, but we can confirm that the TS canonical for
    // a record with a hyphen-containing string is NOT what Python would produce.
    // Specifically, Python: "a-b" -> Python canonical: "a-b" (hyphen literal, unescaped)
    //                        TS:    "a-b" -> TS canonical: "a-b" (hyphen escaped) — DIVERGE
    // The proof is that the existing suite tests all run clean on browser-only records,
    // but any cross-language import/export of the same record will fail hash verification.

    // Demonstrate Bug B: non-ASCII param not escaped by TS
    // TS encodeString('café') -> '"café"' (U+00E9 not escaped)
    // Python json.dumps('café', ensure_ascii=True) -> '"caf\\u00e9"'
    // These produce different SHA-256 for an otherwise identical record.
    let nonAsciiChain = await runAction([], "execute_sql", { sql: "SELECT * FROM café" });
    const nonAsciiV = await verifyChain(nonAsciiChain);
    check("[RT-05a] browser-only chain with non-ASCII param is internally consistent", nonAsciiV.ok);
    // This PASSES (browser-only consistency), but the hash != what Python would compute.
    // We document it as a parity bug, not a browser-side tamper bypass.

    // Demonstrate: a record with hyphen in a param still verifies within TS
    let hyphenChain = await runAction([], "execute_sql", { sql: "SELECT first-name FROM users" });
    const hyphenV = await verifyChain(hyphenChain);
    check("[RT-05b] browser-only chain with hyphen in param is internally consistent", hyphenV.ok);
    // Also PASSES for the same reason. Python would compute a different hash.
    // The cross-language divergence cannot be asserted here without a Python reference hash,
    // but it is proven by the analysis in attack_probe.ts / attack_probe2.ts.
  }

  // --- [RT-06] APPROVAL ABUSE: resolve unknown pending_id ---
  {
    await expectThrows("[RT-06a] resolve unknown pending_id throws", () =>
      resolvePending([], "aaaaaaaa-0000-0000-0000-000000000000", "alice", true));
  }

  // --- [RT-07] APPROVAL ABUSE: resolve a non-REQUIRE_APPROVAL record's id ---
  // DENY and ALLOW records have no pending_id, so requests() never finds them.
  // Attempting to resolve a fake UUID throws correctly.
  {
    let deniedRec = await runAction([], "execute_sql", { sql: "DROP TABLE x" }); // DENY, pending_id=null
    // The DENY record has no pending_id, so we can only probe with a made-up UUID
    await expectThrows("[RT-07a] resolve DENY record's null pending_id throws", () =>
      resolvePending(deniedRec, "fake-uuid-not-real", "alice", true));
  }

  // --- [RT-08] APPROVAL ABUSE: approve-after-deny is blocked ---
  {
    let ad: DemoRecord[] = await runAction([], "export_data", { dataset: "rt08" });
    const adPid = last(ad).pending_id as string;
    ad = await resolvePending(ad, adPid, "carol", false); // deny
    check("[RT-08a] deny does not execute", !ad.some((x) => x.decision === "EXECUTED" && x.pending_id === adPid));
    await expectThrows("[RT-08b] approve-after-deny throws (already resolved)", () =>
      resolvePending(ad, adPid, "dave", true));
  }

  // --- [RT-09] APPROVAL ABUSE: double-approve is blocked ---
  {
    let da: DemoRecord[] = await runAction([], "export_data", { dataset: "rt09" });
    const daPid = last(da).pending_id as string;
    da = await resolvePending(da, daPid, "eve", true);
    check("[RT-09a] first approve adds ALLOW+EXECUTED", da.some((x) => x.decision === "EXECUTED" && x.pending_id === daPid));
    await expectThrows("[RT-09b] second approve throws (already resolved)", () =>
      resolvePending(da, daPid, "mallory", true));
  }

  // --- [RT-10] TRAJECTORY ABUSE: EXECUTED records do NOT count toward rate-limit cap ---
  // If EXECUTED records were counted as ALLOWs in countHolds, refund cap would exhaust faster.
  // countHolds only counts decision === "ALLOW", so EXECUTED is correctly ignored.
  {
    // Build 3 refund ALLOWs + 1 RATE_LIMIT (the cap)
    let rt10: DemoRecord[] = [];
    for (let i = 0; i < 3; i++) rt10 = await runAction(rt10, "issue_refund", { amount: 50 });
    rt10 = await runAction(rt10, "issue_refund", { amount: 50 });
    check("[RT-10a] 4th refund RATE_LIMITs at exactly the cap", last(rt10).decision === "RATE_LIMIT");

    // Approve an export_data action (adds ALLOW+EXECUTED records for export_data)
    // Verify this does NOT inflate the issue_refund count
    let rt10b: DemoRecord[] = [];
    rt10b = await runAction(rt10b, "issue_refund", { amount: 50 }); // 1
    rt10b = await runAction(rt10b, "issue_refund", { amount: 50 }); // 2
    rt10b = await runAction(rt10b, "export_data", { dataset: "x" }); // REQUIRE_APPROVAL
    const rt10Pid = last(rt10b).pending_id as string;
    rt10b = await resolvePending(rt10b, rt10Pid, "alice", true); // adds ALLOW(export)+EXECUTED(export)
    rt10b = await runAction(rt10b, "issue_refund", { amount: 50 }); // 3rd refund
    check("[RT-10b] 3rd refund after export approval is still ALLOW", last(rt10b).decision === "ALLOW");
    rt10b = await runAction(rt10b, "issue_refund", { amount: 50 }); // 4th refund
    check("[RT-10c] 4th refund after export approval is RATE_LIMIT", last(rt10b).decision === "RATE_LIMIT");
  }

  // --- [RT-11] TRAJECTORY ABUSE: REQUIRE_APPROVAL record does NOT arm after-clause ---
  // A REQUIRE_APPROVAL lookup_customer record has decision !== "ALLOW".
  // afterHolds only fires on decision === "ALLOW". The exfil rule must NOT trigger.
  // (lookup_customer has no REQUIRE_APPROVAL rule in the default pack, but the principle
  // is tested by verifying that only ALLOWed reads arm the after-clause.)
  {
    // Fresh session: email without any prior lookup -> ALLOW (no after-match)
    let rt11: DemoRecord[] = await runAction([], "send_email", { to: "ops@partner.example.com" });
    check("[RT-11a] email with no prior lookup -> ALLOW", last(rt11).decision === "ALLOW");
    // After an ALLOWed lookup -> exfil rule fires -> DENY
    rt11 = await runAction([], "lookup_customer", { id: 1 });
    rt11 = await runAction(rt11, "send_email", { to: "ops@partner.example.com" });
    check("[RT-11b] email after ALLOW lookup -> DENY (exfil rule)", last(rt11).decision === "DENY");
    check("[RT-11c] exfil deny rule", last(rt11).rule === "email.deny_exfil_after_read");
  }

  // --- [RT-12] TRAJECTORY ABUSE: rate-limit RATE_LIMIT record does NOT count as ALLOW ---
  // A RATE_LIMIT verdict is not ALLOW, so a 4th refund that was RATE_LIMITed
  // must not be counted as an allowed refund in subsequent calls.
  {
    let rt12: DemoRecord[] = [];
    for (let i = 0; i < 3; i++) rt12 = await runAction(rt12, "issue_refund", { amount: 50 });
    rt12 = await runAction(rt12, "issue_refund", { amount: 50 }); // RATE_LIMIT (4th)
    rt12 = await runAction(rt12, "issue_refund", { amount: 50 }); // 5th: still RATE_LIMIT
    check("[RT-12a] 5th refund after RATE_LIMIT is still RATE_LIMIT (not ALLOW)", last(rt12).decision === "RATE_LIMIT");
    // count is still >= 3 (only 3 ALLOWs, RATE_LIMIT records don't decrement)
    const allowCount = rt12.filter((x) => x.tool === "issue_refund" && x.decision === "ALLOW").length;
    check("[RT-12b] exactly 3 ALLOW refund records in trajectory", allowCount === 3);
  }

  // --- [RT-13] INJECTION: XSS payload in params is stored but rendered safely ---
  // audit-trail.tsx uses JSON.stringify in a <pre> block and React's default escaping
  // for approver/rule text fields — no dangerouslySetInnerHTML anywhere in the render path.
  // The attack payload is stored verbatim but cannot execute.
  {
    const xssPayload = '<script>alert("xss")</script>';
    let xssRec = await runAction([], "execute_sql", { sql: xssPayload });
    check("[RT-13a] XSS payload stored verbatim in params", last(xssRec).params.sql === xssPayload);
    // Chain must still be intact (no hash disruption from the payload)
    const xssV = await verifyChain(xssRec);
    check("[RT-13b] chain verifies with XSS payload in params", xssV.ok);
    // Approver field also accepts arbitrary string (stored raw, rendered by React auto-escaping)
    let xssApproval = await runAction([], "export_data", { dataset: "test" });
    const xssPid = last(xssApproval).pending_id as string;
    xssApproval = await resolvePending(xssApproval, xssPid, xssPayload, true);
    const injApproverRec = xssApproval.find((x) => x.decision === "ALLOW" && x.pending_id === xssPid);
    check("[RT-13c] XSS approver stored verbatim", injApproverRec?.approver === xssPayload);
    const xssApprovalV = await verifyChain(xssApproval);
    check("[RT-13d] chain verifies with XSS approver", xssApprovalV.ok);
  }

  console.log(`\n${passed} passed, ${failed} failed`);
  if (failed > 0) process.exit(1);
}

main().catch((err) => {
  console.error(err);
  process.exit(1);
});
