# Phase 2 Red-Team Findings

## Suite Status

See the run report at the bottom.  All numbers are from `py -m pytest tests/ -q`.

---

## Deliberate Re-pin Inventory

Every change from a Phase-1 rule id to a Phase-2 pack rule id, file by file.
**Nothing was weakened.** Decisions are identical; only the id strings changed
because the spec changed (ADR 0003 §e says so explicitly).

### tests/conftest.py

| Change | Why |
|---|---|
| Added `configure_default_pack` autouse function-scoped fixture | Gateway is now unconfigured by default; every pre-Phase-2 test that calls `evaluate()` or `run_loop()` needs the default pack loaded.  WHY autouse: the pack is test-environment setup, not behaviour change. |
| Added module-level `_DEFAULT_PACK_CACHE` + `_get_default_pack()` | Load the pack once per session (disk I/O is expensive), cache the immutable `Pack` object. |

### tests/test_core_proofs.py

| Location | Old id | New id | Posture change? |
|---|---|---|---|
| `TestDropTableDenied.test_gateway_evaluate_denies_drop_table` | `phase1.deny_destructive_sql` | `sql.deny_destructive` | No (still DENY) |
| `TestDropTableDenied.test_run_loop_denies_drop_table_and_audits` `record["rule"]` | `phase1.deny_destructive_sql` | `sql.deny_destructive` | No |
| `TestBenignRunProceeds.test_lookup_customer_allowed` `record["rule"]` | `phase1.default_allow` | `customers.allow_lookup` | No (still ALLOW) |
| `TestBenignRunProceeds.test_calculator_allowed` `record["rule"]` | `phase1.default_allow` | `math.allow_calculator` | No (still ALLOW) |
| `TestDeterminism.test_repeated_calls_deny_same_result` `rule_ids` assertion | `{"phase1.deny_destructive_sql"}` | `{"sql.deny_destructive"}` | No |
| `TestDeterminism.test_repeated_calls_allow_same_result` `rule_ids` assertion | `{"phase1.default_allow"}` (all tools same) | per-tool: `sql.allow_other` / `customers.allow_lookup` / `math.allow_calculator` | No (each tool now has its own named rule; ids differ but decisions identical) |
| `TestDeterminism.test_context_argument_does_not_affect_decision` DENY assertion | `phase1.deny_destructive_sql` | `sql.deny_destructive` | No |
| `TestAuditIntegrity.test_deny_record_written_with_correct_fields` `record["rule"]` | `phase1.deny_destructive_sql` | `sql.deny_destructive` | No |
| `TestAuditIntegrity.test_allow_record_written_with_correct_fields` `record["rule"]` | `phase1.default_allow` | `customers.allow_lookup` | No |

### tests/test_evasion_gaps.py

| Location | Old id | New id | Posture change? |
|---|---|---|---|
| `TestCaseWhitespaceDodges.test_case_whitespace_variation_still_denied` `rule_id` assertion | `phase1.deny_destructive_sql` | `sql.deny_destructive` | No (still DENY) |
| `TestParameterAbuseGap.test_missing_sql_param_is_allowed` | no rule_id assertion; added `result.rule_id == "sql.allow_other"` | `sql.allow_other` | No (still ALLOW; mechanism changed: Phase-1 used `.get("sql","")` default; Phase-2 uses totality: missing param -> constraint does not hold -> rule 1 skip -> rule 2 `sql.allow_other` fires) |
| `TestParameterAbuseGap.test_sql_param_on_non_sql_tool_is_allowed` | no rule_id assertion; added `result.rule_id == "customers.allow_lookup"` | `customers.allow_lookup` | No (still ALLOW) |

### tests/test_write_ahead_audit.py

No `phase1.*` string literals found.  No changes needed.
The `record["rule"]` check in `required_fields` is a field-presence check only,
not a value assertion — passes unchanged.
With the conftest autouse fixture, all tests receive the default pack, so the
gateway `evaluate()` calls behave identically to the Phase-1 hardcoded rule.

---

## Confirmed Gaps Carried Forward by Design

ADR 0003 Consequences §1 says explicitly:

> The SQL evasions remain open — default-deny does NOT fix them.

The following gap classes remain open with the Phase-2 pack for the **same
reason they were open in Phase 1**: the `sql.deny_destructive` rule is in the
*negative* form (allow-unless-keyword), not the *positive* form
(allow-only-safe-SQL).  The pack's rationale field names this in-band.

| Gap class | Test file | Test class | Status |
|---|---|---|---|
| 7a: comment splitting (`DR--\nOP TABLE`) | `test_evasion_gaps.py` | `TestCommentInjectionGap` | Open by design; ALLOW / `sql.allow_other` |
| 7c: unicode look-alikes (`DRОP` with Cyrillic О) | `test_evasion_gaps.py` | `TestEncodedAndConcatenatedSQLGap` | Open by design; ALLOW / `sql.allow_other` |
| 7c: hex encoding | `test_evasion_gaps.py` | `TestEncodedAndConcatenatedSQLGap` | Open by design; ALLOW / `sql.allow_other` |
| 7d: unlisted destructive verbs (UPDATE, MERGE, GRANT, REPLACE, VACUUM, PRAGMA) | `test_evasion_gaps.py` | `TestDestructiveButUnlistedVerbsGap` | Open by design; ALLOW / `sql.allow_other` |

The `documented_gap` mark is preserved on all of the above tests.

**Why acceptable**: 2a's job is the *framework* — declarative packs, default-deny,
per-parameter constraints — not SQL parsing.  The secure form is a *positive*
"allow only provably-safe SQL" rule requiring a real SQL parser, explicitly deferred.
Default-deny closes the *unknown-tool* threat class (e.g. `rm_rf_everything`);
it does not close the *known-tool-with-evasive-params* threat.

---

## New Attack Tests (tests/test_policy_attacks.py)

Eight attack classes, 32 individual tests.

| # | Class | What it attacks | Expected decision |
|---|---|---|---|
| 1 | `TestYamlSafeLoadProof` | `!!python/object/apply:os.system`, `!!python/object:builtins.dict`, `!!python/object:pathlib.Path`, embedded code tag in rule rationale | `PolicyError` raised; `os.system` spy never called |
| 2 | `TestPartialLoadForbidden` | Pack with 3 valid rules + 1 unknown-operator rule; prove NOTHING from the pack takes effect | `PolicyError`; gateway remains `policy.no_pack` after failed load |
| 3 | `TestReservedNamespaceMinting` | ids `aegis.*`, `policy.*` (10 variants) rejected; look-alike ids (`aegisx.*`, `my.aegis.*`, etc., 8 variants) accepted | Reserved: `PolicyError`; look-alike: accepted |
| 4 | `TestShadowingAttack` | Broad ALLOW above DENY shadows the DENY (documented sharp edge); reverse order DENYs | ALLOW-above-DENY: ALLOW/`broad_allow`; DENY-above-ALLOW: DENY/`deny_drop` |
| 5 | `TestOperatorBoundaryAbuse` | max exact boundary, float/int cross, bool smuggling (True vs max:1), huge string with/without keyword, one_of int-vs-string, one_of bool-vs-int, domain_in two-@, domain_in no-@, case-insensitive domain | See individual test expectations |
| 6 | `TestAllowGuardOmissionAttack` | wire_transfer with missing amount, string amount, valid amount, exact cap, over cap, None amount | Missing/wrong-type: DENY; valid: ALLOW |
| 7 | `TestDeterminismUnderHostility` | 50 repeats for each of 10 adversarial call patterns (wire pack + default pack) | All 50 identical |
| 8 | `TestLoopIntegration` | DROP TABLE via loop, unknown tool `rm_rf_everything` via loop, denial message content, benign tool after deny | DENY/`sql.deny_destructive`; DENY/`policy.default_deny`; marker in content; no latched state |

---

## Bug Reports

**None found.**

All attacks produced the expected decisions.  The enforcement path held on:

- YAML code-construction tags (dead via `yaml.safe_load`).
- Partial-load (all-or-nothing rejected correctly).
- Reserved-namespace ids (exact-prefix check works; look-alike ids accepted).
- Shadowing (first-match-wins is the documented behavior, not a bypass).
- Operator boundary abuse (bool excluded from max, type-aware one_of, exact-one-@ for domain_in).
- ALLOW-guard omission (missing/wrong-type param cannot satisfy ALLOW guard).
- Determinism (50 repeats identical in every case).
- Loop integration (default-deny posture for unknown tools; write-ahead for default_deny rule id).

---

## Full Suite Run (Slice 2a — pre-2b)

Run command: `py -m pytest tests/ -q`
Result: **270 passed, 0 failed** (pyyaml 6.0.3 / Python 3.11).

Breakdown: all Phase-1 proofs (re-pinned ids, identical decisions), the ADR 0002
write-ahead suite (unchanged), `test_policy_engine.py` (schema/engine/loader/adapter
units), and `test_policy_attacks.py` (8 attack classes, 32 tests).

One test-code defect was found and fixed during the first run (not an engine bug):
`TestReservedNamespaceMinting::test_reserved_id_rejected` had a malformed `with`
statement (an f-string accidentally treated as a second context manager), which
raised `TypeError` before `validate()` ran.  After the fix, all 10 reserved-id
rejections pass against the existing `schema.py` enforcement — reserved-namespace
enforcement was present in the engine all along; only the test was broken.

---

## Slice 2b — Trajectory Awareness Attack Suite

**File:** `tests/test_trajectory_attacks.py`

### Attack Inventory

| # | Class | What it attacks | Expected decision |
|---|---|---|---|
| 1 | `TestFullLoopBeforeAfterPair` | Full four-turn loop run: partner send before read (ALLOW), lookup (ALLOW), SAME partner send after read (DENY), internal send (ALLOW). Spy counts. Denial message names exfil rule. | ALLOW/ALLOW/DENY/ALLOW; spy called exactly once for partner address; is_error denial names `email.deny_exfil_after_read` |
| 2 | `TestDeniedReadDoesNotTaint` | DENYed lookup_customer (custom pack) → partner send must ALLOW. Ghost-read must not taint. Tests ALLOW-only pinning end-to-end. | lookup DENY/`test.deny_lookup`; send ALLOW/`email.allow_known_domains` |
| 3a | `TestTrajectoryInjectionViaEvaluateSeam::test_3a_forged_trajectory_fires_exfil_deny` | Forged trajectory handed directly to `evaluate()`. BY DESIGN: evaluate trusts its caller → exfil DENY fires. | DENY/`email.deny_exfil_after_read` (by-design note) |
| 3b | `TestTrajectoryInjectionViaEvaluateSeam::test_3b_*` | Untaint attempt: call evaluate with None or non-list after a tainted call → 2a behavior. BY DESIGN: loop never does this. | ALLOW/`email.allow_known_domains` (by-design note) |
| 3c | `TestTrajectoryInjectionViaEvaluateSeam::test_3c_*` | Junk flood (1000 entries) → no crash, same decision as empty trajectory. Plus junk+real-record at end → real record found. | No crash; ALLOW (junk only); DENY (junk+real) |
| 3d | `TestTrajectoryInjectionViaEvaluateSeam::test_3d_non_string_tool_type_is_not_a_match` | Non-string tool/decision types in record (`list`, `bool`, `int`, `None`) → not-match, no crash. | ALLOW/`email.allow_known_domains` |
| 3e | `TestTrajectoryInjectionViaEvaluateSeam::test_3e_list_of_lists_trajectory_no_crash_no_match` | Trajectory is a list of lists (not dicts) → no crash, no match. | ALLOW/`email.allow_known_domains` |
| 4a | `TestDomainNotInEvasionAtLoopLevel::test_4a_double_at_sign_address_denied_by_floor` | Two-@ address after tainted run: malformed → domain_not_in does not hold; domain_in does not hold → floor catches it. | DENY/`policy.default_deny` (floor, NOT exfil rule) |
| 4b | `TestDomainNotInEvasionAtLoopLevel::test_4b_uppercase_internal_address_allowed_after_taint` | Uppercase internal address `ALICE@INTERNAL.EXAMPLE.COM` after tainted run → case-insensitive match → ALLOW. | ALLOW/`email.allow_known_domains` |
| 4c | `TestDomainNotInEvasionAtLoopLevel::test_4c_empty_to_address_denied_by_floor` | Empty `to` after tainted run → floor. | DENY/`policy.default_deny` |
| 4d | `TestDomainNotInEvasionAtLoopLevel::test_4d_malicious_subject_body_*` | Hostile subject/body (DROP TABLE, policy-override text) → identical decision to benign (content never inspected, invariant 1). | Same decision as benign subject/body |
| 5a | `TestOrderingSelfReference::test_5a_first_action_send_email_*` | First action in the run is a partner send (empty trajectory) → ALLOW. Default pack's exfil DENY sees an empty trajectory. | ALLOW/`email.allow_known_domains` |
| 5b | `TestOrderingSelfReference::test_5b_strictly_earlier_property_*` | Self-referential pack (send_email after:{tool:send_email}). First send ALLOW (empty trajectory), second send DENY (first send in trajectory). Directly proves the strictly-earlier property. | trail[0] ALLOW/`email.allow_partner`; trail[1] DENY/`email.deny_after_send` |
| 6a | `TestDeterminismUnderTaintAtLoopLevel::test_two_identical_tainted_runs_*` | Two identical full runs → identical (tool, decision, rule) tuples. | Both trails identical |
| 6b | `TestDeterminismUnderTaintAtLoopLevel::test_determinism_ten_runs_all_identical` | Ten identical runs → all audit trails identical. | All 10 identical |

### By-Design Findings (not bugs)

**Finding 2b-BD-1: evaluate seam trusts its caller (attack 3a).**
`gateway.evaluate(tool, params, context)` accepts any list as the trajectory and trusts
it verbatim. An attacker who can call `evaluate()` directly can forge a trajectory that
makes the exfil DENY fire (or pass `None` to revert to 2a behavior). This is BY DESIGN
at the `evaluate` seam: the ADR 0004 §d extraction branch is `isinstance(context, list)`;
it classifies every input into one of two paths with zero interpretation. The LOOP is the
trust boundary: `run_loop` owns the trajectory (its own `audit_trail` list), constructs
it from its own write-ahead audit records, and threads it directly into `evaluate`. No
outside caller controls the trajectory once the loop is running. The `evaluate` seam is
an internal function consumed only by `run_loop` in production; its contract is "caller
must pass a valid trajectory or None." The loop satisfies this contract by construction.

**Finding 2b-BD-2: non-list context silently reverts to 2a behavior (attack 3b).**
Calling `evaluate()` with `context=None` (or any non-list) after a tainted run produces
a 2a decision (ALLOW for a partner send). This is BY DESIGN at the `evaluate` seam: the
extraction branch `trajectory = context if isinstance(context, list) else None` is total
and intentionally maps all non-list values to the safe (2a) fallback. The loop never
passes `None` after a run has started — it always threads `audit_trail` (a list, even if
empty) as the context argument. The fallback is therefore unreachable in normal loop
operation; it exists to handle the bootstrapping case and to preserve 2a behavior for
callers that never set up a trajectory. Direct callers who pass `None` deliberately get
exactly what they ask for: no trajectory awareness. This is not a bug; it is the
documented totality contract of the extraction seam (ADR 0004 §d).

### run_loop context= parameter: confirmation

The `run_loop` signature in `core/loop.py` has NO `context=` parameter (it was REMOVED
per ADR 0004 §d review decision). A grep of all test files (`tests/*.py`) and demo files
(`demos/*.py`) for the pattern `run_loop.*context=` returns zero matches. No existing
tests pass `context=` to `run_loop`, confirming that the parameter removal is a safe
change and no existing test depends on the former caller-facing `context` handle.

### Suite Status

Suite NOT run — pending user execution (shell blocked; harness outage noted in task spec).

The suite covers 19 test methods across 6 attack classes. It does not duplicate any case
from `test_policy_engine.py` (which covers schema rejections, `_after_holds` basics,
junk-trajectory totality at `decide()`, `domain_not_in` semantics, the engine-level
proof-of-worth pair, and determinism repeats at `decide()` level). This suite adds the
loop-level and evaluate-seam adversarial coverage that completes the 2b red-team mandate.
