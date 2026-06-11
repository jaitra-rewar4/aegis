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

## Full Suite Run

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
