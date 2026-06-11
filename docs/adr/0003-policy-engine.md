# 0003 — The declarative policy engine (Phase 2)

- Status: Accepted
- Date: 2026-06-09
- Deciders: architect (policy-engineer implements 2a, gateway-engineer wires the adapter, red-team proves)
- Supersedes: — (replaces the single hardcoded rule pinned in ADR 0001 §2; composes with the write-ahead ordering pinned in ADR 0002)

## Problem

ADR 0001 shipped exactly one rule, hardcoded in Python inside `core/gateway.py`: deny `execute_sql` when a destructive keyword is present, allow everything else. It was always a stopgap — ADR 0001 §2/§7 said so out loud. Two structural properties of that stopgap are now the thing blocking us:

1. **Policies are not declarative or reviewable.** A rule is Python a non-author has to read as code, not data. The thesis requires policies be reviewable by someone who didn't write them — that means data with a first-class rationale, not a function body.
2. **The posture is default-allow.** Any tool the rule does not name sails through to ALLOW. That is the wrong default for a least-privilege gateway: an unknown or unanticipated tool is exactly the action we cannot reason about, and it is currently permitted.

Phase 2 introduces the declarative policy engine that replaces the hardcoded rule. This ADR pins **slice 2a** — the *stateless* engine (a pure decision function over a validated YAML pack + per-parameter constraints) — to build now, and **sketches slice 2b** — *trajectory awareness* — to build next.

What 2a must not pretend to be: a fix for the SQL keyword-scan evasions. ADR 0001 documented gap classes 7a/7c/7d (comment splitting, unicode look-alikes, hex encoding, unlisted verbs) in `tests/PHASE1_FINDINGS.md`. 2a carries those gaps forward unchanged, on purpose, and says so plainly (see Consequences). The engine's value is the *framework* — declarative packs, default-deny, per-parameter constraints, and later trajectory — not SQL parsing.

This ADR pins, for 2a: format and posture (user-decided), the module layout, the purity boundary, the rule schema and operator set, precedence, the default-pack migration, and how it composes with the loop and the write-ahead audit. Then it sketches 2b's two load-bearing decisions.

## Decisions

### User-decided constraints (recorded and justified, not relitigated)

**Format: YAML, via `pyyaml` — the one new dependency.**

- **`yaml.safe_load` only, never `yaml.load`.** `yaml.load` can construct arbitrary Python objects from a document; a policy pack is untrusted-adjacent configuration that should never be able to instantiate code. `safe_load` restricts the document to plain scalars, lists, and dicts. This is non-negotiable: a loader that can be made to execute code is a non-deterministic, injectable hole in the path that *produces* the rules the enforcement path runs on.
- **Strict schema validation that fail-closes.** A malformed pack, an unknown field, an unknown operator, an unknown effect, or a bad type → the **whole pack is rejected**, and the engine is left with **no pack** (which is default-deny — see posture). Never partial, never guessed, never "load the rules we understood and skip the ones we didn't." WHY all-or-nothing: a partially-loaded pack is a policy nobody wrote and nobody reviewed — its actual behavior is the intersection of what the author intended and what the parser happened to tolerate. That is precisely the un-reviewable, un-predictable state default-deny exists to forbid. Rejecting the whole pack keeps the predicate "a non-author can read the pack and predict the decision" true: the pack either *is* the spec, or there is no spec and everything is denied.
- **Rationale is a first-class schema field on every rule** — a required string, not a YAML comment. WHY first-class: comments do not survive parsing or serialization, cannot be asserted on in tests, and cannot be surfaced in the dashboard or the denial message. A policy that cannot be explained to the person reviewing it is not reviewable. Making rationale required and parsed means every rule carries its own justification through the audit trail and the UI, and a rule with no stated reason fails to load.

**Posture: default-deny, declared in the pack.**

The pack declares its fallthrough explicitly (`default: deny`). With no pack loaded (none configured, or a pack that failed validation), the engine denies everything. WHY default-deny is the right posture and consistent with ADR 0002: ADR 0002 made the *audit* fail closed (an action that cannot be logged does not execute). Default-deny makes the *policy* fail closed in the same spirit — an action no rule speaks to does not execute. This closes the unknown/unanticipated-tool threat that default-allow left open.

**Honest scope of what default-deny does and does not fix.** Default-deny closes the *unknown tool* gap. It does **not** close the SQL keyword-scan evasions. The migrated SQL rule keeps its Phase-1 *negative* structure — ALLOW `execute_sql` *unless* a destructive keyword is present — so the documented evasions (7a comment splitting, 7c unicode/hex, 7d unlisted verbs) still reach ALLOW exactly as before. The secure form is the *positive* one — "allow `execute_sql` only when the statement is provably one of a small set of safe shapes" — and that needs a real SQL parser, which is explicitly deferred. This ADR does not represent default-deny as fixing SQL evasion (see Consequences §1).

**Out of scope: `RATE_LIMIT` and `REQUIRE_APPROVAL` enforcement flows — and the 2a schema does not accept those effect values.** The `Decision` enum carries all four values (ADR 0001 §6), but in 2a a rule may only declare `effect: ALLOW` or `effect: DENY`. A pack that names `RATE_LIMIT` or `REQUIRE_APPROVAL` as an effect is **rejected at load** (unknown-effect → whole pack rejected). WHY validation refuses them rather than accepting-and-ignoring: if the schema silently accepted `REQUIRE_APPROVAL`, an author would ship a rule believing it gates on human approval while the loop (which treats every non-ALLOW as a non-executing refusal — ADR 0001 §6) would in fact behave as a blunt DENY with no approval ever solicited. That is a policy that lies about itself. Refusing the value at load makes the gap loud. **Widening later is backward-compatible; narrowing is not** — so we start narrow. When the approval and rate-limit flows ship, the schema admits the new effects and existing ALLOW/DENY packs keep validating unchanged.

### a) Module layout in `policy/`

Keep it small; one responsibility per file; disk touched in exactly one place.

```
policy/
  schema.py    # the strict validator: dict-in → validated Pack/Rule objects, or raise PolicyError.
               # No file I/O. No YAML. Pure structural + type validation over plain dicts.
  engine.py    # the pure decision function: decide(pack, tool, params) -> GatewayResult.
               # No file I/O, no YAML, no clock, no random, no network. Imports nothing from loader.
  loader.py    # the ONLY module that touches disk and YAML. Reads a path, yaml.safe_load,
               # hands the resulting dict to schema.validate(), returns a Pack (or raises).
  packs/
    default.yaml   # the example pack that reproduces current demo behavior under default-deny.
```

WHY this split: it makes the purity boundary a module boundary, not a discipline. `engine.py` *cannot* perform I/O or parse YAML because it imports neither `loader` nor `yaml`. A reviewer confirms the decision path is pure by reading the imports of one file. `schema.py` is separated from `loader.py` so validation is testable on in-memory dicts with no filesystem, and so the loader's only job is the boring "bytes → dict → validate."

### b) The purity boundary

**File I/O and YAML parsing happen only at load time, in `loader.py`, never inside evaluation.** The engine core is the pure function:

```
engine.decide(pack, tool, params) -> GatewayResult
```

`core/gateway.py` keeps its pinned signature `evaluate(tool, params, context)` (ADR 0001 §1a — the loop's call site does **not** change) and becomes a **thin adapter**: it holds the configured pack and calls `engine.decide(pack, tool, params)`.

**How the pack reaches `evaluate` — pinned: a module-level pack in `core/gateway.py`, set once at startup by an explicit `configure(pack)` call; the pack is NOT passed through `context`.**

- An explicit startup call `gateway.configure(loaded_pack)` (fed by `loader.load(path)`) sets a module-level `_ACTIVE_PACK`. `evaluate` reads `_ACTIVE_PACK` and delegates to `engine.decide`.
- **If `_ACTIVE_PACK` is `None`** (nobody configured a pack, or load failed and the caller chose to proceed), `evaluate` returns `DENY` with rule id `policy.no_pack` (see §f). Default-deny is the literal default of the unconfigured module.

WHY module-level configured pack and not via `context`:
- **`context` is reserved for session trajectory** (ADR 0001 §1a, and 2b below). Overloading it to also carry policy would entangle "what the rules *are*" (set once, at startup, by an operator) with "what has happened *this session*" (accumulated per call, by the loop). Those are different lifecycles and different trust origins; keeping them in different handles keeps each one's nondeterminism story clean.
- **The loop's call site must not change.** ADR 0001 pinned `evaluate(tool, params, context)`. Threading a pack as a *fourth* argument would break that signature and ripple through the loop and tests. A module-level pack set out-of-band by `configure` leaves `evaluate(tool, params, context)` byte-for-byte unchanged.
- **The pack is set once and is immutable for the run.** WHY that preserves determinism: `decide` is pure in `(pack, tool, params)`; if the pack is fixed for the run, `evaluate(tool, params, context)` is a pure function of its inputs for that run, identically to Phase 1. `configure` is a startup wiring step, not part of the decision path — exactly as `ts` stamping is audit metadata outside the decision path (ADR 0001 §4).

**No clock, no random, no network anywhere in `decide` or `evaluate`** (invariant 2). The operator set (§c) is deliberately regex-free and arithmetic/membership only, so there is not even a regex engine in the path.

### c) The rule schema

A pack is:

```yaml
version: 1
default: deny            # deny | allow ; default posture when no rule matches. REQUIRED.
rules:
  - id: <namespaced id>  # REQUIRED. e.g. sql.deny_destructive. MUST NOT be in aegis.* or policy.*.
    rationale: <string>  # REQUIRED, first-class. Why this rule exists. Survives parsing.
    tool: <tool name>    # REQUIRED. Exact string match against the proposed tool name.
    when:                # OPTIONAL. Per-parameter constraints; ALL must hold for the rule to match.
      <param>: { <operator>: <operand> }
    effect: ALLOW | DENY # REQUIRED. Only these two in 2a (see Out of scope).
```

Field rules (any violation → **whole pack rejected**, per the strict-validation mandate):

- **`id`** — required, non-empty string, namespaced. **Reject any id in the reserved `aegis.*` namespace** (operational markers like `aegis.audit_unavailable` — ADR 0002) **and in the reserved `policy.*` namespace** (engine markers like `policy.no_pack` — §f). WHY reserve both: the audit `rule` field and the loop's branching distinguish *policy rule fired* from *operational refusal* (ADR 0002) and from *engine default*; a pack that could mint an `aegis.*` or `policy.*` id would blur that boundary, which is the one boundary ADR 0002 told us to keep clean.
- **`rationale`** — required, non-empty string.
- **`tool`** — required, exact match (no globbing in 2a; a glob is a new operator and we are not introducing one we cannot trivially make total and obvious).
- **`when`** — optional. A mapping of parameter name → a single-operator constraint. Absent `when` means the rule matches any call to that tool.
- **`effect`** — required, `ALLOW` or `DENY` only.

**The operator set for `when` — the minimal, total, deterministic set:**

| Operator | Operand | Holds when | Constraint class |
|---|---|---|---|
| `max` | number | param is a number and `param <= operand` | numeric threshold (amount limits) |
| `min` | number | param is a number and `param >= operand` | numeric threshold |
| `one_of` | list of scalars | param equals one of the listed values | value allowlist |
| `prefix_one_of` | list of strings | param is a string starting with one of the listed prefixes | path/scope allowlist |
| `domain_in` | list of strings | param is a string of form `local@domain` and `domain` is in the list | recipient-domain rule (email param) |
| `contains_keyword` | list of strings | param, normalized (uppercase + whitespace-collapse, exactly ADR 0001 §2), tokenizes to a set intersecting the listed keywords | migrate the Phase-1 SQL scan |
| `not_contains_keyword` | list of strings | the negation of `contains_keyword` | positive-safe phrasing where wanted |

Every operand type is validated at load; a wrong operand type (e.g. `max: "ten"`, `one_of: 5`) → pack rejected. **An unknown operator → pack rejected at load.** WHY this exact set: it covers every constraint class the user named (numeric limits, value allowlists, path/scope allowlists, recipient-domain, and the SQL keyword migration) with operators that are each (1) **total** — defined for every input including missing/wrong-typed params, (2) **regex-free** — pure arithmetic, membership, and string-prefix/split, no regex engine, no catastrophic-backtracking surface, (3) **obvious** — a non-author reads the operator name and predicts its result. `contains_keyword` reuses ADR 0001's exact normalization so the migrated SQL rule behaves identically to the hardcoded one — same behavior, same documented gaps, no surprises.

**Totality and the missing-parameter rule — pinned: a constraint on a missing (or wrong-typed) parameter does NOT hold; therefore the rule does NOT match.**

Concretely: if `when` names parameter `p` and `p` is absent from `params` (or present but of a type the operator cannot evaluate, e.g. `max` on a string), that constraint evaluates to `False`, and since all constraints in a `when` must hold for the rule to match, **the rule does not match** and evaluation falls through to the next rule (and ultimately to `default`).

WHY "constraint-on-missing-param does not hold" is the fail-safe direction, thought through for **both** effects:

- **The rule's effect is the thing that varies; the constraint semantics must be invariant.** A constraint is a *predicate about a concrete parameter value*. If the value is not there, the predicate has nothing to be true about — `False` is the honest answer. We do not invent a value, and we do not let "I couldn't evaluate this" silently satisfy the predicate.
- **For a DENY rule:** "does-not-hold → does-not-match → fall through" means a *missing* parameter does not, by itself, trigger the DENY — but because the pack is **default-deny**, falling through all rules lands on `default: deny`. So a malformed call that dodges every DENY rule's `when` still ends at DENY. The fail-safe is delivered by the *posture*, not by overloading the constraint. This keeps the constraint's meaning identical regardless of the rule's effect, which is what makes the engine predictable.
- **For an ALLOW rule:** "does-not-hold → does-not-match" means a missing or wrong-typed parameter **cannot satisfy an ALLOW rule's guard**. An ALLOW rule that says "allow `wire_transfer` when `amount` has `max: 1000`" must never fire for a call with no `amount` — that would be allowing an unbounded transfer because a field was omitted. Making the constraint fail closed means the omission denies (via fallthrough to default-deny), never allows. This is the case that would bite hardest if we got it backwards, and it is exactly why the rule is "missing → does not hold" rather than "missing → vacuously true."
- **Net:** the constraint predicate is *monotone toward not-matching* on missing data, and default-deny converts not-matching into denying. An author reasoning about a rule never has to ask "what if the param is missing?" — the answer is always "the rule doesn't fire, and absence ultimately denies."

This is documented on the schema and proven by red-team for both an ALLOW guard and a DENY guard.

### d) Precedence — pinned: first-match-wins, in file (document) order

Rules are evaluated **top to bottom in the order they appear in the pack**. The **first** rule whose `tool` matches and whose `when` (if present) holds determines the decision; its `effect` and `id` are returned immediately. If no rule matches, the pack's `default` decides (`policy.default_deny` / `policy.default_allow` — §f).

WHY first-match-wins over DENY-overrides:
- **The pack is the spec, and order is visible.** A reviewer reads the file top to bottom and sees precedence directly — the order on the page *is* the precedence. DENY-overrides requires the reviewer to scan the *whole* pack for any DENY that might countermand an earlier ALLOW; precedence becomes a property of the set, not of the position, and is harder to predict by eye.
- **Determinism is trivially provable.** Same pack + same `(tool, params)` → the same first matching rule fires, because dict/list iteration over a parsed YAML sequence is insertion-ordered and stable in Python. There is no scoring, no "most specific wins" tie-break that could depend on hashing or set ordering.
- **The author keeps explicit control.** Want a deny to win over a broad allow? Put the deny first. The mechanism for "this should override that" is "write it above" — which is exactly what the file order already shows. WHY this is acceptable given default-deny: the dangerous failure mode of first-match-wins (a too-broad ALLOW high in the file shadowing a later DENY) is the author's visible mistake on the page, reviewable in the pack; it is not a hidden interaction. And the *un-anticipated* case — a tool/param combo no rule matches — is caught by default-deny regardless of ordering.

Pinned property to prove (red-team): for any pack and any `(tool, params)`, the rule that fires is a pure function of the pack's rule order — re-running yields the identical `id`, every time.

### e) Migration — `packs/default.yaml` reproduces current demo behavior under default-deny

The default pack makes the three demo tools behave as they do today, but now under an explicit default-deny floor:

- `default: deny`.
- An explicit **ALLOW** rule for `lookup_customer` (no `when` — read-only, always allowed in 2a).
- An explicit **ALLOW** rule for `calculator` (no `when` — pure, always allowed).
- The SQL rule **migrated in its negative form**: a **DENY** rule on `execute_sql` with `when: { sql: { contains_keyword: [DROP, DELETE, TRUNCATE, ALTER] } }`, placed *above* an explicit **ALLOW** rule on `execute_sql` (no `when`). First-match-wins: destructive SQL hits the DENY; everything else on `execute_sql` hits the ALLOW. This is byte-for-byte the Phase-1 behavior — **and it carries the Phase-1 gaps (7a/7c/7d) forward unchanged, by design** (Consequences §1). Each rule's `rationale` states this explicitly, including that the destructive-keyword rule is a documented-gap stopgap pending a real SQL parser.

**Named consequence for the test suite (deliberate, not a weakening):**

- **`rule_id`s change** from `phase1.*` to pack-defined ids (`phase1.deny_destructive_sql` → e.g. `sql.deny_destructive`; `phase1.default_allow` → per-tool allow ids and the `policy.default_deny` fallthrough). Tests that assert literal `phase1.*` ids must be **updated deliberately by red-team** to the new ids — the assertion changes because the *spec* changed, not because the test was loosened.
- **Unmatched tools flip from ALLOW to DENY.** Any test that implicitly relied on default-allow for an un-named tool now correctly expects DENY (`policy.default_deny`). This is the posture change landing; the test must be re-pinned to the new, stricter expectation.
- **What does NOT change, and red-team must keep proving:** the non-execution proofs (a DENY means the tool function is never called — row-survival + spy), the determinism proofs (same input → same decision, repeated), the write-ahead ordering proofs (ADR 0002), and the invariant-1 proof (text blocks never reach `evaluate`). The decisions move from a Python `if` to a YAML pack; the *guarantees* are identical and the proofs of them must stay green.

### f) How it composes — with the loop and with the write-ahead audit

**With the loop (ADR 0001 §1, ADR 0002): the call site does not change.** The loop still calls `evaluate(tool, params, context)`, still write-ahead-appends the record, still executes **only** on an exact `Decision.ALLOW`, still refuses everything else. The engine produces only `ALLOW` and `DENY` in 2a, so the loop's "exact ALLOW executes, everything else refuses" logic is untouched. The loop's denial message (`_make_denial_result`) already names the `rule_id`; now that id is a pack rule id (or an engine marker), which is *more* informative, not less.

**With the write-ahead audit (ADR 0002): the record's `rule` field now carries the pack rule id.** `append_record(..., rule=result.rule_id, ...)` is unchanged; the value it logs is now `sql.deny_destructive`, `lookup_customer.allow`, etc. — exactly the reviewable id from the pack.

**Reserved engine markers for the non-rule decisions — pinned in a `policy.*` namespace, distinct from both pack ids and `aegis.*`:**

| Marker | Emitted when | Decision |
|---|---|---|
| `policy.default_deny` | a pack is loaded, no rule matched, and `default: deny` | DENY |
| `policy.default_allow` | a pack is loaded, no rule matched, and `default: allow` | ALLOW |
| `policy.no_pack` | no pack is configured, or the configured pack failed to load | DENY |

WHY three markers and a dedicated `policy.*` namespace, not folded into one:
- **`policy.*` vs `aegis.*` is the boundary ADR 0002 told us to keep clean.** ADR 0002 made the audit fail-closed marker `aegis.audit_unavailable` an *operational* refusal that `evaluate()` was never consulted about, and required it stay distinguishable from every policy `rule_id`. The `policy.*` markers are the opposite kind of thing: they ARE the engine's decision (the default fired, or there was no pack to consult). Putting engine decisions under `policy.*` and operational overrides under `aegis.*` means a single glance at a `rule` value in the audit log says which world produced it: `aegis.*` = the loop overrode a decision because infrastructure failed; `policy.*` = the engine decided via its default/no-pack path; anything else = a named rule the author wrote. Packs are forbidden (§c) from minting ids in either reserved namespace, so the three categories never collide.
- **`no_pack` is kept distinct from `default_deny` on purpose.** Both produce DENY, but they mean different things to an operator reading the log: `default_deny` says "your pack is loaded and this action matched nothing," `no_pack` says "there is no pack at all — check your startup wiring / your pack failed validation." Folding them would erase the single most useful signal for diagnosing a misconfigured deployment (everything denied because the pack silently failed to load). Same decision, different diagnosis — so, different marker.

## Slice 2b — sketch only (trajectory awareness)

2b adds rules that depend on what happened *earlier in the same session* — the exfiltration catch: **block a send/egress action if a read-sensitive action occurred earlier in the same session.** A `send_email` / egress demo tool arrives with 2b (the "send" half of the read→send chain; `lookup_customer` is already the "read sensitive" half — ADR 0001 §3). No implementation here; this ADR pins the two load-bearing decisions 2b must honor.

**Decision 1 — where the session trajectory lives: derived from the recorded audit trail, threaded through the existing `context` handle. NOT a separate in-memory mutable session object.**

The loop already accumulates `audit_trail: list[dict]` — the records returned by the write-ahead `append_record` (`core/loop.py`). ADR 0002 guarantees **record-before-execute**: every executed action is in that list, durably, before it ran. So that list is *exactly* "the recorded trajectory of concrete decisions this session." 2b threads that handle into `context`, and `evaluate` reads prior **records** from it.

WHY derived-from-the-recorded-trail over a separate session object:
- **It is the trail ADR 0002 already guarantees.** "What the engine sees as history" and "what is durably recorded as having happened" become the *same* object. The trajectory rule reasons over precisely the decisions that were logged, with no second source of truth to drift.
- **No file I/O inside `evaluate`.** The records are already in memory in the loop; threading the existing list keeps the purity boundary (§b) intact — `evaluate` reads an in-memory data structure handed to it, it does not read the log file. "Derived from the audit trail" here means *derived from the in-memory records the loop holds, which are by construction the recorded ones* — not "re-parse the JSONL on every call."
- **Failure modes of the alternative (a separate mutable in-memory session object), named:** (1) **Drift** — a session object updated independently of the audit append can disagree with the log; the engine would then enforce on a history that was never recorded, or miss one that was. (2) **A second write path** — every place that mutates the session object is a place that can forget to, or can record something the audit trail did not, reintroducing exactly the executed-but-unrecorded gap ADR 0002 closed. (3) **Ordering ambiguity** — two sources (session object + audit list) means a reviewer must reason about which one `evaluate` trusts when they differ. Deriving from the recorded trail collapses all three: there is one list, it is the logged one, and `evaluate` reads it.

**Decision 2 — the determinism story for invariant 2, with history in the inputs.**

`evaluate` will now depend on session history, and that is still deterministic — precisely because of *what* the history is and *what it is not*:

- **Deterministic given `(tool, params, recorded trajectory)`.** The decision is a pure function of three data inputs. Same tool, same params, same prior recorded decisions → same decision, every time. The trajectory is *input data*, exactly like `params` — adding a data input does not add nondeterminism; reading a clock or an LLM would, and we do neither.
- **The trajectory is data about prior CONCRETE tool calls — never model text (invariant 1).** Each record is `{tool, params, decision, rule, ...}` — concrete actions and their decisions. The engine reasons over "did a `lookup_customer` (a read-sensitive *action*) get ALLOWed earlier," never over anything the model *said*. Invariant 1 holds in 2b exactly as in 2a: only concrete tool calls — now including *past* concrete tool calls — reach the gate.
- **No wall-clock, anywhere.** The trajectory is an *ordered list of prior actions*, not a set of timestamps the decision branches on. Sequence ("a read happened *before* this send") is read from list order — a deterministic, recorded fact — not from comparing `ts` values. **Time-based limits stay out of scope precisely to preserve this:** the moment a rule says "within the last N seconds," `evaluate` reads a clock and the gate stops being a pure function of its inputs. 2b's rules are *sequence*-aware, never *time*-aware. (This is the same reason ADR 0001 §4 kept `ts` out of the decision path; 2b extends the principle to trajectory.)

**Canonical 2b rule to sketch:** on a `send_email` (egress) call, DENY if any earlier record in this session's recorded trajectory is an ALLOWed read-sensitive action (e.g. an ALLOWed `lookup_customer`). The demo: the agent reads a customer record (ALLOWed), then tries to egress it (DENYed by the trajectory rule) — the exfiltration chain, caught at the *action* layer, deterministically, on the recorded sequence of concrete calls. The schema shape that expresses this (a `when` that names a prior action rather than a current param) is 2b's design work and is **not** pinned here.

## How the invariants hold

**Invariant 1 (tool-call boundary, not model text).** Unchanged and reinforced. The loop still routes only `tool_use` blocks to `evaluate` (ADR 0001 §1); text blocks are still ignored. The engine evaluates the concrete tool name and concrete parameter *values* against declarative constraints — never model prose. The rationale field is author-written policy data, not model output, and never enters the decision (it is metadata for review and the audit log). In 2b the added input is *prior concrete actions*, still never text.

**Invariant 2 (deterministic gate).** Held. `engine.decide(pack, tool, params)` is a pure function — no LLM, no `random`, no clock, no network, no I/O. The pack is fixed for the run (set once by `configure`, immutable thereafter), so `evaluate(tool, params, context)` is a pure function of its inputs exactly as in Phase 1. Precedence is first-match-wins over a stably-ordered list, so the same pack + same call provably fires the same rule. The operator set is arithmetic/membership/prefix/split only — regex-free, total on missing/wrong-typed params, with the missing-param semantics pinned. File I/O and YAML parsing live only in `loader.py`, only at startup, structurally outside the decision path. The strict, fail-closed validator means the engine never runs on a half-understood pack: it runs on a fully-validated pack or on no pack (default-deny) — there is no third, ambiguous state.

## Consequences / Tradeoffs

Named plainly so they can be defended out loud:

1. **The SQL evasions remain open — default-deny does NOT fix them.** The migrated `execute_sql` rule keeps its Phase-1 *negative* form (ALLOW unless a destructive keyword is present), so gap classes 7a (comment splitting `DR--\nOP`), 7c (unicode look-alikes, hex encoding), and 7d (unlisted destructive verbs: `UPDATE`, `MERGE`, `GRANT`, `REPLACE`, `VACUUM`…) still reach ALLOW, exactly as documented in `tests/PHASE1_FINDINGS.md`. Default-deny closes the *unknown-tool* threat, not the *known-tool-with-evasive-params* threat. The secure form is a *positive* "allow only provably-safe SQL" rule requiring a real SQL parser, and it is explicitly deferred. We accept this because 2a's job is the *framework* — declarative packs, default-deny, per-parameter constraints, and the road to trajectory — not SQL parsing. The default pack's rationale fields say this in-band so no reviewer mistakes the keyword rule for real SQL safety.

2. **One new dependency: `pyyaml`.** It is the cost of declarative, reviewable policy in a format humans and the dashboard both read. We bound the risk: `yaml.safe_load` only (no arbitrary object construction), strict fail-closed validation over the parsed dict (no unknown field, operator, or effect survives), and YAML confined to `loader.py` at startup — never in the decision path. The lean-dependency principle (CLAUDE.md) is honored: one dependency, tightly scoped, with the dangerous half of the library (`yaml.load`) forbidden.

3. **Existing tests change deliberately.** `rule_id` assertions move from `phase1.*` to pack ids, and un-named tools flip ALLOW→DENY. This is the spec changing, not the tests weakening; red-team re-pins the assertions and keeps every non-execution, determinism, ordering, and invariant-1 proof green (§e).

4. **`configure` is global, run-scoped state.** The active pack lives at module level in `core/gateway.py`. WHY acceptable: it is set once at startup and immutable for the run, so it carries no per-call nondeterminism; it is the policy equivalent of the audit log path. The cost is that two concurrent runs in one process would share one pack — out of scope now (the loop is single-run), and the seam to make the pack per-run is a localized change to the adapter, not the engine.

## Out of scope

- `RATE_LIMIT` and `REQUIRE_APPROVAL` enforcement flows, and their effect values in the schema (2a validation refuses them; widening is backward-compatible later).
- A real SQL parser / positive "allow only safe SQL" rule — the SQL evasions stay documented-open.
- Trajectory awareness *implementation* (2b is sketched here, built next), and the schema shape for trajectory `when` clauses.
- Any time-based / rate-based rule — deliberately excluded to keep the clock out of the decision path (a precondition for 2b's determinism story).
- Tool-name globbing / regex matching in `tool` or operators — exact match and regex-free operators only.
- Pack hot-reload, multiple concurrent packs, per-run pack isolation — `configure` once at startup, immutable for the run.
- Hash-chaining of the audit log (Phase 3); the `rule` field carrying pack ids composes with it but does not depend on it.

## Standing non-determinism check on the proposed enforcement path

Walked the path an action takes through 2a, looking for any leak:

- **LLM in the decision?** No. The engine is declarative data + a pure matcher. The model proposes the tool call; it never decides. Rationale text is author-written and never evaluated.
- **YAML loading / parsing in the path?** No. `yaml.safe_load` and all file I/O are confined to `loader.py` and run only at startup (`configure`), structurally outside `evaluate`/`decide`. `safe_load` cannot construct code.
- **Dict / list iteration order?** Safe. Rules are a parsed YAML *sequence* → a Python list, iterated in insertion (file) order; first-match-wins reads that order. `when` is a small dict, but constraints are conjunctive (all must hold), so dict iteration order does not change the outcome — only short-circuit *timing*, never the decision.
- **Regex?** None in the decision path. The operator set is arithmetic (`max`/`min`), membership (`one_of`, `domain_in`, `contains_keyword`), and string prefix/split (`prefix_one_of`, the keyword tokenizer). The keyword normalizer reuses ADR 0001's `re.sub(r"\s+", " ", ...)` — a fixed, non-backtracking whitespace collapse, the same one already proven deterministic in Phase 1; no user/pack-supplied pattern ever reaches a regex engine.
- **Randomness?** None in `decide` or `evaluate`.
- **Wall-clock?** None in the decision path. `ts` is still stamped only by `append_record`, after the decision (ADR 0001 §4 / ADR 0002). 2b is sequence-aware, never time-aware — by design, to keep it that way.
- **Network / I/O the decision waits on?** None. `decide` is local, synchronous, in-memory. The write-ahead audit append is I/O, but it runs *after* `evaluate` and does not feed back into it (ADR 0002).
- **Missing-param behavior?** Total and pinned: constraint-on-missing-param does-not-hold → rule-does-not-match → fallthrough → default-deny. No `KeyError`, no exception, no implicit-truthiness ambiguity, no branch that varies with anything but the inputs.
- **The `context` handle (2a)?** Carries no nondeterminism — 2a does not read it (it stays the unread session handle from ADR 0001 §1a). In 2b it carries prior *recorded concrete actions*, never model text, never a clock — see the 2b determinism story.
- **The configured pack?** Set once at startup, immutable for the run → no per-call variance.

**Result: no nondeterminism leaks into the enforcement path in this design.** The one new dependency (`pyyaml`) touches only load-time, with `safe_load` and strict fail-closed validation; the decision path stays a pure, regex-free, clock-free, network-free function of `(pack, tool, params)`.
