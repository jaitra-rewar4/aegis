# 0004 — Trajectory awareness: the read→send exfiltration catch (Phase 2, slice 2b)

- Status: Accepted
- Date: 2026-06-09 (accepted 2026-06-12 with three review decisions: `after` matches ALLOW-only records — confirmed; `after` shape is `{tool: <string>}` only — confirmed; `run_loop`'s dead caller-facing `context=` parameter is REMOVED, not kept as a vestige)
- Deciders: architect (policy-engineer implements the `after` clause + `domain_not_in`; gateway-engineer wires the trajectory through the adapter and the loop; red-team proves the before/after pair)
- Supersedes: — (builds directly on ADR 0003's "Slice 2b — sketch only" section; must not contradict it; composes with the write-ahead ordering of ADR 0002)

## Problem

ADR 0003 shipped slice 2a: a stateless, pure decision function `decide(pack, tool, params)`. Every decision is judged in isolation — the engine sees the current tool and its current parameters and nothing else. That is exactly enough to catch a destructive *single* action (a `DROP TABLE`), and exactly not enough to catch a *chained* one.

The chain we now have to catch is the canonical exfiltration pattern ADR 0003 §2b named and ADR 0001 §3 deliberately set up: an agent **reads sensitive data** (`lookup_customer`, the sensitive read — already a demo tool) and then **egresses it** (`send_email` to an outside address — the "send" half, arriving now). Neither action is dangerous *alone*. A `lookup_customer` is a benign read. A `send_email` to a partner is benign business correspondence. The danger is in the *sequence*: read-then-send-outside is the shape of data leaving the building. A stateless 2a pack cannot see it, because at the moment it judges the `send_email` it has no memory that a sensitive read just happened — the two facts never meet in one decision.

Why now: 2a is the framework; 2b is the first decision that *requires* the framework's reserved seam — the `context` handle ADR 0001 §1a stabilized and ADR 0003 §2b pinned as "the recorded trajectory, threaded through context." This ADR pins the design that turns that seam into a working rule, without smuggling a clock, an LLM, or a second source of truth into the enforcement path. Nothing is built here; the user reviews this ADR before the policy-engineer and gateway-engineer touch code.

## Decisions

These record and justify the user-pinned decisions; the two open calls left to the architect — (a) ALLOW-only filtering, (b) the `after` schema shape — are made and defended below. The deltas are named file by file but described, not implemented.

### a) The demo tool — `send_email(to, subject, body)`, fake

A new demo tool in `demos/tools.py`: `send_email(to, subject, body)` that **returns a success string and does nothing else** — no socket, no SMTP, no network of any kind, ever. WHY fake: the demo must prove the *gate's* behavior on a read→send chain, not exercise real egress; a real sender would add a network dependency to the demo and a way to actually leak the fake customer data. The tool is the "send" half of the chain; `lookup_customer` (ADR 0001 §3) is the "read sensitive" half. It joins `TOOL_REGISTRY` and `TOOL_SCHEMAS` alongside the existing three. `subject` and `body` are accepted and passed through but **never inspected** by any rule (see Honest scope).

Target scenario: `lookup_customer` (ALLOWed sensitive read) followed by `send_email` to a non-allowlisted address → **DENY**.

### b) The trajectory model — the loop's live `audit_trail`, threaded through `context`

The trajectory is the loop's existing `audit_trail: list[dict]` (core/loop.py) — an in-memory, per-run, **ordered** list of the write-ahead audit records, threaded into `gateway.evaluate` through the `context` argument it already accepts and ignores today. It is **not** a separate session object. It resets every run because `audit_trail` is a fresh local list each `run_loop` call.

What it holds: prior **concrete** tool calls — `{tool, params, decision, rule, ...}` — because the records *are* the audit records (`append_record(...)` builds them from `tool`, `params`, `result.decision.value`, `result.rule_id`). It never holds model text and never holds tool outputs (invariant 1; the record shape carries no output field — ADR 0002 §Consequences 2 froze that). This is ADR 0003 §2b Decision 1 honored exactly: "what the engine sees as history" and "what is durably recorded as having happened" are the same object — one list, the logged one, no second source of truth to drift.

**The elegant ordering property, called out explicitly.** In core/loop.py the order per tool_use block is: `evaluate(...)` → `append_record(...)` → `audit_trail.append(record)`. The current action's record is appended to `audit_trail` *after* `evaluate` has already returned. So at the instant `evaluate` runs for action *N*, `audit_trail` contains records for actions *1..N-1* only — strictly **earlier** actions. **The current proposal never sees itself.** This falls out of the write-ahead ordering ADR 0002 pinned for an entirely different reason (no executed action goes unlogged), and we get the "trajectory = strictly-earlier actions" guarantee for free, structurally, with no special-casing in the engine. No "skip the last record," no index arithmetic, no risk of a rule matching the very call it is judging.

### c) The engine signature — `decide` gains an additive `trajectory` parameter

`engine.decide` becomes `decide(pack, tool, params, trajectory=None)` — purely **additive**. WHY additive with a `None` default: ADR 0003's determinism tests and the whole 2a suite call `decide(pack, tool, params)`; an optional trailing parameter leaves every existing call site and every existing decision byte-for-byte identical. The hard requirement: **an empty/None trajectory must reproduce 2a behavior exactly**, so all 270 existing tests pass unchanged. This is enforced structurally — the trajectory is only ever read by the new `after` clause (decision e); a pack with no `after` clause never touches it, and `None`/`[]` makes every `after` clause not-hold (decision e), so a 2a pack decides identically whether `trajectory` is `None`, `[]`, or a full history.

### d) The gateway adapter and the loop — extraction semantics, pinned totally

**Adapter (`core/gateway.py`).** `evaluate(tool, params, context)` keeps its byte-for-byte three-argument signature (ADR 0001 §1a — the loop's call site does not change). It stops ignoring `context` and instead **extracts the trajectory from it** with one totally-pinned branch, then threads it into `decide`:

- `context` **is a `list`** → it **is** the trajectory; pass it as `decide(..., trajectory=context)`.
- `context` is **anything else** — `None`, a `str`, an `int`, an arbitrary object → `trajectory=None` → exact 2a behavior.

WHY this exact, total branch and no other: the 2a determinism tests throw seven non-list context values at `evaluate` (None, str, int, float, an object, etc.) and assert identical behavior. A single `isinstance(context, list)` check is total over every possible Python value — list goes one way, everything else goes the other — with no `KeyError`, no attribute lookup that could raise, no type the branch fails to classify. It is the trajectory-input analogue of the missing-param chokepoint: one predicate, total, obvious, fail-toward-2a. A reviewer reads one line and predicts the trajectory for any context value.

**Loop (`core/loop.py`).** `run_loop` now **owns the trajectory and threads it**: at each tool_use block it passes its live `audit_trail` list as the `context` argument to `evaluate` (replacing today's pass-through of the caller-supplied `context`).

WHY this is reconcilable with "270 existing tests pass UNCHANGED," named precisely:
- **No existing pack rule has an `after` clause.** Every 2a rule decides on `(tool, params)` only. So even though the loop now hands `evaluate` a *real, growing* list instead of the caller's `context`, the engine never reads it for any existing rule — every existing decision is identical, action for action, id for id.
- **The caller-facing `context` parameter on `run_loop`.** Pinned: the loop owns the trajectory, so `run_loop`'s `context=None` parameter is **retired from the evaluate call path** — the loop no longer forwards it to `evaluate`; it forwards its own `audit_trail`. The reviewer must verify (and red-team must assert) that **nothing in the existing tests asserts the literal context value that reaches `evaluate` via the loop** — 2a never read context, so no 2a test can depend on its identity; this is a safe change precisely because 2a made `context` inert. Whether the `run_loop(context=...)` keyword is removed outright or kept as an accepted-but-now-unused vestige is an implementation nicety for the gateway-engineer; the load-bearing decision is that **the value `evaluate` sees is the loop's `audit_trail`, not the caller's handle.** The architect leans toward removing the dead `run_loop` parameter so there is no second, ignored handle to confuse a reader — one owner, one trajectory.

### e) The new `after:` rule clause — matches the trajectory

A new **optional** rule clause: `after: {tool: <non-empty string>}`. `after: {tool: lookup_customer}` means **the rule applies only if a `lookup_customer` call appears earlier in the run's recorded trajectory.** It is **conjunctive** with `tool` and `when`: a rule fires only if the current tool matches **and** `after` holds **and** every `when` constraint holds. A missing/empty/`None` trajectory → `after` **does-not-hold** → the rule does not match — the same fail-safe direction as a missing param (ADR 0003 §c totality): when there is nothing to match against, the predicate is honestly `False`, and default-deny converts not-matching into the safe outcome.

**Open call (a) — does `after` match only prior records with decision `ALLOW`, or any record? Pinned: ALLOW only.**

`after: {tool: lookup_customer}` holds iff the trajectory contains a record with `tool == "lookup_customer"` **and** `decision == "ALLOW"`. WHY ALLOW-only, thought through:

- **A DENYed read never executed, so no data was read.** ADR 0002's write-ahead ordering means a DENY record exists for an action that was *refused* — the tool function was never called (execution is reachable only through the `Decision.ALLOW` branch). If `after` matched *any* record including DENYs, the exfil rule would fire on a `lookup_customer` that **never actually read anything** — blocking a later send because of a read that was itself blocked. That is the rule firing on a ghost: punishing the agent for data it was prevented from reading.
- **The taint must track real reads, not proposed ones.** The threat model is "sensitive data was read, now it might leave." Data is read only on an executed (ALLOWed) read. Matching denied proposals would untether the rule from the actual data-access event it exists to guard.
- **Consistency with the strictly-earlier property (decision b):** the trajectory already excludes the current proposal; ALLOW-only further restricts it to *prior actions that actually happened*. The rule reasons over the recorded history of **executed** sensitive reads — concrete, logged, real.

So `after` matches: a prior record whose `tool` equals the named tool **and** whose `decision` is `ALLOW`. This is a pure list scan over recorded fields — no clock, no output, no text.

**Totality over arbitrary trajectory contents (review-added build requirement).** The `after` scan must be total over whatever the list actually contains: a record missing the `tool` or `decision` field, a non-dict entry (string, int, None, arbitrary object), or any other junk **does not match and does not crash**. Field access uses `.get(...)` with a safe default (never `record["tool"]` / attribute access directly); a non-dict entry is classified as not-a-match before any field access. WHY: `evaluate`'s `context` is an externally-reachable input — a caller can hand it any list — and the gate must never be crashable from its inputs (a crash in `evaluate` is a denial-of-decision, and worse, an exception path nobody reasoned about). Junk entries fail toward not-matching, the same direction as every other totality rule in this design. Red-team probes this explicitly with malformed/junk trajectories.

**Open call (b) — the `after` schema shape in 2b: exactly `{tool: <non-empty string>}`, nothing else. Pinned.**

In 2b, `after` is a single-key mapping `{tool: <non-empty string>}`. **Out of scope inside `after`, deliberately** (noted as future extensions, not built): param constraints inside `after` (e.g. "after a `lookup_customer` *with customer_id C001*"), multiple tools, counts/thresholds ("after 3 reads"), ordering between multiple priors, and any negative form ("after *no* read"). WHY start at exactly one tool-identity key: it is the minimal shape that expresses the read→send pattern, it is **total** (a list scan for a tool name + ALLOW is defined for every trajectory including the empty one), and it is **obvious** (a non-author reads `after: {tool: lookup_customer}` and predicts "this rule only fires once a lookup_customer was allowed earlier"). Widening later is backward-compatible; narrowing is not — so we start narrow, exactly as 2a did with effects (ADR 0003 §Out of scope).

**Schema validation (`policy/schema.py`), fail-closed, unchanged mandate.** `after` joins `_ALLOWED_RULE_KEYS`. A new `_normalize_after` (mirroring `_normalize_when`) validates that `after`, when present, is a dict with exactly the one key `tool` whose value is a non-empty string; **any other shape rejects the whole pack** — unknown keys inside `after`, a non-string `tool`, a multi-key `after`, an empty string, a wrong type. This is the 2a all-or-nothing fail-closed mandate (ADR 0003 §c) applied unchanged: the pack either *is* the spec or there is no spec (default-deny). The frozen `Rule` dataclass gains an `after` field, kept deeply immutable like `when`.

### f) The new operator `domain_not_in` — the negation of `domain_in`

A new `when` operator `domain_not_in`, the negation of the existing `domain_in`, implemented following the **exact** pattern of `not_contains_keyword`. It is evaluated **only after the missing-param chokepoint** in `_constraint_holds` — so totality holds and the negation trap from 2a is already structurally closed: a missing `to` param returns `False` at the chokepoint *before* `domain_not_in` ever runs, so a missing recipient does **not** satisfy `domain_not_in`. Said plainly: the chokepoint that made `not_contains_keyword` safe makes `domain_not_in` safe by the identical mechanism — no new trap is opened.

Semantics: `domain_not_in` holds iff the param **is a string with exactly one `@` AND its domain (case-insensitive) is NOT in the list.** It reuses `_op_domain_in`'s exact parsing discipline (one `@`, split on the `@`, lowercase the domain).

**Malformed-address case, pinned explicitly:** `"a@b@evil.com"` (two `@`), `"no-at-sign"` (zero `@`), `""`, or a non-string → `domain_not_in` does **NOT** hold. WHY fail toward not-matching: `domain_not_in` is "a string whose *parseable domain* is outside the list." A malformed address has **no parseable domain**, so it is not such a string — the honest answer is `False`, not "well, its (nonexistent) domain isn't in the list, so true." This is the same fail-safe direction as totality everywhere else: when the predicate has nothing well-formed to be true about, it does-not-hold. Critically, this is **not** a hole in the exfil DENY rule, because that rule sits under default-deny: a malformed `to` makes the DENY rule not-match *and* makes the ALLOW rule below it not-match (its `domain_in` also requires a parseable domain), so the call falls through to `default: deny`. A garbage recipient is denied — by the floor, not by the operator pretending to understand it.

Schema: `domain_not_in` joins `_STRING_LIST_OPERATORS` — operand is a non-empty list of strings, validated identically to `domain_in`, any wrong type rejects the whole pack.

### g) Determinism — sequence, never time (invariant 2)

The `after` match is **pure sequence/membership** over the recorded list: "does a record with this tool and decision ALLOW exist earlier in `audit_trail`." It is **never time-based**. No wall-clock read, no "within N minutes," no `ts` comparison. Time-based rules stay out of scope precisely to keep the clock out of the decision path (ADR 0003 §2b Decision 2 / §Out of scope, extended here). The decision is deterministic given `(pack, tool, params, recorded trajectory)`: same four inputs → same `GatewayResult`, every time. Adding `trajectory` as a fourth **data** input adds no nondeterminism — it is input data exactly like `params`; reading a clock or an LLM would add nondeterminism, and we do neither.

## The default pack delta and the proof-of-worth ordering

The default pack (`policy/packs/default.yaml`) gains `send_email` rules, in **first-match-wins** order (ADR 0003 §d), placed so the trajectory rule wins:

1. **Exfil DENY** — `tool: send_email`, `after: {tool: lookup_customer}`, `when: {to: {domain_not_in: [internal.example.com]}}`, `effect: DENY`. Placed **first** among the `send_email` rules so it wins when it matches. Rationale states: blocks egress to a non-internal recipient once a sensitive customer read was ALLOWed earlier in this run — the read→send exfiltration chain, caught at the action layer.
2. **Send ALLOW** — `tool: send_email`, `when: {to: {domain_in: [internal.example.com, partner.example.com]}}`, `effect: ALLOW`. Reached only when rule 1 did not match. Allows sends to known-good internal and partner domains.
3. Everything else `send_email` (and every unnamed recipient) falls to `default: deny`.

**Proof of worth — the same call, two histories, two decisions.** A `send_email` to `partner.example.com`:

- **No `lookup_customer` earlier in the run** → exfil DENY's `after` does-not-hold → rule 1 does not match → falls to rule 2's `domain_in` ALLOW (partner is allowlisted) → **ALLOW**.
- **A `lookup_customer` was ALLOWed earlier in the run** → exfil DENY's `after` holds; `partner.example.com` is not `internal.example.com`, so `domain_not_in` holds; tool matches → rule 1 fires first → **DENY**.

Identical tool, identical params, **different recorded history → different decision.** That is trajectory awareness observable inside a single run — a DENY a stateless 2a pack would have ALLOWed (2a has no rule 1 because it cannot express `after`; the send to a partner would simply hit the `domain_in` ALLOW). This is the explicit bar: the trajectory rule denies a send that the stateless pack permits, and it is *not* something default-deny already caught (partner.example.com is allowlisted; default-deny lets it through). The hostile demo (`demos/run_hostile.py`, or a sibling exfil demo) shows the **before/after pair** in one run: a partner-send ALLOWed early, a `lookup_customer` ALLOWed, then the *same* partner-send DENYed — the chain catching the leak, deterministically, on the recorded sequence of concrete calls.

## How the invariants hold

**Invariant 1 (tool-call boundary, not model text).** Held and reinforced. The added input is the trajectory, and the trajectory is a list of **recorded audit records** — `{tool, params, decision, rule}` — i.e. prior **concrete tool calls and their decisions**. It is never model text and never tool outputs: the record shape carries no output field (ADR 0002 froze the record to decision-only), and `send_email`'s `subject`/`body` and every prior tool's *result* never enter any decision. The loop still routes only `tool_use` blocks to `evaluate`; text blocks are still ignored. The `after` clause reasons over "did a `lookup_customer` *action* get ALLOWed earlier," never over anything the model *said*. Rationale fields stay author-written policy data, never evaluated.

**Invariant 2 (deterministic gate).** Held. `decide(pack, tool, params, trajectory)` is a pure function of four **data** inputs — no LLM, no `random`, no clock, no network, no I/O. The `after` match is membership over a recorded, in-memory list; the operator set stays arithmetic/membership/prefix/split (now plus one more pure membership negation, `domain_not_in`) — still regex-free in the decision path. The pack is fixed for the run (ADR 0003 §b), the trajectory is the loop's own in-memory list, and the **strictly-earlier-actions property** (decision b) means the current proposal never sees itself, so there is no self-referential or order-of-evaluation ambiguity. Same `(pack, tool, params, trajectory)` → same decision, every time.

## Honest scope / Consequences

Named plainly so they can be defended out loud:

1. **2b keys on the read→send TOOL-IDENTITY pattern, not on data provenance.** The rule fires because a `lookup_customer` was ALLOWed earlier *and* a non-internal `send_email` is now proposed — **not** because the data in the send's `body` actually came from that read. `send_email`'s body content provenance is **not** tracked. A send whose body contains nothing from the read still gets DENYed (over-block); a send that launders read data through a benign-looking body is caught only because the *read happened*, not because of what it carries.
2. **Laundering through an intermediate tool is not modeled.** read → `calculator`/transform → `send` defeats nothing here *unless* such a tool is itself named in an `after` clause. 2b models the two-step read→send shape, not arbitrary multi-hop dataflow. Closing this is data-flow tracking — explicitly future, not 2b.
3. **The trajectory resets per run.** No cross-run or cross-session persistence; `session_id` stays a reserved null (ADR 0001 §4 / ADR 0002 record shape). A read in run A does not taint a send in run B. Per-run is the honest boundary because the in-memory `audit_trail` is the trajectory and it is born fresh each `run_loop`.
4. **`subject`/`body` are not content-inspected.** No rule reads them; they ride along in `params` and the audit record but never enter a decision. (Content inspection of model-produced text is also exactly the kind of thing invariant 1 keeps out of the gate.)
5. **One ALLOWed read taints ALL subsequent non-internal sends for the rest of the run — coarse by design.** There is no per-customer scoping, no "this send is unrelated to that read," no decay. Once any `lookup_customer` is ALLOWed, every later send to a non-internal domain is DENYed until the run ends. This **over-blocks**, and over-blocking is the fail-safe direction for a least-privilege gateway: a false DENY costs a refused benign send; a false ALLOW costs a leak. We choose the cheaper failure, state it out loud, and leave per-read scoping to a future `after` with param constraints (decision e, out of scope).

## Out of scope

- **Param constraints inside `after`** (e.g. `after: {tool: lookup_customer, when: {customer_id: ...}}`) — future extension; 2b's `after` is tool-identity only.
- **Multiple tools, counts, thresholds, or ordering between priors in `after`** — single tool key only.
- **Time-windowed / rate-based `after`** ("within N minutes/seconds") — deliberately excluded to keep the clock out of the decision path; 2b is sequence-aware, never time-aware.
- **Data-flow / provenance tracking** — whether sent bytes actually originated from the read; tool-identity pattern only.
- **Cross-run / session persistence** — `session_id` stays a reserved null; trajectory is per-run.
- **`RATE_LIMIT` / `REQUIRE_APPROVAL` flows** — still out of scope (ADR 0003); 2b adds only `DENY`/`ALLOW` decisions and one operator.
- **Content inspection of `subject`/`body` or any model-produced text** — out by invariant 1.

## Standing non-determinism check on the proposed enforcement-path change

Walked the four new things this design puts in (or near) the decision path, looking for any leak:

- **The trajectory input (the fourth `decide` argument).** Data, not behavior. It is the loop's in-memory `audit_trail` list of recorded concrete actions — no clock, no text, no output, no network. Adding a data input is exactly like adding `params`; it adds no nondeterminism. The strictly-earlier-actions property (the loop appends the current record *after* `evaluate` returns) means the input for action *N* is deterministically actions *1..N-1* — no self-reference, no order ambiguity. **No leak.**
- **The extraction branch in the adapter (`isinstance(context, list)`).** Total over every Python value: list → trajectory, everything else → `None` → exact 2a. One predicate, no attribute access that can raise, no `KeyError`, no type it fails to classify. Deterministic and obvious. **No leak.**
- **List iteration over records (the `after` scan, ALLOW-only filter).** A membership scan over an insertion-ordered Python list for `(tool == name and decision == "ALLOW")`. Insertion order is stable; the predicate is pure field equality; first-match short-circuits without changing the result (existence is order-independent). No regex, no scoring, no hashing-dependent tie-break. **No leak.**
- **The ALLOW-only filter itself.** Reads the recorded `decision` field — a value the engine itself produced earlier and the loop durably logged (ADR 0002). It is a recorded fact, not a re-evaluation; no clock, no second decision, no feedback from tool output. **No leak.**
- **`domain_not_in`.** Pure string parse (one `@`, lowercase, membership negation), gated behind the missing-param chokepoint, total on missing/malformed/wrong-typed input, regex-free. The negation trap is already structurally closed by `_constraint_holds` returning `False` before the operator runs. **No leak.**
- **Schema validation of `after` / the new operator.** Runs at load time in `schema.py` (no I/O, no YAML), structurally outside `evaluate`/`decide`, fail-closed all-or-nothing. **No leak into the decision path.**

**Result: no nondeterminism leaks into the enforcement path in this design.** The decision stays a pure, regex-free, clock-free, network-free function of `(pack, tool, params, recorded trajectory)`; the trajectory is concrete recorded actions only (invariant 1); and the strictly-earlier-actions ordering — inherited for free from ADR 0002's write-ahead — guarantees the proposal never judges itself.
