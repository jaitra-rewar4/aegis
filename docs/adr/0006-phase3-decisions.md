# 0006 — Phase 3: RATE_LIMIT, REQUIRE_APPROVAL, the approval HTTP surface, and the real-audit dashboard

- Status: Accepted
- Date: 2026-06-17
- Deciders: architect (owner); policy-engineer (engine/schema), gateway-engineer (runtime, audit, hash chain), frontend-engineer (dashboard); red-team + reviewer gate each slice.
- Supersedes: — (composes with ADR 0002 write-ahead audit, ADR 0003 pure engine, ADR 0004 trajectory, ADR 0005 MCP transport).

## Problem

Two of the four `Decision` values are vocabulary without behaviour. `RATE_LIMIT` and `REQUIRE_APPROVAL` exist in `core/decision.py`, but the schema rejects them at load (`schema.py`), the engine collapses every non-ALLOW effect to `DENY` (`engine.py`), and the loop treats DENY / RATE_LIMIT / REQUIRE_APPROVAL identically as a blunt non-execution refusal (`loop.py`). Aegis cannot yet express "allowed but only N times" or "allowed only with a human's sign-off." CLAUDE.md names all four decisions as the product; today we ship two.

Making the remaining two real forces the first HTTP surface (a human must approve/deny out-of-band) and the first real binding of the dashboard to the audit log (today `web/src/components/audit-log.tsx` is a hardcoded visual mock). The decision being made: **how to add RATE_LIMIT and REQUIRE_APPROVAL without putting a clock, a network wait, or a human's judgment into the deterministic decision path** — and how to add an HTTP layer that records a human's verdict without ever letting that layer (or the human) re-judge policy.

The hard constraint is the two invariants. RATE_LIMIT is the dangerous one: the obvious implementation ("max 5 per minute") reads a wall clock inside the decision, which is invariant 2 leaking. REQUIRE_APPROVAL is dangerous differently: the obvious implementation blocks the loop on a network round-trip, and the temptation is to let the approval UI "look at what the agent said" — both threaten the invariants if done naively.

## Decisions

### a. RATE_LIMIT is COUNT-over-trajectory, never time-over-clock. (invariant 2)

A rate limit fires when the **count of prior ALLOWed records for a tool in the recorded trajectory** crosses a declared threshold. It is a pure list-scan over the same trajectory `_after_holds` already scans — the same data input as `params`, never a clock.

WHY not time-based: "N per minute" requires `now()` inside `decide`. That is a clock in the enforcement path — a non-author can no longer predict the decision from `(pack, tool, params, trajectory)` alone, because the same inputs decide differently at 11:59 vs 12:00. ADR 0004 §g already forbade `ts` comparisons in the gate for exactly this reason. A count over the recorded sequence is total, replayable, predictable. WHY a count is still a real limit: the trajectory is the sequence of actions this agent has taken; "no more than 5 ALLOWed `wire_transfer` calls in this run" is a genuine least-privilege bound on what the agent can DO, expressed on actions, not seconds.

**Schema — a new `count` clause, parallel to `after`.** A new optional rule key `count`, validated to exactly the shape `{tool: <non-empty string>, max: <non-negative int>}`:

```yaml
- id: cap_refunds
  rationale: "An agent may issue at most 3 refunds per run; the 4th needs review."
  tool: issue_refund
  effect: RATE_LIMIT
  count: { tool: issue_refund, max: 3 }
```

WHY a distinct `count` clause and not an overload of `after`: `after` answers a boolean ("did an ALLOWed X happen earlier?"); `count` answers an arithmetic threshold ("how many, and is that ≥ max?"). Keeping them separate keeps each clause single-purpose and readable. WHY `tool` is named explicitly inside `count` rather than implicitly "this rule's tool": it lets a rule count a *different* tool than the one it gates (e.g. REQUIRE_APPROVAL on `export_data` once `read_customer` has been ALLOWed 10 times) without a schema change later, and it mirrors the `after: {tool: ...}` shape a reader already knows. WHY `max` is the threshold name: it reuses the operator vocabulary the author already learned, and the semantics are "fires when prior count ≥ max" (pinned below).

**Engine — a pure scan in the `_after_holds` style.** `_count_holds(count_clause, trajectory) -> bool` counts entries where `isinstance(entry, dict) and entry.get("tool") == count_tool and entry.get("decision") == "ALLOW"`, and returns `count >= max`. It is conjunctive with `tool`, `after`, and `when` in `_rule_matches`. The effect-mapping in `decide` widens from a binary ALLOW/DENY to a total mapping from the validated effect string to its `Decision`.

**Totality / junk-trajectory rules (same fail-direction as every existing operator):**
- `count is None` (no clause) → vacuously True, **without reading the trajectory** — identical discipline to `after is None`, so a pack with no `count` rule is byte-for-byte 2a/2b.
- trajectory `None`/empty → count is 0. With `max: 0` the threshold `0 >= 0` holds and the rule fires immediately; with `max >= 1` it does not. `max: 0` is allowed and pinned (rate-limited from the first call, fully predictable).
- non-dict / wrong-typed entries → not counted (isinstance gate first, `.get` with safe defaults), exactly as `_after_holds` does — total over whatever the list contains, never crashable from inputs.

**Precedence — first-match-wins, unchanged.** A RATE_LIMIT rule sits in the ordered rule list like any other; the author controls cap-vs-allow ordering by rule order. **Self-counting boundary, pinned:** the loop appends the current action's record *after* `evaluate` returns, so the trajectory at decision time holds strictly-earlier actions only. So `max: 3` means the 4th call is the one that trips RATE_LIMIT (3 prior ALLOWed + this one). This falls out of write-ahead ordering for free, exactly as the `after` self-exclusion does — no index arithmetic.

**Standing non-determinism check (RATE_LIMIT):** the clause reads `trajectory` and a literal `max` integer. It touches no clock, no `now()`, no `ts` field, no random, no I/O. Confirmed at review by reading `engine.py`'s imports (still `re` only) and grepping the new function for `time`/`datetime`/`now`/`ts`/`random` — all absent. The verdict is a pure function of `(pack, tool, params, trajectory)`.

### b. The effect→Decision mapping becomes total; the loop distinguishes the four verdicts.

The engine's effect→Decision step becomes a total lookup from the validated effect string to its `Decision` member (all four effects now valid at load), with a fail-safe DENY default for an unreachable unknown. WHY a mapping not an if-ladder: it is exhaustive by construction and a reviewer reads one table.

The loop's `else` branch splits. ALLOW executes (unchanged). DENY refuses (unchanged). RATE_LIMIT refuses-this-call with a *distinct* message (a refusal of *this* attempt, not a permanent policy DENY — the message must not lie about which). REQUIRE_APPROVAL enters the hold flow (§c). The single execute gate `is Decision.ALLOW` stays the only path to execution: every new verdict is a refusal-or-hold, never a second execute path.

### c. REQUIRE_APPROVAL: the GATE is pure; the HOLD is runtime. (the invariant-2 distinction)

Split the concept in two and never let them blur:

- **The decision** "this action requires approval" is computed by `decide` from `(pack, tool, params, trajectory)` — pure, deterministic, no human, no clock. Identical in kind to DENY: a rule fired, the engine named it. Invariant 2 untouched.
- **The hold** — pausing the action until a human approves or denies — is *runtime orchestration*, downstream of and outside the decision function. A human's later approve/deny does NOT feed back into `decide`; it gates only whether the runtime *executes* the already-judged action. Non-determinism (a human, a clock, a network wait) is quarantined to the runtime, where `append_record` already stamps a wall-clock `ts` without threatening invariant 2 because it is downstream of the decision.

The rule, stated out loud: **the gate decides; the human authorizes; neither is the other.** The human can only turn an engine-REQUIRE_APPROVAL into an executed or refused action — never a DENY into an ALLOW, and is never consulted for any verdict other than REQUIRE_APPROVAL. Same monotonicity the audit-outage path already has: an out-of-band signal can only refuse-or-permit an already-judged action, never re-judge.

**Hold model — deferred, not synchronous (chosen).** On REQUIRE_APPROVAL the loop does NOT execute: it writes the audit record with `decision=REQUIRE_APPROVAL`, enqueues a pending action, and returns a "held, not executed — pending approval id=…" tool_result to the model immediately. The human resolves it out-of-band via the API; resolution is a *separate, later* audit record carrying the approver. WHY deferred over a synchronous block: a block puts an unbounded human-reaction wait inside the agent turn, makes the loop un-runnable headless (no human ⇒ hang), and tempts a "show the approver the transcript" UI — the slippery slope toward gating on model text. Deferred keeps the synchronous loop synchronous and clock-free in its control flow, and makes the hold a *record*, not a *wait*, matching Aegis's spine: the audit log is the source of truth, so "pending" and "resolved" are just records.

**Pending-action store.** Pending actions keyed by a `pending_id`, each `{pending_id, tool, params, rule_id, requested_ts, status, approver, resolved_ts}`. Backed by the audit trail as the spine, not a parallel database of record: the request is an audit record (`decision=REQUIRE_APPROVAL`); the resolution is a *later* audit record (`decision=ALLOW` or `DENY`, `approver=<identity>`, naming the same `pending_id` and originating `rule_id`). The pending store is a *materialized view* over those records, rebuildable from the log, never the authority. (Derived-on-read from the JSONL for this build; an index can come later if `GET /pending` gets slow.)

**Approver identity via the already-plumbed kwarg.** The resolution record is written through `append_record(approver=<identity>, …)` — the kwarg already exists and threads to the `approver` field, today always None. The API records *who* approved; it never decides *whether* policy allows.

**FastAPI endpoints (the first HTTP surface):**
- `GET /pending` — list pending actions (from the materialized view).
- `POST /pending/{id}/approve` — body carries approver identity; writes the resolution audit record with `approver`, marks the action approved (executable on resume).
- `POST /pending/{id}/deny` — writes a DENY resolution record with `approver`; never executed.
- `GET /audit` — searchable read-only view over the audit trail for the dashboard.

WHY the FastAPI layer is NOT a second decision-maker (load-bearing): these endpoints contain no policy logic. Approve/deny records a *human's* verdict on an action the engine *already* tagged REQUIRE_APPROVAL; the endpoint never calls `decide`, never re-judges, never inspects model text or the conversation — it sees only the concrete `{tool, params}` of the held action. An approve cannot manufacture an ALLOW for an action the engine DENYed (only REQUIRE_APPROVAL actions are ever in the pending store). One decider (the engine); one authorizer (the human, only on REQUIRE_APPROVAL); they never trade places.

**On approve — execute on resume, not in the API.** Approval marks the action; execution still happens in exactly one place — the loop, on a re-run/resume. WHY: keeping a single execution site means there is never a second place that runs governed actions to guard. In-API execution is a deliberate later decision, not smuggled in here.

### d. Hash-chained tamper-evident audit log (the reserved `prev_hash`/`hash`).

Populate the reserved `prev_hash`/`hash` fields with a SHA-256 chain over the canonical record. WHY now: Phase 3 makes the audit trail the authority for approvals — "who approved this" is only trustworthy if the record cannot be silently altered. WHY it does not threaten invariant 2: hashing happens in `append_record`, *after* the decision, on the way to disk — same downstream position as `ts`. The hash is never an input to `decide`. Canonicalization is deterministic (stable key order, fixed separators); a chain-verify reader detects a break at exactly the altered record.

**Honest limits of the chain (integrity, not authenticity).** The chain is tamper-EVIDENCE of existing history: altering any past record breaks the chain from that record onward, and `verify_chain` reports the first broken index. It is NOT authentication. With no signing key, an adversary who can WRITE the log can still (a) append a new, self-consistent record (correct `prev_hash` + recomputed `hash`) that verifies, (b) rewrite the entire file as a fresh self-consistent chain, or (c) truncate the tail undetectably. Defending those needs writer authentication (a signing key, or an append-only OS ACL / WORM store) and an external length/most-recent-hash witness — explicitly out of scope for this phase. What the chain buys today: an append-only writer cannot quietly edit what it already wrote, and any reader can detect it if someone does. **Single-writer assumption:** `append_record` reads the log tail for `prev_hash` then appends; two processes writing the same log concurrently (e.g. the loop and the API on one path) can fork the chain (two records sharing a `prev_hash`), which `verify_chain` then flags as a break. Concurrency-safe writing (a cross-process lock or a single append broker) is deferred with multi-session support.

## Honest scope

In scope (this build-out, all four slices): the `count` clause + RATE_LIMIT effect (count-over-trajectory only); REQUIRE_APPROVAL with a deferred hold + pending store; the first FastAPI surface (list/approve/deny/audit-search); the dashboard bound to the real audit log (replacing the mock) with a pending-approval queue and a searchable audit view; SHA-256 hash-chaining of the log.

Explicitly NOT in scope: time-windowed rate limits (no clock in the gate, ever); auth/authz on the FastAPI endpoints beyond capturing an approver string (who *may* approve is a real security question for its own ADR — the endpoint trusts its caller's asserted identity, a documented gap); multi-session / multi-agent partitioning (`session_id`/`agent_id` stay reserved); in-API execution of approved actions (execution stays in the loop); per-tool or sliding-window counts beyond a single `{tool, max}`; counting DENYed or held actions (we count ALLOWed only, matching `_after_holds`). The ADR 0003 SQL keyword-scan gaps (7a/7c/7d) are unchanged.

## Consequences

- The engine gains one clause and a total effect map; the decision stays a pure function of four data inputs. A non-author can still read a pack and predict any verdict.
- The loop gains a hold branch but keeps exactly one execute path guarded by `is Decision.ALLOW`.
- Aegis grows its first network surface. The risk it introduces (a second decider, a text-gate, a blocking clock dependency) is bounded by §c: the HTTP layer records, it does not judge; the hold is a record, not a wait.
- The audit trail becomes tamper-evident and the literal source of truth for approvals; the dashboard finally reads it.
- New standing review obligations: (1) no clock/random/network reaches `decide`; (2) no endpoint calls `decide` or reads model text; (3) the pending store never becomes the authority over the log; (4) `decide` never reads the hash.
