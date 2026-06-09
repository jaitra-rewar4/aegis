# 0001 — Phase 1: the walking skeleton

- Status: Accepted
- Date: 2026-06-04
- Deciders: architect (with gateway-engineer to implement)
- Supersedes: —

## Problem

Phase 0 scaffolded the repo. Phase 1 must prove the load-bearing claim of Aegis in the
smallest possible end-to-end slice: an Anthropic tool-use agent proposes a destructive
action, and Aegis blocks it **before the side effect happens**, deterministically, on the
concrete tool parameters — while letting benign actions through and logging every
decision.

This ADR pins down, for Phase 1 only, the seven things that decide whether the skeleton
is honest: the interception point, the single hardcoded rule, the fake tools, the audit
record shape, how the two invariants hold, the module layout, and what is explicitly out
of scope. Everything here is a deliberate stopgap that the policy engine, audit chain,
and approval flow will replace in later phases.

## Options

We are not choosing the whole architecture here — that is settled by the invariants. The
real Phase-1 decision is **where the gate sits in the tool-use loop** and **how thin to
make it**.

1. **Gate inside the loop, between proposal and execution (chosen).**
   The runtime owns the tool-use loop. After the model returns `tool_use` blocks, the
   runtime calls `gateway.evaluate(tool, params, context)` for each one and only executes
   on `ALLOW`. Tradeoff: the runtime must own the loop rather than hand tools straight to
   an SDK helper — slightly more code, but the gate is structurally impossible to bypass.

2. **Wrap each tool function with a guard decorator.**
   Let the SDK drive the loop; each tool checks the policy on entry. Tradeoff: the gate
   lives in N places instead of one. A new tool added without the decorator is silently
   ungoverned — the enforcement point is not a single chokepoint, which violates the
   "predictable by a non-author" goal. Rejected.

3. **Post-hoc audit only (log what the agent did, no blocking yet).**
   Tradeoff: cheapest, but proves nothing — the whole thesis is that we govern what the
   agent DOES before it does it. A logger that never blocks is not a gateway. Rejected.

## Choice

**Option 1.** The Phase-1 runtime owns the Anthropic tool-use loop and routes every
proposed `tool_use` through a single synchronous chokepoint before execution.

### 1. The interception point

The gate sits between proposal and execution, and the ordering is unmistakable: **the
tool's side effect must never run before `evaluate` returns `ALLOW`.**

Control flow, per assistant turn:

```
model returns content blocks
        │
        ├─ text blocks ............... ignored by the gate (NEVER evaluated — invariant 1)
        │
        └─ for each tool_use block (tool name + concrete params):
                 │
                 gateway.evaluate(tool, params, context)  ──► Decision  (pure, sync, local)
                 │
                 ├─ ALLOW  → execute tool → real tool_result ──┐
                 │                                             │
                 └─ DENY   → DO NOT execute                    │
                            → synthesize a denial tool_result  │
                              naming the rule that fired ──────┤
                                                               │
                 (RATE_LIMIT / REQUIRE_APPROVAL: not reachable │
                  in Phase 1 — see Scope; if ever returned,    │
                  treat as DENY, never as ALLOW)               │
                                                               ▼
                            append audit record (ALLOW and DENY alike)
                                                               │
   all tool_results for this turn ──► sent back to model ──► loop continues
```

WHY decision-before-execution is structural, not a convention: `evaluate` is called and
its result inspected *before* the tool's Python function is ever invoked. There is no
optimistic path, no async fire-and-forget, no "run then check." A reviewer can read the
loop top to bottom and see that `execute(...)` is only reachable through the `ALLOW`
branch.

WHY text blocks are never passed to the gate: invariant 1. The model's natural-language
output is not an action. Only `tool_use` blocks — concrete tool + concrete params — reach
`evaluate`.

WHY tool *outputs* don't touch control flow: a `tool_result` is data returned to the
model; it is never read by the gate or the loop to decide anything. This keeps the known
injection vector out of the enforcement path from day one.

### 1a. The `context` handle (signature decision)

`evaluate` takes a **session/context handle from the start**: `evaluate(tool, params,
context)`. The Phase-1 rule ignores `context` entirely — it is a pure function of
`(tool, params)` today.

WHY add an argument the rule does not yet read: Phase 2's signature demo is a
read→send exfiltration chain, and trajectory rules fundamentally need to know what
happened earlier in the session. If `evaluate` were `(tool, params)` now, that argument
would have to be threaded through the loop, the gateway, and the audit code later — a
refactor across the whole enforcement path. Stabilizing the signature now is the same
cheap future-proofing move as the reserved hash fields and the full decision enum: later
phases add *behavior*, not a new signature. `context` carries no nondeterminism in Phase 1
because nothing reads it; when trajectory logic arrives it will read prior **actions**
(concrete tool calls), never model text — invariant 1 still holds.

### 2. The single hardcoded deny rule

Phase 1 has **exactly one rule, hardcoded in Python — no DSL, no policy files yet:**

> Deny any call to the destructive database tool whose SQL parameter contains a
> destructive statement (`DROP`, `DELETE`, `TRUNCATE`, `ALTER`).
> Allow everything else.

Deterministic detection, on the concrete parameter — not on model text:

- Input is the tool's concrete `sql` string parameter, nothing else.
- Normalize: uppercase, collapse whitespace. (WHY: case/whitespace are the obvious dodges;
  normalizing closes them without introducing any nondeterminism.)
- Match the presence of a destructive keyword against a **fixed, in-code set**
  `{DROP, DELETE, TRUNCATE, ALTER}`.
- Hit → `DENY` (rule id `phase1.deny_destructive_sql`). No hit → `ALLOW` (rule id
  `phase1.default_allow`).

This is a deliberately blunt keyword check, and the keyword set stays minimal **on
purpose**. It is a **stopgap**: it will be replaced wholesale by the policy engine's
declarative, per-parameter, trajectory-aware rules in a later phase. We accept its
limitations now (see Tradeoff) because Phase 1's job is to prove the *path*, not to ship a
complete SQL parser. The red-team suite will **document** the known evasions (comment
injection, stacked statements, encoding) as expected gaps to be closed by the real
engine — it does not fix them, and the keyword set is not expanded to chase them.

WHY a keyword set and not an LLM "is this dangerous?" call: an LLM in the decision path
violates invariant 2 and is exactly the bypassable self-evaluation the thesis rejects.
The check must be code a non-author can read and predict.

### 3. The fake tools

Two or three demo tools, one dangerous, the rest benign:

| Tool | Params | Contract |
|------|--------|----------|
| `execute_sql` (dangerous) | `sql: str` | Runs SQL against an in-memory/throwaway SQLite DB and returns rows or a status string. The only tool that can cause an irreversible side effect. |
| `lookup_customer` (benign) | `customer_id: str` | Read-only lookup; returns a fixed/fake customer record. No writes, ever. The "read sensitive" half of the Phase-2 exfiltration trajectory will be built around this. |
| `calculator` (benign) | `expression: str` | Evaluates a simple arithmetic expression and returns the number. Pure, no side effects. |

WHY one dangerous + benign neighbors: the demo must show the gate *discriminating* —
blocking the destructive `execute_sql` while `lookup_customer` and `calculator` sail
through — not just refusing everything.

WHY no "send/egress" tool yet: Phase 1 proves the ordering, not the trajectory. The egress
tool arrives in Phase 2 with the read→send exfiltration demo; `lookup_customer` already
gives us the "read sensitive" half to build that rule around.

### 4. The audit log (Phase 1 form)

A flat **JSONL** file (`demos/audit.log.jsonl` or a path the runtime is given), one record
per **evaluated** action, appended. Logged for `ALLOW` and `DENY` alike.

Record shape (fields present now are real; the chain fields are reserved nulls so the
shape never has to change when hash-chaining lands):

```json
{
  "ts": "2026-06-04T00:00:00Z",
  "tool": "execute_sql",
  "params": { "sql": "DROP TABLE customers" },
  "decision": "DENY",
  "rule": "phase1.deny_destructive_sql",
  "prev_hash": null,
  "hash": null
}
```

WHY reserve `prev_hash` / `hash` now: Phase 3 makes the log append-only and hash-chained.
Leaving the fields in place (null in Phase 1) means consumers and the future chain code
inherit a stable schema — no migration, no record-shape churn.

WHY `ts` does not threaten determinism: the timestamp is written to the audit record
*after* the decision is made. It is never an *input* to `evaluate`. (See invariants
below — this is the one place a clock appears, and it is outside the enforcement path.)

### 5. How the two invariants are upheld — and where nondeterminism could sneak in

**Invariant 1 (tool-call boundary, not model text):** only `tool_use` blocks reach
`evaluate`; text blocks are ignored. The rule reads the concrete `sql` parameter, never
the model's prose. Tool outputs are returned to the model as data and never steer the
loop or the gate.

**Invariant 2 (deterministic gate):** `evaluate` is a pure function of `(tool, params)` —
`context` is accepted but unread in Phase 1. Given the same tool and the same params it
returns the same decision, every time. No LLM call, no `random`, no network, no clock read
inside it.

Explicit nondeterminism audit of the enforcement path:

- **LLM call in the decision?** No. The model proposes; it never decides. The rule is
  fixed Python.
- **Randomness?** None in `evaluate`.
- **Wall-clock dependence?** The clock is read only to stamp the audit record, *after* the
  decision, never as an input to it. No time-of-day branch, no TTL, no race.
- **Network / I/O the decision waits on?** None. `evaluate` is local and synchronous; the
  audit append is I/O but happens *after* the decision and does not change it.
- **The `context` handle?** Carries no nondeterminism — nothing reads it in Phase 1, and
  when Phase 2 does, it reads prior concrete actions, never model text.

Confirmed: **no nondeterminism leaks into the enforcement path in this design.**

### 6. Minimal module layout (Phase 1)

```
core/
  gateway.py     # evaluate(tool, params, context) -> Decision; the single hardcoded rule lives here for now.
  loop.py        # owns the Anthropic tool-use loop: propose → evaluate → execute|deny → audit.
  audit.py       # append_record(record) to JSONL; defines the record shape incl. reserved prev_hash/hash.
  decision.py    # Decision enum/value (ALLOW, DENY, RATE_LIMIT, REQUIRE_APPROVAL) + rule id.

demos/
  tools.py       # the 2–3 fake tools (execute_sql, lookup_customer, calculator) + their schemas.
  run_benign.py  # demo: agent does allowed work; every call ALLOWed; run completes.
  run_hostile.py # demo: agent is steered toward DROP TABLE; the destructive call is DENYed.
```

WHY the rule sits in `core/gateway.py` and not a policy file: there is no policy engine in
Phase 1. Putting it in one named function keeps the future swap surgical — the policy
engine replaces the body of `evaluate`, the loop never changes.

WHY `decision.py` already carries all four decision values: the runtime should speak the
full vocabulary from the start so later phases add behavior, not a new type. In Phase 1
only `ALLOW`/`DENY` are produced; `RATE_LIMIT`/`REQUIRE_APPROVAL` are defined but
unreachable, and if one ever appears it is handled as non-ALLOW (no execution).

### 7. Scope boundaries — what Phase 1 explicitly does NOT do

- **No policy DSL / schema / policy packs.** One hardcoded Python rule only.
- **No trajectory awareness.** Each call is judged in isolation; `context` is accepted but
  unread; no session history, no chain-of-tools rules.
- **No FastAPI, no approval endpoints, no human-in-the-loop.** `REQUIRE_APPROVAL` is a
  defined value with no flow behind it.
- **No hash chaining and no append-only enforcement.** Plain JSONL append; `prev_hash`/
  `hash` reserved but null.
- **No `RATE_LIMIT` / `REQUIRE_APPROVAL` execution paths** beyond the enum stub — never
  reachable, and treated as non-ALLOW if they ever surface.
- **No dashboard / React.** The audit log is read by eye for now.
- **No SQL parser, and no expansion of the deny keyword set.** Keyword detection only;
  known evasions are documented by red-team as gaps for the real engine, not fixed here.

## Tradeoff

Named plainly so it can be defended out loud:

1. **The deny rule is shallow.** A keyword scan over `sql` will miss obfuscated
   destructive statements (comments, stacked statements, encoding, `UPDATE`/`MERGE`
   without a WHERE scope) and may over-block benign SQL that merely mentions a keyword.
   We accept this because Phase 1 proves the *enforcement path*, not detection
   completeness — and the policy engine replaces this rule wholesale. The cost is real:
   until then, the demo's "security" is illustrative, and red-team will have a list of
   open evasions on the record.

2. **No tamper-evidence yet.** Plain JSONL can be edited or truncated; integrity arrives
   with hash-chaining in a later phase. Acceptable for a skeleton; the reserved fields
   keep the upgrade cheap.

3. **The runtime owns the loop** instead of delegating to an SDK convenience helper —
   marginally more code to maintain. This is the price of a single, unbypassable
   chokepoint, and it is the right price to pay for the one thing Phase 1 must get right:
   the decision gates the side effect, every time, with no fast path around it.
