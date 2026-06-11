# 0002 — Write-ahead, fail-closed audit ordering

- Status: Accepted
- Date: 2026-06-09
- Deciders: architect (gateway-engineer implements, red-team proves)
- Supersedes: — (refines the audit ordering pinned in ADR 0001 §1, §4)

## Problem

ADR 0001 §1 made the gate decision structurally precede the side effect. It did **not**
constrain where the *audit append* sits. In the shipped loop it sits last:

```
core/loop.py  result = evaluate(...)        # decide
core/loop.py  raw = tool_fn(**params)       # EXECUTE (side effect happens)
core/loop.py  record = append_record(...)   # log — runs AFTER execution
```

If `append_record` raises (disk full, bad `log_path`, permissions), the side effect has
already happened, no record exists, and the exception crashes the turn — leaving later
blocks in the turn unlogged too. This is reviewer finding #2 (MAJOR) in
`tests/PHASE1_FINDINGS.md`, "TRACKED MUST-FIX (audit hardening)". It is not an ordering or
determinism failure — the gate still decides correctly before execution — it is an
**audit-completeness** failure: an executed action can go unrecorded, the exact thing the
audit trail exists to prevent.

## Options

The decision is **where the append sits relative to the side effect, and what to do when
it fails.**

1. **Leave the append last, wrap it in try/except + re-raise (naive fix).**
   Stops the silent swallow. But by the time the append runs the tool has *already*
   executed, so a failed append still leaves an executed-but-unlogged action — the
   guarantee is not delivered, only the crash is made louder. Misleading; rejected.

2. **Write-ahead, then halt the run on append failure.**
   Append before execution; if it fails, abort the whole turn/loop. Delivers
   "no unlogged executed action," but halting gates the model's ability to *speak* — and
   the thesis says we govern what the agent DOES, not what it SAYS. An audit outage should
   not silence text. Rejected on mandate grounds.

3. **Write-ahead, fail-closed, refuse + continue (chosen).**
   Append after `evaluate` but **before** the execute/deny branch. If the append fails,
   execute nothing and synthesize an `is_error` tool_result telling the model the action
   was blocked because the audit log is unavailable — then continue the loop. Every action
   is refused while the log is down; the model can still respond in text. Tradeoff: refusals
   during the outage are themselves unlogged (the log is what is down).

## Choice

**Option 3.** This is information-preserving in Phase 1 because the record is
decision-only — `{ts, session_id, agent_id, tool, params, decision, rule, approver,
prev_hash, hash}` (`core/audit.py`) — and never contains the tool's output. Logging
before execution loses nothing.

### New ordering, per tool_use block

```
evaluate(tool, params, context)  ──► Decision        (pure, sync, local — unchanged)
        │
        ▼
append_record(...)  ── write-ahead: flush + os.fsync before returning
        │
        ├─ append OK ──► branch on decision:
        │                   ALLOW → execute tool → real tool_result
        │                   non-ALLOW → synthesize denial tool_result (names the rule)
        │
        └─ append RAISES ──► DO NOT execute (regardless of decision)
                             synthesize is_error tool_result: "aegis.audit_unavailable"
                             continue the loop
```

Net invariant delivered: **no action executes that was not first durably logged.**

**Fail-closed semantics.** On append failure the action is refused whatever the gate
decided. The refusal marker is the string `aegis.audit_unavailable`. This is an
**operational refusal, not a policy rule_id**: `evaluate()` was never consulted about it,
and where a decision did exist it is *overridden* by the operational failure. The marker
must be distinguishable in the loop and tests from any `rule_id` the policy engine emits.

**Surfacing.** The failure must be surfaced clearly to the caller, never silently
swallowed. The loop emits an `AuditUnavailableWarning` (a `UserWarning` subclass)
carrying the tool name, the marker, and the underlying exception, and the model receives
the `is_error` tool_result for every refused action. Warnings print to `stderr` by
default; a caller that wants stricter, halt-the-run semantics can escalate the warning to
an error with a standard `warnings` filter — refuse + continue is the default, not a
ceiling.

**Self-healing.** The append is attempted fresh for **every** action; there is no latched
"log is down" state anywhere in the loop. The moment the log becomes writable again, the
next action's write-ahead append succeeds and normal execution resumes. Red-team must
prove this: a forced failure followed by recovery yields refusals during the outage and
logged executions after it.

**Durability.** `append_record` flushes and `os.fsync`es before returning, so "logged"
means on-disk, not sitting in a userspace or OS buffer. Cheap at this scale, and it is what
makes write-ahead real against a crash between append and execute.

## How the invariants hold

**Invariant 1 (tool-call boundary, not model text).** Unchanged. Only `tool_use` blocks
reach `evaluate`; text blocks are still ignored. The fail-closed refusal does not gate
speech — the model still responds in text during an outage; only *actions* are blocked.
That is fail-closed at the action layer, precisely the mandate.

**Invariant 2 (deterministic gate).** Strengthened, not touched. `evaluate` stays pure and
unmodified; the gate decision is still made first. The new `try/except` around
`append_record` **makes no decision** — it only refuses. The failure handling is
mechanical, not evaluative: same input, same outcome, no LLM, no randomness, no clock or
network in the decision. The new invariant — *no unlogged executed action* — sits on top
of the decision path without reaching into it.

The append failure is an *environmental* signal (disk, permissions), not an evaluative
one — and it is **monotonic**: an outage can only ever turn an ALLOW into a refusal,
never a DENY into an ALLOW. The decision-versus-refusal boundary stays clean as long as
`aegis.audit_unavailable` is kept distinct from every policy `rule_id`.

## Consequences / Tradeoffs

Named plainly so they can be defended out loud:

1. **Refusals during an audit outage are unlogged.** The guaranteed invariant covers
   *executed* actions only — and during an outage nothing executes. The log being down is
   exactly why those refusals cannot be recorded. Each refusal still emits an
   `AuditUnavailableWarning` naming the underlying exception (see Surfacing) and an
   `is_error` tool_result, so the outage is visible even though it is unloggable; outage
   recovery/replay is out of scope.

2. **The record logs the decision, not the outcome.** It says what was allowed/denied, not
   whether the tool then succeeded. Outcome capture (tool result, success/failure) is a
   second record or a follow-up field for a later phase — the record is **not** widened
   now.

3. **fsync per record is an fsync per action.** Fine at Phase 1/2 scale. Revisit if
   throughput matters; it composes naturally with the Phase 3 hash-chain work, which also
   touches the append path.

## Out of scope

- Logging refusals that occur while the log is unavailable.
- Audit-outage recovery, buffering, or replay.
- Recording execution outcomes (success/failure, tool output).
- Hash-chaining and OS-level append-only enforcement (Phase 3) — write-ahead composes with
  it but does not depend on it.
