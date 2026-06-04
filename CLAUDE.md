# Aegis — working agreement

Aegis is a deterministic, action-layer policy gateway for AI agents. It sits at the
tool-call boundary of an agent: for every action the agent proposes (a tool + its
concrete parameters), Aegis evaluates it against declarative least-privilege policies
and returns one of `ALLOW`, `DENY`, `RATE_LIMIT`, or `REQUIRE_APPROVAL` — then logs the
action, the decision, the policy that fired, and the approver to an append-only audit
trail.

## The thesis (law)

> You make an agent safe by governing what it DOES, not by filtering what it SAYS —
> and deterministically, because LLM self-evaluation is bypassable by the agent's own
> autonomy.

## The two invariants (law — never violate)

1. **Enforcement happens at the tool-call boundary**, on concrete actions + parameters
   — never on the model's natural-language text.
2. **The gate is deterministic.** An LLM may advise, but must never BE the decision.

Any change that smuggles non-determinism into the enforcement path, or that tries to
gate on model text instead of concrete tool calls, is wrong by definition — reject it.

## Tech

Python (core gateway + policy engine), the Anthropic API (for the governed agent, via the
tool-use loop), FastAPI (approval endpoints + dashboard backend), an append-only
hash-chained audit log (SQLite or JSONL), React for the dashboard, pytest, Docker. Keep
dependencies lean.

## Repo structure

```
aegis/
  core/        # interception loop, audit log
  policy/      # policy engine, schema, example policy packs
  demos/       # benign + hostile agent scenarios
  dashboard/   # React app
  tests/       # pytest, including the red-team attack suite
  CLAUDE.md
  README.md
```

## Working agreement

- The thesis and two invariants above are law.
- Conventional commits (`feat:`, `fix:`, `test:`, `docs:`, `chore:`). Branch per feature,
  PR per merge.
- Non-obvious code carries a comment explaining WHY — every design choice must be
  defensible out loud later.
- After each feature: **red-team** attacks it, **reviewer** reviews it, then the
  non-obvious parts get explained before moving on.
- Never mention any company, employer, or job application anywhere in the repo or
  commits. This is a standalone open tool.

## Subagents

Defined in `.claude/agents/`. They load at session start.

- **architect** — lead architect; defends the two invariants; writes short ADRs.
- **policy-engineer** — owns the policy schema/DSL and trajectory-aware evaluation.
- **gateway-engineer** — owns the runtime interception loop and the hash-chained audit log.
- **red-team** — the attacker; tries to make Aegis fail; documents successful attacks as
  bug reports.
- **frontend-engineer** — owns the React dashboard, bound to the real audit log.
- **reviewer** — read-only pre-merge gate on determinism, ordering, audit integrity,
  injection safety, and test coverage.

## Build order

- **Phase 0** — scaffold: structure, MIT LICENSE, `.gitignore`, `CLAUDE.md`, the six
  subagents. (done)
- **Phase 1** — the walking skeleton: a demo agent (Anthropic tool-use loop) with 2–3
  fake tools, one dangerous (a db tool that can `DROP TABLE`); a single hardcoded gateway
  rule that denies the destructive action and allows the rest; decisions logged to a flat
  file; a red-team test proving the drop-table attack is blocked and a benign run proceeds.
