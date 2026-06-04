# Aegis

**A deterministic, action-layer policy gateway for AI agents.**

Aegis sits at the tool-call boundary of an AI agent. For every action the agent proposes
— a tool plus its concrete parameters — Aegis evaluates it against declarative
least-privilege policies and returns one of:

| Decision | Meaning |
| --- | --- |
| `ALLOW` | Execute the action. |
| `DENY` | Refuse the action. |
| `RATE_LIMIT` | Refuse because a frequency/quota bound was hit. |
| `REQUIRE_APPROVAL` | Hold the action until a human approves or denies it. |

It then logs the action, the decision, the policy that fired, and the approver to an
append-only, hash-chained audit trail.

## The thesis

> You make an agent safe by governing what it **does**, not by filtering what it **says**
> — and deterministically, because LLM self-evaluation is bypassable by the agent's own
> autonomy.

## Two invariants

1. **Enforcement happens at the tool-call boundary**, on concrete actions + parameters —
   never on the model's natural-language text.
2. **The gate is deterministic.** An LLM may advise, but must never *be* the decision.

## Why deterministic enforcement

An agent that can reason can also rationalize. Asking the model to police itself puts the
guard inside the thing being guarded — one clever prompt, one injected tool output, and
the guard stands down. Aegis moves the decision out of the model entirely: it is a plain,
auditable rule check on the concrete action about to run. The model can argue; it cannot
overrule the gate.

## Status

Phase 0 — scaffold. The walking skeleton lands in Phase 1.

## Repo structure

```
aegis/
  core/        # interception loop, audit log
  policy/      # policy engine, schema, example policy packs
  demos/       # benign + hostile agent scenarios
  dashboard/   # React app
  tests/       # pytest, including the red-team attack suite
```

## License

[MIT](./LICENSE)
