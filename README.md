# Aegis

A deterministic, action-layer policy gateway for AI agents.

Aegis sits at the tool-call boundary of an AI agent. For every action the agent proposes (a tool plus its concrete parameters), Aegis checks it against declarative least-privilege policies and returns one of four decisions, then writes the action, the decision, the rule that fired, and the approver to an append-only audit trail.

| Decision | Meaning |
| --- | --- |
| `ALLOW` | Execute the action. |
| `DENY` | Refuse the action. |
| `RATE_LIMIT` | Refuse because a frequency or quota bound was hit. |
| `REQUIRE_APPROVAL` | Hold the action until a human approves or denies it. |

## The idea

You make an agent safe by governing what it does, not by filtering what it says, and you do it deterministically. A model that can reason can also rationalize its way past a guard that lives inside it. So the guard does not live inside it.

Two rules hold everywhere in the codebase:

1. Enforcement happens at the tool-call boundary, on concrete actions and parameters, never on the model's natural-language text.
2. The gate is deterministic. A model may advise, but it is never the decision.

The verdict is a plain, auditable rule check on the concrete action about to run. The model can argue; it cannot overrule the gate.

## What is here

- `core/` is the interception loop and the append-only audit log.
- `policy/` is the policy engine, the schema and validator, and the example policy packs.
- `demos/` holds benign and hostile agent runs you can execute without an API key.
- `tests/` is the pytest suite, including the red-team attack tests.
- `web/` is the marketing site and an interactive playground that runs the real policy engine in the browser.
- `docs/adr/` holds the architecture decision records, one per phase.

## How the engine decides

`decide(pack, tool, params, trajectory)` is a pure function. Given a policy pack, a tool name, its parameters, and the actions already taken this run, it returns a verdict and the id of the rule that produced it. There is no clock, no randomness, no network, and no model in that path, so the same inputs always produce the same verdict.

Policies are data, not code. A pack is a small YAML file that a reviewer who did not write it can still read and predict. Rules match on the tool name, on per-parameter constraints (amount thresholds, allow-lists, recipient domains, keyword scans), and on the trajectory. A trajectory rule can, for example, deny a send to an outside domain once a customer record has been read this run. First match wins, and the default is deny.

## Run the Python core

You need Python 3.11 or newer.

```
pip install -r requirements.txt
py -m pytest tests/ -q          # run the full suite
py demos/run_benign.py --stub   # a benign run, no API key needed
py demos/run_hostile.py --stub  # the hostile runs, including the exfiltration catch
```

The demos drive an Anthropic tool-use loop when `ANTHROPIC_API_KEY` is set, and a deterministic stub turn when it is not, so the gate, the audit log, and the policy engine all run offline.

## Run the web app

The site lives in `web/` and is a Next.js app. It includes a playground that imports the same engine logic, ported to TypeScript, and runs `decide()` live in the browser. Every allow or deny shown on the site comes from that function, never from a hardcoded value.

```
cd web
npm install
npm run dev      # http://localhost:3000
npm run build    # production build
```

## Deploy the web app

The app deploys to Vercel as a standard Next.js project. The one setting that matters is the root directory, because the app is in the `web/` subfolder.

1. Import the repository at vercel.com.
2. Set Root Directory to `web`.
3. The framework preset is detected as Next.js. Leave the build and output settings at their defaults.
4. Deploy.

The CLI path is the same. From `web`, run `npx vercel` for a preview and `npx vercel --prod` for production.

## Build order

- Phase 0, the scaffold.
- Phase 1, the walking skeleton: a governed tool-use loop, a hardcoded deny rule, an audit log, and a red-team test that proves a destructive action is blocked while a benign run proceeds.
- Phase 2, the policy engine: declarative YAML packs with per-parameter constraints, a default-deny posture, and trajectory-aware rules that catch a read-then-send exfiltration chain.

## License

[MIT](./LICENSE)
