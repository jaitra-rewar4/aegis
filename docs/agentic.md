# Agentic operations in Aegis

This repo doubles as a place to practice agentic engineering. The idea is simple. Aegis governs what agents do, so we build it with agents that are kept honest by the same kinds of guardrails: tests, deterministic checks, and a real record of what changed. No tool here makes a decision that the tests cannot check.

Most of the long list of buzzwords reduces to about seven real primitives. The rest are patterns you compose from those, or different names for the same thing. Here is what is wired up, and how to grow it.

## What is in the repo now

Subagents. See `.claude/agents`. Six roles: architect, policy-engineer, gateway-engineer, red-team, frontend-engineer, reviewer. They load at session start. An orchestrator that dispatches several of them in parallel is what people mean by agent teams and agents managing agents.

Context files. `CLAUDE.md` is the working agreement. `web/AGENTS.md` carries the Next.js warning. AGENTS.md is the cross-tool convention, CLAUDE.md is Claude Code's. Same idea: put the right rules next to the code.

Slash commands. See `.claude/commands`. `/verify` runs the tests and the web build. `/redteam` attacks the current diff with the red-team subagent. `/adr` drafts an ADR with the architect. Each is one markdown file; add your own the same way.

A skill. See `.claude/skills/aegis-new-rule`. A reusable procedure the model loads on demand when you add a policy rule, so every rule ships with tests.

The Aegis MCP server. See `mcp_server`. A custom Model Context Protocol server that exposes the real engine as a tool, `aegis_check(tool, params, trajectory)`. Any MCP client can consult Aegis before it acts. This is the most useful piece, because it turns Aegis from a demo into a guardrail that other agents plug into.

CI. See `.github/workflows/ci.yml`. Runs pytest and the web build on every push and pull request. This is the substrate that everything autonomous needs.

## Run the MCP server

```
pip install -r mcp_server/requirements.txt
python mcp_server/server.py
claude mcp add aegis -- python /absolute/path/to/aegis/mcp_server/server.py
```

Then in a new session an agent can call `aegis_check` before running a tool.

## How to grow it (the rest of the list)

Hooks. `settings.json` can run a command on tool use. A good one for this repo runs pytest when `core/` or `policy/` changes, and blocks edits to `core/gateway.py` unless the determinism tests pass. The repo then enforces its own invariants. Add it when you want the safety without remembering to run it.

Eval-driven loops, self-improving loops, agent fixes own tests. These are one idea: act, run the eval, read the failure, fix, repeat. The red-team suite is the eval set. The loop is: add a bypass attempt, run the suite, harden the rule until it passes, repeat. `/redteam` plus `/verify` is the manual version.

Headless Claude Code, routines, unsupervised and overnight runs. `claude -p` runs a prompt without a session, which is how CI and cron call it. A nightly job that runs the suite, the red-team loop, and the web build, then reports, is a reasonable first unsupervised task because the gate is pass or fail.

CI run by agents. The workflow above is plain CI. The next step is the official Claude Code action reviewing pull requests or running on a mention.

Worktrees, parallel agents, multiple windows, multi-repo orchestration. `git worktree add` gives an agent its own copy of the tree so two agents never edit the same files. Use it for parallel work. This is the fix for a collision that happened once when two efforts edited the same files at the same time.

## The honest part

Unsupervised and overnight runs only work with a tight scope, a strong eval, and a sandbox. That is an Aegis shaped problem. Do not point an autonomous loop at the code without a clear gate that tells it when it is done. Words like ultracode are not real features. The real modes are extended thinking (ultrathink) and the deep multi-agent code review (`/code-review ultra`).
