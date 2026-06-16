---
name: aegis-new-rule
description: Add or change a rule in an Aegis policy pack with its tests. Use when adding a policy rule, a per-parameter constraint, a trajectory (after) clause, or a default-pack entry.
---
# Adding an Aegis policy rule

Every rule ships with tests. Follow this whenever you add or change one.

1. Decide the shape. id is namespaced and must not start with `aegis.` or `policy.`. rationale is required and is first-class data, not a comment. tool is an exact match. when holds optional per-parameter constraints. after is the optional trajectory clause. effect is ALLOW or DENY only.

2. Place it correctly. First match wins, so a DENY that must beat a broad ALLOW goes above it. The pack default is deny.

3. Write the tests in tests/. Cover three things: the rule fires on the inputs it should, it does not fire on the inputs it should not, and a missing parameter does not match (totality). For a trajectory rule, test that only an ALLOWed prior action taints a later one.

4. Have the red-team subagent try to bypass it. If it finds a gap, document the gap. Do not weaken the test.

5. Run `py -m pytest tests/ -q`. If the change affects the browser engine port, mirror it in web/src/lib/engine and run the parity tests.

Hold the two invariants the whole time: enforcement is on concrete tool calls and parameters, and the decision is deterministic.
