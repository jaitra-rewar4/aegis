---
description: Attack the current uncommitted change with the red-team subagent.
---
Use the red-team subagent to attack the current diff (`git diff`).

It should write adversarial tests that assert the expected Aegis decision, run the suite, and report any successful bypass as a documented bug. It must not weaken or delete existing tests. Summarize the findings, and if a real gap is found, write it up rather than papering over it.
