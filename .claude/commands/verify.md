---
description: Run the Python tests and the web production build, then report pass or fail.
---
Verify the project end to end and report the results concisely. Do not commit.

1. Python core: run `py -m pytest tests/ -q`.
2. Web app: from `web/`, run `npx tsc --noEmit`, then `npm run build`.

Summarize what passed and what failed, with the exact counts or the errors.
