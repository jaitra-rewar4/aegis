#!/usr/bin/env python3
"""
PostToolUse hook: the repo enforces its own invariants.

When an edit lands on core/ or policy/ (the gate and the policy engine, where the two
invariants live), this runs the Python test suite. If it fails, the hook exits 2 so Claude
Code sees the breakage and fixes it before moving on. Aegis gating Aegis.

The hook is wired in .claude/settings.json under hooks.PostToolUse. It reads the tool event
as JSON on stdin; non gate/policy edits exit immediately, so the cost only lands where the
invariants do.
"""
from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main() -> int:
    try:
        event = json.load(sys.stdin)
    except Exception:
        return 0

    file_path = ((event.get("tool_input") or {}).get("file_path") or "").replace("\\", "/")
    if not file_path:
        return 0

    # Only the gate and the policy engine trip the guard. The whole suite is fast (a few
    # seconds) and its red-team tests are the real invariant check, so we run all of it.
    if "/core/" not in file_path and "/policy/" not in file_path:
        return 0

    result = subprocess.run(
        [sys.executable, "-m", "pytest", "tests/", "-q"],
        cwd=ROOT,
        capture_output=True,
        text=True,
    )
    if result.returncode != 0:
        sys.stderr.write(
            "Aegis hook: the test suite failed after this change to the gate or policy. "
            "Fix it before continuing.\n"
        )
        sys.stderr.write((result.stdout or "")[-3500:])
        sys.stderr.write((result.stderr or "")[-1000:])
        return 2
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
