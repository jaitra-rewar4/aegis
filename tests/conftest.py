"""
conftest.py — shared pytest fixtures for the Aegis test suite.

WHY a shared conftest:
- tmp_path-based audit log fixtures prevent test pollution of the real
  demos/audit.log.jsonl file and keep test runs hermetic.
- The db_reset fixture ensures each test that exercises execute_sql sees
  a clean, seeded in-memory SQLite state (the module-level singleton in
  demos/tools.py would otherwise bleed state between tests).
"""

from __future__ import annotations

import sys
from pathlib import Path

# Make the repo root importable regardless of how pytest is invoked.
# WHY: core/ and demos/ are not installed packages; they live at repo root.
_REPO_ROOT = Path(__file__).parent.parent
if str(_REPO_ROOT) not in sys.path:
    sys.path.insert(0, str(_REPO_ROOT))

import pytest


@pytest.fixture()
def audit_log(tmp_path: Path) -> Path:
    """Return a fresh, isolated JSONL audit log path for one test.

    WHY tmp_path: each test gets its own temp directory from pytest.
    No cross-test pollution; no writes to the real demos/ directory.
    """
    return tmp_path / "audit.log.jsonl"


@pytest.fixture(autouse=False)
def db_reset():
    """Reset the demos module-level SQLite connection to a clean seeded state.

    WHY autouse=False: only tests that call execute_sql and care about DB state
    need this.  The majority of gateway/audit tests don't touch the DB.
    """
    from demos.tools import _reset_db
    _reset_db()
    yield
    # Reset again after so the next test (even outside this fixture) starts
    # clean if it imports the module.
    _reset_db()
