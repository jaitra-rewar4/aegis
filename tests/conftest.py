"""
conftest.py — shared pytest fixtures for the Aegis test suite.

WHY a shared conftest:
- tmp_path-based audit log fixtures prevent test pollution of the real
  demos/audit.log.jsonl file and keep test runs hermetic.
- The db_reset fixture ensures each test that exercises execute_sql sees
  a clean, seeded in-memory SQLite state (the module-level singleton in
  demos/tools.py would otherwise bleed state between tests).
- The configure_default_pack autouse fixture loads the default policy pack
  and calls core.gateway.configure() before each test, then restores the
  previous pack state after.  WHY autouse: the pre-Phase-2 tests were written
  against a governed gateway; the pack is now the spec of that governance, so
  configuring it is test-environment setup, not behaviour change.  Tests that
  need the unconfigured posture (test_policy_engine.py handles its own state
  via its own autouse fixture) can call configure(None) inside the test body —
  this fixture's restore tolerates that because it snapshots _ACTIVE_PACK
  before overwriting and restores the exact value (even if the test set it to
  None).
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


# ---------------------------------------------------------------------------
# Module-level lazy cache: load the default pack ONCE per session.
# WHY: loader.load() performs disk I/O and YAML parsing; loading it on every
# test function invocation (hundreds of calls) would be wasteful and would
# re-verify an invariant that has not changed.  A session-level cache is safe
# because Pack is a frozen dataclass — nothing can mutate the cached object.
# The cache is populated on first access inside the autouse fixture.
# ---------------------------------------------------------------------------
_DEFAULT_PACK_CACHE = None


def _get_default_pack():
    """Return the default pack, loading and caching it on first call."""
    global _DEFAULT_PACK_CACHE
    if _DEFAULT_PACK_CACHE is None:
        from policy.loader import DEFAULT_PACK_PATH, load
        _DEFAULT_PACK_CACHE = load(DEFAULT_PACK_PATH)
    return _DEFAULT_PACK_CACHE


@pytest.fixture(autouse=True)
def configure_default_pack():
    """Autouse function-scoped fixture: configure the default pack before each test.

    WHY autouse + function scope (not session scope): the gateway's _ACTIVE_PACK
    is mutable module-level state.  A test that calls configure(None) to probe
    the unconfigured posture would leave _ACTIVE_PACK=None if we only configured
    once at session start, corrupting subsequent tests.  Function scope + snapshot
    /restore gives every test a clean, known starting state.

    Restore semantics: read _ACTIVE_PACK before overwriting (the previous value
    may be None from a failed startup or a prior test's configure(None)); restore
    exactly that value after yield.  We do NOT assume the previous value is None.
    """
    import core.gateway as gw
    previous = gw._ACTIVE_PACK          # snapshot — could be None or a Pack
    gw.configure(_get_default_pack())   # configure the default pack
    yield
    gw.configure(previous)              # restore exactly — tolerates None


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
