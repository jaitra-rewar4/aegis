"""
loader.py — the ONLY module that touches disk and YAML (ADR 0003 §a).

Reads a path, yaml.safe_load, hands the resulting dict to schema.validate(), returns
a Pack (or raises PolicyError). This confinement is what keeps engine.py pure: the
engine imports neither this module nor yaml, so File I/O and parsing structurally
cannot occur inside the decision path — only here, at startup.

NO partial loading: any failure (unreadable file, YAML parse error, non-dict root, or
schema rejection) raises PolicyError. The caller (startup wiring) then proceeds with
NO pack, which is default-deny everything (ADR 0003 §b/§c).
"""

from __future__ import annotations

from pathlib import Path

import yaml

from policy import schema
from policy.schema import Pack, PolicyError

__all__ = ["load", "DEFAULT_PACK_PATH"]

# The example pack that reproduces Phase-1 demo behavior under default-deny (ADR §e).
DEFAULT_PACK_PATH = Path(__file__).parent / "packs" / "default.yaml"


def load(path: Path | str) -> Pack:
    """Load and validate a policy pack from `path`, or raise PolicyError.

    Steps:
      1. Read the file as UTF-8.
      2. yaml.safe_load — NEVER yaml.load. WHY: yaml.load can construct arbitrary
         Python objects from a document; a policy pack is untrusted-adjacent config
         that must never be able to instantiate code. safe_load restricts the document
         to plain scalars, lists, and dicts (ADR 0003 §user-decided constraints). A
         loader that can be made to execute code is a non-deterministic, injectable
         hole in the path that PRODUCES the rules the enforcement path runs on.
      3. Require a dict root, then schema.validate(...).

    Every failure is wrapped in PolicyError with the cause chained (`from exc`) so the
    operator sees both "the pack failed to load" and the underlying reason.
    """
    path = Path(path)

    try:
        text = path.read_text(encoding="utf-8")
    except OSError as exc:
        raise PolicyError(f"could not read policy pack at {path}: {exc}") from exc

    try:
        raw = yaml.safe_load(text)
    except yaml.YAMLError as exc:
        raise PolicyError(f"could not parse YAML in policy pack at {path}: {exc}") from exc

    if not isinstance(raw, dict):
        # A YAML list, scalar, or empty document is not a pack. Reject before validate
        # so the message names the file (validate's message is content-only).
        raise PolicyError(
            f"policy pack at {path} must be a YAML mapping at the top level, "
            f"got {type(raw).__name__}"
        )

    try:
        return schema.validate(raw)
    except PolicyError as exc:
        # Re-chain so the failure names the file the bad content came from.
        raise PolicyError(f"policy pack at {path} is invalid: {exc}") from exc
