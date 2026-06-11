"""
policy — the declarative Aegis policy engine (ADR 0003).

Layout (ADR 0003 §a — one responsibility per file, disk touched in exactly one place):
    schema.py  — strict validator: dict-in -> validated Pack/Rule, or raise PolicyError.
                 No file I/O, no YAML.
    engine.py  — the pure decision function decide(pack, tool, params) -> GatewayResult.
                 No file I/O, no YAML, no clock, no random, no network.
    loader.py  — the ONLY module that touches disk and YAML (yaml.safe_load + validate).
    packs/     — example packs (default.yaml reproduces Phase-1 demo behavior).

Re-exports below are convenience only; the purity boundary is the *module* boundary
(engine never imports loader/yaml), not these names.
"""

from __future__ import annotations

from policy.schema import Pack, PolicyError, Rule, validate

__all__ = ["Pack", "Rule", "PolicyError", "validate"]
