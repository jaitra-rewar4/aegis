"""
loop.py — the Anthropic tool-use loop with Aegis interception.

This module owns the agent loop.  Its single responsibility is:
    model turn -> for each tool_use block -> gate -> execute|deny -> audit -> repeat.

The key design constraint is testability without a live API key: the public
entry point run_loop() accepts an optional model_turn_fn parameter so red-team
and other tests can inject a stub that returns pre-built content blocks,
exercising the full interception + audit + tool-execution path without any
network call.

Control flow per assistant turn (see ADR 0001 §1, ADR 0002):

    model returns content blocks
            │
            ├─ text blocks ─────────────────── IGNORED by the gate (invariant 1:
            │                                  model text is never an action)
            │
            └─ for each tool_use block:
                     │
                     gateway.evaluate(tool, params, context)   ← pure, sync
                     │
                     append audit record (write-ahead, flush+fsync)  ← ADR 0002
                     │                   WHY before execute: guarantees no action
                     │                   executes that was not first durably logged.
                     │
                     ├─ append OK ──► branch on decision:
                     │                  ALLOW            → execute tool → real result
                     │                  anything else    → DO NOT execute
                     │                  (DENY / RATE_LIMIT / REQUIRE_APPROVAL)
                     │                  → synthesize denial result naming rule_id
                     │
                     └─ append RAISES ──► DO NOT execute (regardless of decision)
                        → synthesize is_error result: aegis.audit_unavailable
                        → continue (loop proceeds; model can still respond in text)
                                                                         │
            all tool_results for this turn ──► sent back to model ──► continue

WHY the gate is between proposal and execution (not a decorator on each tool):
A decorator approach means N enforcement points.  Adding a tool without the
decorator silently removes it from governance — the enforcement point is not a
single chokepoint.  Here, ALL tool_use blocks pass through evaluate() before
ANY tool function is called.  execute() is only reachable through the ALLOW
branch; there is no other path to it.

WHY tool outputs never reach evaluate():
tool_result blocks are data returned to the model.  They are not actions.
Feeding them to the gate would create an injection vector — a tool could
return text that looks like a policy directive and influence the enforcement
path.  The loop passes tool_results straight to the model and nowhere else.

WHY RATE_LIMIT / REQUIRE_APPROVAL are treated as non-ALLOW:
They are defined in the vocabulary (decision.py) but unreachable in Phase 1.
If one ever surfaces (e.g., a future rule accidentally fires), refusing to
execute is the safe default.  The guard `decision is Decision.ALLOW` makes
this explicit: only an exact ALLOW permits execution.
"""

from __future__ import annotations

import os
import warnings
from pathlib import Path
from typing import Any, Callable

from core.audit import append_record
from core.decision import Decision
from core.gateway import evaluate


# ---------------------------------------------------------------------------
# Type aliases for clarity
# ---------------------------------------------------------------------------

# A content block is the dict shape Anthropic returns in message.content[].
ContentBlock = dict[str, Any]

# A model-turn function takes the accumulated messages list and returns a list
# of content blocks (the assistant's response for this turn).
ModelTurnFn = Callable[[list[dict[str, Any]]], list[ContentBlock]]


# WHY a module-level constant rather than an inline string literal:
# This marker is an OPERATIONAL refusal — it signals that the audit log was
# unavailable, not that a policy rule fired.  evaluate() never emits it.
# Keeping it as a named constant (a) prevents typos in the except branch and
# tests, (b) makes it greppable as a distinct identifier, and (c) enforces the
# ADR 0002 "Fail-closed semantics" requirement that the marker be
# distinguishable from every policy rule_id the engine can ever emit.
AUDIT_UNAVAILABLE_MARKER = "aegis.audit_unavailable"


class AuditUnavailableWarning(UserWarning):
    """Emitted when a write-ahead audit append fails and an action is refused.

    WHY a warnings-module warning rather than a bare stderr print (ADR 0002,
    "Surfacing"): the failure must reach the *caller*, not just the terminal.
    A warning is programmatically catchable (pytest.warns, warnings.catch_warnings)
    and escalatable — a caller that wants halt-the-run semantics instead of
    refuse-and-continue can promote it to an error with a standard filter:
        warnings.simplefilter("error", AuditUnavailableWarning)
    Refuse + continue is the default, not a ceiling.  The default "print once
    per location" dedup only affects the stderr echo of repeated identical
    failures; every refused action still gets its own is_error tool_result, so
    no refusal is ever hidden from the model or the transcript.
    """


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _make_denial_result(tool_use_id: str, rule_id: str) -> dict[str, Any]:
    """Build the tool_result block the model receives when a call is denied.

    WHY name the rule_id in the content: the model needs to understand *why*
    it cannot proceed so it can respond sensibly to the user instead of
    retrying the same blocked call.  Naming the specific rule also makes the
    denial legible in transcripts and tests.
    """
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": (
            f"[AEGIS DENY] This action was blocked by policy rule '{rule_id}'. "
            "The requested operation was not executed."
        ),
        "is_error": True,
    }


def _make_audit_unavailable_result(tool_use_id: str) -> dict[str, Any]:
    """Build the tool_result block the model receives when the audit log is down.

    WHY is_error=True: mirrors _make_denial_result's shape so the model gets a
    consistent error signal.  The content names AUDIT_UNAVAILABLE_MARKER so that
    the model — and any test inspecting the message stream — can distinguish an
    operational refusal (log outage) from a policy denial (rule fired).

    WHY this helper returns a refusal without consulting evaluate():
    The append failure is an environmental signal (disk full, bad path,
    permissions), not an evaluative one.  The except branch makes NO decision —
    it only refuses.  This is monotonic by construction: an outage can only
    ever turn an ALLOW into a refusal, never a DENY into an ALLOW (ADR 0002,
    Invariant 2 section).
    """
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": (
            f"[AEGIS OPERATIONAL REFUSAL] Action was blocked because the audit log "
            f"is unavailable (marker: '{AUDIT_UNAVAILABLE_MARKER}'). "
            "The requested operation was NOT executed."
        ),
        "is_error": True,
    }


def _make_allow_result(tool_use_id: str, raw_result: Any) -> dict[str, Any]:
    """Wrap a tool's return value in the Anthropic tool_result shape."""
    return {
        "type": "tool_result",
        "tool_use_id": tool_use_id,
        "content": str(raw_result),
    }


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def run_loop(
    *,
    system_prompt: str,
    initial_user_message: str,
    tool_registry: dict[str, Callable[..., Any]],
    tool_schemas: list[dict[str, Any]],
    model: str = "claude-opus-4-5",
    max_turns: int = 10,
    log_path: Path | str | None = None,
    model_turn_fn: ModelTurnFn | None = None,
    context: Any = None,
) -> list[dict[str, Any]]:
    """Run the governed tool-use loop and return the full audit trail for this run.

    Parameters
    ----------
    system_prompt:
        Instruction text for the agent being governed.
    initial_user_message:
        The first user turn.
    tool_registry:
        Mapping of tool_name -> callable.  Only callables reachable here can
        ever be executed — the registry IS the tool surface.
    tool_schemas:
        Anthropic-format tool definitions sent to the model.
    model:
        Anthropic model ID (ignored when model_turn_fn is injected).
    max_turns:
        Hard cap on agent turns to prevent infinite loops.
    log_path:
        Path for the JSONL audit log.  Defaults to demos/audit.log.jsonl.
    model_turn_fn:
        Injectable stub for the "model turn."  When provided, the loop calls
        this function instead of hitting the Anthropic API.  Signature:
            fn(messages: list[dict]) -> list[ContentBlock]
        This is the testability seam: red-team and unit tests pass a
        deterministic stub so the full interception path runs without a live
        API key or network.
    context:
        Session context handle passed through to gateway.evaluate() on every
        call.  Unread by the Phase 1 rule; accepted to stabilise the signature
        (see ADR 0001 §1a).

    Returns
    -------
    list[dict]
        Every audit record appended during this run, in order.
    """
    # Build the model-turn callable.  We delay importing anthropic so that the
    # module is importable (and testable) even when the SDK is not installed or
    # when ANTHROPIC_API_KEY is absent — the stub path never touches it.
    if model_turn_fn is None:
        model_turn_fn = _build_anthropic_turn_fn(
            model=model,
            system_prompt=system_prompt,
            tool_schemas=tool_schemas,
        )

    messages: list[dict[str, Any]] = [
        {"role": "user", "content": initial_user_message}
    ]
    audit_trail: list[dict[str, Any]] = []

    for _turn in range(max_turns):
        # --- model turn -------------------------------------------------------
        content_blocks = model_turn_fn(messages)

        # Collect assistant content into messages before processing results.
        messages.append({"role": "assistant", "content": content_blocks})

        # --- process blocks ---------------------------------------------------
        tool_results: list[dict[str, Any]] = []
        has_tool_use = False

        for block in content_blocks:
            if block.get("type") != "tool_use":
                # WHY skip non-tool_use blocks silently: text / thinking blocks
                # are model speech, not actions.  Invariant 1 forbids passing
                # them to evaluate().
                continue

            has_tool_use = True
            tool_name = block["name"]
            params = block.get("input", {})
            tool_use_id = block["id"]

            # ---- THE GATE ----
            # evaluate() is called BEFORE the tool function is touched.
            # The result is inspected; only an exact ALLOW opens the execute path.
            # WHY exact enum comparison (not truthiness): Decision.DENY is still
            # a truthy enum member.  `is Decision.ALLOW` is unambiguous and
            # cannot be fooled by a future enum member.
            result = evaluate(tool_name, params, context)

            # --- write-ahead audit (ADR 0002) ---------------------------------
            # WHY append_record runs AFTER evaluate but BEFORE execute/deny:
            # This is the write-ahead guarantee — no action executes that was
            # not first durably logged.  append_record flushes and fsyncs inside,
            # so "logged" means on-disk, not sitting in a buffer.
            # If the append fails (disk full, bad path, permissions), we must
            # NOT execute regardless of what evaluate decided — an unlogged
            # executed action is the exact failure mode the audit trail exists
            # to prevent (ADR 0002 Option 3, "fail-closed, refuse + continue").
            try:
                record = append_record(
                    tool=tool_name,
                    params=params,
                    decision=result.decision.value,
                    rule=result.rule_id,
                    log_path=log_path,
                )
            except Exception as exc:  # noqa: BLE001
                # WHY no decision here — only refusal:
                # The except branch is environmental, not evaluative.  It makes
                # no policy judgment; it only refuses.  This is monotonic:
                # an outage can only turn ALLOW into a refusal, never DENY into
                # ALLOW.  The decision-versus-refusal boundary stays clean as
                # long as AUDIT_UNAVAILABLE_MARKER stays distinct from every
                # policy rule_id (ADR 0002, Invariant 2 section).
                # WHY the warning carries exc: surfacing the underlying failure
                # (disk full? bad path? permissions?) to the caller is required
                # by ADR 0002 "Surfacing" — a refusal with no diagnosis is a
                # swallowed failure.
                warnings.warn(
                    f"[AEGIS] audit log unavailable for tool '{tool_name}' "
                    f"({exc!r}); action refused (fail-closed, "
                    f"marker='{AUDIT_UNAVAILABLE_MARKER}').",
                    AuditUnavailableWarning,
                    stacklevel=2,
                )
                tool_results.append(_make_audit_unavailable_result(tool_use_id))
                # WHY plain `continue` with no latched state (ADR 0002,
                # "Self-healing"): the append is re-attempted fresh for every
                # subsequent action, so the run recovers the moment the log is
                # writable again — refusals during the outage, normal logged
                # execution after it.
                continue   # DO NOT execute; loop continues to next block

            audit_trail.append(record)

            if result.decision is Decision.ALLOW:
                # --- execute (only reachable here, through ALLOW after a
                #     successful append — the two conditions are now coupled) --
                tool_fn = tool_registry.get(tool_name)
                if tool_fn is None:
                    # Unknown tool — treat as an error, do not crash the loop.
                    raw = f"[ERROR] Unknown tool '{tool_name}' — not in registry."
                    tool_results.append(_make_allow_result(tool_use_id, raw))
                else:
                    try:
                        raw = tool_fn(**params)
                    except Exception as exc:  # noqa: BLE001
                        raw = f"[ERROR] Tool raised an exception: {exc}"
                    tool_results.append(_make_allow_result(tool_use_id, raw))
            else:
                # --- deny (DENY, RATE_LIMIT, REQUIRE_APPROVAL) ---------------
                # WHY treat all non-ALLOW as non-executable: the safe default.
                # RATE_LIMIT and REQUIRE_APPROVAL have no execution path yet.
                tool_results.append(_make_denial_result(tool_use_id, result.rule_id))

        # --- stop condition ---------------------------------------------------
        if not has_tool_use:
            # No tool_use blocks in this turn means the model is done.
            break

        # Feed tool results back for the next model turn.
        messages.append({"role": "user", "content": tool_results})

    return audit_trail


# ---------------------------------------------------------------------------
# Anthropic API turn function (only constructed when a live key is needed)
# ---------------------------------------------------------------------------

def _build_anthropic_turn_fn(
    *,
    model: str,
    system_prompt: str,
    tool_schemas: list[dict[str, Any]],
) -> ModelTurnFn:
    """Return a closure that drives one model turn via the Anthropic API.

    WHY a closure rather than a method: it keeps the API-dependent code in one
    place, behind the model_turn_fn seam.  Swapping to a different provider in
    a future phase means replacing this one function, not refactoring the loop.

    Importing anthropic here (inside the function) means the rest of the module
    — and therefore all test code that uses the stub path — can be imported
    without the SDK being installed.
    """
    try:
        import anthropic  # noqa: PLC0415
    except ImportError as exc:
        raise RuntimeError(
            "The 'anthropic' package is required for live API calls. "
            "Install it with: pip install anthropic"
        ) from exc

    api_key = os.environ.get("ANTHROPIC_API_KEY")
    if not api_key:
        raise RuntimeError(
            "ANTHROPIC_API_KEY environment variable is not set. "
            "Either set it or pass a model_turn_fn stub for testing."
        )

    client = anthropic.Anthropic(api_key=api_key)

    def _turn(messages: list[dict[str, Any]]) -> list[ContentBlock]:
        response = client.messages.create(
            model=model,
            max_tokens=1024,
            system=system_prompt,
            tools=tool_schemas,
            messages=messages,
        )
        # Convert SDK objects to plain dicts for uniform handling downstream.
        blocks: list[ContentBlock] = []
        for block in response.content:
            if block.type == "text":
                blocks.append({"type": "text", "text": block.text})
            elif block.type == "tool_use":
                blocks.append(
                    {
                        "type": "tool_use",
                        "id": block.id,
                        "name": block.name,
                        "input": block.input,
                    }
                )
        return blocks

    return _turn
