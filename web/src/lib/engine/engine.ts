/**
 * engine.ts — the pure policy decision function. Faithful TS port of policy/engine.py.
 *
 *     decide(pack, tool, params, trajectory?) -> GatewayResult
 *
 * PURITY / DETERMINISM (Aegis invariant 2): a pure function of (pack, tool, params,
 * trajectory). No clock, no random, no I/O. First-match-wins over a stably-ordered rule
 * list. Operators are arithmetic / membership / prefix / split only — total on missing and
 * wrong-typed params. The 2b `after` clause is a pure sequence/membership scan over recorded
 * prior actions ("does an ALLOWed record with this tool exist earlier in the list") — never
 * time-based. Adding the trajectory adds a DATA input, not nondeterminism. Same inputs ->
 * same GatewayResult, every time.
 *
 * Known JS/Python divergences (documented, both immaterial to the shipped pack):
 *  1. one_of cannot reproduce Python's int-vs-float type distinction (JS has one number
 *     type, so 1 and 1.0 are identical). String/bool operands match Python exactly; the
 *     default pack uses no one_of, and a float-vs-int operand in the playground is a corner
 *     no realistic policy hits.
 *  2. contains_keyword coerces a non-string param via a small Python-ish str() (bool ->
 *     "True"/"False", null/undefined -> "None"); arrays/objects stringify differently than
 *     Python, but no such coercion can produce an uppercase SQL keyword token, and the only
 *     keyword-scanned param in the pack (`sql`) is a string.
 */

import type {
  Constraint,
  CountClause,
  Decision,
  Effect,
  GatewayResult,
  OperatorName,
  Pack,
  Rule,
} from "./types";

// Total effect -> Decision map (ADR 0006 §b). The pack guarantees one of these four; the
// DENY fallback is an unreachable fail-safe for a corrupted in-memory pack.
const EFFECT_TO_DECISION: Record<Effect, Decision> = {
  ALLOW: "ALLOW",
  DENY: "DENY",
  RATE_LIMIT: "RATE_LIMIT",
  REQUIRE_APPROVAL: "REQUIRE_APPROVAL",
};

// --- engine markers (reserved policy.* namespace; packs may not mint these) ---
export const RULE_NO_PACK = "policy.no_pack";
export const RULE_DEFAULT_DENY = "policy.default_deny";
export const RULE_DEFAULT_ALLOW = "policy.default_allow";

// Uppercase, collapse internal whitespace runs to single spaces, then strip — the exact
// ADR 0001 §2 normalizer. Fixed `\s+` collapse; no user-supplied pattern reaches a regex.
function normalizeKeywordText(value: string): string {
  return value.toUpperCase().replace(/\s+/g, " ").trim();
}

// True for a JS number but NOT a boolean. (typeof excludes booleans for free, unlike
// Python where bool is an int subclass and must be excluded explicitly.) NaN/Infinity pass
// the type check and then simply fail every comparison, exactly as in Python.
function isRealNumber(value: unknown): value is number {
  return typeof value === "number";
}

// Mirrors Python str() for the cases a non-string keyword-scan param could realistically be.
function pyStr(value: unknown): string {
  if (value === null || value === undefined) return "None";
  if (typeof value === "boolean") return value ? "True" : "False";
  return String(value);
}

// Count of '@' in a string, used to require EXACTLY one for a parseable address.
function countAt(value: string): number {
  return value.split("@").length - 1;
}

// --- operator evaluators: each returns true iff the constraint HOLDS for the param value.
// A MISSING param never reaches these — constraintHolds() returns false first. So a
// constraint on a missing/wrong-typed param does-not-hold, the rule does-not-match,
// evaluation falls through, and default-deny converts not-matching into denying. This is
// the fail-safe direction for BOTH effects (a missing param can never satisfy an ALLOW
// guard, e.g. "allow wire_transfer when amount max:1000" must never fire with no amount).

function opMax(param: unknown, operand: unknown): boolean {
  return isRealNumber(param) && param <= (operand as number);
}

function opMin(param: unknown, operand: unknown): boolean {
  return isRealNumber(param) && param >= (operand as number);
}

// param equals one of the listed scalars, type-strict (no coercion). `===` already rejects
// cross-type matches (1 === "1" is false, 1 === true is false), giving Python's
// `type(param) is type(v)` guard for free on strings/bools. See divergence note (1) re
// int-vs-float.
function opOneOf(param: unknown, operand: unknown): boolean {
  return (operand as unknown[]).some(
    (v) => param === v && typeof param === typeof v,
  );
}

function opPrefixOneOf(param: unknown, operand: unknown): boolean {
  return (
    typeof param === "string" &&
    (operand as unknown[]).some((p) => param.startsWith(p as string))
  );
}

// param is `local@domain` with EXACTLY one '@', and domain (case-insensitive) is allowlisted.
// Malformed (non-string, zero/multiple '@') -> false: no parseable domain -> does-not-hold.
function opDomainIn(param: unknown, operand: unknown): boolean {
  if (typeof param !== "string") return false;
  if (countAt(param) !== 1) return false;
  const domain = param.split("@")[1].toLowerCase();
  return (operand as unknown[]).some((d) => domain === String(d).toLowerCase());
}

// The honest negation of domain_in, NOT `!opDomainIn(...)`. A malformed address has no
// parseable domain, so it must does-not-hold (false), NOT true — otherwise garbage would
// satisfy the clause. Same exact one-'@'/split/lowercase discipline; malformed -> false,
// then default-deny catches it at the floor.
function opDomainNotIn(param: unknown, operand: unknown): boolean {
  if (typeof param !== "string") return false;
  if (countAt(param) !== 1) return false;
  const domain = param.split("@")[1].toLowerCase();
  return !(operand as unknown[]).some((d) => domain === String(d).toLowerCase());
}

// param normalizes/tokenizes to a set INTERSECTING the (uppercased) keyword list. A
// non-string param is coerced (totality), matching the Phase-1 gateway's str() behavior.
function opContainsKeyword(param: unknown, operand: unknown): boolean {
  const text = typeof param === "string" ? param : pyStr(param);
  const normalized = normalizeKeywordText(text);
  const tokens = new Set(normalized.length ? normalized.split(" ") : []);
  const keywords = new Set(
    (operand as unknown[]).map((k) => String(k).toUpperCase()),
  );
  for (const token of tokens) {
    if (keywords.has(token)) return true;
  }
  return false;
}

// True only when the param IS present and contains NONE of the keywords. The missing-param
// check in constraintHolds runs first, so a missing param never reaches here and the
// negation can never make an absent param satisfy the rule.
function opNotContainsKeyword(param: unknown, operand: unknown): boolean {
  return !opContainsKeyword(param, operand);
}

const OPERATORS: Record<OperatorName, (p: unknown, o: unknown) => boolean> = {
  max: opMax,
  min: opMin,
  one_of: opOneOf,
  prefix_one_of: opPrefixOneOf,
  domain_in: opDomainIn,
  domain_not_in: opDomainNotIn,
  contains_keyword: opContainsKeyword,
  not_contains_keyword: opNotContainsKeyword,
};

// The single missing-param chokepoint: an absent param -> false BEFORE any operator runs.
// This is what makes "constraint-on-missing-param does not hold" total across every
// operator, including the negations.
function constraintHolds(
  params: Record<string, unknown>,
  paramName: string,
  operator: OperatorName,
  operand: unknown,
): boolean {
  if (!Object.prototype.hasOwnProperty.call(params, paramName)) return false;
  const evaluator = OPERATORS[operator];
  return evaluator(params[paramName], operand);
}

// True iff the rule's `after` clause holds against the recorded trajectory.
//  - afterTool == null -> true, WITHOUT touching the trajectory (a 2a rule never reads it;
//    this is what makes a null/[]/junk trajectory byte-for-byte identical to 2a).
//  - missing/empty trajectory -> false (nothing recorded -> does-not-hold).
//  - otherwise -> true iff SOME entry is an object with .tool === afterTool AND
//    .decision === "ALLOW" (ALLOW-only: a DENYed read never executed, so matching it would
//    fire on a ghost).
// TOTALITY: the scan is crash-proof over WHATEVER the list holds. The isinstance/object gate
// runs BEFORE any field access, and absent fields read as undefined (never throw), so junk
// entries (numbers, strings, null, arrays) classify as not-a-match. Array.isArray guards a
// non-array trajectory to false — at least as total as Python (which would raise on a
// non-iterable), failing in the safe does-not-hold direction.
function afterHolds(afterTool: string | null, trajectory: unknown): boolean {
  if (afterTool == null) return true;
  if (!Array.isArray(trajectory) || trajectory.length === 0) return false;
  for (const entry of trajectory) {
    if (
      entry !== null &&
      typeof entry === "object" &&
      !Array.isArray(entry) &&
      (entry as Record<string, unknown>).tool === afterTool &&
      (entry as Record<string, unknown>).decision === "ALLOW"
    ) {
      return true;
    }
  }
  return false;
}

// True iff the rule's `count` clause holds: the trajectory holds >= count.max prior ALLOWed
// records for count.tool (ADR 0006 §a). A pure list-scan, never a clock — the TS port of
// _count_holds. A null/absent clause -> true WITHOUT touching the trajectory (a rule with no
// count clause never reads it). A null/empty/non-array trajectory counts 0, so the clause
// holds only when max <= 0. Junk entries are skipped (object gate before field access), and
// only `decision === "ALLOW"` records count — the same fail-safe direction as afterHolds.
function countHolds(count: CountClause | null | undefined, trajectory: unknown): boolean {
  if (count == null) return true;
  if (!Array.isArray(trajectory) || trajectory.length === 0) return count.max <= 0;
  let seen = 0;
  for (const entry of trajectory) {
    if (
      entry !== null &&
      typeof entry === "object" &&
      !Array.isArray(entry) &&
      (entry as Record<string, unknown>).tool === count.tool &&
      (entry as Record<string, unknown>).decision === "ALLOW"
    ) {
      seen += 1;
    }
  }
  return seen >= count.max;
}

// A rule matches iff tool matches AND `after` holds AND `count` holds AND every `when`
// constraint holds (all conjunctive). `when` iteration order changes only short-circuit
// timing, never the result.
function ruleMatches(
  rule: Rule,
  tool: string,
  params: Record<string, unknown>,
  trajectory: unknown,
): boolean {
  if (rule.tool !== tool) return false;
  if (!afterHolds(rule.after, trajectory)) return false;
  if (!countHolds(rule.count, trajectory)) return false;
  for (const paramName of Object.keys(rule.when)) {
    const [operator, operand]: Constraint = rule.when[paramName];
    if (!constraintHolds(params, paramName, operator, operand)) return false;
  }
  return true;
}

/**
 * Evaluate one proposed action against the pack and return a GatewayResult.
 *
 * Order:
 *   1. No pack -> DENY / policy.no_pack (the literal default of an unconfigured engine).
 *   2. First-match-wins, top to bottom: the first rule whose tool matches, whose `after`
 *      holds, and whose `when` holds returns its effect + id immediately.
 *   3. No rule matched -> the pack's declared default (deny -> policy.default_deny,
 *      allow -> policy.default_allow).
 *
 * ADDITIVE `trajectory` (defaults to null): a null/empty trajectory reproduces stateless
 * (2a) behavior exactly — it is only ever read by an `after` clause, and a pack with no
 * `after` rule never touches it.
 */
export function decide(
  pack: Pack | null,
  tool: string,
  params: Record<string, unknown>,
  trajectory: unknown = null,
): GatewayResult {
  if (pack == null) {
    return { decision: "DENY", ruleId: RULE_NO_PACK };
  }

  for (const rule of pack.rules) {
    if (ruleMatches(rule, tool, params, trajectory)) {
      const decision: Decision = EFFECT_TO_DECISION[rule.effect] ?? "DENY";
      return { decision, ruleId: rule.id };
    }
  }

  if (pack.default === "deny") {
    return { decision: "DENY", ruleId: RULE_DEFAULT_DENY };
  }
  return { decision: "ALLOW", ruleId: RULE_DEFAULT_ALLOW };
}

// Re-exported so callers (playground, tests) get the types from one place.
export type { Pack, Rule, GatewayResult, Decision, Effect, OperatorName, Constraint };
