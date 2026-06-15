/**
 * types.ts — the decision vocabulary and the (schema-normalized) pack shapes.
 *
 * In the Python codebase these live in two places:
 *   - core.decision   -> Decision, GatewayResult
 *   - policy.schema    -> the validated Pack / Rule, AFTER schema.py has normalized the
 *                         YAML `when: {param: {op: operand}}` into `when: {param: (op, operand)}`
 *                         and `after: {tool: X}` into `after: X` (a bare tool string or None).
 *
 * The engine (engine.ts) consumes exactly these shapes. The YAML loader/validator that
 * PRODUCES them (the TS equivalent of schema.py + loader.py) is a separate concern, added
 * in the playground phase; for now `packs/default.ts` is written directly in normalized form.
 */

/** core.decision.Decision — the two terminal verdicts. */
export type Decision = "ALLOW" | "DENY";

/** core.decision.GatewayResult — what `decide` returns. `ruleId` is Python's `rule_id`. */
export interface GatewayResult {
  decision: Decision;
  ruleId: string;
}

/** A rule's declared effect when it matches. */
export type Effect = "ALLOW" | "DENY";

/** The eight operators registered in engine.py's _OPERATOR_EVALUATORS. */
export type OperatorName =
  | "max"
  | "min"
  | "one_of"
  | "prefix_one_of"
  | "domain_in"
  | "domain_not_in"
  | "contains_keyword"
  | "not_contains_keyword";

/** A single `when` constraint in normalized form: (operator, operand). */
export type Constraint = [OperatorName, unknown];

/** A policy rule, in the shape engine.py reads (post-schema-normalization). */
export interface Rule {
  id: string;
  tool: string;
  effect: Effect;
  /** The 2b `after` clause, normalized to a bare tool string — or null when absent. */
  after: string | null;
  /** param_name -> (operator, operand). Empty object when the rule has no `when`. */
  when: Record<string, Constraint>;
}

/** A validated policy pack. */
export interface Pack {
  version: number;
  default: "allow" | "deny";
  rules: Rule[];
}
