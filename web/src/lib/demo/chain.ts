/**
 * chain.ts — the in-browser SHA-256 hash chain, a faithful port of core/audit.py
 * (_record_hash / verify_chain). This is the REAL chain construction the Python gateway
 * uses, run client-side over the demo session's records — not a mock, not a stand-in.
 *
 * PARITY with core/audit.py:
 *  - the hash is SHA-256 over the record's CANONICAL form, EXCLUDING the `hash` field;
 *  - canonical = Python's json.dumps(payload, sort_keys=True, separators=(",", ":"),
 *    ensure_ascii=True): keys sorted at every level, no whitespace, non-ASCII \u-escaped;
 *  - prev_hash links each record to the one before, so any edit to an earlier record changes
 *    every later hash and verify_chain reports the break at exactly the altered index.
 *
 * WHY re-implement the canonical serializer instead of using JSON.stringify directly:
 * JSON.stringify does NOT sort keys and does NOT \u-escape non-ASCII, so its bytes (and thus
 * its SHA-256) would diverge from the Python writer. canonicalize() below reproduces Python's
 * byte string for the value types a record carries — strings (incl. non-ASCII), integers,
 * booleans, null, and nested objects/arrays. ONE documented residual divergence remains, and it
 * is unreachable in this demo: JS has a single number type, so a Python float that is integral
 * (e.g. 50.0 -> "50.0") would serialize as "50" here. Every demo param is a JS integer, so the
 * demo chain is internally tamper-evident AND matches the Python canonical form for its inputs.
 */
import type { DemoRecord } from "./console";

// Escape a string EXACTLY as Python's json.dumps(ensure_ascii=True) does: start from
// JSON.stringify (which already escapes ", \, and the C0 control chars with the same short
// forms Python uses), then \u-escape every remaining code unit >= 0x80. 0x7F (DEL) is ASCII in
// both, so it stays raw. We walk code units rather than use a regex range so the source stays
// pure ASCII (no literal high-boundary character that could be mangled on save). Surrogate-pair
// halves are each >= 0xD800 >= 0x80, so both are escaped individually — the same \uXXXX\uXXXX
// form Python emits for supplementary-plane characters.
function encodeString(value: string): string {
  const base = JSON.stringify(value);
  let out = "";
  for (let i = 0; i < base.length; i++) {
    const code = base.charCodeAt(i);
    out += code >= 0x80 ? "\\u" + code.toString(16).padStart(4, "0") : base[i];
  }
  return out;
}

// Reproduce json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).
// A legitimate record carries only JSON scalars / objects / arrays. NaN, Infinity, and undefined
// can never appear in one the writer produced — and Python's json.dumps RAISES ValueError on
// NaN/Infinity rather than emitting a value. We mirror that: rather than let JSON.stringify
// silently coerce NaN/Infinity/undefined to the string "null" (which would collide with a real
// null and let a tampered field re-hash to its original value), we THROW. recordHash propagates
// the throw and verifyChain treats an unhashable record as a chain break — fail-closed.
function canonicalize(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "boolean") return value ? "true" : "false";
  if (typeof value === "number") {
    if (!Number.isFinite(value)) {
      throw new Error("non-finite number is not serializable to a canonical record");
    }
    return JSON.stringify(value);
  }
  if (typeof value === "string") return encodeString(value);
  if (Array.isArray(value)) return "[" + value.map(canonicalize).join(",") + "]";
  if (typeof value === "object") {
    const obj = value as Record<string, unknown>;
    const keys = Object.keys(obj).sort();
    return "{" + keys.map((k) => encodeString(k) + ":" + canonicalize(obj[k])).join(",") + "}";
  }
  // undefined / function / symbol: not a JSON value. A real record never holds one; a tampered
  // record that does must NOT silently canonicalize to "null" (see above) — so we throw.
  throw new Error(`value of type ${typeof value} is not serializable to a canonical record`);
}

function toHex(buffer: ArrayBuffer): string {
  const bytes = new Uint8Array(buffer);
  let out = "";
  for (let i = 0; i < bytes.length; i++) {
    out += bytes[i].toString(16).padStart(2, "0");
  }
  return out;
}

/**
 * SHA-256 over the record's canonical form, excluding the `hash` field — the TS port of
 * core.audit._record_hash. Async because Web Crypto's digest is async; the caller awaits it
 * just like the Python writer computes the hash before the record reaches the log. Throws if the
 * record holds a value that has no canonical form (NaN/Infinity/undefined) — fail-closed, so a
 * tampered record can never re-hash to a colliding value.
 */
export async function recordHash(record: DemoRecord): Promise<string> {
  // Exclude only `hash`; every other field (including prev_hash) is part of the payload.
  const payload: Record<string, unknown> = {};
  for (const [k, v] of Object.entries(record)) {
    if (k !== "hash") payload[k] = v;
  }
  const canonical = canonicalize(payload);
  const digest = await crypto.subtle.digest("SHA-256", new TextEncoder().encode(canonical));
  return toHex(digest);
}

export interface ChainVerification {
  ok: boolean;
  firstBrokenIndex: number | null;
}

/**
 * Verify the chain oldest-first — the TS port of core.audit.verify_chain. Each record's
 * prev_hash must equal the previous record's hash, and each record's hash must equal its
 * recomputed value. Returns the first failing index (ok=false), or {ok:true, null} for a
 * clean (or empty) chain. A record that cannot be canonically hashed (e.g. a tampered-in
 * NaN/undefined) is itself a break at its index — recomputation throwing is caught and reported
 * as a failure rather than crashing the verifier.
 */
export async function verifyChain(records: DemoRecord[]): Promise<ChainVerification> {
  let prev: string | null = null;
  for (let i = 0; i < records.length; i++) {
    const rec = records[i];
    if (rec.prev_hash !== prev) return { ok: false, firstBrokenIndex: i };
    let recomputed: string;
    try {
      recomputed = await recordHash(rec);
    } catch {
      return { ok: false, firstBrokenIndex: i };
    }
    if (rec.hash !== recomputed) return { ok: false, firstBrokenIndex: i };
    prev = rec.hash;
  }
  return { ok: true, firstBrokenIndex: null };
}
