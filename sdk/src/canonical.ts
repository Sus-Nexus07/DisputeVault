/**
 * DisputeVault canonical JSON (PROTOCOL.md §2, §4, §7).
 *
 * Deterministic serialization shared by frontend, gateway, and (as a
 * behavioral spec) the Go worker:
 *   - fixed field order (schema order, never alphabetical)
 *   - UTF-8, no BOM, no whitespace
 *   - integers: plain decimal ASCII, no leading '+', no leading zeros, no
 *     exponents, no fraction
 *   - strings: minimal escaping (", \, control chars as \u00XX); non-ASCII
 *     emitted raw as UTF-8
 *   - hash fields: exactly 32 lowercase hex chars
 *   - unknown fields rejected, never ignored
 *   - size budgets enforced in BYTES (UTF-8), never truncated
 */
import {
  DISPUTE_TYPES,
  EVIDENCE_SUMMARY_MAX_CHARS,
  VERDICT_DECISIONS,
  VERDICT_POLICY_VERSION_MAX_CHARS,
  VERDICT_REASON_CODE_MAX_CHARS,
  WIRE,
  type DisputeType,
  type EvidenceV1,
  type VerdictDecision,
  type VerdictV1,
} from './schema.js';

/** Thrown for every protocol violation; message names the violated rule. */
export class ProtocolError extends Error {
  constructor(message: string) {
    super(`disputevault: ${message}`);
    this.name = 'ProtocolError';
  }
}

const encoder = new TextEncoder();

export const byteLength = (s: string): number => encoder.encode(s).length;

const HEX32 = /^[0-9a-f]{32}$/;
const REASON_CODE = /^[A-Z0-9_]{1,32}$/;
const POLICY_VERSION = /^[a-z0-9-]{1,32}$/;

function isPlainObject(x: unknown): x is Record<string, unknown> {
  return typeof x === 'object' && x !== null && !Array.isArray(x);
}

/** Minimal JSON string escaping per PROTOCOL.md §2 rule 5. */
export function escapeJsonString(s: string): string {
  let out = '"';
  for (const ch of s) {
    // iterate by code point so surrogate pairs survive intact
    const code = ch.codePointAt(0)!;
    if (ch === '"') out += '\\"';
    else if (ch === '\\') out += '\\\\';
    else if (code < 0x20) {
      out += '\\u' + code.toString(16).padStart(4, '0');
    } else {
      out += ch; // non-ASCII stays raw (UTF-8), never \uXXXX
    }
  }
  return out + '"';
}

/** Plain decimal ASCII for a non-negative safe integer (§2 rule 4). */
function integerToJson(n: number | bigint): string {
  const value = typeof n === 'bigint' ? n : Math.trunc(n);
  if (value < 0) throw new ProtocolError(`negative integer not allowed: ${n}`);
  if (typeof n === 'number' && !Number.isSafeInteger(n)) {
    throw new ProtocolError(`integer exceeds the safe range: ${n}`);
  }
  return value.toString(10);
}

/**
 * Serialize an already-validated payload to canonical JSON, using the fixed
 * field order of its schema. Field values are emitted raw; validation is the
 * caller's job (validateEvidence / validateVerdict).
 */
function serializeOrdered(fields: Array<[string, string]>): string {
  return '{' + fields.map(([k, v]) => `${escapeJsonString(k)}:${v}`).join(',') + '}';
}

// ---------------------------------------------------------------------------
// EvidenceV1 (§4)
// ---------------------------------------------------------------------------

/** Validate an EvidenceV1 payload against PROTOCOL.md §4. Throws ProtocolError. */
export function validateEvidence(payload: unknown): EvidenceV1 {
  if (!isPlainObject(payload)) {
    throw new ProtocolError('evidence payload must be a JSON object');
  }
  const allowed = ['v', 'bounty_id', 'claimant_id_hash', 'type', 'evidence_ref_hash', 'summary'];
  for (const key of Object.keys(payload)) {
    if (!allowed.includes(key)) {
      throw new ProtocolError(`evidence payload has unknown field: ${key}`);
    }
  }
  for (const key of allowed) {
    if (!(key in payload)) {
      throw new ProtocolError(`evidence payload is missing field: ${key}`);
    }
  }
  const p = payload as Record<string, unknown>;

  if (p.v !== 1) throw new ProtocolError(`evidence v must be 1, got ${JSON.stringify(p.v)}`);
  if (typeof p.bounty_id !== 'number' || !Number.isInteger(p.bounty_id) || p.bounty_id < 0 || p.bounty_id > 0xffffffff) {
    throw new ProtocolError(`evidence bounty_id must be an integer in 0..4294967295, got ${JSON.stringify(p.bounty_id)}`);
  }
  if (typeof p.claimant_id_hash !== 'string' || !HEX32.test(p.claimant_id_hash)) {
    throw new ProtocolError('evidence claimant_id_hash must be 32 lowercase hex chars');
  }
  if (typeof p.type !== 'number' || !DISPUTE_TYPES.includes(p.type as DisputeType)) {
    throw new ProtocolError(`evidence type must be one of ${DISPUTE_TYPES.join(', ')}`);
  }
  if (typeof p.evidence_ref_hash !== 'string' || !HEX32.test(p.evidence_ref_hash)) {
    throw new ProtocolError('evidence evidence_ref_hash must be 32 lowercase hex chars');
  }
  if (typeof p.summary !== 'string') {
    throw new ProtocolError('evidence summary must be a string');
  }
  if ([...p.summary].length > EVIDENCE_SUMMARY_MAX_CHARS) {
    throw new ProtocolError(`evidence summary exceeds ${EVIDENCE_SUMMARY_MAX_CHARS} characters`);
  }
  return {
    v: 1,
    bounty_id: p.bounty_id,
    claimant_id_hash: p.claimant_id_hash,
    type: p.type as DisputeType,
    evidence_ref_hash: p.evidence_ref_hash,
    summary: p.summary,
  };
}

/**
 * Canonicalize an EvidenceV1 payload (§2 + §4). Throws ProtocolError if the
 * payload violates the schema or the canonical JSON exceeds the 250-byte
 * evidence budget - nothing is ever truncated.
 */
export function canonicalizeEvidence(payload: unknown): string {
  const e = validateEvidence(payload);
  const json = serializeOrdered([
    ['v', integerToJson(e.v)],
    ['bounty_id', integerToJson(e.bounty_id)],
    ['claimant_id_hash', escapeJsonString(e.claimant_id_hash)],
    ['type', integerToJson(e.type)],
    ['evidence_ref_hash', escapeJsonString(e.evidence_ref_hash)],
    ['summary', escapeJsonString(e.summary)],
  ]);
  const bytes = byteLength(json);
  if (bytes > WIRE.evidenceMaxJsonBytes) {
    throw new ProtocolError(
      `evidence canonical JSON is ${bytes} bytes; budget is ${WIRE.evidenceMaxJsonBytes} (PROTOCOL §3) - rejected, never truncated`,
    );
  }
  return json;
}

// ---------------------------------------------------------------------------
// VerdictV1 (§7)
// ---------------------------------------------------------------------------

const MAX_DISPUTE_ID = (1n << 64n) - 1n;

/** Validate a VerdictV1 payload against PROTOCOL.md §7. Throws ProtocolError. */
export function validateVerdict(payload: unknown): VerdictV1 {
  if (!isPlainObject(payload)) {
    throw new ProtocolError('verdict payload must be a JSON object');
  }
  const allowed = ['v', 'dispute_id', 'decision', 'confidence', 'reason_code', 'policy_version'];
  for (const key of Object.keys(payload)) {
    if (!allowed.includes(key)) {
      throw new ProtocolError(`verdict payload has unknown field: ${key}`);
    }
  }
  for (const key of allowed) {
    if (!(key in payload)) {
      throw new ProtocolError(`verdict payload is missing field: ${key}`);
    }
  }
  const p = payload as Record<string, unknown>;

  if (p.v !== 1) throw new ProtocolError(`verdict v must be 1, got ${JSON.stringify(p.v)}`);
  const id = p.dispute_id;
  const idBig =
    typeof id === 'bigint' ? id : typeof id === 'number' && Number.isInteger(id) && id >= 0 ? BigInt(id) : undefined;
  if (idBig === undefined || idBig < 0n || idBig > MAX_DISPUTE_ID) {
    throw new ProtocolError(`verdict dispute_id must be an integer in 0..2^64-1, got ${String(id)}`);
  }
  if (typeof p.decision !== 'string' || !VERDICT_DECISIONS.includes(p.decision as VerdictDecision)) {
    throw new ProtocolError(`verdict decision must be one of ${VERDICT_DECISIONS.join(' | ')}`);
  }
  if (typeof p.confidence !== 'number' || !Number.isInteger(p.confidence) || p.confidence < 0 || p.confidence > 100) {
    throw new ProtocolError(`verdict confidence must be an integer in 0..100, got ${JSON.stringify(p.confidence)}`);
  }
  if (typeof p.reason_code !== 'string' || !REASON_CODE.test(p.reason_code) || p.reason_code.length > VERDICT_REASON_CODE_MAX_CHARS) {
    throw new ProtocolError('verdict reason_code must match [A-Z0-9_] with 1..32 chars');
  }
  if (typeof p.policy_version !== 'string' || !POLICY_VERSION.test(p.policy_version) || p.policy_version.length > VERDICT_POLICY_VERSION_MAX_CHARS) {
    throw new ProtocolError('verdict policy_version must match [a-z0-9-] with 1..32 chars');
  }
  return {
    v: 1,
    dispute_id: idBig,
    decision: p.decision as VerdictDecision,
    confidence: p.confidence,
    reason_code: p.reason_code,
    policy_version: p.policy_version,
  };
}

/**
 * Canonicalize a VerdictV1 payload (§2 + §7). Throws ProtocolError if the
 * payload violates the schema or the canonical JSON exceeds the 186-byte
 * verdict budget - nothing is ever truncated.
 */
export function canonicalizeVerdict(payload: unknown): string {
  const v = validateVerdict(payload);
  const json = serializeOrdered([
    ['v', integerToJson(v.v)],
    ['dispute_id', integerToJson(v.dispute_id)],
    ['decision', escapeJsonString(v.decision)],
    ['confidence', integerToJson(v.confidence)],
    ['reason_code', escapeJsonString(v.reason_code)],
    ['policy_version', escapeJsonString(v.policy_version)],
  ]);
  const bytes = byteLength(json);
  if (bytes > WIRE.verdictMaxJsonBytes) {
    throw new ProtocolError(
      `verdict canonical JSON is ${bytes} bytes; budget is ${WIRE.verdictMaxJsonBytes} (PROTOCOL §3) - rejected, never truncated`,
    );
  }
  return json;
}

/** Convenience: parse + validate + canonicalize from raw JSON text. */
export function canonicalizeEvidenceJson(text: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new ProtocolError('evidence payload is not valid JSON');
  }
  return canonicalizeEvidence(parsed);
}

/** Convenience: parse + validate + canonicalize from raw JSON text. */
export function canonicalizeVerdictJson(text: string): string {
  let parsed: unknown;
  try {
    parsed = JSON.parse(text);
  } catch {
    throw new ProtocolError('verdict payload is not valid JSON');
  }
  return canonicalizeVerdict(parsed);
}
