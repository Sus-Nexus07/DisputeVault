/**
 * DisputeVault payload schemas (PROTOCOL.md §4 EvidenceV1, §7 VerdictV1).
 * Types and enumerations only - validation and serialization live in
 * canonical.ts.
 */

/** PROTOCOL.md §4 dispute types. */
export const DISPUTE_TYPES = [0, 1, 2, 3] as const;
export type DisputeType = (typeof DISPUTE_TYPES)[number];

export const DISPUTE_TYPE_NAMES: Record<DisputeType, string> = {
  0: 'rejected-valid-work',
  1: 'payment-not-received',
  2: 'scope-dispute',
  3: 'other',
};

/** PROTOCOL.md §7 verdict decisions, canonical enum order. */
export const VERDICT_DECISIONS = [
  'claimant_wins',
  'platform_wins',
  'partial',
  'needs_human_review',
] as const;
export type VerdictDecision = (typeof VERDICT_DECISIONS)[number];

/** PROTOCOL.md §4 EvidenceV1 - canonical field order is declared here. */
export interface EvidenceV1 {
  v: 1;
  bounty_id: number; // 0 .. 4294967295 (Uint<32>)
  claimant_id_hash: string; // 32 lowercase hex chars (16-byte truncated SHA-256)
  type: DisputeType;
  evidence_ref_hash: string; // 32 lowercase hex chars
  summary: string; // <= 64 characters, must also fit the wire budget
}

/** PROTOCOL.md §7 VerdictV1 - canonical field order is declared here. */
export interface VerdictV1 {
  v: 1;
  dispute_id: bigint | number; // 0 .. 2^64-1; MUST equal the outer dispute id (§7 binding rule)
  decision: VerdictDecision;
  confidence: number; // 0..100
  reason_code: string; // [A-Z0-9_], 1..32 chars
  policy_version: string; // [a-z0-9-], 1..32 chars
}

/** PROTOCOL.md §3 wire budgets. */
export const WIRE = {
  evidenceWireSize: 256,
  evidenceMaxJsonBytes: 250,
  verdictWireSize: 192,
  verdictMaxJsonBytes: 186,
} as const;

/** PROTOCOL.md §4 field limit. */
export const EVIDENCE_SUMMARY_MAX_CHARS = 64;
/** PROTOCOL.md §7 field limits. */
export const VERDICT_REASON_CODE_MAX_CHARS = 32;
export const VERDICT_POLICY_VERSION_MAX_CHARS = 32;
