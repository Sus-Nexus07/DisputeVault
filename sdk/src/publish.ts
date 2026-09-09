/**
 * Verdict publishing with the off-chain dispute-binding check.
 *
 * SECURITY.md §5.1 (named Wave-1 trust assumption): the Compact contract
 * cannot parse the verdict's canonical JSON, so it CANNOT enforce that the
 * payload's embedded `dispute_id` matches the dispute id the verdict is
 * posted against. That binding is enforced HERE, off-chain, BEFORE the
 * contract's `post_verdict` circuit is ever invoked:
 *
 *   1. receive target dispute_id + verdict payload
 *   2. canonicalize/validate the payload (§2, §7)
 *   3. extract the payload's embedded dispute_id
 *   4. compare against the target dispute_id
 *   5. reject immediately if they differ
 *   6. only then hand the canonical wire to the contract layer
 *
 * A mismatched payload never reaches the contract call. This is the single
 * gate every publisher (worker, gateway, frontend) must go through.
 */
import { ProtocolError, canonicalizeVerdict, validateVerdict } from './canonical.js';
import { makeVerdictWire } from './wire.js';
import { verdictCommitment } from './crypto.js';
import type { VerdictV1 } from './schema.js';

/** Contract boundary: the minimum the SDK needs from a contract adapter. */
export interface DisputeVaultContract {
  /**
   * Invoke the contract's `post_verdict` circuit for the given dispute id
   * with the 192-byte verdict wire. Implementations wrap the Midnight
   * gateway/contract instance.
   */
  postVerdict(disputeId: bigint, verdictWire: Uint8Array): Promise<void>;
}

export interface PublishVerdictResult {
  /** The canonical JSON that was committed (for logs/verification UIs). */
  canonicalJson: string;
  /** The 192-byte DV1V wire handed to the contract layer. */
  verdictWire: Uint8Array;
  /** SHA-256 of the wire - equals the on-chain verdict_commitment. */
  commitment: Uint8Array;
}

/**
 * Validate, bind-check, and publish a verdict.
 *
 * Throws ProtocolError - without touching the contract - if:
 *   - the payload violates the §7 schema or size budget,
 *   - the payload's embedded dispute_id differs from `disputeId` (§7 binding
 *     rule; SECURITY.md §5.1 Wave-1 trust assumption), or
 *   - the contract adapter is missing.
 *
 * The `postVerdict` contract call happens only after every check passes.
 */
export async function publishVerdict(
  contract: DisputeVaultContract,
  disputeId: bigint,
  payload: VerdictV1,
): Promise<PublishVerdictResult> {
  if (typeof contract?.postVerdict !== 'function') {
    throw new ProtocolError('a DisputeVault contract adapter is required to publish a verdict');
  }
  if (typeof disputeId !== 'bigint' || disputeId < 0n || disputeId >= 1n << 64n) {
    throw new ProtocolError(`disputeId must be a bigint in 0..2^64-1, got ${String(disputeId)}`);
  }

  // (2) canonicalize/validate strictly - schema, patterns, size budget.
  const canonicalJson = canonicalizeVerdict(payload);

  // (3) extract the embedded dispute_id from the VALIDATED payload.
  const embedded = validateVerdict(payload).dispute_id;

  // (4)+(5) the §7 binding rule: reject before any contract interaction.
  if (embedded !== disputeId) {
    throw new ProtocolError(
      `verdict/dispute binding mismatch (PROTOCOL §7): payload dispute_id=${embedded} does not match target dispute_id=${disputeId} - rejected before the contract call (SECURITY §5.1)`,
    );
  }

  // (6) build the wire and only now invoke the contract layer.
  const verdictWire = makeVerdictWire(canonicalJson);
  const commitment = await verdictCommitment(verdictWire);
  await contract.postVerdict(disputeId, verdictWire);
  return { canonicalJson, verdictWire, commitment };
}
