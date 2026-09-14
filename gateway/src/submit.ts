/**
 * Transaction construction + submission for the DisputeVault gateway
 * (docs/ARCHITECTURE.md §2 `gateway/src/submit.ts`).
 *
 * Wave-1 submission surface (docs/ARCHITECTURE.md §3.3): the Go worker (and
 * Wave-1 tooling) calls this layer over HTTP; it NEVER canonicalizes,
 * hashes, encrypts, or binds verdicts itself. Every protocol operation is
 * delegated to @disputevault/sdk — this file contains NO second
 * implementation of canonical JSON, commitments, wire formats, encryption,
 * or verdict binding.
 *
 * Defense in depth for the Attack-6 binding rule (docs/SECURITY.md §5.1):
 * the SDK's publishVerdict ALREADY rejects a verdict whose embedded
 * dispute_id differs from the target dispute id BEFORE calling the contract
 * adapter (i.e. before postVerdict below is ever invoked). This layer
 * re-checks the binding independently — extract embedded dispute_id,
 * compare with the target, reject mismatch — so a caller that somehow
 * bypasses publishVerdict still cannot post a mismatched verdict.
 *
 * Raw evidence rules: submit_dispute accepts the 256-byte DV1E wire and the
 * 284-byte envelope as OPAQUE byte strings. They are never logged and never
 * echoed in any response.
 */
import {
  publishVerdict,
  validateVerdict,
  ProtocolError,
  type VerdictV1,
} from '@disputevault/sdk';
import type { Logger } from 'pino';

import type { ChainConnection } from './chain.js';

/** The gateway contract adapter the SDK's publishVerdict drives. */
class GatewayContractAdapter {
  constructor(
    private readonly connection: ChainConnection,
    private readonly logger: Logger,
  ) {}

  /**
   * Called by the SDK ONLY after canonicalization, validation, and the
   * binding check have all passed. The verdict wire here is exactly the
   * 192-byte DV1V frame the SDK produced.
   */
  async postVerdict(disputeId: bigint, verdictWire: Uint8Array): Promise<void> {
    if (verdictWire.length !== 192) {
      throw new ProtocolError(`verdict wire must be exactly 192 bytes, got ${verdictWire.length}`);
    }
    this.logger.info({ disputeId: disputeId.toString(10) }, 'post_verdict: submitting transaction');
    await (
      this.connection.deployed as unknown as {
        callTx: {
          post_verdict: (disputeId: bigint, verdictWire: Uint8Array) => Promise<unknown>;
        };
      }
    ).callTx.post_verdict(disputeId, verdictWire);
  }
}

/** Result of a verdict submission (commitment as lowercase hex). */
export interface VerdictSubmitResult {
  readonly disputeId: string;
  readonly verdictCommitment: string;
  readonly canonicalJson: string;
}

/**
 * Canonicalize, bind-check (twice: SDK + defense in depth), and post a
 * verdict for `targetDisputeId`.
 *
 * Throws ProtocolError — before any contract interaction — when the payload
 * violates the schema, or its embedded dispute_id differs from the target
 * (PROTOCOL.md §7 / SECURITY.md §5.1).
 */
export async function submitVerdict(
  connection: ChainConnection,
  logger: Logger,
  targetDisputeId: bigint,
  payload: VerdictV1,
): Promise<VerdictSubmitResult> {
  // Defense in depth (gateway-side re-check of the §7 binding rule):
  // extract the embedded dispute_id and compare BEFORE any contract call.
  // publishVerdict performs the same check; this keeps the guarantee even
  // if a future refactor replaces the SDK call.
  const embedded = validateVerdict(payload).dispute_id;
  if (embedded !== targetDisputeId) {
    throw new ProtocolError(
      `verdict/dispute binding mismatch (PROTOCOL §7): payload dispute_id=${embedded} does not match target dispute_id=${targetDisputeId} - rejected before the contract call (SECURITY §5.1)`,
    );
  }

  const adapter = new GatewayContractAdapter(connection, logger);
  const result = await publishVerdict(adapter, targetDisputeId, payload);
  return {
    disputeId: targetDisputeId.toString(10),
    verdictCommitment: Buffer.from(result.commitment).toString('hex'),
    canonicalJson: result.canonicalJson,
  };
}

/** Result of a dispute submission (fresh id allocated by the contract). */
export interface DisputeSubmitResult {
  readonly disputeId: string;
  readonly evidenceCommitment: string;
}

/**
 * Submit a dispute: the evidence wire (256 bytes) and envelope (284 bytes)
 * are treated as opaque bytes produced by the claimant's client (or tooling
 * on its behalf). The circuit computes evidence_commitment in-circuit and
 * allocates the fresh id from the ledger Counter.
 *
 * The wire bytes are never logged and never included in any response.
 */
export async function submitDispute(
  connection: ChainConnection,
  logger: Logger,
  evidenceWire: Uint8Array,
  envelope: Uint8Array,
): Promise<DisputeSubmitResult> {
  if (evidenceWire.length !== 256) {
    throw new ProtocolError(`evidence wire must be exactly 256 bytes, got ${evidenceWire.length}`);
  }
  if (envelope.length !== 284) {
    throw new ProtocolError(`envelope must be exactly 284 bytes, got ${envelope.length}`);
  }
  logger.info(
    { evidenceWireBytes: evidenceWire.length, envelopeBytes: envelope.length },
    'submit_dispute: submitting transaction',
  );
  const txData = await (
    connection.deployed as unknown as {
      callTx: {
        submit_dispute: (evidenceWire: Uint8Array, envelope: Uint8Array) => Promise<{
          public: { txHash?: string };
        }>;
      };
    }
  ).callTx.submit_dispute(evidenceWire, envelope);

  // The fresh dispute id is allocated by the ledger Counter; the definitive
  // record (with its in-circuit commitment) is readable from the indexer.
  // To avoid a race against indexer indexing, re-read via the public data
  // provider and fall back to the counter inferred from the tx result.
  const { contractLedger } = await import('./chain.js');
  const contractState = await connection.providers.publicDataProvider.queryContractState(
    connection.contractAddress,
  );
  const ledger = contractState != null ? contractLedger(contractState.data) : null;
  if (ledger === null) {
    throw new Error('submit_dispute: contract state not found after submission');
  }
  // The newest id is the current counter (submit_dispute increments then uses).
  const disputeId = ledger.dispute_counter;
  const record = ledger.disputes.member(disputeId)
    ? ledger.disputes.lookup(disputeId)
    : undefined;
  return {
    disputeId: disputeId.toString(10),
    evidenceCommitment: record ? Buffer.from(record.evidence_commitment).toString('hex') : '',
  };
}

/**
 * Register the platform encryption key (one-time, admin-authorized). The
 * 65-byte uncompressed P-256 point is public by design (claimants need it
 * to encrypt evidence).
 */
export async function registerPlatform(
  connection: ChainConnection,
  logger: Logger,
  platformPublicKey: Uint8Array,
): Promise<{ platformEncKey: string }> {
  if (platformPublicKey.length !== 65) {
    throw new ProtocolError(`platform public key must be exactly 65 bytes, got ${platformPublicKey.length}`);
  }
  logger.info('register_platform: submitting transaction');
  await (
    connection.deployed as unknown as {
      callTx: {
        register_platform: (platformPublicKey: Uint8Array) => Promise<unknown>;
      };
    }
  ).callTx.register_platform(platformPublicKey);
  return { platformEncKey: Buffer.from(platformPublicKey).toString('hex') };
}
