/**
 * Ledger reads for the DisputeVault gateway (docs/ARCHITECTURE.md §2
 * `gateway/src/reader.ts`).
 *
 * Reads ONLY public on-chain data through the indexer public-data provider:
 * dispute records (commitments + envelope), the dispute counter, and the
 * platform encryption key. Raw evidence never passes through here — the
 * ledger stores commitments and ciphertext envelopes by design
 * (docs/SECURITY.md §2), and this module adds no way to see more.
 */
import type { ContractAddress } from '@midnight-ntwrk/midnight-js-protocol/compact-runtime';
import { toHex } from '@midnight-ntwrk/midnight-js-utils';

import {
  contractLedger,
  type ChainConnection,
  type Dispute,
  type DisputeStatus,
  type Ledger,
} from './chain.js';

export type { Dispute, DisputeStatus };

/** Public dispute metadata — the only dispute view the gateway exposes. */
export interface DisputeView {
  readonly disputeId: string;
  readonly evidenceCommitment: string;
  readonly envelope: string;
  readonly verdictCommitment: string;
  readonly status: 'SUBMITTED' | 'VERDICT_POSTED';
}

/** Public chain metadata. */
export interface ChainMetadataView {
  readonly connected: boolean;
  readonly contractAddress: string | null;
  readonly disputeCounter: string | null;
  readonly platformEncKey: string | null;
  readonly adminAuthority: string | null;
}

function statusName(status: DisputeStatus): 'SUBMITTED' | 'VERDICT_POSTED' {
  // DisputeStatus.SUBMITTED = 0, VERDICT_POSTED = 1 (compiled enum).
  return status === 1 ? 'VERDICT_POSTED' : 'SUBMITTED';
}

function toDisputeView(disputeId: bigint, d: Dispute): DisputeView {
  return {
    disputeId: disputeId.toString(10),
    evidenceCommitment: toHex(d.evidence_commitment),
    envelope: toHex(d.envelope),
    verdictCommitment: toHex(d.verdict_commitment),
    status: statusName(d.status),
  };
}

/**
 * Fetch the current ledger state for the contract from the indexer.
 * Returns null when the indexer has no state for the address yet.
 */
export async function fetchLedger(
  connection: ChainConnection,
): Promise<Ledger | null> {
  const contractState = await connection.providers.publicDataProvider.queryContractState(
    connection.contractAddress,
  );
  return contractState != null ? contractLedger(contractState.data) : null;
}

/** Read one dispute record; null when the id does not exist on-chain. */
export async function fetchDispute(
  connection: ChainConnection,
  disputeId: bigint,
): Promise<DisputeView | null> {
  const ledger = await fetchLedger(connection);
  if (ledger === null || !ledger.disputes.member(disputeId)) {
    return null;
  }
  return toDisputeView(disputeId, ledger.disputes.lookup(disputeId));
}

/** Public chain metadata for GET /disputes (Wave-1 listing surface). */
export async function fetchChainMetadata(
  connection: ChainConnection,
): Promise<ChainMetadataView> {
  const ledger = await fetchLedger(connection);
  if (ledger === null) {
    return {
      connected: true,
      contractAddress: toHex(connection.contractAddress as unknown as Uint8Array),
      disputeCounter: null,
      platformEncKey: null,
      adminAuthority: null,
    };
  }
  return {
    connected: true,
    contractAddress: toHex(connection.contractAddress as unknown as Uint8Array),
    disputeCounter: ledger.dispute_counter.toString(10),
    platformEncKey: toHex(ledger.platform_enc_key),
    adminAuthority: toHex(ledger.admin_authority),
  };
}

/** List all disputes with their public metadata (ids + records). */
export async function listDisputes(
  connection: ChainConnection,
): Promise<DisputeView[]> {
  const ledger = await fetchLedger(connection);
  if (ledger === null) return [];
  const out: DisputeView[] = [];
  for (const [id, record] of ledger.disputes) {
    out.push(toDisputeView(id, record));
  }
  return out;
}

export type { ContractAddress };
