/**
 * Test harness: a fake ChainConnection whose behavior mirrors the real
 * circuit semantics (PROTOCOL.md) WITHOUT any Midnight network I/O:
 *
 *   - submit_dispute allocates a fresh id from the counter and stores
 *     SHA-256(evidence wire) as the commitment (§5.3, what the circuit
 *     computes in-circuit);
 *   - post_verdict stores SHA-256(verdict wire) and flips the status
 *     (SUBMITTED → VERDICT_POSTED), refusing duplicates (§8);
 *   - register_platform refuses a second registration (Attack 1).
 *
 * The fake ledger is injected past the real `contractLedger` parser via the
 * vi.mock in server.test.ts (real parser expects real Compact state bytes).
 * This harness exists ONLY to test the HTTP layer; the network path itself
 * is NOT mocked anywhere in production code (docs requirement: no fake
 * "live Midnight" implementation).
 */
import { createHash } from 'node:crypto';

import type { Dispute, DisputeStatus } from '../../src/chain.js';

const sha256 = (bytes: Uint8Array): Uint8Array =>
  Uint8Array.from(createHash('sha256').update(bytes).digest());

/** A fake ledger entry. */
export function makeDispute(overrides: Partial<Dispute> = {}): Dispute {
  return {
    evidence_commitment: new Uint8Array(32),
    envelope: new Uint8Array(284),
    verdict_commitment: new Uint8Array(32),
    status: 0 as DisputeStatus,
    ...overrides,
  };
}

/** Fake ledger shape matching the compiled Ledger surface reader.ts uses. */
export interface FakeLedger {
  readonly __fakeLedger: true;
  admin_authority: Uint8Array;
  platform_enc_key: Uint8Array;
  dispute_counter: bigint;
  disputes: {
    isEmpty(): boolean;
    size(): bigint;
    member(key: bigint): boolean;
    lookup(key: bigint): Dispute;
    [Symbol.iterator](): Iterator<[bigint, Dispute]>;
  };
}

export function makeLedger(
  entries: Map<bigint, Dispute> = new Map(),
  counter: bigint = 0n,
): FakeLedger {
  const map = entries;
  const disputes = {
    isEmpty: () => map.size === 0,
    size: () => BigInt(map.size),
    member: (key: bigint) => map.has(key),
    lookup: (key: bigint) => map.get(key)!,
    [Symbol.iterator]: () => map[Symbol.iterator](),
  };
  return {
    __fakeLedger: true,
    admin_authority: new Uint8Array(32).fill(1),
    platform_enc_key: new Uint8Array(65).fill(0),
    // The circuit increments THEN reads (disputevault.compact §submit_dispute):
    // the counter equals the number of submissions, and the newest dispute id
    // equals the counter.
    dispute_counter: counter,
    disputes,
  };
}

/** Records every circuit invocation for assertions. */
export interface CircuitCalls {
  submit_dispute: Array<{ evidenceWire: Uint8Array; envelope: Uint8Array }>;
  post_verdict: Array<{ disputeId: bigint; verdictWire: Uint8Array }>;
  register_platform: Array<{ platformPublicKey: Uint8Array }>;
}

/** Harness returned to tests: connection + circuit call log + ledger control. */
export interface FakeChainHarness {
  readonly connection: Record<string, unknown>;
  readonly calls: CircuitCalls;
  readonly setLedger: (l: FakeLedger) => void;
  readonly failNextQuery: (err: Error) => void;
  readonly failNextPostVerdict: (err: Error) => void;
}

export function makeFakeChainHarness(initial?: FakeLedger): FakeChainHarness {
  let ledger: FakeLedger = initial ?? makeLedger();
  let queryError: Error | null = null;
  let postVerdictError: Error | null = null;

  const insertEntry = (entries: Map<bigint, Dispute>): void => {
    ledger = makeLedger(entries, ledger.dispute_counter);
  };

  const calls: CircuitCalls = {
    submit_dispute: [],
    post_verdict: [],
    register_platform: [],
  };

  const connection: Record<string, unknown> = {
    // connectionStatus() hexes this; reader.ts passes it back opaquely.
    contractAddress: new Uint8Array(32).fill(0xab),
    coinPublicKey: 'feedface' + '00'.repeat(28),
    providers: {
      publicDataProvider: {
        queryContractState: async () => {
          if (queryError) throw queryError;
          return { data: ledger }; // contractLedger is mocked to pass this through
        },
      },
    },
    deployed: {
      callTx: {
        submit_dispute: async (evidenceWire: Uint8Array, envelope: Uint8Array) => {
          calls.submit_dispute.push({ evidenceWire, envelope });
          // Mirror the circuit: increment-then-read allocates a fresh id, and
          // the commitment is SHA-256(wire) (§5.3, computed in-circuit).
          const id = ledger.dispute_counter + 1n;
          const record = makeDispute({
            evidence_commitment: sha256(evidenceWire),
            envelope,
          });
          const entries = new Map<bigint, Dispute>([[id, record]]);
          for (const [k, v] of ledger.disputes) entries.set(k, v);
          ledger = makeLedger(entries, id);
          return { public: { txHash: '0x'.concat('11'.repeat(32)) } };
        },
        post_verdict: async (disputeId: bigint, verdictWire: Uint8Array) => {
          calls.post_verdict.push({ disputeId, verdictWire });
          if (postVerdictError) throw postVerdictError;
          if (!ledger.disputes.member(disputeId)) {
            throw new Error('circuit assert failed: post_verdict: dispute not found');
          }
          const existing = ledger.disputes.lookup(disputeId);
          if (existing.status === 1) {
            throw new Error('circuit assert failed: post_verdict: verdict already posted');
          }
          // Mirror the circuit: commitment = SHA-256(wire); status flips once.
          const record = makeDispute({
            evidence_commitment: existing.evidence_commitment,
            envelope: existing.envelope,
            verdict_commitment: sha256(verdictWire),
            status: 1 as DisputeStatus,
          });
          const entries = new Map<bigint, Dispute>([[disputeId, record]]);
          for (const [k, v] of ledger.disputes) if (k !== disputeId) entries.set(k, v);
          insertEntry(entries);
          return { public: {} };
        },
        register_platform: async (platformPublicKey: Uint8Array) => {
          calls.register_platform.push({ platformPublicKey });
          if (ledger.platform_enc_key.some((b) => b !== 0)) {
            throw new Error('circuit assert failed: register_platform: platform key already registered');
          }
          ledger = {
            ...ledger,
            platform_enc_key: Uint8Array.from(platformPublicKey),
          };
          return { public: {} };
        },
      },
    },
    close: async () => {},
  };

  return {
    connection,
    calls,
    setLedger: (l) => {
      ledger = l;
    },
    failNextQuery: (err) => {
      queryError = err;
    },
    failNextPostVerdict: (err) => {
      postVerdictError = err;
    },
  };
}
