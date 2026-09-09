/**
 * CONTRACT ↔ SDK PARITY (the single highest-risk failure mode in the system:
 * two implementations of "the same" hash silently diverging).
 *
 * The SDK canonicalizes + frames + hashes payloads entirely offline
 * (WebCrypto SHA-256, per PROTOCOL.md §5). The contract computes commitments
 * in-circuit via persistentHash (compact-runtime 0.16.0). These tests submit
 * the SAME raw payload bytes through BOTH paths and require bit-for-bit
 * equality — isolated unit tests on either side cannot catch a divergence.
 *
 * The parity subject is not just the digest: the SDK's wire bytes are fed
 * UNCHANGED into the contract circuits, so this also proves canonicalization
 * and wire-format agreement, not merely that both sides call "SHA-256".
 */
import * as runtime from '@midnight-ntwrk/compact-runtime';
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { canonicalizeEvidence, canonicalizeVerdict } from '../src/canonical.js';
import { makeEvidenceWire, makeVerdictWire } from '../src/wire.js';
import { evidenceCommitment, sha256 } from '../src/crypto.js';
import { fromHex } from '../src/keys.js';
import { publishVerdict, type DisputeVaultContract } from '../src/publish.js';

import {
  call,
  deploy,
  getDispute,
  hex,
  makeEvidenceWire as contractMakeEvidenceWire,
  makeVerdictWire as contractMakeVerdictWire,
  ledgerView,
  VALID_ENVELOPE,
  sha256 as contractSha256,
} from '../../contract/src/test/helpers.js';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'),
);

describe('contract ↔ SDK commitment parity', () => {
  it('§12.1: SDK-built evidence wire committed on-chain equals the offline SDK hash', async () => {
    // Offline: canonicalize + frame + hash via the SDK only.
    const canonicalJson = canonicalizeEvidence(vectors.evidence.payload);
    const sdkWire = makeEvidenceWire(canonicalJson);
    const sdkCommitment = await evidenceCommitment(sdkWire);

    // On-chain: submit the SAME wire bytes through the contract simulator.
    const dv = deploy();
    const id = call(dv, 'submit_dispute', sdkWire, VALID_ENVELOPE);
    const onChain = getDispute(dv, id).evidence_commitment;

    expect(hex(onChain)).toBe(hex(sdkCommitment));
    expect(hex(onChain)).toBe(vectors.evidence.commitment); // §12.1 digest
    expect(hex(onChain)).toBe(hex(await sha256(sdkWire))); // plain SHA-256 semantics
  });

  it('§12.2: SDK-built verdict wire committed on-chain equals the offline SDK hash', async () => {
    // (a) The normative §12.2 wire itself hashes to the normative digest.
    const vectorWire = makeVerdictWire(canonicalizeVerdict(vectors.verdict.payload));
    expect(hex(await contractSha256(vectorWire))).toBe(vectors.verdict.commitment);

    // (b) End-to-end: the verdict is rebound to the actual dispute id (the
    // §7 worker rule), published through the SDK wrapper, and committed by
    // the circuit. Offline hash over THAT wire must equal the on-chain cell.
    const dv = deploy();
    const id = call(dv, 'submit_dispute', makeEvidenceWire(canonicalizeEvidence(vectors.evidence.payload)), VALID_ENVELOPE);
    let captured: Uint8Array | undefined;
    const adapter: DisputeVaultContract = {
      async postVerdict(_id, wire) {
        captured = wire;
        // Drive the contract simulator directly here (this IS the contract
        // layer in the simulator).
        call(dv, 'post_verdict', _id, wire);
      },
    };
    const result = await publishVerdict(adapter, id, {
      ...vectors.verdict.payload,
      dispute_id: Number(id),
    });
    const onChain = getDispute(dv, id).verdict_commitment;

    expect(captured).toBeDefined();
    expect(Buffer.from(captured!).equals(Buffer.from(result.verdictWire))).toBe(true);
    expect(hex(onChain)).toBe(hex(await contractSha256(result.verdictWire)));
    expect(hex(onChain)).toBe(hex(result.commitment));
    // ...and the commitment logic is the same one proven against §12.2 in (a).
  });

  it('SDK and contract wire builders produce identical bytes for arbitrary payloads', () => {
    // Not just the normative vectors: fuzz-ish agreement across sizes.
    const summaries = ['x', 'A'.repeat(63), 'Unicode — ✓ ok', 'tabs\tand\ttabs'];
    for (const summary of summaries) {
      const payload = {
        v: 1,
        bounty_id: 1234,
        claimant_id_hash: 'ab'.repeat(16),
        type: 2,
        evidence_ref_hash: 'cd'.repeat(16),
        summary,
      };
      const sdkWire = makeEvidenceWire(canonicalizeEvidence(payload));
      const contractWire = contractMakeEvidenceWire(canonicalizeEvidence(payload));
      expect(Buffer.from(sdkWire).equals(Buffer.from(contractWire))).toBe(true);
    }
    for (const decision of ['claimant_wins', 'platform_wins', 'partial', 'needs_human_review'] as const) {
      const payload = {
        v: 1,
        dispute_id: 18446744073709551615n,
        decision,
        confidence: 0,
        reason_code: 'CODE_1',
        policy_version: 'bounty-dispute-v1',
      };
      const json = canonicalizeVerdict(payload);
      const sdkWire = makeVerdictWire(json);
      const contractWire = contractMakeVerdictWire(json);
      expect(Buffer.from(sdkWire).equals(Buffer.from(contractWire))).toBe(true);
    }
  });

  it('parity holds for a full end-to-end dispute: submit → verify offline → post verdict', async () => {
    const dv = deploy();
    const payload = {
      v: 1,
      bounty_id: 777,
      claimant_id_hash: 'aa'.repeat(16),
      type: 3,
      evidence_ref_hash: 'bb'.repeat(16),
      summary: 'End-to-end parity check.',
    };
    const canonicalJson = canonicalizeEvidence(payload);
    const wire = makeEvidenceWire(canonicalJson);
    const offlineCommitment = await evidenceCommitment(wire);

    const id = call(dv, 'submit_dispute', wire, VALID_ENVELOPE);

    // A public verifier with only the payload + dispute id:
    const record = getDispute(dv, id);
    expect(hex(record.evidence_commitment)).toBe(hex(offlineCommitment));

    // Verdict path through the SDK wrapper.
    const verdictPayload = {
      v: 1 as const,
      dispute_id: Number(id),
      decision: 'needs_human_review' as const,
      confidence: 42,
      reason_code: 'ENVELOPE_MISMATCH',
      policy_version: 'bounty-dispute-v1',
    };
    const adapter: DisputeVaultContract = {
      async postVerdict(disputeId, verdictWire) {
        call(dv, 'post_verdict', disputeId, verdictWire);
      },
    };
    const result = await publishVerdict(adapter, id, verdictPayload);
    const after = getDispute(dv, id);
    expect(hex(after.verdict_commitment)).toBe(hex(result.commitment));
    expect(after.status).toBe(1);
    expect(ledgerView(dv).dispute_counter).toBe(1n);
  });

  it('adminPk parity: SDK sha256(tag||sk) equals the contract-bound authority', async () => {
    const sk = Uint8Array.from({ length: 32 }, (_, i) => i + 1);
    const tag = new TextEncoder().encode('disputevault:admin:pk');
    const padded = new Uint8Array(32);
    padded.set(tag, 0);
    // SDK-side derivation (plain SHA-256 per PROTOCOL §5.3).
    const sdkHash = await sha256(padded, sk);
    // Contract-side: deploy with the same secret; the constructor binds
    // adminPk(sk) computed in-circuit via persistentHash.
    const dv = deploy(sk);
    expect(hex(ledgerView(dv).admin_authority)).toBe(hex(sdkHash));
  });

  it('runtime persistentHash agrees with the SDK on all wire sizes', async () => {
    const cases: Array<[number, Uint8Array]> = [
      [256, fromHex(vectors.evidence.wire)],
      [192, fromHex(vectors.verdict.wire)],
    ];
    for (const [size, wire] of cases) {
      const viaRuntime = runtime.persistentHash(new runtime.CompactTypeBytes(size), wire);
      const viaSdk = await sha256(wire);
      expect(hex(viaRuntime)).toBe(hex(viaSdk));
    }
  });
});
