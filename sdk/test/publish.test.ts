/**
 * Attack 6 (SECURITY.md §5.1, PROTOCOL.md §7): verdict/dispute binding.
 *
 * The Compact contract CANNOT enforce this binding (it cannot parse the
 * verdict's JSON). It is enforced HERE, in the SDK, BEFORE the contract's
 * post_verdict circuit is ever invoked. These tests prove exactly that:
 *
 *  - a payload whose embedded dispute_id differs from the target id is
 *    rejected, and the contract layer is NEVER called (spy stays silent);
 *  - a correctly bound payload proceeds to the contract layer with the
 *    canonical wire and the exact commitment that will land on-chain.
 */
import { describe, expect, it, vi } from 'vitest';

import { ProtocolError } from '../src/canonical.js';
import { publishVerdict, type DisputeVaultContract } from '../src/publish.js';
import { makeVerdictWire, parseWire } from '../src/wire.js';
import { verdictCommitment } from '../src/crypto.js';
import { sha256 } from '../src/crypto.js';
import { canonicalizeVerdict } from '../src/canonical.js';

const VALID_VERDICT = {
  v: 1 as const,
  dispute_id: 7,
  decision: 'claimant_wins' as const,
  confidence: 87,
  reason_code: 'PAYMENT_NOT_VERIFIED',
  policy_version: 'bounty-dispute-v1',
};

/** A strict contract spy: any call is recorded and fails the test if unexpected. */
function makeContractSpy() {
  const postVerdict = vi.fn(async (_disputeId: bigint, _verdictWire: Uint8Array) => {
    /* recorded only */
  });
  const contract: DisputeVaultContract = { postVerdict };
  return { contract, postVerdict };
}

describe('publishVerdict: Attack 6 — mismatched payload never reaches the contract', () => {
  it('rejects a verdict whose embedded dispute_id differs from the target id', async () => {
    const { contract, postVerdict } = makeContractSpy();
    const mismatched = { ...VALID_VERDICT, dispute_id: 99 }; // target will be 7

    await expect(publishVerdict(contract, 7n, mismatched)).rejects.toThrowError(
      ProtocolError,
    );
    await expect(publishVerdict(contract, 7n, mismatched)).rejects.toThrowError(
      /binding mismatch.*payload dispute_id=99.*target dispute_id=7/s,
    );

    // THE core assertion: the contract layer was never touched.
    expect(postVerdict).not.toHaveBeenCalled();
    expect(postVerdict.mock.calls.length).toBe(0);
  });

  it('rejects in both directions (payload ahead of and behind the target)', async () => {
    const { contract, postVerdict } = makeContractSpy();
    await expect(
      publishVerdict(contract, 10n, { ...VALID_VERDICT, dispute_id: 11 }),
    ).rejects.toThrowError(/binding mismatch/);
    await expect(
      publishVerdict(contract, 10n, { ...VALID_VERDICT, dispute_id: 9 }),
    ).rejects.toThrowError(/binding mismatch/);
    expect(postVerdict).not.toHaveBeenCalled();
  });

  it('rejects before canonicalization side effects could mask the mismatch', async () => {
    // A payload that is BOTH schema-invalid and mismatched must fail on the
    // binding/schema check, never reach the contract.
    const { contract, postVerdict } = makeContractSpy();
    const broken = { ...VALID_VERDICT, dispute_id: 42, decision: 'maybe' } as unknown as typeof VALID_VERDICT;
    await expect(publishVerdict(contract, 7n, broken)).rejects.toThrowError(ProtocolError);
    expect(postVerdict).not.toHaveBeenCalled();
  });

  it('still refuses to call the contract when the id matches but the payload is invalid', async () => {
    const { contract, postVerdict } = makeContractSpy();
    await expect(
      publishVerdict(contract, 7n, { ...VALID_VERDICT, confidence: 101 }),
    ).rejects.toThrowError(/confidence/);
    expect(postVerdict).not.toHaveBeenCalled();
  });

  it('rejects an out-of-range target id without calling the contract', async () => {
    const { contract, postVerdict } = makeContractSpy();
    await expect(
      publishVerdict(contract, 1n << 64n, { ...VALID_VERDICT, dispute_id: 1n << 64n }),
    ).rejects.toThrowError(/disputeId must be a bigint/);
    expect(postVerdict).not.toHaveBeenCalled();
  });

  it('rejects a missing contract adapter before anything else', async () => {
    await expect(
      publishVerdict(undefined as unknown as DisputeVaultContract, 7n, VALID_VERDICT),
    ).rejects.toThrowError(/contract adapter is required/);
  });
});

describe('publishVerdict: correctly bound payload proceeds to the contract layer', () => {
  it('calls the contract exactly once with the target id and the canonical wire', async () => {
    const { contract, postVerdict } = makeContractSpy();
    const payload = { ...VALID_VERDICT, dispute_id: 7 };

    const result = await publishVerdict(contract, 7n, payload);

    expect(postVerdict).toHaveBeenCalledTimes(1);
    const [calledId, calledWire] = postVerdict.mock.calls[0]!;
    expect(calledId).toBe(7n);
    expect(calledWire).toBeInstanceOf(Uint8Array);
    expect(calledWire.length).toBe(192);

    // The wire handed to the contract is the canonical §7 wire.
    const canonicalJson = canonicalizeVerdict(payload);
    expect(Buffer.from(calledWire).equals(Buffer.from(makeVerdictWire(canonicalJson)))).toBe(
      true,
    );
    expect(parseWire('verdict', calledWire).json).toBe(canonicalJson);

    // The returned commitment equals SHA-256 of that wire (= on-chain value).
    expect(Buffer.from(result.commitment).equals(Buffer.from(await sha256(calledWire)))).toBe(
      true,
    );
    expect(result.canonicalJson).toBe(canonicalJson);
  });

  it('accepts bigint dispute ids across the full Uint<64> range', async () => {
    const { contract, postVerdict } = makeContractSpy();
    const maxId = (1n << 64n) - 1n;
    await publishVerdict(contract, maxId, { ...VALID_VERDICT, dispute_id: maxId });
    expect(postVerdict).toHaveBeenCalledTimes(1);
    expect(postVerdict.mock.calls[0]![0]).toBe(maxId);
  });

  it('propagates contract-layer failures to the caller (no swallowing)', async () => {
    const failing: DisputeVaultContract = {
      postVerdict: async () => {
        throw new Error('gateway down');
      },
    };
    await expect(publishVerdict(failing, 7n, { ...VALID_VERDICT, dispute_id: 7 })).rejects.toThrowError(
      /gateway down/,
    );
  });

  it('the commitment returned equals verdictCommitment of the wire (on-chain parity)', async () => {
    const { contract } = makeContractSpy();
    const result = await publishVerdict(contract, 42n, {
      v: 1,
      dispute_id: 42,
      decision: 'claimant_wins',
      confidence: 87,
      reason_code: 'PAYMENT_NOT_VERIFIED',
      policy_version: 'bounty-dispute-v1',
    });
    const viaHelper = await verdictCommitment(result.verdictWire);
    expect(Buffer.from(result.commitment).equals(Buffer.from(viaHelper))).toBe(true);
  });
});
