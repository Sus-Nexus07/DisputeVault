/**
 * Commitment-security tests: PROTOCOL.md §5.3 (wire binding) and the wire
 * domain-separation rule (§3): the magic tag makes an evidence commitment
 * over one payload never collide with a verdict commitment over a *different*
 * payload, and every commitment must be bound to the exact wire bytes.
 */
import { describe, expect, it } from 'vitest';

import {
  VALID_ENVELOPE,
  VECTOR_EVIDENCE_JSON,
  VECTOR_EVIDENCE_WIRE,
  VECTOR_VERDICT_WIRE,
  call,
  deploy,
  getDispute,
  hex,
  makeEvidenceWire,
  makeVerdictWire,
  sha256,
} from './helpers.js';

describe('commitment binding', () => {
  it('binds the commitment to the full wire, including zero padding', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const committed = hex(getDispute(dv, id).evidence_commitment);

    // Hashing only the JSON portion (a classic truncation mistake) MUST NOT
    // reproduce the on-chain commitment.
    const jsonOnly = new TextEncoder().encode(VECTOR_EVIDENCE_JSON);
    expect(hex(sha256(jsonOnly))).not.toBe(committed);

    // Hashing the wire without the header MUST NOT reproduce it either.
    const noHeader = VECTOR_EVIDENCE_WIRE.slice(6);
    expect(hex(sha256(noHeader))).not.toBe(committed);

    // Only the exact 256-byte wire reproduces it.
    expect(hex(sha256(VECTOR_EVIDENCE_WIRE))).toBe(committed);
  });

  it('changes the commitment when any payload byte changes (tamper evidence)', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const committed = hex(getDispute(dv, id).evidence_commitment);

    for (const mutate of [
      (w: Uint8Array) => {
        const c = new Uint8Array(w);
        c[10] ^= 0x01; // flip one bit inside the JSON
        return c;
      },
      (w: Uint8Array) => {
        const c = new Uint8Array(w);
        c[255] = 0x01; // corrupt the zero padding
        return c;
      },
      (w: Uint8Array) => {
        const c = new Uint8Array(w);
        c[0] = 0x44 ^ 0xff; // corrupt the magic tag
        return c;
      },
    ]) {
      expect(hex(sha256(mutate(VECTOR_EVIDENCE_WIRE)))).not.toBe(committed);
    }
  });

  it('domain-separates evidence from verdict wires (magic tag, §3)', () => {
    // The same canonical JSON bytes framed as DV1E vs DV1V must commit
    // differently; an evidence commitment can never double as a verdict
    // commitment over a different payload type.
    const json =
      '{"v":1,"bounty_id":7,"claimant_id_hash":"aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","type":3,"evidence_ref_hash":"bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb","summary":"x"}';
    const evidenceWire = makeEvidenceWire(json);
    const verdictSized = new Uint8Array(192);
    // Frame the same JSON in a DV1V wire (fits: JSON is short).
    verdictSized.set(makeVerdictWire(json));
    expect(hex(sha256(evidenceWire))).not.toBe(hex(sha256(verdictSized)));
  });

  it('keeps verdict commitments independent of the evidence commitment', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const record = getDispute(dv, id);
    const verdictJson =
      '{"v":1,"dispute_id":' +
      id.toString() +
      ',"decision":"platform_wins","confidence":50,"reason_code":"INSUFFICIENT_EVIDENCE","policy_version":"bounty-dispute-v1"}';
    call(dv, 'post_verdict', id, makeVerdictWire(verdictJson));
    const after = getDispute(dv, id);
    expect(hex(after.verdict_commitment)).not.toBe(
      hex(after.evidence_commitment),
    );
    void record;
    void VECTOR_VERDICT_WIRE;
  });
});
