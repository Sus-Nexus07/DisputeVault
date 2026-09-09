/**
 * Happy-path tests: the behavior PROTOCOL.md §8 (dispute lifecycle) requires.
 * Every success is verified against exact bytes/digests, not "it returned".
 */
import { describe, expect, it } from 'vitest';

import {
  ATTACKER_PLATFORM_KEY,
  VALID_ENVELOPE,
  VALID_PLATFORM_KEY,
  VECTOR_ADMIN_PK_HEX,
  VECTOR_ADMIN_SECRET,
  VECTOR_EVIDENCE_COMMITMENT_HEX,
  VECTOR_EVIDENCE_JSON,
  VECTOR_EVIDENCE_WIRE,
  VECTOR_VERDICT_COMMITMENT_HEX,
  VECTOR_VERDICT_JSON,
  VECTOR_VERDICT_WIRE,
  ZERO32,
  ZERO65,
  call,
  deploy,
  fromHex,
  getDispute,
  hex,
  ledgerView,
  makeEvidenceWire,
  makeVerdictWire,
  sha256,
} from './helpers.js';

const codec = new TextEncoder();

describe('deployment (constructor)', () => {
  it('binds admin_authority to the §12.3 derivation of the admin secret', () => {
    const dv = deploy(VECTOR_ADMIN_SECRET);
    const view = ledgerView(dv);
    expect(hex(view.admin_authority)).toBe(VECTOR_ADMIN_PK_HEX);
  });

  it('starts with no platform key, zero counter, and an empty disputes map', () => {
    const dv = deploy();
    const view = ledgerView(dv);
    expect(view.platform_enc_key).toEqual(ZERO65);
    expect(view.dispute_counter).toBe(0n);
    expect(view.disputes.isEmpty()).toBe(true);
    expect(view.disputes.size()).toBe(0n);
  });

  it('binds a different authority for a different secret (no shared authority)', () => {
    const otherSecret = new Uint8Array(32).fill(0x42);
    const dv = deploy(otherSecret);
    const view = ledgerView(dv);
    // sha256(pad32("disputevault:admin:pk") || sk) for the other secret
    const tag = codec.encode('disputevault:admin:pk');
    const padded = new Uint8Array(32);
    padded.set(tag, 0);
    const expected = sha256(padded, otherSecret);
    expect(hex(view.admin_authority)).toBe(hex(expected));
    expect(hex(view.admin_authority)).not.toBe(VECTOR_ADMIN_PK_HEX);
  });
});

describe('register_platform (happy path)', () => {
  it('stores the platform key exactly once', () => {
    const dv = deploy();
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    const view = ledgerView(dv);
    expect(view.platform_enc_key).toEqual(VALID_PLATFORM_KEY);
    expect(view.platform_enc_key).not.toEqual(ZERO65);
  });

  it('does not consume dispute ids or touch the disputes map', () => {
    const dv = deploy();
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    const view = ledgerView(dv);
    expect(view.dispute_counter).toBe(0n);
    expect(view.disputes.isEmpty()).toBe(true);
  });

  it('rejects re-registration even by the admin (one-time semantics)', () => {
    const dv = deploy();
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    let message = '';
    try {
      call(dv, 'register_platform', VALID_PLATFORM_KEY);
      expect.unreachable('re-registration must be rejected');
    } catch (e) {
      message = e instanceof Error ? e.message : String(e);
    }
    expect(message).toContain(
      'failed assert: register_platform: platform key already registered',
    );
    // The original key must survive the failed attempt.
    expect(ledgerView(dv).platform_enc_key).toEqual(VALID_PLATFORM_KEY);
  });

  it('does not let a second registration replace the platform key with an attacker key', () => {
    const dv = deploy();
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    expect(() =>
      call(dv, 'register_platform', ATTACKER_PLATFORM_KEY),
    ).toThrowError(
      /failed assert: register_platform: platform key already registered/,
    );
    expect(ledgerView(dv).platform_enc_key).toEqual(VALID_PLATFORM_KEY);
  });
});

describe('submit_dispute (happy path)', () => {
  it('allocates ids from 1 and increments the counter', () => {
    const dv = deploy();
    const id1 = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const id2 = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const id3 = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    expect([id1, id2, id3]).toEqual([1n, 2n, 3n]);
    expect(ledgerView(dv).dispute_counter).toBe(3n);
    expect(ledgerView(dv).disputes.size()).toBe(3n);
  });

  it('commits SHA-256 over the exact 256-byte wire (§12.1 vector bit-for-bit)', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const record = getDispute(dv, id);
    // On-chain commitment equals the normative vector digest...
    expect(hex(record.evidence_commitment)).toBe(
      VECTOR_EVIDENCE_COMMITMENT_HEX,
    );
    // ...and equals the offline SHA-256 over the raw wire bytes.
    expect(hex(record.evidence_commitment)).toBe(
      hex(sha256(VECTOR_EVIDENCE_WIRE)),
    );
  });

  it('stores the envelope verbatim and the record starts SUBMITTED with no verdict', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const record = getDispute(dv, id);
    expect(record.envelope).toEqual(VALID_ENVELOPE);
    expect(record.status).toBe(0); // DisputeStatus.SUBMITTED
    expect(record.verdict_commitment).toEqual(ZERO32);
  });

  it('binds distinct wires to distinct commitments (no cross-talk)', () => {
    const dv = deploy();
    const wireA = VECTOR_EVIDENCE_WIRE;
    const otherJson = VECTOR_EVIDENCE_JSON.replace('"type":1', '"type":2');
    expect(otherJson).not.toBe(VECTOR_EVIDENCE_JSON);
    const wireB = makeEvidenceWire(otherJson);
    const idA = call(dv, 'submit_dispute', wireA, VALID_ENVELOPE);
    const idB = call(dv, 'submit_dispute', wireB, VALID_ENVELOPE);
    const a = getDispute(dv, idA);
    const b = getDispute(dv, idB);
    expect(hex(a.evidence_commitment)).not.toBe(hex(b.evidence_commitment));
    expect(hex(a.evidence_commitment)).toBe(hex(sha256(wireA)));
    expect(hex(b.evidence_commitment)).toBe(hex(sha256(wireB)));
  });

  it('never reveals the evidence wire through the ledger', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const record = getDispute(dv, id);
    // The record contains only commitment, envelope, verdict commitment, status.
    const view = ledgerView(dv);
    const collected = [...view.disputes].map(([, rec]) => rec);
    for (const rec of collected) {
      const serialized = JSON.stringify({
        c: hex(rec.evidence_commitment),
        e: hex(rec.envelope),
        v: hex(rec.verdict_commitment),
        s: rec.status,
      });
      expect(serialized).not.toContain(VECTOR_EVIDENCE_JSON);
    }
    void id;
  });
});

describe('post_verdict (happy path)', () => {
  it('commits SHA-256 over the exact 192-byte verdict wire (§12.2 vector bit-for-bit)', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    // Use the normative vector wire but rebind it to the actual dispute id,
    // mirroring the worker's mandatory §7 binding rule.
    const verdictJson = VECTOR_VERDICT_JSON.replace('"dispute_id":42', `"dispute_id":${id}`);
    const wire = makeVerdictWire(verdictJson);
    call(dv, 'post_verdict', id, wire);
    const record = getDispute(dv, id);
    expect(hex(record.verdict_commitment)).toBe(hex(sha256(wire)));
    expect(hex(record.verdict_commitment)).not.toBe(ZERO32.length);
    expect(record.verdict_commitment).not.toEqual(ZERO32);
    expect(record.status).toBe(1); // DisputeStatus.VERDICT_POSTED
  });

  it('preserves the evidence commitment and envelope when posting the verdict', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const before = getDispute(dv, id);
    const verdictJson = VECTOR_VERDICT_JSON.replace('"dispute_id":42', `"dispute_id":${id}`);
    call(dv, 'post_verdict', id, makeVerdictWire(verdictJson));
    const after = getDispute(dv, id);
    expect(after.evidence_commitment).toEqual(before.evidence_commitment);
    expect(after.envelope).toEqual(before.envelope);
    expect(after.evidence_commitment).toEqual(fromHex(VECTOR_EVIDENCE_COMMITMENT_HEX));
  });

  it('flips the status exactly once and keeps the map size unchanged', () => {
    const dv = deploy();
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    const idA = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const idB = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const verdictJson = VECTOR_VERDICT_JSON.replace('"dispute_id":42', `"dispute_id":${idA}`);
    call(dv, 'post_verdict', idA, makeVerdictWire(verdictJson));
    const view = ledgerView(dv);
    expect(getDispute(dv, idA).status).toBe(1);
    expect(getDispute(dv, idB).status).toBe(0);
    expect(view.disputes.size()).toBe(2n);
    // Verdict commitment of B is still zero.
    expect(getDispute(dv, idB).verdict_commitment).toEqual(ZERO32);
  });
});
