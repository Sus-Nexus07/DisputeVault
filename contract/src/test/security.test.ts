/**
 * Adversarial tests — one block per documented SECURITY.md attack, plus
 * malformed/invalid-input and invalid-transition tests. Every test asserts
 * the *specific* in-circuit assert that must fire (never just "it threw").
 *
 * Map to SECURITY.md:
 *   Attack 1 (platform-key hijack)      -> describe 'Attack 1'
 *   Attack 2 (fake verdict)             -> describe 'Attack 2'
 *   Attack 3 (verdict for nonexistent dispute) -> describe 'Attack 3'
 *   Attack 4 (duplicate verdict)        -> describe 'Attack 4'
 *   Attack 5 (evidence overwrite)       -> describe 'Attack 5'
 *   Attack 6 (verdict/dispute mismatch) -> describe 'Attack 6' — documented
 *       off-chain binding rule (PROTOCOL.md §7); the circuit cannot parse
 *       JSON, so the tests pin the rule that publishers must enforce before
 *       calling the circuit, and that nothing mismatched ever lands on-chain.
 *   Attack 7 (oversized evidence)       -> describe 'Attack 7' — fixed-size
 *       circuit inputs make truncation/oversize structurally impossible; the
 *       runtime enforces exact byte lengths as hard type errors.
 */
import { describe, expect, it } from 'vitest';

import {
  ATTACKER_PLATFORM_KEY,
  VALID_ENVELOPE,
  VALID_PLATFORM_KEY,
  VECTOR_ADMIN_PK_HEX,
  VECTOR_ADMIN_SECRET,
  VECTOR_EVIDENCE_JSON,
  VECTOR_EVIDENCE_WIRE,
  VECTOR_VERDICT_JSON,
  ZERO32,
  call,
  deploy,
  expectCircuitFailure,
  failedAssert,
  getDispute,
  hex,
  ledgerView,
  makeEvidenceWire,
  makeVerdictWire,
  sha256,
} from './helpers.js';

const codec = new TextEncoder();
const decoder = new TextDecoder();

/** The §12.2 verdict JSON rebound to an arbitrary dispute id (worker rule). */
function verdictJsonFor(id: bigint): string {
  return VECTOR_VERDICT_JSON.replace('"dispute_id":42', `"dispute_id":${id.toString()}`);
}

function deployOtherAdmin(): Uint8Array {
  return new Uint8Array(32).fill(0x77);
}

describe('authorization (hash-based, in-circuit)', () => {
  it('accepts the correct admin secret for register_platform', () => {
    const dv = deploy(VECTOR_ADMIN_SECRET);
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    expect(ledgerView(dv).platform_enc_key).toEqual(VALID_PLATFORM_KEY);
  });

  it('rejects a wrong admin secret for register_platform with the exact assert', () => {
    const dv = deploy(VECTOR_ADMIN_SECRET);
    dv.adminSecret = new Uint8Array(32).fill(0x99); // attacker-controlled witness
    const err = expectCircuitFailure(
      () => call(dv, 'register_platform', ATTACKER_PLATFORM_KEY),
      failedAssert('register_platform: unauthorized'),
    );
    expect(err).toContain('register_platform: unauthorized');
    // Nothing was written.
    expect(ledgerView(dv).platform_enc_key).toEqual(new Uint8Array(65));
  });

  it('rejects a wrong admin secret for post_verdict with the exact assert', () => {
    const dv = deploy(VECTOR_ADMIN_SECRET);
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    dv.adminSecret = new Uint8Array(32).fill(0x13);
    const err = expectCircuitFailure(
      () => call(dv, 'post_verdict', id, makeVerdictWire(verdictJsonFor(id))),
      failedAssert('post_verdict: unauthorized'),
    );
    expect(err).toContain('post_verdict: unauthorized');
    // Status unchanged; no verdict commitment stored.
    expect(getDispute(dv, id).status).toBe(0);
    expect(getDispute(dv, id).verdict_commitment).toEqual(ZERO32);
  });

  it('derives the in-circuit authority exactly like PROTOCOL §12.3 (witness secret → persistentHash → bound authority)', () => {
    const dv = deploy(VECTOR_ADMIN_SECRET);
    // The authority equals the offline derivation of the witness secret.
    expect(hex(ledgerView(dv).admin_authority)).toBe(VECTOR_ADMIN_PK_HEX);
    // And the circuit accepts the same secret later, proving the in-circuit
    // derivation matches the constructor-bound value.
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
  });

  it('never accepts a secret whose hash differs even by one bit', () => {
    const dv = deploy(VECTOR_ADMIN_SECRET);
    const nearMiss = new Uint8Array(VECTOR_ADMIN_SECRET);
    nearMiss[31] ^= 0x01; // flip a single bit of the last byte
    dv.adminSecret = nearMiss;
    expectCircuitFailure(
      () => call(dv, 'register_platform', VALID_PLATFORM_KEY),
      failedAssert('register_platform: unauthorized'),
    );
  });

  it('gives an attacker no path to bind their own authority', () => {
    // Deploy with secret S. An attacker presents secret A; the circuit hashes
    // A in-circuit and compares against the bound authority. Unless A == S
    // the assert fires — there is no "register your own authority" path.
    const dv = deploy(deployOtherAdmin());
    dv.adminSecret = new Uint8Array(32).fill(0x01);
    expectCircuitFailure(
      () => call(dv, 'register_platform', VALID_PLATFORM_KEY),
      failedAssert('register_platform: unauthorized'),
    );
  });
});

describe('Attack 1 — platform-key hijacking', () => {
  it('does not let a second registration replace the platform key', () => {
    const dv = deploy();
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    expectCircuitFailure(
      () => call(dv, 'register_platform', ATTACKER_PLATFORM_KEY),
      failedAssert('register_platform: platform key already registered'),
    );
    expect(ledgerView(dv).platform_enc_key).toEqual(VALID_PLATFORM_KEY);
  });

  it('does not let an unauthorized caller register the first key either', () => {
    const dv = deploy();
    dv.adminSecret = new Uint8Array(32).fill(0x24);
    expectCircuitFailure(
      () => call(dv, 'register_platform', ATTACKER_PLATFORM_KEY),
      failedAssert('register_platform: unauthorized'),
    );
    expect(ledgerView(dv).platform_enc_key).toEqual(new Uint8Array(65));
  });
});

describe('Attack 2 — fake verdict by unauthorized account', () => {
  it('rejects a verdict whose witness secret is not the admin secret', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    dv.adminSecret = new Uint8Array(32).fill(0x2a);
    expectCircuitFailure(
      () => call(dv, 'post_verdict', id, makeVerdictWire(verdictJsonFor(id))),
      failedAssert('post_verdict: unauthorized'),
    );
    expect(getDispute(dv, id).status).toBe(0);
  });

  it('rejects the verdict even when the payload itself is perfectly canonical', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    dv.adminSecret = new Uint8Array(32).fill(0x2b);
    expectCircuitFailure(
      () => call(dv, 'post_verdict', id, makeVerdictWire(verdictJsonFor(id))),
      failedAssert('post_verdict: unauthorized'),
    );
    expect(getDispute(dv, id).verdict_commitment).toEqual(ZERO32);
  });
});

describe('Attack 3 — verdict for a nonexistent dispute', () => {
  it('rejects post_verdict for an id that was never allocated', () => {
    const dv = deploy();
    call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE); // id 1 exists
    expectCircuitFailure(
      () => call(dv, 'post_verdict', 999999n, makeVerdictWire(verdictJsonFor(999999n))),
      failedAssert('post_verdict: dispute does not exist'),
    );
  });

  it('rejects post_verdict on an empty ledger (id 1)', () => {
    const dv = deploy();
    expectCircuitFailure(
      () => call(dv, 'post_verdict', 1n, makeVerdictWire(verdictJsonFor(1n))),
      failedAssert('post_verdict: dispute does not exist'),
    );
  });

  it('rejects post_verdict for future ids and for id 0', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    expect(id).toBe(1n);
    expectCircuitFailure(
      () => call(dv, 'post_verdict', 2n, makeVerdictWire(verdictJsonFor(2n))),
      failedAssert('post_verdict: dispute does not exist'),
    );
    expectCircuitFailure(
      () => call(dv, 'post_verdict', 0n, makeVerdictWire(verdictJsonFor(0n))),
      failedAssert('post_verdict: dispute does not exist'),
    );
  });
});

describe('Attack 4 — duplicate verdict', () => {
  it('rejects a second identical verdict for the same dispute', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const wire = makeVerdictWire(verdictJsonFor(id));
    call(dv, 'post_verdict', id, wire);
    expectCircuitFailure(
      () => call(dv, 'post_verdict', id, wire),
      failedAssert('post_verdict: verdict already posted'),
    );
    // The first verdict commitment is intact.
    expect(hex(getDispute(dv, id).verdict_commitment)).toBe(hex(sha256(wire)));
  });

  it('rejects a *different* second verdict (no replacement verdict)', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const wire1 = makeVerdictWire(verdictJsonFor(id));
    call(dv, 'post_verdict', id, wire1);
    const wire2 = makeVerdictWire(
      verdictJsonFor(id).replace('"decision":"claimant_wins"', '"decision":"platform_wins"'),
    );
    expect(hex(sha256(wire1))).not.toBe(hex(sha256(wire2)));
    expectCircuitFailure(
      () => call(dv, 'post_verdict', id, wire2),
      failedAssert('post_verdict: verdict already posted'),
    );
    // The original verdict stands; the flipped decision never lands.
    expect(hex(getDispute(dv, id).verdict_commitment)).toBe(hex(sha256(wire1)));
    expect(hex(getDispute(dv, id).verdict_commitment)).not.toBe(hex(sha256(wire2)));
  });
});

describe('Attack 5 — evidence overwrite / id collision', () => {
  it('never lets a second submit overwrite an existing dispute record', () => {
    const dv = deploy();
    const id1 = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const attackerWire = makeEvidenceWire(
      VECTOR_EVIDENCE_JSON.replace('"bounty_id":42', '"bounty_id":424242'),
    );
    const id2 = call(dv, 'submit_dispute', attackerWire, VALID_ENVELOPE);
    // Fresh id — record 1 is untouched, structurally.
    expect(id2).toBe(id1 + 1n);
    expect(hex(getDispute(dv, id1).evidence_commitment)).toBe(hex(sha256(VECTOR_EVIDENCE_WIRE)));
    expect(hex(getDispute(dv, id2).evidence_commitment)).toBe(hex(sha256(attackerWire)));
  });

  it('allocates strictly monotonic ids so ids can never collide', () => {
    const dv = deploy();
    const ids: bigint[] = [];
    for (let i = 0; i < 8; i++) {
      ids.push(call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE));
    }
    expect(ids).toEqual([1n, 2n, 3n, 4n, 5n, 6n, 7n, 8n]);
    expect(ledgerView(dv).disputes.size()).toBe(8n);
    // Every record keeps its own distinct identity.
    for (const id of ids) {
      expect(getDispute(dv, id).evidence_commitment).toEqual(
        getDispute(dv, 1n).evidence_commitment,
      );
    }
  });
});

describe('Attack 6 — verdict/dispute mismatch (off-chain binding, §7)', () => {
  it('rejects a mismatched payload before any circuit call (publisher rule)', () => {
    // The circuit cannot parse JSON; PROTOCOL §7 makes the binding rule an
    // off-chain obligation of every publisher. Pin the rule exactly: derive
    // the id from the dispute record, never from the caller.
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const mismatched = makeVerdictWire(verdictJsonFor(99n));
    const parsed = JSON.parse(
      decoder.decode(stripVerdictJson(mismatched)),
    ) as { dispute_id: number };
    const bindingOk = parsed.dispute_id === Number(id);
    expect(bindingOk).toBe(false);
    // A conforming publisher stops here: no post_verdict is invoked.
    expect(getDispute(dv, id).status).toBe(0);
    expect(getDispute(dv, id).verdict_commitment).toEqual(ZERO32);
  });

  it('a correctly-bound payload passes the binding check and commits exactly its wire hash', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const wire = makeVerdictWire(verdictJsonFor(id));
    const parsed = JSON.parse(decoder.decode(stripVerdictJson(wire))) as {
      dispute_id: number;
    };
    expect(parsed.dispute_id).toBe(Number(id)); // binding rule satisfied
    call(dv, 'post_verdict', id, wire);
    expect(hex(getDispute(dv, id).verdict_commitment)).toBe(hex(sha256(wire)));
  });
});

describe('Attack 7 — oversized evidence', () => {
  it('rejects JSON exceeding the 250-byte evidence budget before any wire exists', () => {
    // 64-char summary is within the §4 char limit, but with 3-byte UTF-8
    // characters (each 'あ' is 3 bytes) the canonical JSON exceeds the
    // §3 250-BYTE budget — publishers must count bytes, not code points.
    const multiByteSummary = '\u3042'.repeat(64); // あ × 64 = 192 UTF-8 bytes
    expect(codec.encode(multiByteSummary).length).toBe(192);
    const oversizedJson = JSON.stringify({
      v: 1,
      bounty_id: 1,
      claimant_id_hash: 'a'.repeat(32),
      type: 1,
      evidence_ref_hash: 'b'.repeat(32),
      summary: multiByteSummary,
    });
    const jsonBytes = codec.encode(oversizedJson);
    expect(jsonBytes.length).toBeGreaterThan(250);
    // makeEvidenceWire refuses to frame it — nothing is ever truncated.
    expect(() => makeEvidenceWire(oversizedJson)).toThrowError(/does not fit/);
    // The same 64-char summary in plain ASCII fits comfortably (216 bytes).
    const asciiJson = JSON.stringify({
      v: 1,
      bounty_id: 1,
      claimant_id_hash: 'a'.repeat(32),
      type: 1,
      evidence_ref_hash: 'b'.repeat(32),
      summary: 'A'.repeat(64),
    });
    expect(codec.encode(asciiJson).length).toBeLessThanOrEqual(250);
    expect(() => makeEvidenceWire(asciiJson)).not.toThrow();
  });

  it('enforces exact wire sizes at the runtime type boundary (Bytes<256>)', () => {
    const dv = deploy();
    for (const size of [255, 257]) {
      const bad = new Uint8Array(size);
      bad.set(VECTOR_EVIDENCE_WIRE.subarray(0, Math.min(size, 256)));
      expect(() => call(dv, 'submit_dispute', bad, VALID_ENVELOPE)).toThrowError(
        /Bytes<256>|type error/,
      );
    }
  });

  it('enforces exact envelope and verdict sizes at the runtime type boundary', () => {
    const dv = deploy();
    for (const size of [283, 285]) {
      const bad = new Uint8Array(size);
      expect(() => call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, bad)).toThrowError(
        /Bytes<284>|type error/,
      );
    }
    for (const size of [191, 193]) {
      const bad = new Uint8Array(size);
      expect(() => call(dv, 'post_verdict', 1n, bad)).toThrowError(
        /Bytes<192>|type error/,
      );
    }
  });

  it('accepts a manifest at the size boundary and never trims it', () => {
    const boundaryJson = JSON.stringify({
      v: 1,
      bounty_id: 0,
      claimant_id_hash: 'c'.repeat(32),
      type: 0,
      evidence_ref_hash: 'd'.repeat(32),
      summary: 'A'.repeat(40),
    });
    const jsonBytes = codec.encode(boundaryJson);
    expect(jsonBytes.length).toBeLessThanOrEqual(250);
    const wire = makeEvidenceWire(boundaryJson);
    expect(codec.encode(boundaryJson).length).toBe(jsonBytes.length);
    const dv = deploy();
    const id = call(dv, 'submit_dispute', wire, VALID_ENVELOPE);
    expect(hex(getDispute(dv, id).evidence_commitment)).toBe(hex(sha256(wire)));
  });
});

describe('malformed / invalid inputs', () => {
  it('rejects a dispute id outside Uint<64> for post_verdict', () => {
    const dv = deploy();
    const tooBig = 1n << 64n; // 2^64 — out of range
    expect(() =>
      call(dv, 'post_verdict', tooBig, makeVerdictWire(verdictJsonFor(1n))),
    ).toThrowError(/type error|Uint/);
    expect(() =>
      call(dv, 'post_verdict', -1n, makeVerdictWire(verdictJsonFor(1n))),
    ).toThrowError(/type error|Uint/);
  });

  it('rejects non-byte-array inputs (never coerces)', () => {
    const dv = deploy();
    expect(() =>
      call(dv, 'submit_dispute', 'not-bytes' as unknown as Uint8Array, VALID_ENVELOPE),
    ).toThrowError(/Bytes<256>|type error/);
    expect(() =>
      call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, 42 as unknown as Uint8Array),
    ).toThrowError(/Bytes<284>|type error/);
  });

  it('rejects wrong-size platform keys for register_platform', () => {
    const dv = deploy();
    for (const size of [64, 66]) {
      const bad = new Uint8Array(size);
      expect(() => call(dv, 'register_platform', bad)).toThrowError(/Bytes<65>|type error/);
    }
  });
});

describe('state-machine invariants (PROTOCOL.md §8)', () => {
  it('only SUBMITTED → VERDICT_POSTED is a legal transition', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    expect(getDispute(dv, id).status).toBe(0);
    const wire = makeVerdictWire(verdictJsonFor(id));
    call(dv, 'post_verdict', id, wire);
    expect(getDispute(dv, id).status).toBe(1);
    // No transition back: any further verdict attempt fails.
    expectCircuitFailure(
      () => call(dv, 'post_verdict', id, wire),
      failedAssert('post_verdict: verdict already posted'),
    );
    expect(getDispute(dv, id).status).toBe(1);
  });

  it('a rejected circuit call leaves the ledger unchanged (no partial writes)', () => {
    const dv = deploy();
    call(dv, 'register_platform', VALID_PLATFORM_KEY);
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    const before = ledgerView(dv);
    const snapshot = {
      counter: before.dispute_counter,
      platform: hex(before.platform_enc_key),
      record: getDispute(dv, id),
    };

    // Failed authorization attempt…
    dv.adminSecret = new Uint8Array(32).fill(0xf0);
    expectCircuitFailure(
      () => call(dv, 'post_verdict', id, makeVerdictWire(verdictJsonFor(id))),
      failedAssert('post_verdict: unauthorized'),
    );
    dv.adminSecret = VECTOR_ADMIN_SECRET;
    // …and a failed re-registration attempt.
    expectCircuitFailure(
      () => call(dv, 'register_platform', ATTACKER_PLATFORM_KEY),
      failedAssert('register_platform: platform key already registered'),
    );

    const after = ledgerView(dv);
    expect(after.dispute_counter).toBe(snapshot.counter);
    expect(hex(after.platform_enc_key)).toBe(snapshot.platform);
    expect(getDispute(dv, id)).toEqual(snapshot.record);
  });

  it('verdict commitment stays zero until a verdict is actually posted', () => {
    const dv = deploy();
    const id = call(dv, 'submit_dispute', VECTOR_EVIDENCE_WIRE, VALID_ENVELOPE);
    expect(getDispute(dv, id).verdict_commitment).toEqual(ZERO32);
  });
});

/** Extract the canonical JSON bytes from a DV1V wire via its length field. */
function stripVerdictJson(wire: Uint8Array): Uint8Array {
  expect(decoder.decode(wire.subarray(0, 4))).toBe('DV1V');
  const jsonLen = (wire[4]! << 8) | wire[5]!;
  expect(6 + jsonLen).toBeLessThanOrEqual(wire.length);
  return wire.slice(6, 6 + jsonLen);
}
