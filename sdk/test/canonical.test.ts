/**
 * Canonicalization, wire, and crypto unit tests: valid data, malformed data,
 * tampering, wrong-key decryption. Every rejection names the violated rule.
 */
import { describe, expect, it } from 'vitest';
import { readFileSync } from 'node:fs';

import { canonicalizeEvidence, canonicalizeVerdict, ProtocolError } from '../src/canonical.js';
import { makeEvidenceWire, makeVerdictWire, parseWire } from '../src/wire.js';
import { ENVELOPE_BYTES, openEvidence, sealEvidence, sha256 } from '../src/crypto.js';
import { fromHex, generatePlatformKeypair } from '../src/keys.js';
import { WIRE } from '../src/schema.js';

const VALID_EVIDENCE = {
  v: 1,
  bounty_id: 42,
  claimant_id_hash: '9f86d081884c7d659a2feaa0c55ad015',
  type: 1,
  evidence_ref_hash: '60303ae22b998861bce3b28f33eec1be',
  summary: 'Payment was not received for completed bounty.',
};

const VALID_VERDICT = {
  v: 1,
  dispute_id: 42,
  decision: 'claimant_wins' as const,
  confidence: 87,
  reason_code: 'PAYMENT_NOT_VERIFIED',
  policy_version: 'bounty-dispute-v1',
};

describe('canonical JSON: valid data', () => {
  it('uses schema field order, not alphabetical order', () => {
    const json = canonicalizeEvidence(VALID_EVIDENCE);
    expect(json.startsWith('{"v":1,"bounty_id":42,"claimant_id_hash"')).toBe(true);
    expect(json.indexOf('"type"')).toBeLessThan(json.indexOf('"evidence_ref_hash"'));
    expect(json.indexOf('"evidence_ref_hash"')).toBeLessThan(json.indexOf('"summary"'));
  });

  it('emits exactly the normative bytes (no structural whitespace)', () => {
    const json = canonicalizeEvidence(VALID_EVIDENCE);
    // Byte-exact against the normative §4 example: any injected whitespace
    // (or different escaping) would fail this literal comparison.
    expect(json).toBe(
      '{"v":1,"bounty_id":42,"claimant_id_hash":"9f86d081884c7d659a2feaa0c55ad015","type":1,"evidence_ref_hash":"60303ae22b998861bce3b28f33eec1be","summary":"Payment was not received for completed bounty."}',
    );
    expect(Buffer.byteLength(json)).toBe(199);
  });

  it('accepts bigint dispute ids and emits plain decimal', () => {
    const json = canonicalizeVerdict({ ...VALID_VERDICT, dispute_id: 18446744073709551615n });
    expect(json).toContain('"dispute_id":18446744073709551615');
  });

  it('escapes control characters minimally and keeps non-ASCII raw', () => {
    const json = canonicalizeEvidence({
      ...VALID_EVIDENCE,
      summary: 'line\u0001break"quoted" \\ backslash — ok',
    });
    expect(json).toContain('\\u0001'); // control char -> \u00XX
    expect(json).toContain('\\"quoted\\"');
    expect(json).toContain('\\\\');
    expect(json).toContain('—'); // raw UTF-8, not \u2014
    expect(json).not.toContain('\\u2014');
    // Tab must also be escaped as \u0009 (minimal escaping has no \t shorthand rule).
    const tabbed = canonicalizeEvidence({ ...VALID_EVIDENCE, summary: 'a\tb' });
    expect(tabbed).toContain('\\u0009');
  });

  it('sorts nothing: byte-identical output for equal payloads, different key insertion order', () => {
    const a = canonicalizeEvidence(VALID_EVIDENCE);
    const b = canonicalizeEvidence({
      summary: VALID_EVIDENCE.summary,
      evidence_ref_hash: VALID_EVIDENCE.evidence_ref_hash,
      type: VALID_EVIDENCE.type,
      claimant_id_hash: VALID_EVIDENCE.claimant_id_hash,
      bounty_id: VALID_EVIDENCE.bounty_id,
      v: 1,
    });
    expect(a).toBe(b); // schema order wins over input order
  });
});

describe('canonical JSON: malformed data', () => {
  const cases: Array<[string, unknown, RegExp]> = [
    ['unknown field', { ...VALID_EVIDENCE, extra: 1 }, /unknown field: extra/],
    ['missing field', { ...VALID_EVIDENCE, summary: undefined }, /summary must be a string/],
    ['wrong v', { ...VALID_EVIDENCE, v: 2 }, /v must be 1/],
    ['negative bounty_id', { ...VALID_EVIDENCE, bounty_id: -1 }, /bounty_id/],
    ['bounty_id above Uint<32>', { ...VALID_EVIDENCE, bounty_id: 4294967296 }, /bounty_id/],
    ['fractional bounty_id', { ...VALID_EVIDENCE, bounty_id: 1.5 }, /bounty_id/],
    ['uppercase hex hash', { ...VALID_EVIDENCE, claimant_id_hash: 'A'.repeat(32) }, /claimant_id_hash/],
    ['short hex hash', { ...VALID_EVIDENCE, evidence_ref_hash: 'ab'.repeat(15) }, /evidence_ref_hash/],
    ['type out of enum', { ...VALID_EVIDENCE, type: 4 }, /type must be one of/],
    ['summary too long', { ...VALID_EVIDENCE, summary: 'A'.repeat(65) }, /summary exceeds 64/],
    ['non-object payload', 'nope', /must be a JSON object/],
  ];
  for (const [name, payload, re] of cases) {
    it(`rejects ${name}`, () => {
      expect(() => canonicalizeEvidence(payload)).toThrowError(ProtocolError);
      expect(() => canonicalizeEvidence(payload)).toThrowError(re);
    });
  }

  it('rejects verdict schema violations with specific messages', () => {
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, decision: 'maybe' })).toThrowError(
      /decision must be one of/,
    );
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, confidence: 101 })).toThrowError(/confidence/);
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, confidence: -1 })).toThrowError(/confidence/);
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, reason_code: 'lower-case' })).toThrowError(
      /reason_code/,
    );
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, reason_code: 'A'.repeat(33) })).toThrowError(
      /reason_code/,
    );
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, policy_version: 'UPPER' })).toThrowError(
      /policy_version/,
    );
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, dispute_id: 1n << 64n })).toThrowError(
      /dispute_id/,
    );
    expect(() => canonicalizeVerdict({ ...VALID_VERDICT, extra: true })).toThrowError(/unknown field/);
  });

  it('rejects oversized canonical JSON at the byte budget (never truncates)', () => {
    // 60 chars is within the §4 64-char limit; with 3-byte UTF-8 chars the
    // BYTE budget is exceeded, so canonicalizeEvidence must reject outright.
    const payload = { ...VALID_EVIDENCE, summary: 'あ'.repeat(60) };
    expect(() => canonicalizeEvidence(payload)).toThrowError(ProtocolError);
    expect(() => canonicalizeEvidence(payload)).toThrowError(
      /rejected, never truncated/,
    );
  });
});

describe('wire format', () => {
  it('writes magic + uint16be length + JSON + zero padding', () => {
    const wire = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    expect(wire.length).toBe(256);
    expect(Buffer.from(wire.subarray(0, 4)).toString('ascii')).toBe('DV1E');
    expect((wire[4]! << 8) | wire[5]!).toBe(199);
    for (const b of wire.subarray(6 + 199)) {
      expect(b).toBe(0);
    }
  });

  it('round-trips through parseWire', () => {
    const json = canonicalizeEvidence(VALID_EVIDENCE);
    expect(parseWire('evidence', makeEvidenceWire(json)).json).toBe(json);
    const vjson = canonicalizeVerdict(VALID_VERDICT);
    expect(parseWire('verdict', makeVerdictWire(vjson)).json).toBe(vjson);
  });

  it('rejects wrong-size wires', () => {
    expect(() => parseWire('evidence', new Uint8Array(255))).toThrowError(/exactly 256/);
    expect(() => parseWire('verdict', new Uint8Array(193))).toThrowError(/exactly 192/);
  });

  it('rejects wrong magic / cross-type wires (domain separation)', () => {
    const v = makeVerdictWire(canonicalizeVerdict(VALID_VERDICT));
    expect(() => parseWire('evidence', v)).toThrowError(/must be exactly 256 bytes/);
    const e = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    expect(() => parseWire('verdict', e)).toThrowError(/must be exactly 192 bytes/);
    // Same-size wires with a swapped magic are caught by the magic check.
    const vAsE = new Uint8Array(v);
    vAsE.set(new TextEncoder().encode('DV1E'), 0);
    expect(() => parseWire('verdict', vAsE)).toThrowError(/magic must be "DV1V"/);
  });

  it('rejects inconsistent json_len and non-zero padding', () => {
    const wire = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    wire[5] = 200; // json_len 200 > actual JSON 199: extra "byte" is padding
    expect(() => parseWire('evidence', wire)).toThrowError();
    const wire2 = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    wire2[255] = 1; // padding corruption
    expect(() => parseWire('evidence', wire2)).toThrowError(/non-zero padding/);
  });
});

describe('envelope encryption', () => {
  it('seals to exactly 284 bytes and opens back to the original wire', async () => {
    const { privateKey: platformSk, publicKey: platformPk } = await generatePlatformKeypair();
    const { privateKey: ephSk, publicKey: ephPk } = await generatePlatformKeypair();
    const wire = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    const envelope = await sealEvidence(wire, platformPk, ephSk);
    expect(envelope.length).toBe(ENVELOPE_BYTES);
    const opened = await openEvidence(envelope, platformSk, ephPk);
    expect(Buffer.from(opened).equals(Buffer.from(wire))).toBe(true);
  });

  it('produces a different ciphertext for a different nonce (same plaintext)', async () => {
    const { privateKey: platformSk, publicKey: platformPk } = await generatePlatformKeypair();
    const { privateKey: ephSk } = await generatePlatformKeypair();
    const wire = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    const n1 = new Uint8Array(12).fill(1);
    const n2 = new Uint8Array(12).fill(2);
    const e1 = await sealEvidence(wire, platformPk, ephSk, n1);
    const e2 = await sealEvidence(wire, platformPk, ephSk, n2);
    expect(Buffer.from(e1).equals(Buffer.from(e2))).toBe(false);
    expect(Buffer.from(e1.subarray(0, 12)).toString('hex')).toBe('01'.repeat(12));
  });

  it('fails decryption on tampered ciphertext (GCM authenticates nonce+ct as a unit)', async () => {
    const { privateKey: platformSk, publicKey: platformPk } = await generatePlatformKeypair();
    const { privateKey: ephSk, publicKey: ephPk } = await generatePlatformKeypair();
    const wire = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    const envelope = await sealEvidence(wire, platformPk, ephSk);
    const tampered = new Uint8Array(envelope);
    tampered[100] ^= 0x01;
    await expect(openEvidence(tampered, platformSk, ephPk)).rejects.toThrowError(
      /decryption failed|tampered/,
    );
    // Tampering with the nonce also fails.
    const tampered2 = new Uint8Array(envelope);
    tampered2[3] ^= 0x80;
    await expect(openEvidence(tampered2, platformSk, ephPk)).rejects.toThrowError(
      /decryption failed|tampered/,
    );
  });

  it('fails decryption with the wrong platform key (wrong-key attack)', async () => {
    const { privateKey: platformSk, publicKey: platformPk } = await generatePlatformKeypair();
    const { privateKey: otherSk } = await generatePlatformKeypair();
    const { privateKey: ephSk, publicKey: ephPk } = await generatePlatformKeypair();
    const wire = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    const envelope = await sealEvidence(wire, platformPk, ephSk);
    await expect(openEvidence(envelope, otherSk, ephPk)).rejects.toThrowError(
      /decryption failed|wrong key/,
    );
    void platformSk;
  });

  it('rejects malformed envelopes and non-canonical keys with named errors', async () => {
    const { privateKey: platformSk, publicKey: platformPk } = await generatePlatformKeypair();
    const { privateKey: ephSk } = await generatePlatformKeypair();
    const wire = makeEvidenceWire(canonicalizeEvidence(VALID_EVIDENCE));
    await expect(sealEvidence(wire.subarray(1), platformPk, ephSk)).rejects.toThrowError(
      /evidence wire must be exactly 256/,
    );
    await expect(sealEvidence(wire, platformPk.subarray(1), ephSk)).rejects.toThrowError(
      /platform public key/,
    );
    const envelope = await sealEvidence(wire, platformPk, ephSk);
    await expect(openEvidence(envelope.subarray(0, 283), platformSk, platformPk)).rejects.toThrowError(
      /exactly 284/,
    );
  });

  it('agrees with the §12.5 committed vector bit-for-bit', async () => {
    const vectors = JSON.parse(readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'));
    const v = vectors.envelope;
    const sealed = await sealEvidence(
      fromHex(v.plaintext_wire),
      fromHex(v.platform_pk_hex),
      fromHex(v.ephemeral_sk_hex),
      fromHex(v.nonce_hex),
    );
    expect(Buffer.from(sealed).toString('hex')).toBe(v.envelope);
    const opened = await openEvidence(fromHex(v.envelope), fromHex(v.platform_sk_hex), fromHex(v.ephemeral_pk_hex));
    expect(Buffer.from(opened).toString('hex')).toBe(v.plaintext_wire);
  });
});
