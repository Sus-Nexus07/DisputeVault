/**
 * Normative-vector tests (PROTOCOL.md §12): the SDK's canonicalization,
 * wire framing, and commitments must reproduce every §12 digest bit-for-bit.
 */
import { readFileSync } from 'node:fs';
import { describe, expect, it } from 'vitest';

import { canonicalizeEvidence, canonicalizeVerdict } from '../src/canonical.js';
import { makeEvidenceWire, makeVerdictWire, parseWire } from '../src/wire.js';
import { evidenceCommitment, verdictCommitment, sha256 } from '../src/crypto.js';
import { fromHex } from '../src/keys.js';

const vectors = JSON.parse(
  readFileSync(new URL('./vectors.json', import.meta.url), 'utf8'),
) as {
  evidence: { payload: unknown; canonical_json: string; canonical_json_bytes: number; wire: string; commitment: string };
  verdict: { payload: unknown; canonical_json: string; canonical_json_bytes: number; wire: string; commitment: string };
  admin_pk: { tag_hex: string; sk_hex: string; preimage_hex: string; pk: string };
  envelope: Record<string, string>;
};

describe('§12.1 evidence vector', () => {
  it('canonicalizes to the exact normative JSON', () => {
    expect(canonicalizeEvidence(vectors.evidence.payload)).toBe(vectors.evidence.canonical_json);
    expect(vectors.evidence.canonical_json_bytes).toBe(199);
  });

  it('frames the exact normative 256-byte wire', () => {
    const wire = makeEvidenceWire(vectors.evidence.canonical_json);
    expect(Buffer.from(wire).toString('hex')).toBe(vectors.evidence.wire);
    expect(wire.length).toBe(256);
  });

  it('commits to the normative digest', async () => {
    const wire = fromHex(vectors.evidence.wire);
    await expect(Buffer.from(await evidenceCommitment(wire)).toString('hex')).toBe(
      vectors.evidence.commitment,
    );
  });
});

describe('§12.2 verdict vector', () => {
  it('canonicalizes to the exact normative JSON', () => {
    expect(canonicalizeVerdict(vectors.verdict.payload)).toBe(vectors.verdict.canonical_json);
    expect(vectors.verdict.canonical_json_bytes).toBe(140);
  });

  it('frames the exact normative 192-byte wire', () => {
    const wire = makeVerdictWire(vectors.verdict.canonical_json);
    expect(Buffer.from(wire).toString('hex')).toBe(vectors.verdict.wire);
    expect(wire.length).toBe(192);
  });

  it('commits to the normative digest', async () => {
    const wire = fromHex(vectors.verdict.wire);
    await expect(Buffer.from(await verdictCommitment(wire)).toString('hex')).toBe(
      vectors.verdict.commitment,
    );
  });
});

describe('§12.3 adminPk vector', () => {
  it('reproduces the derivation from tag || sk', async () => {
    const preimage = Buffer.concat([
      fromHex(vectors.admin_pk.tag_hex),
      fromHex(vectors.admin_pk.sk_hex),
    ]);
    expect(Buffer.from(preimage).toString('hex')).toBe(vectors.admin_pk.preimage_hex);
    await expect(Buffer.from(await sha256(preimage)).toString('hex')).toBe(vectors.admin_pk.pk);
  });
});

describe('wire round-trip', () => {
  it('parses both normative wires back to their canonical JSON', () => {
    expect(parseWire('evidence', fromHex(vectors.evidence.wire)).json).toBe(
      vectors.evidence.canonical_json,
    );
    expect(parseWire('verdict', fromHex(vectors.verdict.wire)).json).toBe(
      vectors.verdict.canonical_json,
    );
  });
});
