/**
 * Normative PROTOCOL.md §12 vectors + §5.1 hashing semantics, checked against
 * the *runtime* used by the compiled contract (not a local reimplementation).
 * If any of these drift, the toolchain no longer matches the protocol and the
 * suite must fail loudly before any behavior test runs.
 */
import { describe, expect, it } from 'vitest';

import * as runtime from '@midnight-ntwrk/compact-runtime';

import {
  ADMIN_PK_TAG,
  VECTOR_ADMIN_PK_HEX,
  VECTOR_ADMIN_SECRET,
  VECTOR_EVIDENCE_COMMITMENT_HEX,
  VECTOR_EVIDENCE_WIRE,
  VECTOR_VERDICT_COMMITMENT_HEX,
  VECTOR_VERDICT_WIRE,
  fromHex,
  hex,
  sha256,
} from './helpers.js';

describe('PROTOCOL.md §12 normative vectors (runtime vs plain SHA-256)', () => {
  it('§12.3 adminPk derivation matches the documented digest', () => {
    const viaRuntime = runtime.persistentHash(
      new runtime.CompactTypeVector(2, new runtime.CompactTypeBytes(32)),
      [ADMIN_PK_TAG, VECTOR_ADMIN_SECRET],
    );
    expect(hex(viaRuntime)).toBe(VECTOR_ADMIN_PK_HEX);
    expect(hex(sha256(ADMIN_PK_TAG, VECTOR_ADMIN_SECRET))).toBe(VECTOR_ADMIN_PK_HEX);
  });

  it('§12.1 evidence commitment is persistentHash == SHA-256 of the 256-byte wire', () => {
    const viaRuntime = runtime.persistentHash(
      new runtime.CompactTypeBytes(256),
      VECTOR_EVIDENCE_WIRE,
    );
    expect(hex(viaRuntime)).toBe(VECTOR_EVIDENCE_COMMITMENT_HEX);
    expect(hex(sha256(VECTOR_EVIDENCE_WIRE))).toBe(VECTOR_EVIDENCE_COMMITMENT_HEX);
  });

  it('§12.2 verdict commitment is persistentHash == SHA-256 of the 192-byte wire', () => {
    const viaRuntime = runtime.persistentHash(
      new runtime.CompactTypeBytes(192),
      VECTOR_WIRE_FALLBACK(VECTOR_VERDICT_WIRE),
    );
    expect(hex(viaRuntime)).toBe(VECTOR_VERDICT_COMMITMENT_HEX);
    expect(hex(sha256(VECTOR_VERDICT_WIRE))).toBe(VECTOR_VERDICT_COMMITMENT_HEX);
  });

  it('§5.1(2) vector-of-Bytes preimage is plain concatenation (domain-separated adminPk)', () => {
    const a = new Uint8Array(32).fill(0xaa);
    const b = new Uint8Array(32).fill(0xbb);
    const viaRuntime = runtime.persistentHash(
      new runtime.CompactTypeVector(2, new runtime.CompactTypeBytes(32)),
      [a, b],
    );
    expect(hex(viaRuntime)).toBe(hex(sha256(a, b)));
  });

  it('§5.1(1) trailing zero bytes of Bytes<N> are part of the preimage', () => {
    // Two 8-byte values differing only in trailing zeros must commit differently.
    const x = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 8]);
    const y = Uint8Array.from([1, 2, 3, 4, 5, 6, 7, 0]);
    const t = new runtime.CompactTypeBytes(8);
    const hx = hex(runtime.persistentHash(t, x));
    const hy = hex(runtime.persistentHash(t, y));
    expect(hx).not.toBe(hy);
    expect(hx).toBe(hex(sha256(x)));
    expect(hy).toBe(hex(sha256(y)));
  });
});

/** Identity helper kept explicit so the §12.2 assertion reads cleanly. */
function VECTOR_WIRE_FALLBACK(wire: Uint8Array): Uint8Array {
  return wire;
}

/** Ensure the hex helper round-trips (sanity for the assertions above). */
it('hex helpers round-trip', () => {
  const sample = Uint8Array.from([0, 1, 0xfe, 0xff]);
  expect(fromHex(hex(sample))).toEqual(sample);
});
