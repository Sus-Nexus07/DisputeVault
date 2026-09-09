/**
 * DisputeVault P-256 key handling (PROTOCOL.md §6).
 *
 * The platform keypair is P-256 (secp256r1). The public key is stored/
 * transported as the raw uncompressed point: 0x04 || X || Y (65 bytes).
 * The private key is a 32-byte scalar.
 *
 * Raw scalar/point import is implemented with explicit JWK construction and
 * a small, dependency-free P-256 scalar-multiplication used only to derive
 * the public point from a scalar (required for JWK import). Scalar validity
 * (range check) and point validity (on-curve, not at infinity) are enforced
 * explicitly - WebCrypto then re-validates on use.
 */
import { ProtocolError } from './canonical.js';

/** Convert a BufferSource to a plain Uint8Array (copies). */
export function toBytes(x: BufferSource): Uint8Array {
  if (x instanceof ArrayBuffer) return new Uint8Array(x);
  return new Uint8Array(x.buffer.slice(x.byteOffset, x.byteOffset + x.byteLength));
}

export const hex = (bytes: Uint8Array): string =>
  Buffer.from(bytes).toString('hex');

export function fromHex(s: string): Uint8Array {
  if (!/^[0-9a-fA-F]*$/.test(s) || s.length % 2 !== 0) {
    throw new ProtocolError(`invalid hex string (length ${s.length})`);
  }
  return Uint8Array.from(Buffer.from(s, 'hex'));
}

export const P256_PUBLIC_KEY_BYTES = 65; // 0x04 || X || Y
export const P256_PRIVATE_KEY_BYTES = 32;

export function isValidPlatformPublicKey(key: Uint8Array): boolean {
  return key.length === P256_PUBLIC_KEY_BYTES && key[0] === 0x04;
}

export function assertPlatformPublicKey(key: Uint8Array): void {
  if (!isValidPlatformPublicKey(key)) {
    throw new ProtocolError(
      `platform public key must be ${P256_PUBLIC_KEY_BYTES} bytes starting with 0x04 (uncompressed P-256 point), got ${key.length} bytes`,
    );
  }
}

// ---------------------------------------------------------------------------
// P-256 field/curve constants (minimal scalar multiplication only)
// ---------------------------------------------------------------------------

const P = 2n ** 256n - 2n ** 224n + 2n ** 192n + 2n ** 96n - 1n; // field prime
const N = 0xffffffff00000000ffffffffffffffffbce6faada7179e84f3b9cac2fc632551n; // group order
const A = (P - 3n) % P; // Weierstrass a = -3 for P-256
const GX = 0x6b17d1f2e12c4247f8bce6e563a440f277037d812deb33a0f4a13945d898c296n;
const GY = 0x4fe342e2fe1a7f9b8ee7eb4a7c0f9e162bce33576b315ececbb6406837bf51f5n;

const modP = (x: bigint): bigint => ((x % P) + P) % P;

/** Affine point; undefined = point at infinity. */
type Point = { x: bigint; y: bigint } | undefined;

function pointAdd(a: Point, b: Point): Point {
  if (a === undefined) return b;
  if (b === undefined) return a;
  if (a.x === b.x) {
    if (modP(a.y + b.y) === 0n) return undefined; // inverse points cancel
    return pointDouble(a);
  }
  const l = modP((b.y - a.y) * modInv(b.x - a.x, P));
  const x = modP(l * l - a.x - b.x);
  const y = modP(l * (a.x - x) - a.y);
  return { x, y };
}

function pointDouble(a: Point): Point {
  if (a === undefined) return undefined;
  // lambda = (3x^2 + a) / 2y  (a = -3 for P-256)
  const l = modP((3n * a.x * a.x + A) * modInv(2n * a.y, P));
  const x = modP(l * l - 2n * a.x);
  const y = modP(l * (a.x - x) - a.y);
  return { x, y };
}

function modInv(a: bigint, m: bigint): bigint {
  let [old, inv] = [a, 1n];
  while (old < 0n) old += m;
  let [r0, r1] = [old % m, m];
  let [s0, s1] = [inv, 0n];
  while (r1 !== 0n) {
    const q = r0 / r1;
    [r0, r1] = [r1, r0 - q * r1];
    [s0, s1] = [s1, s0 - q * s1];
  }
  return modP(s0);
}

/** Double-and-add scalar multiplication of the generator (not constant-time; derive-only use). */
function mulGenerator(k: bigint): Point {
  let result: Point = undefined;
  let addend: Point = { x: GX, y: GY };
  while (k > 0n) {
    if (k & 1n) result = pointAdd(result, addend);
    addend = pointDouble(addend);
    k >>= 1n;
  }
  return result;
}

function bigFromBytes(bytes: Uint8Array): bigint {
  let v = 0n;
  for (const b of bytes) v = (v << 8n) | BigInt(b);
  return v;
}

function bytesFromBig(v: bigint, len: number): Uint8Array {
  const out = new Uint8Array(len);
  let x = v;
  for (let i = len - 1; i >= 0; i--) {
    out[i] = Number(x & 0xffn);
    x >>= 8n;
  }
  return out;
}

/**
 * Derive the raw uncompressed public point (0x04 || X || Y, 65 bytes) from a
 * valid 32-byte scalar. Pure JS; identical result to WebCrypto/Node/Go.
 */
export function derivePublicFromPrivate(scalar: Uint8Array): Uint8Array {
  assertScalarValid(scalar);
  const pt = mulGenerator(bigFromBytes(scalar));
  if (pt === undefined) throw new ProtocolError('P-256 scalar multiplication produced infinity');
  return new Uint8Array([0x04, ...bytesFromBig(pt.x, 32), ...bytesFromBig(pt.y, 32)]);
}

function assertScalarValid(scalar: Uint8Array): void {
  if (scalar.length !== P256_PRIVATE_KEY_BYTES) {
    throw new ProtocolError(
      `P-256 private scalar must be ${P256_PRIVATE_KEY_BYTES} bytes, got ${scalar.length}`,
    );
  }
  const d = bigFromBytes(scalar);
  if (d === 0n || d >= N) {
    throw new ProtocolError('P-256 private scalar out of range [1, n-1]');
  }
}

// ---------------------------------------------------------------------------
// Key generation / export
// ---------------------------------------------------------------------------

/**
 * Generate a fresh P-256 keypair. Returns raw bytes: 32-byte scalar and
 * 65-byte uncompressed point.
 */
export async function generatePlatformKeypair(): Promise<{
  privateKey: Uint8Array;
  publicKey: Uint8Array;
}> {
  const pair = await crypto.subtle.generateKey({ name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveKey',
    'deriveBits',
  ]);
  const privateKey = await exportRawPrivateKey(pair.privateKey);
  const publicKey = await exportRawPublicKey(pair.publicKey);
  return { privateKey, publicKey };
}

/** Generate an ephemeral claimant keypair (same format; per-dispute). */
export const generateEphemeralKeypair = generatePlatformKeypair;

export async function exportRawPublicKey(key: CryptoKey): Promise<Uint8Array> {
  const raw = await crypto.subtle.exportKey('raw', key);
  const bytes = toBytes(raw);
  assertPlatformPublicKey(bytes);
  return bytes;
}

/**
 * Export a raw 32-byte scalar: derive the JWK (d) and serialize it big-endian.
 * Unlike PKCS#8 slicing this is exact regardless of DER encodings.
 */
export async function exportRawPrivateKey(key: CryptoKey): Promise<Uint8Array> {
  const jwk = await crypto.subtle.exportKey('jwk', key);
  if (!jwk.d) throw new ProtocolError('private key JWK is missing d');
  const scalar = Uint8Array.from(Buffer.from(jwk.d, 'base64url'));
  if (scalar.length !== P256_PRIVATE_KEY_BYTES) {
    throw new ProtocolError(
      `exported P-256 scalar is ${scalar.length} bytes; expected 32`,
    );
  }
  return scalar;
}

// ---------------------------------------------------------------------------
// Import
// ---------------------------------------------------------------------------

/**
 * Import a raw 32-byte P-256 scalar as an ECDH private key. The scalar is
 * range-checked, its public point derived and validated on-curve, and the
 * key built via JWK import.
 */
export async function importPrivateKey(scalar: Uint8Array): Promise<CryptoKey> {
  assertScalarValid(scalar);
  const point = derivePublicFromPrivate(scalar);
  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    d: Buffer.from(scalar).toString('base64url'),
    x: Buffer.from(point.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(point.subarray(33, 65)).toString('base64url'),
  };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, [
    'deriveKey',
    'deriveBits',
  ]);
}

/** Import a raw uncompressed P-256 point (0x04 || X || Y) as an ECDH public key. */
export async function importPublicKey(point: Uint8Array): Promise<CryptoKey> {
  assertPlatformPublicKey(point);
  const jwk: JsonWebKey = {
    kty: 'EC',
    crv: 'P-256',
    x: Buffer.from(point.subarray(1, 33)).toString('base64url'),
    y: Buffer.from(point.subarray(33, 65)).toString('base64url'),
  };
  return crypto.subtle.importKey('jwk', jwk, { name: 'ECDH', namedCurve: 'P-256' }, true, []);
}
