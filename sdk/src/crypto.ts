/**
 * DisputeVault cryptographic operations (PROTOCOL.md §5, §6).
 *
 * Commitments (§5.3):
 *   evidence_commitment = SHA256(exact 256-byte DV1E wire)
 *   verdict_commitment  = SHA256(exact 192-byte DV1V wire)
 *   (persistentHash semantics of the pinned Compact toolchain, §5.1)
 *
 * Truncated references (§5.2):
 *   first 16 bytes of SHA-256, hex-encoded (32 lowercase hex chars)
 *
 * Envelope (§6):
 *   ECDH(platform_priv, claimant_ephemeral_pub) -> 32-byte x-coordinate
 *   AES-256-GCM(key, 12-byte nonce, plaintext = 256-byte evidence wire)
 *   envelope = nonce (12) || ciphertext+tag (272)  ->  284 bytes
 *
 * All primitives are WebCrypto standard (available in browsers, Node >= 22,
 * and mirrorable by Go's standard library).
 */
import { ProtocolError } from './canonical.js';
import { importPrivateKey, importPublicKey, toBytes } from './keys.js';

export const ENVELOPE_NONCE_BYTES = 12;
export const ENVELOPE_TAG_BYTES = 16;
/** 12-byte nonce + 256-byte wire + 16-byte GCM tag. */
export const ENVELOPE_BYTES = ENVELOPE_NONCE_BYTES + 256 + ENVELOPE_TAG_BYTES;

const subtle = crypto.subtle;

// ---------------------------------------------------------------------------
// Commitments (§5)
// ---------------------------------------------------------------------------

export async function sha256(...chunks: Uint8Array[]): Promise<Uint8Array> {
  const total = chunks.reduce((a, c) => a + c.length, 0);
  const preimage = new Uint8Array(total);
  let off = 0;
  for (const c of chunks) {
    preimage.set(c, off);
    off += c.length;
  }
  const digest = await subtle.digest('SHA-256', preimage);
  return toBytes(digest);
}

/** PROTOCOL.md §5.3: commitment over the exact wire bytes. */
export const evidenceCommitment = (evidenceWire: Uint8Array): Promise<Uint8Array> => {
  expectLength(evidenceWire, 256, 'evidence wire');
  return sha256(evidenceWire);
};

/** PROTOCOL.md §5.3: commitment over the exact verdict wire bytes. */
export const verdictCommitment = (verdictWire: Uint8Array): Promise<Uint8Array> => {
  expectLength(verdictWire, 192, 'verdict wire');
  return sha256(verdictWire);
};

/** PROTOCOL.md §5.2: first 16 bytes of SHA-256, as 32 lowercase hex chars. */
export async function truncatedHash(data: Uint8Array): Promise<string> {
  const digest = await sha256(data);
  return Buffer.from(digest.subarray(0, 16)).toString('hex');
}

// ---------------------------------------------------------------------------
// Envelope (§6)
// ---------------------------------------------------------------------------

/**
 * Encrypt the 256-byte evidence wire to the platform public key.
 * Returns the 284-byte envelope: nonce(12) || AES-256-GCM(wire)+tag(272).
 *
 * The shared secret is the raw 32-byte x-coordinate of the ECDH point, used
 * directly as the AES-256 key (WebCrypto deriveKey semantics; matches Node
 * crypto.diffieHellman and Go ecdh.PrivateKey.ECDH).
 */
export async function sealEvidence(
  evidenceWire: Uint8Array,
  platformPublicKey: Uint8Array,
  ephemeralPrivateKey: Uint8Array,
  nonce?: Uint8Array,
): Promise<Uint8Array> {
  expectLength(evidenceWire, 256, 'evidence wire');
  if (nonce !== undefined) expectLength(nonce, ENVELOPE_NONCE_BYTES, 'nonce');
  const priv = await importPrivateKey(ephemeralPrivateKey);
  const pub = await importPublicKey(platformPublicKey);
  const aesKey = await deriveAesKey(priv, pub);
  const iv = nonce ?? toBytes(crypto.getRandomValues(new Uint8Array(ENVELOPE_NONCE_BYTES)));
  const ciphertext = await subtle.encrypt({ name: 'AES-GCM', iv: iv as unknown as BufferSource }, aesKey, evidenceWire as unknown as BufferSource);
  const ct = toBytes(ciphertext); // 256 + 16 tag = 272 bytes
  if (ct.length !== 272) {
    throw new ProtocolError(`unexpected ciphertext length ${ct.length}; expected 272`);
  }
  const envelope = new Uint8Array(ENVELOPE_BYTES);
  envelope.set(iv, 0);
  envelope.set(ct, ENVELOPE_NONCE_BYTES);
  return envelope;
}

/**
 * Decrypt a 284-byte envelope with the platform private key and the
 * claimant's ephemeral public key (transported off-chain with the dispute
 * metadata; the envelope itself stays exactly 284 bytes, §6). Returns the
 * 256-byte evidence wire. Any tampering with nonce or ciphertext (including
 * the tag) makes decryption fail - AES-GCM authenticates them as a unit.
 *
 * Verifiers/workers MUST compare the decrypted wire's SHA-256 against the
 * on-chain commitment before trusting the payload (PROTOCOL §6, §10).
 */
export async function openEvidence(
  envelope: Uint8Array,
  platformPrivateKey: Uint8Array,
  ephemeralPublicKey: Uint8Array,
): Promise<Uint8Array> {
  if (envelope.length !== ENVELOPE_BYTES) {
    throw new ProtocolError(
      `envelope must be exactly ${ENVELOPE_BYTES} bytes, got ${envelope.length}`,
    );
  }
  const priv = await importPrivateKey(platformPrivateKey);
  const pub = await importPublicKey(ephemeralPublicKey);
  const aesKey = await deriveAesKey(priv, pub);
  const nonce = envelope.slice(0, ENVELOPE_NONCE_BYTES);
  const ciphertext = envelope.slice(ENVELOPE_NONCE_BYTES);
  try {
    const plain = await subtle.decrypt({ name: 'AES-GCM', iv: nonce }, aesKey, ciphertext);
    const wire = toBytes(plain);
    expectLength(wire, 256, 'decrypted evidence wire');
    return wire;
  } catch {
    throw new ProtocolError(
      'envelope decryption failed: wrong key or tampered ciphertext/nonce (AES-GCM authentication failed)',
    );
  }
}

/** ECDH -> raw 32-byte x-coordinate -> AES-256-GCM CryptoKey. */
async function deriveAesKey(priv: CryptoKey, pub: CryptoKey): Promise<CryptoKey> {
  const shared = await subtle.deriveBits({ name: 'ECDH', public: pub }, priv, 256);
  return subtle.importKey('raw', shared as unknown as BufferSource, { name: 'AES-GCM' }, false, ['encrypt', 'decrypt']);
}

function expectLength(bytes: Uint8Array, len: number, what: string): void {
  if (bytes.length !== len) {
    throw new ProtocolError(`${what} must be exactly ${len} bytes, got ${bytes.length}`);
  }
}
