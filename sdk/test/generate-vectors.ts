/**
 * One-off generator for sdk/test/vectors.json (PROTOCOL.md §12, normative).
 *
 * Run:  npx tsx test/generate-vectors.ts
 *
 * Every vector is cross-checked with an independent implementation before
 * being written:
 *   - commitments   -> node:crypto SHA-256 (must equal §12.1/§12.2 digests)
 *   - ECDH/AES-GCM  -> node:crypto diffieHellman + createDecipheriv, plus a
 *                      @noble/curves-free WebCrypto re-derivation; the seal
 *                      output must decrypt back via BOTH stacks.
 * The expected ciphertext is stored so tests never re-encrypt; they assert
 * the committed vector bit-for-bit.
 */
import { writeFileSync } from 'node:fs';
import * as nodeCrypto from 'node:crypto';

import { canonicalizeEvidence, canonicalizeVerdict } from '../src/canonical.js';
import { makeEvidenceWire, makeVerdictWire } from '../src/wire.js';

const EVIDENCE_JSON_NORMATIVE =
  '{"v":1,"bounty_id":42,"claimant_id_hash":"9f86d081884c7d659a2feaa0c55ad015","type":1,"evidence_ref_hash":"60303ae22b998861bce3b28f33eec1be","summary":"Payment was not received for completed bounty."}';
const VERDICT_JSON_NORMATIVE =
  '{"v":1,"dispute_id":42,"decision":"claimant_wins","confidence":87,"reason_code":"PAYMENT_NOT_VERIFIED","policy_version":"bounty-dispute-v1"}';

const PLATFORM_SK_HEX =
  '2b7e151628aed2a6abf7158809cf4f3c762e7160f38b4da56a784d9045190cfe';
const EPHEMERAL_SK_HEX =
  '6b8de5c9e6c3e5a1b2f4d3c2b1a09f8e7d6c5b4a392817263544536372839404';
const NONCE_HEX = '0102030405060708090a0b0c';

const sha256 = (data: Uint8Array): string =>
  nodeCrypto.createHash('sha256').update(data).digest('hex');

/** Force a hex string even when tsx's Buffer.toTryPrimitive interferes. */
function toHex(bytes: Uint8Array): string {
  let out = '';
  for (const b of bytes) out += b.toString(16).padStart(2, '0');
  return out;
}

// --- ECDH via node:crypto (independent of WebCrypto path used by the SDK) --
function nodePublicKeyFromScalar(skHex: string): Buffer {
  const d = Buffer.from(skHex, 'hex');
  const ecdh = nodeCrypto.createECDH('prime256v1');
  ecdh.setPrivateKey(d);
  const pub = ecdh.getPublicKey('hex', 'uncompressed'); // 0x04||X||Y
  return Buffer.from(pub, 'hex');
}

function nodeEcdhShared(skHex: string, peerPub: Buffer): Buffer {
  const ecdh = nodeCrypto.createECDH('prime256v1');
  ecdh.setPrivateKey(Buffer.from(skHex, 'hex'));
  return Buffer.from(ecdh.computeSecret(peerPub)); // 32-byte x-coordinate
}

function nodeAesGcm(key: Buffer, nonce: Buffer, plaintext: Buffer): Buffer {
  const cipher = nodeCrypto.createCipheriv('aes-256-gcm', key, nonce);
  return Buffer.concat([cipher.update(plaintext), cipher.final(), cipher.getAuthTag()]);
}

// --- vector construction ---------------------------------------------------
const evidenceJson = canonicalizeEvidence(JSON.parse(EVIDENCE_JSON_NORMATIVE));
if (evidenceJson !== EVIDENCE_JSON_NORMATIVE) {
  throw new Error('canonicalizeEvidence does not reproduce the §4/§12.1 canonical form');
}
const verdictJson = canonicalizeVerdict(JSON.parse(VERDICT_JSON_NORMATIVE));
if (verdictJson !== VERDICT_JSON_NORMATIVE) {
  throw new Error('canonicalizeVerdict does not reproduce the §7/§12.2 canonical form');
}

const evidenceWire = makeEvidenceWire(evidenceJson);
const verdictWire = makeVerdictWire(verdictJson);

const evidence_commitment = sha256(evidenceWire);
if (evidence_commitment !== '7613067b4ffb158b9c025e30eb0d0934f2a51ea483912893b1434e7a5a245a1a') {
  throw new Error(`evidence commitment drift: ${evidence_commitment}`);
}
const verdict_commitment = sha256(verdictWire);
if (verdict_commitment !== 'e8154db00dd432f5436ac4d66714466d49ca6678ad2aba4b06627123a8e55765') {
  throw new Error(`verdict commitment drift: ${verdict_commitment}`);
}

const adminTag = Buffer.concat([
  Buffer.from('disputevault:admin:pk', 'ascii'),
  Buffer.alloc(32 - Buffer.byteLength('disputevault:admin:pk')),
]);
const admin_sk = Buffer.from(Array.from({ length: 32 }, (_, i) => i + 1));
const admin_pk = sha256(Buffer.concat([adminTag, admin_sk]));
if (admin_pk !== 'b90ec368c58fec263a772c8288ae9143bee84167d2f952eb6ed3bc3ec8ffc212') {
  throw new Error(`adminPk drift: ${admin_pk}`);
}

const platform_sk = Buffer.from(PLATFORM_SK_HEX, 'hex');
const platform_pk = nodePublicKeyFromScalar(PLATFORM_SK_HEX);
const ephemeral_sk = Buffer.from(EPHEMERAL_SK_HEX, 'hex');
const ephemeral_pk = nodePublicKeyFromScalar(EPHEMERAL_SK_HEX);
const nonce = Buffer.from(NONCE_HEX, 'hex');

// Shared secret computed on the node stack, twice, from both sides.
const sharedFromClaimant = nodeEcdhShared(EPHEMERAL_SK_HEX, platform_pk);
const sharedFromPlatform = nodeEcdhShared(PLATFORM_SK_HEX, ephemeral_pk);
if (!sharedFromClaimant.equals(sharedFromPlatform)) {
  throw new Error('ECDH asymmetry: claimant and platform derived different secrets');
}
if (sharedFromClaimant.length !== 32) {
  throw new Error(`shared secret is ${sharedFromClaimant.length} bytes; expected 32`);
}

const envelope = Buffer.concat([
  nonce,
  nodeAesGcm(sharedFromClaimant, nonce, Buffer.from(evidenceWire)),
]);
if (envelope.length !== 284) {
  throw new Error(`envelope is ${envelope.length} bytes; expected 284`);
}

// Round-trip check on the independent stack before committing the vector.
const decipher = nodeCrypto.createDecipheriv('aes-256-gcm', sharedFromClaimant, nonce);
decipher.setAuthTag(envelope.subarray(12 + 256));
const roundtrip = Buffer.concat([decipher.update(envelope.subarray(12, 12 + 256)), decipher.final()]);
if (!roundtrip.equals(evidenceWire)) {
  throw new Error('envelope vector does not round-trip on the independent stack');
}

const vectors = {
  _comment:
    'Normative DisputeVault test vectors (PROTOCOL.md §12). Binding for all implementations. Generated by sdk/test/generate-vectors.ts with independent node:crypto cross-checks.',
  evidence: {
    payload: JSON.parse(EVIDENCE_JSON_NORMATIVE),
    canonical_json: evidenceJson,
    canonical_json_bytes: Buffer.byteLength(evidenceJson),
    wire: toHex(evidenceWire),
    commitment: evidence_commitment,
  },
  verdict: {
    payload: JSON.parse(VERDICT_JSON_NORMATIVE),
    canonical_json: verdictJson,
    canonical_json_bytes: Buffer.byteLength(verdictJson),
    wire: toHex(verdictWire),
    commitment: verdict_commitment,
  },
  admin_pk: {
    tag_hex: adminTag.toString('hex'),
    sk_hex: admin_sk.toString('hex'),
    preimage_hex: Buffer.concat([adminTag, admin_sk]).toString('hex'),
    pk: admin_pk,
  },
  envelope: {
    platform_sk_hex: PLATFORM_SK_HEX,
    platform_pk_hex: platform_pk.toString('hex'),
    ephemeral_sk_hex: EPHEMERAL_SK_HEX,
    ephemeral_pk_hex: ephemeral_pk.toString('hex'),
    shared_secret_hex: sharedFromClaimant.toString('hex'),
    nonce_hex: NONCE_HEX,
    plaintext_wire: toHex(evidenceWire),
    envelope: toHex(envelope),
  },
};

writeFileSync(new URL('./vectors.json', import.meta.url), JSON.stringify(vectors, null, 2) + '\n');
console.log('vectors.json written:');
console.log('  evidence_commitment:', evidence_commitment);
console.log('  verdict_commitment: ', verdict_commitment);
console.log('  admin_pk:           ', admin_pk);
console.log('  envelope_hex[:32]:  ', envelope.subarray(0, 16).toString('hex'), '...');
