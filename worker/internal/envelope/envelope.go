// Package envelope implements the DisputeVault evidence encryption envelope
// (PROTOCOL.md §6), mirroring sdk/src/crypto.ts byte-for-byte.
//
//	ECDH(platform_priv, claimant_ephemeral_pub) -> 32-byte x-coordinate
//	AES-256-GCM(key, 12-byte nonce, plaintext = 256-byte evidence wire)
//	envelope = nonce (12) || ciphertext+tag (272)  ->  284 bytes
//
// The shared secret is the raw 32-byte x-coordinate of the ECDH point, used
// directly as the AES-256 key (WebCrypto deriveKey semantics; matches Node
// crypto.diffieHellman and Go ecdh.PrivateKey.ECDH). The §12.5 normative
// vector pins all of this bit-for-bit (internal/envelope/envelope_test.go).
//
// Unlike the SDK - which must hand-roll P-256 point math because browser
// WebCrypto cannot import a raw scalar - Go's standard crypto/ecdh accepts
// raw scalars and points natively, so no third-party or hand-rolled crypto
// is used here.
package envelope

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/ecdh"
	"crypto/rand"

	"disputevault/worker/internal/canonical"
)

const (
	NonceBytes = 12
	WireSize   = canonical.EvidenceWireSize // 256
	TagBytes   = 16
	// EnvelopeBytes = 12-byte nonce + 256-byte wire + 16-byte GCM tag.
	EnvelopeBytes = NonceBytes + WireSize + TagBytes // 284
)

// errf reuses the canonical package's ProtocolError so callers can treat all
// DisputeVault rejections uniformly.
var errf = canonical.NewProtocolError

// OpenEvidence decrypts a 284-byte envelope with the platform private key and
// the claimant's ephemeral public key (transported off-chain with the dispute
// metadata; the envelope itself stays exactly 284 bytes, §6). Returns the
// 256-byte evidence wire. Any tampering with nonce or ciphertext (including
// the tag) makes decryption fail - AES-GCM authenticates them as a unit.
//
// Callers MUST compare the decrypted wire's SHA-256 against the on-chain
// commitment before trusting the payload (PROTOCOL §6, §10).
func OpenEvidence(envelopeBytes, platformPrivateKey, ephemeralPublicKey []byte) ([]byte, error) {
	if len(envelopeBytes) != EnvelopeBytes {
		return nil, errf("envelope must be exactly %d bytes, got %d", EnvelopeBytes, len(envelopeBytes))
	}
	key, err := sharedKey(platformPrivateKey, ephemeralPublicKey)
	if err != nil {
		return nil, err
	}
	nonce := envelopeBytes[:NonceBytes]
	ciphertext := envelopeBytes[NonceBytes:]

	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	plain, openErr := gcm.Open(nil, nonce, ciphertext, nil)
	if openErr != nil {
		return nil, errf("envelope decryption failed: wrong key or tampered ciphertext/nonce (AES-GCM authentication failed)")
	}
	if len(plain) != WireSize {
		return nil, errf("decrypted evidence wire must be exactly %d bytes, got %d", WireSize, len(plain))
	}
	return plain, nil
}

// SealEvidence encrypts the 256-byte evidence wire to the platform public key
// using an ephemeral private key. Returns the 284-byte envelope:
// nonce(12) || AES-256-GCM(wire)+tag(272).
//
// The worker's production role is decrypt-only; SealEvidence exists for test
// symmetry with the SDK (sdk/src/crypto.ts sealEvidence) and for the §12.5
// vector seal-side parity check. A nonce of nil selects a fresh
// crypto/rand nonce; a deterministic nonce is accepted for vector replay.
func SealEvidence(evidenceWire, platformPublicKey, ephemeralPrivateKey, nonce []byte) ([]byte, error) {
	if len(evidenceWire) != WireSize {
		return nil, errf("evidence wire must be exactly %d bytes, got %d", WireSize, len(evidenceWire))
	}
	if nonce == nil {
		nonce = make([]byte, NonceBytes)
		if _, err := rand.Read(nonce); err != nil {
			return nil, errf("failed to generate nonce: %v", err)
		}
	}
	if len(nonce) != NonceBytes {
		return nil, errf("nonce must be exactly %d bytes, got %d", NonceBytes, len(nonce))
	}
	key, err := sharedKey(ephemeralPrivateKey, platformPublicKey)
	if err != nil {
		return nil, err
	}
	gcm, err := newGCM(key)
	if err != nil {
		return nil, err
	}
	sealed := gcm.Seal(nil, nonce, evidenceWire, nil) // 256 + 16 = 272 bytes
	out := make([]byte, 0, EnvelopeBytes)
	out = append(out, nonce...)
	out = append(out, sealed...)
	return out, nil
}

// sharedKey derives the raw 32-byte ECDH x-coordinate for the given private
// scalar and peer public point. Both keys are length- and format-checked with
// named errors before crypto/ecdh validates them cryptographically.
func sharedKey(privateKey, peerPublicKey []byte) ([]byte, error) {
	if len(privateKey) != 32 {
		return nil, errf("private key must be exactly 32 bytes, got %d", len(privateKey))
	}
	if len(peerPublicKey) != 65 || peerPublicKey[0] != 0x04 {
		return nil, errf("public key must be a 65-byte uncompressed point (0x04 || X || Y), got %d bytes", len(peerPublicKey))
	}
	curve := ecdh.P256()
	priv, err := curve.NewPrivateKey(privateKey)
	if err != nil {
		return nil, errf("invalid private key (must be a valid P-256 scalar): %v", err)
	}
	pub, err := curve.NewPublicKey(peerPublicKey)
	if err != nil {
		return nil, errf("invalid public key (not a valid P-256 point): %v", err)
	}
	shared, err := priv.ECDH(pub)
	if err != nil {
		return nil, errf("ECDH failed: %v", err)
	}
	return shared, nil
}

func newGCM(key []byte) (cipher.AEAD, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, errf("failed to initialize AES: %v", err)
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, errf("failed to initialize AES-GCM: %v", err)
	}
	return gcm, nil
}
