// Package commitment computes DisputeVault SHA-256 commitments
// (PROTOCOL.md §5), mirroring sdk/src/crypto.ts.
//
//	evidence_commitment = SHA256(exact 256-byte DV1E wire)
//	verdict_commitment  = SHA256(exact 192-byte DV1V wire)
//	adminPk(sk)         = SHA256(pad32("disputevault:admin:pk") || sk)
//
// persistentHash (Compact toolchain, §5.1) equals plain SHA-256 over the raw
// wire bytes / concatenation, which the normative §12 vectors pin.
package commitment

import (
	"crypto/sha256"

	"disputevault/worker/internal/canonical"
)

// AdminPKTag is pad(32, "disputevault:admin:pk") - the in-circuit domain tag.
var AdminPKTag = func() []byte {
	tag := []byte("disputevault:admin:pk")
	out := make([]byte, 32)
	copy(out, tag)
	return out
}()

// Evidence returns SHA256 over the exact 256-byte evidence wire.
func Evidence(evidenceWire []byte) ([]byte, error) {
	if len(evidenceWire) != canonical.EvidenceWireSize {
		return nil, canonical.NewProtocolError(
			"evidence wire must be exactly %d bytes, got %d",
			canonical.EvidenceWireSize, len(evidenceWire))
	}
	h := sha256.Sum256(evidenceWire)
	return h[:], nil
}

// Verdict returns SHA256 over the exact 192-byte verdict wire.
func Verdict(verdictWire []byte) ([]byte, error) {
	if len(verdictWire) != canonical.VerdictWireSize {
		return nil, canonical.NewProtocolError(
			"verdict wire must be exactly %d bytes, got %d",
			canonical.VerdictWireSize, len(verdictWire))
	}
	h := sha256.Sum256(verdictWire)
	return h[:], nil
}

// AdminPk derives the admin authority from a 32-byte secret:
// SHA256(pad32("disputevault:admin:pk") || sk) (PROTOCOL §5.3, §12.3).
func AdminPk(sk []byte) ([]byte, error) {
	if len(sk) != 32 {
		return nil, canonical.NewProtocolError(
			"admin secret must be exactly 32 bytes, got %d", len(sk))
	}
	preimage := make([]byte, 0, 64)
	preimage = append(preimage, AdminPKTag...)
	preimage = append(preimage, sk...)
	h := sha256.Sum256(preimage)
	return h[:], nil
}

// TruncatedHash returns the first 16 bytes of SHA-256 as 32 lowercase hex
// chars (PROTOCOL §5.2) - the form used by claimant_id_hash and
// evidence_ref_hash.
func TruncatedHash(data []byte) string {
	h := sha256.Sum256(data)
	const hexdigits = "0123456789abcdef"
	out := make([]byte, 32)
	for i, b := range h[:16] {
		out[i*2] = hexdigits[b>>4]
		out[i*2+1] = hexdigits[b&0x0f]
	}
	return string(out)
}
