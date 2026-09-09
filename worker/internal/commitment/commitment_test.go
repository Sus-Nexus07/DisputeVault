package commitment_test

import (
	"bytes"
	"testing"

	"disputevault/worker/internal/commitment"
)

func TestEvidenceRejectsWrongWireSize(t *testing.T) {
	for _, size := range []int{0, 128, 255, 257, 512} {
		if _, err := commitment.Evidence(make([]byte, size)); err == nil {
			t.Fatalf("Evidence accepted a %d-byte wire", size)
		}
	}
}

func TestVerdictRejectsWrongWireSize(t *testing.T) {
	for _, size := range []int{0, 96, 191, 193, 256} {
		if _, err := commitment.Verdict(make([]byte, size)); err == nil {
			t.Fatalf("Verdict accepted a %d-byte wire", size)
		}
	}
}

func TestAdminPkRejectsWrongSecretSize(t *testing.T) {
	for _, size := range []int{0, 16, 31, 33, 64} {
		if _, err := commitment.AdminPk(make([]byte, size)); err == nil {
			t.Fatalf("AdminPk accepted a %d-byte secret", size)
		}
	}
}

// The §5.1(1) semantics: trailing zero bytes are part of the preimage, so
// hashing must distinguish byte strings that differ only in trailing zeros
// at the same fixed length. (Framed wires always hash at fixed length.)
func TestTruncatedHashForm(t *testing.T) {
	h := commitment.TruncatedHash([]byte("disputevault"))
	if len(h) != 32 {
		t.Fatalf("truncated hash is %d chars, want 32", len(h))
	}
	for _, c := range h {
		if !((c >= '0' && c <= '9') || (c >= 'a' && c <= 'f')) {
			t.Fatalf("truncated hash %q is not lowercase hex", h)
		}
	}
	// Sanity: truncation really is the first 16 bytes of the full digest is
	// pinned by the vectors; here only the form is checked.
	if h != commitment.TruncatedHash([]byte("disputevault")) {
		t.Fatal("truncated hash is not deterministic")
	}
}

// The commitment must differ when any wire byte differs (tamper evidence).
func TestCommitmentTamperEvidence(t *testing.T) {
	wire256 := make([]byte, 256)
	wire256[0] = 'D'
	c1, err := commitment.Evidence(wire256)
	if err != nil {
		t.Fatal(err)
	}
	wire256[255] = 0x01 // flip padding
	c2, err := commitment.Evidence(wire256)
	if err != nil {
		t.Fatal(err)
	}
	if bytes.Equal(c1, c2) {
		t.Fatal("commitments identical after a one-byte change")
	}
}
