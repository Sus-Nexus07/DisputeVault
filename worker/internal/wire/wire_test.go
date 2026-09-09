// Wire-format tests mirroring sdk/test/canonical.test.ts (wire section):
// exact framing bytes, strict parsing, and rejection of malformed wires.
package wire_test

import (
	"bytes"
	"encoding/binary"
	"strings"
	"testing"

	"disputevault/worker/internal/canonical"
	"disputevault/worker/internal/wire"
)

const evidenceJSON = `{"v":1,"bounty_id":42,"claimant_id_hash":"9f86d081884c7d659a2feaa0c55ad015","type":1,"evidence_ref_hash":"60303ae22b998861bce3b28f33eec1be","summary":"Payment was not received for completed bounty."}`

func TestMakeEvidenceExactBytes(t *testing.T) {
	w, err := wire.MakeEvidence(evidenceJSON)
	if err != nil {
		t.Fatalf("MakeEvidence: %v", err)
	}
	if len(w) != 256 {
		t.Fatalf("wire is %d bytes, want 256", len(w))
	}
	if string(w[0:4]) != "DV1E" {
		t.Fatalf("magic is %q, want DV1E", w[0:4])
	}
	if got := binary.BigEndian.Uint16(w[4:6]); got != 199 {
		t.Fatalf("json_len is %d, want 199", got)
	}
	if string(w[6:6+199]) != evidenceJSON {
		t.Fatal("JSON bytes not embedded verbatim")
	}
	for i := 6 + 199; i < 256; i++ {
		if w[i] != 0 {
			t.Fatalf("padding at offset %d is 0x%02x, want 0x00", i, w[i])
		}
	}
}

func TestRoundTrip(t *testing.T) {
	w, err := wire.MakeEvidence(evidenceJSON)
	if err != nil {
		t.Fatal(err)
	}
	p, err := wire.ParseEvidence(w)
	if err != nil {
		t.Fatalf("ParseEvidence: %v", err)
	}
	if p.JSON != evidenceJSON {
		t.Fatal("round-trip JSON mismatch")
	}
	if p.JSONLen != 199 || p.Magic != "DV1E" {
		t.Fatalf("parsed metadata wrong: len=%d magic=%q", p.JSONLen, p.Magic)
	}
}

func TestRejectWrongSize(t *testing.T) {
	if _, err := wire.ParseEvidence(make([]byte, 255)); err == nil {
		t.Fatal("accepted a 255-byte evidence wire")
	}
	if _, err := wire.ParseVerdict(make([]byte, 193)); err == nil {
		t.Fatal("accepted a 193-byte verdict wire")
	}
}

func TestRejectWrongMagic(t *testing.T) {
	w, _ := wire.MakeEvidence(evidenceJSON)
	bad := append([]byte(nil), w...)
	copy(bad[0:4], "XXXX")
	if _, err := wire.ParseEvidence(bad); err == nil {
		t.Fatal("accepted a wire with a wrong magic")
	}
}

func TestRejectCrossTypeWire(t *testing.T) {
	// A DV1V magic on an evidence-size wire: the magic check must fire.
	w, err := wire.MakeEvidence(evidenceJSON)
	if err != nil {
		t.Fatal(err)
	}
	crossed := append([]byte(nil), w...)
	copy(crossed[0:4], "DV1V")
	if _, err := wire.ParseEvidence(crossed); err == nil {
		t.Fatal("accepted DV1V magic as evidence wire")
	}
}

func TestRejectBadJSONLen(t *testing.T) {
	w, _ := wire.MakeEvidence(evidenceJSON)
	bad := append([]byte(nil), w...)
	binary.BigEndian.PutUint16(bad[4:6], 300) // exceeds 250-byte budget
	if _, err := wire.ParseEvidence(bad); err == nil {
		t.Fatal("accepted json_len above the budget")
	}
}

func TestRejectInconsistentJSONLen(t *testing.T) {
	w, _ := wire.MakeEvidence(evidenceJSON)
	bad := append([]byte(nil), w...)
	binary.BigEndian.PutUint16(bad[4:6], 200) // > actual 199: swallows padding
	if _, err := wire.ParseEvidence(bad); err == nil {
		t.Fatal("accepted inconsistent json_len")
	}
}

func TestRejectNonZeroPadding(t *testing.T) {
	w, _ := wire.MakeEvidence(evidenceJSON)
	bad := append([]byte(nil), w...)
	bad[255] = 1
	if _, err := wire.ParseEvidence(bad); err == nil {
		t.Fatal("accepted non-zero padding")
	}
}

func TestOversizedJSONRejectedAtFrameTime(t *testing.T) {
	// 84 three-byte chars = 252 bytes: within no char limit issue, but over
	// the 250-byte §3 budget. The builder must refuse - never truncate.
	long := strings.Repeat("あ", 84)
	_, err := wire.MakeEvidence(long)
	if err == nil {
		t.Fatal("oversized canonical JSON accepted by Make")
	}
	pe, ok := err.(*canonical.ProtocolError)
	if !ok {
		t.Fatalf("error type is %T, want *canonical.ProtocolError", err)
	}
	if !strings.Contains(pe.Error(), "rejected, never truncated") {
		t.Fatalf("error message lacks the never-truncated rule: %v", err)
	}
}

func TestMakeVerdictSize(t *testing.T) {
	vd := `{"v":1,"dispute_id":42,"decision":"claimant_wins","confidence":87,"reason_code":"PAYMENT_NOT_VERIFIED","policy_version":"bounty-dispute-v1"}`
	w, err := wire.MakeVerdict(vd)
	if err != nil {
		t.Fatal(err)
	}
	if len(w) != 192 {
		t.Fatalf("verdict wire is %d bytes, want 192", len(w))
	}
	if string(w[0:4]) != "DV1V" {
		t.Fatalf("verdict magic is %q", w[0:4])
	}
	if got := binary.BigEndian.Uint16(w[4:6]); got != 140 {
		t.Fatalf("verdict json_len is %d, want 140", got)
	}
	if !bytes.Contains(w, []byte(vd)) {
		t.Fatal("verdict JSON not embedded verbatim")
	}
}
