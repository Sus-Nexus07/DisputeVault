// Parity tests: the Go implementation must reproduce the normative vectors
// (sdk/test/vectors.json, sourced from PROTOCOL.md §12) BYTE-FOR-BYTE.
//
// testdata/vectors.json is a verbatim copy of sdk/test/vectors.json
// (regenerate via `npx tsx test/generate-vectors.ts` in sdk/ and re-copy);
// this milestone is deliberately cross-language: a canonicalization or
// hashing divergence between Go and TypeScript would silently break every
// commitment the worker publishes, and neither the contract nor SDK tests
// can catch it.
package commitment_test

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"os"
	"testing"

	"disputevault/worker/internal/canonical"
	"disputevault/worker/internal/commitment"
	"disputevault/worker/internal/wire"
)

type vectors struct {
	Evidence struct {
		Payload            map[string]any `json:"payload"`
		CanonicalJSON      string         `json:"canonical_json"`
		CanonicalJSONBytes int            `json:"canonical_json_bytes"`
		Wire               string         `json:"wire"`
		Commitment         string         `json:"commitment"`
	} `json:"evidence"`
	Verdict struct {
		Payload            map[string]any `json:"payload"`
		CanonicalJSON      string         `json:"canonical_json"`
		CanonicalJSONBytes int            `json:"canonical_json_bytes"`
		Wire               string         `json:"wire"`
		Commitment         string         `json:"commitment"`
	} `json:"verdict"`
	AdminPk struct {
		TagHex      string `json:"tag_hex"`
		SkHex       string `json:"sk_hex"`
		PreimageHex string `json:"preimage_hex"`
		Pk          string `json:"pk"`
	} `json:"admin_pk"`
	Envelope struct {
		PlaintextWire string `json:"plaintext_wire"`
	} `json:"envelope"`
}

func loadVectors(t *testing.T) vectors {
	t.Helper()
	raw, err := os.ReadFile("../../testdata/vectors.json")
	if err != nil {
		t.Fatalf("read testdata/vectors.json: %v", err)
	}
	var v vectors
	if err := json.Unmarshal(raw, &v); err != nil {
		t.Fatalf("parse vectors.json: %v", err)
	}
	return v
}

// evFromMap builds the Go EvidenceV1 from the vector's payload map.
func evFromMap(t *testing.T, m map[string]any) canonical.EvidenceV1 {
	t.Helper()
	return canonical.EvidenceV1{
		V:               uint32(m["v"].(float64)),
		BountyID:        uint32(m["bounty_id"].(float64)),
		ClaimantIDHash:  m["claimant_id_hash"].(string),
		Type:            uint8(m["type"].(float64)),
		EvidenceRefHash: m["evidence_ref_hash"].(string),
		Summary:         m["summary"].(string),
	}
}

func vdFromMap(t *testing.T, m map[string]any) canonical.VerdictV1 {
	t.Helper()
	return canonical.VerdictV1{
		V:             uint32(m["v"].(float64)),
		DisputeID:     uint64(m["dispute_id"].(float64)),
		Decision:      m["decision"].(string),
		Confidence:    uint8(m["confidence"].(float64)),
		ReasonCode:    m["reason_code"].(string),
		PolicyVersion: m["policy_version"].(string),
	}
}

// TestEvidenceVectorParity: canonical JSON, wire, and commitment must equal
// the §12.1 vector byte-for-byte.
func TestEvidenceVectorParity(t *testing.T) {
	v := loadVectors(t)
	ev := evFromMap(t, v.Evidence.Payload)

	gotJSON, err := ev.CanonicalJSON()
	if err != nil {
		t.Fatalf("canonicalize evidence: %v", err)
	}
	if gotJSON != v.Evidence.CanonicalJSON {
		t.Fatalf("evidence canonical JSON mismatch:\n got:  %q\n want: %q", gotJSON, v.Evidence.CanonicalJSON)
	}
	if len(gotJSON) != v.Evidence.CanonicalJSONBytes {
		t.Fatalf("evidence canonical JSON is %d bytes, vector says %d", len(gotJSON), v.Evidence.CanonicalJSONBytes)
	}

	gotWire, err := wire.MakeEvidence(gotJSON)
	if err != nil {
		t.Fatalf("frame evidence wire: %v", err)
	}
	wantWire, _ := hex.DecodeString(v.Evidence.Wire)
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatalf("evidence wire mismatch:\n got:  %x\n want: %x", gotWire, wantWire)
	}
	if len(wantWire) != 256 {
		t.Fatalf("vector wire is %d bytes, expected 256", len(wantWire))
	}

	gotCommitment, err := commitment.Evidence(gotWire)
	if err != nil {
		t.Fatalf("commit evidence: %v", err)
	}
	if hex.EncodeToString(gotCommitment) != v.Evidence.Commitment {
		t.Fatalf("evidence commitment mismatch:\n got:  %x\n want: %s", gotCommitment, v.Evidence.Commitment)
	}
}

// TestVerdictVectorParity: same, for the §12.2 vector.
func TestVerdictVectorParity(t *testing.T) {
	v := loadVectors(t)
	vd := vdFromMap(t, v.Verdict.Payload)

	gotJSON, err := vd.CanonicalJSON()
	if err != nil {
		t.Fatalf("canonicalize verdict: %v", err)
	}
	if gotJSON != v.Verdict.CanonicalJSON {
		t.Fatalf("verdict canonical JSON mismatch:\n got:  %q\n want: %q", gotJSON, v.Verdict.CanonicalJSON)
	}

	gotWire, err := wire.MakeVerdict(gotJSON)
	if err != nil {
		t.Fatalf("frame verdict wire: %v", err)
	}
	wantWire, _ := hex.DecodeString(v.Verdict.Wire)
	if !bytes.Equal(gotWire, wantWire) {
		t.Fatalf("verdict wire mismatch:\n got:  %x\n want: %x", gotWire, wantWire)
	}
	if len(wantWire) != 192 {
		t.Fatalf("vector wire is %d bytes, expected 192", len(wantWire))
	}

	gotCommitment, err := commitment.Verdict(gotWire)
	if err != nil {
		t.Fatalf("commit verdict: %v", err)
	}
	if hex.EncodeToString(gotCommitment) != v.Verdict.Commitment {
		t.Fatalf("verdict commitment mismatch:\n got:  %x\n want: %s", gotCommitment, v.Verdict.Commitment)
	}
}

// TestAdminPkVectorParity: SHA256(pad32("disputevault:admin:pk") || sk) must
// equal the §12.3 vector.
func TestAdminPkVectorParity(t *testing.T) {
	v := loadVectors(t)
	sk, _ := hex.DecodeString(v.AdminPk.SkHex)
	tag, _ := hex.DecodeString(v.AdminPk.TagHex)
	if !bytes.Equal(tag, commitment.AdminPKTag) {
		t.Fatalf("adminPk tag mismatch: got %x want %x", commitment.AdminPKTag, tag)
	}

	got, err := commitment.AdminPk(sk)
	if err != nil {
		t.Fatalf("AdminPk: %v", err)
	}
	if hex.EncodeToString(got) != v.AdminPk.Pk {
		t.Fatalf("adminPk mismatch:\n got:  %x\n want: %s", got, v.AdminPk.Pk)
	}
}

// TestEnvelopePlaintextIsTheEvidenceWire: the §12.5 envelope vector's
// plaintext must equal the §12.1 evidence wire (binding the two vectors
// together in Go too).
func TestEnvelopePlaintextIsTheEvidenceWire(t *testing.T) {
	v := loadVectors(t)
	plain, _ := hex.DecodeString(v.Envelope.PlaintextWire)
	evWire, _ := hex.DecodeString(v.Evidence.Wire)
	if !bytes.Equal(plain, evWire) {
		t.Fatal("envelope plaintext_wire does not equal the evidence wire")
	}
}
