// Package wire implements the DisputeVault DV1E/DV1V wire format
// (PROTOCOL.md §3), mirroring sdk/src/wire.ts exactly.
//
//	offset  size  field
//	0       4     magic     ASCII "DV1E" (evidence) | "DV1V" (verdict)
//	4       2     json_len  uint16 big-endian
//	6       n     json      canonical JSON (n == json_len)
//	6+n     ...   padding   0x00 up to the fixed wire size
//
// Rules enforced (identical to the SDK):
//   - json_len == actual JSON byte count; 6 + json_len <= wire size
//   - padding bytes MUST be zero
//   - the magic doubles as domain separation
//   - a wire that violates any rule is rejected, never repaired
package wire

import (
	"encoding/binary"
	"encoding/json"
	"unicode/utf8"

	"disputevault/worker/internal/canonical"
)

const (
	EvidenceMagic = "DV1E"
	VerdictMagic  = "DV1V"
)

// Kind selects the wire type; it fixes both the magic and the sizes.
type Kind int

const (
	Evidence Kind = iota
	Verdict
)

func (k Kind) String() string {
	if k == Verdict {
		return VerdictMagic
	}
	return EvidenceMagic
}

func (k Kind) wireSize() int {
	if k == Verdict {
		return canonical.VerdictWireSize
	}
	return canonical.EvidenceWireSize
}

func (k Kind) maxJSON() int {
	if k == Verdict {
		return canonical.VerdictMaxJSON
	}
	return canonical.EvidenceMaxJSON
}

func (k Kind) magic() string {
	if k == Verdict {
		return VerdictMagic
	}
	return EvidenceMagic
}

// Make frames a canonical JSON string into a fixed-size wire. The JSON byte
// count must fit the kind's budget; oversized payloads are rejected, never
// truncated.
func Make(kind Kind, canonicalJSON string) ([]byte, error) {
	jsonBytes := []byte(canonicalJSON) // Go strings are UTF-8; len counts BYTES
	if len(jsonBytes) > kind.maxJSON() {
		return nil, canonical.NewProtocolError(
			"canonical JSON is %d bytes; %s budget is %d (PROTOCOL §3) - rejected, never truncated",
			len(jsonBytes), kind, kind.maxJSON())
	}
	out := make([]byte, kind.wireSize())
	copy(out[0:4], kind.magic())
	binary.BigEndian.PutUint16(out[4:6], uint16(len(jsonBytes)))
	copy(out[6:], jsonBytes)
	return out, nil
}

// MakeEvidence frames a 256-byte DV1E wire.
func MakeEvidence(canonicalJSON string) ([]byte, error) { return Make(Evidence, canonicalJSON) }

// MakeVerdict frames a 192-byte DV1V wire.
func MakeVerdict(canonicalJSON string) ([]byte, error) { return Make(Verdict, canonicalJSON) }

// Parsed is the decoded view of a wire.
type Parsed struct {
	Kind    Kind
	Magic   string
	JSON    string
	JSONLen int
	Wire    []byte
}

// Parse strictly decodes a wire of the expected kind. Any deviation - wrong
// magic, inconsistent length, non-zero padding, invalid UTF-8, oversized
// JSON, unparsable JSON - is an error. Verifiers must use this before
// re-hashing.
func Parse(kind Kind, wire []byte) (*Parsed, error) {
	if len(wire) != kind.wireSize() {
		return nil, canonical.NewProtocolError(
			"%s wire must be exactly %d bytes, got %d", kind, kind.wireSize(), len(wire))
	}
	magic := string(wire[0:4])
	if magic != kind.magic() {
		return nil, canonical.NewProtocolError(
			"%s wire magic must be %q, got %q", kind, kind.magic(), magic)
	}
	jsonLen := int(binary.BigEndian.Uint16(wire[4:6]))
	if 6+jsonLen > kind.wireSize() {
		return nil, canonical.NewProtocolError(
			"%s wire json_len %d exceeds wire capacity (%d bytes)", kind, jsonLen, kind.wireSize())
	}
	if jsonLen > kind.maxJSON() {
		return nil, canonical.NewProtocolError(
			"%s wire json_len %d exceeds the %d-byte budget (PROTOCOL §3)", kind, jsonLen, kind.maxJSON())
	}
	jsonBytes := wire[6 : 6+jsonLen]
	if !utf8.Valid(jsonBytes) {
		return nil, canonical.NewProtocolError("%s wire JSON is not valid UTF-8", kind)
	}
	// json_len must equal the actual JSON byte count; a too-large length
	// field swallows padding bytes into the JSON, which cannot parse.
	if !json.Valid(jsonBytes) {
		return nil, canonical.NewProtocolError(
			"%s wire json_len %d is inconsistent with the embedded JSON (PROTOCOL §3)", kind, jsonLen)
	}
	for i := 6 + jsonLen; i < kind.wireSize(); i++ {
		if wire[i] != 0 {
			return nil, canonical.NewProtocolError(
				"%s wire has non-zero padding at offset %d (PROTOCOL §3)", kind, i)
		}
	}
	return &Parsed{
		Kind:    kind,
		Magic:   magic,
		JSON:    string(jsonBytes),
		JSONLen: jsonLen,
		Wire:    append([]byte(nil), wire...),
	}, nil
}

// ParseEvidence strictly decodes a DV1E wire.
func ParseEvidence(wire []byte) (*Parsed, error) { return Parse(Evidence, wire) }

// ParseVerdict strictly decodes a DV1V wire.
func ParseVerdict(wire []byte) (*Parsed, error) { return Parse(Verdict, wire) }
