// Package canonical implements DisputeVault EvidenceV1/VerdictV1 payloads
// and deterministic canonical JSON (PROTOCOL.md §2, §4, §7), mirroring
// sdk/src/canonical.ts and sdk/src/schema.ts byte-for-byte.
//
// Canonical rules (§2):
//   - fixed field order (schema order, never alphabetical)
//   - UTF-8, no BOM, no whitespace
//   - integers: plain decimal ASCII
//   - strings: minimal escaping (", \, control chars as \u00XX); non-ASCII
//     raw UTF-8, never \uXXXX
//   - hash fields: exactly 32 lowercase hex chars
//   - size budgets enforced in BYTES, never truncated
//
// Go's encoding/json is deliberately NOT used for serialization: it escapes
// non-ASCII by default, HTML-escapes <>&, and orders map fields
// alphabetically. The encoders here write the exact bytes the SDK writes.
package canonical

import (
	"errors"
	"fmt"
	"regexp"
	"strings"
)

// ProtocolError is returned for every protocol violation; the message names
// the violated rule (mirrors sdk ProtocolError).
type ProtocolError struct{ Msg string }

func (e *ProtocolError) Error() string { return "disputevault: " + e.Msg }

// NewProtocolError wraps a message into a *ProtocolError for use by sibling
// packages (wire, commitment).
func NewProtocolError(format string, args ...any) error {
	return &ProtocolError{Msg: fmt.Sprintf(format, args...)}
}

func errf(format string, args ...any) error {
	return &ProtocolError{Msg: fmt.Sprintf(format, args...)}
}

// Wire budgets (PROTOCOL.md §3).
const (
	EvidenceWireSize = 256
	EvidenceMaxJSON  = 250
	VerdictWireSize  = 192
	VerdictMaxJSON   = 186
)

// Field limits.
const (
	EvidenceSummaryMaxChars      = 64 // PROTOCOL §4 (characters, not bytes)
	VerdictReasonCodeMaxChars    = 32
	VerdictPolicyVersionMaxChars = 32
)

// Dispute types (§4).
const (
	TypeRejectedValidWork  = 0
	TypePaymentNotReceived = 1
	TypeScopeDispute       = 2
	TypeOther              = 3
)

// Verdict decisions (§7).
const (
	DecisionClaimantWins     = "claimant_wins"
	DecisionPlatformWins     = "platform_wins"
	DecisionPartial          = "partial"
	DecisionNeedsHumanReview = "needs_human_review"
)

var (
	hex32         = regexp.MustCompile(`^[0-9a-f]{32}$`)
	reasonCode    = regexp.MustCompile(`^[A-Z0-9_]{1,32}$`)
	policyVersion = regexp.MustCompile(`^[a-z0-9-]{1,32}$`)
)

var validDecisions = map[string]bool{
	DecisionClaimantWins:     true,
	DecisionPlatformWins:     true,
	DecisionPartial:          true,
	DecisionNeedsHumanReview: true,
}

// EvidenceV1 mirrors PROTOCOL.md §4; the struct order documents the canonical
// field order but encoding is explicit in CanonicalJSON.
type EvidenceV1 struct {
	V               uint32 // must be 1
	BountyID        uint32 // 0..4294967295
	ClaimantIDHash  string // 32 lowercase hex chars
	Type            uint8  // 0..3
	EvidenceRefHash string // 32 lowercase hex chars
	Summary         string // <= 64 chars, must also fit the byte budget
}

// VerdictV1 mirrors PROTOCOL.md §7.
type VerdictV1 struct {
	V             uint32 // must be 1
	DisputeID     uint64 // 0..2^64-1; MUST equal the outer dispute id (§7)
	Decision      string // enum
	Confidence    uint8  // 0..100
	ReasonCode    string // [A-Z0-9_], 1..32
	PolicyVersion string // [a-z0-9-], 1..32
}

// EscapeJSONString applies minimal JSON escaping per §2 rule 5: only ",
// \, and control characters (as \u00XX) are escaped; non-ASCII stays raw.
// It iterates by Unicode code point (the SDK iterates code points too), so
// surrogate-pair semantics are identical.
func EscapeJSONString(s string) string {
	var b strings.Builder
	b.WriteByte('"')
	for _, r := range s {
		switch {
		case r == '"':
			b.WriteString(`\"`)
		case r == '\\':
			b.WriteString(`\\`)
		case r < 0x20:
			b.WriteString(fmt.Sprintf(`\u%04x`, r))
		default:
			b.WriteRune(r) // raw UTF-8
		}
	}
	b.WriteByte('"')
	return b.String()
}

// CanonicalJSON serializes a validated EvidenceV1 payload to canonical JSON.
// It returns (json, error): error if the payload violates §4 or the canonical
// JSON exceeds the 250-byte evidence budget (§3) - nothing is ever truncated.
func (e EvidenceV1) CanonicalJSON() (string, error) {
	if err := e.validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`{"v":1,`)
	b.WriteString(`"bounty_id":` + itoa(uint64(e.BountyID)) + `,`)
	b.WriteString(`"claimant_id_hash":` + EscapeJSONString(e.ClaimantIDHash) + `,`)
	b.WriteString(`"type":` + itoa(uint64(e.Type)) + `,`)
	b.WriteString(`"evidence_ref_hash":` + EscapeJSONString(e.EvidenceRefHash) + `,`)
	b.WriteString(`"summary":` + EscapeJSONString(e.Summary))
	b.WriteByte('}')

	json := b.String()
	if n := len([]byte(json)); n > EvidenceMaxJSON {
		return "", errf("evidence canonical JSON is %d bytes; budget is %d (PROTOCOL §3) - rejected, never truncated", n, EvidenceMaxJSON)
	}
	return json, nil
}

func (e EvidenceV1) validate() error {
	if e.V != 1 {
		return errf("evidence v must be 1, got %d", e.V)
	}
	if !hex32.MatchString(e.ClaimantIDHash) {
		return errors.New("disputevault: evidence claimant_id_hash must be 32 lowercase hex chars")
	}
	if e.Type > 3 {
		return errf("evidence type must be one of 0, 1, 2, 3 (got %d)", e.Type)
	}
	if !hex32.MatchString(e.EvidenceRefHash) {
		return errors.New("disputevault: evidence evidence_ref_hash must be 32 lowercase hex chars")
	}
	if n := len([]rune(e.Summary)); n > EvidenceSummaryMaxChars {
		return errf("evidence summary exceeds %d characters", EvidenceSummaryMaxChars)
	}
	return nil
}

// CanonicalJSON serializes a validated VerdictV1 payload to canonical JSON.
// Error if the payload violates §7 or the canonical JSON exceeds the
// 186-byte verdict budget (§3).
func (v VerdictV1) CanonicalJSON() (string, error) {
	if err := v.validate(); err != nil {
		return "", err
	}
	var b strings.Builder
	b.WriteString(`{"v":1,`)
	b.WriteString(`"dispute_id":` + itoa(v.DisputeID) + `,`)
	b.WriteString(`"decision":` + EscapeJSONString(v.Decision) + `,`)
	b.WriteString(`"confidence":` + itoa(uint64(v.Confidence)) + `,`)
	b.WriteString(`"reason_code":` + EscapeJSONString(v.ReasonCode) + `,`)
	b.WriteString(`"policy_version":` + EscapeJSONString(v.PolicyVersion))
	b.WriteByte('}')

	json := b.String()
	if n := len([]byte(json)); n > VerdictMaxJSON {
		return "", errf("verdict canonical JSON is %d bytes; budget is %d (PROTOCOL §3) - rejected, never truncated", n, VerdictMaxJSON)
	}
	return json, nil
}

func (v VerdictV1) validate() error {
	if v.V != 1 {
		return errf("verdict v must be 1, got %d", v.V)
	}
	if !validDecisions[v.Decision] {
		return errors.New("disputevault: verdict decision must be one of claimant_wins | platform_wins | partial | needs_human_review")
	}
	if v.Confidence > 100 {
		return errf("verdict confidence must be an integer in 0..100, got %d", v.Confidence)
	}
	if !reasonCode.MatchString(v.ReasonCode) || len(v.ReasonCode) > VerdictReasonCodeMaxChars {
		return errors.New("disputevault: verdict reason_code must match [A-Z0-9_] with 1..32 chars")
	}
	if !policyVersion.MatchString(v.PolicyVersion) || len(v.PolicyVersion) > VerdictPolicyVersionMaxChars {
		return errors.New("disputevault: verdict policy_version must match [a-z0-9-] with 1..32 chars")
	}
	return nil
}

// itoa renders a non-negative integer as plain decimal ASCII (§2 rule 4).
func itoa(n uint64) string {
	return fmt.Sprintf("%d", n)
}
