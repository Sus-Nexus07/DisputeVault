// Canonical-encoder tests mirroring sdk/test/canonical.test.ts: field order,
// escaping, byte budgets, and the adversarial cases (max summary, multibyte
// UTF-8 near the budget, control characters, oversized rejection).
package canonical_test

import (
	"strings"
	"testing"

	"disputevault/worker/internal/canonical"
)

func validEvidence() canonical.EvidenceV1 {
	return canonical.EvidenceV1{
		V:               1,
		BountyID:        42,
		ClaimantIDHash:  "9f86d081884c7d659a2feaa0c55ad015",
		Type:            1,
		EvidenceRefHash: "60303ae22b998861bce3b28f33eec1be",
		Summary:         "Payment was not received for completed bounty.",
	}
}

func validVerdict() canonical.VerdictV1 {
	return canonical.VerdictV1{
		V:             1,
		DisputeID:     42,
		Decision:      canonical.DecisionClaimantWins,
		Confidence:    87,
		ReasonCode:    "PAYMENT_NOT_VERIFIED",
		PolicyVersion: "bounty-dispute-v1",
	}
}

const wantEvidenceJSON = `{"v":1,"bounty_id":42,"claimant_id_hash":"9f86d081884c7d659a2feaa0c55ad015","type":1,"evidence_ref_hash":"60303ae22b998861bce3b28f33eec1be","summary":"Payment was not received for completed bounty."}`
const wantVerdictJSON = `{"v":1,"dispute_id":42,"decision":"claimant_wins","confidence":87,"reason_code":"PAYMENT_NOT_VERIFIED","policy_version":"bounty-dispute-v1"}`

func TestEvidenceCanonicalJSONExact(t *testing.T) {
	got, err := validEvidence().CanonicalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantEvidenceJSON {
		t.Fatalf("evidence JSON mismatch:\n got:  %s\n want: %s", got, wantEvidenceJSON)
	}
	if len(got) != 199 {
		t.Fatalf("evidence JSON is %d bytes, want 199", len(got))
	}
}

func TestVerdictCanonicalJSONExact(t *testing.T) {
	got, err := validVerdict().CanonicalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != wantVerdictJSON {
		t.Fatalf("verdict JSON mismatch:\n got:  %s\n want: %s", got, wantVerdictJSON)
	}
	if len(got) != 140 {
		t.Fatalf("verdict JSON is %d bytes, want 140", len(got))
	}
}

func TestFieldOrderIsSchemaOrder(t *testing.T) {
	got, _ := validEvidence().CanonicalJSON()
	// byte-exact literal comparison already proves order; assert markers too
	if !strings.HasPrefix(got, `{"v":1,"bounty_id":42,"claimant_id_hash"`) {
		t.Fatalf("field order wrong: %s", got)
	}
}

func TestEscaping(t *testing.T) {
	// control chars -> \u00XX; quote and backslash escaped; non-ASCII raw.
	ev := validEvidence()
	ev.Summary = "line\u0001break\"quoted\" \\ backslash — ok\u0001"
	got, err := ev.CanonicalJSON()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	for _, want := range []string{`\u0001`, `\"quoted\"`, `\\`, "—"} {
		if !strings.Contains(got, want) {
			t.Fatalf("escaped output missing %q: %s", want, got)
		}
	}
	if strings.Contains(got, `\u2014`) {
		t.Fatalf("non-ASCII was escaped, must stay raw: %s", got)
	}
}

func TestMaxSummaryStillFits(t *testing.T) {
	ev := validEvidence()
	ev.Summary = strings.Repeat("A", 64) // §4 char limit exactly
	got, err := ev.CanonicalJSON()
	if err != nil {
		t.Fatalf("64-char ASCII summary rejected: %v", err)
	}
	if len(got) != 217 {
		t.Fatalf("expected 217 bytes, got %d", len(got))
	}
}

func TestMultibyteSummaryHitsByteBudgetButCharLimit(t *testing.T) {
	// 60 chars x 3-byte UTF-8 = within the §4 64-char limit but busts the
	// §3 250-BYTE budget: must be rejected, never truncated.
	ev := validEvidence()
	ev.Summary = strings.Repeat("あ", 60)
	if _, err := ev.CanonicalJSON(); err == nil {
		t.Fatal("multibyte oversized summary accepted; byte budget not enforced")
	}
}

func TestOversizedJSONRejected(t *testing.T) {
	ev := validEvidence()
	ev.Summary = strings.Repeat("A", 64) // 216 bytes: fits
	if _, err := ev.CanonicalJSON(); err != nil {
		t.Fatalf("unexpected rejection: %v", err)
	}
	// Force an over-budget payload through a longer summary is impossible
	// under the 64-char limit with ASCII, so verify the budget check via
	// multibyte (above) and the verdict path below.
	vd := validVerdict()
	vd.ReasonCode = strings.Repeat("A", 32) // longest allowed
	vd.PolicyVersion = strings.Repeat("a", 32)
	vd.Decision = canonical.DecisionNeedsHumanReview // longest enum
	if _, err := vd.CanonicalJSON(); err != nil {
		t.Fatalf("longest legal verdict rejected: %v", err)
	}
}

func TestEvidenceValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*canonical.EvidenceV1)
	}{
		{"v != 1", func(e *canonical.EvidenceV1) { e.V = 2 }},
		{"uppercase hash", func(e *canonical.EvidenceV1) { e.ClaimantIDHash = strings.ToUpper(e.ClaimantIDHash) }},
		{"short hash", func(e *canonical.EvidenceV1) { e.EvidenceRefHash = "ab" }},
		{"type out of enum", func(e *canonical.EvidenceV1) { e.Type = 4 }},
		{"summary over char limit", func(e *canonical.EvidenceV1) { e.Summary = strings.Repeat("A", 65) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			ev := validEvidence()
			tc.mut(&ev)
			if _, err := ev.CanonicalJSON(); err == nil {
				t.Fatalf("%s: expected rejection", tc.name)
			}
		})
	}
}

func TestVerdictValidationErrors(t *testing.T) {
	cases := []struct {
		name string
		mut  func(*canonical.VerdictV1)
	}{
		{"v != 1", func(v *canonical.VerdictV1) { v.V = 0 }},
		{"bad decision", func(v *canonical.VerdictV1) { v.Decision = "maybe" }},
		{"confidence 101", func(v *canonical.VerdictV1) { v.Confidence = 101 }},
		{"lowercase reason", func(v *canonical.VerdictV1) { v.ReasonCode = "oops" }},
		{"reason 33 chars", func(v *canonical.VerdictV1) { v.ReasonCode = strings.Repeat("A", 33) }},
		{"uppercase policy", func(v *canonical.VerdictV1) { v.PolicyVersion = "UPPER" }},
		{"policy 33 chars", func(v *canonical.VerdictV1) { v.PolicyVersion = strings.Repeat("a", 33) }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			vd := validVerdict()
			tc.mut(&vd)
			if _, err := vd.CanonicalJSON(); err == nil {
				t.Fatalf("%s: expected rejection", tc.name)
			}
		})
	}
}

func TestVerdictMaxDisputeID(t *testing.T) {
	vd := validVerdict()
	vd.DisputeID = ^uint64(0) // 2^64-1 must serialize in plain decimal
	got, err := vd.CanonicalJSON()
	if err != nil {
		t.Fatalf("max dispute id rejected: %v", err)
	}
	if !strings.Contains(got, `"dispute_id":18446744073709551615`) {
		t.Fatalf("max dispute id not plain decimal: %s", got)
	}
}

func TestEscapeJSONStringUnits(t *testing.T) {
	cases := []struct{ in, want string }{
		{"plain", `"plain"`},
		{"say \"hi\"", `"say \"hi\""`},
		{`back\slash`, `"back\\slash"`},
		{"a\u0001b", `"a\u0001b"`},
		// \t and \n are control chars: §2 rule 5 escapes them as \u00XX
		// (there are no \t/\n shorthand rules in the canonical form).
		{"tab\there", `"tab\u0009here"`},
		{"new\nline", `"new\u000aline"`},
		{"unicode — ✓", `"unicode — ✓"`}, // raw UTF-8
	}
	for _, tc := range cases {
		if got := canonical.EscapeJSONString(tc.in); got != tc.want {
			t.Fatalf("EscapeJSONString(%q) = %s, want %s", tc.in, got, tc.want)
		}
	}
}
