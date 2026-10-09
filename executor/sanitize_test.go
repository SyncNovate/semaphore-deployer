package executor

import (
	"strings"
	"testing"
)

// TestSanitizeStripsCommonSecretPatterns is the data-driven
// test surface: every case in SanitizationTestCases must pass
// before the executor ships. Adding a new pattern means
// adding a test case here.
func TestSanitizeStripsCommonSecretPatterns(t *testing.T) {
	for _, tc := range SanitizationTestCases {
		t.Run(tc.Name, func(t *testing.T) {
			got := Sanitize(tc.Input)
			if got != tc.Want {
				t.Errorf("Sanitize:\n  input: %q\n  got:   %q\n  want:  %q", tc.Input, got, tc.Want)
			}
		})
	}
}

// TestSanitizeEmptyInputReturnsEmpty pins the no-op
// contract on empty strings (avoids a regex panic on a zero-
// length input — some regex engines treat that as "match").
func TestSanitizeEmptyInputReturnsEmpty(t *testing.T) {
	if got := Sanitize(""); got != "" {
		t.Errorf("Sanitize(\"\") = %q, want \"\"", got)
	}
}

// TestSanitizeDoesNotAlterBenignStrings is a sanity check
// that the sanitizer doesn't over-strip. A line with no
// secret-shaped substrings must come back byte-identical.
func TestSanitizeDoesNotAlterBenignStrings(t *testing.T) {
	benign := "ok: [server1] => {\"changed\": false, \"msg\": \"hello world\"}\n"
	if got := Sanitize(benign); got != benign {
		t.Errorf("Sanitize altered benign string:\n  input: %q\n  got:   %q", benign, got)
	}
}

// TestSanitizeStripsPEMPrivateKeyAcrossNewlines is a
// regression test for a class of bugs where the regex
// matchers don't handle multi-line input. PEM key blocks
// span newlines; the sanitizer must catch the entire
// block, not just the first line.
func TestSanitizeStripsPEMPrivateKeyAcrossNewlines(t *testing.T) {
	input := "before\n-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA...\nabc==\n-----END RSA PRIVATE KEY-----\nafter"
	got := Sanitize(input)
	if strings.Contains(got, "MIIEowIBAAKCAQEA") {
		t.Errorf("Sanitize left PEM key bytes in output: %q", got)
	}
	if !strings.Contains(got, "before") || !strings.Contains(got, "after") {
		t.Errorf("Sanitize altered non-secret text: %q", got)
	}
}

// TestSanitizeRedactionTokenIsConsistent pins the
// `[REDACTED]` replacement so downstream SIEM consumers
// can pattern-match on the redacted form.
func TestSanitizeRedactionTokenIsConsistent(t *testing.T) {
	if !strings.Contains(Sanitize("password=foo"), "[REDACTED]") {
		t.Error("redaction token should be '[REDACTED]' (do not change without coordinating with the SIEM team)")
	}
}

// TestSanitizeHandlesMultipleSecretsOnOneLine verifies the
// sanitizer replaces every match in a single pass, not just
// the first.
func TestSanitizeHandlesMultipleSecretsOnOneLine(t *testing.T) {
	input := `password=foo token=bar api_key=baz`
	got := Sanitize(input)
	if strings.Contains(got, "foo") || strings.Contains(got, "bar") || strings.Contains(got, "baz") {
		t.Errorf("Sanitize left secret values in output: %q", got)
	}
	// Three redactions, one per secret.
	if c := strings.Count(got, "[REDACTED]"); c != 3 {
		t.Errorf("Sanitize produced %d [REDACTED] tokens, want 3: %q", c, got)
	}
}
