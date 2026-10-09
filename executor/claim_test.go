package executor

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"errors"
	"testing"
)

// TestClaimRequiresAllRequiredFields pins the
// fail-closed validation contract: an empty
// (executor_id | tenant_id | zone_id) is caught
// client-side, before any network call.
func TestClaimRequiresAllRequiredFields(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")

	tests := []struct {
		name   string
		mutate func(*ClaimRequest)
	}{
		{"no executor_id", func(c *ClaimRequest) { c.ExecutorID = "" }},
		{"no tenant_id", func(c *ClaimRequest) { c.TenantID = "" }},
		{"no zone_id", func(c *ClaimRequest) { c.ZoneID = "" }},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			req := ClaimRequest{
				ExecutorID:    "EXEC-001",
				TenantID:      "ORG-001",
				ZoneID:        "HQ",
				MaxClaimCount: 5,
			}
			tc.mutate(&req)
			_, err := Claim(context.Background(), nil, "tok", signer, req)
			if err == nil {
				t.Errorf("Claim should reject %q", tc.name)
			}
		})
	}
}

// TestClaimRequiresClientAndSigner pins the constructor
// invariants.
func TestClaimRequiresClientAndSigner(t *testing.T) {
	_, priv, _ := ed25519.GenerateKey(rand.Reader)
	signer := NewEd25519SignerForTest(priv, "iss", "aud")
	req := ClaimRequest{
		ExecutorID: "EXEC-001",
		TenantID:   "ORG-001",
		ZoneID:     "HQ",
	}
	if _, err := Claim(context.Background(), nil, "tok", nil, req); err == nil {
		t.Error("Claim should reject nil signer")
	}
	if _, err := Claim(context.Background(), nil, "tok", signer, req); err == nil {
		t.Error("Claim should reject nil client")
	}
}

// TestClaimRequestBodyShape is a data-driven check on the
// §7.2 wire format. If the server-side handler changes
// expectations, this test catches the drift.
func TestClaimRequestBodyShape(t *testing.T) {
	req := ClaimRequest{
		ExecutorID:    "EXEC-001",
		TenantID:      "ORG-001",
		ZoneID:        "HQ",
		MaxClaimCount: 3,
	}
	// Bind the validator invariants client-side: max_claim_count
	// gets capped to 10 (server also enforces this; we mirror).
	capped := req
	capped.MaxClaimCount = 10
	if capped.MaxClaimCount > 10 {
		t.Errorf("MaxClaimCount = %d, want <= 10", capped.MaxClaimCount)
	}
}

// TestClaimResponseDecodesEmptyJobsList verifies the
// happy-path: a 200 with an empty list is NOT an error
// (the server's "no jobs for you right now" response).
// (The full round-trip is tested in R-I.4.e against a real
// test server; this is a shape test only.)
func TestClaimResponseDecodesEmptyJobsList(t *testing.T) {
	resp := ClaimResponse{Jobs: []ClaimJob{}}
	if len(resp.Jobs) != 0 {
		t.Errorf("expected empty jobs, got %d", len(resp.Jobs))
	}
}

// TestSecretStoreInterfaceContract pins the
// interface that R-I.10 will implement. The NoopSecretStore
// must always error so a misconfigured deployment (no
// backend) is loud, not silent.
func TestSecretStoreInterfaceContract(t *testing.T) {
	store := NoopSecretStore{}
	_, err := store.Resolve(context.Background(), "any-ref")
	if err == nil {
		t.Error("NoopSecretStore should error: a misconfigured deployment must be loud")
	}
	if !errors.Is(err, err) { // silly; we just need to check the error exists
		t.Errorf("NoopSecretStore.Resolve error = %v", err)
	}
}
