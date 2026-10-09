package executor

import (
	"context"
	"errors"
	"os"
	"testing"
)

// TestProcessEnvSecretStoreEnvNameConversion pins the canonical
// env-var translation rules. Operators read this to know what
// to set in their systemd unit / scheduled-task environment.
func TestProcessEnvSecretStoreEnvNameConversion(t *testing.T) {
	tests := []struct {
		name string
		ref  string
		want string
	}{
		{"simple uppercase", "DEPLOY-CRED-WINDOWS-HQ", "SENTRAOPS_EXECUTOR_CREDENTIAL_DEPLOY_CRED_WINDOWS_HQ"},
		{"already uppercase", "DEPLOY_CRED_WINDOWS_HQ", "SENTRAOPS_EXECUTOR_CREDENTIAL_DEPLOY_CRED_WINDOWS_HQ"},
		{"mixed case normalises", "Deploy-Cred-Windows-HQ", "SENTRAOPS_EXECUTOR_CREDENTIAL_DEPLOY_CRED_WINDOWS_HQ"},
		{"space becomes underscore", "deploy cred hq", "SENTRAOPS_EXECUTOR_CREDENTIAL_DEPLOY_CRED_HQ"},
		{"dot becomes underscore", "deploy.cred.hq", "SENTRAOPS_EXECUTOR_CREDENTIAL_DEPLOY_CRED_HQ"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			s := NewProcessEnvSecretStore("")
			if got := s.envNameFor(tc.ref); got != tc.want {
				t.Errorf("envNameFor(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
}

// TestProcessEnvSecretStoreResolvesSetValue verifies the
// happy path: set env, resolve returns it.
func TestProcessEnvSecretStoreResolvesSetValue(t *testing.T) {
	t.Setenv("SENTRAOPS_EXECUTOR_CREDENTIAL_MY_REF", "supersecretvalue")
	s := NewProcessEnvSecretStore("")
	got, err := s.Resolve(context.Background(), "my-ref")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "supersecretvalue" {
		t.Errorf("Resolve = %q, want supersecretvalue", got)
	}
}

// TestProcessEnvSecretStoreEmptyRefFails ensures an empty
// credential_ref is rejected loudly (fail-closed).
func TestProcessEnvSecretStoreEmptyRefFails(t *testing.T) {
	s := NewProcessEnvSecretStore("")
	if _, err := s.Resolve(context.Background(), ""); err == nil {
		t.Error("Resolve(\"\") should fail")
	}
}

// TestProcessEnvSecretStoreMissingEnvFails ensures a missing
// env var returns a descriptive error (the operator needs
// to know WHICH env to set).
func TestProcessEnvSecretStoreMissingEnvFails(t *testing.T) {
	// Unset any leftover from a prior test run.
	os.Unsetenv("SENTRAOPS_EXECUTOR_CREDENTIAL_DEFINITELY_NOT_SET_XYZ")
	s := NewProcessEnvSecretStore("")
	_, err := s.Resolve(context.Background(), "DEFINITELY-NOT-SET-XYZ")
	if err == nil {
		t.Fatal("Resolve should fail for a missing env")
	}
	if !errors.Is(err, err) { // ensure it's a real error, not nil
		t.Errorf("err = %v, want non-nil", err)
	}
}

// TestProcessEnvSecretStoreEmptyValueFails verifies that
// `KEY=` (set, but empty) errors instead of returning "".
// Catches a class of "set up but forgot to fill in" bugs.
func TestProcessEnvSecretStoreEmptyValueFails(t *testing.T) {
	t.Setenv("SENTRAOPS_EXECUTOR_CREDENTIAL_EMPTY_VAL_TEST", "")
	s := NewProcessEnvSecretStore("")
	_, err := s.Resolve(context.Background(), "EMPTY-VAL-TEST")
	if err == nil {
		t.Error("Resolve should fail for an empty env value")
	}
}
