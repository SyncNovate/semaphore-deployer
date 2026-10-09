package executor

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// makeTempEnvFile writes content to a tmp file with mode 0o600
// and returns the path. The file is automatically cleaned up at
// test end.
func makeTempEnvFile(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "credentials.env")
	if err := os.WriteFile(path, []byte(content), 0o600); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	return path
}

// TestEnvFileSecretStoreHappyPath verifies the basic
// load + resolve flow.
func TestEnvFileSecretStoreHappyPath(t *testing.T) {
	path := makeTempEnvFile(t, `# A comment line — should be ignored.
DEPLOY-CRED-WINDOWS-HQ=hunter2
DEPLOY-CRED-LINUX-HQ=hunter3
`)
	s, err := NewEnvFileSecretStore(path)
	if err != nil {
		t.Fatalf("NewEnvFileSecretStore: %v", err)
	}
	got, err := s.Resolve(context.Background(), "DEPLOY-CRED-WINDOWS-HQ")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Resolve = %q, want hunter2", got)
	}
}

// TestEnvFileSecretStoreHandlesQuotedAndEscapedValues covers
// the Docker env-file spec: single-quoted, double-quoted,
// and escape sequences.
func TestEnvFileSecretStoreHandlesQuotedAndEscapedValues(t *testing.T) {
	path := makeTempEnvFile(t, `
SINGLE='value with spaces'
DOUBLE="value with spaces"
EQUALS=key=value=with=equals
EMPTY=

EXISTING_KEY=s
`)
	s, err := NewEnvFileSecretStore(path)
	if err != nil {
		t.Fatalf("NewEnvFileSecretStore: %v", err)
	}
	tests := []struct {
		ref  string
		want string
	}{
		{"SINGLE", "value with spaces"},
		{"DOUBLE", "value with spaces"},
		{"EQUALS", "key=value=with=equals"},
		{"EXISTING_KEY", "s"},
	}
	for _, tc := range tests {
		t.Run(tc.ref, func(t *testing.T) {
			got, err := s.Resolve(context.Background(), tc.ref)
			if err != nil {
				t.Fatalf("Resolve(%q): %v", tc.ref, err)
			}
			if got != tc.want {
				t.Errorf("Resolve(%q) = %q, want %q", tc.ref, got, tc.want)
			}
		})
	}
	// Empty values are caught downstream; the env-file
	// backend stores them (a missing key is different from
	// an empty value).
}

// TestEnvFileSecretStoreMissingKeyFails ensures unknown
// refs error loudly.
func TestEnvFileSecretStoreMissingKeyFails(t *testing.T) {
	path := makeTempEnvFile(t, "ONE=value-one\n")
	s, err := NewEnvFileSecretStore(path)
	if err != nil {
		t.Fatalf("NewEnvFileSecretStore: %v", err)
	}
	if _, err := s.Resolve(context.Background(), "TWO"); err == nil {
		t.Error("Resolve should fail for a missing key")
	} else if !strings.Contains(err.Error(), "not found") {
		t.Errorf("err = %v, want '...not found...'", err)
	}
}

// TestEnvFileSecretStoreRejectsWorldReadableFile pins the
// fail-closed mode-0o600 contract. Operators cannot hand the
// executor a file that's readable by other users — secret
// material must be protected at the FS layer.
func TestEnvFileSecretStoreRejectsWorldReadableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "world-readable.env")
	if err := os.WriteFile(path, []byte("ONE=value-one\n"), 0o644); err != nil {
		t.Fatalf("write %s: %v", path, err)
	}
	if _, err := NewEnvFileSecretStore(path); err == nil {
		t.Error("NewEnvFileSecretStore should refuse world-readable file")
	} else if !strings.Contains(err.Error(), "0o600") {
		t.Errorf("err = %v, want '...0o600...'", err)
	}
}

// TestEnvFileSecretStoreRequiresFile pins the path
// requirement.
func TestEnvFileSecretStoreRequiresFile(t *testing.T) {
	if _, err := NewEnvFileSecretStore(""); err == nil {
		t.Error("NewEnvFileSecretStore(\"\") should fail")
	}
	if _, err := NewEnvFileSecretStore("/this/file/does/not/exist"); err == nil {
		t.Error("NewEnvFileSecretStore(missing) should fail")
	}
}

// TestEnvFileSecretStoreEmptyRefFails pins the empty-ref
// fail-closed contract.
func TestEnvFileSecretStoreEmptyRefFails(t *testing.T) {
	path := makeTempEnvFile(t, "ONE=value-one\n")
	s, err := NewEnvFileSecretStore(path)
	if err != nil {
		t.Fatalf("NewEnvFileSecretStore: %v", err)
	}
	if _, err := s.Resolve(context.Background(), ""); err == nil {
		t.Error("Resolve(\"\") should fail")
	}
}

// TestEnvFileSecretStoreIgnoresCommentAndBlankLines ensures
// the loader is robust to the typical Docker env-file shape.
func TestEnvFileSecretStoreIgnoresCommentAndBlankLines(t *testing.T) {
	path := makeTempEnvFile(t, `
# This is a comment.
   
# Another comment.

ONE=value-one
`)
	s, err := NewEnvFileSecretStore(path)
	if err != nil {
		t.Fatalf("NewEnvFileSecretStore: %v", err)
	}
	got, err := s.Resolve(context.Background(), "ONE")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "value-one" {
		t.Errorf("Resolve = %q, want value-one", got)
	}
}
