package executor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
)

// ProcessEnvSecretStore resolves credentials from process
// environment variables. The credential_ref is uppercased +
// prefixed: a reference like "DEPLOY-CRED-WINDOWS-HQ" looks
// up SENTRAOPS_EXECUTOR_CREDENTIAL_DEPLOY_CRED_WINDOWS_HQ.
//
// Why this backend:
//   - Zero dependencies. Works in dev/test/CI without Vault,
//     AWS, or any external service.
//   - Operator can set the env in the systemd unit /
//     scheduled-task environment, or via a k8s Secret /
//     Docker secret.
//   - Credential must NEVER appear on the command line
//     (the systemd unit uses `Environment=`, not `ExecStart`
//     arguments).
//
// Why we DON'T just use os.Getenv directly: env var names
// have shell-safe character constraints (`-` is not allowed
// in env var names by POSIX). The underscore conversion +
// uppercasing normalizes the operator's credential_ref to a
// valid env var identifier.
type ProcessEnvSecretStore struct {
	prefix string
}

// NewProcessEnvSecretStore builds the backend with the given
// prefix (default "SENTRAOPS_EXECUTOR_CREDENTIAL_").
func NewProcessEnvSecretStore(prefix string) *ProcessEnvSecretStore {
	if prefix == "" {
		prefix = "SENTRAOPS_EXECUTOR_CREDENTIAL_"
	}
	return &ProcessEnvSecretStore{prefix: prefix}
}

// Resolve looks up the credential in the process env. Returns
// a loud error (not a panicking miss) so the caller can
// distinguish "missing credential" from "broken backend".
func (s *ProcessEnvSecretStore) Resolve(_ context.Context, credentialRef string) (string, error) {
	if credentialRef == "" {
		return "", errors.New("executor/secret/processenv: empty credential_ref")
	}
	envVar := s.envNameFor(credentialRef)
	value, ok := os.LookupEnv(envVar)
	if !ok {
		return "", fmt.Errorf("executor/secret/processenv: %s not in process env (set it in the systemd unit / scheduled-task environment)", envVar)
	}
	if value == "" {
		return "", fmt.Errorf("executor/secret/processenv: %s is set but empty", envVar)
	}
	return value, nil
}

// envNameFor converts `DEPLOY-CRED-WINDOWS-HQ` to the
// canonical env var identifier the operator must set.
//
// We:
//   1. Uppercase the whole reference (POSIX env vars are
//      case-sensitive; we standardize on UPPERCASE).
//   2. Replace every `-` and space with `_` (env vars do not
//      allow `-`).
//   3. Replace any other non-alphanumeric / underscore with
//      `_` (paranoid defensive rule for unusual ref formats).
func (s *ProcessEnvSecretStore) envNameFor(credentialRef string) string {
	upper := strings.ToUpper(credentialRef)
	var b strings.Builder
	b.Grow(len(s.prefix) + len(upper))
	b.WriteString(s.prefix)
	for _, r := range upper {
		switch {
		case r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_':
			b.WriteRune(r)
		default:
			b.WriteRune('_')
		}
	}
	return b.String()
}
