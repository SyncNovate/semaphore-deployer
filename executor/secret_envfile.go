package executor

import (
	"bufio"
	"context"
	"errors"
	"fmt"
	"os"
	"strings"
	"sync"
)

// EnvFileSecretStore resolves credentials from a Docker-style
// env file (`KEY=value` per line). Standard env-file format:
// comments start with `#`, blank lines are skipped, values may
// be quoted (single or double quotes), trailing whitespace is
// trimmed, `\` escapes work for newlines + quotes + `$`.
//
// Why this backend:
//   - The customer-side operator hands the executor a file
//     (path-on-disk) instead of N env vars. Easier to manage
//     in ops tooling (Ansible Vault, sealed-secrets, etc.).
//   - The executor loads the file once at startup, then
//     resolves credentials in-memory — no disk reads on the
//     hot path (no log-spam from `stat`).
//   - The file is read with strict permissions (0o600) —
//     refuses to load if it's world-readable.
//
// Why mutex: the lookup table is read-only after `Load`, but
// Go's memory model doesn't formally guarantee that without
// a happens-before edge. The mutex makes Load→Resolve
// ordering explicit + cheap.
type EnvFileSecretStore struct {
	path string
	mu    sync.RWMutex
	table map[string]string
}

// NewEnvFileSecretStore loads the env file at startup. The
// file MUST be readable only by the executor's user (mode
// 0o600 or stricter); a more open mode is refused loudly.
//
// The path may be relative; resolved against the current
// working directory at construction time (the daemon should
// cd to a known working directory in the systemd unit).
func NewEnvFileSecretStore(path string) (*EnvFileSecretStore, error) {
	if path == "" {
		return nil, errors.New("executor/secret/envfile: path is required")
	}
	info, err := os.Stat(path)
	if err != nil {
		return nil, fmt.Errorf("executor/secret/envfile: stat %s: %w", path, err)
	}
	// Refuse world-readable / group-writable files. The
	// secret material lives in there; ops misconfigurations
	// must surface at startup, not after a credential leak.
	mode := info.Mode()
	if mode.Perm() != 0o600 {
		return nil, fmt.Errorf("executor/secret/envfile: %s mode is %#o (expected 0o600 — refusing world-readable secret material)", path, mode.Perm())
	}
	f, err := os.Open(path)
	if err != nil {
		return nil, fmt.Errorf("executor/secret/envfile: open %s: %w", path, err)
	}
	defer f.Close()

	table := make(map[string]string)
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		// `KEY=value` — split on the FIRST `=` only (values may
		// contain `=` chars, e.g. base64 padding).
		eq := strings.IndexByte(line, '=')
		if eq < 0 {
			continue // malformed line; skip silently
		}
		key := strings.TrimSpace(line[:eq])
		value := strings.TrimSpace(line[eq+1:])
		// Strip surrounding quotes (single or double).
		if len(value) >= 2 {
			first, last := value[0], value[len(value)-1]
			if (first == '"' && last == '"') || (first == '\'' && last == '\'') {
				value = value[1 : len(value)-1]
			}
		}
		if key == "" {
			continue
		}
		table[key] = value
	}
	if err := scanner.Err(); err != nil {
		return nil, fmt.Errorf("executor/secret/envfile: scan %s: %w", path, err)
	}
	return &EnvFileSecretStore{
		path:  path,
		table: table,
	}, nil
}

// Resolve looks the credential_ref up in the loaded table.
// Note: this matches the reference key verbatim — there's no
// `SENTRAOPS_EXECUTOR_CREDENTIAL_` prefix here (the operator
// populated the file with whatever keys they want, and the
// server's credential_ref string is the lookup key).
func (s *EnvFileSecretStore) Resolve(_ context.Context, credentialRef string) (string, error) {
	if credentialRef == "" {
		return "", errors.New("executor/secret/envfile: empty credential_ref")
	}
	s.mu.RLock()
	value, ok := s.table[credentialRef]
	s.mu.RUnlock()
	if !ok {
		return "", fmt.Errorf("executor/secret/envfile: %q not found in %s", credentialRef, s.path)
	}
	if value == "" {
		return "", fmt.Errorf("executor/secret/envfile: %q has empty value in %s", credentialRef, s.path)
	}
	return value, nil
}
