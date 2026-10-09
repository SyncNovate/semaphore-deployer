package executor

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"
)

// VaultSecretStore resolves credentials from a HashiCorp
// Vault server using the KV v2 secret engine. The store is
// configured with a base URL (e.g. https://vault.example.com),
// a token, and a mount point (default "secret").
//
// Wire protocol:
//
//   GET /v1/<mount>/data/<path>
//   Headers: X-Vault-Token: <token>
//
// A successful response (200 OK) has the shape:
//
//   {
//     "data": {
//       "data": {
//         "value": "<plaintext secret>"
//       },
//       "metadata": { ... }
//     }
//   }
//
// The store reads `data.data.value` (or the alternative
// `data.data.credential` for ops that prefer a less
// editor-friendly field name). Both keys are tried in order.
//
// Network + auth errors are NOT cached — every Resolve()
// makes a fresh request (Vault's KV v2 backend is fast; no
// client-side cache reduces the staleness footprint).
//
// No TLS pinning here: the customer-side executor trusts the
// system CA bundle for the Vault URL (the executor's regular
// HTTP client has its own pinning behaviour for the
// Semaphore backend, but Vault is a separate trust domain).
type VaultSecretStore struct {
	baseURL    string
	token      string
	mount      string
	httpClient *http.Client
}

// VaultConfig is the constructor input. The factory in
// secret_registry.go assembles this from Config + env.
type VaultConfig struct {
	BaseURL string
	Token   string
	Mount   string // optional; defaults to "secret"
	Timeout time.Duration // optional; defaults to 5s
}

// NewVaultSecretStore constructs the backend. baseURL must be
// a non-empty HTTPS URL (the constructor refuses HTTP — Vault
// tokens MUST NOT traverse plaintext).
func NewVaultSecretStore(cfg VaultConfig) (*VaultSecretStore, error) {
	if cfg.BaseURL == "" {
		return nil, errors.New("executor/secret/vault: BaseURL is required")
	}
	if !strings.HasPrefix(strings.ToLower(cfg.BaseURL), "https://") {
		return nil, errors.New("executor/secret/vault: BaseURL must be https:// (Vault tokens are sent in X-Vault-Token; plaintext transport is forbidden)")
	}
	if cfg.Token == "" {
		return nil, errors.New("executor/secret/vault: Token is required")
	}
	mount := cfg.Mount
	if mount == "" {
		mount = "secret"
	}
	timeout := cfg.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	return &VaultSecretStore{
		baseURL: strings.TrimRight(cfg.BaseURL, "/"),
		token:   cfg.Token,
		mount:   mount,
		httpClient: &http.Client{
			Timeout: timeout,
		},
	}, nil
}

// Resolve fetches the credential_ref as a Vault KV v2 path.
// The operator maps their `credential_ref` strings to Vault
// paths — the simplest convention is `secret/data/<ref>`
// (Vault's `data/data` double-prefix comes from the KV v2
// URL scheme; we strip the "data/" prefix from the ref
// since the mount itself already names the engine).
func (s *VaultSecretStore) Resolve(ctx context.Context, credentialRef string) (string, error) {
	if credentialRef == "" {
		return "", errors.New("executor/secret/vault: empty credential_ref")
	}
	path := strings.TrimLeft(credentialRef, "/")
	// Allow `secret/data/foo` style refs verbatim (the
	// operator may want full control over the mount path).
	if strings.HasPrefix(path, s.mount+"/data/") {
		path = strings.TrimPrefix(path, s.mount+"/data/")
	}
	url := fmt.Sprintf("%s/v1/%s/data/%s", s.baseURL, s.mount, path)

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, url, nil)
	if err != nil {
		return "", fmt.Errorf("executor/secret/vault: build request: %w", err)
	}
	req.Header.Set("X-Vault-Token", s.token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return "", fmt.Errorf("executor/secret/vault: GET %s: %w", url, err)
	}
	defer resp.Body.Close()

	switch {
	case resp.StatusCode == http.StatusForbidden || resp.StatusCode == http.StatusUnauthorized:
		// Token expired or revoked. The operator must
		// rotate; the executor cannot auto-recover.
		return "", fmt.Errorf("executor/secret/vault: token rejected (HTTP %d) — rotate the Vault token", resp.StatusCode)
	case resp.StatusCode == http.StatusNotFound:
		return "", fmt.Errorf("executor/secret/vault: no secret at path %q (HTTP 404)", path)
	case resp.StatusCode != http.StatusOK:
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("executor/secret/vault: HTTP %d from %s: %s", resp.StatusCode, url, strings.TrimSpace(string(body)))
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return "", fmt.Errorf("executor/secret/vault: read body: %w", err)
	}

	var parsed struct {
		Data struct {
			Data map[string]interface{} `json:"data"`
		} `json:"data"`
	}
	if err := json.Unmarshal(body, &parsed); err != nil {
		return "", fmt.Errorf("executor/secret/vault: parse response: %w", err)
	}

	// Look up the secret in `data.data` — operators may use
	// either the `value` or `credential` field name; both
	// are conventional.
	for _, key := range []string{"value", "credential", "password", "secret"} {
		if v, ok := parsed.Data.Data[key].(string); ok && v != "" {
			return v, nil
		}
	}
	return "", fmt.Errorf("executor/secret/vault: no value/credential/password/secret field under data.data at path %q", path)
}
