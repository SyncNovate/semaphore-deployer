package executor

import (
	"errors"
	"fmt"
	"os"
	"strings"
)

// SecretStoreBackend enumerates the backend names the
// executor recognises. The set is closed (string-typed) so
// an operator's typo on `Config.SecretStore` fails loud at
// startup instead of silently falling back to NoopSecretStore.
const (
	SecretStoreBackendNoop        = "noop"
	SecretStoreBackendProcessEnv  = "processenv"
	SecretStoreBackendEnvFile     = "envfile"
	SecretStoreBackendVault       = "vault"
)

// NewSecretStoreFromConfig picks the right backend and
// instantiates it. The orchestrator calls this when it has
// no SecretStore injected (which is the normal production
// path; tests usually pass a stub directly).
//
// Returns the chosen SecretStore OR an error describing why
// the constructor failed. Never silently returns a
// NoopSecretStore for a misconfigured backend — the operator
// needs to know.
func NewSecretStoreFromConfig(cfg Config) (SecretStore, error) {
	backend := strings.TrimSpace(strings.ToLower(cfg.SecretStore))
	switch backend {
	case "", SecretStoreBackendNoop:
		// Empty string defaults to noop (the historical V1
		// behavior — useful for sandbox deployments where
		// the playbook doesn't need a secret).
		return NoopSecretStore{}, nil

	case SecretStoreBackendProcessEnv:
		return NewProcessEnvSecretStore("SENTRAOPS_EXECUTOR_CREDENTIAL_"), nil

	case SecretStoreBackendEnvFile:
		path := strings.TrimSpace(cfg.SecretStoreEnvFile)
		if path == "" {
			// Default to a conventional location; the
			// operator can override via env if needed.
			path = os.Getenv("SENTRAOPS_EXECUTOR_CREDENTIALS_FILE")
		}
		if path == "" {
			return nil, errors.New("executor/secret: SecretStore=envfile requires SecretStoreEnvFile (or SENTRAOPS_EXECUTOR_CREDENTIALS_FILE env var)")
		}
		return NewEnvFileSecretStore(path)

	case SecretStoreBackendVault:
		url := strings.TrimSpace(cfg.SecretStoreVaultURL)
		token := strings.TrimSpace(cfg.SecretStoreVaultToken)
		// Env-var fallback for the token — never commit it
		// to the YAML file. URL goes via Config because it's
		// not as sensitive as the token.
		if token == "" {
			token = os.Getenv("SENTRAOPS_EXECUTOR_VAULT_TOKEN")
		}
		if url == "" {
			return nil, errors.New("executor/secret: SecretStore=vault requires SecretStoreVaultURL")
		}
		if token == "" {
			return nil, errors.New("executor/secret: SecretStore=vault requires SecretStoreVaultToken (or SENTRAOPS_EXECUTOR_VAULT_TOKEN env var)")
		}
		return NewVaultSecretStore(VaultConfig{
			BaseURL: url,
			Token:   token,
			Mount:   cfg.SecretStoreVaultMount,
		})

	default:
		return nil, fmt.Errorf("executor/secret: unknown backend %q (supported: noop, processenv, envfile, vault)", backend)
	}
}
