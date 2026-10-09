package executor

import (
	"context"
	"crypto/tls"
	"crypto/x509"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

// newTestVaultServer spins a real Vault-fake httptest server
// on TLS (so it passes the executor's HTTPS-only check). The
// caller supplies a handler that returns Vault-shaped JSON
// from `data.data.<key>=value` requests.
func newTestVaultServer(t *testing.T, handler http.HandlerFunc) (*httptest.Server, string) {
	t.Helper()
	srv := httptest.NewTLSServer(handler)
	t.Cleanup(srv.Close)
	return srv, srv.URL
}

// vaultStoreFromTestServer builds a VaultSecretStore wired
// to a test server URL. We override the constructor's
// "must be https" check by using the test server's https://
// URL (which IS https) + a custom transport that skips CA
// verification (test scaffolding only — production never
// uses InsecureSkipVerify).
func vaultStoreFromTestServer(t *testing.T, srvURL string, token string) *VaultSecretStore {
	t.Helper()
	cfg := VaultConfig{
		BaseURL: srvURL,
		Token:   token,
		Mount:   "secret",
	}
	s, err := NewVaultSecretStore(cfg)
	if err != nil {
		t.Fatalf("NewVaultSecretStore: %v", err)
	}
	// Replace TLS verification with InsecureSkipVerify
	// (test scaffolding — production trusts the system CA
	// bundle). The Vault production path uses the default
	// http.Client's TLS config (system roots).
	s.httpClient.Transport = &http.Transport{
		TLSClientConfig: &tls.Config{InsecureSkipVerify: true}, //nolint:gosec
		Proxy:           http.ProxyFromEnvironment,
		DialContext: (&net.Dialer{
			Timeout:   2 * time.Second,
			KeepAlive: 30 * time.Second,
		}).DialContext,
	}
	_ = x509.NewCertPool // keep import "used" in case future test needs it
	return s
}

// TestVaultSecretStoreConstructorRejectsPlaintext pins the
// fail-closed "must be HTTPS" check.
func TestVaultSecretStoreConstructorRejectsPlaintext(t *testing.T) {
	tests := []struct {
		name string
		url  string
	}{
		{"http", "http://vault.example.com"},
		{"empty", ""},
		{"missing token", "https://vault.example.com"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			cfg := VaultConfig{
				BaseURL: tc.url,
				Token:   "if-set",
			}
			if tc.name == "missing token" {
				cfg.Token = ""
			}
			if _, err := NewVaultSecretStore(cfg); err == nil {
				t.Errorf("NewVaultSecretStore(%v) should fail", cfg)
			}
		})
	}
}

// TestVaultSecretStoreHappyPath verifies the basic KV v2
// round-trip.
func TestVaultSecretStoreHappyPath(t *testing.T) {
	_, url := newTestVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		if r.Header.Get("X-Vault-Token") != "test-token" {
			w.WriteHeader(http.StatusForbidden)
			return
		}
		if !strings.Contains(r.URL.Path, "/v1/secret/data/deploy/windows") {
			w.WriteHeader(http.StatusNotFound)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"value": "hunter2",
				},
				"metadata": map[string]interface{}{},
			},
		})
	})
	store := vaultStoreFromTestServer(t, url, "test-token")
	got, err := store.Resolve(context.Background(), "deploy/windows")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "hunter2" {
		t.Errorf("Resolve = %q, want hunter2", got)
	}
}

// TestVaultSecretStoreForbiddenToken ensures a 403 from Vault
// (token rejected) surfaces as a clear error.
func TestVaultSecretStoreForbiddenToken(t *testing.T) {
	_, url := newTestVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	})
	store := vaultStoreFromTestServer(t, url, "expired-token")
	_, err := store.Resolve(context.Background(), "deploy/windows")
	if err == nil {
		t.Fatal("Resolve should fail when Vault returns 403")
	}
	if !strings.Contains(err.Error(), "token rejected") {
		t.Errorf("err = %v, want '...token rejected...'", err)
	}
}

// TestVaultSecretStoreNotFound ensures a 404 from Vault
// surfaces as a descriptive error.
func TestVaultSecretStoreNotFound(t *testing.T) {
	_, url := newTestVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
	})
	store := vaultStoreFromTestServer(t, url, "test-token")
	_, err := store.Resolve(context.Background(), "missing/path")
	if err == nil {
		t.Fatal("Resolve should fail when Vault returns 404")
	}
	if !strings.Contains(err.Error(), "no secret") {
		t.Errorf("err = %v, want '...no secret...'", err)
	}
}

// TestVaultSecretStoreAcceptsAlternativeFieldNames verifies
// that operators can use `credential` / `password` / `secret`
// as the field name (we try multiple conventional keys).
func TestVaultSecretStoreAcceptsAlternativeFieldNames(t *testing.T) {
	tests := []struct {
		name  string
		field string
		value string
	}{
		{"value", "value", "v-val"},
		{"credential", "credential", "c-val"},
		{"password", "password", "p-val"},
		{"secret", "secret", "s-val"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, url := newTestVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
				_ = json.NewEncoder(w).Encode(map[string]interface{}{
					"data": map[string]interface{}{
						"data": map[string]interface{}{
							tc.field: tc.value,
						},
					},
				})
			})
			store := vaultStoreFromTestServer(t, url, "token")
			got, err := store.Resolve(context.Background(), "deploy/windows")
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			if got != tc.value {
				t.Errorf("Resolve = %q, want %q", got, tc.value)
			}
		})
	}
}

// TestVaultSecretStoreEmptyCredentialsFails pins the
// fail-closed empty-ref contract.
func TestVaultSecretStoreEmptyCredentialsFails(t *testing.T) {
	store := vaultStoreFromTestServer(t, "https://vault.invalid", "token")
	if _, err := store.Resolve(context.Background(), ""); err == nil {
		t.Error("Resolve(\"\") should fail")
	}
}

// TestVaultSecretStoreMissingFieldIsLoud ensures that a
// successful HTTP response without a recognized field
// produces a clear error (not an empty string).
func TestVaultSecretStoreMissingFieldIsLoud(t *testing.T) {
	_, url := newTestVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{
					"unrecognized": "not-a-secret",
				},
			},
		})
	})
	store := vaultStoreFromTestServer(t, url, "token")
	_, err := store.Resolve(context.Background(), "deploy/windows")
	if err == nil {
		t.Fatal("Resolve should fail when no recognized field exists")
	}
	if !strings.Contains(err.Error(), "no value") {
		t.Errorf("err = %v, want '...no value...'", err)
	}
}

// TestVaultSecretStoreSupportsSecretsPrefix ensures the
// operator can write `secret/data/foo` style refs without
// doubling up the mount.
func TestVaultSecretStoreSupportsSecretsPrefix(t *testing.T) {
	_, url := newTestVaultServer(t, func(w http.ResponseWriter, r *http.Request) {
		expected := "/v1/secret/data/deploy/linux"
		if r.URL.Path != expected {
			t.Errorf("path = %q, want %q", r.URL.Path, expected)
		}
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(map[string]interface{}{
			"data": map[string]interface{}{
				"data": map[string]interface{}{"value": "ok"},
			},
		})
	})
	store := vaultStoreFromTestServer(t, url, "token")
	got, err := store.Resolve(context.Background(), "secret/data/deploy/linux")
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if got != "ok" {
		t.Errorf("Resolve = %q, want ok", got)
	}
	_ = fmt.Sprintf // keep import used
}
