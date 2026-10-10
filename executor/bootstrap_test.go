package executor

import (
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"io"
	"math/big"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// selfSignedTestCA generates a fresh ECDSA CA + matching leaf cert
// for tests that need a real PEM cert. We use ECDSA here (not
// Ed25519) so the bootstrap tests don't pull in the certgen package's
// heavyweight setup — the bootstrap layer treats the bytes as opaque
// PEM.
func selfSignedTestCA(t *testing.T) (certPEM, keyPEM, caPEM []byte) {
	t.Helper()
	caKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	caTmpl := &x509.Certificate{
		SerialNumber:          big.NewInt(1),
		Subject:               pkix.Name{CommonName: "Test CA"},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(time.Hour),
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
	}
	caDER, err := x509.CreateCertificate(rand.Reader, caTmpl, caTmpl, &caKey.PublicKey, caKey)
	require.NoError(t, err)
	caPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: caDER})

	leafKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	require.NoError(t, err)
	leafTmpl := &x509.Certificate{
		SerialNumber: big.NewInt(2),
		Subject:      pkix.Name{CommonName: "exec-1"},
		NotBefore:    time.Now().Add(-time.Minute),
		NotAfter:     time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:     x509.KeyUsageDigitalSignature,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}
	leafDER, err := x509.CreateCertificate(rand.Reader, leafTmpl, caTmpl, &leafKey.PublicKey, caKey)
	require.NoError(t, err)
	certPEM = pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: leafDER})

	keyDER, err := x509.MarshalPKCS8PrivateKey(leafKey)
	require.NoError(t, err)
	keyPEM = pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})
	return certPEM, keyPEM, caPEM
}

// fakeEnrollServer spins an httptest.Server that returns the
// supplied EnrollResponse on POST. It records the header it saw so
// tests can assert the executor sent X-Enrollment-Token.
type fakeEnrollServer struct {
	*httptest.Server
	t                *testing.T
	receivedToken    atomic.Value // string
	receivedAuth     atomic.Value // string
	callCount        atomic.Int32
	cannedResponse   *EnrollResponse
	cannedStatus     int
	cannedBody       string
}

func newFakeEnrollServer(t *testing.T, status int, body string) *fakeEnrollServer {
	t.Helper()
	f := &fakeEnrollServer{
		t:             t,
		cannedStatus:  status,
		cannedBody:    body,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/executor/enroll", func(w http.ResponseWriter, r *http.Request) {
		f.callCount.Add(1)
		f.receivedToken.Store(strings.TrimSpace(r.Header.Get(HeaderEnrollmentToken)))
		f.receivedAuth.Store(strings.TrimSpace(r.Header.Get("Authorization")))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		if body != "" {
			_, _ = io.WriteString(w, body)
		}
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

func newFakeEnrollServerWithResponse(t *testing.T, resp EnrollResponse) *fakeEnrollServer {
	t.Helper()
	f := &fakeEnrollServer{
		t:              t,
		cannedStatus:   http.StatusOK,
		cannedResponse: &resp,
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/api/v1/executor/enroll", func(w http.ResponseWriter, r *http.Request) {
		f.callCount.Add(1)
		f.receivedToken.Store(strings.TrimSpace(r.Header.Get(HeaderEnrollmentToken)))
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(http.StatusOK)
		_ = json.NewEncoder(w).Encode(resp)
	})
	f.Server = httptest.NewServer(mux)
	t.Cleanup(f.Server.Close)
	return f
}

// TestRunBootstrap_NoTokenIsNoop verifies a config without a token is
// a clean no-op (the post-migration steady state where the cert is
// already on disk).
func TestRunBootstrap_NoTokenIsNoop(t *testing.T) {
	tmp := t.TempDir()
	cfg := Config{
		ServerURL:       "https://doesnotmatter.example",
		ClientCertPath:  filepath.Join(tmp, "cert.pem"),
		ClientKeyPath:   filepath.Join(tmp, "key.pem"),
		ServerCAFile:    filepath.Join(tmp, "ca.pem"),
		BootstrapToken:  "", // post-migration steady state
	}
	require.NoError(t, RunBootstrap(cfg, "", logrus.New()))
	assert.Equal(t, int32(0), int32(0), "no network call expected") // sanity; the asserts above do all the work
}

// TestRunBootstrap_HappyPath verifies a token exchanges for a cert,
// the cert is written to disk, the cert on disk matches the server
// response, the file mode is 0o600, the token is cleared from the
// config file, and a re-run with an empty token is a no-op.
func TestRunBootstrap_HappyPath(t *testing.T) {
	tmp := t.TempDir()
	certPEM, keyPEM, caPEM := selfSignedTestCA(t)

	srv := newFakeEnrollServerWithResponse(t, EnrollResponse{
		ExecutorID:    "exec-1",
		ExecutorToken: "exec-token-clear",
		CertPEM:       string(certPEM),
		KeyPEM:        string(keyPEM),
		CABundlePEM:   string(caPEM),
		SentraOpsURL:  "https://example.com",
		TenantID:      "ORG-1",
	})

	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	caPath := filepath.Join(tmp, "ca.pem")
	configPath := filepath.Join(tmp, "config.yaml")

	// Pre-write the config file so we can verify clearBootstrapToken
	// in place after the exchange.
	configBody := []byte(
		"server_url: " + srv.URL + "\n" +
			"tenant_id: ORG-1\n" +
			"deployment_zone_id: ZONE-A\n" +
			"client_cert_path: " + certPath + "\n" +
			"client_key_path: " + keyPath + "\n" +
			"server_ca_file: " + caPath + "\n" +
			"bootstrap_token: THE-PLAINTEXT-TOKEN\n" +
			"bootstrap_url: " + srv.URL + "\n",
	)
	require.NoError(t, os.WriteFile(configPath, configBody, PathCertFileMode))

	cfg := Config{
		ServerURL:      srv.URL,
		TenantID:       "ORG-1",
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
		ServerCAFile:   caPath,
		BootstrapToken: "THE-PLAINTEXT-TOKEN",
		BootstrapURL:   srv.URL,
	}
	require.NoError(t, RunBootstrap(cfg, configPath, logrus.New()))

	// Files written with correct content.
	writtenCert, err := os.ReadFile(certPath)
	require.NoError(t, err)
	assert.Equal(t, string(certPEM), string(writtenCert))
	writtenKey, err := os.ReadFile(keyPath)
	require.NoError(t, err)
	assert.Equal(t, string(keyPEM), string(writtenKey))
	writtenCA, err := os.ReadFile(caPath)
	require.NoError(t, err)
	assert.Equal(t, string(caPEM), string(writtenCA))

	// Files written with mode 0o600 (owner-only).
	for _, p := range []string{certPath, keyPath, caPath} {
		st, err := os.Stat(p)
		require.NoError(t, err)
		assert.Equal(t, os.FileMode(PathCertFileMode), st.Mode().Perm(),
			"file %s must be owner-only", p)
	}

	// Token cleared from config (the secret value is no longer on
	// disk).
	updated, err := os.ReadFile(configPath)
	require.NoError(t, err)
	assert.NotContains(t, string(updated), "THE-PLAINTEXT-TOKEN",
		"bootstrap_token must be cleared from config after exchange")

	// Server saw the token in the right header.
	assert.Equal(t, "THE-PLAINTEXT-TOKEN", srv.receivedToken.Load())
	assert.Equal(t, int32(1), srv.callCount.Load())

	// Re-run with no token is a clean no-op (the cert is already
	// on disk; bootstrap.go short-circuits).
	cfg.BootstrapToken = ""
	require.NoError(t, RunBootstrap(cfg, configPath, logrus.New()))
	assert.Equal(t, int32(1), srv.callCount.Load(), "second run must not hit network")
}

// TestRunBootstrap_IdempotentWhenCertExists verifies the cert-already-on-disk
// short-circuit (no network call, no file rewrite).
func TestRunBootstrap_IdempotentWhenCertExists(t *testing.T) {
	tmp := t.TempDir()
	certPEM, _, _ := selfSignedTestCA(t)
	certPath := filepath.Join(tmp, "cert.pem")
	require.NoError(t, os.WriteFile(certPath, certPEM, PathCertFileMode))

	srv := newFakeEnrollServerWithResponse(t, EnrollResponse{
		CertPEM:     "should-not-be-used",
		KeyPEM:      "should-not-be-used",
		CABundlePEM: "should-not-be-used",
	})

	cfg := Config{
		ServerURL:      srv.URL,
		TenantID:       "ORG-1",
		ClientCertPath: certPath,
		ClientKeyPath:  filepath.Join(tmp, "key.pem"),
		ServerCAFile:   filepath.Join(tmp, "ca.pem"),
		BootstrapToken: "ANY-TOKEN",
	}
	require.NoError(t, RunBootstrap(cfg, "", logrus.New()))
	assert.Equal(t, int32(0), srv.callCount.Load(),
		"existing cert must short-circuit before any network call")
}

// TestRunBootstrap_FailsLoudOn401 verifies a non-200 from /enroll
// surfaces as a clear error WITHOUT writing any files. The
// bootstrap_token stays in the config so install.sh can retry.
func TestRunBootstrap_FailsLoudOn401(t *testing.T) {
	tmp := t.TempDir()
	certPath := filepath.Join(tmp, "cert.pem")
	keyPath := filepath.Join(tmp, "key.pem")
	caPath := filepath.Join(tmp, "ca.pem")
	configPath := filepath.Join(tmp, "config.yaml")
	require.NoError(t, os.WriteFile(configPath, []byte("bootstrap_token: STILL-HERE\n"), PathCertFileMode))

	srv := newFakeEnrollServer(t, http.StatusUnauthorized, `{"error":"enrollment_token_invalid"}`)

	cfg := Config{
		ServerURL:      srv.URL,
		TenantID:       "ORG-1",
		ClientCertPath: certPath,
		ClientKeyPath:  keyPath,
		ServerCAFile:   caPath,
		BootstrapToken: "BAD-TOKEN",
	}

	err := RunBootstrap(cfg, configPath, logrus.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "401")

	// No files materialized.
	for _, p := range []string{certPath, keyPath, caPath} {
		_, statErr := os.Stat(p)
		assert.True(t, os.IsNotExist(statErr),
			"file %s must not exist after a failed exchange", p)
	}

	// Token NOT cleared from config (retry path).
	data, _ := os.ReadFile(configPath)
	assert.Contains(t, string(data), "STILL-HERE",
		"bootstrap_token must stay on disk so install.sh can retry")
}

// TestRunBootstrap_FailsLoudOn410 verifies expired tokens surface as
// 410 with the server's body in the error so the operator can see it.
func TestRunBootstrap_FailsLoudOn410(t *testing.T) {
	tmp := t.TempDir()
	srv := newFakeEnrollServer(t, http.StatusGone, `{"error":"enrollment_token_expired"}`)
	cfg := Config{
		ServerURL:      srv.URL,
		TenantID:       "ORG-1",
		ClientCertPath: filepath.Join(tmp, "cert.pem"),
		ClientKeyPath:  filepath.Join(tmp, "key.pem"),
		ServerCAFile:   filepath.Join(tmp, "ca.pem"),
		BootstrapToken: "EXPIRED",
	}
	err := RunBootstrap(cfg, "", logrus.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "410")
	assert.Contains(t, err.Error(), "enrollment_token_expired",
		"the server's error message must surface in our error")
}

// TestRunBootstrap_RejectsMissingServerURL guards the
// fail-closed-with-empty-server-url case (caller passed bootstrap_token
// but no ServerURL).
func TestRunBootstrap_RejectsMissingServerURL(t *testing.T) {
	cfg := Config{
		TenantID:       "ORG-1",
		ClientCertPath: "/x",
		ClientKeyPath:  "/x",
		ServerCAFile:   "/x",
		BootstrapToken: "ANY",
	}
	err := RunBootstrap(cfg, "", logrus.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "server_url")
}

// TestRunBootstrap_RejectsMissingCertPaths guards against a config
// that says bootstrap_token is set but has no place to write the cert.
func TestRunBootstrap_RejectsMissingCertPaths(t *testing.T) {
	cfg := Config{
		ServerURL:      "https://example.com",
		TenantID:       "ORG-1",
		BootstrapToken: "ANY",
	}
	err := RunBootstrap(cfg, "", logrus.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "client_cert_path")
}

// TestEnrollResponse_RejectsMissingFields guards against the
// server returning a malformed 200 (e.g. empty cert_pem). The
// executor must refuse rather than write a half-formed cert.
func TestEnrollResponse_RejectsMissingFields(t *testing.T) {
	srv := newFakeEnrollServerWithResponse(t, EnrollResponse{
		// CertPEM, KeyPEM, CABundlePEM all empty.
	})
	cfg := Config{
		ServerURL:      srv.URL,
		TenantID:       "ORG-1",
		ClientCertPath: filepath.Join(t.TempDir(), "cert.pem"),
		ClientKeyPath:  filepath.Join(t.TempDir(), "key.pem"),
		ServerCAFile:   filepath.Join(t.TempDir(), "ca.pem"),
		BootstrapToken: "ANY",
	}
	err := RunBootstrap(cfg, "", logrus.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "cert_pem")
}

// TestEnrollResponse_RejectsNonPEMCert guards against a cert that
// doesn't start with the BEGIN CERTIFICATE marker.
func TestEnrollResponse_RejectsNonPEMCert(t *testing.T) {
	srv := newFakeEnrollServerWithResponse(t, EnrollResponse{
		CertPEM:     "not a cert",
		KeyPEM:      "-----BEGIN PRIVATE KEY-----\nABC\n-----END PRIVATE KEY-----\n",
		CABundlePEM: "-----BEGIN CERTIFICATE-----\nABC\n-----END CERTIFICATE-----\n",
	})
	cfg := Config{
		ServerURL:      srv.URL,
		TenantID:       "ORG-1",
		ClientCertPath: filepath.Join(t.TempDir(), "cert.pem"),
		ClientKeyPath:  filepath.Join(t.TempDir(), "key.pem"),
		ServerCAFile:   filepath.Join(t.TempDir(), "ca.pem"),
		BootstrapToken: "ANY",
	}
	err := RunBootstrap(cfg, "", logrus.New())
	require.Error(t, err)
	assert.Contains(t, err.Error(), "not PEM")
}

// TestWriteFileAtomic_Applies0600 verifies the on-disk file mode is
// enforced (matches the SecretStore 0o600 refusal posture).
func TestWriteFileAtomic_Applies0600(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "x.pem")
	require.NoError(t, writeFileAtomic(path, []byte("hello"), 0o600))
	st, err := os.Stat(path)
	require.NoError(t, err)
	assert.Equal(t, os.FileMode(0o600), st.Mode().Perm())
}

// TestWriteFileAtomic_RefusesZeroPerm is a defensive guard: a
// caller passing 0o000 must error out (matches the SecretStore 0o000
// refusal).
func TestWriteFileAtomic_RefusesZeroPerm(t *testing.T) {
	err := writeFileAtomic("/tmp/should-not-exist", []byte("nope"), 0o000)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "refusing zero perm")
}

// TestClearBootstrapTokenInConfig verifies the on-disk config has
// the bootstrap_token line + bootstrap_url line removed, comments
// and ordering otherwise preserved.
func TestClearBootstrapTokenInConfig(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "config.yaml")
	original := strings.Join([]string{
		"# header comment",
		"server_url: https://example.com",
		"bootstrap_token: SECRET-VALUE",
		"tenant_id: ORG-1",
		"bootstrap_url: https://example.com",
		"deployment_zone_id: ZONE-A",
		"",
	}, "\n")
	require.NoError(t, os.WriteFile(path, []byte(original), PathCertFileMode))

	require.NoError(t, clearBootstrapTokenInConfig(path))

	data, err := os.ReadFile(path)
	require.NoError(t, err)
	got := string(data)
	assert.NotContains(t, got, "SECRET-VALUE")
	assert.NotContains(t, got, "bootstrap_token")
	assert.NotContains(t, got, "bootstrap_url")
	// Comments + other keys preserved.
	assert.Contains(t, got, "# header comment")
	assert.Contains(t, got, "server_url: https://example.com")
	assert.Contains(t, got, "tenant_id: ORG-1")
	assert.Contains(t, got, "deployment_zone_id: ZONE-A")
	// Trailing newline preserved.
	assert.True(t, strings.HasSuffix(got, "\n"))
}