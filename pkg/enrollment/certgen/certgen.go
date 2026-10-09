// Package certgen mints the long-lived mTLS leaf certificates the
// executor receives from POST /api/v1/executor/enroll (R-I.10.re1).
//
// The CA keypair is generated once at server startup (or loaded from
// the platform's KMS — see R-I.10.re1 followup). For test scaffolding
// the CA is generated per-process so tests do not need a real CA on
// disk. The CA root is the only thing the executor needs in its CA
// bundle to verify the server's TLS cert at every subsequent call.
//
// Why Ed25519 (per design doc §9.2): small keys, fast verify, modern
// security margins, RFC 8037 + RFC 8410 compliant. The existing
// executor already uses Ed25519 for its JWT (R-I.4.b); the cert stays
// in the same key family so the platform has a single signing story.
package certgen

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"time"
)

// CAMaterial is the long-lived CA keypair the server signs every
// executor's leaf cert with. CA private key is held server-side only;
// the PEM-encoded cert (without the key) is what /enroll returns in
// the ca_bundle so the executor can verify the server's TLS cert.
type CAMaterial struct {
	CertPEM []byte // PEM-encoded X.509 certificate (CA:TRUE)
	KeyPEM  []byte // PEM-encoded PKCS#8 private key (NEVER sent to the executor)
}

// NewCA generates a fresh Ed25519 self-signed CA. Use at server
// startup; persist CertPEM + KeyPEM to the platform's KMS + CA
// keystore. The CA subject is generic on purpose — it is the issuer,
// not the principal.
func NewCA(commonName string) (CAMaterial, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return CAMaterial{}, fmt.Errorf("ca key gen: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return CAMaterial{}, fmt.Errorf("ca serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   commonName,
			Organization: []string{"SentraOps"},
		},
		NotBefore:             time.Now().Add(-time.Hour),
		NotAfter:              time.Now().Add(10 * 365 * 24 * time.Hour), // 10y
		KeyUsage:              x509.KeyUsageCertSign | x509.KeyUsageCRLSign,
		BasicConstraintsValid: true,
		IsCA:                  true,
		MaxPathLen:            1,
		MaxPathLenZero:        false,
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, pub, priv)
	if err != nil {
		return CAMaterial{}, fmt.Errorf("ca create cert: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return CAMaterial{}, fmt.Errorf("ca marshal key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return CAMaterial{CertPEM: certPEM, KeyPEM: keyPEM}, nil
}

// ParseCA parses a previously-stored CA back from PEM. Used at server
// startup to load the CA from the platform's KMS.
func ParseCA(certPEM, keyPEM []byte) (CAMaterial, *x509.Certificate, ed25519.PrivateKey, error) {
	cb, _ := pem.Decode(certPEM)
	if cb == nil || cb.Type != "CERTIFICATE" {
		return CAMaterial{}, nil, nil, errors.New("ca cert pem: invalid or missing CERTIFICATE block")
	}
	cert, err := x509.ParseCertificate(cb.Bytes)
	if err != nil {
		return CAMaterial{}, nil, nil, fmt.Errorf("ca cert parse: %w", err)
	}
	if !cert.IsCA {
		return CAMaterial{}, nil, nil, errors.New("ca cert: not a CA (IsCA=false)")
	}

	kb, _ := pem.Decode(keyPEM)
	if kb == nil || kb.Type != "PRIVATE KEY" {
		return CAMaterial{}, nil, nil, errors.New("ca key pem: invalid or missing PRIVATE KEY block")
	}
	key, err := x509.ParsePKCS8PrivateKey(kb.Bytes)
	if err != nil {
		return CAMaterial{}, nil, nil, fmt.Errorf("ca key parse: %w", err)
	}
	edKey, ok := key.(ed25519.PrivateKey)
	if !ok {
		return CAMaterial{}, nil, nil, errors.New("ca key: not Ed25519")
	}

	return CAMaterial{CertPEM: certPEM, KeyPEM: keyPEM}, cert, edKey, nil
}

// ExecutorCert is the bundle /enroll returns to the executor. The
// executor writes CertPEM + KeyPEM to its standard paths (e.g.
// /etc/sentraops-executor/cert.pem + key.pem) and uses CABundlePEM to
// verify the server's TLS cert at every subsequent call.
type ExecutorCert struct {
	CertPEM    []byte // leaf cert (mTLS client cert)
	KeyPEM     []byte // leaf private key (PKCS#8)
	CABundlePEM []byte // CA cert (so the executor can verify the server)
}

// IssueExecutorCert mints a fresh Ed25519 leaf cert for the executor
// signed by the given CA. Validity is 1 year per design doc §9.3.
// Subject CN is the public ExecutorID; SAN includes the literal CN as
// well (x509 requires it for client cert auth per RFC 6125).
//
// hostname is the optional hostname the executor reported at
// enrollment; it becomes a SAN entry. Pass "" if not known.
func IssueExecutorCert(ca *CAMaterial, executorID string, hostname string) (ExecutorCert, error) {
	if executorID == "" {
		return ExecutorCert{}, errors.New("executor id required")
	}
	if len(ca.CertPEM) == 0 || len(ca.KeyPEM) == 0 {
		return ExecutorCert{}, errors.New("ca material required (cert + key)")
	}

	_, caCert, caKey, err := ParseCA(ca.CertPEM, ca.KeyPEM)
	if err != nil {
		return ExecutorCert{}, fmt.Errorf("parse ca: %w", err)
	}

	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return ExecutorCert{}, fmt.Errorf("executor key gen: %w", err)
	}

	serial, err := randomSerial()
	if err != nil {
		return ExecutorCert{}, fmt.Errorf("executor serial: %w", err)
	}

	tmpl := &x509.Certificate{
		SerialNumber: serial,
		Subject: pkix.Name{
			CommonName:   executorID,
			Organization: []string{"SentraOps Executor"},
		},
		NotBefore:   time.Now().Add(-time.Minute),
		NotAfter:    time.Now().Add(365 * 24 * time.Hour), // 1y
		KeyUsage:    x509.KeyUsageDigitalSignature,
		ExtKeyUsage: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		IsCA:                  false,
	}
	// SAN entries. The CN must be duplicated here per RFC 6125 for
	// strict verifier compatibility (some verifiers ignore CN).
	tmpl.DNSNames = append(tmpl.DNSNames, executorID)
	if hostname != "" {
		// Only set as DNS SAN if it parses as a name. For IP-shaped
		// hostnames, prefer IPAddresses.
		if ip := net.ParseIP(hostname); ip != nil {
			tmpl.IPAddresses = append(tmpl.IPAddresses, ip)
		} else {
			tmpl.DNSNames = append(tmpl.DNSNames, hostname)
		}
	}

	der, err := x509.CreateCertificate(rand.Reader, tmpl, caCert, pub, caKey)
	if err != nil {
		return ExecutorCert{}, fmt.Errorf("create leaf: %w", err)
	}
	certPEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der})

	keyDER, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return ExecutorCert{}, fmt.Errorf("marshal leaf key: %w", err)
	}
	keyPEM := pem.EncodeToMemory(&pem.Block{Type: "PRIVATE KEY", Bytes: keyDER})

	return ExecutorCert{
		CertPEM:     certPEM,
		KeyPEM:      keyPEM,
		CABundlePEM: ca.CertPEM,
	}, nil
}

// randomSerial returns a 128-bit random serial number. The x509
// spec requires serials be positive; crypto/rand never returns
// negative values, so the int conversion is safe.
func randomSerial() (*big.Int, error) {
	limit := new(big.Int).Lsh(big.NewInt(1), 128)
	n, err := rand.Int(rand.Reader, limit)
	if err != nil {
		return nil, err
	}
	// Ensure the high bit is set so the value is unambiguously
	// positive when interpreted as int64 (some tooling is paranoid).
	n.SetBit(n, 127, 1)
	return n, nil
}