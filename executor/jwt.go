package executor

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// ExecutorClaims is the JWT payload the customer-side executor
// sends to the `semaphore-deployer` fork for every authenticated
// call (register, heartbeat, claim, result).
//
// The claims intentionally mirror the platform's ServiceClaims
// shape (per `pkg/jwt/verifier.go` in the fork) so the server-side
// verifier (already shipped in R-I.1.d) accepts them with no
// changes. The Audience + Issuer are conventional values that
// the fork's `PlatformPublicKeyPEM` and `AllowedAudience` env
// vars drive.
type ExecutorClaims struct {
	// Registered claims (subset that go-jose requires).
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`

	// SentraOps-specific claims.
	TenantID          string `json:"tenant_id"`
	DeploymentZoneID  string `json:"deployment_zone_id"`
	ExecutorID        string `json:"executor_id"`
}

// Signer mints Ed25519-signed JWTs for executor-to-Semaphore
// calls. The audience + issuer are fixed at construction time
// because the server enforces a specific (iss, aud) tuple per
// the R-I.1.d contract.
//
// Why Ed25519: per design doc §9.2 "mTLS (Ed25519 per R-B.1)".
// The fork's verifier (pkg/jwt/verifier.go) accepts Ed25519 as
// one of three allowed rotations. Using the same algorithm as
// the mTLS client cert keeps the key material centralized.
type Signer interface {
	// Sign produces a compact JWS for the given claims. A fresh
	// jti is NOT injected — the claims are the signer's only
	// input. The caller (auth.go) controls replay protection.
	Sign(claims ExecutorClaims) (string, error)
	// PublicKeyPEM returns the matching public key as PEM. The
	// executor embeds this in the registration payload so the
	// server can verify subsequent calls without an out-of-band
	// public-key distribution channel.
	PublicKeyPEM() ([]byte, error)
	// KeyID returns the kid header. Computed once at signer
	// construction; stable for the lifetime of the process.
	KeyID() string
}

type ed25519Signer struct {
	priv       ed25519.PrivateKey
	pub        ed25519.PublicKey
	kid        string
	issuer     string
	audience   string
	defaultTTL time.Duration
}

// NewEd25519SignerFromPEM creates a Signer from a PEM-encoded
// Ed25519 private key (PKCS#8 format, the same shape
// `cryptography` in Python produces — see SentraOps BE
// `services/runner_deployment.py:_sign_jwt`).
func NewEd25519SignerFromPEM(pemBytes []byte, issuer, audience string, defaultTTL time.Duration) (Signer, error) {
	if defaultTTL <= 0 {
		defaultTTL = 60 * time.Second
	}
	if issuer == "" {
		return nil, errors.New("executor/jwt: issuer is required")
	}
	if audience == "" {
		return nil, errors.New("executor/jwt: audience is required")
	}

	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("executor/jwt: no PEM block found in key file")
	}
	raw, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("executor/jwt: parse PKCS8: %w", err)
	}
	priv, ok := raw.(ed25519.PrivateKey)
	if !ok {
		return nil, fmt.Errorf("executor/jwt: key is not Ed25519 (got %T)", raw)
	}
	pub, ok := priv.Public().(ed25519.PublicKey)
	if !ok {
		return nil, errors.New("executor/jwt: Ed25519 private key has no valid public key")
	}

	kid, err := computeKeyID(pub)
	if err != nil {
		return nil, fmt.Errorf("executor/jwt: compute kid: %w", err)
	}

	return &ed25519Signer{
		priv:       priv,
		pub:        pub,
		kid:        kid,
		issuer:     issuer,
		audience:   audience,
		defaultTTL: defaultTTL,
	}, nil
}

// NewEd25519SignerForTest is a constructor that takes a raw
// key (not PEM) for use in tests. Production code uses
// NewEd25519SignerFromPEM. The test constructor is here (not in
// a _test.go file) because the round-trip test in transport_test.go
// needs to instantiate the signer without going through PEM.
func NewEd25519SignerForTest(priv ed25519.PrivateKey, issuer, audience string) Signer {
	pub := priv.Public().(ed25519.PublicKey)
	kid, _ := computeKeyID(pub)
	return &ed25519Signer{
		priv:       priv,
		pub:        pub,
		kid:        kid,
		issuer:     issuer,
		audience:   audience,
		defaultTTL: 60 * time.Second,
	}
}

func (s *ed25519Signer) KeyID() string { return s.kid }

func (s *ed25519Signer) PublicKeyPEM() ([]byte, error) {
	der, err := x509.MarshalPKIXPublicKey(s.pub)
	if err != nil {
		return nil, fmt.Errorf("executor/jwt: marshal public key: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PUBLIC KEY",
		Bytes: der,
	}), nil
}

func (s *ed25519Signer) Sign(claims ExecutorClaims) (string, error) {
	now := time.Now().UTC()
	claims.Issuer = s.issuer
	claims.Audience = s.audience
	claims.IssuedAt = now.Unix()
	claims.NotBefore = now.Unix()
	claims.ExpiresAt = now.Add(s.defaultTTL).Unix()

	if claims.Subject == "" {
		claims.Subject = fmt.Sprintf("executor:%s", claims.ExecutorID)
	}

	signingKey := jose.SigningKey{
		Algorithm: jose.EdDSA,
		Key: jose.JSONWebKey{
			Key:       s.priv,
			KeyID:     s.kid,
			Algorithm: string(jose.EdDSA),
			Use:       "sig",
		},
	}
	sigOpts := (&jose.SignerOptions{}).WithType("JWT")
	js, err := jose.NewSigner(signingKey, sigOpts)
	if err != nil {
		return "", fmt.Errorf("executor/jwt: create signer: %w", err)
	}

	token, err := josejwt.Signed(js).Claims(claims).Serialize()
	if err != nil {
		return "", fmt.Errorf("executor/jwt: sign: %w", err)
	}
	return token, nil
}

// computeKeyID returns the base64url-encoded SHA-256 of the
// PKIX-marshalled public key. Matches the convention in
// pkg/jwt/signer.go so the fork's JWKS endpoint accepts our
// key without a custom mapping.
func computeKeyID(pub ed25519.PublicKey) (string, error) {
	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(der)
	return base64.RawURLEncoding.EncodeToString(sum[:]), nil
}

// GenerateEd25519KeyPEM generates a fresh Ed25519 keypair and
// returns the private key as PKCS#8 PEM. The matching public key
// is recoverable via Signer.PublicKeyPEM. Used by the operator
// bootstrap command (out of scope for R-I.4.a, but referenced by
// the plan for R-I.4 follow-ups that ship a one-shot init).
func GenerateEd25519KeyPEM() ([]byte, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, fmt.Errorf("executor/jwt: generate key: %w", err)
	}
	_ = pub
	der, err := x509.MarshalPKCS8PrivateKey(priv)
	if err != nil {
		return nil, fmt.Errorf("executor/jwt: marshal PKCS8: %w", err)
	}
	return pem.EncodeToMemory(&pem.Block{
		Type:  "PRIVATE KEY",
		Bytes: der,
	}), nil
}
