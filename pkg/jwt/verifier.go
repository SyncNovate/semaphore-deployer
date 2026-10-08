package jwt

import (
	"crypto/ecdsa"
	"crypto/ed25519"
	"crypto/elliptic"
	"crypto/rsa"
	"crypto/x509"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"time"

	jose "github.com/go-jose/go-jose/v4"
	josejwt "github.com/go-jose/go-jose/v4/jwt"
)

// ServiceClaims is the JWT payload the SentraOps platform BE mints for
// service-to-service calls into this fork. The verifier extracts the
// bound tenant scope from these claims so downstream handlers can
// apply the storage-layer filter with the same tenant_id/zone_ids the
// platform has already validated.
//
// SentraOps fork (R-I.1.d). See
// docs/architecture/2026-10-07-semaphore-fork-design.md §7.
type ServiceClaims struct {
	// Registered claims (subset that we actually consume).
	Issuer    string `json:"iss,omitempty"`
	Subject   string `json:"sub,omitempty"`
	Audience  string `json:"aud,omitempty"`
	ExpiresAt int64  `json:"exp,omitempty"`
	NotBefore int64  `json:"nbf,omitempty"`
	IssuedAt  int64  `json:"iat,omitempty"`

	// SentraOps-specific claims carried in the JWT.
	TenantID          string   `json:"tenant_id"`
	DeploymentZoneIDs []string `json:"deployment_zone_ids,omitempty"`
	ActorID           string   `json:"actor_id,omitempty"` // operator on whose behalf the BE is acting
}

// Sentinel errors returned by Verify so the middleware can distinguish
// "expired" from "bad signature" + "malformed" cleanly. Callers may
// surface any of these to the operator as the same generic 401 (we
// never want to leak which one fired).
var (
	ErrInvalidToken   = errors.New("jwt: invalid token")
	ErrTokenExpired   = errors.New("jwt: token expired")
	ErrKeyUnsupported = errors.New("jwt: public key is not a supported algorithm")
	ErrKeyUnparseable = errors.New("jwt: could not parse public key PEM")
)

// Verify parses and verifies a compact JWS against the provided PEM
// public key, then extracts the ServiceClaims. The PEM may carry an
// Ed25519, ECDSA P-256, or RSA public key (the three algorithms
// SentraOps may rotate through).
//
// The function rejects:
//   - malformed JWT (ErrInvalidToken)
//   - signature mismatch (ErrInvalidToken)
//   - nbf in the future or exp in the past (ErrTokenExpired)
//   - missing tenant_id claim (ErrInvalidToken)
//
// The claims are returned on success. A nil result with a non-nil
// error should be treated as "refuse the request" by the caller.
func Verify(token string, publicKeyPEM []byte) (*ServiceClaims, error) {
	if token == "" {
		return nil, ErrInvalidToken
	}

	pubKey, err := parsePublicKey(publicKeyPEM)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyUnparseable, err)
	}

	parsed, err := josejwt.ParseSigned(token, []jose.SignatureAlgorithm{
		jose.EdDSA, jose.ES256, jose.RS256,
	})
	if err != nil {
		return nil, fmt.Errorf("%w: parse: %v", ErrInvalidToken, err)
	}

	// Build a JWK so the go-jose verifier runs the algorithm/key
	// consistency check before decoding the payload.
	jwk := jose.JSONWebKey{
		Key:       pubKey,
		Algorithm: string(joseAlgorithmName(pubKey)),
		Use:       "sig",
	}

	var claims ServiceClaims
	if err := parsed.Claims(&jwk, &claims); err != nil {
		// go-jose already maps alg/key mismatch + signature failure
		// to a single verification error. The signature never saw
		// the claims, so this cannot leak payload bytes.
		return nil, fmt.Errorf("%w: verify: %v", ErrInvalidToken, err)
	}

	now := time.Now()
	if claims.ExpiresAt > 0 && now.Unix() > claims.ExpiresAt {
		return nil, ErrTokenExpired
	}
	if claims.NotBefore > 0 && now.Unix() < claims.NotBefore {
		return nil, fmt.Errorf("%w: nbf in future", ErrInvalidToken)
	}

	if claims.TenantID == "" {
		return nil, fmt.Errorf("%w: missing tenant_id claim", ErrInvalidToken)
	}

	return &claims, nil
}

// parsePublicKey accepts PKIX/SPKI PEM-encoded public keys of any
// type the platform may sign with. RSA keys may also be encoded as
// PKCS#1.
func parsePublicKey(pemBytes []byte) (any, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("no PEM block")
	}

	pub, err := x509.ParsePKIXPublicKey(block.Bytes)
	if err != nil {
		if rsaPub, rsaErr := x509.ParsePKCS1PublicKey(block.Bytes); rsaErr == nil {
			return rsaPub, nil
		}
		return nil, fmt.Errorf("parse PKIX: %w", err)
	}

	switch k := pub.(type) {
	case ed25519.PublicKey:
		return k, nil
	case *ecdsa.PublicKey:
		if k.Curve != elliptic.P256() {
			return nil, fmt.Errorf("%w: ECDSA curve %s", ErrKeyUnsupported, k.Curve.Params().Name)
		}
		return k, nil
	case *rsa.PublicKey:
		return k, nil
	default:
		return nil, fmt.Errorf("%w: type %T", ErrKeyUnsupported, pub)
	}
}

// joseAlgorithmName matches the parsed public key type to the go-jose
// algorithm header. The verifier accepts any of the three rotations.
func joseAlgorithmName(key any) jose.SignatureAlgorithm {
	switch key.(type) {
	case ed25519.PublicKey:
		return jose.EdDSA
	case *ecdsa.PublicKey:
		return jose.ES256
	case *rsa.PublicKey:
		return jose.RS256
	default:
		return ""
	}
}

// CompactJSON returns the JSON encoding of v with leading/trailing
// whitespace trimmed. Used by the audit webhook to compute the HMAC
// over the canonical request body (we always re-encode before signing
// so the signer cannot disagree with the verifier).
func CompactJSON(v any) ([]byte, error) {
	b, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	return b, nil
}
