// DB adapter for the install handler. Wires the package's
// TokenStore interface to the fork's db.Store so the route
// registration in api/router.go can plug the install handler
// into the existing router without changing the install
// handler's test surface.
//
// R-D (2026-10-12).
package install

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"time"

	"github.com/semaphoreui/semaphore/db"
)

// dbTokenStore wraps db.Store to satisfy TokenStore. The real
// DB method is ``GetEnrollmentTokenByHash(tokenHashHex string)``
// which returns ``(EnrollmentToken, error)``. We hex-encode
// the raw hash bytes the handler passes us, then translate
// the store's "not found" sentinel to install.ErrTokenNotFound;
// other errors pass through unchanged.
type dbTokenStore struct {
	store db.Store
}

// LookupByHash returns the (tenantID, expiresAt) tuple for the
// given token hash. The handler passes raw SHA-256 bytes; we
// hex-encode to the format the DB expects.
func (d dbTokenStore) LookupByHash(hash []byte) (string, time.Time, error) {
	hexHash := hex.EncodeToString(hash)
	row, err := d.store.GetEnrollmentTokenByHash(hexHash)
	if err != nil {
		if errors.Is(err, db.ErrNotFound) {
			return "", time.Time{}, ErrTokenNotFound
		}
		return "", time.Time{}, err
	}
	// The DB returns an EnrollmentToken value, never a
	// pointer — the zero value's TenantID is "" and
	// ExpiresAt is the zero time, both defensible
	// fallbacks. An empty TenantID here is the
	// "row was actually missing" case in some stores.
	if row.TenantID == "" {
		return "", time.Time{}, ErrTokenNotFound
	}
	return row.TenantID, row.ExpiresAt, nil
}

// NewHandlerFromDB returns a Handler backed by the real
// db.Store. The baseURL is the publicly-routable URL the
// executor will call /enroll on — it is baked into the rendered
// install script as SENTRAOPS_EXECUTOR_SERVER_URL.
//
// For the dev VPS: pass the same install_base_url the platform
// BE uses (e.g. https://sentraops.5-189-177-170.sslip.io:9443).
// For production: pass the customer-facing Semaphore URL.
func NewHandlerFromDB(store db.Store, baseURL string) *Handler {
	return &Handler{
		Store:     dbTokenStore{store: store},
		ServerURL: trimTrailingSlash(baseURL),
		BinaryURL: "",
		Now:       time.Now,
		Hasher:    defaultHasher,
	}
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func defaultHasher(b []byte) []byte {
	h := sha256.Sum256(b)
	return h[:]
}
