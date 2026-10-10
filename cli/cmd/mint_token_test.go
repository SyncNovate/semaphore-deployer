package cmd

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/sql"
	"github.com/semaphoreui/semaphore/util"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
)

// sha256SumImpl does the actual hash. Wrapped in a function so the
// test file imports one symbol instead of leaking the standard
// library everywhere.
func sha256SumImpl(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// resetMintTokenArgs clears package-level state between tests so each
// test runs against a clean slate. Without this, args bleed across
// tests because cobra re-uses the persistent flags.
func resetMintTokenArgs() {
	mintTokenArgs = mintTokenArgsZero()
}

// mintTokenArgsZero returns a fresh zero-valued mintTokenArgs literal
// matching the package-level struct shape. Declared as a helper so
// tests can spell the shape once + stay in sync with the package var.
func mintTokenArgsZero() mintTokenArgsT {
	return mintTokenArgsT{}
}

// mintTokenArgsT is a named alias for the package-level mintTokenArgs
// struct shape so tests can declare literals (the package var is
// anonymous). Keep this in lock-step with the var declaration in
// mint_token.go.
type mintTokenArgsT = struct {
	tenantID         string
	zoneIDs          []string
	executorName     string
	hostname         string
	installBaseURL   string
	jsonOutput       bool
	stdin            bool
	registrationAt   string
	expiresInMinutes int
}

// freshTestStoreForMintToken wraps sql.CreateTestStore (which already
// wires util.Config to a working *SqlDb with all migrations applied)
// and installs it as the test-time Store source via SetStoreForTest
// so runMintToken's resolveStoreForMintToken returns it. The
// harness's store is already connected + migrated, so production
// wiring (factory.CreateStore + Connect + Migrate) is bypassed.
func freshTestStoreForMintToken(t *testing.T) db.Store {
	t.Helper()
	store := sql.CreateTestStore()
	// Sqlite is a *sql.SqlDb. Pin util.Config's WebHost so install
	// base URL derivation works (some tests pass --install-base-url
	// explicitly; this is belt-and-suspenders for the default branch).
	if util.Config != nil {
		util.Config.WebHost = "https://sentraops.example.com"
	}
	SetStoreForTest(store)
	t.Cleanup(func() { SetStoreForTest(nil) })
	return store
}

// runWithArgs drives the mintToken subcommand against the
// caller-supplied store, capturing stdout. It resets the package-
// level state and invokes the Run func directly.
//
// IMPORTANT: caller is responsible for calling freshTestStoreForMintToken
// FIRST so resolveStoreForMintToken (called inside runMintToken) sees
// the harness-provided store. We do NOT call freshTestStoreForMintToken
// here — calling it twice creates two distinct in-memory SQLite
// databases and the row inserted in one is invisible to the other.
func runWithArgs(t *testing.T, args mintTokenArgsT) (string, error) {
	t.Helper()
	resetMintTokenArgs()
	mintTokenArgs = args
	var out bytes.Buffer
	runErr := runMintToken(&out)
	return out.String(), runErr
}

// TestRunMintToken_RequiresTenantID guards the fail-closed case where
// the SOC admin forgets to pass --tenant-id (or --stdin). The CLI must
// refuse, not mint a token bound to an empty tenant.
func TestRunMintToken_RequiresTenantID(t *testing.T) {
	_, err := runWithArgs(t, mintTokenArgsT{installBaseURL: "https://x"})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "tenant-id is required")
}

// TestRunMintToken_RequiresInstallBaseURL guards the second
// fail-closed case: a missing install base URL (no flag, no env, no
// util.Config.WebHost) must error, not produce a half-link.
func TestRunMintToken_RequiresInstallBaseURL(t *testing.T) {
	freshTestStoreForMintToken(t)
	// Wipe the WebHost the test harness set so the fallback chain
	// (--install-base-url + env + WebHost) all return empty.
	prevWebHost := util.Config.WebHost
	util.Config.WebHost = ""
	defer func() { util.Config.WebHost = prevWebHost }()

	resetMintTokenArgs()
	mintTokenArgs = mintTokenArgsT{tenantID: "ORG-1"}
	var out bytes.Buffer
	err := runMintToken(&out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "install base URL is unknown")
}

// TestRunMintToken_TTLBoundedBy60Min guards the --ttl-minutes guard:
// the token is a security boundary (single-use, short-lived), not a
// session cookie. Anything > 60 min must be refused.
func TestRunMintToken_TTLBoundedBy60Min(t *testing.T) {
	_, err := runWithArgs(t, mintTokenArgsT{
		tenantID:          "ORG-1",
		installBaseURL:    "https://x",
		expiresInMinutes:  120,
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "ttl-minutes may not exceed 60")
}

// TestRunMintToken_HappyPath_PlainText emits the human-readable
// output, persists the row, and verifies the hash matches what we
// expect.
func TestRunMintToken_HappyPath_PlainText(t *testing.T) {
	store := freshTestStoreForMintToken(t)

	out, err := runWithArgs(t, mintTokenArgsT{
		tenantID:       "ORG-1",
		zoneIDs:        []string{"ZONE-A", "ZONE-B"},
		executorName:   "exec-happy",
		hostname:       "happy-host",
		installBaseURL: "https://sentraops.example.com",
	})
	require.NoError(t, err)

	// Install link line is present + looks right.
	assert.Contains(t, out, "Install link: https://sentraops.example.com/install/")
	assert.Contains(t, out, "Tenant:       ORG-1")
	assert.Contains(t, out, "Zones:        [ZONE-A ZONE-B]")

	// The plaintext token is NOT in the human-readable output
	// (only the link, tenant, zones, expires_at, hash). The link
	// embeds it; if the link is in the output the token IS in the
	// output — so we don't redact it. The trade-off: a single line
	// of copy-paste that the operator sends over a (still-encrypted)
	// chat. The --json flag is the right shape for the R-I.9 UI to
	// consume the token without scanning stdout.

	// 1 row persisted; show the link.
	token := extractTokenFromInstallLink(t, out)
	hashHex := hashHexFor(token)
	loaded, err := store.GetEnrollmentTokenByHash(hashHex)
	require.NoError(t, err)
	assert.Equal(t, "ORG-1", loaded.TenantID)
	assert.Equal(t, "exec-happy", loaded.ExecutorName)
	assert.Equal(t, "happy-host", loaded.Hostname)
	assert.True(t, loaded.ExpiresAt.After(time.Now().UTC()),
		"expires_at must be in the future")
	assert.Nil(t, loaded.ConsumedAt, "freshly minted token is not yet consumed")
	assert.Equal(t, []string{"ZONE-A", "ZONE-B"}, loaded.DeploymentZoneIDs())
}

// TestRunMintToken_HappyPath_JSON emits the machine-parseable JSON
// shape that the R-I.9 UI consumes.
func TestRunMintToken_HappyPath_JSON(t *testing.T) {
	store := freshTestStoreForMintToken(t)

	out, err := runWithArgs(t, mintTokenArgsT{
		tenantID:       "ORG-TENANT-JSON",
		zoneIDs:        []string{"ZONE-X"},
		executorName:   "exec-json",
		hostname:       "json-host",
		installBaseURL: "https://sentraops.example.com",
		jsonOutput:     true,
	})
	require.NoError(t, err)

	// Parse the JSON line.
	var res mintTokenResult
	require.NoError(t, json.Unmarshal([]byte(out), &res),
		"output must be a single JSON object; got %q", out)

	assert.Equal(t, "ORG-TENANT-JSON", res.TenantID)
	assert.Equal(t, []string{"ZONE-X"}, res.ZoneIDs)
	assert.Equal(t, "exec-json", res.ExecutorName)
	assert.Equal(t, "json-host", res.Hostname)
	assert.NotEmpty(t, res.Token, "plaintext token must be in the JSON output (only the UI sees it)")
	assert.NotEmpty(t, res.TokenHash)
	assert.True(t, res.ExpiresAt.After(time.Now().UTC()))
	assert.Contains(t, res.InstallLink, "/install/")
	assert.Contains(t, res.InstallLink, res.Token,
		"install link must embed the plaintext token")

	// Row persisted.
	loaded, err := store.GetEnrollmentTokenByHash(res.TokenHash)
	require.NoError(t, err)
	assert.Equal(t, "ORG-TENANT-JSON", loaded.TenantID)
}

// TestRunMintToken_StdinTenantID verifies the --stdin branch: the
// tenant_id is read from stdin (one line). Lets a CI pipeline pipe
// the tenant_id from a secrets manager.
func TestRunMintToken_StdinTenantID(t *testing.T) {
	store := freshTestStoreForMintToken(t)

	resetMintTokenArgs()
	mintTokenArgs = mintTokenArgsT{
		stdin:         true,
		installBaseURL: "https://x",
	}
	// Stash stdin contents via the package-level hook below; the
	// simpler version here is to call runMintToken while piping into
	// os.Stdin via t.Setenv + a redirector. We use the in-test
	// reader instead.
	SetStdinReaderForTest(strings.NewReader("ORG-STDIN\n"))
	defer func() { SetStdinReaderForTest(nil) }()

	var out bytes.Buffer
	err := runMintToken(&out)
	require.NoError(t, err)
	assert.Contains(t, out.String(), "Tenant:       ORG-STDIN")

	// Row persisted with the stdined tenant_id.
	all, err := store.GetEnrollmentTokenByHash(extractHashFromOutput(t, out.String()))
	require.NoError(t, err)
	assert.Equal(t, "ORG-STDIN", all.TenantID)
}

// TestRunMintToken_RejectsEmptyStdin guards the case where --stdin
// was passed with no actual content. The CLI must error, not mint a
// token with an empty tenant_id.
func TestRunMintToken_RejectsEmptyStdin(t *testing.T) {
	freshTestStoreForMintToken(t)

	resetMintTokenArgs()
	mintTokenArgs = mintTokenArgsT{stdin: true, installBaseURL: "https://x"}
	SetStdinReaderForTest(strings.NewReader(""))
	defer func() { SetStdinReaderForTest(nil) }()

	var out bytes.Buffer
	err := runMintToken(&out)
	require.Error(t, err)
	assert.Contains(t, err.Error(), "no tenant_id was supplied")
}

// TestRunMintToken_RejectsInvalidRegistrationAt guards the
// --registration-at parser.
func TestRunMintToken_RejectsInvalidRegistrationAt(t *testing.T) {
	_, err := runWithArgs(t, mintTokenArgsT{
		tenantID:        "ORG-1",
		installBaseURL:  "https://x",
		registrationAt:  "not-a-rfc3339",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "RFC3339")
}

// TestRunMintToken_RejectsInvalidBaseURL guards the URL parser.
func TestRunMintToken_RejectsInvalidBaseURL(t *testing.T) {
	_, err := runWithArgs(t, mintTokenArgsT{
		tenantID:       "ORG-1",
		installBaseURL: "://bad-url",
	})
	require.Error(t, err)
	assert.Contains(t, err.Error(), "valid URL")
}

// TestRunMintToken_EmptyZoneIDsIsOK verifies a SOC admin can mint a
// token bound to a tenant but no zone (the executor cannot claim
// until zones are assigned later). Zero zones is a valid starting
// state, not an error.
func TestRunMintToken_EmptyZoneIDsIsOK(t *testing.T) {
	store := freshTestStoreForMintToken(t)

	out, err := runWithArgs(t, mintTokenArgsT{
		tenantID:       "ORG-1",
		zoneIDs:        nil,
		installBaseURL: "https://x",
	})
	require.NoError(t, err)
	assert.Contains(t, out, "Zones:        []")

	loaded, err := store.GetEnrollmentTokenByHash(extractHashFromOutput(t, out))
	require.NoError(t, err)
	assert.Empty(t, loaded.DeploymentZoneIDs())
}

// TestRunMintToken_DefaultTTLIs5Min verifies the default TTL is exactly
// 5 minutes (matches db.EnrollmentTokenTTL). Changing the constant
// without review is a security-relevant decision.
func TestRunMintToken_DefaultTTLIs5Min(t *testing.T) {
	store := freshTestStoreForMintToken(t)

	beforeMint := time.Now().UTC()
	out, err := runWithArgs(t, mintTokenArgsT{
		tenantID:       "ORG-1",
		installBaseURL: "https://x",
	})
	require.NoError(t, err)
	afterMint := time.Now().UTC()

	loaded, err := store.GetEnrollmentTokenByHash(extractHashFromOutput(t, out))
	require.NoError(t, err)

	// Window must be ~5 minutes, allowing for a small slack on
	// either side (the mint path may have measured before/after time.Now).
	assert.True(t, loaded.ExpiresAt.After(beforeMint.Add(5*time.Minute).Add(-time.Second)),
		"expires_at must be at least ~5 min after the mint started")
	assert.True(t, loaded.ExpiresAt.Before(afterMint.Add(5*time.Minute).Add(time.Second)),
		"expires_at must be at most ~5 min after the mint finished")
}

// TestRunMintToken_ConsumedAfterExchange integrates with /enroll's
// race-safe single-use gate: after the fork consumes the token via
// ConsumeEnrollmentToken, GetEnrollmentTokenByHash reports it
// consumed. Mirrors TestRunBootstrap_HappyPath's mid-scenario so we
// know the mint + enroll halves compose.
func TestRunMintToken_ConsumedAfterExchange(t *testing.T) {
	store := freshTestStoreForMintToken(t)

	out, err := runWithArgs(t, mintTokenArgsT{
		tenantID:       "ORG-1",
		installBaseURL: "https://x",
	})
	require.NoError(t, err)

	hashHex := extractHashFromOutput(t, out)
	loaded, err := store.GetEnrollmentTokenByHash(hashHex)
	require.NoError(t, err)
	require.Nil(t, loaded.ConsumedAt, "freshly minted token must not be consumed yet")

	// Now consume it (the executor's /enroll handler does this).
	consumed, err := store.ConsumeEnrollmentToken(hashHex, "EXEC-TEST", time.Now().UTC())
	require.NoError(t, err)
	assert.NotNil(t, consumed.ConsumedAt)
	assert.Equal(t, "EXEC-TEST", *consumed.ConsumedByExecutorID)

	// A second consume returns ErrAlreadyExists (single-use).
	_, err = store.ConsumeEnrollmentToken(hashHex, "EXEC-TEST2", time.Now().UTC())
	assert.ErrorIs(t, err, db.ErrAlreadyExists)
}

// --- small test helpers -------------------------------------------------

// extractTokenFromInstallLink pulls the plaintext token out of the
// "Install link: <url>" line. Used by the tests that verify the row
// was persisted via the URL embedded in the output.
func extractTokenFromInstallLink(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Install link:") {
			continue
		}
		url := strings.TrimSpace(strings.TrimPrefix(line, "Install link:"))
		slash := strings.LastIndex(url, "/")
		require.Greater(t, slash, -1)
		return url[slash+1:]
	}
	t.Fatalf("no Install link line in output: %q", out)
	return ""
}

// extractHashFromOutput pulls the token hash from the "Token hash:"
// line. We test against the hash (NOT the plaintext) because the
// human-readable output intentionally does NOT include the plaintext.
func extractHashFromOutput(t *testing.T, out string) string {
	t.Helper()
	for _, line := range strings.Split(out, "\n") {
		if !strings.HasPrefix(line, "Token hash:") {
			continue
		}
		return strings.TrimSpace(strings.TrimPrefix(line, "Token hash:"))
	}
	t.Fatalf("no Token hash line in output: %q", out)
	return ""
}

// hashHexFor is a small helper for tests that already know the
// plaintext token (the link-consumed-from-human-readable-output tests
// use this to verify the same hash is persisted).
func hashHexFor(s string) string {
	import_crypto_sha256 := sha256SumHex(s)
	return import_crypto_sha256
}

// stdinReader is the test-time stdin source. Production code reads
// os.Stdin directly; tests set this var to a strings.Reader to drive
// the --stdin branch without forking the process.
// (replaced by SetStdinReaderForTest in production code; the old
//  var is kept as a package-private alias so the test setters compile
//  alongside the production setter)

// sha256SumHex returns the lowercase hex SHA-256 of s. Defined here
// so the test file is self-contained (no extra imports).
func sha256SumHex(s string) string {
	sum := sha256SumImpl(s)
	return sum
}