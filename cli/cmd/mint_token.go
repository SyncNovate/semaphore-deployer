package cmd

import (
	"crypto/rand"
	"crypto/sha256"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/url"
	"os"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/factory"
	"github.com/semaphoreui/semaphore/util"
	"github.com/spf13/cobra"

	log "github.com/sirupsen/logrus"
)

// mintTokenArgs are the CLI flags for the `mint-token` subcommand.
// The pattern: a SOC admin runs this from the platform BE after
// clicking "Send Executor" in the SOC console; the subcommand prints
// the install link to stdout (machine-parseable JSON via --json) so
// the operator / CI pipeline can pipe it to the customer's deploy
// admin's email or chat.
//
// This subcommand REPLACES the manual SQL INSERT workflow that the
// R-I.10.re1 / R-I.11 live-fork-env verification used. The token TTL
// is fixed at db.EnrollmentTokenTTL (5 min) per design.
var mintTokenArgs struct {
	tenantID         string
	zoneIDs          []string
	executorName     string
	hostname         string
	installBaseURL   string // e.g. https://sentraops.example.com
	jsonOutput       bool
	stdin            bool
	registrationAt   string // optional override for testing; RFC3339
	expiresInMinutes int    // optional override for the standard 5-min TTL
}

func init() {
	mintTokenCmd.PersistentFlags().StringVar(&mintTokenArgs.tenantID, "tenant-id", "",
		"tenant UUID (required; fail-closed if empty)")
	mintTokenCmd.PersistentFlags().StringSliceVar(&mintTokenArgs.zoneIDs, "zone-id", nil,
		"deployment zone IDs (repeat or comma-separated). "+
				"Empty list = no zones bound (executor cannot claim until assigned).")
	mintTokenCmd.PersistentFlags().StringVar(&mintTokenArgs.executorName, "name", "",
		"proposed executor name (defaults to the executor_id at enroll time)")
	mintTokenCmd.PersistentFlags().StringVar(&mintTokenArgs.hostname, "hostname", "",
		"proposed hostname (defaults to the OS hostname at enroll time)")
	mintTokenCmd.PersistentFlags().StringVar(&mintTokenArgs.installBaseURL, "install-base-url", "",
		"base URL prepended to the install link (e.g. https://sentraops.example.com). "+
				"If empty, derives from SEMAPHORE_WEBROOT or SEMAPHORE_PUBLIC_URL env.")
	mintTokenCmd.PersistentFlags().BoolVar(&mintTokenArgs.jsonOutput, "json", false,
		"emit the result as a single JSON object (machine-parseable)")
	mintTokenCmd.PersistentFlags().BoolVar(&mintTokenArgs.stdin, "stdin", false,
		"read --tenant-id from stdin (one line; useful for piping)")
	mintTokenCmd.PersistentFlags().StringVar(&mintTokenArgs.registrationAt, "registration-at", "",
		"override the server's now() for the created_at column (RFC3339; for testing)")
	mintTokenCmd.PersistentFlags().IntVar(&mintTokenArgs.expiresInMinutes, "ttl-minutes", 0,
		"override the default 5-min TTL (for testing only; production should use the default)")

	rootCmd.AddCommand(mintTokenCmd)
}

var mintTokenCmd = &cobra.Command{
	Use:   "mint-token",
	Short: "Mint a single-use enrollment token (R-I.10.re1 / R-I.11.followup). Prints the install link on stdout.",
	Long: strings.TrimSpace(`
Mints a short-lived (5 min TTL, single-use) enrollment token for the
Wazuh-style "Send Executor" 1-click install flow. Writes the row to
the enrollment_tokens table via the same Store interface /enroll uses.
Prints the install link on stdout.

Output:
  - Default: human-readable — "Install link: <url>"
  - --json:  single JSON object with token, expires_at, install_link, etc.

Caller must hold the platform BE's secrets (SENTRAOPS_PLATFORM_*) for
the backend the executor will enroll against. Tokens are bound to
--tenant-id at mint time; the /enroll handler refuses any other
tenant_id on the request side.
`),
	Run: func(cmd *cobra.Command, args []string) {
		if err := runMintToken(cmd.OutOrStdout()); err != nil {
			fmt.Fprintf(cmd.ErrOrStderr(), "mint-token failed: %v\n", err)
			os.Exit(1)
		}
	},
}

// mintTokenResult is the JSON shape emitted with --json. Stable shape
// (consumed by the R-I.9 UI's "Send Executor" button wiring).
type mintTokenResult struct {
	Token       string    `json:"token"`         // plaintext; ONLY seen here + in the install bundle
	TokenHash   string    `json:"token_hash"`    // sha256 hex digest (matches enrollment_tokens.token_hash)
	TenantID    string    `json:"tenant_id"`
	ZoneIDs     []string  `json:"zone_ids"`
	ExecutorName string   `json:"executor_name,omitempty"`
	Hostname    string    `json:"hostname,omitempty"`
	ExpiresAt   time.Time `json:"expires_at"`
	InstallLink string    `json:"install_link"` // full URL with token embedded
}

// runMintToken mints the token, INSERTs it, emits. With --json the
// shape is stable for the R-I.9 UI. Without --json the output is a
// single line "Install link: <url>" so operators can copy + paste.
func runMintToken(stdout io.Writer) error {
	// 1. Resolve + validate tenant_id. Std-in flag wins over --flag
	//    so the same CLI can be driven by an interactive prompt or
	//    by a CI pipeline reading from a file/pipe.
	if mintTokenArgs.stdin {
		b, err := io.ReadAll(stdinReaderOverride())
		if err != nil {
			return fmt.Errorf("read stdin: %w", err)
		}
		tenantID := strings.TrimSpace(string(b))
		if tenantID == "" {
			return fmt.Errorf("--stdin was passed but no tenant_id was supplied")
		}
		mintTokenArgs.tenantID = tenantID
	}
	if strings.TrimSpace(mintTokenArgs.tenantID) == "" {
		return fmt.Errorf("--tenant-id is required (or pass --stdin)")
	}

	// 2. Resolve install base URL. Priority: --install-base-url >
	//    SEMAPHORE_PUBLIC_URL env > util.Config.WebHost > localhost.
	base := strings.TrimRight(strings.TrimSpace(mintTokenArgs.installBaseURL), "/")
	if base == "" {
		base = strings.TrimSpace(os.Getenv("SEMAPHORE_PUBLIC_URL"))
	}
	if base == "" && util.Config != nil && util.Config.WebHost != "" {
		base = util.Config.WebHost
	}
	if base == "" {
		return fmt.Errorf("install base URL is unknown; pass --install-base-url or set SEMAPHORE_PUBLIC_URL")
	}
	if _, err := url.Parse(base); err != nil {
		return fmt.Errorf("--install-base-url %q is not a valid URL: %w", base, err)
	}

	// 3. Generate a 32-byte cryptographically random token. Same
	//    shape as the executor's existing bearer-token mint
	//    (executor/client.go's mintToken pattern).
	var raw [32]byte
	if _, err := rand.Read(raw[:]); err != nil {
		return fmt.Errorf("generate token: %w", err)
	}
	plaintext := base64.RawURLEncoding.EncodeToString(raw[:])
	sum := sha256.Sum256([]byte(plaintext))
	hashHex := hex.EncodeToString(sum[:])

	// 4. Resolve the created_at + expires_at. Default: now + 5 min.
	//    Allow --registration-at + --ttl-minutes for testing.
	now := time.Now().UTC()
	createdAt := now
	if v := strings.TrimSpace(mintTokenArgs.registrationAt); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return fmt.Errorf("--registration-at must be RFC3339: %w", err)
		}
		createdAt = t
	}
	ttl := time.Duration(db.EnrollmentTokenTTL)
	if mintTokenArgs.expiresInMinutes > 0 {
		ttl = time.Duration(mintTokenArgs.expiresInMinutes) * time.Minute
		if ttl > 60*time.Minute {
			return fmt.Errorf("--ttl-minutes may not exceed 60 (the token is a security boundary, not a session cookie)")
		}
	}
	expiresAt := createdAt.Add(ttl)

	// 5. Encode zone IDs as JSON list (matches Executor.DeploymentZoneIDsJSON).
	zoneJSON, err := json.Marshal(mintTokenArgs.zoneIDs)
	if err != nil {
		return fmt.Errorf("marshal zone ids: %w", err)
	}

	// 6. INSERT via the Store. We use the same Store interface as the
	//    /enroll handler so the read-path tests on ConsumeEnrollmentToken
	//    cover both directions. Resolve the store via the package-
	//    level hook (production: a factory-built connected SqlDb;
	//    tests: the harness-provided store). Both paths satisfy the
	//    db.Store interface so /enroll + mint-token share the same
	//    persistence story.
	store := resolveStoreForMintToken()
	if store == nil {
		return fmt.Errorf("store is not configured (set SEMAPHORE_DB_HOST / SEMAPHORE_DB_USER / SEMAPHORE_DB_PASS)")
	}
	// We intentionally do NOT close the store here: this is a
	// short-lived CLI command, the process exits when Run returns,
	// and closing the SqlDb disconnects any pool the test harness
	// set up — the test would then panic on the next operation.
	tok := db.EnrollmentToken{
		TokenHash:             hashHex,
		TenantID:              strings.TrimSpace(mintTokenArgs.tenantID),
		DeploymentZoneIDsJSON: string(zoneJSON),
		ExecutorName:          strings.TrimSpace(mintTokenArgs.executorName),
		Hostname:              strings.TrimSpace(mintTokenArgs.hostname),
		ExpiresAt:             expiresAt,
		CreatedAt:             createdAt,
	}
	if _, err := store.CreateEnrollmentToken(tok); err != nil {
		return fmt.Errorf("create enrollment token: %w", err)
	}

	// 7. Compose the install link. Same shape install.sh expects
	//    (the customer curl-pipes to bash). We intentionally keep
	//    the URL simple — no path embedding; the bash wrapper reads
	//    the token from a header or query-string at fetch time. The
	//    path "/install/<token>" is the documented Wazuh-style
	//    pattern; install.sh on the server side serves the bundle
	//    + write-headers + signed installer URL.
	u, err := url.Parse(base)
	if err != nil {
		return fmt.Errorf("parse base url: %w", err)
	}
	u.Path = strings.TrimRight(u.Path, "/") + "/install/" + plaintext
	installLink := u.String()

	res := mintTokenResult{
		Token:        plaintext,
		TokenHash:    hashHex,
		TenantID:     tok.TenantID,
		ZoneIDs:      mintTokenArgs.zoneIDs,
		ExecutorName: tok.ExecutorName,
		Hostname:     tok.Hostname,
		ExpiresAt:    expiresAt,
		InstallLink:  installLink,
	}

	// 8. Emit. --json for machine consumers (R-I.9 UI, CI), plain
	//    text for human operators.
	if mintTokenArgs.jsonOutput {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(res)
	}
	fmt.Fprintf(stdout, "Install link: %s\n", res.InstallLink)
	fmt.Fprintf(stdout, "Tenant:       %s\n", res.TenantID)
	fmt.Fprintf(stdout, "Zones:        %v\n", res.ZoneIDs)
	fmt.Fprintf(stdout, "Expires at:   %s\n", res.ExpiresAt.Format(time.RFC3339))
	fmt.Fprintf(stdout, "Token hash:   %s\n", res.TokenHash)
	return nil
}

// stdinReaderOverride returns the io.Reader used to satisfy --stdin
// reads. Production: os.Stdin. Tests: a strings.Reader the test sets
// via SetStdinReaderForTest. Same pattern as
// api/executor.SetPlatformCAPEMForTest (R-I.10.re1).
func stdinReaderOverride() io.Reader {
	if stdinReaderForTest != nil {
		return stdinReaderForTest
	}
	return os.Stdin
}

// stdinReaderForTest is the test-time stdin source. nil = production.
var stdinReaderForTest io.Reader

// SetStdinReaderForTest lets tests drive the --stdin branch without
// forking the process. Reset to nil at t.Cleanup.
func SetStdinReaderForTest(r io.Reader) { stdinReaderForTest = r }

// resolveStoreForMintToken returns the db.Store the mint-token
// subcommand should use. Production: factory-built SqlDb with a fresh
// Connect() + migration (the same shape the other CLI subcommands
// use via createStoreWithMigrationVersion). Tests: the harness-
// provided store, set via SetStoreForTest, so unit tests share the
// in-memory SQLite the harness already opened + migrated.
func resolveStoreForMintToken() db.Store {
	if storeForTest != nil {
		return storeForTest
	}
	if util.Config == nil {
		util.ConfigInit(persistentFlags.configPath, persistentFlags.noConfig)
	}
	store := factory.CreateStore()
	store.Connect()
	if err := db.Migrate(store, nil); err != nil {
		log.WithError(err).Warn("mint-token: migrate skipped (table already present)")
	}
	return store
}

// storeForTest is the test-time Store source. nil = production.
var storeForTest db.Store

// SetStoreForTest lets the test inject a pre-connected db.Store
// (the harness's CreateTestStore return value). Reset to nil at
// t.Cleanup.
func SetStoreForTest(s db.Store) { storeForTest = s }