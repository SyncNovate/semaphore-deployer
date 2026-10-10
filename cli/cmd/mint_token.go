package cmd

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"strings"
	"time"

	"github.com/semaphoreui/semaphore/db"
	"github.com/semaphoreui/semaphore/db/factory"
	"github.com/semaphoreui/semaphore/pkg/enrollment/mint"
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
// is fixed at mint.DefaultTTL (5 min) per design.
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
			"If empty, derives from SEMAPHORE_PUBLIC_URL or util.Config.WebHost.")
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
//
// Re-declared here (instead of reusing mint.Result) so the wire shape
// stays under CLI control — the JSON tags match mint.Result so the
// R-I.9 UI parses both equivalently.
type mintTokenResult struct {
	Token        string    `json:"token"`
	TokenHash    string    `json:"token_hash"`
	TenantID     string    `json:"tenant_id"`
	ZoneIDs      []string  `json:"zone_ids"`
	ExecutorName string    `json:"executor_name,omitempty"`
	Hostname     string    `json:"hostname,omitempty"`
	ExpiresAt    time.Time `json:"expires_at"`
	CreatedAt    time.Time `json:"created_at"`
	InstallLink  string    `json:"install_link"`
}

// runMintToken parses the CLI input, delegates the actual mint to
// ``mint.Token`` (the shared helper used by the HTTP handler too),
// and emits the result in the requested shape. Keeping the parse
// + emit logic in this file but the security-sensitive mint work
// in the shared package means the two surfaces can't drift on TTL
// math, URL shape, or row contents.
func runMintToken(stdout io.Writer) error {
	// 1. --stdin branch: the same CLI can be driven by an interactive
	//    prompt or by a CI pipeline reading from a file/pipe.
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
	// 2. Resolve install base URL (CLI priority order). The shared
	//    helper re-validates the URL on the way in.
	base := strings.TrimRight(strings.TrimSpace(mintTokenArgs.installBaseURL), "/")
	if base == "" {
		base = strings.TrimSpace(os.Getenv("SEMAPHORE_PUBLIC_URL"))
	}
	if base == "" && util.Config != nil && util.Config.WebHost != "" {
		base = util.Config.WebHost
	}

	// 3. Resolve the time anchor (--registration-at for tests;
	//    time.Now() otherwise). Tests pin this so the
	//    expires-at assertion is stable.
	var now time.Time
	if v := strings.TrimSpace(mintTokenArgs.registrationAt); v != "" {
		t, err := time.Parse(time.RFC3339, v)
		if err != nil {
			return fmt.Errorf("--registration-at must be RFC3339: %w", err)
		}
		now = t
	}
	// 4. Resolve TTL (mint.Token will reject anything > MaxTTL).
	var ttl time.Duration
	if mintTokenArgs.expiresInMinutes > 0 {
		ttl = time.Duration(mintTokenArgs.expiresInMinutes) * time.Minute
	}
	// 5. Resolve the store (test hook or factory).
	s := resolveStoreForMintToken()
	if s == nil {
		return fmt.Errorf("store is not configured (set SEMAPHORE_DB_HOST / SEMAPHORE_DB_USER / SEMAPHORE_DB_PASS)")
	}
	// 6. Delegate the mint.
	res, err := mint.Token(s, mint.Request{
		TenantID:       mintTokenArgs.tenantID,
		DeploymentZone: mintTokenArgs.zoneIDs,
		ExecutorName:   mintTokenArgs.executorName,
		Hostname:       mintTokenArgs.hostname,
		TTL:            ttl,
		InstallBaseURL: base,
		Now:            now,
	})
	if err != nil {
		return err
	}
	// 7. Emit. --json for machine consumers (R-I.9 UI, CI), plain
	//    text for human operators.
	if mintTokenArgs.jsonOutput {
		out := mintTokenResult{
			Token:        res.Token,
			TokenHash:    res.TokenHash,
			TenantID:     res.TenantID,
			ZoneIDs:      res.ZoneIDs,
			ExecutorName: res.ExecutorName,
			Hostname:     res.Hostname,
			ExpiresAt:    res.ExpiresAt,
			CreatedAt:    res.CreatedAt,
			InstallLink:  res.InstallLink,
		}
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		return enc.Encode(out)
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