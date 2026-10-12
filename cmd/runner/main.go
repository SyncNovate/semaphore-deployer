// Command sentraops-runner is the entry point for the
// runner-only binary (R-F.3). The actual logic lives in the
// `runner` package; this file is the thin `main` that wires
// `runner.Main` to the host's os.Args / os.Stdout / os.Stderr.
//
// Build:
//   go build -o sentraops-runner ./cmd/runner
//
// The cmd/runner entry point is small on purpose — every
// meaningful behaviour (config loading, command loop, kill
// switch, uninstaller dispatch) is in the runner package so
// tests can drive it without a `package main` linkage.
package main

import (
	"os"

	"github.com/semaphoreui/semaphore/runner"
)

func main() {
	// Linker-injected version. The cmd package owns the var
	// so a real binary always reports its real version
	// in the User-Agent + --version output.
	if v := os.Getenv("SENTRAOPS_RUNNER_VERSION"); v != "" {
		runner.Version = v
	}
	os.Exit(runner.Main(os.Args[1:], os.Stdout, os.Stderr))
}
