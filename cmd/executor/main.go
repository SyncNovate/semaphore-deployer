// Command sentraops-executor is the customer-side deployment
// executor for the SentraOps `semaphore-deployer` fork. The actual
// implementation lives in `internal/executor`-style package
// (here: the top-level `executor` package); this file is the thin
// `package main` shim that satisfies Go's `go build` requirement
// for a binary.
//
// The split (library `executor` + main `cmd/executor`) lets the
// library be tested in isolation (no `package main` linkage) while
// still producing a single static binary at build time:
//
//	go build -o sentraops-executor ./cmd/executor
package main

import (
	"os"

	"github.com/semaphoreui/semaphore/executor"
)

func main() {
	os.Exit(executor.Main(os.Args[1:], os.Stdout, os.Stderr))
}
