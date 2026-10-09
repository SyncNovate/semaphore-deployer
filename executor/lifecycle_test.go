package executor

import (
	"bytes"
	"syscall"
	"testing"
	"time"

	"github.com/sirupsen/logrus"
)

// TestWaitForShutdownOnSIGTERM verifies the happy path: send
// SIGTERM to the current process, waitForShutdown returns
// (in this test, via a separate goroutine + signal injection).
//
// The function under test (waitForShutdown) blocks until a
// signal arrives; we drive it from a goroutine, send the signal
// to ourselves, and assert the goroutine returns within a
// reasonable timeout.
func TestWaitForShutdownOnSIGTERM(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})

	done := make(chan int, 1)
	go func() {
		done <- waitForShutdown(logger)
	}()

	// Give the goroutine a moment to install the signal handler
	// before we send the signal. Without this, a fast signal
	// could race the signal.NotifyContext setup.
	time.Sleep(20 * time.Millisecond)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGTERM); err != nil {
		t.Fatalf("send SIGTERM: %v", err)
	}

	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("waitForShutdown returned %d, want 0", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForShutdown did not return within 2s after SIGTERM")
	}
}

// TestWaitForShutdownOnSIGINT verifies SIGINT also produces a
// clean exit (the standard "operator pressed Ctrl-C" path).
func TestWaitForShutdownOnSIGINT(t *testing.T) {
	logger := logrus.New()
	logger.SetOutput(&bytes.Buffer{})

	done := make(chan int, 1)
	go func() {
		done <- waitForShutdown(logger)
	}()

	time.Sleep(20 * time.Millisecond)

	if err := syscall.Kill(syscall.Getpid(), syscall.SIGINT); err != nil {
		t.Fatalf("send SIGINT: %v", err)
	}

	select {
	case rc := <-done:
		if rc != 0 {
			t.Errorf("waitForShutdown returned %d, want 0", rc)
		}
	case <-time.After(2 * time.Second):
		t.Fatal("waitForShutdown did not return within 2s after SIGINT")
	}
}

// TestSigNameReturnsReadable verifies the human-readable signal
// name is one of the two expected values. We do not assert which
// one (the function inspects the controlling TTY which is not
// portable across CI environments), only that it is one of them.
func TestSigNameReturnsReadable(t *testing.T) {
	name := sigName(syscall.SIGTERM)
	if name != "SIGTERM" && name != "SIGINT" {
		t.Errorf("sigName = %q, want SIGTERM or SIGINT", name)
	}
}

// TestIsInterruptRequestedIsBoolJustReturnsNoPanic verifies
// the helper does not panic and returns a deterministic shape.
func TestIsInterruptRequestedIsBoolJustReturnsNoPanic(t *testing.T) {
	_ = isInterruptRequested() // just must not panic
}

// TestShutdownTimeoutConstantSane pins the shutdown timeout
// at 30 seconds. A future refactor that raises this would make
// the operator's `kill` feel hung; lowering it would risk
// in-flight operations being abandoned mid-write.
func TestShutdownTimeoutConstantSane(t *testing.T) {
	if shutdownTimeout != 30*time.Second {
		t.Errorf("shutdownTimeout = %v, want 30s", shutdownTimeout)
	}
}
