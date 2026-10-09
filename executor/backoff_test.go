package executor

import (
	"context"
	"errors"
	"testing"
	"time"
)

// TestBackoffNextExponentialGrows verifies the base × 2^attempt
// schedule at low attempt counts. The jitter band is wide
// (0.5–1.5), so we don't pin the exact value — just verify
// growth.
func TestBackoffNextExponentialGrows(t *testing.T) {
	b, err := NewBackoff(50*time.Millisecond, 1*time.Second)
	if err != nil {
		t.Fatalf("NewBackoff: %v", err)
	}
	if got := b.Next(); got < 25*time.Millisecond || got > 75*time.Millisecond {
		t.Errorf("attempt 0: got %v, want range [25ms, 75ms]", got)
	}
	if got := b.Next(); got < 50*time.Millisecond || got > 150*time.Millisecond {
		t.Errorf("attempt 1: got %v, want range [50ms, 150ms]", got)
	}
	if got := b.Next(); got < 100*time.Millisecond || got > 300*time.Millisecond {
		t.Errorf("attempt 2: got %v, want range [100ms, 300ms]", got)
	}
}

// TestBackoffNextCappedAtMax verifies the cap behavior: the
// schedule saturates at max regardless of attempt count.
func TestBackoffNextCappedAtMax(t *testing.T) {
	b, _ := NewBackoff(100*time.Millisecond, 200*time.Millisecond)
	for i := 0; i < 10; i++ {
		_ = b.Next()
	}
	got := b.Next()
	if got > 300*time.Millisecond {
		t.Errorf("attempt saturates above max: got %v, want <= 300ms (150%% of max)", got)
	}
}

// TestBackoffResetReturnsToAttempt0 verifies Reset puts the
// scheduler back to the small initial delay.
func TestBackoffResetReturnsToAttempt0(t *testing.T) {
	b, _ := NewBackoff(50*time.Millisecond, 10*time.Second)
	for i := 0; i < 5; i++ {
		_ = b.Next()
	}
	b.Reset()
	got := b.Next()
	if got < 25*time.Millisecond || got > 75*time.Millisecond {
		t.Errorf("after Reset: got %v, want range [25ms, 75ms]", got)
	}
}

// TestBackoffRejectsBadInput pins the constructor's fail-closed
// contract. Bad input must produce an error, not silently
// construct a broken scheduler.
func TestBackoffRejectsBadInput(t *testing.T) {
	tests := []struct {
		name string
		base time.Duration
		max  time.Duration
	}{
		{"zero base", 0, 1 * time.Second},
		{"negative base", -1 * time.Second, 1 * time.Second},
		{"zero max", 1 * time.Second, 0},
		{"max < base", 100 * time.Millisecond, 50 * time.Millisecond},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			_, err := NewBackoff(tc.base, tc.max)
			if err == nil {
				t.Errorf("NewBackoff(%v, %v) should fail", tc.base, tc.max)
			}
		})
	}
}

// TestSleepCancellationContextCancels quickly verifies that
// Sleep respects ctx cancellation. Critical for retry loops:
// without this, a cancelled executor would keep retrying
// forever even after the operator hits Ctrl-C.
func TestSleepCancellationContextCancels(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	go func() {
		time.Sleep(10 * time.Millisecond)
		cancel()
	}()
	start := time.Now()
	err := Sleep(ctx, 5*time.Second)
	dur := time.Since(start)
	if !errors.Is(err, context.Canceled) {
		t.Errorf("Sleep err = %v, want context.Canceled", err)
	}
	if dur > 500*time.Millisecond {
		t.Errorf("Sleep did not return quickly after cancel: %v", dur)
	}
}

// TestSleepZeroOrNegativeReturnsImmediately verifies that the
// caller can pass `0` to mean "no delay" without blocking.
func TestSleepZeroOrNegativeReturnsImmediately(t *testing.T) {
	start := time.Now()
	if err := Sleep(context.Background(), 0); err != nil {
		t.Errorf("Sleep(0) err = %v, want nil", err)
	}
	if err := Sleep(context.Background(), -1*time.Second); err != nil {
		t.Errorf("Sleep(-1s) err = %v, want nil", err)
	}
	if dur := time.Since(start); dur > 50*time.Millisecond {
		t.Errorf("Sleep(0) blocked for %v, want immediate", dur)
	}
}
