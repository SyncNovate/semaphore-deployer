package executor

import (
	"context"
	"errors"
	"math/rand"
	"time"
)

// Backoff is an exponential-backoff schedule with full jitter.
//
// Used by retry loops that need to back off after a 5xx or network
// error (transient failures). Each call to Next() returns the next
// sleep duration. The schedule is `min(max, base * 2^attempt)`
// randomized in [0.5, 1.5] of the computed value — the jitter
// prevents thundering-herd when N executors reconnect at the same
// moment after the server returns.
//
// Why full jitter (vs equal or decorrelated jitter): AWS's
// "Exponential Backoff and Jitter" article (Marc Brooker, 2015)
// shows full jitter minimizes the contention window when many
// clients are retrying in lockstep. We default to full jitter
// because the executor's typical scenario (one executor per
// customer) doesn't NEED the worst-case latency reduction of
// decorrelated jitter.
type Backoff struct {
	base    time.Duration
	max     time.Duration
	attempt int
	rng     *rand.Rand
}

// NewBackoff builds a backoff schedule with the given base +
// max. Both must be > 0; the constructor fails closed if not.
func NewBackoff(base, max time.Duration) (*Backoff, error) {
	if base <= 0 {
		return nil, errors.New("executor/backoff: base must be > 0")
	}
	if max <= 0 {
		return nil, errors.New("executor/backoff: max must be > 0")
	}
	if max < base {
		return nil, errors.New("executor/backoff: max must be >= base")
	}
	return &Backoff{
		base: base,
		max:  max,
		rng:  rand.New(rand.NewSource(time.Now().UnixNano())),
	}, nil
}

// Next returns the next sleep duration and increments the
// attempt counter. The first call returns a value in
// [0.5*base, 1.5*base] (full jitter around the base); subsequent
// calls grow exponentially up to max.
func (b *Backoff) Next() time.Duration {
	if b == nil {
		return 0
	}
	// base * 2^attempt, capped at max.
	d := b.base << b.attempt
	if d <= 0 || d > b.max {
		d = b.max
	}
	// Jitter: random factor in [0.5, 1.5]. The math is
	// done in float to avoid overflow at extreme attempt
	// counts.
	jittered := time.Duration(float64(d) * (0.5 + b.rng.Float64()))
	b.attempt++
	return jittered
}

// Reset returns the schedule to attempt=0. Use after a successful
// operation so the next failure starts from the base again.
func (b *Backoff) Reset() {
	if b == nil {
		return
	}
	b.attempt = 0
}

// Sleep blocks for d, or returns early if ctx is cancelled. The
// helper makes retry loops cancellable without each loop having
// to wire `select { case <-ctx.Done(): ...; case <-time.After(d): }`.
//
// Returns ctx.Err() if cancelled; nil otherwise.
func Sleep(ctx context.Context, d time.Duration) error {
	if d <= 0 {
		return nil
	}
	t := time.NewTimer(d)
	defer t.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-t.C:
		return nil
	}
}
