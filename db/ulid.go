package db

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	"sync"
	"time"
)

// NewExecutorID returns a fresh executor public id in the canonical
// SentraOps format: "EXEC-" + 26 Crockford-Base32 chars (a ULID).
//
// The format matches the example in
// docs/architecture/2026-10-07-semaphore-fork-design.md §3.3
// (e.g. "EXEC-01HZX2N3K9ABCDEF0456"). ULIDs are time-sortable, which
// matches the executor's lifecycle (registration time = first sort key).
//
// Implementation note: we implement a minimal ULID here rather than pull
// in oklog/ulid. The generator is ~40 lines of straight-line code and
// has no third-party dependencies. If we ever need the full ULID spec
// (monotonic counters, multi-byte batch generation) we can swap to
// oklog/ulid without changing the public id format.
func NewExecutorID() (string, error) {
	// Crockford Base32 alphabet. Same as the canonical ULID encoding.
	const alphabet = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

	// 16 bytes = 6 timestamp bytes (ms since epoch, big-endian) +
	//            10 randomness bytes.
	var b [16]byte

	ms := uint64(time.Now().UnixMilli())
	binary.BigEndian.PutUint16(b[0:2], uint16(ms>>32))
	binary.BigEndian.PutUint32(b[2:6], uint32(ms&0xFFFFFFFF))

	if _, err := rand.Read(b[6:16]); err != nil {
		return "", fmt.Errorf("read randomness for executor id: %w", err)
	}

	// Encode 16 bytes to 26 Base32 chars. Stream 5 bits at a time
	// through a 130-bit accumulator (8 bits * 16 bytes + 2 zero-pad
	// bits = 130 bits = 26 * 5).
	out := make([]byte, 26)
	var acc uint64
	var accBits uint
	pos := 0

	for i := 0; i < 16; i++ {
		acc = (acc << 8) | uint64(b[i])
		accBits += 8
		for accBits >= 5 {
			shift := accBits - 5
			idx := (acc >> shift) & 0x1F
			out[pos] = alphabet[idx]
			pos++
			acc &= (uint64(1) << shift) - 1
			accBits = shift
		}
	}
	// Final partial group: pad to 5 bits and emit one more char.
	if accBits > 0 {
		idx := (acc << (5 - accBits)) & 0x1F
		out[pos] = alphabet[idx]
		pos++
	}

	return "EXEC-" + string(out[:pos]), nil
}

// executorIDGenMu serialises the timestamp read in NewExecutorID so
// two back-to-back calls in the same millisecond don't produce
// ambiguous ids. ULIDs guarantee uniqueness via the 80 random bits
// (collision probability ~ 2^-80 per ms), so this is only a hygiene
// measure, not a correctness requirement.
var executorIDGenMu sync.Mutex
