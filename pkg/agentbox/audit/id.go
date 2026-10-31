package audit

import (
	"crypto/rand"
	"strings"
	"time"
)

const crockford = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"

// idGen makes ULIDs: 48 bits of Unix milliseconds, then 80 random bits.
// Within one millisecond, or if the clock steps back, it increments the
// previous ID instead, so one generator's IDs always sort in creation order.
type idGen struct {
	ms   uint64
	rand [10]byte
}

func (g *idGen) next(t time.Time) string {
	ms := uint64(t.UnixMilli())
	if ms > g.ms {
		g.ms = ms
		rand.Read(g.rand[:])
	} else if !increment(g.rand[:]) {
		// 2^80 IDs in one millisecond: borrow the next one.
		g.ms++
		rand.Read(g.rand[:])
	}
	var b [16]byte
	for i := 0; i < 6; i++ {
		b[i] = byte(g.ms >> (40 - 8*i))
	}
	copy(b[6:], g.rand[:])
	return "evt_" + encode(b)
}

// increment adds one to a big-endian number; false when it wraps.
func increment(b []byte) bool {
	for i := len(b) - 1; i >= 0; i-- {
		b[i]++
		if b[i] != 0 {
			return true
		}
	}
	return false
}

// encode writes 128 bits as 26 Crockford base32 digits (2 leading zero bits).
func encode(b [16]byte) string {
	var hi, lo uint64
	for i := 0; i < 8; i++ {
		hi = hi<<8 | uint64(b[i])
		lo = lo<<8 | uint64(b[8+i])
	}
	var out [26]byte
	for i := 25; i >= 0; i-- {
		out[i] = crockford[lo&31]
		lo = lo>>5 | hi<<59
		hi >>= 5
	}
	return string(out[:])
}

func validEventID(id string) bool {
	s, ok := strings.CutPrefix(id, "evt_")
	if !ok || len(s) != 26 || s[0] > '7' {
		return false
	}
	for i := 0; i < len(s); i++ {
		if strings.IndexByte(crockford, s[i]) < 0 {
			return false
		}
	}
	return true
}
