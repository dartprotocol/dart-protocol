package core

// Sequence numbers are 24 bits on the wire. Internally we keep them in this
// same modular space so the counter wraps cleanly at 2^24 instead of drifting
// away from the wire encoding (which would silently stop delivery at the wrap
// boundary).
const SeqMod = uint32(1) << 24

// SeqDelta returns the number of sequence steps from `from` to `to`, modulo
// the 24-bit space. 0 means equal; values in (0, SeqMod/2) mean `to` is ahead
// of `from`; values >= SeqMod/2 mean `to` is behind (a stale/duplicate).
func SeqDelta(from, to uint32) uint32 {
	return (to - from) & 0xFFFFFF
}

// SeqNext returns the next sequence number in the 24-bit space. The value 0 is
// a legitimate message (right after 0xFFFFFF); callers distinguish "no messages
// seen yet" by checking whether a per-sender entry exists in their
// highest-seen map, never by the numeric value alone.
func SeqNext(s uint32) uint32 {
	return (s + 1) & 0xFFFFFF
}
