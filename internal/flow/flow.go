// SPDX-License-Identifier: MIT

// Package flow tracks TCP connections and reassembles each direction's byte
// stream, in order, within bounded memory.
//
// A connection is a direction-independent 4-tuple plus an epoch (4-tuple
// reuse starts a new one). Each direction delivers its bytes in sequence
// order to a Handler, together with the packet that carried them, and
// reports every hole as a gap with the number of missing bytes when the
// sequence numbers give it. Retransmissions and duplicate observations of a
// packet (capture on "any", two taps) fall out as old data and are counted,
// so no byte is delivered twice, and the Handler is told which stream range
// was seen again. The first data wins an overlap; a conflicting overlap is
// counted. Checksums are never checked.
package flow

import (
	"bytes"
	"net/netip"
	"sort"

	"github.com/otfabric/go-modbus-trace/internal/link"
	"github.com/otfabric/go-modbus-trace/internal/pcapio"
)

// Limits bound the tracker.
type Limits struct {
	MaxConns     int    // tracked connections; the least recently seen is evicted
	BufferPerDir int    // out-of-order bytes held per direction
	BufferTotal  int    // out-of-order bytes held over all connections
	TailKeep     int    // delivered bytes kept per direction to detect conflicting overlaps
	EpochWindow  uint32 // a SYN further than this from a live direction's next byte starts a new epoch
}

// DefaultLimits are the documented defaults (ARCHITECTURE.md section 2).
var DefaultLimits = Limits{MaxConns: 100_000, BufferPerDir: 1 << 20, BufferTotal: 64 << 20, TailKeep: 512, EpochWindow: 1 << 20}

// Open says how a connection was first seen.
type Open uint8

// Opens.
const (
	OpenSYN       Open = iota + 1 // a SYN was seen before any data
	OpenMidstream                 // the capture started during the connection
)

// String returns how the connection opened, as the JSON output names it.
func (o Open) String() string {
	switch o {
	case OpenSYN:
		return "syn"
	case OpenMidstream:
		return "midstream"
	default:
		return ""
	}
}

// Close says how a connection ended.
type Close uint8

// Closes.
const (
	Live       Close = iota // not closed yet
	CloseFIN                // FIN in both directions
	CloseRST                // RST
	CloseEnd                // still open at the end of the trace
	CloseEvict              // evicted by the connection limit
	CloseSuper              // superseded by a new epoch of the same 4-tuple
)

// String returns how the connection closed, as the JSON output names it.
func (c Close) String() string {
	names := [...]string{"", "fin", "rst", "end_of_trace", "evicted", "superseded"}
	if int(c) >= len(names) {
		return "unknown"
	}
	return names[c]
}

// GapKind says why bytes are missing.
type GapKind uint8

// Gap kinds.
const (
	GapLoss     GapKind = iota + 1 // never captured
	GapSnaplen                     // cut by the snap length: the count is exact
	GapOverflow                    // the direction's buffer limit was reached
	GapBudget                      // the total buffer budget was reached
)

// String returns the gap kind as the JSON output names it.
func (g GapKind) String() string {
	names := [...]string{"", "loss", "snaplen", "reassembly_overflow", "reassembly_budget"}
	if int(g) >= len(names) {
		return "unknown"
	}
	return names[g]
}

// Chunk is where delivered bytes come from.
type Chunk struct {
	Part          uint16 // input file
	Frame         uint64
	Offset        int64
	Iface         uint32
	TimeNS        int64
	HasTime       bool
	PayOff        int32 // offset of the bytes in the packet's data; -1 after IP reassembly
	Retransmitted bool  // the packet also carried bytes already delivered (Handler.Repeat reports which)
	OutOfOrder    bool  // held until an earlier hole was filled
}

// Handler receives a connection's events. Data's bytes are valid only
// during the call. Repeat says that a segment carried the already delivered
// stream range [pos, end) again (never for a keepalive probe); the range is
// clipped to the start of the stream.
type Handler interface {
	Open(c *Conn)
	Data(c *Conn, dir int, pos uint64, b []byte, ch Chunk)
	Repeat(c *Conn, dir int, pos, end uint64)
	Gap(c *Conn, dir int, pos uint64, n int64, kind GapKind)
	Close(c *Conn)
}

// ConnStats count conditions on one connection.
type ConnStats struct {
	Retransmits uint64
	OutOfOrder  uint64
	Conflicts   uint64
	Keepalives  uint64
	Gaps        uint64
	GapBytes    uint64
	SnapBytes   uint64 // payload bytes cut by the snap length
	SYNRetrans  uint64
}

// Conn is one connection epoch.
type Conn struct {
	ID         uint32            // in order of the first packet, from 1
	Endpoints  [2]netip.AddrPort // [0] sent the first packet seen
	SYNFrom    int               // direction of the first SYN without ACK; -1 if none
	SYNACKFrom int               // direction of the first SYN+ACK; -1 if none
	Open       Open
	Close      Close
	FirstNS    int64
	LastNS     int64
	Iface      uint32 // interface of the first packet
	MultiIface bool   // also seen on another interface
	Packets    [2]uint64
	Bytes      [2]uint64 // TCP payload bytes per direction
	Stats      ConnStats
	User       any // for the handler

	key        key
	dirs       [2]half
	prev, next *Conn // LRU list
}

type key struct{ a, b netip.AddrPort }

func keyOf(s, d netip.AddrPort) key {
	if c := s.Addr().Compare(d.Addr()); c < 0 || (c == 0 && s.Port() < d.Port()) {
		return key{s, d}
	}
	return key{d, s}
}

type pending struct {
	seq     uint32
	data    []byte
	missing uint32
	ch      Chunk
	cost    int // len(data) + heldOverhead, charged against the limits
}

// heldOverhead is charged per held segment besides its bytes, so empty or
// tiny segments (snap-length cuts, one-byte writes) cannot fill the buffer
// for free: a direction holds at most BufferPerDir/heldOverhead segments.
const heldOverhead = 128

type half struct {
	started  bool
	isn      uint32
	hasISN   bool
	next     uint32 // next expected sequence number
	pos      uint64 // stream position of next (bytes delivered or skipped)
	peerAck  uint32 // highest ACK the peer sent for this direction
	hasPeer  bool
	firstAck uint32 // the first ACK the peer sent: where the capture of this direction could start
	fin      bool
	pend     []pending
	pendLen  int
	tail     []byte
	gapEnd   uint64 // stream position where the last gap ended
	hasGap   bool
}

// Stats count over the whole trace.
type Stats struct {
	Conns      uint64 // connection epochs
	Midstream  uint64
	Evicted    uint64 // live connections closed by the limit
	MaxTracked int
	AfterClose uint64 // packets of a closed connection (final ACKs, late retransmissions)
	Overflows  uint64 // gaps declared by the per-direction limit
	BudgetGaps uint64 // gaps declared by the total budget
	Superseded uint64
	ConnStats  // sums over all closed connections
}

// Tracker is the flow stage. It is not safe for concurrent use.
type Tracker struct {
	L       Limits
	H       Handler
	Stats   Stats
	conns   map[key]*Conn
	lru     Conn // sentinel: lru.next is the most recent
	pendAll int
	ids     uint32
	gapping int // > 0 while gapTo drains: held data follows a skipped hole
}

// NewTracker returns a tracker. Zero limits take the defaults.
func NewTracker(l Limits, h Handler) *Tracker {
	d := DefaultLimits
	if l.MaxConns <= 0 {
		l.MaxConns = d.MaxConns
	}
	if l.BufferPerDir <= 0 {
		l.BufferPerDir = d.BufferPerDir
	}
	if l.BufferTotal <= 0 {
		l.BufferTotal = d.BufferTotal
	}
	if l.TailKeep < 0 {
		l.TailKeep = 0
	}
	if l.EpochWindow == 0 {
		l.EpochWindow = d.EpochWindow
	}
	t := &Tracker{L: l, H: h, conns: map[key]*Conn{}}
	t.lru.prev, t.lru.next = &t.lru, &t.lru
	return t
}

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }

func (t *Tracker) touch(c *Conn) {
	if c.next != nil {
		c.prev.next, c.next.prev = c.next, c.prev
	}
	c.prev, c.next = &t.lru, t.lru.next
	t.lru.next.prev = c
	t.lru.next = c
}

func (t *Tracker) unlink(c *Conn) {
	c.prev.next, c.next.prev = c.next, c.prev
	c.prev, c.next = nil, nil
	delete(t.conns, c.key)
}

// Packet feeds one decoded packet and returns the connection it belongs to.
func (t *Tracker) Packet(p *pcapio.Packet, s *link.Segment) *Conn {
	k := keyOf(s.Src, s.Dst)
	c := t.conns[k]
	syn := s.Flags&link.SYN != 0 && s.Flags&link.ACK == 0
	if c != nil && c.Close != Live {
		if !syn {
			t.Stats.AfterClose++
			t.touch(c)
			return c
		}
		t.unlink(c) // a new epoch after FIN or RST
		c = nil
	}
	if c != nil && syn {
		d := t.dir(c, s.Src)
		h := &c.dirs[d]
		switch {
		case h.hasISN && s.Seq == h.isn:
			c.Stats.SYNRetrans++
			t.seen(c, p, d, s)
			return c
		case h.started && dist(s.Seq, h.next) > t.L.EpochWindow:
			t.end(c, CloseSuper)
			t.Stats.Superseded++
			t.unlink(c)
			c = nil
		}
	}
	if c == nil {
		c = t.newConn(k, p, s)
	}
	t.touch(c)
	d := t.dir(c, s.Src)
	t.seen(c, p, d, s)
	t.segment(c, d, p, s)
	return c
}

func dist(a, b uint32) uint32 {
	if seqLT(a, b) {
		return b - a
	}
	return a - b
}

func (t *Tracker) dir(c *Conn, src netip.AddrPort) int {
	if src == c.Endpoints[0] {
		return 0
	}
	return 1
}

func (t *Tracker) newConn(k key, p *pcapio.Packet, s *link.Segment) *Conn {
	for len(t.conns) >= t.L.MaxConns {
		old := t.lru.prev
		if old.Close == Live {
			t.end(old, CloseEvict)
			t.Stats.Evicted++
		}
		t.unlink(old)
	}
	t.ids++
	t.Stats.Conns++
	c := &Conn{ID: t.ids, key: k, Endpoints: [2]netip.AddrPort{s.Src, s.Dst}, SYNFrom: -1, SYNACKFrom: -1,
		FirstNS: p.TimeNS, LastNS: p.TimeNS, Iface: p.Iface}
	t.conns[k] = c
	t.Stats.MaxTracked = max(t.Stats.MaxTracked, len(t.conns))
	return c
}

// seen updates the connection's packet facts.
func (t *Tracker) seen(c *Conn, p *pcapio.Packet, d int, s *link.Segment) {
	c.Packets[d]++
	c.Bytes[d] += uint64(len(s.Payload)) + uint64(s.Missing)
	if p.HasTime {
		if c.FirstNS == 0 {
			c.FirstNS = p.TimeNS
		}
		c.LastNS = p.TimeNS
	}
	if p.Iface != c.Iface {
		c.MultiIface = true
	}
}

func (t *Tracker) segment(c *Conn, d int, p *pcapio.Packet, s *link.Segment) {
	h, o := &c.dirs[d], &c.dirs[1-d]
	if s.Flags&link.SYN != 0 {
		if s.Flags&link.ACK == 0 && c.SYNFrom < 0 {
			c.SYNFrom = d
		}
		if s.Flags&link.ACK != 0 && c.SYNACKFrom < 0 {
			c.SYNACKFrom = d
		}
		if !h.started {
			h.started, h.isn, h.hasISN, h.next = true, s.Seq, true, s.Seq+1
		}
	}
	data := len(s.Payload) > 0 || s.Missing > 0
	if c.Open == 0 && (data || s.Flags&(link.FIN|link.RST) != 0) {
		c.Open = OpenMidstream
		if c.SYNFrom >= 0 || c.SYNACKFrom >= 0 {
			c.Open = OpenSYN
		} else {
			t.Stats.Midstream++
		}
		t.H.Open(c)
	} else if c.Open == 0 && s.Flags&link.SYN != 0 {
		c.Open = OpenSYN
		t.H.Open(c)
	}
	if s.Flags&link.ACK != 0 {
		if !o.hasPeer {
			o.firstAck = s.Ack
		}
		if !o.hasPeer || seqLT(o.peerAck, s.Ack) {
			o.peerAck, o.hasPeer = s.Ack, true
		}
		// The peer acknowledged bytes the capture never saw: they reached
		// it and will not be retransmitted. Declare the hole once there is
		// later data waiting behind it.
		if o.started && len(o.pend) > 0 && seqLT(o.next, o.peerAck) {
			t.gapTo(c, 1-d, o.peerAck, GapLoss)
		}
	}
	seq := s.Seq
	if s.Flags&link.SYN != 0 {
		seq++
	}
	if data {
		if !h.started {
			// Midstream: the peer's first ACK in the capture says where
			// this direction's bytes start. That recovers a first segment
			// captured out of order, and makes bytes sent but not captured
			// before the first captured one a gap.
			h.started, h.next = true, seq
			if h.hasPeer && seqLT(h.firstAck, seq) && int(seq-h.firstAck) <= t.L.BufferPerDir {
				h.next = h.firstAck
			}
		}
		ch := Chunk{Part: p.Part, Frame: p.Frame, Offset: p.Offset, Iface: p.Iface, TimeNS: p.TimeNS, HasTime: p.HasTime, PayOff: int32(s.PayOff)}
		if s.PayOff < 0 {
			ch.PayOff = -1
		}
		t.accept(c, d, seq, s.Payload, s.Missing, ch, false)
	}
	if s.Flags&link.FIN != 0 && !h.fin {
		h.fin = true
		end := seq + uint32(len(s.Payload)) + s.Missing
		if h.started && seqLT(h.next, end) {
			t.gapTo(c, d, end, GapLoss)
		}
		if c.dirs[1-d].fin {
			t.end(c, CloseFIN)
		}
	}
	if s.Flags&link.RST != 0 && c.Close == Live {
		t.end(c, CloseRST)
	}
}

// accept handles payload bytes at seq (missing: bytes after them that the
// snap length cut). held: the bytes come from the out-of-order buffer.
func (t *Tracker) accept(c *Conn, d int, seq uint32, b []byte, missing uint32, ch Chunk, held bool) {
	h := &c.dirs[d]
	end := seq + uint32(len(b)) + missing
	switch {
	case !seqLT(h.next, end): // all old
		// A keepalive probe is one old byte just before the next one; a
		// copy drained from the buffer only looks like one.
		if !held && len(b) <= 1 && missing == 0 && seq == h.next-1 {
			c.Stats.Keepalives++
			return
		}
		c.Stats.Retransmits++
		t.compare(c, h, seq, b)
		t.repeat(c, d, seq, end)
		return
	case seqLT(seq, h.next): // partly new
		c.Stats.Retransmits++
		t.repeat(c, d, seq, h.next)
		cut := h.next - seq
		if int(cut) >= len(b) {
			t.compare(c, h, seq, b)
			missing -= cut - uint32(len(b))
			b = nil
		} else {
			t.compare(c, h, seq, b[:cut])
			b = b[cut:]
			if ch.PayOff >= 0 {
				ch.PayOff += int32(cut)
			}
		}
		seq = h.next
		ch.Retransmitted = true
	}
	if seq != h.next {
		t.hold(c, d, seq, b, missing, ch)
		return
	}
	t.deliver(c, d, b, ch)
	if missing > 0 {
		t.skip(c, d, int64(missing), GapSnaplen)
		c.Stats.SnapBytes += uint64(missing)
	}
	if !held {
		t.drain(c, d, true) // a held segment is delivered by drain's own loop: no recursion per segment
	}
}

// repeat reports the bytes [seq, end), all before next, as seen again.
func (t *Tracker) repeat(c *Conn, d int, seq, end uint32) {
	h := &c.dirs[d]
	back, rest := uint64(h.next-seq), uint64(h.next-end)
	if rest >= h.pos {
		return // before the first byte of the stream
	}
	var pos uint64
	if back < h.pos {
		pos = h.pos - back
	}
	if to := h.pos - rest; pos < to {
		t.H.Repeat(c, d, pos, to)
	}
}

// hold buffers future bytes within the per-direction and total limits.
func (t *Tracker) hold(c *Conn, d int, seq uint32, b []byte, missing uint32, ch Chunk) {
	h := &c.dirs[d]
	if h.hasPeer && seqLT(h.next, h.peerAck) {
		// Already known lost (acknowledged, never seen): skip it now.
		t.gapTo(c, d, h.peerAck, GapLoss)
		t.accept(c, d, seq, b, missing, ch, false)
		return
	}
	cost := len(b) + heldOverhead
	if h.pendLen+cost > t.L.BufferPerDir && len(h.pend) > 0 {
		t.Stats.Overflows++
		t.gapTo(c, d, h.pend[0].seq, GapOverflow)
		t.accept(c, d, seq, b, missing, ch, false) // delivers, holds again, or overflows again
		return
	}
	for t.pendAll+cost > t.L.BufferTotal {
		v := t.largest()
		if v == nil {
			break
		}
		vd := 0
		if v.dirs[1].pendLen > v.dirs[0].pendLen {
			vd = 1
		}
		t.Stats.BudgetGaps++
		t.gapTo(v, vd, v.dirs[vd].pend[0].seq, GapBudget)
		if v == c && vd == d {
			t.accept(c, d, seq, b, missing, ch, false)
			return
		}
	}
	// After any held segment with the same start: the first data wins.
	i := sort.Search(len(h.pend), func(i int) bool { return seqLT(seq, h.pend[i].seq) })
	h.pend = append(h.pend, pending{})
	copy(h.pend[i+1:], h.pend[i:])
	h.pend[i] = pending{seq: seq, data: append([]byte(nil), b...), missing: missing, ch: ch, cost: cost}
	h.pendLen += cost
	t.pendAll += cost
}

// largest returns the connection holding the most buffered bytes in one
// direction (a scan: the budget bites rarely).
func (t *Tracker) largest() *Conn {
	var best *Conn
	n := 0
	for c := t.lru.next; c != &t.lru; c = c.next {
		for d := range c.dirs {
			if c.dirs[d].pendLen > n {
				best, n = c, c.dirs[d].pendLen
			}
		}
	}
	return best
}

// compare checks bytes at seq, all before next, against the delivered tail.
func (t *Tracker) compare(c *Conn, h *half, seq uint32, b []byte) {
	back := int(h.next - seq)
	if back > len(h.tail) {
		skip := back - len(h.tail)
		if skip >= len(b) {
			return
		}
		b, back = b[skip:], len(h.tail)
	}
	old := h.tail[len(h.tail)-back:]
	n := min(len(old), len(b))
	if !bytes.Equal(old[:n], b[:n]) {
		c.Stats.Conflicts++
	}
}

// drain delivers held segments that now fit. filled: the hole before them
// was filled by data (they were out of order), not skipped as a gap.
func (t *Tracker) drain(c *Conn, d int, filled bool) {
	h := &c.dirs[d]
	for len(h.pend) > 0 && !seqLT(h.next, h.pend[0].seq) {
		q := h.pend[0]
		h.pend = h.pend[1:]
		h.pendLen -= q.cost
		t.pendAll -= q.cost
		if filled && t.gapping == 0 {
			c.Stats.OutOfOrder++
			q.ch.OutOfOrder = true
		}
		t.accept(c, d, q.seq, q.data, q.missing, q.ch, true)
	}
	if len(h.pend) == 0 {
		h.pend = nil
	}
}

func (t *Tracker) deliver(c *Conn, d int, b []byte, ch Chunk) {
	if len(b) == 0 {
		return
	}
	h := &c.dirs[d]
	pos := h.pos
	h.next += uint32(len(b))
	h.pos += uint64(len(b))
	if k := t.L.TailKeep; k > 0 {
		if len(b) >= k {
			h.tail = append(h.tail[:0], b[len(b)-k:]...)
		} else {
			if len(h.tail)+len(b) > k {
				h.tail = append(h.tail[:0], h.tail[len(h.tail)+len(b)-k:]...)
			}
			h.tail = append(h.tail, b...)
		}
	}
	t.H.Data(c, d, pos, b, ch)
}

// skip moves the direction past n bytes that will never be delivered.
func (t *Tracker) skip(c *Conn, d int, n int64, kind GapKind) {
	h := &c.dirs[d]
	pos := h.pos
	h.next += uint32(n)
	h.pos += uint64(n)
	h.tail = h.tail[:0]
	if kind != GapSnaplen {
		// A gap that continues the previous one (nothing delivered in
		// between) is the same hole, declared in two steps.
		if !h.hasGap || h.gapEnd != pos {
			c.Stats.Gaps++
		}
		c.Stats.GapBytes += uint64(n)
		h.gapEnd, h.hasGap = h.pos, true
	}
	t.H.Gap(c, d, pos, n, kind)
}

// gapTo skips the direction forward to seq, delivering buffered data that
// lies before it on the way.
func (t *Tracker) gapTo(c *Conn, d int, seq uint32, kind GapKind) {
	h := &c.dirs[d]
	for seqLT(h.next, seq) {
		target := seq
		if len(h.pend) > 0 && seqLT(h.pend[0].seq, target) {
			target = h.pend[0].seq
		}
		if seqLT(h.next, target) {
			t.skip(c, d, int64(target-h.next), kind)
		}
		t.gapping++
		t.drain(c, d, false) // delivers pend[0] once it fits, so the loop advances
		t.gapping--
	}
}

// end closes a connection: what is still buffered is delivered after gaps.
func (t *Tracker) end(c *Conn, why Close) {
	for d := range c.dirs {
		h := &c.dirs[d]
		if n := len(h.pend); n > 0 {
			last := h.pend[n-1]
			t.gapTo(c, d, last.seq+uint32(len(last.data))+last.missing, GapLoss)
		}
	}
	if c.Open == 0 { // only bare ACKs were seen
		c.Open = OpenMidstream
		t.Stats.Midstream++
		t.H.Open(c)
	}
	c.Close = why
	t.H.Close(c)
	t.Stats.Fold(c)
}

// Finish closes every live connection at the end of the trace, in
// connection order.
func (t *Tracker) Finish() {
	var live []*Conn
	for c := t.lru.next; c != &t.lru; c = c.next {
		if c.Close == Live {
			live = append(live, c)
		}
	}
	sort.Slice(live, func(i, j int) bool { return live[i].ID < live[j].ID })
	for _, c := range live {
		t.end(c, CloseEnd)
	}
}

// Fold adds a connection's counters to the trace totals (done when it closes).
func (s *Stats) Fold(c *Conn) {
	x := &s.ConnStats
	y := c.Stats
	x.Retransmits += y.Retransmits
	x.OutOfOrder += y.OutOfOrder
	x.Conflicts += y.Conflicts
	x.Keepalives += y.Keepalives
	x.Gaps += y.Gaps
	x.GapBytes += y.GapBytes
	x.SnapBytes += y.SnapBytes
	x.SYNRetrans += y.SYNRetrans
}
