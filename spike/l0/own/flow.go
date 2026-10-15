// SPDX-License-Identifier: MIT

package own

import (
	"bytes"
	"net/netip"
	"sort"
)

// Limits of the flow stage.
type Limits struct {
	BufferPerDir int // reassembly buffer per direction (bytes)
	TailKeep     int // delivered bytes kept to detect conflicting overlaps
	ResyncScan   int
}

// DefaultLimits are the ARCHITECTURE.md defaults.
var DefaultLimits = Limits{BufferPerDir: 1 << 20, TailKeep: 512, ResyncScan: 64 << 10}

// Stats is what the spike compares with the ground truth.
type Stats struct {
	Packets, Bytes  int64
	Dropped         [numReasons]int64
	Conns           int64
	Midstream       int64
	ADUs            int64
	Gaps            int64
	GapBytes        int64
	Retransmits     int64
	Conflicts       int64
	OutOfOrder      int64
	Resyncs         int64
	BadHeaders      int64
	Overflows       int64
	MaxConnsTracked int
}

type key struct{ a, b netip.AddrPort }

func keyOf(s, d netip.AddrPort) (key, int) {
	if s.Addr().Less(d.Addr()) || (s.Addr() == d.Addr() && s.Port() < d.Port()) {
		return key{s, d}, 0
	}
	return key{d, s}, 1
}

type ref struct {
	frame uint64
	n     int
}

type pending struct {
	seq   uint32
	data  []byte
	frame uint64
}

type half struct {
	ack     uint32 // last ACK this direction sent (the peer's next byte)
	hasAck  bool
	started bool
	closed  bool
	next    uint32
	pend    []pending
	pendLen int
	tail    []byte // last delivered bytes, for overlap comparison
	// framer
	buf    []byte
	refs   []ref
	resync bool
}

type conn struct {
	id   int64
	dirs [2]half
}

// Pipeline is the own-code flow stage plus MBAP framer.
type Pipeline struct {
	L     Limits
	S     Stats
	conns map[key]*conn
	seg   Segment
	// OnADU, if set, receives each framed ADU with its frames.
	OnADU func(conn int64, dir int, adu []byte, frames []ref)
}

// NewPipeline returns a pipeline with limits l.
func NewPipeline(l Limits) *Pipeline {
	return &Pipeline{L: l, conns: map[key]*conn{}}
}

func seqLT(a, b uint32) bool { return int32(a-b) < 0 }

// Packet feeds one captured packet.
func (p *Pipeline) Packet(pk *Packet) {
	p.S.Packets++
	p.S.Bytes += int64(len(pk.Data))
	if r := ParseTCP(pk.Link, pk.Data, &p.seg); r != OK {
		p.S.Dropped[r]++
		return
	}
	s := &p.seg
	k, d := keyOf(s.Src, s.Dst)
	c := p.conns[k]
	if c != nil && s.Flags&SYN != 0 && s.Flags&ACK == 0 && c.dirs[0].closed && c.dirs[1].closed {
		p.close(c) // 4-tuple reuse: a new epoch
		c = nil
	}
	if c == nil {
		p.S.Conns++
		c = &conn{id: p.S.Conns}
		p.conns[k] = c
		p.S.MaxConnsTracked = max(p.S.MaxConnsTracked, len(p.conns))
		if s.Flags&SYN == 0 {
			p.S.Midstream++
		}
	}
	h, o := &c.dirs[d], &c.dirs[1-d]
	// The peer acknowledged bytes we never saw: the capture lost them, and
	// they will not come again. Declare the gap now instead of buffering up
	// to the limit.
	if s.Flags&ACK != 0 && o.started && seqLT(o.next, s.Ack) {
		p.gapTo(c, 1-d, s.Ack)
	}
	switch {
	case s.Flags&SYN != 0:
		if !h.started {
			h.started, h.next = true, s.Seq+1
		}
	case !h.started && len(s.Payload) > 0:
		// Midstream: the peer's ACK says where this direction's next byte
		// is, which recovers a first segment that arrived out of order.
		h.started, h.next = true, s.Seq
		if o.hasAck && seqLT(o.ack, s.Seq) && int(s.Seq-o.ack) <= p.L.BufferPerDir {
			h.next = o.ack
		}
	}
	if s.Flags&ACK != 0 {
		h.ack, h.hasAck = s.Ack, true
	}
	if len(s.Payload) > 0 {
		p.data(c, d, s.Seq, s.Payload, pk.Frame)
	}
	if s.Flags&(FIN|RST) != 0 {
		if len(h.pend) > 0 {
			p.gapTo(c, d, h.pend[len(h.pend)-1].seq+uint32(len(h.pend[len(h.pend)-1].data)))
		}
		h.closed = true
		if s.Flags&RST != 0 {
			o.closed = true
		}
	}
}

func (p *Pipeline) data(c *conn, d int, seq uint32, b []byte, frame uint64) {
	h := &c.dirs[d]
	end := seq + uint32(len(b))
	switch {
	case !seqLT(h.next, end): // all old: retransmission or duplicate
		p.S.Retransmits++
		p.compare(h, seq, b)
	case seqLT(seq, h.next): // partly new
		p.S.Retransmits++
		cut := h.next - seq
		p.compare(h, seq, b[:cut])
		p.deliver(c, d, b[cut:], frame)
	case seq == h.next:
		p.deliver(c, d, b, frame)
	default: // future: buffer
		if h.pendLen+len(b) > p.L.BufferPerDir && len(h.pend) > 0 {
			p.S.Overflows++
			p.gapTo(c, d, h.pend[0].seq)
			p.data(c, d, seq, b, frame)
			return
		}
		i := sort.Search(len(h.pend), func(i int) bool { return !seqLT(h.pend[i].seq, seq) })
		h.pend = append(h.pend, pending{})
		copy(h.pend[i+1:], h.pend[i:])
		h.pend[i] = pending{seq: seq, data: append([]byte(nil), b...), frame: frame}
		h.pendLen += len(b)
		return
	}
	p.drain(c, d)
}

// compare checks retransmitted bytes against what was delivered, as far as the
// kept tail reaches.
func (p *Pipeline) compare(h *half, seq uint32, b []byte) {
	back := int(h.next - seq) // bytes from seq to next
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
		p.S.Conflicts++
	}
}

func (p *Pipeline) drain(c *conn, d int) {
	h := &c.dirs[d]
	for len(h.pend) > 0 && !seqLT(h.next, h.pend[0].seq) {
		q := h.pend[0]
		h.pend = h.pend[1:]
		h.pendLen -= len(q.data)
		p.S.OutOfOrder++
		if end := q.seq + uint32(len(q.data)); seqLT(h.next, end) {
			p.deliver(c, d, q.data[h.next-q.seq:], q.frame)
		}
	}
	if len(h.pend) == 0 {
		h.pend = nil
	}
}

// gapTo skips the direction forward to seq, delivering buffered data on the way.
func (p *Pipeline) gapTo(c *conn, d int, seq uint32) {
	h := &c.dirs[d]
	for seqLT(h.next, seq) {
		target := seq
		if len(h.pend) > 0 && seqLT(h.pend[0].seq, target) {
			target = h.pend[0].seq
		}
		if seqLT(h.next, target) {
			p.S.Gaps++
			p.S.GapBytes += int64(target - h.next)
			h.next = target
			h.buf, h.refs, h.resync = h.buf[:0], h.refs[:0], true
			h.tail = h.tail[:0]
		}
		p.drain(c, d) // delivers pend[0] when it now fits, so the loop advances
	}
}

func (p *Pipeline) deliver(c *conn, d int, b []byte, frame uint64) {
	h := &c.dirs[d]
	h.next += uint32(len(b))
	if k := p.L.TailKeep; k > 0 {
		h.tail = append(h.tail, b...)
		if len(h.tail) > k {
			h.tail = append(h.tail[:0], h.tail[len(h.tail)-k:]...)
		}
	}
	h.buf = append(h.buf, b...)
	h.refs = append(h.refs, ref{frame, len(b)})
	p.frame(c, d)
}

func validHeader(b []byte) (int, bool) {
	n := int(b[4])<<8 | int(b[5])
	return 6 + n, b[2] == 0 && b[3] == 0 && n >= 2 && n <= 254
}

// frame cuts MBAP ADUs out of the direction's byte run.
func (p *Pipeline) frame(c *conn, d int) {
	h := &c.dirs[d]
	off, done := 0, 0 // h.refs describe h.buf[done:]
	for len(h.buf)-off >= 7 {
		n, ok := validHeader(h.buf[off:])
		if ok && h.resync {
			// After a gap: accept a header only if the next one is valid
			// too, or the run ends exactly after it.
			rest := h.buf[off:]
			switch {
			case len(rest) == n:
			case len(rest) >= n+7:
				_, ok = validHeader(rest[n:])
			default:
				goto wait
			}
		}
		if !ok {
			p.S.BadHeaders++
			if off++; off > p.L.ResyncScan {
				off = len(h.buf) // give up on this run
			}
			h.resync = true
			continue
		}
		if len(h.buf)-off < n {
			break
		}
		if h.resync {
			p.S.Resyncs++
			h.resync = false
		}
		p.S.ADUs++
		frames := p.take(h, off-done, n)
		done = off + n
		if p.OnADU != nil {
			p.OnADU(c.id, d, h.buf[off:off+n], frames)
		}
		off += n
	}
wait:
	if off > 0 {
		p.take(h, off-done, 0)
		h.buf = append(h.buf[:0], h.buf[off:]...)
	}
	if cap(h.buf) > 4096 && len(h.buf) < 256 {
		h.buf = append([]byte(nil), h.buf...) // do not keep a large buffer per connection
	}
}

// take consumes the refs of the next skip+n bytes and returns those of the
// n-byte ADU after the skipped bytes.
var frameScratch []ref

func (p *Pipeline) take(h *half, skip, n int) []ref {
	frameScratch = frameScratch[:0]
	for n > 0 && len(h.refs) > 0 {
		r := &h.refs[0]
		if skip >= r.n {
			skip -= r.n
			h.refs = h.refs[1:]
			continue
		}
		use := min(r.n-skip, n)
		frameScratch = append(frameScratch, ref{r.frame, use})
		r.n -= skip + use
		skip, n = 0, n-use
		if r.n == 0 {
			h.refs = h.refs[1:]
		}
	}
	if skip > 0 { // consume skipped bytes without an ADU
		for skip > 0 && len(h.refs) > 0 {
			r := &h.refs[0]
			use := min(r.n, skip)
			r.n -= use
			skip -= use
			if r.n == 0 {
				h.refs = h.refs[1:]
			}
		}
	}
	if len(h.refs) == 0 {
		h.refs = h.refs[:0:min(cap(h.refs), 8)] // keep a small backing array
	}
	return frameScratch
}

func (p *Pipeline) close(c *conn) {
	for d := range c.dirs {
		h := &c.dirs[d]
		if len(h.pend) > 0 {
			last := h.pend[len(h.pend)-1]
			p.gapTo(c, d, last.seq+uint32(len(last.data)))
		}
	}
}

// Finish closes everything at the end of the trace.
func (p *Pipeline) Finish() {
	ids := make([]*conn, 0, len(p.conns))
	for _, c := range p.conns {
		ids = append(ids, c)
	}
	sort.Slice(ids, func(i, j int) bool { return ids[i].id < ids[j].id }) // deterministic
	for _, c := range ids {
		p.close(c)
	}
}

// Tracked returns the number of tracked connections.
func (p *Pipeline) Tracked() int { return len(p.conns) }
