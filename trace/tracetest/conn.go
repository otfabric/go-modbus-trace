// SPDX-License-Identifier: MIT

package tracetest

import (
	"encoding/binary"
	"net/netip"
)

// Dir is a direction of a connection.
type Dir int

// Directions.
const (
	ToServer Dir = iota // client to server: requests
	ToClient            // server to client: responses
)

// ADU is one Modbus/TCP ADU the script wrote, with its fate.
type ADU struct {
	Conn      uint32 // connection number, in order of the first packet (1-based)
	Dir       Dir
	TID       uint16
	Unit      uint8
	PDU       []byte
	Lost      bool // some of its bytes were never captured
	Truncated bool // the snap length cut it; the visible bytes are there
	Resynced  bool // the first ADU after a gap in its direction
}

// Truth is what a correct reader, reassembler and framer must report.
type Truth struct {
	Packets     uint64 // packet records written
	Conns       uint32 // connections (epochs) that sent a packet
	Midstream   uint64 // connections without a captured handshake
	ADUs        []ADU
	Gaps        uint64 // holes in a direction's byte stream
	GapBytes    uint64
	Retransmits uint64 // segments that carry only bytes already seen
	Conflicts   uint64 // ... whose bytes differ from the first copy
	OutOfOrder  uint64 // segments that arrived before a gap before them was filled
	Keepalives  uint64
}

// Delivered returns the ADUs a framer must produce, in write order per
// connection and direction.
func (t *Truth) Delivered() []ADU {
	var out []ADU
	for _, a := range t.ADUs {
		if !a.Lost {
			out = append(out, a)
		}
	}
	return out
}

// Frame is one item of a Write: an ADU (recorded in the truth) or raw
// bytes (not recorded).
type Frame struct {
	TID  uint16
	Unit uint8
	PDU  []byte
	Raw  []byte
}

// MBAP returns a Modbus/TCP ADU: header (protocol 0, length) and PDU.
func MBAP(tid uint16, unit uint8, pdu []byte) []byte {
	b := binary.BigEndian.AppendUint16(make([]byte, 0, 7+len(pdu)), tid)
	b = append(b, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(1+len(pdu)))
	b = append(b, unit)
	return append(b, pdu...)
}

func (f Frame) bytes() []byte {
	if f.Raw != nil {
		return f.Raw
	}
	return MBAP(f.TID, f.Unit, f.PDU)
}

// ReadRequest returns the PDU of an FC01-04 request.
func ReadRequest(fc uint8, addr, qty uint16) []byte {
	return []byte{fc, byte(addr >> 8), byte(addr), byte(qty >> 8), byte(qty)}
}

// RegistersResponse returns the PDU of an FC03/04 response.
func RegistersResponse(fc uint8, values ...uint16) []byte {
	b := []byte{fc, byte(2 * len(values))}
	for _, v := range values {
		b = binary.BigEndian.AppendUint16(b, v)
	}
	return b
}

// Exception returns an exception response PDU.
func Exception(fc, code uint8) []byte { return []byte{fc | 0x80, code} }

// ConnOptions configure a connection.
type ConnOptions struct {
	Client, Server netip.AddrPort // default 10.0.0.1:40000 and 10.0.0.2:502
	Iface          int
	Midstream      bool   // no handshake: the capture starts during the connection
	SYNRetransmit  bool   // the client's SYN is sent twice
	ClientISN      uint32 // initial sequence numbers; 0 picks one
	ServerISN      uint32
	MSS            int // default 1460
}

// Conn is a scripted TCP connection.
type Conn struct {
	b        *Builder
	o        ConnOptions
	id       uint32
	seq      [2]uint32
	anchored [2]bool
	lostRun  [2]int64 // bytes lost since the last captured data; -1: none
	sent     [2]bool  // the direction has captured data
	// A hole stays open (for a reader that declares a loss only once the
	// peer acknowledged past it and later data waits behind it) until both
	// happened.
	holeOpen, peerAcked, dataAfter [2]bool
	resync                         [2]bool // the next delivered ADU follows a gap
	closed                         bool
}

// Conn starts a connection; without Midstream it writes the handshake.
func (b *Builder) Conn(o ConnOptions) *Conn {
	if !o.Client.IsValid() {
		o.Client = netip.MustParseAddrPort("10.0.0.1:40000")
	}
	if !o.Server.IsValid() {
		o.Server = netip.MustParseAddrPort("10.0.0.2:502")
	}
	if o.MSS == 0 {
		o.MSS = 1460
	}
	n := uint32(b.conns + 1)
	if o.ClientISN == 0 {
		o.ClientISN = 1000 * n
	}
	if o.ServerISN == 0 {
		o.ServerISN = 0x7000_0000 + 5000*n
	}
	c := &Conn{b: b, o: o, seq: [2]uint32{o.ClientISN + 1, o.ServerISN + 1}, lostRun: [2]int64{-1, -1}}
	if o.Midstream {
		b.truth.Midstream++
		return c
	}
	c.segment(ToServer, o.ClientISN, 0x02, nil, segOpts{})
	if o.SYNRetransmit {
		c.segment(ToServer, o.ClientISN, 0x02, nil, segOpts{})
	}
	c.segment(ToClient, o.ServerISN, 0x12, nil, segOpts{})
	c.segment(ToServer, c.seq[0], 0x10, nil, segOpts{})
	c.anchored = [2]bool{true, true}
	return c
}

// ID returns the connection number (0 before its first packet).
func (c *Conn) ID() uint32 { return c.id }

type segOpts struct {
	iface    int
	frag     int
	snap     int
	override bool
}

// segment writes one TCP segment as a packet.
func (c *Conn) segment(d Dir, seq uint32, flags uint8, payload []byte, so segOpts) {
	b := c.b
	if c.id == 0 {
		b.conns++
		c.id = uint32(b.conns)
		b.truth.Conns++
	}
	src, dst := c.o.Client, c.o.Server
	if d == ToClient {
		src, dst = dst, src
	}
	ack := c.seq[1-d]
	if flags&0x02 != 0 && flags&0x10 == 0 {
		ack = 0
	}
	t := binary.BigEndian.AppendUint16(make([]byte, 0, 20+len(payload)), src.Port())
	t = binary.BigEndian.AppendUint16(t, dst.Port())
	t = binary.BigEndian.AppendUint32(t, seq)
	t = binary.BigEndian.AppendUint32(t, ack)
	t = append(t, 5<<4, flags, 0xff, 0xff, 0, 0, 0, 0)
	t = append(t, payload...)
	iface := c.o.Iface
	if so.override {
		iface = so.iface
	}
	v6 := src.Addr().Is6()
	if so.frag > 0 {
		for _, ip := range b.fragments(src.Addr(), dst.Addr(), 6, t, so.frag) {
			b.packet(iface, b.wrap(iface, ip, v6))
		}
	} else {
		pkt := b.wrap(iface, b.ipPacket(src.Addr(), dst.Addr(), 6, t), v6)
		if so.snap > 0 && so.snap < len(payload) {
			cut := len(pkt) - len(payload) + so.snap
			for len(pkt) > 60 && cut < 60 { // keep the Ethernet minimum out of the cut
				cut++
			}
			b.write(iface, uint32(len(pkt)), pkt[:min(cut, len(pkt))])
		} else {
			b.packet(iface, pkt)
		}
	}
	// Any packet acknowledges the peer's bytes so far.
	if flags&0x10 != 0 {
		x := 1 - d
		c.anchored[x] = true
		if c.holeOpen[x] {
			c.peerAcked[x] = true
			if c.dataAfter[x] {
				c.holeOpen[x] = false
			}
		}
	}
}

// WriteOpts shape one Write.
type WriteOpts struct {
	Seg        []int // segment sizes; the rest goes in MSS-sized segments
	OneByte    bool  // one byte per segment
	Lose       []int // segment indices never captured
	Retransmit []int // indices sent again, identical, after the write
	Conflict   []int // indices sent again with the last byte changed
	Duplicate  []int // indices captured a second time on DupIface
	DupIface   int
	Reverse    bool // segments in reverse order
	Fragment   int  // IP fragments of this payload size (a multiple of 8)
	Snap       int  // capture only the first Snap payload bytes of each segment
}

func has(xs []int, i int) bool {
	for _, x := range xs {
		if x == i {
			return true
		}
	}
	return false
}

// Write sends frames back to back as one write in direction d.
func (c *Conn) Write(d Dir, o WriteOpts, frames ...Frame) {
	var data []byte
	type span struct{ start, end, adu int }
	var spans []span
	for _, f := range frames {
		b := f.bytes()
		idx := -1
		if f.Raw == nil && !c.b.o.CountOnly {
			idx = len(c.b.truth.ADUs)
			c.b.truth.ADUs = append(c.b.truth.ADUs, ADU{Dir: d, TID: f.TID, Unit: f.Unit, PDU: append([]byte(nil), f.PDU...)})
		}
		spans = append(spans, span{len(data), len(data) + len(b), idx})
		data = append(data, b...)
	}
	// Cut into segments.
	type seg struct{ start, end int }
	var segs []seg
	for off, i := 0, 0; off < len(data); i++ {
		n := c.o.MSS
		switch {
		case o.OneByte:
			n = 1
		case i < len(o.Seg):
			n = o.Seg[i]
		}
		end := min(off+max(n, 1), len(data))
		segs = append(segs, seg{off, end})
		off = end
	}
	base := c.seq[d]
	if c.holeOpen[d] || !c.anchored[d] {
		// Reordering behind an unresolved loss, or before anything says
		// where the direction starts, has no single right reading; the
		// builder writes in order then.
		o.Reverse = false
	}
	order := make([]int, len(segs))
	for i := range segs {
		order[i] = i
		if o.Reverse {
			order[i] = len(segs) - 1 - i
		}
	}
	// A loss before anything anchors the direction is not a gap: the
	// capture of the stream just starts later, at capStart.
	unanchored, capStart := false, -1
	lostBytes := make([]bool, len(data))
	snapped := make([]bool, len(data))
	captured := 0
	for _, i := range order {
		s := segs[i]
		if has(o.Lose, i) {
			for k := s.start; k < s.end; k++ {
				lostBytes[k] = true
			}
			if c.anchored[d] {
				c.holeOpen[d], c.peerAcked[d], c.dataAfter[d] = true, false, false
			} else {
				unanchored = true
			}
			if c.anchored[d] {
				if c.lostRun[d] < 0 {
					c.lostRun[d] = 0
				}
				c.lostRun[d] += int64(s.end - s.start)
			}
			continue
		}
		if c.lostRun[d] >= 0 && !o.Reverse {
			c.endGap(d)
		}
		if unanchored && capStart < 0 {
			capStart = s.start
		}
		so := segOpts{frag: o.Fragment, snap: o.Snap}
		c.segment(d, base+uint32(s.start), 0x18, data[s.start:s.end], so)
		if o.Snap > 0 {
			for k := s.start + o.Snap; k < s.end; k++ {
				snapped[k] = true
			}
		}
		captured++
		c.anchored[d] = true
		c.sent[d] = true
		if c.holeOpen[d] {
			if c.peerAcked[d] {
				c.holeOpen[d] = false
			} else {
				c.dataAfter[d] = true
			}
		}
		if has(o.Duplicate, i) && s.end-s.start > 1 { // see the keepalive note below
			c.segment(d, base+uint32(s.start), 0x18, data[s.start:s.end], segOpts{iface: o.DupIface, override: true})
			c.b.truth.Retransmits++
		}
	}
	if o.Reverse && captured > 1 {
		c.b.truth.OutOfOrder += uint64(captured - 1) // held until the first segment filled the hole
	}
	for i, s := range segs {
		if s.end-s.start == 1 && s.end == len(data) {
			// A one-byte copy of the last byte is indistinguishable from a
			// keepalive probe; the builder does not write that ambiguity.
			continue
		}
		if has(o.Retransmit, i) && !has(o.Lose, i) {
			c.segment(d, base+uint32(s.start), 0x18, data[s.start:s.end], segOpts{})
			c.b.truth.Retransmits++
		}
		if has(o.Conflict, i) && !has(o.Lose, i) {
			bad := append([]byte(nil), data[s.start:s.end]...)
			bad[len(bad)-1] ^= 0xFF
			c.segment(d, base+uint32(s.start), 0x18, bad, segOpts{})
			c.b.truth.Retransmits++
			c.b.truth.Conflicts++
		}
	}
	c.seq[d] += uint32(len(data))
	// Fates of the ADUs.
	for _, sp := range spans {
		lost, cut, allCut := false, false, true
		for k := sp.start; k < sp.end; k++ {
			lost = lost || lostBytes[k]
			cut = cut || snapped[k]
			allCut = allCut && snapped[k]
		}
		if sp.adu < 0 {
			if lost {
				c.resync[d] = true
			}
			continue
		}
		a := &c.b.truth.ADUs[sp.adu]
		a.Conn = c.id
		switch {
		case lost && unanchored && (capStart < 0 || sp.end <= capStart):
			a.Lost = true // before the capture of the stream starts
		case lost:
			a.Lost = true
			c.resync[d] = true
		case allCut:
			// The snap length removed it entirely; its size is known, so
			// framing stays in sync.
			a.Lost = true
		case cut:
			a.Truncated = true
		default:
			a.Resynced = c.resync[d]
			c.resync[d] = false
		}
	}
}

func (c *Conn) endGap(d Dir) {
	c.b.truth.Gaps++
	c.b.truth.GapBytes += uint64(c.lostRun[d])
	c.lostRun[d] = -1
}

// Request writes one request ADU to the server.
func (c *Conn) Request(tid uint16, unit uint8, pdu []byte) {
	c.Write(ToServer, WriteOpts{}, Frame{TID: tid, Unit: unit, PDU: pdu})
}

// Response writes one response ADU to the client.
func (c *Conn) Response(tid uint16, unit uint8, pdu []byte) {
	c.Write(ToClient, WriteOpts{}, Frame{TID: tid, Unit: unit, PDU: pdu})
}

// Keepalive writes a keepalive probe (one old byte) in direction d. It is
// skipped where it would be ambiguous: before the direction sent captured
// data (it would start the stream) and after an unresolved loss (its byte
// would fill the hole).
func (c *Conn) Keepalive(d Dir) {
	if !c.sent[d] || c.lostRun[d] >= 0 || c.holeOpen[d] {
		return
	}
	c.segment(d, c.seq[d]-1, 0x10, []byte{0}, segOpts{})
	c.b.truth.Keepalives++
}

// Close ends the connection with FIN in both directions.
func (c *Conn) Close() {
	if c.closed {
		return
	}
	c.closed = true
	for _, d := range []Dir{ToServer, ToClient} {
		if c.lostRun[d] >= 0 {
			c.endGap(d)
		}
		c.segment(d, c.seq[d], 0x11, nil, segOpts{})
		c.seq[d]++
	}
	c.segment(ToServer, c.seq[0], 0x10, nil, segOpts{})
}

// Reset ends the connection with an RST from d.
func (c *Conn) Reset(d Dir) {
	if c.closed {
		return
	}
	c.closed = true
	if c.lostRun[d] >= 0 {
		c.endGap(d)
	}
	c.segment(d, c.seq[d], 0x14, nil, segOpts{})
}

// MustEndpoint parses ip:port and panics on error (for tests).
func MustEndpoint(s string) netip.AddrPort { return netip.MustParseAddrPort(s) }

// ConnContinue carries a connection over into b, a second file of the same
// trace (rotated captures): sequence numbers, roles and the clock continue.
func (b *Builder) ConnContinue(c *Conn) *Conn {
	n := *c
	n.b = b
	b.now = max(b.now, c.b.now)
	b.conns = max(b.conns, c.b.conns)
	return &n
}
