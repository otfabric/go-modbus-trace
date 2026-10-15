// SPDX-License-Identifier: MIT

// Package synth writes a deterministic synthetic Modbus/TCP trace for the L0
// spike: many client connections polling FC03, with handshakes, midstream
// starts, split headers, coalesced ADUs, one-byte segments, retransmissions,
// identical and conflicting overlaps, reordering, losses, duplicates from a
// second interface and sequence wraparound. It is streaming: a trace of any
// size is written without being held in memory. It also returns the ground
// truth the pipelines are compared with.
//
// This is spike code, not trace/tracetest; L1 rewrites the builder properly.
package synth

import (
	"bufio"
	"encoding/binary"
	"io"
	"time"
)

// Format of the output file.
type Format int

const (
	Pcap   Format = iota // classic pcap, microseconds, little endian, Ethernet
	PcapNG               // pcapng, if0 Ethernet tsresol 6, if1 raw IPv4 tsresol 9
)

// Options for a trace.
type Options struct {
	Format    Format
	Conns     int   // concurrent client connections
	TargetLen int64 // stop once the file reaches this many bytes
	Faults    bool  // inject faults
}

// Truth is what a correct pipeline must report.
type Truth struct {
	Packets     int64
	Bytes       int64
	ADUsSent    int64 // ADUs put on the wire (both directions)
	ADUsLost    int64 // ADUs whose segment was dropped (never captured)
	Gaps        int64 // directions in which a loss leaves a hole
	Retransmits int64 // segments that are fully old data (incl. duplicates)
	Conflicts   int64 // retransmits whose bytes differ from the original
	Midstream   int64 // connections without a handshake
}

type conn struct {
	cIP, sIP     [4]byte
	cPort        uint16
	cSeq, sSeq   uint32
	tid          uint16
	iface        int
	midstream    bool
	polls        int
	synSent      bool
	lastResponse []byte
}

const (
	serverPort = 502
	regs       = 125
)

type writer struct {
	w     *bufio.Writer
	opts  Options
	truth Truth
	t     time.Time
	n     int64
	buf   []byte
}

// Write writes the trace to w and returns the ground truth.
func Write(w io.Writer, opts Options) (Truth, error) {
	wr := &writer{w: bufio.NewWriterSize(w, 1<<20), opts: opts, t: time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)}
	wr.header()
	conns := make([]*conn, opts.Conns)
	for i := range conns {
		c := &conn{
			cIP:   [4]byte{10, 0, byte(i >> 8), byte(i)},
			sIP:   [4]byte{10, 1, 0, byte(1 + i%4)},
			cPort: uint16(40000 + i),
			cSeq:  uint32(i) * 2654435761,
			sSeq:  0xFFFFF000 + uint32(i)*7, // wraps after ~4 KiB of responses
		}
		if opts.Format == PcapNG {
			c.iface = i % 2
		}
		c.midstream = opts.Faults && i%8 == 1
		conns[i] = c
	}
	for round := 0; wr.n < opts.TargetLen; round++ {
		for _, c := range conns {
			if wr.n >= opts.TargetLen {
				break
			}
			wr.poll(c, round)
		}
	}
	for _, c := range conns {
		wr.fin(c)
	}
	return wr.truth, wr.w.Flush()
}

func (wr *writer) header() {
	b := make([]byte, 0, 128)
	switch wr.opts.Format {
	case Pcap:
		b = binary.LittleEndian.AppendUint32(b, 0xa1b2c3d4)
		b = binary.LittleEndian.AppendUint16(b, 2)
		b = binary.LittleEndian.AppendUint16(b, 4)
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint32(b, 0)
		b = binary.LittleEndian.AppendUint32(b, 65535)
		b = binary.LittleEndian.AppendUint32(b, 1)
	case PcapNG:
		// SHB with no options.
		b = binary.LittleEndian.AppendUint32(b, 0x0A0D0D0A)
		b = binary.LittleEndian.AppendUint32(b, 28)
		b = binary.LittleEndian.AppendUint32(b, 0x1A2B3C4D)
		b = binary.LittleEndian.AppendUint16(b, 1)
		b = binary.LittleEndian.AppendUint16(b, 0)
		b = binary.LittleEndian.AppendUint64(b, 0xFFFFFFFFFFFFFFFF)
		b = binary.LittleEndian.AppendUint32(b, 28)
		b = idb(b, 1, 6)
		b = idb(b, 101, 9)
	}
	wr.write(b)
}

func idb(b []byte, link uint16, tsresol byte) []byte {
	b = binary.LittleEndian.AppendUint32(b, 1)
	b = binary.LittleEndian.AppendUint32(b, 32)
	b = binary.LittleEndian.AppendUint16(b, link)
	b = binary.LittleEndian.AppendUint16(b, 0)
	b = binary.LittleEndian.AppendUint32(b, 65535)
	b = binary.LittleEndian.AppendUint16(b, 9) // if_tsresol
	b = binary.LittleEndian.AppendUint16(b, 1)
	b = append(b, tsresol, 0, 0, 0)
	b = binary.LittleEndian.AppendUint32(b, 0) // opt_endofopt
	return binary.LittleEndian.AppendUint32(b, 32)
}

func (wr *writer) write(b []byte) {
	n, _ := wr.w.Write(b)
	wr.n += int64(n)
}

const (
	fSYN = 0x02
	fACK = 0x10
	fPSH = 0x08
	fFIN = 0x01
)

// seg writes one TCP segment as a packet. fromClient picks the direction.
func (wr *writer) seg(c *conn, fromClient bool, seq uint32, flags byte, payload []byte) {
	wr.t = wr.t.Add(137 * time.Microsecond)
	src, dst, sp, dp := c.cIP, c.sIP, c.cPort, uint16(serverPort)
	ack := c.sSeq
	if !fromClient {
		src, dst, sp, dp = c.sIP, c.cIP, serverPort, c.cPort
		ack = c.cSeq
	}
	link := 1
	if c.iface == 1 {
		link = 101
	}
	b := wr.buf[:0]
	if link == 1 {
		b = append(b, 0, 1, 2, 3, 4, 5, 0, 1, 2, 3, 4, 6, 0x08, 0x00)
	}
	ipStart := len(b)
	total := 20 + 20 + len(payload)
	b = append(b, 0x45, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(total))
	b = append(b, 0, 0, 0x40, 0, 64, 6, 0, 0)
	b = append(b, src[:]...)
	b = append(b, dst[:]...)
	b = binary.BigEndian.AppendUint16(b, sp)
	b = binary.BigEndian.AppendUint16(b, dp)
	b = binary.BigEndian.AppendUint32(b, seq)
	b = binary.BigEndian.AppendUint32(b, ack)
	b = append(b, 5<<4, flags|fACK*boolByte(flags&fSYN == 0))
	b = append(b, 0xFF, 0xFF, 0, 0, 0, 0)
	b = append(b, payload...)
	_ = ipStart
	if link == 1 && len(b) < 60 {
		b = append(b, make([]byte, 60-len(b))...) // Ethernet padding must not become data
	}
	wr.buf = b
	wr.record(c.iface, b)
}

func boolByte(v bool) byte {
	if v {
		return 1
	}
	return 0
}

func (wr *writer) record(iface int, data []byte) {
	wr.truth.Packets++
	wr.truth.Bytes += int64(len(data))
	var h [32]byte
	switch wr.opts.Format {
	case Pcap:
		us := wr.t.UnixMicro()
		binary.LittleEndian.PutUint32(h[0:], uint32(us/1e6))
		binary.LittleEndian.PutUint32(h[4:], uint32(us%1e6))
		binary.LittleEndian.PutUint32(h[8:], uint32(len(data)))
		binary.LittleEndian.PutUint32(h[12:], uint32(len(data)))
		wr.write(h[:16])
		wr.write(data)
	case PcapNG:
		ts := uint64(wr.t.UnixMicro())
		if iface == 1 {
			ts = uint64(wr.t.UnixNano())
		}
		pad := (4 - len(data)%4) % 4
		total := 32 + len(data) + pad
		binary.LittleEndian.PutUint32(h[0:], 6)
		binary.LittleEndian.PutUint32(h[4:], uint32(total))
		binary.LittleEndian.PutUint32(h[8:], uint32(iface))
		binary.LittleEndian.PutUint32(h[12:], uint32(ts>>32))
		binary.LittleEndian.PutUint32(h[16:], uint32(ts))
		binary.LittleEndian.PutUint32(h[20:], uint32(len(data)))
		binary.LittleEndian.PutUint32(h[24:], uint32(len(data)))
		wr.write(h[:28])
		wr.write(data)
		var tail [8]byte
		binary.LittleEndian.PutUint32(tail[pad:], uint32(total))
		wr.write(tail[:pad+4])
	}
}

func (wr *writer) handshake(c *conn) {
	wr.seg(c, true, c.cSeq-1, fSYN, nil)
	wr.seg(c, false, c.sSeq-1, fSYN|fACK, nil)
	wr.seg(c, true, c.cSeq, 0, nil)
}

func (wr *writer) fin(c *conn) {
	if !c.synSent && !c.midstream {
		return
	}
	wr.seg(c, true, c.cSeq, fFIN, nil)
	wr.seg(c, false, c.sSeq, fFIN, nil)
}

func adu(tid uint16, pdu []byte) []byte {
	b := make([]byte, 0, 7+len(pdu))
	b = binary.BigEndian.AppendUint16(b, tid)
	b = append(b, 0, 0)
	b = binary.BigEndian.AppendUint16(b, uint16(1+len(pdu)))
	b = append(b, 1)
	return append(b, pdu...)
}

// poll writes one request/response pair, with the fault scheduled for this
// connection and round.
func (wr *writer) poll(c *conn, round int) {
	if !c.synSent {
		c.synSent = true
		if !c.midstream {
			wr.handshake(c)
		} else {
			wr.truth.Midstream++
		}
	}
	c.tid++
	c.polls++
	start := uint16(0x1000 + (round%4)*regs)
	req := adu(c.tid, []byte{3, byte(start >> 8), byte(start), 0, regs})
	pdu := make([]byte, 2+2*regs)
	pdu[0], pdu[1] = 3, 2*regs
	for i := 0; i < regs; i++ {
		binary.BigEndian.PutUint16(pdu[2+2*i:], uint16(round+i))
	}
	resp := adu(c.tid, pdu)
	wr.truth.ADUsSent += 2

	fault := -1
	if wr.opts.Faults {
		fault = (c.polls*7 + int(c.cPort)) % 97
	}
	switch fault {
	case 0: // request in one-byte segments
		for i := range req {
			wr.seg(c, true, c.cSeq+uint32(i), fPSH, req[i:i+1])
		}
	case 1: // request retransmitted (identical)
		wr.seg(c, true, c.cSeq, fPSH, req)
		wr.seg(c, true, c.cSeq, fPSH, req)
		wr.truth.Retransmits++
	default:
		wr.seg(c, true, c.cSeq, fPSH, req)
	}
	c.cSeq += uint32(len(req))

	switch fault {
	case 2: // MBAP header split over two segments
		wr.seg(c, false, c.sSeq, 0, resp[:4])
		wr.seg(c, false, c.sSeq+4, fPSH, resp[4:])
	case 3: // out of order: second half first
		h := len(resp) / 2
		wr.seg(c, false, c.sSeq+uint32(h), fPSH, resp[h:])
		wr.seg(c, false, c.sSeq, 0, resp[:h])
	case 4: // loss: the response segment is never captured
		wr.truth.ADUsLost++
		wr.truth.Gaps++
	case 5: // duplicate observation on the other interface (pcapng) or a retransmission
		wr.seg(c, false, c.sSeq, fPSH, resp)
		if wr.opts.Format == PcapNG {
			c.iface ^= 1
			wr.seg(c, false, c.sSeq, fPSH, resp)
			c.iface ^= 1
		} else {
			wr.seg(c, false, c.sSeq, fPSH, resp)
		}
		wr.truth.Retransmits++
	case 7: // pipelining: a second request, then both responses coalesced into one segment
		c.tid++
		req2 := adu(c.tid, req[7:])
		resp2 := adu(c.tid, pdu)
		wr.seg(c, true, c.cSeq, fPSH, req2)
		c.cSeq += uint32(len(req2))
		wr.seg(c, false, c.sSeq, fPSH, append(append([]byte(nil), resp...), resp2...))
		c.sSeq += uint32(len(resp2))
		wr.truth.ADUsSent += 2
	case 6: // conflicting overlap: a retransmission with different bytes
		wr.seg(c, false, c.sSeq, fPSH, resp)
		bad := append([]byte(nil), resp...)
		bad[len(bad)-1] ^= 0xFF
		wr.seg(c, false, c.sSeq, fPSH, bad)
		wr.truth.Retransmits++
		wr.truth.Conflicts++
	default:
		wr.seg(c, false, c.sSeq, fPSH, resp)
	}
	c.sSeq += uint32(len(resp))
	c.lastResponse = resp
}
