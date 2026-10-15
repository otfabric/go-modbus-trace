// SPDX-License-Identifier: MIT

// Package own is the spike's candidate for writing the reader, link parsing,
// reassembly and framing ourselves (internal/pcapio, internal/link,
// internal/flow, mbtcp in the target layout).
package own

import (
	"bufio"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// Packet is one record. Data is valid until the next call to Next.
type Packet struct {
	Frame   uint64 // 1-based, as Wireshark counts
	Offset  int64  // record start in the uncompressed stream
	Iface   uint32
	TimeNS  int64 // UTC nanoseconds; 0 when the block has no timestamp (SPB)
	HasTime bool
	CapLen  uint32
	OrigLen uint32
	Link    uint16
	Data    []byte
}

// Limits for hostile input.
const (
	MaxRecord = 256 << 10 // largest packet we accept
	MaxBlock  = 16 << 20  // largest pcapng block we skip over
)

// ErrFormat reports a stream that is neither pcap nor pcapng.
var ErrFormat = errors.New("not a pcap or pcapng file")

type iface struct {
	resol    byte
	link     uint16
	snap     uint32
	unitsSec uint64 // timestamp units per second
	offset   int64  // if_tsoffset, seconds
}

// Reader reads classic pcap and pcapng, plain or gzip.
type Reader struct {
	r       *bufio.Reader
	off     int64
	frame   uint64
	ng      bool
	bo      binary.ByteOrder
	nanos   bool
	link    uint16
	ifaces  []iface
	buf     []byte
	hdr     [32]byte // record header scratch; a local would escape through io.ReadFull
	Skipped int      // corrupt or oversized blocks skipped
	SPB     int      // simple packet blocks (no timestamp)
}

// NewReader detects the format from the first bytes.
func NewReader(r io.Reader) (*Reader, error) {
	br := bufio.NewReaderSize(r, 256<<10)
	head, err := br.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(br)
		if err != nil {
			return nil, err
		}
		return NewReader(zr)
	}
	rd := &Reader{r: br, buf: make([]byte, 64<<10)}
	switch m := binary.LittleEndian.Uint32(head); m {
	case 0xa1b2c3d4, 0xa1b23c4d:
		rd.bo = binary.LittleEndian
		rd.nanos = m == 0xa1b23c4d
	case 0xd4c3b2a1, 0x4d3cb2a1:
		rd.bo = binary.BigEndian
		rd.nanos = m == 0x4d3cb2a1
	case 0x0A0D0D0A:
		rd.ng = true
		return rd, nil
	default:
		return nil, fmt.Errorf("%w: first bytes % x", ErrFormat, head)
	}
	var h [24]byte
	if err := rd.read(h[:]); err != nil {
		return nil, err
	}
	rd.link = uint16(rd.bo.Uint32(h[20:]) & 0xFFFF)
	return rd, nil
}

func (rd *Reader) read(b []byte) error {
	n, err := io.ReadFull(rd.r, b)
	rd.off += int64(n)
	return err
}

func (rd *Reader) discard(n int) error {
	m, err := rd.r.Discard(n)
	rd.off += int64(m)
	return err
}

func (rd *Reader) data(n int) ([]byte, error) {
	if cap(rd.buf) < n {
		rd.buf = make([]byte, n)
	}
	b := rd.buf[:n]
	return b, rd.read(b)
}

// Next returns the next packet, or io.EOF.
func (rd *Reader) Next(p *Packet) error {
	if rd.ng {
		return rd.nextNG(p)
	}
	h := rd.hdr[:16]
	start := rd.off
	if err := rd.read(h); err != nil {
		if err == io.ErrUnexpectedEOF {
			return io.EOF // truncated last record: tolerated
		}
		return err
	}
	capLen, origLen := rd.bo.Uint32(h[8:]), rd.bo.Uint32(h[12:])
	if capLen > MaxRecord {
		return fmt.Errorf("corrupt record at offset %d: caplen %d", start, capLen)
	}
	d, err := rd.data(int(capLen))
	if err != nil {
		return io.EOF
	}
	rd.frame++
	sub := int64(rd.bo.Uint32(h[4:]))
	if !rd.nanos {
		sub *= 1000
	}
	*p = Packet{Frame: rd.frame, Offset: start, TimeNS: int64(rd.bo.Uint32(h[0:]))*1e9 + sub, HasTime: true,
		CapLen: capLen, OrigLen: origLen, Link: rd.link, Data: d}
	return nil
}

func (rd *Reader) nextNG(p *Packet) error {
	for {
		start := rd.off
		h := rd.hdr[:12]
		if err := rd.read(h[:8]); err != nil {
			if err == io.ErrUnexpectedEOF {
				return io.EOF
			}
			return err
		}
		typ := binary.LittleEndian.Uint32(h[0:])
		if typ == 0x0A0D0D0A {
			if err := rd.read(h[8:12]); err != nil {
				return io.EOF
			}
			switch binary.LittleEndian.Uint32(h[8:]) {
			case 0x1A2B3C4D:
				rd.bo = binary.LittleEndian
			case 0x4D3C2B1A:
				rd.bo = binary.BigEndian
			default:
				return fmt.Errorf("corrupt section header at offset %d", start)
			}
			rd.ifaces = rd.ifaces[:0]
			n := rd.bo.Uint32(h[4:])
			if n < 28 || n%4 != 0 || n > MaxBlock {
				return fmt.Errorf("corrupt section header at offset %d", start)
			}
			if err := rd.discard(int(n) - 12); err != nil {
				return io.EOF
			}
			continue
		}
		if rd.bo == nil {
			return fmt.Errorf("%w: no section header", ErrFormat)
		}
		typ = rd.bo.Uint32(h[0:])
		n := rd.bo.Uint32(h[4:])
		if n < 12 || n%4 != 0 || n > MaxBlock {
			return fmt.Errorf("corrupt block at offset %d (length %d)", start, n)
		}
		body, err := rd.data(int(n) - 8)
		if err != nil {
			return io.EOF
		}
		body = body[:len(body)-4]
		switch typ {
		case 1: // IDB
			if len(body) < 8 {
				rd.Skipped++
				continue
			}
			f := iface{link: rd.bo.Uint16(body[0:]), snap: rd.bo.Uint32(body[4:]), unitsSec: 1e6, resol: 6}
			rd.options(body[8:], func(code uint16, v []byte) {
				switch {
				case code == 9 && len(v) >= 1:
					f.resol = v[0]
					if v[0]&0x80 != 0 {
						f.unitsSec = 1 << (v[0] & 0x7F)
					} else if v[0] <= 19 {
						f.unitsSec = pow10(v[0])
					}
				case code == 14 && len(v) >= 8:
					f.offset = int64(rd.bo.Uint64(v))
				}
			})
			rd.ifaces = append(rd.ifaces, f)
		case 6: // EPB
			if len(body) < 20 {
				rd.Skipped++
				continue
			}
			id := rd.bo.Uint32(body[0:])
			capLen := rd.bo.Uint32(body[12:])
			if int(id) >= len(rd.ifaces) || capLen > MaxRecord || int(capLen) > len(body)-20 {
				rd.Skipped++
				continue
			}
			f := rd.ifaces[id]
			ts := uint64(rd.bo.Uint32(body[4:]))<<32 | uint64(rd.bo.Uint32(body[8:]))
			rd.frame++
			*p = Packet{Frame: rd.frame, Offset: start, Iface: id, TimeNS: tsNS(ts, f), HasTime: true,
				CapLen: capLen, OrigLen: rd.bo.Uint32(body[16:]), Link: f.link, Data: body[20 : 20+capLen]}
			return nil
		case 3: // SPB
			if len(rd.ifaces) == 0 || len(body) < 4 {
				rd.Skipped++
				continue
			}
			orig := rd.bo.Uint32(body[0:])
			capLen := min(uint32(len(body)-4), orig)
			if s := rd.ifaces[0].snap; s != 0 {
				capLen = min(capLen, s)
			}
			rd.frame++
			rd.SPB++
			*p = Packet{Frame: rd.frame, Offset: start, CapLen: capLen, OrigLen: orig, Link: rd.ifaces[0].link, Data: body[4 : 4+capLen]}
			return nil
		default: // ISB, NRB, DSB, custom, unknown: skipped (ISB is read in L1)
		}
	}
}

func (rd *Reader) options(b []byte, fn func(uint16, []byte)) {
	for len(b) >= 4 {
		code, n := rd.bo.Uint16(b), int(rd.bo.Uint16(b[2:]))
		if code == 0 || 4+n > len(b) {
			return
		}
		fn(code, b[4:4+n])
		b = b[min(len(b), 4+(n+3)&^3):]
	}
}

func pow10(e byte) uint64 {
	v := uint64(1)
	for range e {
		v *= 10
	}
	return v
}

func tsNS(ts uint64, f iface) int64 {
	sec := ts / f.unitsSec
	frac := ts % f.unitsSec
	var ns uint64
	if f.unitsSec <= 1e9 {
		ns = frac * (1e9 / f.unitsSec)
	} else {
		ns = frac / (f.unitsSec / 1e9)
	}
	return (int64(sec)+f.offset)*1e9 + int64(ns)
}

// Interfaces returns the interfaces seen so far (one for classic pcap).
func (rd *Reader) Interfaces() []Iface {
	if !rd.ng {
		r := byte(6)
		if rd.nanos {
			r = 9
		}
		return []Iface{{Link: rd.link, TSResol: r}}
	}
	out := make([]Iface, len(rd.ifaces))
	for i, f := range rd.ifaces {
		out[i] = Iface{Link: f.link, Snap: f.snap, TSResol: f.resol}
	}
	return out
}
