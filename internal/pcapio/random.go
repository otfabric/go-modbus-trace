// SPDX-License-Identifier: MIT

package pcapio

import (
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"sort"
)

// ErrNotSeekable reports random access to a compressed file.
var ErrNotSeekable = errors.New("random access needs an uncompressed file")

// Index is what random access needs to re-read one record: the byte order
// and interfaces of every section. Build it once per file.
type Index struct {
	format   Format
	bo       binary.ByteOrder
	nanos    bool
	link     uint16
	sections []sectionAt
	ifaces   []Interface
}

type sectionAt struct {
	off  int64
	bo   binary.ByteOrder
	base int // index of the section's first interface
}

// NewIndex reads the headers of a file: for pcapng it walks the block
// headers and reads the interface descriptions, skipping the packets.
func NewIndex(r io.ReaderAt, size int64) (*Index, error) {
	var h [24]byte
	if _, err := r.ReadAt(h[:4], 0); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFormat, err)
	}
	if h[0] == 0x1f && h[1] == 0x8b {
		return nil, ErrNotSeekable
	}
	ix := &Index{}
	switch m := binary.LittleEndian.Uint32(h[:]); m {
	case 0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, 0x4d3cb2a1:
		if _, err := r.ReadAt(h[:], 0); err != nil {
			return nil, fmt.Errorf("%w: header cut short", ErrFormat)
		}
		ix.format, ix.bo = Pcap, binary.LittleEndian
		if m == 0xd4c3b2a1 || m == 0x4d3cb2a1 {
			ix.bo = binary.BigEndian
		}
		ix.nanos = m == 0xa1b23c4d || m == 0x4d3cb2a1
		ix.link = uint16(ix.bo.Uint32(h[20:]))
		return ix, nil
	case 0x0A0D0D0A:
		ix.format = PcapNG
	default:
		return nil, fmt.Errorf("%w: first bytes % x", ErrFormat, h[:4])
	}
	var bo binary.ByteOrder
	for off := int64(0); off+12 <= size; {
		var b [12]byte
		if n, _ := r.ReadAt(b[:], off); n < len(b) {
			break // a cut-short tail: index what came before
		}
		typ := binary.LittleEndian.Uint32(b[:])
		if typ == blockSHB {
			switch binary.LittleEndian.Uint32(b[8:]) {
			case 0x1A2B3C4D:
				bo = binary.LittleEndian
			case 0x4D3C2B1A:
				bo = binary.BigEndian
			default:
				return ix, nil // damaged: index what came before
			}
			ix.sections = append(ix.sections, sectionAt{off: off, bo: bo, base: len(ix.ifaces)})
		} else if bo == nil {
			return nil, fmt.Errorf("%w: no section header", ErrFormat)
		}
		n := int64(bo.Uint32(b[4:]))
		if n < 12 || n%4 != 0 || n > DefaultMaxBlock {
			return ix, nil
		}
		if bo.Uint32(b[:]) == blockIDB {
			body := make([]byte, n-12)
			if _, err := r.ReadAt(body, off+8); err == nil && len(body) >= 8 {
				f := Interface{Section: len(ix.sections) - 1, LinkType: bo.Uint16(body), SnapLen: bo.Uint32(body[4:]), TSResol: 6}
				rd := &Reader{bo: bo}
				rd.options(body[8:], func(code uint16, v []byte) {
					switch {
					case code == 9 && len(v) >= 1:
						if _, ok := unitsPerSecond(v[0]); ok {
							f.TSResol = v[0]
						}
					case code == 14 && len(v) >= 8:
						f.TSOffset = int64(bo.Uint64(v))
					}
				})
				ix.ifaces = append(ix.ifaces, f)
			}
		}
		off += n
	}
	return ix, nil
}

// ReadAt reads the packet record or block that starts at off. The
// returned packet has no frame number; Data is newly allocated.
func (ix *Index) ReadAt(r io.ReaderAt, off int64) (Packet, error) {
	if ix.format == Pcap {
		var h [16]byte
		if _, err := r.ReadAt(h[:], off); err != nil {
			return Packet{}, err
		}
		capLen := ix.bo.Uint32(h[8:])
		if capLen > DefaultMaxPacket {
			return Packet{}, fmt.Errorf("%w: record at offset %d", ErrCorrupt, off)
		}
		data := make([]byte, capLen)
		if _, err := r.ReadAt(data, off+16); err != nil {
			return Packet{}, err
		}
		sub := int64(ix.bo.Uint32(h[4:]))
		if !ix.nanos {
			sub *= 1000
		}
		return Packet{Offset: off, TimeNS: int64(ix.bo.Uint32(h[0:]))*1e9 + sub, HasTime: true, CapLen: capLen,
			OrigLen: max(ix.bo.Uint32(h[12:]), capLen), LinkType: ix.link, Data: data}, nil
	}
	i := sort.Search(len(ix.sections), func(i int) bool { return ix.sections[i].off > off }) - 1
	if i < 0 {
		return Packet{}, fmt.Errorf("%w: offset %d is before the first section", ErrCorrupt, off)
	}
	sec := ix.sections[i]
	var h [8]byte
	if _, err := r.ReadAt(h[:], off); err != nil {
		return Packet{}, err
	}
	typ, n := sec.bo.Uint32(h[:]), sec.bo.Uint32(h[4:])
	if n < 12 || n > DefaultMaxBlock {
		return Packet{}, fmt.Errorf("%w: block at offset %d", ErrCorrupt, off)
	}
	body := make([]byte, n-12)
	if _, err := r.ReadAt(body, off+8); err != nil {
		return Packet{}, err
	}
	// A copy of the interfaces: the reader counts packets in them, and
	// ReadAt must be safe for concurrent use.
	rd := &Reader{bo: sec.bo, ifaces: append([]Interface(nil), ix.ifaces...), secBase: sec.base, opts: Options{MaxPacket: DefaultMaxPacket}}
	var p Packet
	ok := false
	switch typ {
	case blockEPB, blockPB:
		ok = rd.epb(typ, off, body, &p)
	case blockSPB:
		ok = rd.spb(off, body, &p)
	}
	if !ok {
		return Packet{}, fmt.Errorf("%w: no packet at offset %d", ErrCorrupt, off)
	}
	return p, nil
}
