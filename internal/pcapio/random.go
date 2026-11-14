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
var ErrNotSeekable = errors.New("trace: random access needs an uncompressed trace file")

// Index is what random access needs to re-read one record: the byte order
// and interfaces of every section. Build it once per file. It is not changed
// after NewIndex, so ReadAt is safe for concurrent use.
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

// NewIndex reads what random access needs from a file. For pcapng it is one
// pass of the sequential reader itself over the file, bounded by opts, so
// the index holds exactly the sections and interfaces a pass sees: a block
// the reader skips (a damaged one, or one past a limit) is not in the index
// either, and a packet read back by its offset has the interface, link type
// and time the pass gave it. Where the reader stops (damage, a cut-short
// tail), the index stops: it covers what came before.
func NewIndex(r io.ReaderAt, size int64, opts Options) (*Index, error) {
	var h [24]byte
	if _, err := r.ReadAt(h[:4], 0); err != nil {
		return nil, fmt.Errorf("%w: %w", ErrFormat, err)
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
	rd, err := newReader(&countingReader{r: io.NewSectionReader(r, 0, size)}, opts)
	if err != nil {
		return nil, err
	}
	rd.ix = ix
	var p Packet
	for {
		if err := rd.Next(&p); err != nil {
			if errors.Is(err, ErrFormat) {
				return nil, err // no section header at the start
			}
			break
		}
	}
	// Only what ReadAt reads: the reader's table also counts packets.
	ix.ifaces = make([]Interface, len(rd.ifaces))
	for i, f := range rd.ifaces {
		ix.ifaces[i] = Interface{Section: f.Section, LinkType: f.LinkType, SnapLen: f.SnapLen, TSResol: f.TSResol, TSOffset: f.TSOffset}
	}
	return ix, nil
}

// ReadAt reads the packet record or block that starts at off. The
// returned packet has no frame number; Data is newly allocated. A packet
// may be as large as a block (DefaultMaxBlock): the pass that found the
// offset already applied its own MaxPacket.
func (ix *Index) ReadAt(r io.ReaderAt, off int64) (Packet, error) {
	if ix.format == Pcap {
		var h [16]byte
		if _, err := r.ReadAt(h[:], off); err != nil {
			return Packet{}, err
		}
		capLen := ix.bo.Uint32(h[8:])
		if capLen > DefaultMaxBlock {
			return Packet{}, fmt.Errorf("%w: record at offset %d", ErrCorrupt, off)
		}
		data := make([]byte, capLen)
		if capLen > 0 { // an empty record has nothing to read, also at the very end of the file
			if _, err := r.ReadAt(data, off+16); err != nil {
				return Packet{}, err
			}
		}
		sub := int64(ix.bo.Uint32(h[4:]))
		if (ix.nanos && sub >= 1e9) || (!ix.nanos && sub >= 1e6) {
			return Packet{}, fmt.Errorf("%w: record at offset %d has a sub-second part of %d", ErrCorrupt, off, sub)
		}
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
	if n < 12 || n%4 != 0 || n > DefaultMaxBlock {
		return Packet{}, fmt.Errorf("%w: block at offset %d", ErrCorrupt, off)
	}
	block := make([]byte, n-8)
	if _, err := r.ReadAt(block, off+8); err != nil {
		return Packet{}, err
	}
	// The same decoders as the sequential reader, on the same table: the
	// table is only read, so calls do not disturb each other.
	var p Packet
	ok := sec.bo.Uint32(block[len(block)-4:]) == n // as the reader: the trailing length agrees
	body := block[:len(block)-4]
	switch {
	case !ok:
	case typ == blockEPB || typ == blockPB:
		ok = epbAt(sec.bo, ix.ifaces, sec.base, DefaultMaxBlock, typ, off, body, &p)
	case typ == blockSPB:
		ok = spbAt(sec.bo, ix.ifaces, sec.base, DefaultMaxBlock, off, body, &p)
	default:
		ok = false
	}
	if !ok {
		return Packet{}, fmt.Errorf("%w: no packet at offset %d", ErrCorrupt, off)
	}
	return p, nil
}
