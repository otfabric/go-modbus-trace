// SPDX-License-Identifier: MIT

// Package pcapio reads classic pcap and pcapng files, plain or gzip, from a
// file or a stream, and writes them. Every record carries its frame number
// and its offset in the uncompressed stream, so that a packet can be found
// again. The reader treats its input as hostile: every length is bounded,
// and a damaged pcapng block with a plausible length is skipped and counted.
// The interfaces, sections and option text kept from one input are limited,
// so what the reader holds does not grow with the size of the input.
package pcapio

import (
	"bufio"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"hash"
	"io"
	"math"
	"math/bits"
)

// Format is a trace file format.
type Format int

// Formats.
const (
	Pcap Format = iota + 1
	PcapNG
)

// String returns "pcap" or "pcapng".
func (f Format) String() string {
	switch f {
	case Pcap:
		return "pcap"
	case PcapNG:
		return "pcapng"
	default:
		return "unknown"
	}
}

// Errors.
var (
	// ErrFormat reports a stream that is neither pcap nor pcapng.
	ErrFormat = errors.New("trace: not a pcap or pcapng file")
	// ErrCorrupt reports damage that ends the read; the packets read so
	// far are valid.
	ErrCorrupt = errors.New("trace: corrupt trace file")
)

// Default bounds.
const (
	DefaultMaxPacket = 256 << 10 // largest captured packet accepted
	DefaultMaxBlock  = 16 << 20  // largest pcapng block skipped over
	// DefaultMaxInterfaces is the number of interfaces kept from one input,
	// over all its sections. Captures have a handful per section; a file
	// merged from thousands of captures stays below it.
	DefaultMaxInterfaces = 65536
	// DefaultMaxSections is the number of pcapng sections read from one
	// input. A capture has one; files joined end to end have one each
	// (hourly files of seven years are 61,000).
	DefaultMaxSections = 65536
	// DefaultMaxText is the number of bytes of interface and section option
	// text (names, descriptions, comments) kept from one input: 250 bytes
	// for each of the interfaces and sections above.
	DefaultMaxText = 16 << 20
	maxOptions     = 64 << 10 // largest options area that is parsed
)

// Packet is one packet record. Data is valid until the next call to Next.
type Packet struct {
	Frame    uint64 // 1-based over all packet records, as Wireshark numbers frames
	Part     uint16 // index of the input file (set by the caller; the reader reads one)
	Offset   int64  // start of the record or block in the uncompressed stream
	Iface    uint32 // index into Interfaces (all sections); 0 for classic pcap
	TimeNS   int64  // capture time, UTC nanoseconds since the Unix epoch
	HasTime  bool   // false for a pcapng Simple Packet Block
	CapLen   uint32
	OrigLen  uint32
	LinkType uint16
	Data     []byte
}

// Truncated reports whether the snap length cut the packet.
func (p *Packet) Truncated() bool { return p.CapLen < p.OrigLen }

// Interface describes a capture interface. Classic pcap has one.
type Interface struct {
	Section     int    // pcapng section number, 0-based
	LinkType    uint16 // LINKTYPE_ value
	SnapLen     uint32 // 0: unlimited
	TSResol     byte   // pcapng if_tsresol (6 = µs, 9 = ns; bit 7 set: power of 2)
	TSOffset    int64  // if_tsoffset, seconds
	Name        string
	Description string
	OS          string
	Packets     uint64 // packets read on this interface
	Stats       *InterfaceStats
}

// InterfaceStats is the last Interface Statistics Block of an interface.
// A nil field was not present.
type InterfaceStats struct {
	TimeNS       int64
	IfRecv       *uint64
	IfDrop       *uint64
	FilterAccept *uint64
	OSDrop       *uint64
	UsrDeliv     *uint64
}

// Section is the metadata of a pcapng Section Header Block.
type Section struct {
	BigEndian   bool
	Application string
	OS          string
	Hardware    string
	Comment     string
}

// Counters report what the reader skipped or tolerated.
type Counters struct {
	SimplePackets  uint64 // packets without a timestamp (SPB)
	SkippedBlocks  uint64 // damaged blocks with a plausible length, skipped
	UnknownBlocks  uint64 // block types that are not read (NRB, DSB, custom, ...)
	ObsoletePacket uint64 // obsolete Packet Blocks (type 2), read like EPB
	OtherFrames    uint64 // custom and systemd journal blocks: not packets, but Wireshark numbers them as frames
	BadOptions     uint64 // option areas that did not parse (ignored), and text options not kept (Options.MaxText)
	BadTimestamps  uint64 // packets whose time does not fit in 64-bit nanoseconds: read without a time
	TruncatedTail  bool   // the last record or block was cut short
}

// Options bound the reader.
type Options struct {
	MaxPacket     int // default DefaultMaxPacket
	MaxBlock      int // default DefaultMaxBlock
	MaxInterfaces int // default DefaultMaxInterfaces
	MaxSections   int // default DefaultMaxSections
	MaxText       int // default DefaultMaxText
}

func (o Options) withDefaults() Options {
	if o.MaxPacket <= 0 {
		o.MaxPacket = DefaultMaxPacket
	}
	if o.MaxBlock <= 0 {
		o.MaxBlock = DefaultMaxBlock
	}
	if o.MaxInterfaces <= 0 {
		o.MaxInterfaces = DefaultMaxInterfaces
	}
	if o.MaxSections <= 0 {
		o.MaxSections = DefaultMaxSections
	}
	if o.MaxText <= 0 {
		o.MaxText = DefaultMaxText
	}
	return o
}

// Reader reads one trace stream.
type Reader struct {
	src      *countingReader
	r        *bufio.Reader
	off      int64
	frame    uint64
	format   Format
	gzip     bool
	bo       binary.ByteOrder
	nanos    bool
	ifaces   []Interface
	secBase  int // index of the current section's first interface
	sections []Section
	c        Counters
	opts     Options
	maxPkt   uint32 // opts.MaxPacket as a capture length
	maxBlk   uint32 // opts.MaxBlock as a block length
	text     int    // bytes of option text kept so far
	ix       *Index // set while the reader builds an index: where each section starts
	buf      []byte
	hdr      [32]byte
	done     bool
}

type countingReader struct {
	r io.Reader
	h hash.Hash // nil: the input is not hashed
	n int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	n, err := c.r.Read(p)
	if c.h != nil {
		c.h.Write(p[:n])
	}
	c.n += int64(n)
	return n, err
}

// setLimits converts the limits of opts to the 32-bit lengths of a capture.
// A limit above the largest 32-bit length limits nothing, so it becomes that
// length instead of wrapping around.
func (rd *Reader) setLimits() {
	rd.maxPkt, rd.maxBlk = lengthLimit(rd.opts.MaxPacket), lengthLimit(rd.opts.MaxBlock)
}

func lengthLimit(n int) uint32 {
	if n <= 0 {
		return 0
	}
	if uint64(n) > math.MaxUint32 {
		return math.MaxUint32
	}
	return uint32(n)
}

// NewReader detects the format from the first bytes, never from a name.
func NewReader(r io.Reader, opts Options) (*Reader, error) {
	return newReader(&countingReader{r: r, h: sha256.New()}, opts)
}

func newReader(src *countingReader, opts Options) (*Reader, error) {
	opts = opts.withDefaults()
	rd := &Reader{src: src, r: bufio.NewReaderSize(src, 256<<10), opts: opts, buf: make([]byte, 64<<10)}
	rd.setLimits()
	head, err := rd.r.Peek(4)
	if err != nil {
		return nil, fmt.Errorf("%w: %d bytes", ErrFormat, len(head))
	}
	if head[0] == 0x1f && head[1] == 0x8b {
		zr, err := gzip.NewReader(rd.r)
		if err != nil {
			return nil, fmt.Errorf("gzip: %w", err)
		}
		zr.Multistream(true)
		rd.r = bufio.NewReaderSize(zr, 256<<10)
		rd.gzip = true
		if head, err = rd.r.Peek(4); err != nil {
			return nil, fmt.Errorf("%w: gzip stream with %d bytes", ErrFormat, len(head))
		}
	}
	switch m := binary.LittleEndian.Uint32(head); m {
	case 0xa1b2c3d4, 0xa1b23c4d, 0xd4c3b2a1, 0x4d3cb2a1:
		rd.format = Pcap
		if err := rd.pcapHeader(); err != nil {
			return nil, err
		}
	case 0x0A0D0D0A:
		rd.format = PcapNG
	default:
		return nil, fmt.Errorf("%w: first bytes % x", ErrFormat, head)
	}
	return rd, nil
}

// Format returns the detected format.
func (rd *Reader) Format() Format { return rd.format }

// Gzip reports whether the stream was gzip-compressed.
func (rd *Reader) Gzip() bool { return rd.gzip }

// Interfaces returns the interfaces seen so far, over all sections.
func (rd *Reader) Interfaces() []Interface { return rd.ifaces }

// Sections returns the pcapng sections seen so far.
func (rd *Reader) Sections() []Section { return rd.sections }

// Counters returns what the reader skipped or tolerated so far.
func (rd *Reader) Counters() Counters { return rd.c }

// SHA256 returns the hash of the raw input (compressed bytes for gzip).
// After Next returned io.EOF it covers the whole input.
func (rd *Reader) SHA256() [32]byte {
	var s [32]byte
	if rd.src.h != nil {
		copy(s[:], rd.src.h.Sum(nil))
	}
	return s
}

// InputBytes returns the number of raw input bytes consumed so far.
func (rd *Reader) InputBytes() int64 { return rd.src.n }

func (rd *Reader) read(b []byte) error {
	n, err := io.ReadFull(rd.r, b)
	rd.off += int64(n)
	return err
}

func (rd *Reader) data(n int) ([]byte, error) {
	if cap(rd.buf) < n {
		rd.buf = make([]byte, n)
	}
	b := rd.buf[:n]
	return b, rd.read(b)
}

// eof ends the read at the end of the input: it drains what is left so
// that the hash covers the whole input.
func (rd *Reader) eof(truncated bool) error {
	if truncated {
		rd.c.TruncatedTail = true
	}
	if !rd.done {
		rd.done = true
		if _, err := io.Copy(io.Discard, rd.src); err != nil {
			rd.c.TruncatedTail = true // the hash then covers only what was read
		}
	}
	return io.EOF
}

// ended ends the read after a read of the record or block that starts at
// offset start failed with err. The end of the input is the end of the
// trace: clean (io.EOF) between two records or blocks, a cut-short tail
// inside one (also io.ErrUnexpectedEOF: a gzip stream that stops before its
// trailer). Any other error means the input could not be read as stored (a
// gzip checksum or length that does not match, damaged compressed data, a
// failing device): the read ends with an error wrapping ErrCorrupt and the
// cause, and what was read before stands.
func (rd *Reader) ended(err error, start int64) error {
	inside := rd.off > start
	if errors.Is(err, io.EOF) || errors.Is(err, io.ErrUnexpectedEOF) {
		return rd.eof(inside || errors.Is(err, io.ErrUnexpectedEOF))
	}
	rd.done = true
	if inside {
		rd.c.TruncatedTail = true
	}
	return fmt.Errorf("%w: reading at offset %d: %w", ErrCorrupt, rd.off, err)
}

func (rd *Reader) pcapHeader() error {
	h := rd.hdr[:24]
	if err := rd.read(h); err != nil {
		return fmt.Errorf("%w: pcap header cut short", ErrFormat)
	}
	switch binary.LittleEndian.Uint32(h) {
	case 0xa1b2c3d4:
		rd.bo = binary.LittleEndian
	case 0xa1b23c4d:
		rd.bo, rd.nanos = binary.LittleEndian, true
	case 0xd4c3b2a1:
		rd.bo = binary.BigEndian
	case 0x4d3cb2a1:
		rd.bo, rd.nanos = binary.BigEndian, true
	}
	resol := byte(6)
	if rd.nanos {
		resol = 9
	}
	// The link type is the low 16 bits; the upper bits carry the FCS length
	// and are ignored.
	rd.ifaces = []Interface{{LinkType: uint16(rd.bo.Uint32(h[20:])), SnapLen: rd.bo.Uint32(h[16:]), TSResol: resol}}
	return nil
}

// Next reads the next packet into p. It returns io.EOF at the end (also
// after a cut-short last record, see Counters), and an error wrapping
// ErrCorrupt when the file is damaged beyond what can be skipped.
func (rd *Reader) Next(p *Packet) error {
	if rd.done {
		return io.EOF
	}
	if rd.format == PcapNG {
		return rd.nextNG(p)
	}
	h := rd.hdr[:16]
	start := rd.off
	if err := rd.read(h); err != nil {
		return rd.ended(err, start)
	}
	capLen, origLen := rd.bo.Uint32(h[8:]), rd.bo.Uint32(h[12:])
	if capLen > rd.maxPkt {
		rd.done = true
		return fmt.Errorf("%w: record at offset %d has a captured length of %d bytes", ErrCorrupt, start, capLen)
	}
	d, err := rd.data(int(capLen))
	if err != nil {
		return rd.ended(err, start)
	}
	sub := int64(rd.bo.Uint32(h[4:]))
	if !rd.nanos {
		sub *= 1000
	}
	if sub >= 1e9 {
		rd.done = true
		return fmt.Errorf("%w: record at offset %d has a sub-second part of %d", ErrCorrupt, start, sub)
	}
	rd.frame++
	rd.ifaces[0].Packets++
	*p = Packet{Frame: rd.frame, Offset: start, TimeNS: int64(rd.bo.Uint32(h[0:]))*1e9 + sub, HasTime: true,
		CapLen: capLen, OrigLen: max(origLen, capLen), LinkType: rd.ifaces[0].LinkType, Data: d}
	return nil
}

// pcapng block types.
const (
	blockSHB = 0x0A0D0D0A
	blockIDB = 1
	blockPB  = 2
	blockSPB = 3
	blockNRB = 4
	blockISB = 5
	blockEPB = 6
	blockSJE = 9          // systemd Journal Export
	blockCB  = 0x0BAD     // Custom Block, may be copied
	blockCBN = 0x40000BAD // Custom Block, must not be copied
)

func (rd *Reader) nextNG(p *Packet) error {
	for {
		start := rd.off
		h := rd.hdr[:12]
		if err := rd.read(h[:8]); err != nil {
			return rd.ended(err, start)
		}
		if binary.LittleEndian.Uint32(h) == blockSHB {
			if err := rd.section(start, h); err != nil {
				return err
			}
			continue
		}
		if rd.bo == nil {
			rd.done = true
			return fmt.Errorf("%w: no section header before offset %d", ErrFormat, start)
		}
		typ, n := rd.bo.Uint32(h[0:]), rd.bo.Uint32(h[4:])
		if n < 12 || n%4 != 0 || n > rd.maxBlk {
			rd.done = true
			return fmt.Errorf("%w: block at offset %d has a length of %d", ErrCorrupt, start, n)
		}
		block, err := rd.data(int(n) - 8)
		if err != nil {
			return rd.ended(err, start)
		}
		if rd.bo.Uint32(block[len(block)-4:]) != n {
			rd.c.SkippedBlocks++ // the trailing length disagrees: damaged
			continue
		}
		body := block[:len(block)-4]
		switch typ {
		case blockIDB:
			rd.idb(body)
		case blockEPB, blockPB:
			if ok := rd.epb(typ, start, body, p); ok {
				return nil
			}
		case blockSPB:
			if ok := rd.spb(start, body, p); ok {
				return nil
			}
		case blockISB:
			rd.isb(body)
		case blockSJE, blockCB, blockCBN:
			// Not packets, but Wireshark (4.6) numbers them as frames; count
			// them so that frame numbers stay the same as Wireshark's.
			rd.frame++
			rd.c.OtherFrames++
		default:
			rd.c.UnknownBlocks++
		}
	}
}

func (rd *Reader) section(start int64, h []byte) error {
	if err := rd.read(h[8:12]); err != nil {
		return rd.ended(err, start)
	}
	var bo binary.ByteOrder
	switch binary.LittleEndian.Uint32(h[8:]) {
	case 0x1A2B3C4D:
		bo = binary.LittleEndian
	case 0x4D3C2B1A:
		bo = binary.BigEndian
	default:
		rd.done = true
		return fmt.Errorf("%w: section header at offset %d has no byte-order magic", ErrCorrupt, start)
	}
	n := bo.Uint32(h[4:])
	if n < 28 || n%4 != 0 || n > rd.maxBlk {
		rd.done = true
		return fmt.Errorf("%w: section header at offset %d has a length of %d", ErrCorrupt, start, n)
	}
	if len(rd.sections) >= rd.opts.MaxSections {
		rd.done = true
		return fmt.Errorf("%w: section header at offset %d: more than %d sections", ErrCorrupt, start, rd.opts.MaxSections)
	}
	block, err := rd.data(int(n) - 12)
	if err != nil {
		return rd.ended(err, start)
	}
	rd.bo = bo
	rd.secBase = len(rd.ifaces)
	if rd.ix != nil {
		rd.ix.sections = append(rd.ix.sections, sectionAt{off: start, bo: bo, base: rd.secBase})
	}
	s := Section{BigEndian: bo == binary.BigEndian}
	if bo.Uint32(block[len(block)-4:]) == n {
		// version (4) and section length (8) precede the options
		rd.options(block[12:len(block)-4], func(code uint16, v []byte) {
			switch code {
			case 1:
				s.Comment = rd.keep(v)
			case 2:
				s.Hardware = rd.keep(v)
			case 3:
				s.OS = rd.keep(v)
			case 4:
				s.Application = rd.keep(v)
			}
		})
	} else {
		rd.c.SkippedBlocks++
	}
	rd.sections = append(rd.sections, s)
	return nil
}

// keep returns option text as a string to keep, within Options.MaxText over
// the whole input; text past the limit is left out and counted. An index
// keeps no text.
func (rd *Reader) keep(v []byte) string {
	if rd.ix != nil || len(v) == 0 {
		return ""
	}
	if len(v) > rd.opts.MaxText-rd.text {
		rd.c.BadOptions++
		return ""
	}
	rd.text += len(v)
	return string(v)
}

// idb adds the interface of an Interface Description Block. A block past
// Options.MaxInterfaces is skipped and counted like a damaged one, and so are
// the packets that name its interface, as for any interface never described.
func (rd *Reader) idb(body []byte) {
	if len(body) < 8 || len(rd.ifaces) >= rd.opts.MaxInterfaces {
		rd.c.SkippedBlocks++
		return
	}
	f := Interface{Section: len(rd.sections) - 1, LinkType: rd.bo.Uint16(body), SnapLen: rd.bo.Uint32(body[4:]), TSResol: 6}
	rd.options(body[8:], func(code uint16, v []byte) {
		switch {
		case code == 2:
			f.Name = rd.keep(v)
		case code == 3:
			f.Description = rd.keep(v)
		case code == 9 && len(v) >= 1:
			if _, ok := unitsPerSecond(v[0]); ok {
				f.TSResol = v[0]
			} else {
				rd.c.BadOptions++
			}
		case code == 12:
			f.OS = rd.keep(v)
		case code == 14 && len(v) >= 8:
			f.TSOffset = int64(rd.bo.Uint64(v))
		}
	})
	rd.ifaces = append(rd.ifaces, f)
}

// epb reads the packet of an Enhanced Packet Block or an obsolete Packet
// Block and counts it.
func (rd *Reader) epb(typ uint32, start int64, body []byte, p *Packet) bool {
	if typ == blockPB && len(body) >= 20 {
		rd.c.ObsoletePacket++
	}
	if !epbAt(rd.bo, rd.ifaces, rd.secBase, rd.maxPkt, typ, start, body, p) {
		rd.c.SkippedBlocks++
		return false
	}
	rd.frame++
	rd.ifaces[p.Iface].Packets++
	p.Frame = rd.frame
	if !p.HasTime {
		rd.c.BadTimestamps++
	}
	return true
}

// epbAt decodes the packet of an Enhanced Packet Block or an obsolete Packet
// Block whose body starts at stream offset start, in a section whose first
// interface is ifaces[secBase]. It reports false for a block that names no
// interface of the table or whose lengths do not fit. A time that does not
// fit in 64-bit nanoseconds leaves the packet without one. It changes
// nothing, so the sequential reader and random access decode a block with
// the same code.
func epbAt(bo binary.ByteOrder, ifaces []Interface, secBase int, maxPkt, typ uint32, start int64, body []byte, p *Packet) bool {
	if len(body) < 20 {
		return false
	}
	var id uint32
	if typ == blockPB {
		id = uint32(bo.Uint16(body)) // obsolete Packet Block: 16-bit interface, 16-bit drops count
	} else {
		id = bo.Uint32(body)
	}
	capLen := bo.Uint32(body[12:])
	g := secBase + int(id) // id < len: int(id) stays positive on 32-bit platforms
	if id >= uint32(len(ifaces)) || g >= len(ifaces) || capLen > maxPkt || int(capLen) > len(body)-20 {
		return false
	}
	f := &ifaces[g]
	ts := uint64(bo.Uint32(body[4:]))<<32 | uint64(bo.Uint32(body[8:]))
	ns, ok := toNS(ts, f.TSResol, f.TSOffset)
	*p = Packet{Offset: start, Iface: uint32(g), TimeNS: ns, HasTime: ok,
		CapLen: capLen, OrigLen: max(bo.Uint32(body[16:]), capLen), LinkType: f.LinkType, Data: body[20 : 20+capLen]}
	return true
}

// spb reads the packet of a Simple Packet Block and counts it.
func (rd *Reader) spb(start int64, body []byte, p *Packet) bool {
	if !spbAt(rd.bo, rd.ifaces, rd.secBase, rd.maxPkt, start, body, p) {
		rd.c.SkippedBlocks++
		return false
	}
	rd.frame++
	rd.ifaces[p.Iface].Packets++
	rd.c.SimplePackets++
	p.Frame = rd.frame
	return true
}

// spbAt decodes the packet of a Simple Packet Block, which belongs to the
// first interface of its section and has no time; see epbAt.
func spbAt(bo binary.ByteOrder, ifaces []Interface, secBase int, maxPkt uint32, start int64, body []byte, p *Packet) bool {
	g := secBase
	if g >= len(ifaces) || len(body) < 4 {
		return false
	}
	f := &ifaces[g]
	orig := bo.Uint32(body)
	capLen := min(uint32(len(body)-4), orig)
	if f.SnapLen != 0 {
		capLen = min(capLen, f.SnapLen)
	}
	if capLen > maxPkt {
		return false
	}
	*p = Packet{Offset: start, Iface: uint32(g), CapLen: capLen, OrigLen: max(orig, capLen),
		LinkType: f.LinkType, Data: body[4 : 4+capLen]}
	return true
}

func (rd *Reader) isb(body []byte) {
	if len(body) < 12 {
		rd.c.SkippedBlocks++
		return
	}
	id := rd.bo.Uint32(body)
	g := rd.secBase + int(id)
	if id >= uint32(len(rd.ifaces)) || g >= len(rd.ifaces) {
		rd.c.SkippedBlocks++
		return
	}
	f := &rd.ifaces[g]
	ts := uint64(rd.bo.Uint32(body[4:]))<<32 | uint64(rd.bo.Uint32(body[8:]))
	ns, _ := toNS(ts, f.TSResol, f.TSOffset) // 0 when it does not fit
	s := &InterfaceStats{TimeNS: ns}
	rd.options(body[12:], func(code uint16, v []byte) {
		if len(v) < 8 {
			return
		}
		x := rd.bo.Uint64(v)
		switch code {
		case 4:
			s.IfRecv = &x
		case 5:
			s.IfDrop = &x
		case 6:
			s.FilterAccept = &x
		case 7:
			s.OSDrop = &x
		case 8:
			s.UsrDeliv = &x
		}
	})
	f.Stats = s
}

// options walks a pcapng options area; a malformed area is counted and the
// rest of it ignored.
func (rd *Reader) options(b []byte, fn func(code uint16, v []byte)) {
	if len(b) > maxOptions {
		rd.c.BadOptions++
		return
	}
	for len(b) >= 4 {
		code, n := rd.bo.Uint16(b), int(rd.bo.Uint16(b[2:]))
		if code == 0 {
			return
		}
		if 4+n > len(b) {
			rd.c.BadOptions++
			return
		}
		fn(code, b[4:4+n])
		b = b[min(len(b), 4+(n+3)&^3):]
	}
}

// unitsPerSecond decodes if_tsresol.
func unitsPerSecond(r byte) (uint64, bool) {
	if r&0x80 != 0 {
		e := r & 0x7F
		if e > 63 {
			return 0, false
		}
		return 1 << e, true
	}
	if r > 19 {
		return 0, false
	}
	u := uint64(1)
	for range r {
		u *= 10
	}
	return u, true
}

// toNS converts a pcapng timestamp in if_tsresol units, with the interface's
// if_tsoffset in seconds, to UTC nanoseconds. The sub-second part is exact
// (128-bit intermediate). It reports false when the time does not fit in 64
// bits of nanoseconds (it lies before 1677-09-21 or after 2262-04-11):
// nothing wraps around.
func toNS(ts uint64, resol byte, offset int64) (int64, bool) {
	const second = 1_000_000_000
	u, ok := unitsPerSecond(resol)
	if !ok {
		u = 1e6
	}
	sec, frac := ts/u, ts%u
	hi, lo := bits.Mul64(frac, second)
	ns, _ := bits.Div64(hi, lo, u) // below one second
	// sec + offset, a 64-bit unsigned count plus a signed one, without
	// leaving the range of either: the sum is whole seconds after 1970, or
	// back seconds before it.
	var whole, back uint64
	if offset >= 0 {
		whole = sec + uint64(offset)
		if whole < sec {
			return 0, false
		}
	} else if neg := uint64(-(offset + 1)) + 1; sec >= neg { // neg is -offset, also for the smallest int64
		whole = sec - neg
	} else {
		back = neg - sec
	}
	if back == 0 {
		if whole > math.MaxInt64/second {
			return 0, false
		}
		v := whole*second + ns
		if v > math.MaxInt64 {
			return 0, false
		}
		return int64(v), true
	}
	if back > math.MaxInt64/second+1 {
		return 0, false
	}
	v := back*second - ns // nanoseconds before 1970: at most 2^63
	if v > 1<<63 {
		return 0, false
	}
	return -int64(v), true // also for 2^63, the smallest int64
}
