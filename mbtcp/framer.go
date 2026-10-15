// SPDX-License-Identifier: MIT

// Package mbtcp frames Modbus/TCP: it cuts MBAP ADUs out of one direction's
// reassembled byte stream, survives gaps and garbage with a bounded resync,
// and decides which endpoint of a connection is the server.
//
// MBAP header: transaction ID (2 bytes), protocol ID (2, 0 for Modbus),
// length (2: unit ID + PDU, 2..254), unit ID (1). An ADU is at most 260
// bytes. TCP segment boundaries are never message boundaries.
package mbtcp

import "encoding/binary"

// Header sizes and limits.
const (
	HeaderLen = 7
	MinLength = 2   // unit ID + function code
	MaxLength = 254 // unit ID + 253-byte PDU
	MaxADU    = 6 + MaxLength
)

// DefaultResyncLimit bounds the bytes scanned for a resync.
const DefaultResyncLimit = 64 << 10

// Header is an MBAP header.
type Header struct {
	TID     uint16
	ProtoID uint16
	Length  uint16 // bytes after the length field: unit ID and PDU
	Unit    uint8
}

// ParseHeader reads an MBAP header from the first 7 bytes of b.
func ParseHeader(b []byte) (Header, bool) {
	if len(b) < HeaderLen {
		return Header{}, false
	}
	return Header{TID: binary.BigEndian.Uint16(b), ProtoID: binary.BigEndian.Uint16(b[2:]),
		Length: binary.BigEndian.Uint16(b[4:]), Unit: b[6]}, true
}

// LengthOK reports whether the length field is in 2..254.
func (h Header) LengthOK() bool { return h.Length >= MinLength && h.Length <= MaxLength }

// Valid reports a Modbus header: protocol ID 0 and a valid length.
func (h Header) Valid() bool { return h.ProtoID == 0 && h.LengthOK() }

// Size returns the size of the whole ADU the header announces.
func (h Header) Size() int { return 6 + int(h.Length) }

// PlausibleFunction reports a function code that can start a PDU: not 0
// and not a bare exception bit.
func PlausibleFunction(fc byte) bool { return fc != 0 && fc != 0x80 }

// Flags qualify a framed ADU.
type Flags uint8

// ADU flags.
const (
	Resynced  Flags = 1 << iota // the first ADU found by a resync: never trusted for MBCAP
	Foreign                     // protocol ID is not 0: framed by its length, not Modbus
	Truncated                   // the snap length cut it: PDU holds only the captured bytes
)

// ADU is one framed application data unit. PDU is valid only during the
// Sink call.
type ADU struct {
	Pos     uint64 // stream position of the first header byte
	Size    int    // bytes on the wire, header included
	TID     uint16
	ProtoID uint16
	Unit    uint8
	PDU     []byte
	Missing int // PDU bytes the snap length cut (Truncated)
	Flags   Flags
}

// Confidence is the strongest rule that held for a resync.
type Confidence uint8

// Confidences.
const (
	ByNextHeader Confidence = iota + 1 // a valid header follows at the announced length
	ByRunEnd                           // the captured bytes end exactly at the announced length
)

func (c Confidence) String() string {
	return [...]string{"", "next_header", "run_end"}[c]
}

// JunkReason says why bytes were not framed.
type JunkReason uint8

// Junk reasons.
const (
	Skipped      JunkReason = iota + 1 // passed over by a resync that then succeeded
	ResyncFailed                       // the resync scan limit passed without a valid header
	Incomplete                         // a partial ADU cut by a gap, or by the end of the stream
)

func (r JunkReason) String() string {
	return [...]string{"", "skipped", "resync_failed", "incomplete"}[r]
}

// Sink receives what a framer finds.
type Sink interface {
	ADU(a *ADU)
	Resync(pos uint64, skipped int, c Confidence)
	Junk(pos uint64, n int, why JunkReason)
}

// Framer frames one direction. It is not safe for concurrent use.
type Framer struct {
	sink   Sink
	limit  int
	buf    []byte
	pos    uint64 // stream position of buf[0]
	resync bool
	scan   int // bytes scanned in the current resync
	// A truncated ADU's bytes after the cut are dropped up to dropEnd (a
	// stream position), whatever gaps come in between.
	dropEnd uint64
	hasDrop bool
	adu     ADU
}

// NewFramer returns a framer; limit 0 means DefaultResyncLimit.
func NewFramer(limit int, s Sink) *Framer {
	if limit <= 0 {
		limit = DefaultResyncLimit
	}
	return &Framer{sink: s, limit: limit}
}

// Write appends the stream bytes at pos (contiguous with the last call or
// gap) and frames what it can. A midstream stream is tried at its first
// byte before any resync.
func (f *Framer) Write(pos uint64, b []byte) {
	if len(f.buf) == 0 {
		f.pos = pos
	}
	if f.hasDrop {
		if pos < f.dropEnd {
			n := int(min(f.dropEnd-pos, uint64(len(b))))
			b, pos = b[n:], pos+uint64(n)
			if len(f.buf) == 0 {
				f.pos = pos
			}
		}
		if pos >= f.dropEnd {
			f.hasDrop = false
		}
	}
	f.buf = append(f.buf, b...)
	f.frame(false)
}

// Gap reports n missing bytes at pos. exact is true when only the snap
// length cut them (the count is certain and nothing else is missing): an
// ADU cut that way is reported Truncated and framing stays in sync when
// the cut ends inside it. Any other gap starts a resync.
func (f *Framer) Gap(pos uint64, n int64, exact bool) {
	if f.hasDrop {
		end := pos + uint64(n)
		if end <= f.dropEnd {
			return // inside the rest of a truncated ADU: nothing more is lost
		}
		if pos < f.dropEnd {
			pos, n = f.dropEnd, int64(end-f.dropEnd)
		}
		f.hasDrop = false
	}
	if exact && !f.resync && len(f.buf) >= HeaderLen {
		h, _ := ParseHeader(f.buf)
		have := len(f.buf)
		if (h.Valid() || h.LengthOK()) && have < h.Size() {
			cut := min(int64(h.Size()-have), n)
			start := f.pos
			f.emit(h, have, h.Size()-have, Truncated) // the PDU lacks every byte after the cut
			f.buf = f.buf[:0]
			if n == cut {
				// The cut ended inside the ADU: the rest of it is still
				// to come, and the next ADU starts after it.
				f.dropEnd, f.hasDrop = start+uint64(h.Size()), true
				f.pos = pos + uint64(n)
				return
			}
		}
	}
	f.frame(true) // the run ends here: decide what is waiting (a resync, a foreign frame)
	f.flushScan()
	if len(f.buf) > 0 {
		f.sink.Junk(f.pos, len(f.buf), Incomplete)
		f.buf = f.buf[:0]
	}
	f.resync, f.scan = true, 0
	f.pos = pos + uint64(n)
}

// Close reports bytes left at the end of the stream.
func (f *Framer) Close() {
	f.frame(true)
	if f.resync {
		// Everything scanned and left over failed to resync.
		if n := f.scan + len(f.buf); n > 0 {
			f.sink.Junk(f.pos-uint64(f.scan), n, ResyncFailed)
		}
		f.scan, f.buf = 0, f.buf[:0]
		return
	}
	if len(f.buf) > 0 {
		f.sink.Junk(f.pos, len(f.buf), Incomplete)
		f.buf = f.buf[:0]
	}
}

// flushScan reports bytes a resync passed over without finding a header,
// when a gap ends the scan.
func (f *Framer) flushScan() {
	if f.resync && f.scan > 0 {
		f.sink.Junk(f.pos-uint64(f.scan), f.scan, ResyncFailed)
	}
	f.scan = 0
}

// emit reports the ADU at the start of the buffer; have bytes of it are
// buffered (fewer than its size only when truncated).
func (f *Framer) emit(h Header, have, missing int, flags Flags) {
	if h.ProtoID != 0 {
		flags |= Foreign
	}
	if f.resync {
		flags |= Resynced
	}
	f.adu = ADU{Pos: f.pos, Size: h.Size(), TID: h.TID, ProtoID: h.ProtoID, Unit: h.Unit,
		PDU: f.buf[HeaderLen:min(have, h.Size())], Missing: missing, Flags: flags}
	f.sink.ADU(&f.adu)
	f.resync, f.scan = false, 0
}

// frame cuts ADUs out of the buffer. final: no more bytes will come.
func (f *Framer) frame(final bool) {
	off := 0
	defer func() {
		if off > 0 {
			f.pos += uint64(off)
			f.buf = append(f.buf[:0], f.buf[off:]...)
		}
		if cap(f.buf) > 4*MaxADU && len(f.buf) < MaxADU {
			f.buf = append([]byte(nil), f.buf...) // do not keep a large buffer per direction
		}
	}()
	for len(f.buf)-off >= HeaderLen {
		rest := f.buf[off:]
		h, _ := ParseHeader(rest)
		if !f.resync {
			if h.Valid() {
				if len(rest) < h.Size() {
					return
				}
				f.take(&off, h)
				continue
			}
			// A foreign protocol: plausible length, and the next header
			// (or the end of the run) where the length says.
			if h.LengthOK() {
				switch ok, wait := f.follows(rest, h, final); {
				case wait:
					return
				case ok:
					f.take(&off, h)
					continue
				}
			}
			f.resync, f.scan = true, 0
		}
		// Resync: a valid header, a plausible function code, and either a
		// valid header after it or the end of the captured run.
		if h.Valid() && len(rest) == HeaderLen && !final {
			return // wait for the function code
		}
		if h.Valid() && len(rest) > HeaderLen && PlausibleFunction(rest[HeaderLen]) {
			ok, wait := f.follows(rest, h, final)
			if wait {
				return
			}
			if ok {
				conf := ByNextHeader
				if len(rest) == h.Size() {
					conf = ByRunEnd
				}
				if f.scan > 0 {
					f.sink.Junk(f.pos+uint64(off)-uint64(f.scan), f.scan, Skipped)
				}
				f.sink.Resync(f.pos+uint64(off), f.scan, conf)
				f.take(&off, h)
				continue
			}
		}
		off++
		f.scan++
		if f.scan >= f.limit {
			f.sink.Junk(f.pos+uint64(off)-uint64(f.scan), f.scan, ResyncFailed)
			f.scan = 0
		}
	}
}

// follows reports whether a valid header follows the ADU that h announces
// at the start of b, or b ends exactly after it; wait when b is too short
// to tell yet. final: the run ends with b (a gap or the end of the
// stream); then a cut-off next header counts if what is there of it is
// valid (the protocol ID bytes present are 0, the length when present is
// 2..254). Such an ADU is still Resynced: never trusted.
func (f *Framer) follows(b []byte, h Header, final bool) (ok, wait bool) {
	n := h.Size()
	switch {
	case len(b) == n:
		return true, false
	case len(b) >= n+HeaderLen:
		next, _ := ParseHeader(b[n:])
		return next.Valid(), false
	case !final:
		return false, true
	case len(b) > n:
		rest := b[n:]
		for _, x := range rest[min(2, len(rest)):min(4, len(rest))] {
			if x != 0 { // the protocol ID bytes that are there must be 0
				return false, false
			}
		}
		if len(rest) >= 6 {
			l := binary.BigEndian.Uint16(rest[4:])
			return l >= MinLength && l <= MaxLength, false
		}
		return true, false
	default:
		return false, false
	}
}

// take emits the complete ADU at off and moves past it.
func (f *Framer) take(off *int, h Header) {
	// emit works on the buffer start; shift the view.
	base := f.buf
	f.buf = f.buf[*off:]
	p := f.pos
	f.pos += uint64(*off)
	f.emit(h, h.Size(), 0, 0)
	f.buf = base
	f.pos = p
	*off += h.Size()
}
