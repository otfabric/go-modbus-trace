// SPDX-License-Identifier: MIT

package mbtcp

import (
	"bytes"
	"testing"
)

// spanSink checks that framed spans never overlap and stay in bounds.
type spanSink struct {
	t    *testing.T
	last uint64
	end  uint64
}

func (s *spanSink) span(pos uint64, n int, early bool) {
	// A truncated ADU is reported at the cut, before the rest of it (which
	// is dropped) arrives.
	if pos < s.last || (!early && pos+uint64(n) > s.end) {
		s.t.Fatalf("span %d+%d after %d, stream end %d", pos, n, s.last, s.end)
	}
	s.last = pos + uint64(n)
}

func (s *spanSink) ADU(a *ADU) {
	if a.Size > MaxADU || len(a.PDU)+HeaderLen+a.Missing != a.Size {
		s.t.Fatalf("ADU size %d, PDU %d, missing %d", a.Size, len(a.PDU), a.Missing)
	}
	s.span(a.Pos, a.Size, a.Flags&Truncated != 0)
}
func (s *spanSink) Resync(uint64, int, Confidence) {}
func (s *spanSink) Junk(pos uint64, n int, _ JunkReason) {
	if n <= 0 {
		s.t.Fatalf("junk of %d bytes", n)
	}
	s.span(pos, n, false)
}

// FuzzFramer feeds a stream in pieces; the control bytes choose the cuts
// and gaps.
func FuzzFramer(f *testing.F) {
	f.Add(bytes.Join([][]byte{mbap(1, 0, 1, read...), mbap(2, 7, 1, 1), {9, 9}, mbap(3, 0, 1, read...)}, nil), []byte{3, 0x80, 7, 0x45})
	f.Fuzz(func(t *testing.T, stream, ctl []byte) {
		s := &spanSink{t: t}
		fr := NewFramer(64, s)
		pos := uint64(0)
		for i := 0; len(stream) > 0; i++ {
			c := byte(7)
			if len(ctl) > 0 {
				c = ctl[i%len(ctl)]
			}
			n := min(len(stream), int(c&0x3F)+1)
			s.end = pos + uint64(n)
			if c&0xC0 == 0x80 { // a gap of n bytes
				fr.Gap(pos, int64(n), c&1 == 0)
			} else {
				fr.Write(pos, stream[:n])
			}
			stream = stream[n:]
			pos += uint64(n)
		}
		fr.Close()
	})
}
