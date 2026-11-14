// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"errors"
	"io"
	"testing"
)

// sameByOffset reads the packet p again by its offset and fails when random
// access gives anything else than the sequential reader gave.
func sameByOffset(t testing.TB, ix *Index, r io.ReaderAt, p *Packet) {
	t.Helper()
	got, err := ix.ReadAt(r, p.Offset)
	if err != nil {
		t.Fatalf("frame %d at offset %d: by offset: %v", p.Frame, p.Offset, err)
	}
	if got.Iface != p.Iface || got.LinkType != p.LinkType || got.TimeNS != p.TimeNS || got.HasTime != p.HasTime ||
		got.CapLen != p.CapLen || got.OrigLen != p.OrigLen || !bytes.Equal(got.Data, p.Data) {
		got.Data, got.Frame = nil, p.Frame
		want := *p
		want.Data = nil
		t.Fatalf("frame %d at offset %d: by offset %+v, sequentially %+v", p.Frame, p.Offset, got, want)
	}
}

// fuzzRead reads everything and checks the bounds; any panic fails. Every
// packet read is read again by its offset and must be the same packet: the
// same interface, link type, time and bytes.
func fuzzRead(t *testing.T, b []byte) {
	opts := Options{MaxPacket: 4096, MaxBlock: 1 << 16, MaxInterfaces: 64, MaxSections: 16, MaxText: 256}
	rd, err := NewReader(bytes.NewReader(b), opts)
	if err != nil {
		return
	}
	ra := bytes.NewReader(b)
	ix, ixErr := NewIndex(ra, int64(len(b)), opts)
	if rd.Gzip() != errors.Is(ixErr, ErrNotSeekable) || (ixErr != nil && !rd.Gzip()) {
		t.Fatalf("a file the reader opens (gzip: %v) has no index: %v", rd.Gzip(), ixErr)
	}
	var p Packet
	for n := 0; ; n++ {
		err := rd.Next(&p)
		if err != nil {
			if err != io.EOF && rd.Next(&p) != io.EOF {
				t.Fatal("Next after an error must return io.EOF")
			}
			if len(rd.Interfaces()) > opts.MaxInterfaces || len(rd.Sections()) > opts.MaxSections {
				t.Fatalf("%d interfaces, %d sections kept", len(rd.Interfaces()), len(rd.Sections()))
			}
			return
		}
		if ix != nil {
			sameByOffset(t, ix, ra, &p)
		}
		if len(p.Data) > 4096 || uint32(len(p.Data)) != p.CapLen || p.OrigLen < p.CapLen {
			t.Fatalf("packet out of bounds: %d bytes, caplen %d, origlen %d", len(p.Data), p.CapLen, p.OrigLen)
		}
		if p.Offset < 0 || p.Offset >= int64(len(b))*1024 || p.Frame == 0 {
			t.Fatalf("frame %d offset %d", p.Frame, p.Offset)
		}
		if n > len(b) {
			t.Fatal("more packets than input bytes")
		}
	}
}

func FuzzPcapReader(f *testing.F) {
	for _, nanos := range []bool{false, true} {
		var buf bytes.Buffer
		w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1, Nanos: nanos, BigEndian: nanos})
		_ = w.WritePacket(t0, 0, []byte("hello"))
		_ = w.WritePacket(t0, 100, []byte("world!"))
		_ = w.Flush()
		f.Add(buf.Bytes())
	}
	f.Fuzz(fuzzRead)
}

func FuzzPcapngReader(f *testing.F) {
	f.Add(ngFile(f, false))
	f.Add(ngFile(f, true))
	f.Add(skippedInterfaceFile(f))
	f.Fuzz(fuzzRead)
}
