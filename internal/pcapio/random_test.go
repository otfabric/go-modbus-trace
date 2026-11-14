// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"slices"
	"testing"
)

// TestReadAt: every packet read sequentially reads back the same at its
// offset, in pcap (both byte orders, µs and ns) and pcapng (several
// sections, both byte orders, SPB).
func TestReadAt(t *testing.T) {
	files := map[string][]byte{"pcapng": ngFile(t, false), "pcapng-be": ngFile(t, true)}
	for _, be := range []bool{false, true} {
		var buf bytes.Buffer
		w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 113, Nanos: be, BigEndian: be})
		_ = w.WritePacket(t0, 0, []byte("first"))
		_ = w.WritePacket(t0+5, 99, []byte("second packet"))
		_ = w.Flush()
		files["pcap"+map[bool]string{false: "", true: "-be-ns"}[be]] = buf.Bytes()
	}
	var ms bytes.Buffer
	nw, _ := NewNgWriter(&ms, Section{}, []Interface{{LinkType: 1}})
	_ = nw.WritePacket(0, t0, 0, []byte("one"))
	_ = nw.NewSection(Section{BigEndian: true}, []Interface{{LinkType: 113}, {LinkType: 276, TSResol: 9}})
	_ = nw.WritePacket(1, t0+7, 0, []byte("two"))
	_ = nw.Flush()
	files["sections"] = ms.Bytes()
	for name, b := range files {
		r := bytes.NewReader(b)
		ix, err := NewIndex(r, int64(len(b)), Options{})
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		rd, _ := NewReader(bytes.NewReader(b), Options{})
		var p Packet
		for rd.Next(&p) == nil {
			got, err := ix.ReadAt(r, p.Offset)
			if err != nil {
				t.Fatalf("%s frame %d: %v", name, p.Frame, err)
			}
			if !bytes.Equal(got.Data, p.Data) || got.TimeNS != p.TimeNS || got.LinkType != p.LinkType || got.Iface != p.Iface || got.OrigLen != p.OrigLen {
				t.Errorf("%s frame %d: %+v, sequential %+v", name, p.Frame, got, p)
			}
		}
	}
}

func TestIndexErrors(t *testing.T) {
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write(ngFile(t, false))
	_ = zw.Close()
	if _, err := NewIndex(bytes.NewReader(z.Bytes()), int64(z.Len()), Options{}); !errors.Is(err, ErrNotSeekable) {
		t.Errorf("gzip: %v", err)
	}
	if _, err := NewIndex(bytes.NewReader([]byte("nope")), 4, Options{}); !errors.Is(err, ErrFormat) {
		t.Errorf("not a trace: %v", err)
	}
	if _, err := NewIndex(bytes.NewReader(nil), 0, Options{}); !errors.Is(err, ErrFormat) {
		t.Errorf("empty: %v", err)
	}
	b := ngFile(t, false)
	r := bytes.NewReader(b)
	ix, _ := NewIndex(r, int64(len(b)), Options{})
	if _, err := ix.ReadAt(r, 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a section header is not a packet: %v", err)
	}
	if _, err := ix.ReadAt(r, int64(len(b))+100); err == nil {
		t.Errorf("beyond the end: %v", err)
	}
	// A damaged block length stops the index; what came before stays usable.
	d := append([]byte(nil), b...)
	d[len(d)/2&^3] ^= 0xFF
	if _, err := NewIndex(bytes.NewReader(d), int64(len(d)), Options{}); err != nil {
		t.Errorf("damaged: %v", err)
	}
}

// TestReadAtSubSecond: random access refuses a pcap record whose
// sub-second part is out of range, as the sequential reader does.
func TestReadAtSubSecond(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1})
	_ = w.WritePacket(t0, 0, []byte("x"))
	_ = w.Flush()
	b := buf.Bytes()
	binary.LittleEndian.PutUint32(b[24+4:], 2_000_000) // µs part of 2 s
	ix, err := NewIndex(bytes.NewReader(b), int64(len(b)), Options{})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ix.ReadAt(bytes.NewReader(b), 24); !errors.Is(err, ErrCorrupt) {
		t.Errorf("sub-second of 2 s: %v", err)
	}
}

type failAfter struct {
	r io.Reader
}

var errDeviceGone = errors.New("device gone")

func (f *failAfter) Read(p []byte) (int, error) {
	n, err := f.r.Read(p)
	if err == io.EOF {
		return n, errDeviceGone
	}
	return n, err
}

// TestDrainError: a read error inside a record ends the read with an error
// that wraps ErrCorrupt and the cause, and marks the tail truncated, so the
// hash is known to cover only what was read. Between two records the same
// error ends the read without a truncated tail.
func TestDrainError(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1})
	_ = w.WritePacket(t0, 0, []byte("whole"))
	_ = w.Flush()
	for _, c := range []struct {
		name      string
		tail      []byte
		truncated bool
	}{
		{"inside a record header", []byte{1, 2, 3}, true},
		{"between two records", nil, false},
	} {
		b := append(bytes.Clone(buf.Bytes()), c.tail...)
		rd, err := NewReader(&failAfter{bytes.NewReader(b)}, Options{})
		if err != nil {
			t.Fatal(err)
		}
		var p Packet
		n := 0
		for err = rd.Next(&p); err == nil; err = rd.Next(&p) {
			n++
		}
		if n != 1 || rd.Counters().TruncatedTail != c.truncated || !errors.Is(err, ErrCorrupt) || !errors.Is(err, errDeviceGone) {
			t.Errorf("%s: %d packets, counters %+v, error %v", c.name, n, rd.Counters(), err)
		}
		if err := rd.Next(&p); err != io.EOF {
			t.Errorf("%s: Next after the error: %v, want io.EOF", c.name, err)
		}
	}
}

// skippedInterfaceFile is a pcapng file whose first of three interface blocks
// has a trailing length that disagrees with its leading one, so a reader
// skips it: the packets' interface IDs then count from the second block.
func skippedInterfaceFile(t testing.TB) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, Section{}, []Interface{{LinkType: 113, TSResol: 9}, {LinkType: 1, TSResol: 6}, {LinkType: 101, TSResol: 3, TSOffset: 5}})
	if err != nil {
		t.Fatal(err)
	}
	_ = w.WritePacket(0, t0, 0, []byte("first"))
	_ = w.WritePacket(1, t0+2_000_000, 0, []byte("second"))
	_ = w.WritePacket(2, t0, 0, []byte("third"))
	_ = w.WriteSimplePacket(0, []byte("simple"))
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	b := buf.Bytes()
	idb := binary.LittleEndian.Uint32(b[4:])        // the first block after the section header
	n := binary.LittleEndian.Uint32(b[idb+4:])      // its length
	binary.LittleEndian.PutUint32(b[idb+n-4:], n+4) // the trailing copy disagrees
	return b
}

// TestReadAtAfterSkippedBlocks: random access resolves a packet's interface
// as the pass that reported the packet did, also when that pass skipped
// interface blocks before it: a damaged one, or one past the interface
// limit. The index is built by the reader itself, so it cannot know an
// interface the reader does not.
func TestReadAtAfterSkippedBlocks(t *testing.T) {
	check := func(t *testing.T, b []byte, scan, index Options, links []uint16, skipped uint64) {
		t.Helper()
		rd, err := NewReader(bytes.NewReader(b), scan)
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(b)
		ix, err := NewIndex(r, int64(len(b)), index)
		if err != nil {
			t.Fatal(err)
		}
		var p Packet
		var got []uint16
		for rd.Next(&p) == nil {
			got = append(got, p.LinkType)
			sameByOffset(t, ix, r, &p)
		}
		if !slices.Equal(got, links) || rd.Counters().SkippedBlocks != skipped {
			t.Errorf("link types %v, want %v; %d blocks skipped, want %d", got, links, rd.Counters().SkippedBlocks, skipped)
		}
	}
	t.Run("a damaged interface block", func(t *testing.T) {
		// Interfaces 0 and 1 are the second and third block; the packet for
		// interface 2 names none and is skipped with the damaged block.
		check(t, skippedInterfaceFile(t), Options{}, Options{}, []uint16{1, 101, 1}, 2)
	})
	t.Run("interface blocks past the limit", func(t *testing.T) {
		var buf bytes.Buffer
		w, _ := NewNgWriter(&buf, Section{}, []Interface{{LinkType: 113}, {LinkType: 1}})
		_ = w.WritePacket(0, t0, 0, []byte("one"))
		_ = w.NewSection(Section{}, []Interface{{LinkType: 101, TSResol: 9}, {LinkType: 276}})
		_ = w.WritePacket(0, t0, 0, []byte("two"))
		_ = w.WritePacket(1, t0, 0, []byte("three"))
		_ = w.Flush()
		// A limit of 3: the second section's second interface is not kept.
		// The pass and the index agree at the same limit, and at the default
		// limit the index still gives the pass's packets the same interface.
		check(t, buf.Bytes(), Options{MaxInterfaces: 3}, Options{MaxInterfaces: 3}, []uint16{113, 101}, 2)
		lim, err := NewReader(bytes.NewReader(buf.Bytes()), Options{MaxInterfaces: 3})
		if err != nil {
			t.Fatal(err)
		}
		r := bytes.NewReader(buf.Bytes())
		ix, _ := NewIndex(r, int64(buf.Len()), Options{})
		var p Packet
		for lim.Next(&p) == nil {
			got, err := ix.ReadAt(r, p.Offset)
			if err != nil || got.LinkType != p.LinkType || got.TimeNS != p.TimeNS || !bytes.Equal(got.Data, p.Data) {
				t.Errorf("frame %d: by offset %+v (%v), sequentially %+v", p.Frame, got, err, p)
			}
		}
	})
	t.Run("a block whose trailing length disagrees is no packet", func(t *testing.T) {
		b := ngFile(t, false)
		_, _, pks, _ := readAll(t, b)
		off := pks[1].Offset
		n := binary.LittleEndian.Uint32(b[off+4:])
		binary.LittleEndian.PutUint32(b[off+int64(n)-4:], n+4)
		r := bytes.NewReader(b)
		ix, _ := NewIndex(r, int64(len(b)), Options{})
		if _, err := ix.ReadAt(r, off); !errors.Is(err, ErrCorrupt) {
			t.Errorf("by offset: %v, want ErrCorrupt as the reader skips the block", err)
		}
	})
}
