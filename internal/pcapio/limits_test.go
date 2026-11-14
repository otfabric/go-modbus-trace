// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"compress/flate"
	"compress/gzip"
	"encoding/binary"
	"errors"
	"io"
	"runtime"
	"strings"
	"testing"
)

// liveHeap returns the bytes of live heap objects after a collection.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// manyInterfaces is a pcapng file of one section with n interfaces, each
// with a name, and one packet on the first and one on the last interface.
func manyInterfaces(t testing.TB, n int, name string) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, Section{Application: "limits"}, nil)
	if err != nil {
		t.Fatal(err)
	}
	for range n {
		if err := w.AddInterface(Interface{LinkType: 1, Name: name}); err != nil {
			t.Fatal(err)
		}
	}
	_ = w.WritePacket(0, t0, 0, []byte("first"))
	_ = w.WritePacket(uint32(n-1), t0, 0, []byte("last"))
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func drain(t testing.TB, rd *Reader) (packets int, err error) {
	t.Helper()
	var p Packet
	for {
		if err = rd.Next(&p); err != nil {
			if err == io.EOF {
				err = nil
			}
			return packets, err
		}
		packets++
	}
}

// TestInterfaceLimit: the interfaces kept from one input are limited. At
// the limit every block is kept; a block past it is skipped and counted, and
// so is a packet that names its interface.
func TestInterfaceLimit(t *testing.T) {
	for _, c := range []struct {
		name          string
		limit, blocks int
		kept, packets int
		skipped       uint64
		onLast        uint64 // packets counted on the last interface kept
	}{
		{"one below the limit", 4, 3, 3, 2, 0, 1},
		{"at the limit", 4, 4, 4, 2, 0, 1},
		{"one past the limit", 4, 5, 4, 1, 2, 0}, // the block, and the packet on its interface
		{"far past the limit", 4, 500, 4, 1, 497, 0},
		{"the default limit", 0, DefaultMaxInterfaces, DefaultMaxInterfaces, 2, 0, 1},
		{"one past the default limit", 0, DefaultMaxInterfaces + 1, DefaultMaxInterfaces, 1, 2, 0},
	} {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NewReader(bytes.NewReader(manyInterfaces(t, c.blocks, "")), Options{MaxInterfaces: c.limit})
			if err != nil {
				t.Fatal(err)
			}
			n, err := drain(t, rd)
			ifs := rd.Interfaces()
			if err != nil || n != c.packets || len(ifs) != c.kept || rd.Counters().SkippedBlocks != c.skipped ||
				ifs[0].Packets != 1 || ifs[len(ifs)-1].Packets != c.onLast {
				t.Errorf("err %v, %d packets, %d interfaces, counters %+v, packets on the first %d and the last %d",
					err, n, len(ifs), rd.Counters(), ifs[0].Packets, ifs[len(ifs)-1].Packets)
			}
		})
	}
}

// TestSectionLimit: the sections read from one input are limited. A section
// header past the limit ends the read with ErrCorrupt; what came before it
// is read.
func TestSectionLimit(t *testing.T) {
	file := func(sections int) []byte {
		var buf bytes.Buffer
		w, _ := NewNgWriter(&buf, Section{}, []Interface{{LinkType: 1}})
		_ = w.WritePacket(0, t0, 0, []byte("packet"))
		for range sections - 1 {
			_ = w.NewSection(Section{}, []Interface{{LinkType: 1}})
			_ = w.WritePacket(0, t0, 0, []byte("packet"))
		}
		_ = w.Flush()
		return buf.Bytes()
	}
	for _, c := range []struct {
		name            string
		limit, sections int
		read            int
		refused         bool
	}{
		{"one below the limit", 3, 2, 2, false},
		{"at the limit", 3, 3, 3, false},
		{"one past the limit", 3, 4, 3, true},
		{"far past the limit", 3, 40, 3, true},
		{"the default limit", 0, DefaultMaxSections, DefaultMaxSections, false},
		{"one past the default limit", 0, DefaultMaxSections + 1, DefaultMaxSections, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			rd, err := NewReader(bytes.NewReader(file(c.sections)), Options{MaxSections: c.limit})
			if err != nil {
				t.Fatal(err)
			}
			n, err := drain(t, rd)
			if n != c.read || len(rd.Sections()) != c.read || len(rd.Interfaces()) != c.read {
				t.Errorf("%d packets, %d sections, %d interfaces, want %d of each", n, len(rd.Sections()), len(rd.Interfaces()), c.read)
			}
			if c.refused != errors.Is(err, ErrCorrupt) || (err != nil && !strings.Contains(err.Error(), "sections")) {
				t.Errorf("error %v, refused %v", err, c.refused)
			}
		})
	}
}

// TestTextLimit: the option text kept from one input is limited. Text that
// does not fit is left out and counted; the interface or section itself is
// kept.
func TestTextLimit(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewNgWriter(&buf, Section{Application: "12345", OS: "678"}, []Interface{{LinkType: 1, Name: "ab"}, {LinkType: 1, Name: "cd", Description: "e"}})
	_ = w.WritePacket(1, t0, 0, []byte("packet"))
	_ = w.Flush()
	for _, c := range []struct {
		limit int
		kept  string
		lost  uint64
	}{
		{0, "678|12345|ab|cd|e", 0},  // the default limit
		{13, "678|12345|ab|cd|e", 0}, // exactly what there is
		{12, "678|12345|ab|cd|", 1},
		{9, "678|12345|||e", 2}, // a later, shorter text still fits
		{2, "||ab||", 4},
		{1, "||||e", 4},
	} {
		rd, err := NewReader(bytes.NewReader(buf.Bytes()), Options{MaxText: c.limit})
		if err != nil {
			t.Fatal(err)
		}
		n, err := drain(t, rd)
		s, f := rd.Sections()[0], rd.Interfaces()
		got := strings.Join([]string{s.OS, s.Application, f[0].Name, f[1].Name, f[1].Description}, "|")
		if err != nil || n != 1 || len(f) != 2 || got != c.kept || rd.Counters().BadOptions != c.lost {
			t.Errorf("limit %d: err %v, %d packets, text %q, %d not kept; want %q, %d", c.limit, err, n, got, rd.Counters().BadOptions, c.kept, c.lost)
		}
	}
}

// TestMetadataBudget: what a reader keeps of a file's interfaces, sections
// and their text is bounded by the limits, not by the file. Files with four
// times and sixteen times as many interface blocks as the limit, each with a
// name, leave the same live heap behind, within a budget derived from the
// limits.
func TestMetadataBudget(t *testing.T) {
	const (
		limit = 4096
		text  = 64 << 10
		name  = "interface-name-of-thirty-two-byt"
		// A kept interface is its struct (two words short of 100 bytes on
		// 64-bit platforms) in a slice that may have grown by half again.
		perInterface = 256
	)
	budget := uint64(limit*perInterface + 2*text + 64<<10)
	var held [2]uint64
	for i, blocks := range []int{4 * limit, 16 * limit} {
		file := manyInterfaces(t, blocks, name)
		before := liveHeap()
		rd, err := NewReader(bytes.NewReader(file), Options{MaxInterfaces: limit, MaxText: text})
		if err != nil {
			t.Fatal(err)
		}
		n, err := drain(t, rd)
		after := liveHeap()
		if err != nil || n != 1 || len(rd.Interfaces()) != limit || rd.Counters().SkippedBlocks != uint64(blocks-limit)+1 {
			t.Fatalf("%d blocks: err %v, %d packets, %d interfaces, counters %+v", blocks, err, n, len(rd.Interfaces()), rd.Counters())
		}
		kept := 0
		for _, f := range rd.Interfaces() {
			kept += len(f.Name)
		}
		if kept > text || kept < text-len(name) {
			t.Errorf("%d blocks: %d bytes of names kept, limit %d", blocks, kept, text)
		}
		held[i] = after - min(after, before)
		t.Logf("%d interface blocks in %d KiB: %d KiB live after the read (budget %d KiB)", blocks, len(file)>>10, held[i]>>10, budget>>10)
		if held[i] > budget {
			t.Errorf("%d blocks: %d bytes live after the read, budget %d", blocks, held[i], budget)
		}
		runtime.KeepAlive(file)
		runtime.KeepAlive(rd)
	}
}

// gz compresses b; stored: without compression, in stored blocks whose
// headers the test can find.
func gz(t testing.TB, b []byte, stored bool) []byte {
	t.Helper()
	var z bytes.Buffer
	level := gzip.DefaultCompression
	if stored {
		level = gzip.NoCompression
	}
	zw, err := gzip.NewWriterLevel(&z, level)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := zw.Write(b); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return z.Bytes()
}

// TestGzipDamage: a gzip input that cannot be decompressed as stored ends
// the read with an error wrapping ErrCorrupt and the cause, after the
// packets that could be read; a gzip stream that merely stops early is a
// cut-short tail, as for a plain file.
func TestGzipDamage(t *testing.T) {
	var plain bytes.Buffer
	w, _ := NewPcapWriter(&plain, PcapOptions{LinkType: 1})
	const total = 2000
	payload := bytes.Repeat([]byte("payload "), 12)
	for i := range total {
		_ = w.WritePacket(t0+int64(i), 0, payload)
	}
	_ = w.Flush()
	read := func(t *testing.T, z []byte) (int, Counters, error) {
		t.Helper()
		rd, err := NewReader(bytes.NewReader(z), Options{})
		if err != nil {
			t.Fatal(err)
		}
		n, err := drain(t, rd)
		var p Packet
		if again := rd.Next(&p); again != io.EOF {
			t.Errorf("Next after the end: %v, want io.EOF", again)
		}
		return n, rd.Counters(), err
	}
	t.Run("intact", func(t *testing.T) {
		if n, c, err := read(t, gz(t, plain.Bytes(), false)); err != nil || n != total || c.TruncatedTail {
			t.Errorf("%d packets, counters %+v, %v", n, c, err)
		}
	})
	t.Run("a checksum that does not match", func(t *testing.T) {
		z := gz(t, plain.Bytes(), false)
		z[len(z)-8] ^= 0x01 // CRC-32 of the uncompressed data
		n, c, err := read(t, z)
		if n != total || c.TruncatedTail || !errors.Is(err, ErrCorrupt) || !errors.Is(err, gzip.ErrChecksum) {
			t.Errorf("%d packets, counters %+v, %v", n, c, err)
		}
	})
	t.Run("a length that does not match", func(t *testing.T) {
		z := gz(t, plain.Bytes(), false)
		z[len(z)-4] ^= 0x01 // size of the uncompressed data
		n, c, err := read(t, z)
		if n != total || c.TruncatedTail || !errors.Is(err, ErrCorrupt) || !errors.Is(err, gzip.ErrChecksum) {
			t.Errorf("%d packets, counters %+v, %v", n, c, err)
		}
	})
	t.Run("damaged compressed data", func(t *testing.T) {
		z := gz(t, plain.Bytes(), true)
		// Stored blocks: 1 byte of block header, the length, and its
		// complement. The second block starts after the first one's 65535
		// bytes; a complement that does not match is damage in mid-stream.
		second := 10 + 5 + 65535
		if binary.LittleEndian.Uint16(z[second+1:])^binary.LittleEndian.Uint16(z[second+3:]) != 0xFFFF {
			t.Fatal("the second stored block is not where the test expects it")
		}
		z[second+3] ^= 0x01
		n, c, err := read(t, z)
		var ce flate.CorruptInputError
		if n == 0 || n >= total || !c.TruncatedTail || !errors.Is(err, ErrCorrupt) || !errors.As(err, &ce) {
			t.Errorf("%d packets, counters %+v, %v", n, c, err)
		}
	})
	t.Run("a stream that stops early", func(t *testing.T) {
		z := gz(t, plain.Bytes(), false)
		n, c, err := read(t, z[:len(z)/2])
		if n == 0 || n >= total || !c.TruncatedTail || err != nil {
			t.Errorf("%d packets, counters %+v, %v", n, c, err)
		}
	})
	t.Run("a stream that stops before its trailer", func(t *testing.T) {
		z := gz(t, plain.Bytes(), false)
		n, c, err := read(t, z[:len(z)-8])
		if n != total || !c.TruncatedTail || err != nil {
			t.Errorf("%d packets, counters %+v, %v", n, c, err)
		}
	})
}

// TestSizeLimits: a captured packet is read up to Options.MaxPacket and a
// pcapng block up to Options.MaxBlock; a length above the limit is refused
// before anything of that size is allocated, whatever it claims.
func TestSizeLimits(t *testing.T) {
	const maxPacket, maxBlock = 1024, 4096
	opts := Options{MaxPacket: maxPacket, MaxBlock: maxBlock}
	pcap := func(capLen uint32, have int) []byte {
		var buf bytes.Buffer
		w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1})
		_ = w.WritePacket(t0, 0, []byte("first"))
		_ = w.Flush()
		rec := make([]byte, 16+have)
		binary.LittleEndian.PutUint32(rec[8:], capLen)
		binary.LittleEndian.PutUint32(rec[12:], capLen)
		return append(buf.Bytes(), rec...)
	}
	ng := func(blockLen uint32, have int) []byte {
		var buf bytes.Buffer
		w, _ := NewNgWriter(&buf, Section{}, []Interface{{LinkType: 1}})
		_ = w.WritePacket(0, t0, 0, []byte("first"))
		_ = w.Flush()
		blk := make([]byte, have)
		binary.LittleEndian.PutUint32(blk[0:], 0x99) // a block type the reader does not read
		binary.LittleEndian.PutUint32(blk[4:], blockLen)
		if int(blockLen) == have {
			binary.LittleEndian.PutUint32(blk[have-4:], blockLen)
		}
		return append(buf.Bytes(), blk...)
	}
	for _, c := range []struct {
		name    string
		file    []byte
		packets int
		refused bool
	}{
		{"pcap: a packet one below the limit", pcap(maxPacket-1, maxPacket-1), 2, false},
		{"pcap: a packet at the limit", pcap(maxPacket, maxPacket), 2, false},
		{"pcap: a packet one above the limit", pcap(maxPacket+1, maxPacket+1), 1, true},
		{"pcap: a length of 2 GiB", pcap(1<<31, 64), 1, true},
		{"pcap: the largest length", pcap(0xFFFFFFFF, 64), 1, true},
		{"pcapng: a block at the limit", ng(maxBlock, maxBlock), 1, false},
		{"pcapng: a block above the limit", ng(maxBlock+4, maxBlock+4), 1, true},
		{"pcapng: a length of 2 GiB", ng(1<<31, 64), 1, true},
		{"pcapng: the largest length", ng(0xFFFFFFFC, 64), 1, true},
	} {
		t.Run(c.name, func(t *testing.T) {
			var before, after runtime.MemStats
			runtime.ReadMemStats(&before)
			rd, err := NewReader(bytes.NewReader(c.file), opts)
			if err != nil {
				t.Fatal(err)
			}
			n, err := drain(t, rd)
			runtime.ReadMemStats(&after)
			if n != c.packets || c.refused != errors.Is(err, ErrCorrupt) {
				t.Errorf("%d packets, error %v; want %d, refused %v", n, err, c.packets, c.refused)
			}
			// The reader's own buffers are 576 KiB; nothing a length claims.
			if got := after.TotalAlloc - before.TotalAlloc; got > 1<<20 {
				t.Errorf("%d bytes allocated", got)
			}
		})
	}
}
