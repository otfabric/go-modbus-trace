// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

type rec struct {
	iface   uint32
	timeNS  int64
	hasTime bool
	origLen uint32
	data    []byte
}

func readAll(t *testing.T, b []byte) (*Reader, []rec, []Packet, error) {
	t.Helper()
	rd, err := NewReader(bytes.NewReader(b), Options{})
	if err != nil {
		t.Fatal(err)
	}
	var out []rec
	var pks []Packet
	for {
		var p Packet
		err := rd.Next(&p)
		if err != nil {
			if err == io.EOF {
				err = nil
			}
			return rd, out, pks, err
		}
		out = append(out, rec{p.Iface, p.TimeNS, p.HasTime, p.OrigLen, append([]byte(nil), p.Data...)})
		p.Data = nil
		pks = append(pks, p)
	}
}

const t0 = int64(1760515200_123456789) // 2025-10-15T08:00:00.123456789Z

func TestPcapVariants(t *testing.T) {
	for _, nanos := range []bool{false, true} {
		for _, be := range []bool{false, true} {
			t.Run(fmt.Sprintf("nanos=%v,be=%v", nanos, be), func(t *testing.T) {
				var buf bytes.Buffer
				w, err := NewPcapWriter(&buf, PcapOptions{LinkType: 1, Nanos: nanos, BigEndian: be})
				if err != nil {
					t.Fatal(err)
				}
				want := []rec{{0, t0, true, 60, bytes.Repeat([]byte{1}, 60)}, {0, t0 + 1500, true, 1514, bytes.Repeat([]byte{2}, 100)}}
				for _, r := range want {
					if err := w.WritePacket(r.timeNS, r.origLen, r.data); err != nil {
						t.Fatal(err)
					}
				}
				if err := w.Flush(); err != nil {
					t.Fatal(err)
				}
				rd, got, pks, err := readAll(t, buf.Bytes())
				if err != nil {
					t.Fatal(err)
				}
				if rd.Format() != Pcap || rd.Interfaces()[0].LinkType != 1 {
					t.Fatalf("format %v, interfaces %+v", rd.Format(), rd.Interfaces())
				}
				for i := range want {
					w := want[i]
					if !nanos {
						w.timeNS = w.timeNS / 1000 * 1000
					}
					if fmt.Sprint(got[i]) != fmt.Sprint(w) {
						t.Errorf("packet %d: got %v, want %v", i, got[i], w)
					}
				}
				if pks[0].Offset != 24 || pks[1].Offset != 24+16+60 || pks[1].Frame != 2 || !pks[1].Truncated() {
					t.Errorf("offsets/frames: %+v", pks)
				}
				if rd.SHA256() != sha256.Sum256(buf.Bytes()) {
					t.Error("SHA-256 does not cover the input")
				}
			})
		}
	}
}

func ngFile(t testing.TB, be bool) []byte {
	t.Helper()
	var buf bytes.Buffer
	w, err := NewNgWriter(&buf, Section{BigEndian: be, Application: "tracetest", OS: "test-os", Comment: "hello"},
		[]Interface{{LinkType: 1, TSResol: 6, Name: "eth0"}, {LinkType: 101, TSResol: 9, Name: "tun0", TSOffset: 0}})
	if err != nil {
		t.Fatal(err)
	}
	steps := []func() error{
		func() error { return w.WritePacket(0, t0, 0, []byte("abc")) },
		func() error { return w.WritePacket(1, t0+1, 0, []byte("defg")) },
		func() error { return w.WriteSimplePacket(0, []byte("spb")) },
		func() error { return w.WriteBlock(0x99, []byte("unknown block")) },
		func() error { return w.WriteBlock(blockCB, []byte{0, 0, 0x7e, 0xd9, 'x'}) },
		func() error { return w.WriteBlock(blockNRB, []byte{0, 0, 0, 0}) },
		func() error {
			drop, recv := uint64(7), uint64(100)
			return w.WriteInterfaceStats(0, InterfaceStats{TimeNS: t0 + 5, IfDrop: &drop, IfRecv: &recv})
		},
		func() error { return w.WritePacket(1, t0+2, 9, []byte("hij")) },
	}
	for _, s := range steps {
		if err := s(); err != nil {
			t.Fatal(err)
		}
	}
	if err := w.Flush(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func TestPcapNG(t *testing.T) {
	for _, be := range []bool{false, true} {
		b := ngFile(t, be)
		rd, got, pks, err := readAll(t, b)
		if err != nil {
			t.Fatal(err)
		}
		want := []rec{
			{0, t0 / 1000 * 1000, true, 3, []byte("abc")},
			{1, t0 + 1, true, 4, []byte("defg")},
			{0, 0, false, 3, []byte("spb")},
			{1, t0 + 2, true, 9, []byte("hij")},
		}
		if fmt.Sprint(got) != fmt.Sprint(want) {
			t.Fatalf("be=%v:\n got  %v\n want %v", be, got, want)
		}
		ifs := rd.Interfaces()
		if len(ifs) != 2 || ifs[1].LinkType != 101 || ifs[1].TSResol != 9 || ifs[0].Name != "eth0" || ifs[0].Packets != 2 {
			t.Errorf("interfaces %+v", ifs)
		}
		if s := ifs[0].Stats; s == nil || *s.IfDrop != 7 || *s.IfRecv != 100 || s.FilterAccept != nil {
			t.Errorf("stats %+v", s)
		}
		sec := rd.Sections()
		if len(sec) != 1 || sec[0].Application != "tracetest" || sec[0].OS != "test-os" || sec[0].Comment != "hello" || sec[0].BigEndian != be {
			t.Errorf("sections %+v", sec)
		}
		c := rd.Counters()
		if c.SimplePackets != 1 || c.UnknownBlocks != 2 || c.OtherFrames != 1 || c.SkippedBlocks != 0 || c.TruncatedTail || pks[3].Frame != 5 {
			t.Errorf("counters %+v", c)
		}
		// Offsets point at the block start: the block type is there.
		for _, p := range pks {
			bo := binary.ByteOrder(binary.LittleEndian)
			if be {
				bo = binary.BigEndian
			}
			typ := bo.Uint32(b[p.Offset:])
			if (p.HasTime && typ != blockEPB) || (!p.HasTime && typ != blockSPB) {
				t.Errorf("frame %d: block type %d at offset %d", p.Frame, typ, p.Offset)
			}
		}
	}
}

func TestPcapNGTimestamps(t *testing.T) {
	cases := []struct {
		resol  byte
		ts     uint64
		offset int64
		want   int64
	}{
		{6, 1_500_000, 0, 1_500_000_000},
		{9, 1_500_000_001, 0, 1_500_000_001},
		{3, 1500, 10, 11_500_000_000},
		{0x80 | 10, 1024 + 512, 0, 1_500_000_000},            // 2^-10 s units
		{0x80 | 30, 3<<30 + 1, 0, 3_000_000_000},             // sub-ns fraction truncates
		{12, 2_000_000_000_001, 0, 2_000_000_000},            // picoseconds
		{0x80 | 64, 5, 0, 5_000},                             // invalid: treated as µs
		{20, 5, 0, 5_000},                                    // invalid: treated as µs
		{0x80 | 1, 3, -1, 500_000_000},                       // negative offset
		{0x80 | 63, 1 << 63, 0, 1_000_000_000},               // largest binary unit
		{19, 10_000_000_000_000_000_000 - 1, 0, 999_999_999}, // largest decimal unit
	}
	for _, c := range cases {
		if got := toNS(c.ts, c.resol, c.offset); got != c.want {
			t.Errorf("toNS(%d, %#x, %d) = %d, want %d", c.ts, c.resol, c.offset, got, c.want)
		}
	}
}

func TestMultipleSections(t *testing.T) {
	var buf bytes.Buffer
	w, _ := NewNgWriter(&buf, Section{Application: "a"}, []Interface{{LinkType: 1}})
	_ = w.WritePacket(0, t0, 0, []byte("one"))
	_ = w.NewSection(Section{BigEndian: true, Application: "b"}, []Interface{{LinkType: 113}, {LinkType: 276, TSResol: 9}})
	_ = w.WritePacket(1, t0, 0, []byte("two"))
	_ = w.WritePacket(0, t0, 0, []byte("three"))
	_ = w.Flush()
	rd, got, pks, err := readAll(t, buf.Bytes())
	if err != nil {
		t.Fatal(err)
	}
	if len(got) != 3 || got[1].iface != 2 || got[2].iface != 1 || pks[1].LinkType != 276 || pks[2].LinkType != 113 {
		t.Fatalf("got %v %+v", got, pks)
	}
	if len(rd.Sections()) != 2 || rd.Interfaces()[2].Section != 1 {
		t.Errorf("sections %+v interfaces %+v", rd.Sections(), rd.Interfaces())
	}
}

func TestDamage(t *testing.T) {
	good := ngFile(t, false)
	t.Run("truncated last block", func(t *testing.T) {
		rd, got, _, err := readAll(t, good[:len(good)-5])
		if err != nil || len(got) != 3 || !rd.Counters().TruncatedTail {
			t.Fatalf("err %v, %d packets, counters %+v", err, len(got), rd.Counters())
		}
	})
	t.Run("damaged block with plausible length is skipped", func(t *testing.T) {
		b := append([]byte(nil), good...)
		// Find the second EPB and break its trailing length.
		_, _, pks, _ := readAll(t, good)
		off := pks[1].Offset
		n := binary.LittleEndian.Uint32(b[off+4:])
		binary.LittleEndian.PutUint32(b[off+int64(n)-4:], n+4)
		rd, got, _, err := readAll(t, b)
		if err != nil || len(got) != 3 || rd.Counters().SkippedBlocks != 1 || string(got[1].data) != "spb" {
			t.Fatalf("err %v, packets %v, counters %+v", err, got, rd.Counters())
		}
	})
	t.Run("EPB for an undefined interface is skipped", func(t *testing.T) {
		b := append([]byte(nil), good...)
		_, _, pks, _ := readAll(t, good)
		binary.LittleEndian.PutUint32(b[pks[0].Offset+8:], 9)
		rd, got, _, err := readAll(t, b)
		if err != nil || len(got) != 3 || rd.Counters().SkippedBlocks != 1 {
			t.Fatalf("err %v, %d packets, counters %+v", err, len(got), rd.Counters())
		}
	})
	t.Run("implausible block length ends the read", func(t *testing.T) {
		b := append([]byte(nil), good...)
		_, _, pks, _ := readAll(t, good)
		binary.LittleEndian.PutUint32(b[pks[1].Offset+4:], 0xFFFFFFF0)
		_, got, _, err := readAll(t, b)
		if !errors.Is(err, ErrCorrupt) || len(got) != 1 || !strings.Contains(err.Error(), "offset") {
			t.Fatalf("err %v, %d packets", err, len(got))
		}
	})
	t.Run("corrupt pcap record header ends the read", func(t *testing.T) {
		var buf bytes.Buffer
		w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1})
		_ = w.WritePacket(t0, 0, []byte("ok"))
		_ = w.WritePacket(t0, 0, []byte("bad"))
		_ = w.Flush()
		b := buf.Bytes()
		binary.LittleEndian.PutUint32(b[24+16+2+8:], 1<<30)
		_, got, _, err := readAll(t, b)
		if !errors.Is(err, ErrCorrupt) || len(got) != 1 {
			t.Fatalf("err %v, %d packets", err, len(got))
		}
	})
	t.Run("truncated pcap record", func(t *testing.T) {
		var buf bytes.Buffer
		w, _ := NewPcapWriter(&buf, PcapOptions{LinkType: 1})
		_ = w.WritePacket(t0, 0, []byte("ok"))
		_ = w.WritePacket(t0, 0, []byte("cut"))
		_ = w.Flush()
		rd, got, _, err := readAll(t, buf.Bytes()[:buf.Len()-1])
		if err != nil || len(got) != 1 || !rd.Counters().TruncatedTail {
			t.Fatalf("err %v, %d packets", err, len(got))
		}
	})
	t.Run("not a trace", func(t *testing.T) {
		for _, b := range [][]byte{nil, []byte("GIF89a..."), {0x1f, 0x8b, 0, 0}} {
			if _, err := NewReader(bytes.NewReader(b), Options{}); err == nil {
				t.Errorf("% x: no error", b)
			}
		}
		_, err := NewReader(strings.NewReader("hello world"), Options{})
		if !errors.Is(err, ErrFormat) || !strings.Contains(err.Error(), "68 65 6c 6c") {
			t.Errorf("err %v", err)
		}
	})
}

func TestGzip(t *testing.T) {
	plain := ngFile(t, false)
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	_, _ = zw.Write(plain)
	_ = zw.Close()
	rd, got, pks, err := readAll(t, z.Bytes())
	if err != nil || !rd.Gzip() || len(got) != 4 {
		t.Fatalf("err %v gzip %v packets %d", err, rd.Gzip(), len(got))
	}
	_, _, plainPks, _ := readAll(t, plain)
	for i := range pks {
		if pks[i].Offset != plainPks[i].Offset {
			t.Errorf("offset %d is not in the uncompressed stream", pks[i].Offset)
		}
	}
	if rd.SHA256() != sha256.Sum256(z.Bytes()) {
		t.Error("SHA-256 must cover the file as stored (compressed)")
	}
}

// TestTshark cross-checks timestamps and lengths with Wireshark's reader
// where tshark is installed.
func TestTshark(t *testing.T) {
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not installed")
	}
	path := filepath.Join(t.TempDir(), "t.pcapng")
	if err := os.WriteFile(path, ngFile(t, false), 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command(tshark, "-r", path, "-T", "fields", "-e", "frame.number", "-e", "frame.interface_id",
		"-e", "frame.len", "-e", "frame.cap_len").Output()
	if err != nil {
		t.Fatalf("tshark: %v", err)
	}
	_, got, pks, _ := readAll(t, ngFile(t, false))
	var mine strings.Builder
	for i, r := range got {
		fmt.Fprintf(&mine, "%d\t%d\t%d\t%d\n", pks[i].Frame, r.iface, r.origLen, len(r.data))
	}
	// tshark also lists the custom block as frame 4; ours skips it but keeps the numbering.
	var theirs strings.Builder
	for _, l := range strings.SplitAfter(string(out), "\n") {
		if !strings.HasPrefix(l, "4\t") {
			theirs.WriteString(l)
		}
	}
	if theirs.String() != mine.String() {
		t.Errorf("tshark:\n%s\nours:\n%s", out, mine.String())
	}
}
