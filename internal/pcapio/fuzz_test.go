// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"io"
	"testing"
)

// fuzzRead reads everything and checks the bounds; any panic fails.
func fuzzRead(t *testing.T, b []byte) {
	rd, err := NewReader(bytes.NewReader(b), Options{MaxPacket: 4096, MaxBlock: 1 << 16})
	if err != nil {
		return
	}
	var p Packet
	for n := 0; ; n++ {
		err := rd.Next(&p)
		if err != nil {
			if err != io.EOF && rd.Next(&p) != io.EOF {
				t.Fatal("Next after an error must return io.EOF")
			}
			return
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
	f.Fuzz(fuzzRead)
}
