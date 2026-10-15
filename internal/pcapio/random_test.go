// SPDX-License-Identifier: MIT

package pcapio

import (
	"bytes"
	"compress/gzip"
	"errors"
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
		ix, err := NewIndex(r, int64(len(b)))
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
	if _, err := NewIndex(bytes.NewReader(z.Bytes()), int64(z.Len())); !errors.Is(err, ErrNotSeekable) {
		t.Errorf("gzip: %v", err)
	}
	if _, err := NewIndex(bytes.NewReader([]byte("nope")), 4); !errors.Is(err, ErrFormat) {
		t.Errorf("not a trace: %v", err)
	}
	if _, err := NewIndex(bytes.NewReader(nil), 0); !errors.Is(err, ErrFormat) {
		t.Errorf("empty: %v", err)
	}
	b := ngFile(t, false)
	r := bytes.NewReader(b)
	ix, _ := NewIndex(r, int64(len(b)))
	if _, err := ix.ReadAt(r, 0); !errors.Is(err, ErrCorrupt) {
		t.Errorf("a section header is not a packet: %v", err)
	}
	if _, err := ix.ReadAt(r, int64(len(b))+100); err == nil {
		t.Errorf("beyond the end: %v", err)
	}
	// A damaged block length stops the index; what came before stays usable.
	d := append([]byte(nil), b...)
	d[len(d)/2&^3] ^= 0xFF
	if _, err := NewIndex(bytes.NewReader(d), int64(len(d))); err != nil {
		t.Errorf("damaged: %v", err)
	}
}
