// SPDX-License-Identifier: MIT

package trace

import (
	"encoding/binary"
	"testing"

	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// TestTSOSegments: a capture taken on the sending host before TCP
// segmentation offload filled in the IPv4 total length (0 in every
// packet) yields the same ADUs as with the lengths, and counts them.
func TestTSOSegments(t *testing.T) {
	data, truth := build(t, tracetest.Options{Format: tracetest.Pcap, Interfaces: []tracetest.Iface{{Link: tracetest.Raw}}},
		func(b *tracetest.Builder) {
			c := b.Conn(tracetest.ConnOptions{})
			c.Request(1, 1, rd3)
			c.Response(1, 1, resp3(1))
			c.Close()
		})
	// Classic pcap: a 24-byte file header, then per record 16 bytes and
	// the packet (link type raw: the IPv4 header first).
	var ipv4 uint64
	for off := 24; off+16 <= len(data); {
		n := int(binary.LittleEndian.Uint32(data[off+8:]))
		p := data[off+16 : off+16+n]
		if len(p) >= 20 && p[0]>>4 == 4 {
			p[2], p[3] = 0, 0
			ipv4++
		}
		off += 16 + n
	}
	if ipv4 == 0 {
		t.Fatal("no IPv4 packet in the trace")
	}
	r := run(t, data, ScanOptions{})
	checkADUs(t, r, truth)
	if r.sum.TSOSegments != ipv4 || r.sum.Unsupported["bad_header"] != 0 {
		t.Errorf("tso_segments %d (want %d), bad_header %d", r.sum.TSOSegments, ipv4, r.sum.Unsupported["bad_header"])
	}
}
