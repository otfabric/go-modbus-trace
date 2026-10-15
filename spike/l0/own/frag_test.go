// SPDX-License-Identifier: MIT

package own_test

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/otfabric/go-modbus-trace/spike/l0/own"
)

func TestDefragIPv4AndIPv6(t *testing.T) {
	payload := make([]byte, 3000)
	for i := range payload {
		payload[i] = byte(i * 7)
	}
	// IPv4: three fragments, out of order, with an identical overlap.
	f := own.NewDefrag(16 << 20)
	ip := make([]byte, 20)
	copy(ip[12:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	ip[9] = 6
	binary.BigEndian.PutUint16(ip[4:], 77)
	frag := func(off int, more bool) []byte {
		v := uint16(off / 8)
		if more {
			v |= 0x2000
		}
		binary.BigEndian.PutUint16(ip[6:], v)
		return ip
	}
	order := []struct {
		off, end int
		more     bool
	}{{1480, 2960, true}, {2960, 3000, false}, {0, 1480, true}}
	var got []byte
	var ok bool
	for _, o := range order {
		k, off, more := own.IPv4Frag(frag(o.off, o.more))
		got, ok = f.Add(k, off, more, payload[o.off:o.end])
	}
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("IPv4: ok=%v, %d bytes", ok, len(got))
	}
	// IPv6: the same through the Fragment header.
	src, dst := netip.MustParseAddr("fd00::1"), netip.MustParseAddr("fd00::2")
	h := make([]byte, 8)
	h[0] = 6
	binary.BigEndian.PutUint32(h[4:], 0xdeadbeef)
	for _, o := range order {
		v := uint16(o.off/8) << 3
		if o.more {
			v |= 1
		}
		binary.BigEndian.PutUint16(h[2:], v)
		k, next, off, more := own.IPv6Frag(src, dst, h)
		k.Proto = next
		got, ok = f.Add(k, off, more, payload[o.off:o.end])
	}
	if !ok || !bytes.Equal(got, payload) {
		t.Fatalf("IPv6: ok=%v, %d bytes", ok, len(got))
	}
	// Budget: a datagram that never completes is dropped when the budget bites.
	small := own.NewDefrag(1000)
	k, _, _ := own.IPv4Frag(frag(0, true))
	small.Add(k, 0, true, payload[:800])
	k.ID++
	small.Add(k, 0, true, payload[:800])
	if small.Dropped != 1 {
		t.Fatalf("dropped %d, want 1", small.Dropped)
	}
}
