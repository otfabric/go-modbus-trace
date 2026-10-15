// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"encoding/binary"
	"net/netip"
	"testing"
)

func tcp(payload string) []byte {
	t := []byte{0x9c, 0x40, 0x01, 0xf6, 0, 0, 0, 1, 0, 0, 0, 2, 5 << 4, ACK | PSH, 0xff, 0xff, 0, 0, 0, 0}
	return append(t, payload...)
}

func ipv4(proto uint8, opts int, payload []byte) []byte {
	ihl := 20 + opts
	ip := make([]byte, ihl)
	ip[0], ip[9] = 0x40|byte(ihl/4), proto
	binary.BigEndian.PutUint16(ip[2:], uint16(ihl+len(payload)))
	copy(ip[12:], []byte{10, 0, 0, 1, 10, 0, 0, 2})
	return append(ip, payload...)
}

func ipv6(next uint8, payload []byte) []byte {
	ip := make([]byte, 40)
	ip[0], ip[6] = 0x60, next
	binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
	ip[23], ip[39] = 1, 2
	return append(ip, payload...)
}

func ether(typ uint16, b []byte) []byte {
	e := append(make([]byte, 12), byte(typ>>8), byte(typ))
	return append(e, b...)
}

func TestDecode(t *testing.T) {
	cases := []struct {
		name    string
		link    uint16
		data    []byte
		want    Reason
		payload string
		payOff  int
	}{
		{"IPv4 with options", LinkRaw, ipv4(6, 8, tcp("hello")), OK, "hello", 48},
		{"Ethernet padding is not data", LinkEthernet, append(ether(0x0800, ipv4(6, 0, tcp("x"))), make([]byte, 5)...), OK, "x", 54},
		{"IPv6 with hop-by-hop and destination options", LinkIPv6,
			ipv6(0, append([]byte{60, 0, 0, 0, 0, 0, 0, 0}, append([]byte{6, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0}, tcp("v6")...)...)), OK, "v6", 84},
		{"too many extension headers", LinkIPv6, ipv6(0, bytes.Repeat([]byte{0, 0, 0, 0, 0, 0, 0, 0}, 10)), ExtHeaders, "", 0},
		{"AH", LinkIPv6, ipv6(51, make([]byte, 16)), IPsec, "", 0},
		{"ESP", LinkRaw, ipv4(50, 0, make([]byte, 16)), IPsec, "", 0},
		{"GRE", LinkRaw, ipv4(47, 0, make([]byte, 16)), Tunnel, "", 0},
		{"IPv4 in IPv4", LinkRaw, ipv4(4, 0, ipv4(6, 0, tcp(""))), Tunnel, "", 0},
		{"UDP", LinkRaw, ipv4(17, 0, []byte{0, 1, 0, 2, 0, 8, 0, 0}), NotTCP, "", 0},
		{"ARP", LinkEthernet, ether(0x0806, make([]byte, 28)), NotIP, "", 0},
		{"unsupported link", 147, []byte{1, 2, 3}, LinkUnsupported, "", 0},
		{"short TCP header", LinkRaw, ipv4(6, 0, tcp("")[:12]), Short, "", 0},
		{"bad IHL", LinkRaw, append([]byte{0x41}, ipv4(6, 0, tcp(""))[1:]...), BadHeader, "", 0},
		{"bad TCP data offset", LinkRaw, ipv4(6, 0, append(tcp("")[:12], append([]byte{2 << 4}, tcp("")[13:]...)...)), BadHeader, "", 0},
		{"version mismatch", LinkIPv4, ipv6(6, tcp("")), BadHeader, "", 0},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var s Segment
			d := NewDecoder(1 << 20)
			if r := d.Decode(tc.link, tc.data, &s); r != tc.want {
				t.Fatalf("reason %v, want %v", r, tc.want)
			}
			if tc.want == OK && (string(s.Payload) != tc.payload || s.PayOff != tc.payOff || !bytes.Equal(tc.data[s.PayOff:s.PayOff+len(s.Payload)], s.Payload)) {
				t.Errorf("payload %q at %d", s.Payload, s.PayOff)
			}
		})
	}
}

func TestSnaplenMissing(t *testing.T) {
	full := ipv4(6, 0, tcp("0123456789"))
	var s Segment
	if r := NewDecoder(1).Decode(LinkRaw, full[:44], &s); r != OK || string(s.Payload) != "0123" || s.Missing != 6 {
		t.Fatalf("reason %v payload %q missing %d", r, s.Payload, s.Missing)
	}
}

func TestSLL2InterfaceIndex(t *testing.T) {
	h := []byte{0x08, 0x00, 0, 0, 0, 0, 0, 7, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0}
	var s Segment
	if r := NewDecoder(1).Decode(LinkSLL2, append(h, ipv4(6, 0, tcp("a"))...), &s); r != OK || s.IfIndex != 7 {
		t.Fatalf("reason %v ifindex %d", r, s.IfIndex)
	}
}

func TestDefrag(t *testing.T) {
	k := FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), ID: 1, Proto: 6}
	data := bytes.Repeat([]byte("0123456789abcdef"), 4)
	t.Run("out of order with an overlap", func(t *testing.T) {
		f := NewDefrag(1 << 16)
		if _, r := f.Add(k, 32, false, data[32:]); r != FragmentHeld {
			t.Fatal(r)
		}
		if _, r := f.Add(k, 8, true, data[8:40]); r != FragmentHeld {
			t.Fatal(r)
		}
		got, r := f.Add(k, 0, true, data[:16])
		if r != OK || !bytes.Equal(got, data) || f.Pending != 0 || f.Datagrams != 1 {
			t.Fatalf("%v %q pending %d", r, got, f.Pending)
		}
	})
	t.Run("invalid fragments", func(t *testing.T) {
		f := NewDefrag(1 << 16)
		for _, c := range []struct {
			off  int
			more bool
			data []byte
		}{{0, true, nil}, {65530, false, data}, {0, true, data[:5]}} {
			if _, r := f.Add(k, c.off, c.more, c.data); r != FragmentBad {
				t.Errorf("%+v: %v", c, r)
			}
		}
		f.Add(k, 16, false, data[:16])                               // ends at 32
		if _, r := f.Add(k, 8, false, data[:16]); r != FragmentBad { // ends at 24
			t.Error("two different last fragments")
		}
	})
	t.Run("budget", func(t *testing.T) {
		f := NewDefrag(300) // one datagram of 32 bytes costs 32+fragOverhead+datagramOverhead
		f.Add(k, 0, true, data[:32])
		k2 := k
		k2.ID = 2
		f.Add(k2, 0, true, data[:32])
		if f.Dropped != 1 || f.Pending != 1 {
			t.Fatalf("dropped %d pending %d", f.Dropped, f.Pending)
		}
	})
}

func FuzzLinkIPTCP(f *testing.F) {
	f.Add(uint16(LinkEthernet), ether(0x0800, ipv4(6, 4, tcp("seed"))))
	f.Add(uint16(LinkRaw), ipv6(44, append([]byte{6, 0, 0, 1, 0, 0, 0, 9}, tcp("frag")...)))
	f.Add(uint16(LinkSLL), append(make([]byte, 14), append([]byte{0x86, 0xdd}, ipv6(0, make([]byte, 30))...)...))
	f.Fuzz(func(t *testing.T, lt uint16, b []byte) {
		d := NewDecoder(1 << 12)
		var s Segment
		for range 3 { // fragments may complete on a repeat
			if d.Decode(lt, b, &s) == OK {
				if len(s.Payload) > len(b)+65535 {
					t.Fatal("payload larger than possible")
				}
				if s.PayOff >= 0 && !bytes.Equal(b[s.PayOff:s.PayOff+len(s.Payload)], s.Payload) {
					t.Fatal("PayOff does not point at the payload")
				}
			}
		}
	})
}

// TestDefragHostile: tiny fragments are charged their overhead, finished
// datagrams leave no order entries behind, and nested fragment headers
// are bounded like other extension headers.
func TestDefragHostile(t *testing.T) {
	f := NewDefrag(testFragBudget)
	k := FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), Proto: 6}
	for i := range 1_000_000 {
		k.ID = uint32(i)
		f.Add(k, 0, true, make([]byte, 8))
		if f.used > testFragBudget {
			t.Fatalf("%d bytes held over a budget of %d", f.used, testFragBudget)
		}
	}
	if f.Pending > testFragBudget/(8+fragOverhead+datagramOverhead) {
		t.Errorf("%d datagrams pending", f.Pending)
	}
	for i := range 100_000 { // complete ones: the order list stays short
		k.ID = uint32(2_000_000 + i)
		if _, r := f.Add(k, 0, false, make([]byte, 8)); r != OK {
			t.Fatalf("reason %v", r)
		}
	}
	if len(f.order) > 2*len(f.m)+64 {
		t.Errorf("%d order entries for %d datagrams", len(f.order), len(f.m))
	}

	// An IPv6 packet whose atomic fragment headers (offset 0, no more
	// fragments) nest: each completes at once, and the chain is bounded
	// like other extension headers.
	ip := make([]byte, 40, 40+8*20)
	ip[0], ip[6] = 0x60, 44
	for i := range 20 {
		next := byte(44)
		if i == 19 {
			next = 6
		}
		ip = append(ip, next, 0, 0, 0, 0, 0, 0, byte(i))
	}
	ip[4], ip[5] = 0, byte(8*20)
	var s Segment
	dec := NewDecoder(1 << 20)
	if r := dec.Decode(LinkRaw, ip, &s); r != ExtHeaders || !dec.Fragment {
		t.Errorf("nested fragment headers: %v, fragment %v", r, dec.Fragment)
	}

	// An IPv4 fragment names its datagram.
	v4 := []byte{0x45, 0, 0, 28, 0x12, 0x34, 0x20, 0, 64, 6, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2, 1, 2, 3, 4, 5, 6, 7, 8}
	if r := dec.Decode(LinkRaw, v4, &s); r != FragmentHeld || !dec.Fragment || dec.Frag.ID != 0x1234 {
		t.Errorf("IPv4 fragment: %v %+v", r, dec.Frag)
	}
	if dec.Decode(LinkRaw, []byte{0x45, 0, 0, 20, 0, 0, 0, 0, 64, 17, 0, 0, 10, 0, 0, 1, 10, 0, 0, 2}, &s); dec.Fragment {
		t.Error("a whole datagram is not a fragment")
	}
}

const testFragBudget = 1 << 20
