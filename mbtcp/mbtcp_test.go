// SPDX-License-Identifier: MIT

package mbtcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"net/netip"
	"strings"
	"testing"
)

type rec struct{ out []string }

func (r *rec) ADU(a *ADU) {
	r.out = append(r.out, fmt.Sprintf("adu@%d tid=%d pid=%d size=%d pdu=%x miss=%d flags=%d", a.Pos, a.TID, a.ProtoID, a.Size, a.PDU, a.Missing, a.Flags))
}
func (r *rec) Resync(pos uint64, skipped int, c Confidence) {
	r.out = append(r.out, fmt.Sprintf("resync@%d skipped=%d %s", pos, skipped, c))
}
func (r *rec) Junk(pos uint64, n int, why JunkReason) {
	r.out = append(r.out, fmt.Sprintf("junk@%d n=%d %s", pos, n, why))
}

func mbap(tid, pid uint16, unit uint8, pdu ...byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, tid)
	b = binary.BigEndian.AppendUint16(b, pid)
	b = binary.BigEndian.AppendUint16(b, uint16(1+len(pdu)))
	b = append(b, unit)
	return append(b, pdu...)
}

var read = []byte{3, 0, 0, 0, 1}

func TestFramer(t *testing.T) {
	a1, a2, a3 := mbap(1, 0, 1, read...), mbap(2, 0, 1, read...), mbap(3, 0, 1, read...)
	cases := []struct {
		name string
		run  func(f *Framer)
		want string
	}{
		{"byte by byte", func(f *Framer) {
			for i, c := range append(append([]byte(nil), a1...), a2...) {
				f.Write(uint64(i), []byte{c})
			}
		}, "adu@0 tid=1 pid=0 size=12 pdu=0300000001 miss=0 flags=0|adu@12 tid=2 pid=0 size=12 pdu=0300000001 miss=0 flags=0"},
		{"gap then resync by run end", func(f *Framer) {
			f.Write(0, a1[:5])
			f.Gap(5, 7, false)
			f.Write(12, a2)
		}, "junk@0 n=5 incomplete|resync@12 skipped=0 run_end|adu@12 tid=2 pid=0 size=12 pdu=0300000001 miss=0 flags=1"},
		{"gap then resync by next header", func(f *Framer) {
			f.Gap(0, 100, false)
			f.Write(100, append(append([]byte{9, 9, 9}, a2...), a3...))
		}, "junk@100 n=3 skipped|resync@103 skipped=3 next_header|adu@103 tid=2 pid=0 size=12 pdu=0300000001 miss=0 flags=1|adu@115 tid=3 pid=0 size=12 pdu=0300000001 miss=0 flags=0"},
		{"foreign protocol is skipped by its length", func(f *Framer) {
			f.Write(0, bytes.Join([][]byte{a1, mbap(9, 7, 1, 0x41, 1), a3}, nil))
		}, "adu@0 tid=1 pid=0 size=12 pdu=0300000001 miss=0 flags=0|adu@12 tid=9 pid=7 size=9 pdu=4101 miss=0 flags=2|adu@21 tid=3 pid=0 size=12 pdu=0300000001 miss=0 flags=0"},
		{"snap length cut inside an ADU keeps sync", func(f *Framer) {
			f.Write(0, a1[:8])
			f.Gap(8, 4, true)
			f.Write(12, a2)
		}, "adu@0 tid=1 pid=0 size=12 pdu=03 miss=4 flags=4|adu@12 tid=2 pid=0 size=12 pdu=0300000001 miss=0 flags=0"},
		{"snap cut with the rest of the ADU in the next segment", func(f *Framer) {
			f.Write(0, a1[:8])
			f.Gap(8, 2, true)
			f.Write(10, append(append([]byte(nil), a1[10:]...), a2...))
		}, "adu@0 tid=1 pid=0 size=12 pdu=03 miss=4 flags=4|adu@12 tid=2 pid=0 size=12 pdu=0300000001 miss=0 flags=0"},
		{"incomplete at the end", func(f *Framer) {
			f.Write(0, a1[:9])
			f.Close()
		}, "junk@0 n=9 incomplete"},
		{"resync failure is bounded and reported", func(f *Framer) {
			f.Gap(0, 1, false)
			f.Write(1, bytes.Repeat([]byte{0xff}, 40))
			f.Close()
		}, "junk@1 n=16 resync_failed|junk@17 n=16 resync_failed|junk@33 n=8 resync_failed"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			r := &rec{}
			f := NewFramer(16, r)
			tc.run(f)
			if got := strings.Join(r.out, "|"); got != tc.want {
				t.Errorf("\n got  %s\n want %s", got, tc.want)
			}
		})
	}
}

func TestShapes(t *testing.T) {
	s := func(b ...byte) *Sample { x := NewSample(0, 0, 0, b); return &x }
	reqs := []*Sample{s(3, 0, 0, 0, 10), s(1, 0, 0, 7, 208), s(5, 0, 1, 0xff, 0), s(6, 0, 1, 0, 9), s(7), s(8, 0, 0, 1, 2),
		s(15, 0, 0, 0, 9, 2, 0xff, 1), s(16, 0, 0, 0, 1, 2, 0, 1), s(20, 7, 6, 0, 1, 0, 0, 0, 2), s(22, 0, 1, 0, 0, 0xff, 0xff),
		s(23, 0, 0, 0, 1, 0, 1, 0, 1, 2, 0, 9), s(24, 0, 1), s(43, 14, 1, 0)}
	for _, r := range reqs {
		if !RequestShape(r) {
			t.Errorf("request % x: not a request", r.Head[:min(int(r.Len), 10)])
		}
	}
	resps := []*Sample{s(3, 2, 0, 1), s(1, 1, 5), s(5, 0, 1, 0xff, 0), s(16, 0, 0, 0, 1), s(7, 0), s(0x83, 2), s(43, 14, 1, 0)}
	for _, r := range resps {
		if !ResponseShape(r) {
			t.Errorf("response % x: not a response", r.Head[:min(int(r.Len), 10)])
		}
	}
	for _, r := range []*Sample{s(3, 2, 0, 1), s(0x83, 2), s(3, 0, 0, 0, 200), s(99)} {
		if RequestShape(r) {
			t.Errorf("% x: taken for a request", r.Head[:r.Len])
		}
	}
}

func TestDecideRole(t *testing.T) {
	a, b := netip.MustParseAddrPort("10.0.0.1:40000"), netip.MustParseAddrPort("10.0.0.2:1502")
	req := NewSample(1, 7, 1, []byte{3, 0, 0, 0, 2})
	resp := NewSample(2, 7, 1, []byte{3, 4, 0, 1, 0, 2})
	in := RoleInput{Endpoints: [2]netip.AddrPort{a, b}, SYNFrom: -1, SYNACKFrom: -1, ServerPorts: []uint16{502}}
	if r := DecideRole(in); r.Source != RoleUnknown || r.Server != -1 {
		t.Errorf("no evidence: %+v", r)
	}
	in.Samples = [2][]Sample{{req}, {resp}}
	if r := DecideRole(in); r.Source != RoleStructure || r.Server != 1 {
		t.Errorf("structure: %+v", r)
	}
	in.Samples = [2][]Sample{{resp}, {req}} // now direction 1 sends the request
	if r := DecideRole(in); r.Source != RoleStructure || r.Server != 0 {
		t.Errorf("structure, mirrored: %+v", r)
	}
	in.SYNACKFrom = 0
	if r := DecideRole(in); r.Source != RoleSYN || r.Server != 0 {
		t.Errorf("SYN+ACK: %+v", r)
	}
	in.Clients = []netip.AddrPort{netip.AddrPortFrom(b.Addr(), 0)}
	if r := DecideRole(in); r.Source != RoleOverride || r.Server != 0 {
		t.Errorf("override: %+v", r)
	}
}
