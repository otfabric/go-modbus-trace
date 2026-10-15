// SPDX-License-Identifier: MIT

package selection

import (
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
)

func TestMatch(t *testing.T) {
	t0 := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	at := t0.Add(90 * time.Second)
	tx := &model.Transaction{Conn: 3, Client: netip.MustParseAddrPort("10.0.0.1:40000"), Server: netip.MustParseAddrPort("10.0.0.2:502"),
		Unit: 1, Function: 3, Status: "ok", Class: "read", Flags: []string{"midstream"},
		Ranges:  []mbtcp.Range{{Space: mbtcp.Holding, Start: 4096, Count: 10}},
		Request: &model.ADU{First: &at}}
	d := func(x time.Duration) *time.Duration { return &x }
	cases := []struct {
		name string
		s    Selection
		want bool
	}{
		{"everything", Selection{}, true},
		{"server ip", Selection{Servers: []netip.AddrPort{netip.AddrPortFrom(netip.MustParseAddr("10.0.0.2"), 0)}}, true},
		{"server port mismatch", Selection{Servers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:1502")}}, false},
		{"client", Selection{Clients: []netip.Addr{netip.MustParseAddr("10.0.0.9")}}, false},
		{"unit", Selection{Units: []uint8{1, 2}}, true},
		{"conn", Selection{Conns: []uint32{4}}, false},
		{"function", Selection{Functions: []uint8{4}}, false},
		{"status", Selection{Statuses: []string{"ok"}}, true},
		{"class", Selection{Classes: []string{"write"}}, false},
		{"required flag", Selection{Require: []string{"midstream"}}, true},
		{"excluded flag", Selection{Exclude: []string{"midstream"}}, false},
		{"window by offsets", Selection{FromOffset: d(time.Minute), ToOffset: d(2 * time.Minute)}, true},
		{"before the window", Selection{FromOffset: d(2 * time.Minute)}, false},
		{"end is exclusive", Selection{ToOffset: d(90 * time.Second)}, false},
		{"range overlaps", Selection{Space: mbtcp.Holding, Start: 4105, End: 4200}, true},
		{"range after", Selection{Space: mbtcp.Holding, Start: 4106, End: 4200}, false},
		{"other space", Selection{Space: mbtcp.Input, Start: 0, End: 65535}, false},
	}
	for _, c := range cases {
		c.s.Resolve(t0)
		if got := c.s.Match(tx); got != c.want {
			t.Errorf("%s: %v (%s)", c.name, got, c.s.String())
		}
	}
	s := Selection{Units: []uint8{1, 2}, Functions: []uint8{3}, FromOffset: d(10 * time.Minute), Space: mbtcp.Holding, Start: 1, End: 9}
	if got := s.String(); got != "unit=1,2; fc=3; from=10m0s; range=holding:1-9" {
		t.Errorf("String %q", got)
	}
}
