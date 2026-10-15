// SPDX-License-Identifier: MIT

package analyze

import (
	"bytes"
	"context"
	"net/netip"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

func TestAnalyzers(t *testing.T) {
	var buf bytes.Buffer
	b, _ := tracetest.New(&buf, tracetest.Options{})
	c := b.Conn(tracetest.ConnOptions{})
	d := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.5:41000"), Server: netip.MustParseAddrPort("10.0.0.3:502")})
	for i := range 10 {
		c.Request(uint16(i), 1, tracetest.ReadRequest(3, 100, 4))
		c.Response(uint16(i), 1, tracetest.RegistersResponse(3, uint16(i/5), 0, 0, 0)) // changes once
		c.Request(uint16(100+i), 1, tracetest.ReadRequest(3, 104, 2))
		c.Response(uint16(100+i), 1, tracetest.RegistersResponse(3, 1, 2))
		d.Request(uint16(i), 2, tracetest.ReadRequest(4, 0, 1))
		d.Response(uint16(i), 2, tracetest.Exception(4, 2))
		b.Advance(time.Second)
	}
	c.Request(50, 1, []byte{6, 0, 200, 0, 1})
	c.Response(50, 1, []byte{6, 0, 200, 0, 1})
	_ = b.Close()
	ov, dev, pat, cov := NewOverview(), NewDevices(), NewPatterns(), NewCoverage()
	_, err := trace.Analyze(context.Background(), trace.OpenReader(&buf), trace.Options{}, Tee(ov, dev, pat, cov))
	if err != nil {
		t.Fatal(err)
	}
	o := ov.Result()
	if o.Transactions != 31 || o.Connections != 2 || o.ByStatus["exception"] != 10 || o.ByFunction["6"] != 1 || o.ByClass["write"] != 1 ||
		o.DurationNS < int64(9*time.Second) {
		t.Errorf("overview %+v", o)
	}
	dv := dev.Result()
	if len(dv.Devices) != 2 || dv.Devices[0].Server != "10.0.0.2:502" || dv.Devices[0].Transactions != 21 || dv.Devices[1].ByStatus["exception"] != 10 ||
		dv.Devices[0].Latency == nil || dv.Devices[0].Latency.Count != 21 || dv.Devices[0].Clients[0] != "10.0.0.1" {
		t.Errorf("devices %+v", dv)
	}
	pt := pat.Result()
	if len(pt.Patterns) != 4 {
		t.Fatalf("patterns %+v", pt)
	}
	p0 := pt.Patterns[0]
	if p0.Count != 10 || p0.Interval == nil || abs(p0.Interval.P50NS-int64(time.Second)) > int64(20*time.Millisecond) || p0.Summary != "Read 4 holding registers @ 100" ||
		p0.Changed != 1 || p0.Volatility < 0.1 || p0.Volatility > 0.12 || p0.JitterNS > int64(20*time.Millisecond) {
		t.Errorf("pattern %+v %+v", p0, p0.Interval)
	}
	cv := cov.Result()
	if len(cv) != 1 || cv[0].Space != "holding" || len(cv[0].Read) != 1 || cv[0].Read[0].Start != 100 || cv[0].Read[0].End != 105 ||
		cv[0].Read[0].Count != 20 || len(cv[0].Written) != 1 || cv[0].Written[0].Start != 200 {
		t.Errorf("coverage %+v", cv)
	}
}

func abs(x int64) int64 {
	if x < 0 {
		return -x
	}
	return x
}

func TestHistogram(t *testing.T) {
	var h Histogram
	for i := 1; i <= 1000; i++ {
		h.Add(time.Duration(i) * time.Millisecond)
	}
	for q, want := range map[float64]time.Duration{0.5: 500 * time.Millisecond, 0.99: 990 * time.Millisecond} {
		got := h.Quantile(q)
		if d := got - want; d > want/50 || d < -want/50 {
			t.Errorf("q%.2f = %v, want %v", q, got, want)
		}
	}
	if s := h.Stats(); s.MinNS != int64(time.Millisecond) || s.MaxNS != int64(time.Second) {
		t.Errorf("%+v", s)
	}
	var empty Histogram
	if empty.Stats() != nil || empty.Quantile(0.5) != 0 {
		t.Error("empty")
	}
}

func TestCaps(t *testing.T) {
	var list []Interval
	var over uint64
	for i := range MaxIntervals + 10 {
		list = merge(list, Interval{Start: uint16(2 * i), End: uint16(2 * i), Count: 1}, &over)
	}
	if len(list) != MaxIntervals || over != 10 {
		t.Errorf("%d intervals, %d over", len(list), over)
	}
	list = merge(list, Interval{Start: 0, End: 65535, Count: 1}, &over)
	if len(list) != 1 || list[0].Count != MaxIntervals+1 {
		t.Errorf("merged %+v", list[:1])
	}
	dev, pat := NewDevices(), NewPatterns()
	for i := range MaxDevices + 3 {
		tx := &model.Transaction{Server: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 502),
			Client: netip.MustParseAddrPort("10.9.9.9:1"), Unit: 1, Function: 3, Status: "ok",
			Request: &model.ADU{PDU: []byte{3, byte(i >> 8), byte(i), 0, 1}, View: &mbtcp.View{}}}
		_ = dev.Event(&model.Event{Txn: tx})
		_ = pat.Event(&model.Event{Txn: tx})
	}
	if dev.Result().Overflow != 3 || pat.Result().Overflow != 3 {
		t.Errorf("overflow %d %d", dev.Result().Overflow, pat.Result().Overflow)
	}
}

// TestCoverageKeyCap: coverage keeps at most MaxCoverageSpaces server,
// unit and space keys and counts the ranges of the others.
func TestCoverageKeyCap(t *testing.T) {
	c := NewCoverage()
	for i := range MaxCoverageSpaces + 5 {
		srv := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(i >> 16), byte(i >> 8), byte(i)}), 502)
		_ = c.Event(&model.Event{Txn: &model.Transaction{Status: model.StatusOK, Server: srv, Unit: 1,
			Ranges: []mbtcp.Range{{Space: mbtcp.Holding, Start: 0, Count: 1}}}})
	}
	if n := len(c.Result()); n != MaxCoverageSpaces || c.Overflow() != 5 {
		t.Errorf("%d keys, overflow %d", n, c.Overflow())
	}
}
