// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// The tests of this file hold a limit to what it is for: the memory behind
// it. Each feeds a trace made to grow one kind of state without end, and
// measures the live heap against a budget derived from the limit, at the
// point of the trace where the state is largest.

// liveHeap returns the bytes of live heap objects after a collection.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// marker is the client of the connection a budget trace ends with. When it
// opens, every packet before it went through the pipeline and nothing was
// flushed yet: the state is at its largest.
var marker = netip.MustParseAddrPort("10.250.250.250:40000")

func clientN(i int) netip.AddrPort {
	return netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, byte(1 + i>>16), byte(i >> 8), byte(i)}), 40000)
}

// budgetTrace builds a trace of n connections, each written by conn, and
// the marker connection.
func budgetTrace(t *testing.T, n int, conn func(c *tracetest.Conn, i int)) []byte {
	t.Helper()
	data, _ := build(t, tracetest.Options{CountOnly: true}, func(b *tracetest.Builder) {
		for i := range n {
			conn(b.Conn(tracetest.ConnOptions{Client: clientN(i)}), i)
		}
		b.Conn(tracetest.ConnOptions{Client: marker})
	})
	return data
}

type measured struct {
	held     uint64 // live heap at the marker, over the heap before the pass
	sum      *FileSummary
	statuses map[string]int // transactions by status
	closes   map[string]int // connections by how they closed
}

// analyzeAtMarker runs Analyze over data and measures the live heap when
// the marker connection opens.
func analyzeAtMarker(t *testing.T, data []byte, o Options) measured {
	t.Helper()
	m := measured{statuses: map[string]int{}, closes: map[string]int{}}
	seen := false
	before := liveHeap()
	sum, err := Analyze(context.Background(), OpenReader(bytes.NewReader(data)), o, SinkFunc(func(e *model.Event) error {
		switch {
		case e.Txn != nil:
			m.statuses[e.Txn.Status]++
		case e.Kind == model.KindConnClose:
			m.closes[e.Conn.Close]++
		case e.Kind == model.KindConnOpen && e.Conn.Client == marker:
			at := liveHeap()
			m.held, seen = at-min(at, before), true
		}
		return nil
	}))
	if err != nil || !seen || sum.InternalErrorCount != 0 {
		t.Fatalf("err %v, marker seen %v, internal errors %+v", err, seen, sum.InternalErrors)
	}
	m.sum = sum
	runtime.KeepAlive(data)
	return m
}

const kib, mib = 1 << 10, 1 << 20

// TestAnalyzeKeepsNoFlowList: Analyze reports connections as events and
// keeps nothing of a connection that closed, so what it holds does not grow
// with the number of connections in the trace: twenty times as many short
// connections as the connection limit leave the same live heap as twice as
// many.
func TestAnalyzeKeepsNoFlowList(t *testing.T) {
	const maxConns = 1000
	o := Options{ScanOptions: ScanOptions{Limits: Limits{MaxConns: maxConns}}}
	short := func(c *tracetest.Conn, _ int) { c.Close() }
	few := analyzeAtMarker(t, budgetTrace(t, 2*maxConns, short), o)
	many := analyzeAtMarker(t, budgetTrace(t, 20*maxConns, short), o)
	t.Logf("%d connections: %d KiB live; %d connections: %d KiB live", 2*maxConns, few.held/kib, 20*maxConns, many.held/kib)
	if many.sum.Connections.Total != 20*maxConns+1 || many.sum.Connections.FlowsDropped != 0 {
		t.Errorf("connections %+v", many.sum.Connections)
	}
	// The connection table is full in both passes; the rest is the same.
	if budget := few.held + mib/2; many.held > budget {
		t.Errorf("%d bytes live after %d connections, %d after %d: the state grows with the trace", many.held, 20*maxConns, few.held, 2*maxConns)
	}
}

// TestMaxFlows: Scan returns at most Limits.MaxFlows flows, those of the
// connections that closed first, and counts the others; at the limit and
// below it every flow is returned. The list is bounded by the limit in heap
// bytes too.
func TestMaxFlows(t *testing.T) {
	const limit = 300
	short := func(c *tracetest.Conn, _ int) { c.Close() }
	for _, c := range []struct {
		conns   int // with the marker connection
		flows   int
		dropped uint64
	}{{limit - 1, limit - 1, 0}, {limit, limit, 0}, {limit + 1, limit, 1}, {20 * limit, limit, 19 * limit}} {
		data := budgetTrace(t, c.conns-1, short)
		before := liveHeap()
		sum, flows, err := Scan(context.Background(), OpenReader(bytes.NewReader(data)), ScanOptions{Limits: Limits{MaxFlows: limit, MaxConns: 100}})
		after := liveHeap()
		if err != nil || len(flows) != c.flows || sum.Connections.FlowsDropped != c.dropped || sum.Connections.Total != uint64(c.conns) {
			t.Fatalf("%d connections: err %v, %d flows, connections %+v; want %d flows, %d dropped", c.conns, err, len(flows), sum.Connections, c.flows, c.dropped)
		}
		for i, f := range flows {
			if f.ID != uint32(i+1) {
				t.Fatalf("%d connections: flow %d has ID %d: not the first to close, in order", c.conns, i, f.ID)
			}
		}
		// A flow is under 400 bytes with its two times; the list may have
		// grown by a quarter beyond its length.
		if held, budget := after-min(after, before), uint64(limit*kib+64*kib); held > budget {
			t.Errorf("%d connections: %d bytes live with the result, budget %d", c.conns, held, budget)
		}
		runtime.KeepAlive(data)
		runtime.KeepAlive(flows)
	}
	if n := (Limits{}).withDefaults().MaxFlows; n != 1_000_000 {
		t.Errorf("default MaxFlows %d", n)
	}
}

// requestCost is what one read request waiting for its response is charged
// against the analysis budget: its PDU of 5 bytes came in one packet.
const requestCost = costADU + 5*costByte + costRef

// unanswered writes n read requests that get no response.
func unanswered(n int) func(c *tracetest.Conn, _ int) {
	return func(c *tracetest.Conn, _ int) {
		for i := range n {
			c.Request(uint16(i), 1, rd3)
		}
	}
}

// TestAnalysisBudget: the requests waiting for a response over all
// connections are bounded by Limits.AnalysisBudget. Past it the connection
// that waited longest decides its oldest request unanswered and uncertain,
// and each is counted. At the budget and below it nothing is decided early.
func TestAnalysisBudget(t *testing.T) {
	t.Run("at the boundary", func(t *testing.T) {
		const fit = 10
		for _, c := range []struct {
			requests int
			early    int
		}{{fit - 1, 0}, {fit, 0}, {fit + 1, 1}, {fit + 5, 5}} {
			o := Options{ScanOptions: ScanOptions{Limits: Limits{AnalysisBudget: fit * requestCost}}}
			m := analyzeAtMarker(t, budgetTrace(t, 1, unanswered(c.requests)), o)
			if m.statuses[model.StatusUncertain] != c.early || m.sum.Quality.AnalysisBudget != uint64(c.early) ||
				m.statuses[model.StatusUnanswered] != c.requests-c.early || m.closes["evicted"] != 0 {
				t.Errorf("%d requests, room for %d: %v, counter %d, closes %v", c.requests, fit, m.statuses, m.sum.Quality.AnalysisBudget, m.closes)
			}
		}
	})
	t.Run("many connections", func(t *testing.T) {
		// 60 connections with 256 requests each (the limit per connection)
		// would hold 15,360 requests, eight times the budget.
		const (
			conns, each = 60, 256
			budget      = 2 * mib
		)
		data := budgetTrace(t, conns, unanswered(each))
		m := analyzeAtMarker(t, data, Options{ScanOptions: ScanOptions{Limits: Limits{AnalysisBudget: budget}}})
		early := conns*each - budget/requestCost
		t.Logf("%d requests in %d KiB of trace: %d KiB live at the end (budget %d KiB), %d decided early", conns*each, len(data)/kib, m.held/kib, budget/kib, m.sum.Quality.AnalysisBudget)
		if m.statuses[model.StatusUncertain] != early || m.sum.Quality.AnalysisBudget != uint64(early) ||
			m.statuses[model.StatusUnanswered] != conns*each-early || m.closes["evicted"] != 0 {
			t.Errorf("%v, counter %d, closes %v; want %d decided early", m.statuses, m.sum.Quality.AnalysisBudget, m.closes, early)
		}
		// The budget, the connections' own state and the reader's buffers.
		if limit := uint64(budget + conns*8*kib + mib); m.held > limit {
			t.Errorf("%d bytes live, limit %d", m.held, limit)
		}
	})
	t.Run("the default budget is not reached by a full connection table's worth of polls", func(t *testing.T) {
		// One request outstanding on each of 4,000 connections: nothing is
		// decided early.
		m := analyzeAtMarker(t, budgetTrace(t, 4000, unanswered(1)), Options{})
		if m.sum.Quality.AnalysisBudget != 0 || m.statuses[model.StatusUncertain] != 0 || m.statuses[model.StatusUnanswered] != 4000 {
			t.Errorf("%v, counter %d", m.statuses, m.sum.Quality.AnalysisBudget)
		}
	})
}

// TestAnalysisBudgetUndecidedRoles: ADUs held while a connection's roles
// are undecided are charged too. Past the budget the roles of the
// connection that waited longest are decided with what there is, and its
// ADUs are reported.
func TestAnalysisBudgetUndecidedRoles(t *testing.T) {
	const conns, each = 200, 40
	data, _ := build(t, tracetest.Options{CountOnly: true}, func(b *tracetest.Builder) {
		for i := range conns { // no handshake, no known port: the roles wait for both directions
			c := b.Conn(tracetest.ConnOptions{Client: clientN(i), Server: netip.MustParseAddrPort("10.0.0.2:1502"), Midstream: true})
			for k := range each {
				c.Request(uint16(k), 1, rd3)
			}
		}
		b.Conn(tracetest.ConnOptions{Client: marker})
	})
	const budget = mib
	m := analyzeAtMarker(t, data, Options{ScanOptions: ScanOptions{Limits: Limits{AnalysisBudget: budget}}})
	t.Logf("%d held ADUs: %d KiB live at the end (budget %d KiB), the budget freed state %d times, %v", conns*each, m.held/kib, budget/kib, m.sum.Quality.AnalysisBudget, m.statuses)
	total := 0
	for _, n := range m.statuses {
		total += n
	}
	if total != conns*each || m.sum.Quality.AnalysisBudget == 0 || m.closes["evicted"] != 0 {
		t.Errorf("%d transactions of %d ADUs, counter %d, closes %v", total, conns*each, m.sum.Quality.AnalysisBudget, m.closes)
	}
	if limit := uint64(budget + conns*8*kib + mib); m.held > limit {
		t.Errorf("%d bytes live, limit %d", m.held, limit)
	}
}

// TestAnalysisBudgetChunks: the provenance of bytes being framed is charged
// too. Connections that each hold an ADU cut after its first bytes, sent one
// byte per packet, hold nothing a decision could free: past the budget the
// one that waited longest is closed as evicted, and counted.
func TestAnalysisBudgetChunks(t *testing.T) {
	const conns, bytesEach = 300, 100
	part := tracetest.MBAP(1, 1, make([]byte, 250))[:bytesEach] // the header announces 250 bytes of PDU
	part[7] = 3
	data := budgetTrace(t, conns, func(c *tracetest.Conn, _ int) {
		c.Write(tracetest.ToServer, tracetest.WriteOpts{OneByte: true}, tracetest.Frame{Raw: part})
	})
	const budget = 256 * kib
	m := analyzeAtMarker(t, data, Options{ScanOptions: ScanOptions{Limits: Limits{AnalysisBudget: budget}}})
	room := budget / (bytesEach * costChunk)
	t.Logf("%d connections with %d chunks each: %d KiB live at the end (budget %d KiB), %d evicted", conns, bytesEach, m.held/kib, budget/kib, m.sum.Connections.Evicted)
	if got := m.sum.Connections.Evicted; got != uint64(conns-room) || m.sum.Quality.AnalysisBudget != got || m.closes["evicted"] != conns-room {
		t.Errorf("%d evicted, counter %d, closes %v; want %d", got, m.sum.Quality.AnalysisBudget, m.closes, conns-room)
	}
	if limit := uint64(budget + conns*8*kib + mib); m.held > limit {
		t.Errorf("%d bytes live, limit %d", m.held, limit)
	}
	// At the default budget the same trace keeps every connection.
	if m := analyzeAtMarker(t, data, Options{}); m.sum.Connections.Evicted != 0 || m.sum.Quality.AnalysisBudget != 0 {
		t.Errorf("default budget: %d evicted, counter %d", m.sum.Connections.Evicted, m.sum.Quality.AnalysisBudget)
	}
}

// TestChunksOfJunkAreDropped: a direction keeps the provenance of the bytes
// its framer can still frame, not of the bytes it passed over. A megabyte of
// bytes that frame as nothing, one byte per packet, leaves no more chunks
// than a framer's window.
func TestChunksOfJunkAreDropped(t *testing.T) {
	junk := make([]byte, 30000) // under the resync scan limit: nothing is reported in between
	for i := range junk {
		junk[i] = 0xEE
	}
	data := budgetTrace(t, 1, func(c *tracetest.Conn, _ int) {
		c.Write(tracetest.ToServer, tracetest.WriteOpts{OneByte: true}, tracetest.Frame{Raw: junk})
	})
	// Room for the window's chunks and no more: nothing is evicted.
	o := Options{ScanOptions: ScanOptions{Limits: Limits{AnalysisBudget: (framerWindow + 2) * costChunk}}}
	if m := analyzeAtMarker(t, data, o); m.sum.Connections.Evicted != 0 || m.sum.Quality.AnalysisBudget != 0 || m.sum.Quality.JunkBytes != uint64(len(junk)) {
		t.Errorf("%d evicted, counter %d, quality %+v", m.sum.Connections.Evicted, m.sum.Quality.AnalysisBudget, m.sum.Quality)
	}
}

// TestMaxConnsHeap: the state of the tracked connections is bounded by
// Limits.MaxConns in heap bytes: five times as many open connections as the
// limit, each with a request waiting, leave what the limit allows.
func TestMaxConnsHeap(t *testing.T) {
	const (
		maxConns = 2000
		perConn  = 8 * kib // a tracked connection with one request waiting, generously
	)
	o := Options{ScanOptions: ScanOptions{Limits: Limits{MaxConns: maxConns}}}
	m := analyzeAtMarker(t, budgetTrace(t, 5*maxConns, unanswered(1)), o)
	t.Logf("%d open connections, %d tracked: %d KiB live (%d bytes per tracked connection)", 5*maxConns, maxConns, m.held/kib, m.held/maxConns)
	if m.sum.Connections.Evicted != 4*maxConns+1 || m.sum.Connections.MaxTracked != maxConns {
		t.Errorf("connections %+v", m.sum.Connections)
	}
	if limit := uint64(maxConns*perConn + mib); m.held > limit {
		t.Errorf("%d bytes live, limit %d", m.held, limit)
	}
}

// TestMaxOutstandingHeap: the requests one connection keeps waiting are
// bounded by Options.MaxOutstanding in heap bytes.
func TestMaxOutstandingHeap(t *testing.T) {
	const limit, requests = 256, 10000
	m := analyzeAtMarker(t, budgetTrace(t, 1, unanswered(requests)), Options{MaxOutstanding: limit})
	t.Logf("%d requests, %d waiting: %d KiB live", requests, limit, m.held/kib)
	if m.statuses[model.StatusUncertain] != requests-limit || m.statuses[model.StatusUnanswered] != limit || m.sum.Quality.AnalysisBudget != 0 {
		t.Errorf("%v, analysis budget counter %d", m.statuses, m.sum.Quality.AnalysisBudget)
	}
	if max := uint64(limit*requestCost + mib); m.held > max {
		t.Errorf("%d bytes live, limit %d", m.held, max)
	}
}

// TestFramesAllocation: reading a packet back by reference costs the same
// whatever the number of interfaces in the file: the interface table is
// looked up, not copied.
func TestFramesAllocation(t *testing.T) {
	perCall := func(interfaces int) uint64 {
		data, _ := build(t, tracetest.Options{Format: tracetest.PcapNG, Interfaces: make([]tracetest.Iface, interfaces)}, func(b *tracetest.Builder) {
			c := b.Conn(tracetest.ConnOptions{Iface: interfaces - 1})
			poll(c, 1, 2)
			c.Close()
		})
		path := filepath.Join(t.TempDir(), "t.pcapng")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		f, err := Open(path)
		if err != nil {
			t.Fatal(err)
		}
		var refs []model.FrameRef
		if _, err := Analyze(context.Background(), f, Options{}, SinkFunc(func(e *model.Event) error {
			if e.Txn != nil && len(refs) == 0 {
				refs = e.Txn.Request.Refs
			}
			return nil
		})); err != nil || len(refs) != 1 {
			t.Fatalf("err %v, refs %v", err, refs)
		}
		if frs, err := f.Frames(refs); err != nil || len(frs) != 1 || len(frs[0].Payload) != 12 { // builds the index
			t.Fatalf("frames %v, %v", frs, err)
		}
		const calls = 200
		var before, after runtime.MemStats
		runtime.ReadMemStats(&before)
		for range calls {
			if _, err := f.Frames(refs); err != nil {
				t.Fatal(err)
			}
		}
		runtime.ReadMemStats(&after)
		return (after.TotalAlloc - before.TotalAlloc) / calls
	}
	few, many := perCall(2), perCall(20000)
	t.Logf("%d bytes allocated per call with 2 interfaces, %d with 20000", few, many)
	if many > few+kib || many > 8*kib {
		t.Errorf("a Frames call allocates %d bytes with 20000 interfaces and %d with 2", many, few)
	}
}

// TestReaderLimits: the limits of the file reader are those of Limits. An
// interface block past MaxInterfaces is skipped and counted with the
// packets on it; a section past MaxSections ends the read with ErrCorrupt
// and the summary so far.
func TestReaderLimits(t *testing.T) {
	data, _ := build(t, tracetest.Options{Format: tracetest.PcapNG, Interfaces: make([]tracetest.Iface, 5)}, func(b *tracetest.Builder) {
		for i := range 5 {
			c := b.Conn(tracetest.ConnOptions{Client: clientN(i), Iface: i})
			poll(c, 1, 1)
			c.Close()
		}
	})
	sum, flows, err := Scan(context.Background(), OpenReader(bytes.NewReader(data)), ScanOptions{Limits: Limits{MaxInterfaces: 3}})
	if err != nil || len(sum.Interfaces) != 3 || len(flows) != 3 || sum.Reader.SkippedBlocks != 2+2*uint64(sum.Interfaces[0].Packets) {
		t.Errorf("err %v, %d interfaces, %d flows, reader %+v", err, len(sum.Interfaces), len(flows), sum.Reader)
	}
	sum, flows, err = Scan(context.Background(), OpenReader(bytes.NewReader(data)), ScanOptions{})
	if err != nil || len(sum.Interfaces) != 5 || len(flows) != 5 || sum.Reader.SkippedBlocks != 0 {
		t.Errorf("default limits: err %v, %d interfaces, %d flows, reader %+v", err, len(sum.Interfaces), len(flows), sum.Reader)
	}
	two := append(bytes.Clone(data), data...) // two sections
	sum, flows, err = Scan(context.Background(), OpenReader(bytes.NewReader(two)), ScanOptions{Limits: Limits{MaxSections: 1}})
	if !errors.Is(err, ErrCorrupt) || sum == nil || sum.Error == "" || len(sum.Sections) != 1 || len(flows) != 5 || sum.Packets != uint64(5*sum.Interfaces[0].Packets) {
		t.Errorf("one section allowed: err %v, summary %+v, %d flows", err, sum, len(flows))
	}
	if sum, _, err = Scan(context.Background(), OpenReader(bytes.NewReader(two)), ScanOptions{}); err != nil || len(sum.Sections) != 2 || len(sum.Interfaces) != 10 {
		t.Errorf("default limits, two sections: err %v, %d sections, %d interfaces", err, len(sum.Sections), len(sum.Interfaces))
	}
	if d := (Limits{}).withDefaults(); d.MaxInterfaces != 65536 || d.MaxSections != 65536 || d.AnalysisBudget != 64*mib {
		t.Errorf("defaults %+v", d)
	}
}
