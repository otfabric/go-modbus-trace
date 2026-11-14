// SPDX-License-Identifier: MIT

package flow

import (
	"math/bits"
	"net/netip"
	"runtime"
	"testing"

	"github.com/otfabric/go-modbus-trace/internal/link"
	"github.com/otfabric/go-modbus-trace/internal/pcapio"
)

func segment(tr *Tracker, src, dst netip.AddrPort, seq uint32, payload []byte) {
	s := link.Segment{Src: src, Dst: dst, Seq: seq, Flags: link.ACK, Payload: payload}
	tr.Packet(&pcapio.Packet{HasTime: true, TimeNS: 1}, &s)
}

// TestHoldWork: holding out-of-order segments costs work that grows with the
// logarithm of what is held, not with its size: a direction filled to its
// limit with one-byte segments in descending order (each new one is
// delivered before all the others), and the total budget kept full by
// thousands of connections, so that every further segment makes the largest
// holder give up its hole.
func TestHoldWork(t *testing.T) {
	client, server := netip.MustParseAddrPort(cl), netip.MustParseAddrPort(sv)
	t.Run("one direction filled in descending order", func(t *testing.T) {
		r := &recorder{}
		tr := NewTracker(Limits{}, r)
		n := DefaultLimits.BufferPerDir / (heldOverhead + 1) // one-byte segments that fit
		segment(tr, client, server, 1000, []byte{'a'})
		for i := n; i >= 1; i-- {
			segment(tr, client, server, 1001+uint32(2*i), []byte{'x'}) // every other byte: nothing joins
		}
		c := tr.conns[keyOf(client, server)]
		if len(c.dirs[0].pend) != n || tr.Stats.Overflows != 0 {
			t.Fatalf("%d segments held of %d, %d overflows", len(c.dirs[0].pend), n, tr.Stats.Overflows)
		}
		held := tr.work
		tr.Finish() // the holes are declared and every segment delivered, in order
		budget := uint64(n) * uint64(2*bits.Len(uint(n))+2)
		t.Logf("%d segments: %d steps to hold them, %d to deliver them (budget %d each)", n, held, tr.work-held, budget)
		if held > budget || tr.work-held > budget {
			t.Errorf("%d segments took %d steps to hold and %d to deliver, more than %d", n, held, tr.work-held, budget)
		}
		if got := r.data["1/0"]; len(got) != 2*n+2 || got[0] != 'a' || got[3] != 'x' || got[2*n+1] != 'x' {
			t.Errorf("%d bytes delivered", len(got))
		}
	})
	t.Run("the total budget kept full", func(t *testing.T) {
		const (
			conns   = 5000
			further = 20000
			size    = 10
		)
		tr := NewTracker(Limits{MaxConns: conns, BufferTotal: conns * (size + heldOverhead)}, &recorder{data: map[string][]byte{}})
		ends := make([]netip.AddrPort, conns)
		next := make([]uint32, conns)
		payload := make([]byte, size)
		for i := range ends {
			ends[i] = netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, byte(i >> 8), byte(i)}), 40000)
			segment(tr, ends[i], server, 1000, []byte{'a'})
			segment(tr, ends[i], server, 1100, payload) // held behind a hole: the budget is full after the last one
			next[i] = 1100 + size + 100
		}
		if tr.pendAll != conns*(size+heldOverhead) || tr.Stats.BudgetGaps != 0 {
			t.Fatalf("%d bytes held, %d budget gaps", tr.pendAll, tr.Stats.BudgetGaps)
		}
		before := tr.work
		for i := range further { // each needs room: the largest holder gives up its hole
			k := (i * 7) % conns
			segment(tr, ends[k], server, next[k], payload)
			next[k] += size + 100
		}
		work := tr.work - before
		budget := uint64(further) * uint64(6*bits.Len(conns)+8)
		t.Logf("%d further segments over %d connections: %d steps (budget %d), %d budget gaps", further, conns, work, budget, tr.Stats.BudgetGaps)
		if tr.Stats.BudgetGaps < further/2 || tr.pendAll > tr.L.BufferTotal {
			t.Errorf("%d budget gaps, %d bytes held of %d", tr.Stats.BudgetGaps, tr.pendAll, tr.L.BufferTotal)
		}
		if work > budget {
			t.Errorf("%d segments took %d steps, more than %d", further, work, budget)
		}
	})
}

// liveHeap returns the bytes of live heap objects after a collection.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestBufferBudgetHeap: what the tracker holds of out-of-order segments is
// bounded by its limits in heap bytes, not only in the bytes it counts.
// Empty and one-byte segments that never fit (each costs its overhead), and
// full-size ones, are fed far past the limit of one direction and past the
// total budget over many connections; the live heap stays within the limit
// and a third, plus the connections' own state.
func TestBufferBudgetHeap(t *testing.T) {
	server := netip.MustParseAddrPort(sv)
	for _, c := range []struct {
		name         string
		conns        int
		size         int // payload bytes of each held segment
		perDir       int
		total        int
		segments     int // per connection
		perConnState int // heap of a tracked connection besides what it holds
	}{
		{"one direction, one-byte segments", 1, 1, 1 << 20, 64 << 20, 50_000, 4096},
		{"one direction, 1400-byte segments", 1, 1400, 1 << 20, 64 << 20, 5_000, 4096},
		{"the total budget, one-byte segments over 2000 connections", 2000, 1, 1 << 20, 4 << 20, 40, 1024},
	} {
		t.Run(c.name, func(t *testing.T) {
			payload := make([]byte, c.size)
			before := liveHeap()
			tr := NewTracker(Limits{MaxConns: c.conns, BufferPerDir: c.perDir, BufferTotal: c.total, TailKeep: DefaultLimits.TailKeep}, nullHandler{})
			for i := range c.conns {
				segment(tr, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 2, byte(i >> 8), byte(i)}), 40000), server, 1000, []byte{'a'})
			}
			for s := range c.segments {
				for i := range c.conns {
					// Always behind a hole: two bytes are missing before each.
					segment(tr, netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 2, byte(i >> 8), byte(i)}), 40000), server,
						1003+uint32(s*(c.size+2)), payload)
				}
			}
			after := liveHeap()
			held := after - min(after, before)
			limit := min(c.conns*c.perDir, c.total)
			budget := uint64(limit*4/3 + c.conns*c.perConnState)
			t.Logf("%d segments of %d bytes over %d connections: %d KiB counted, %d KiB live (budget %d KiB), %d overflows, %d budget gaps",
				c.segments*c.conns, c.size, c.conns, tr.pendAll>>10, held>>10, budget>>10, tr.Stats.Overflows, tr.Stats.BudgetGaps)
			if tr.pendAll > limit || tr.pendAll < limit/2 || tr.Stats.Overflows+tr.Stats.BudgetGaps == 0 {
				t.Errorf("%d bytes counted, limit %d, %d overflows, %d budget gaps", tr.pendAll, limit, tr.Stats.Overflows, tr.Stats.BudgetGaps)
			}
			if held > budget {
				t.Errorf("%d bytes live, budget %d", held, budget)
			}
			runtime.KeepAlive(tr)
		})
	}
}

type nullHandler struct{}

func (nullHandler) Open(*Conn)                             {}
func (nullHandler) Data(*Conn, int, uint64, []byte, Chunk) {}
func (nullHandler) Repeat(*Conn, int, uint64, uint64)      {}
func (nullHandler) Gap(*Conn, int, uint64, int64, GapKind) {}
func (nullHandler) Close(*Conn)                            {}
