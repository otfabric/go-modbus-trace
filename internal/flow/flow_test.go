// SPDX-License-Identifier: MIT

package flow

import (
	"fmt"
	"net/netip"
	"testing"

	"github.com/otfabric/go-modbus-trace/internal/link"
	"github.com/otfabric/go-modbus-trace/internal/pcapio"
)

// recorder is a Handler that records events as text.
type recorder struct {
	events []string
	data   map[string][]byte
}

func (r *recorder) Open(c *Conn) {
	r.events = append(r.events, fmt.Sprintf("open %d %s", c.ID, c.Open))
}
func (r *recorder) Data(c *Conn, d int, pos uint64, b []byte, ch Chunk) {
	if r.data == nil {
		r.data = map[string][]byte{}
	}
	k := fmt.Sprintf("%d/%d", c.ID, d)
	if uint64(len(r.data[k])) != pos {
		r.events = append(r.events, fmt.Sprintf("BAD POS %s %d %d", k, pos, len(r.data[k])))
	}
	r.data[k] = append(r.data[k], b...)
}
func (r *recorder) Gap(c *Conn, d int, pos uint64, n int64, kind GapKind) {
	k := fmt.Sprintf("%d/%d", c.ID, d)
	r.data[k] = append(r.data[k], make([]byte, n)...) // keep positions aligned
	r.events = append(r.events, fmt.Sprintf("gap %d/%d %d %s", c.ID, d, n, kind))
}
func (r *recorder) Close(c *Conn) {
	r.events = append(r.events, fmt.Sprintf("close %d %s", c.ID, c.Close))
}

type pkt struct {
	src, dst string
	seq, ack uint32
	flags    uint8
	data     string
}

func feed(t *Tracker, ps ...pkt) {
	for i, p := range ps {
		s := link.Segment{Src: netip.MustParseAddrPort(p.src), Dst: netip.MustParseAddrPort(p.dst), Seq: p.seq, Ack: p.ack,
			Flags: p.flags, Payload: []byte(p.data)}
		t.Packet(&pcapio.Packet{Frame: uint64(i + 1), HasTime: true, TimeNS: int64(i+1) * 1000}, &s)
	}
}

const (
	cl = "10.0.0.1:40000"
	sv = "10.0.0.2:502"
)

func TestEviction(t *testing.T) {
	r := &recorder{}
	tr := NewTracker(Limits{MaxConns: 2}, r)
	feed(tr,
		pkt{"10.0.0.1:1", sv, 1, 0, link.ACK, "a"},
		pkt{"10.0.0.1:2", sv, 1, 0, link.ACK, "b"},
		pkt{"10.0.0.1:1", sv, 2, 0, link.ACK, "c"}, // touches connection 1
		pkt{"10.0.0.1:3", sv, 1, 0, link.ACK, "d"}, // evicts connection 2
	)
	tr.Finish()
	want := "[open 1 midstream open 2 midstream close 2 evicted open 3 midstream close 1 end_of_trace close 3 end_of_trace]"
	if fmt.Sprint(r.events) != want || tr.Stats.Evicted != 1 || tr.Stats.MaxTracked != 2 {
		t.Errorf("events %v stats %+v", r.events, tr.Stats)
	}
}

func TestOverflowAndBudget(t *testing.T) {
	t.Run("per direction", func(t *testing.T) {
		r := &recorder{}
		tr := NewTracker(Limits{BufferPerDir: 10}, r)
		feed(tr,
			pkt{cl, sv, 100, 0, link.ACK, "0123"},
			pkt{cl, sv, 110, 0, link.ACK, "abcdef"}, // held (6)
			pkt{cl, sv, 120, 0, link.ACK, "ghijkl"}, // over 10: gap to 110, deliver, hold
			pkt{cl, sv, 116, 0, link.ACK, "mnop"},   // fills
		)
		tr.Finish()
		if got := string(r.data["1/0"]); got != "0123\x00\x00\x00\x00\x00\x00abcdefmnopghijkl" || tr.Stats.Overflows != 1 {
			t.Errorf("data %q events %v stats %+v", got, r.events, tr.Stats)
		}
	})
	t.Run("total budget picks the largest holder", func(t *testing.T) {
		r := &recorder{}
		tr := NewTracker(Limits{BufferTotal: 12}, r)
		feed(tr,
			pkt{"10.0.0.1:1", sv, 100, 0, link.ACK, "x"},
			pkt{"10.0.0.1:1", sv, 110, 0, link.ACK, "AAAAAAAA"}, // held 8
			pkt{"10.0.0.1:2", sv, 100, 0, link.ACK, "y"},
			pkt{"10.0.0.1:2", sv, 110, 0, link.ACK, "BBBBBB"}, // over 12: connection 1 gives up its hole
		)
		tr.Finish()
		if tr.Stats.BudgetGaps != 1 || r.events[2] != "gap 1/0 9 reassembly_budget" {
			t.Errorf("events %v stats %+v", r.events, tr.Stats)
		}
	})
}

func TestEpochs(t *testing.T) {
	r := &recorder{}
	tr := NewTracker(Limits{}, r)
	feed(tr,
		pkt{cl, sv, 100, 0, link.SYN, ""},
		pkt{sv, cl, 500, 101, link.SYN | link.ACK, ""},
		pkt{cl, sv, 101, 501, link.ACK, "req"},
		pkt{cl, sv, 100, 0, link.SYN, ""},       // retransmitted SYN: same epoch
		pkt{cl, sv, 9_000_000, 0, link.SYN, ""}, // far from the live stream: a new epoch
		pkt{sv, cl, 7000, 9_000_001, link.SYN | link.ACK, ""},
		pkt{cl, sv, 9_000_001, 7001, link.ACK, "two"},
	)
	tr.Finish()
	want := "[open 1 syn close 1 superseded open 2 syn close 2 end_of_trace]"
	if fmt.Sprint(r.events) != want || tr.Stats.Superseded != 1 || tr.Stats.SYNRetrans != 1 {
		t.Errorf("events %v stats %+v", r.events, tr.Stats)
	}
	if string(r.data["2/0"]) != "two" {
		t.Errorf("data %q", r.data)
	}
}

func TestAfterCloseAndMidstreamACKStart(t *testing.T) {
	r := &recorder{}
	tr := NewTracker(Limits{}, r)
	feed(tr,
		pkt{cl, sv, 100, 1000, link.ACK, "rq"},   // midstream; says the server's next byte is 1000
		pkt{sv, cl, 1004, 102, link.ACK, "efgh"}, // the server's first capture is out of order
		pkt{sv, cl, 1000, 102, link.ACK, "abcd"}, // fills
		pkt{cl, sv, 102, 1008, link.FIN | link.ACK, ""},
		pkt{sv, cl, 1008, 103, link.FIN | link.ACK, ""},
		pkt{cl, sv, 103, 1009, link.ACK, ""}, // after close
	)
	tr.Finish()
	if string(r.data["1/1"]) != "abcdefgh" || tr.Stats.AfterClose != 1 || tr.Stats.OutOfOrder != 1 {
		t.Errorf("data %q events %v stats %+v", r.data, r.events, tr.Stats)
	}
}

// TestHostileHolding: every held segment costs its overhead, so empty
// (snap-length cut) segments cannot fill the buffer for free, and a long
// run of held segments drains in a loop, not one stack frame per segment.
func TestHostileHolding(t *testing.T) {
	t.Run("empty segments are charged", func(t *testing.T) {
		tr := NewTracker(Limits{}, &recorder{})
		feed(tr, pkt{cl, sv, 100, 0, link.ACK, "x"})
		for i := range 200_000 {
			s := link.Segment{Src: netip.MustParseAddrPort(cl), Dst: netip.MustParseAddrPort(sv), Seq: uint32(1000 + 10*i),
				Flags: link.ACK, Missing: 10}
			tr.Packet(&pcapio.Packet{Frame: uint64(i + 2), HasTime: true, TimeNS: int64(i+2) * 1000}, &s)
			if n := len(tr.conns[tr.lru.next.key].dirs[0].pend); n > DefaultLimits.BufferPerDir/heldOverhead+1 {
				t.Fatalf("%d segments held", n)
			}
		}
		tr.Finish()
		if tr.Stats.Overflows == 0 {
			t.Error("no overflow declared")
		}
	})
	t.Run("a long held run drains without recursion", func(t *testing.T) {
		r := &recorder{}
		const n = 20_000
		tr := NewTracker(Limits{BufferPerDir: n * (heldOverhead + 1), BufferTotal: n * (heldOverhead + 1)}, r)
		feed(tr, pkt{cl, sv, 100, 0, link.ACK, "a"})
		for i := n; i >= 1; i-- { // reversed: everything waits for byte 101
			s := link.Segment{Src: netip.MustParseAddrPort(cl), Dst: netip.MustParseAddrPort(sv), Seq: uint32(101 + i),
				Flags: link.ACK, Payload: []byte{'c'}}
			tr.Packet(&pcapio.Packet{Frame: uint64(n - i + 2), HasTime: true, TimeNS: 1}, &s)
		}
		feed(tr, pkt{cl, sv, 101, 0, link.ACK, "b"})
		tr.Finish()
		if got := r.data["1/0"]; len(got) != n+2 || got[1] != 'b' || tr.Stats.Overflows != 0 {
			t.Errorf("%d bytes delivered, overflows %d", len(got), tr.Stats.Overflows)
		}
	})
}
