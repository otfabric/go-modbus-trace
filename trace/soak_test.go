// SPDX-License-Identifier: MIT

package trace

import (
	"context"
	"fmt"
	"io"
	"net/netip"
	"os"
	"runtime/metrics"
	"strconv"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// TestSoak is LA14's memory half: a generated stream (never stored) of
// MBTRACE_SOAK GiB, 1,000 connections polling with losses, reordering and
// retransmissions, goes through Analyze (pairing, decoding, provenance) with
// flat memory. Run with
// MBTRACE_SOAK=5 (make soak); skipped otherwise.
func TestSoak(t *testing.T) {
	gib, err := strconv.Atoi(os.Getenv("MBTRACE_SOAK"))
	if err != nil || gib <= 0 {
		t.Skip("set MBTRACE_SOAK=<GiB> to run")
	}
	pr, pw := io.Pipe()
	target := int64(gib) << 30
	go func() {
		b, err := tracetest.New(&countingWriter{w: pw, limit: target}, tracetest.Options{Format: tracetest.PcapNG, CountOnly: true})
		if err != nil {
			pw.CloseWithError(err)
			return
		}
		var conns []*tracetest.Conn
		for i := range 1000 {
			conns = append(conns, b.Conn(tracetest.ConnOptions{
				Client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, byte(i >> 8), byte(i)}), 40000),
				Server: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 1, 0, byte(i % 7)}), 502),
			}))
		}
		vals := make([]uint16, 125)
		for i := 0; b.Err() == nil; i++ {
			c := conns[i%len(conns)]
			tid := uint16(i)
			c.Request(tid, 1, tracetest.ReadRequest(3, 0x1000, 125))
			for j := range vals {
				vals[j] = uint16(i + j)
			}
			var o tracetest.WriteOpts
			switch i % 101 {
			case 3:
				o.Lose = []int{0}
			case 5:
				o.Seg, o.Reverse = []int{100, 100}, true
			case 7:
				o.Retransmit = []int{0}
			}
			c.Write(tracetest.ToClient, o, tracetest.Frame{TID: tid, Unit: 1, PDU: tracetest.RegistersResponse(3, vals...)})
		}
		_ = pw.Close()
	}()
	var maxHeap, samples uint64
	live := []metrics.Sample{{Name: "/gc/heap/live:bytes"}} // live heap after the last GC
	opts := Options{ScanOptions: ScanOptions{Progress: func(read, _ int64) {
		if samples++; samples%16 == 0 { // every 64 MiB
			metrics.Read(live)
			maxHeap = max(maxHeap, live[0].Value.Uint64())
		}
	}}}
	var events uint64
	sum, err := Analyze(context.Background(), OpenReader(pr), opts, SinkFunc(func(*model.Event) error {
		events++
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("%d packets, %d events, %v, %d gaps, max live heap %d MiB", sum.Packets, events, sum.Transactions, sum.Quality.Gaps, maxHeap>>20)
	if maxHeap > 64<<20 {
		t.Errorf("the live heap reached %d MiB", maxHeap>>20)
	}
}

// countingWriter ends the stream once limit bytes were written.
type countingWriter struct {
	w     io.Writer
	n     int64
	limit int64
}

func (c *countingWriter) Write(p []byte) (int, error) {
	if c.n >= c.limit {
		return 0, fmt.Errorf("soak size reached")
	}
	n, err := c.w.Write(p)
	c.n += int64(n)
	return n, err
}
