// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"net/netip"
	"sync"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

var (
	benchOnce sync.Once
	benchData []byte
)

// benchTrace is about 32 MiB: 100 connections polling 125 holding
// registers, with occasional losses and reordering (LA18).
func benchTrace(b *testing.B) []byte {
	benchOnce.Do(func() {
		var buf bytes.Buffer
		tb, _ := tracetest.New(&buf, tracetest.Options{CountOnly: true})
		var cs []*tracetest.Conn
		for i := range 100 {
			cs = append(cs, tb.Conn(tracetest.ConnOptions{Client: netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i)}), 40000)}))
		}
		vals := make([]uint16, 125)
		for i := 0; buf.Len() < 32<<20; i++ {
			c := cs[i%len(cs)]
			c.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 125))
			vals[i%125]++
			var o tracetest.WriteOpts
			if i%97 == 5 {
				o.Seg, o.Reverse = []int{100}, true
			}
			c.Write(tracetest.ToClient, o, tracetest.Frame{TID: uint16(i), Unit: 1, PDU: tracetest.RegistersResponse(3, vals...)})
		}
		_ = tb.Close()
		benchData = buf.Bytes()
	})
	return benchData
}

func BenchmarkScan(b *testing.B) {
	data := benchTrace(b)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		if _, _, err := Scan(context.Background(), OpenReader(bytes.NewReader(data)), ScanOptions{}); err != nil {
			b.Fatal(err)
		}
	}
}

func BenchmarkAnalyze(b *testing.B) {
	data := benchTrace(b)
	b.SetBytes(int64(len(data)))
	b.ReportAllocs()
	b.ResetTimer()
	for range b.N {
		_, err := Analyze(context.Background(), OpenReader(bytes.NewReader(data)), Options{}, SinkFunc(func(*model.Event) error { return nil }))
		if err != nil {
			b.Fatal(err)
		}
	}
}
