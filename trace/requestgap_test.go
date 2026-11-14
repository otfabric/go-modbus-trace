// SPDX-License-Identifier: MIT

package trace

import (
	"testing"

	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// TestResponseAfterRequestGap: a response that follows a hole in the request
// direction is uncertain when it pairs with a request that was outstanding
// across the hole, whether the hole is known from the response's own
// acknowledgement or was declared as a gap before it. A response that pairs
// with nothing stays an orphan, and without a hole pairing is unchanged.
func TestResponseAfterRequestGap(t *testing.T) {
	lost := func(c *tracetest.Conn, tid uint16, pdu []byte) {
		c.Write(tracetest.ToServer, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: tid, Unit: 1, PDU: pdu})
	}
	cases := []struct {
		name   string
		script func(c *tracetest.Conn)
		want   string
	}{
		{"the transaction ID reused with another PDU, the hole not declared yet", func(c *tracetest.Conn) {
			c.Request(7, 1, rd3)
			lost(c, 7, rd3b)
			c.Response(7, 1, resp3(9))
		}, "c1 u1 tid7 fc3 uncertain resp=03020009 [gap_adjacent]"},
		{"a client that sends transaction ID 0 on every request", func(c *tracetest.Conn) {
			c.Request(0, 1, rd3)
			c.Response(0, 1, resp3(1))
			c.Request(0, 1, rd3)
			lost(c, 0, rd3b)
			c.Response(0, 1, resp3(9))
		}, "c1 u1 tid0 fc3 ok resp=03020001\nc1 u1 tid0 fc3 uncertain resp=03020009 [gap_adjacent]"},
		{"the gap declared before the response", func(c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			lost(c, 1, rd3b)
			c.Request(2, 1, rd3) // data behind the hole: the gap is declared here
			c.Response(1, 1, resp3(9))
			c.Response(2, 1, resp3(2))
		}, "c1 u1 tid1 fc3 uncertain resp=03020009 [gap_adjacent]\nc1 u1 tid2 fc3 uncertain resp=03020002 [gap_adjacent,resynced]"},
		{"the gap declared after the response", func(c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			lost(c, 1, rd3b)
			c.Response(1, 1, resp3(9))
			c.Request(2, 1, rd3)
			c.Response(2, 1, resp3(2))
		}, "c1 u1 tid1 fc3 uncertain resp=03020009 [gap_adjacent]\nc1 u1 tid2 fc3 uncertain resp=03020002 [gap_adjacent,resynced]"},
		{"a request left unanswered across the hole stays unanswered", func(c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			lost(c, 5, rd3b)
			c.Response(5, 1, resp3(9))
		}, "c1 u1 tid5 fc3 orphan_response resp=03020009\nc1 u1 tid1 fc3 unanswered"},
		{"no hole: an answer after another exchange is certain", func(c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			c.Request(2, 1, rd3b)
			c.Response(2, 1, resp3(2))
			c.Response(1, 1, resp3(1))
		}, "c1 u1 tid2 fc3 ok resp=03020002\nc1 u1 tid1 fc3 ok resp=03020001"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
				c := b.Conn(tracetest.ConnOptions{})
				tc.script(c)
				c.Close()
			})
			_, evs := analyze(t, data, Options{})
			if got := lines(txns(evs)); got != tc.want {
				t.Errorf("\n got:\n%s\n want:\n%s", got, tc.want)
			}
		})
	}
}
