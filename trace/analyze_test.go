// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"compress/gzip"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

func analyze(t *testing.T, data []byte, o Options) (*FileSummary, []*model.Event) {
	t.Helper()
	var evs []*model.Event
	sum, err := Analyze(context.Background(), OpenReader(bytes.NewReader(data)), o, SinkFunc(func(e *model.Event) error {
		evs = append(evs, e)
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return sum, evs
}

func txns(evs []*model.Event) []*model.Transaction {
	var out []*model.Transaction
	for _, e := range evs {
		if e.Txn != nil {
			out = append(out, e.Txn)
		}
	}
	return out
}

// line renders a transaction compactly for comparison.
func line(t *model.Transaction) string {
	s := fmt.Sprintf("c%d u%d tid%d fc%d %s", t.Conn, t.Unit, t.TID, t.Function, t.Status)
	if t.Response != nil {
		s += " resp=" + hex.EncodeToString(t.Response.PDU)
	}
	if len(t.Flags) > 0 {
		s += " [" + strings.Join(t.Flags, ",") + "]"
	}
	return s
}

func lines(ts []*model.Transaction) string {
	p := make([]string, len(ts))
	for i, t := range ts {
		p[i] = line(t)
	}
	return strings.Join(p, "\n")
}

var (
	rd3  = tracetest.ReadRequest(3, 0, 1)
	rd3b = tracetest.ReadRequest(3, 9, 1)
)

func resp3(v uint16) []byte { return tracetest.RegistersResponse(3, v) }

// TestPairing is LA7.
func TestPairing(t *testing.T) {
	cases := []struct {
		name   string
		conn   tracetest.ConnOptions
		o      Options
		script func(b *tracetest.Builder, c *tracetest.Conn)
		want   string
	}{
		{"pipelining", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			c.Request(2, 1, rd3)
			c.Response(1, 1, resp3(1))
			c.Response(2, 1, resp3(2))
		}, "c1 u1 tid1 fc3 ok resp=03020001\nc1 u1 tid2 fc3 ok resp=03020002"},
		{"out-of-order responses", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			c.Request(2, 1, rd3)
			c.Response(2, 1, resp3(2))
			c.Response(1, 1, resp3(1))
		}, "c1 u1 tid2 fc3 ok resp=03020002\nc1 u1 tid1 fc3 ok resp=03020001"},
		{"units sharing a transaction ID", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(5, 1, rd3)
			c.Request(5, 2, rd3)
			c.Response(5, 2, resp3(2))
			c.Response(5, 1, resp3(1))
		}, "c1 u2 tid5 fc3 ok resp=03020002\nc1 u1 tid5 fc3 ok resp=03020001"},
		{"a reused ID after its answer", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(0, 1, rd3)
			c.Response(0, 1, resp3(1))
			c.Request(0, 1, rd3b)
			c.Response(0, 1, resp3(2))
		}, "c1 u1 tid0 fc3 ok resp=03020001\nc1 u1 tid0 fc3 ok resp=03020002"},
		{"a retried identical request", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(7, 1, rd3)
			c.Request(7, 1, rd3)
			c.Response(7, 1, resp3(7))
		}, "c1 u1 tid7 fc3 ok resp=03020007 [retried]\nc1 u1 tid7 fc3 unanswered [retried]"},
		{"an ambiguous pair: same key, different PDUs", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(8, 1, rd3)
			c.Request(8, 1, rd3b)
			c.Response(8, 1, resp3(8))
		}, "c1 u1 tid8 fc3 ambiguous resp=03020008\nc1 u1 tid8 fc3 unanswered"},
		{"an orphan response at a midstream start", tracetest.ConnOptions{Midstream: true}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Response(3, 1, resp3(3))
			c.Request(4, 1, rd3)
			c.Response(4, 1, resp3(4))
		}, "c1 u1 tid3 fc3 orphan_response resp=03020003 [midstream,role_guessed]\nc1 u1 tid4 fc3 ok resp=03020004 [midstream,role_guessed]"},
		{"unanswered at the end, and a broadcast", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			c.Request(2, 0, tracetest.ReadRequest(3, 0, 1))
		}, "c1 u1 tid1 fc3 unanswered\nc1 u0 tid2 fc3 unanswered [broadcast]"},
		{"a slow response", tracetest.ConnOptions{}, Options{Slow: 500 * time.Millisecond}, func(b *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			b.Advance(2 * time.Second)
			c.Response(1, 1, resp3(1))
		}, "c1 u1 tid1 fc3 ok resp=03020001 [slow]"},
		{"a response stamped before its request", tracetest.ConnOptions{}, Options{}, func(b *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			b.Advance(-time.Second)
			c.Response(1, 1, resp3(1))
		}, "c1 u1 tid1 fc3 ok resp=03020001 [clock_order]"},
		{"an exception", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			c.Response(1, 1, tracetest.Exception(3, 2))
		}, "c1 u1 tid1 fc3 exception resp=8302"},
		{"a response that does not fit its request", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, tracetest.ReadRequest(3, 0, 2))
			c.Response(1, 1, resp3(1))
		}, "c1 u1 tid1 fc3 ok resp=03020001 [invalid_pdu]"},
		{"serial-line and unknown functions", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, []byte{7})
			c.Response(1, 1, []byte{7, 0x6D})
			c.Request(2, 1, []byte{0x41, 1})
			c.Response(2, 1, []byte{0x41, 2})
		}, "c1 u1 tid1 fc7 ok resp=076d [serial_function_over_tcp]\nc1 u1 tid2 fc65 ok resp=4102 [unknown_function]"},
		{"a foreign protocol frame", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			f := tracetest.MBAP(1, 1, rd3)
			f[3] = 9
			c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: f})
			c.Request(2, 1, rd3)
			c.Response(2, 1, resp3(2))
		}, "c1 u1 tid1 fc3 malformed [foreign_protocol]\nc1 u1 tid2 fc3 ok resp=03020002"},
		{"the outstanding limit", tracetest.ConnOptions{}, Options{MaxOutstanding: 2}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			c.Request(2, 1, rd3)
			c.Request(3, 1, rd3)
			c.Response(3, 1, resp3(3))
		}, "c1 u1 tid1 fc3 uncertain\nc1 u1 tid3 fc3 ok resp=03020003\nc1 u1 tid2 fc3 unanswered"},
		{"a lost response: unanswered becomes uncertain, the next is resynced", tracetest.ConnOptions{}, Options{}, func(_ *tracetest.Builder, c *tracetest.Conn) {
			c.Request(1, 1, rd3)
			c.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: 1, Unit: 1, PDU: resp3(1)})
			c.Request(2, 1, rd3)
			c.Response(2, 1, resp3(2))
			// tid1's response was in the gap: decided as soon as the later
			// tid2 is answered.
		}, "c1 u1 tid1 fc3 uncertain [gap_adjacent]\nc1 u1 tid2 fc3 uncertain resp=03020002 [gap_adjacent,resynced]"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
				c := b.Conn(tc.conn)
				tc.script(b, c)
				c.Close()
			})
			_, evs := analyze(t, data, tc.o)
			if got := lines(txns(evs)); got != tc.want {
				t.Errorf("\n got:\n%s\n want:\n%s", got, tc.want)
			}
		})
	}
}

// TestParallelClients: the same transaction IDs on two connections pair
// within each.
func TestParallelClients(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		a := b.Conn(tracetest.ConnOptions{})
		c := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.7:41000")})
		a.Request(1, 1, rd3)
		c.Request(1, 1, rd3)
		c.Response(1, 1, resp3(2))
		a.Response(1, 1, resp3(1))
	})
	_, evs := analyze(t, data, Options{})
	if got := lines(txns(evs)); got != "c2 u1 tid1 fc3 ok resp=03020002\nc1 u1 tid1 fc3 ok resp=03020001" {
		t.Errorf("got:\n%s", got)
	}
}

// TestEventsAndCounters checks the event sequence of a connection and the
// summary's counters (LA8).
func TestEventsAndCounters(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, rd3)
		c.Response(1, 1, resp3(1))
		c.Request(2, 1, rd3)
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: 2, Unit: 1, PDU: resp3(2)})
		c.Request(3, 1, rd3)
		c.Response(3, 1, tracetest.Exception(3, 4))
		c.Close()
	})
	sum, evs := analyze(t, data, Options{})
	var kinds []string
	for _, e := range evs {
		kinds = append(kinds, e.Kind)
		if e.Seq != uint64(len(kinds)) {
			t.Errorf("event %d has seq %d", len(kinds), e.Seq)
		}
	}
	want := "conn.open txn gap resync txn txn conn.close"
	if got := strings.Join(kinds, " "); got != want {
		t.Errorf("kinds %s, want %s", got, want)
	}
	if fmt.Sprint(sum.Transactions) != "map[ok:1 uncertain:2]" || sum.TransactionFlags[model.FlagGapAdjacent] != 2 {
		t.Errorf("counters %v %v", sum.Transactions, sum.TransactionFlags)
	}
	closeEv := evs[len(evs)-1].Conn
	if closeEv.Close != "fin" || closeEv.Transactions != 3 || closeEv.Client != client || closeEv.Server != server {
		t.Errorf("close %+v", closeEv)
	}
}

// TestFrames is LA16: the frame references of every ADU lead back to its
// bytes; gzip and streams are not seekable.
func TestFrames(t *testing.T) {
	for _, f := range []tracetest.Format{tracetest.Pcap, tracetest.PcapNGBE} {
		data, _ := build(t, tracetest.Options{Format: f, Interfaces: []tracetest.Iface{{Link: tracetest.EthernetVLAN, TSResol: 9}}},
			func(b *tracetest.Builder) {
				c := b.Conn(tracetest.ConnOptions{MSS: 7})
				poll(c, 1, 3)
				c.Write(tracetest.ToClient, tracetest.WriteOpts{OneByte: true}, tracetest.Frame{TID: 9, Unit: 1, PDU: resp3(9)})
				c.Close()
			})
		path := filepath.Join(t.TempDir(), "t.pcap")
		if err := os.WriteFile(path, data, 0o600); err != nil {
			t.Fatal(err)
		}
		file, _ := Open(path)
		_, evs := analyze(t, data, Options{})
		for _, tx := range txns(evs) {
			for _, a := range []*model.ADU{tx.Request, tx.Response} {
				if a == nil {
					continue
				}
				frs, err := file.Frames(a.Refs)
				if err != nil {
					t.Fatal(err)
				}
				var got []byte
				for _, fr := range frs {
					got = append(got, fr.Payload...)
				}
				if want := tracetest.MBAP(a.TID, a.Unit, a.PDU); !bytes.Equal(got, want) {
					t.Errorf("format %d, ADU %x: frames give %x", f, want, got)
				}
				if a.Size != len(got) || a.First == nil || a.Last.Before(*a.First) {
					t.Errorf("size %d, times %v %v", a.Size, a.First, a.Last)
				}
			}
		}
	}
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) { poll(b.Conn(tracetest.ConnOptions{}), 1, 1) })
	_, _ = zw.Write(data)
	_ = zw.Close()
	path := filepath.Join(t.TempDir(), "t.pcap.gz")
	_ = os.WriteFile(path, z.Bytes(), 0o600)
	gz, _ := Open(path)
	if _, err := gz.Frames([]model.FrameRef{{Frame: 1, Offset: 24}}); !errors.Is(err, ErrNotSeekable) {
		t.Errorf("gzip: %v", err)
	}
	if _, err := OpenReader(bytes.NewReader(data)).Frames(nil); !errors.Is(err, ErrNotSeekable) {
		t.Errorf("stream: %v", err)
	}
}

// TestDeterminism: two runs give byte-identical event JSON (LA11 for the
// events).
func TestDeterminism(t *testing.T) {
	data, _, servers := randomScript(t, 7)
	run := func() []byte {
		var buf bytes.Buffer
		enc := json.NewEncoder(&buf)
		_, err := Analyze(context.Background(), OpenReader(bytes.NewReader(data)), Options{ScanOptions: ScanOptions{Servers: servers}},
			SinkFunc(func(e *model.Event) error { return enc.Encode(e) }))
		if err != nil {
			t.Fatal(err)
		}
		return buf.Bytes()
	}
	a, b := run(), run()
	if !bytes.Equal(a, b) || len(a) == 0 {
		t.Error("two runs differ")
	}
}

// TestSinkError: an error from the sink stops the pass.
func TestSinkError(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) { poll(b.Conn(tracetest.ConnOptions{}), 1, 5) })
	stop := errors.New("stop")
	n := 0
	_, err := Analyze(context.Background(), OpenReader(bytes.NewReader(data)), Options{}, SinkFunc(func(*model.Event) error {
		if n++; n == 3 {
			return stop
		}
		return nil
	}))
	if !errors.Is(err, stop) || n != 3 {
		t.Errorf("err %v after %d events", err, n)
	}
}

// TestFlowSelection: Options.Flows restricts the events.
func TestFlowSelection(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		poll(b.Conn(tracetest.ConnOptions{}), 1, 2)
		poll(b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.7:41000")}), 1, 2)
	})
	_, evs := analyze(t, data, Options{Flows: []uint32{2}})
	for _, e := range evs {
		if e.Txn != nil && e.Txn.Conn != 2 || e.Conn != nil && e.Conn.ID != 2 {
			t.Fatalf("event of another flow: %+v", e)
		}
	}
	if len(txns(evs)) != 2 {
		t.Errorf("%d transactions", len(txns(evs)))
	}
}

// TestReadRangesOnResponses: a read response carries its request's range.
func TestReadRangesOnResponses(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, tracetest.ReadRequest(4, 4096, 2))
		c.Response(1, 1, tracetest.RegistersResponse(4, 7, 8))
	})
	_, evs := analyze(t, data, Options{})
	tx := txns(evs)[0]
	if len(tx.Response.View.Ranges) != 1 || tx.Response.View.Ranges[0] != (mbtcp.Range{Space: mbtcp.Input, Start: 4096, Count: 2}) ||
		tx.Summary != "Read 2 input registers @ 4096" || tx.Class != "read" {
		t.Errorf("%+v %+v", tx, tx.Response.View)
	}
	if v, ok := mbtcp.ValueAt(tx.Request.PDU, tx.Response.PDU, 4097); !ok || v != 8 {
		t.Errorf("ValueAt %d %v", v, ok)
	}
	if !slices.Contains(evs[0].Conn.Client.Addr().AsSlice(), 10) {
		t.Error("conn.open first")
	}
}

// TestUndecidedRoles: a midstream connection on a non-standard port holds
// its ADUs (and a gap) until the structure test decides, then replays them
// in order; a connection that never decides reports role_unknown.
func TestUndecidedRoles(t *testing.T) {
	odd := netip.MustParseAddrPort("10.0.0.9:1502")
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{Midstream: true, Server: odd})
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: 99, Unit: 1, PDU: resp3(1)})
		for i := range 25 {
			c.Request(uint16(i), 1, rd3)
			c.Response(uint16(i), 1, resp3(uint16(i)))
		}
		u := b.Conn(tracetest.ConnOptions{Midstream: true, Client: netip.MustParseAddrPort("10.0.0.8:41000"), Server: netip.MustParseAddrPort("10.0.0.9:7")})
		u.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{TID: 1, Unit: 1, PDU: []byte{0x41, 1}})
		u.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{TID: 2, Unit: 1, PDU: []byte{0x41, 2}})
	})
	_, evs := analyze(t, data, Options{})
	var c1, c2 []string
	for _, e := range evs {
		var id uint32
		var s string
		switch {
		case e.Conn != nil:
			id, s = e.Conn.ID, e.Kind+":"+e.Conn.RoleSource
		case e.Txn != nil:
			id, s = e.Txn.Conn, e.Txn.Status
		case e.Gap != nil:
			id, s = e.Gap.Conn, "gap"
		case e.Resync != nil:
			id, s = e.Resync.Conn, "resync"
		}
		if id == 1 {
			c1 = append(c1, s)
		} else {
			c2 = append(c2, s)
		}
	}
	if len(c1) < 4 || c1[0] != "conn.open:structure" || c1[1] != "ok" || c1[len(c1)-1] != "conn.close:structure" {
		t.Errorf("connection 1: %v", c1)
	}
	if strings.Join(c2, " ") != "conn.open:unknown uncertain uncertain conn.close:unknown" {
		t.Errorf("connection 2: %v", c2)
	}
	for _, x := range txns(evs) {
		if x.Conn == 2 && !hasFlagT(x, model.FlagRoleUnknown) {
			t.Errorf("%+v", x)
		}
	}
}

func hasFlagT(t *model.Transaction, f string) bool { return slices.Contains(t.Flags, f) }

// TestNotes: trace-level facts become notes at the end.
func TestNotes(t *testing.T) {
	data, _ := build(t, tracetest.Options{Format: tracetest.PcapNG, SnapLen: 70}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, rd3)
		c.Response(1, 1, tracetest.RegistersResponse(3, 1, 2, 3, 4, 5, 6, 7, 8, 9, 10))
		b.InterfaceDrops(0, 5)
		b.UDP(0, client, server, []byte("x"))
	})
	_, evs := analyze(t, data, Options{})
	var codes []string
	for _, e := range evs {
		if e.Note != nil {
			codes = append(codes, e.Note.Code)
		}
	}
	if strings.Join(codes, " ") != "capture_drops snaplen unsupported" {
		t.Errorf("notes %v", codes)
	}
	// A damaged file ends with a note too.
	bad := append([]byte(nil), data...)
	bad = append(bad[:len(bad)-3], 0xFF, 0xFF, 0xFF)
	_, evs = analyze(t, bad, Options{})
	if e := evs[len(evs)-1]; e.Note == nil || e.Note.Code != "damaged_file" {
		t.Errorf("last event %+v", e)
	}
}
