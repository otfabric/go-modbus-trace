// SPDX-License-Identifier: MIT

package timeline

import (
	"bytes"
	"context"
	"encoding/csv"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// fixture: two connections; the second one's clock runs 30 s behind the
// first (a merged capture), so file order and time order differ.
func fixture(t *testing.T) []byte {
	var buf bytes.Buffer
	b, err := tracetest.New(&buf, tracetest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	a := b.Conn(tracetest.ConnOptions{})
	for i := range 3 {
		a.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 1))
		a.Response(uint16(i), 1, tracetest.RegistersResponse(3, uint16(i)))
		b.Advance(2 * time.Second)
	}
	a.Close()
	b.Advance(-30 * time.Second)
	c := b.Conn(tracetest.ConnOptions{Client: tracetest.MustEndpoint("10.0.0.5:41000")})
	c.Request(9, 1, tracetest.ReadRequest(4, 7, 1))
	c.Response(9, 1, tracetest.Exception(4, 2))
	c.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func export(t *testing.T, data []byte, o Options) (string, Stats) {
	t.Helper()
	var out bytes.Buffer
	_, st, err := Write(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.Options{}, &out, o)
	if err != nil {
		t.Fatal(err)
	}
	return out.String(), st
}

func TestJSONLines(t *testing.T) {
	data := fixture(t)
	out, st := export(t, data, Options{Format: JSONL, Order: ByTime})
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if uint64(len(lines)) != st.Rows || st.Late != 0 {
		t.Fatalf("%d lines, stats %+v", len(lines), st)
	}
	var prev time.Time
	kinds := ""
	for _, l := range lines {
		var e model.Event
		if err := json.Unmarshal([]byte(l), &e); err != nil {
			t.Fatal(err)
		}
		if e.Time != nil {
			if e.Time.Before(prev) {
				t.Errorf("out of time order: %s", l)
			}
			prev = *e.Time
		}
		kinds += e.Kind[:1]
	}
	// The second connection (opened 24 s earlier in trace time) comes
	// first: its open, transaction and close; then the first connection.
	if kinds != "ctcctttc" {
		t.Errorf("kinds %s", kinds)
	}
	again, _ := export(t, data, Options{Format: JSONL, Order: ByTime})
	if again != out {
		t.Error("two runs differ")
	}
	byFile, _ := export(t, data, Options{Format: JSONL, Order: ByFile})
	if byFile == out || len(byFile) != len(out) {
		t.Error("file order should differ from time order here, with the same events")
	}
}

func TestCSV(t *testing.T) {
	out, st := export(t, fixture(t), Options{Format: CSV, Selection: selection.Selection{Statuses: []string{"exception"}}})
	r := csv.NewReader(strings.NewReader(out))
	rows, err := r.ReadAll()
	if err != nil {
		t.Fatal(err)
	}
	if len(rows[0]) != len(Columns) || st.Rows != uint64(len(rows)-1) {
		t.Fatalf("header %v, stats %+v", rows[0], st)
	}
	col := map[string]int{}
	for i, c := range rows[0] {
		col[c] = i
	}
	var txn []string
	for _, row := range rows[1:] {
		if row[col["kind"]] == "txn" {
			if txn != nil {
				t.Fatal("more than one transaction selected")
			}
			txn = row
		}
	}
	want := map[string]string{"status": "exception", "exception": "2", "function": "4", "request_pdu": "0400070001",
		"response_pdu": "8402", "summary": "Read 1 input register @ 7: exception 2 (illegal data address)", "ranges": "input:7+1"}
	for k, v := range want {
		if txn[col[k]] != v {
			t.Errorf("%s = %q, want %q", k, txn[col[k]], v)
		}
	}
	if strings.Contains(out, "\r") {
		t.Error("CRLF line endings")
	}
}

func TestReorderBuffer(t *testing.T) {
	// A buffer of one row writes everything at once: the earlier
	// connection's rows come late.
	_, st := export(t, fixture(t), Options{Format: JSONL, Order: ByTime, Buffer: 1})
	if st.Late == 0 {
		t.Errorf("stats %+v", st)
	}
}

func TestReorderWindow(t *testing.T) {
	// With a window shorter than the clock jump, the earlier connection's
	// events arrive late and are counted.
	_, st := export(t, fixture(t), Options{Format: JSONL, Order: ByTime, Window: time.Second})
	if st.Late == 0 {
		t.Errorf("stats %+v", st)
	}
}
