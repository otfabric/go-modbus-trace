// SPDX-License-Identifier: MIT

package mbcapexport

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/jsonl"
	"github.com/otfabric/go-modbus-capture/mbcap"
	"github.com/otfabric/go-modbus-capture/mbcsv"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

var (
	srv  = netip.MustParseAddrPort("10.0.0.2:502")
	srv2 = netip.MustParseAddrPort("10.0.0.3:502")
)

func build(t *testing.T, script func(b *tracetest.Builder)) []byte {
	t.Helper()
	var buf bytes.Buffer
	b, err := tracetest.New(&buf, tracetest.Options{Format: tracetest.PcapNG})
	if err != nil {
		t.Fatal(err)
	}
	script(b)
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// rows writes one transaction per row of the admission matrix
// (MBCAP-EXPORT.md section 3) and returns the reason each must get.
func rows(b *tracetest.Builder) []Reason {
	c := b.Conn(tracetest.ConnOptions{})
	var want []Reason
	tid := uint16(0)
	pair := func(req, resp []byte, r Reason) {
		tid++
		c.Request(tid, 1, req)
		if resp != nil {
			c.Response(tid, 1, resp)
		}
		want = append(want, r)
	}
	regs := tracetest.RegistersResponse
	pair(tracetest.ReadRequest(1, 0, 8), []byte{1, 1, 0xA5}, Admit)
	pair(tracetest.ReadRequest(2, 0, 8), []byte{2, 1, 0x5A}, Admit)
	pair(tracetest.ReadRequest(3, 100, 2), regs(3, 1, 2), Admit)
	pair(tracetest.ReadRequest(4, 100, 1), regs(4, 7), Admit)
	pair([]byte{7}, []byte{7, 0x6D}, Admit)
	pair([]byte{11}, []byte{11, 0, 0, 1, 8}, Admit)
	pair([]byte{12}, []byte{12, 6, 0, 0, 1, 8, 1, 0x21}, Admit)
	pair([]byte{17}, []byte{17, 2, 0x42, 0xFF}, Admit)
	pair([]byte{20, 7, 6, 0, 4, 0, 1, 0, 1}, []byte{20, 4, 3, 6, 0, 9}, Admit)
	pair([]byte{24, 0, 1}, []byte{24, 0, 4, 0, 1, 0, 9}, Admit)
	pair([]byte{8, 0, 0, 1, 2}, []byte{8, 0, 0, 1, 2}, Admit)
	pair([]byte{8, 0, 2, 0, 0}, []byte{8, 0, 2, 0xA5, 0x5A}, Admit)
	pair([]byte{8, 0, 0x0B, 0, 0}, []byte{8, 0, 0x0B, 0, 3}, Admit)
	pair([]byte{8, 0, 1, 0, 0}, []byte{8, 0, 1, 0, 0}, FC08StateChanging)
	pair([]byte{43, 14, 1, 0}, []byte{43, 14, 1, 1, 0, 0, 1, 0, 2, 'O', 'K'}, Admit)
	pair([]byte{43, 13, 1}, []byte{43, 13, 2}, MEINot14)
	pair(tracetest.ReadRequest(3, 9, 1), tracetest.Exception(3, 2), Admit)
	pair([]byte{5, 0, 1, 0xFF, 0}, []byte{5, 0, 1, 0xFF, 0}, WriteFunction)
	pair([]byte{6, 0, 1, 0, 7}, []byte{6, 0, 1, 0, 7}, WriteFunction)
	pair([]byte{15, 0, 0, 0, 8, 1, 0xFF}, []byte{15, 0, 0, 0, 8}, WriteFunction)
	pair([]byte{16, 0, 0, 0, 1, 2, 0, 9}, []byte{16, 0, 0, 0, 1}, WriteFunction)
	pair([]byte{21, 9, 6, 0, 4, 0, 7, 0, 1, 0, 1}, []byte{21, 9, 6, 0, 4, 0, 7, 0, 1, 0, 1}, WriteFunction)
	pair([]byte{22, 0, 4, 0, 0xF2, 0, 0x25}, []byte{22, 0, 4, 0, 0xF2, 0, 0x25}, WriteFunction)
	pair([]byte{23, 0, 3, 0, 1, 0, 14, 0, 1, 2, 0, 0xFF}, regs(23, 9), FC23)
	pair([]byte{0x41, 1}, []byte{0x41, 2}, UnsupportedFunction)
	pair(tracetest.ReadRequest(3, 0, 2), regs(3, 1), ResponseMismatch)
	pair(tracetest.ReadRequest(3, 0, 0), regs(3), InvalidPDU)
	pair(tracetest.ReadRequest(3, 0, 1), nil, Unanswered) // decided when the connection closes
	tid++
	c.Response(200, 1, regs(3, 1)) // orphan
	want = append(want, OrphanResponse)
	tid++
	c.Request(300, 1, tracetest.ReadRequest(3, 0, 1))
	c.Request(300, 1, tracetest.ReadRequest(3, 1, 1))
	c.Response(300, 1, regs(3, 1)) // ambiguous, and the other one unanswered
	want = append(want, AmbiguousPair)
	c.Request(400, 1, tracetest.ReadRequest(3, 0, 1))
	b.Advance(-time.Second)
	c.Response(400, 1, regs(3, 1))
	want = append(want, ClockOrder)
	f := tracetest.MBAP(500, 1, tracetest.ReadRequest(3, 0, 1))
	f[3] = 7
	c.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: f})
	want = append(want, Malformed)
	c.Close()
	// A lost response, on its own connection (the gap would make every
	// request still waiting on the first one uncertain too).
	g := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.1:40009")})
	g.Request(600, 1, tracetest.ReadRequest(3, 0, 1))
	g.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: 600, Unit: 1, PDU: regs(3, 1)})
	g.Request(601, 1, tracetest.ReadRequest(3, 0, 1))
	g.Response(601, 1, regs(3, 2))
	g.Close()
	want = append(want, Uncertain, Uncertain) // the lost one, and the resynced one after the gap
	// Order of determination: the ambiguous pair's second request and the
	// unanswered one are decided at the close, after the rest.
	return append(want, Unanswered)
}

// TestAdmissionMatrix is LA9's matrix: every row gets its reason.
func TestAdmissionMatrix(t *testing.T) {
	var want []Reason
	data := build(t, func(b *tracetest.Builder) { want = rows(b) })
	got := map[Reason]int{}
	_, err := trace.Analyze(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.Options{},
		trace.SinkFunc(func(e *model.Event) error {
			if e.Txn != nil {
				got[Classify(e.Txn)]++
			}
			return nil
		}))
	if err != nil {
		t.Fatal(err)
	}
	wantN := map[Reason]int{}
	for _, r := range want {
		wantN[r]++
	}
	if fmt.Sprint(got) != fmt.Sprint(wantN) {
		t.Errorf("\n got  %v\n want %v", got, wantN)
	}
}

// TestClassifyMatchesTheChecker is LA9's property test: for every function
// code, FC08 sub-function and FC43 MEI type, an ok transaction is admitted
// exactly when go-modbus-capture's own rules accept the sample.
func TestClassifyMatchesTheChecker(t *testing.T) {
	try := func(req, resp []byte) {
		rq, rs := mbtcp.Decode(mbtcp.AsRequest, req), mbtcp.Decode(mbtcp.AsResponse, resp)
		warns := mbtcp.CheckPair(req, rq, resp, &rs)
		tx := &model.Transaction{Function: rq.Function, Sub: rq.Sub, Class: string(rq.Class), Status: model.StatusOK,
			Request: &model.ADU{PDU: req}, Response: &model.ADU{PDU: resp}, Warnings: append(append(warns, rq.Warnings...), rs.Warnings...)}
		if len(tx.Warnings) > 0 {
			tx.Flags = []string{model.FlagInvalidPDU}
		}
		mine := Classify(tx) == Admit
		theirs := capture.CheckPDUs(req, resp) == nil
		if mine && !theirs {
			t.Errorf("% x / % x: admitted, but the capture library refuses it", req, resp)
		}
		if theirs && !mine && len(tx.Warnings) == 0 {
			t.Errorf("% x / % x: refused (%s), but the capture library accepts it", req, resp, Classify(tx))
		}
	}
	for fc := 1; fc < 128; fc++ {
		req := append([]byte{byte(fc)}, 0, 0, 0, 1)
		try(req, append([]byte{byte(fc)}, 2, 0, 1))
	}
	for sub := 0; sub <= 0x20; sub++ {
		try([]byte{8, 0, byte(sub), 0, 0}, []byte{8, 0, byte(sub), 0, 0})
	}
	for mei := 0; mei < 256; mei++ {
		try([]byte{43, byte(mei), 1, 0}, []byte{43, byte(mei), 1, 1, 0, 0, 0})
	}
}

// export runs an export into a JSON Lines capture.
func export(t *testing.T, data []byte, eo Options, enc string) ([]byte, *Report) {
	t.Helper()
	var out bytes.Buffer
	if eo.Producer == "" {
		eo.Producer = "test"
	}
	rep, err := Export(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.Options{}, eo,
		func(h capture.Header) (capture.Writer, error) {
			switch enc {
			case "mbcap":
				return mbcap.NewWriter(&out, h, nil)
			case "csv":
				return mbcsv.NewWriter(&out, h)
			default:
				return jsonl.NewWriter(&out, h)
			}
		})
	if err != nil {
		t.Fatal(err)
	}
	return out.Bytes(), rep
}

func readCapture(t *testing.T, b []byte, enc string) *capture.Capture {
	t.Helper()
	var r capture.Reader
	var err error
	switch enc {
	case "mbcap":
		r, err = mbcap.NewReader(bytes.NewReader(b))
	case "csv":
		r, err = mbcsv.NewReader(bytes.NewReader(b))
	default:
		r, err = jsonl.NewReader(bytes.NewReader(b))
	}
	if err != nil {
		t.Fatal(err)
	}
	c, err := capture.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	return c
}

func identity(t *testing.T, r *Report) {
	t.Helper()
	sum := r.SamplesWritten + r.ChangeOnlyDropped
	for _, n := range r.Excluded {
		sum += n
	}
	if sum != r.TransactionsSeen {
		t.Errorf("transactions seen %d, accounted %d", r.TransactionsSeen, sum)
	}
}

// TestEncodingsAndReport: the three encodings hold the same capture, the
// report adds up, and two runs are byte-identical (LA9, LA11).
func TestEncodingsAndReport(t *testing.T) {
	data := build(t, func(b *tracetest.Builder) { rows(b) })
	caps := map[string]*capture.Capture{}
	for _, enc := range []string{"mbcap", "jsonl", "csv"} {
		out, rep := export(t, data, Options{}, enc)
		identity(t, rep)
		caps[enc] = readCapture(t, out, enc)
		again, _ := export(t, data, Options{}, enc)
		if !bytes.Equal(out, again) {
			t.Errorf("%s: two runs differ", enc)
		}
		if rep.SamplesWritten != 15 || rep.Excluded["write_function"] != 6 || len(rep.Targets) != 1 || rep.Targets[0].Exceptions != 1 {
			b, _ := json.MarshalIndent(rep, "", " ")
			t.Errorf("%s: report %s", enc, b)
		}
	}
	if d := capture.Diff(caps["mbcap"], caps["jsonl"]); d != "" {
		t.Errorf("mbcap vs jsonl: %s", d)
	}
	if d := capture.Diff(caps["jsonl"], caps["csv"]); d != "" {
		t.Errorf("jsonl vs csv: %s", d)
	}
	c := caps["jsonl"]
	h := c.Header
	if !h.Exceptions || h.ChangeOnly || h.TickNS != capture.DefaultTickNS || h.Tags["export.admission"] != "reads-only/1" ||
		h.Tags["trace.format"] != "pcapng" || h.Tags[capture.TagProvenance] == "" || h.Tags["trace.clock"] != "packet timestamps" {
		t.Errorf("header %+v", h)
	}
	if tg := c.Targets[0]; tg.Host != "10.0.0.2" || tg.Port != 502 || tg.Unit != 1 || tg.Label != "10.0.0.2:502 unit 1" || tg.Tags["trace.role_source"] != "syn" {
		t.Errorf("target %+v", tg)
	}
	if s := c.Streams[0]; s.Role != "passive" || s.Label != "client 10.0.0.1" {
		t.Errorf("stream %+v", s)
	}
}

// TestOptions: no exceptions, change-only, names, tick, selection.
func TestOptions(t *testing.T) {
	data := build(t, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		d := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.1:40001"), Server: srv2})
		for i := range 6 {
			c.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 1))
			c.Response(uint16(i), 1, tracetest.RegistersResponse(3, uint16(i/3))) // two distinct values
			d.Request(uint16(i), 1, tracetest.ReadRequest(4, 0, 1))
			d.Response(uint16(i), 1, tracetest.Exception(4, 2))
			b.Advance(time.Second)
		}
		c.Close()
		d.Close()
	})
	out, rep := export(t, data, Options{NoExceptions: true, ChangeOnly: true, TickNS: 1e6,
		Names: map[string]string{"10.0.0.2:502/1": "Inverter A"}}, "jsonl")
	identity(t, rep)
	c := readCapture(t, out, "jsonl")
	if rep.SamplesWritten != 2 || rep.ChangeOnlyDropped != 4 || rep.Excluded["exceptions_disabled"] != 6 ||
		c.Targets[0].Label != "Inverter A" || c.Header.TickNS != 1e6 || !c.Header.ChangeOnly || c.Header.Exceptions {
		t.Errorf("report %+v, header %+v", rep, c.Header)
	}
	from, to := 2*time.Second, 4*time.Second
	_, rep = export(t, data, Options{Selection: selection.Selection{Servers: []netip.AddrPort{srv}, FromOffset: &from, ToOffset: &to}}, "jsonl")
	identity(t, rep)
	if rep.Excluded["not_selected"] != 6 || rep.SamplesWritten != 2 || rep.Excluded["outside_window"] != 4 || rep.Selection == "" {
		t.Errorf("selection: %+v", rep)
	}
}

// TestWarnings: stale after write, unit collision, single sample, replay
// memory.
func TestWarnings(t *testing.T) {
	data := build(t, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, tracetest.ReadRequest(3, 100, 2))
		c.Response(1, 1, tracetest.RegistersResponse(3, 1, 2))
		c.Request(2, 1, []byte{6, 0, 101, 0, 9})
		c.Response(2, 1, []byte{6, 0, 101, 0, 9})
		d := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.1:40001"), Server: srv2})
		d.Request(1, 1, tracetest.ReadRequest(3, 0, 1))
		d.Response(1, 1, tracetest.RegistersResponse(3, 1))
	})
	_, rep := export(t, data, Options{WarnReplayMemory: 1}, "jsonl")
	codes := map[string]int{}
	for _, w := range rep.Warnings {
		codes[w.Code]++
		if w.Code == "stale_after_write" && (w.Space != "holding" || *w.Start != 101 || w.Target != 1) {
			t.Errorf("%+v", w)
		}
	}
	for _, c := range []string{"format_draft", "stale_after_write", "unit_collision", "single_sample_target", "replay_memory"} {
		if codes[c] == 0 {
			t.Errorf("no %s warning: %v", c, codes)
		}
	}
	if rep.Replay.EstimatedInMemoryBytes != 12<<20+750*2+36*3 {
		t.Errorf("replay estimate %+v", rep.Replay)
	}
}

// TestSeveralFiles: a trace split in two files exports the same samples as
// the whole.
func TestSeveralFiles(t *testing.T) {
	dir := t.TempDir()
	var whole, a, bb bytes.Buffer
	mk := func(w *bytes.Buffer) *tracetest.Builder {
		b, _ := tracetest.New(w, tracetest.Options{})
		return b
	}
	// The same script, cut after the third poll.
	script := func(first, second *tracetest.Builder) {
		c := first.Conn(tracetest.ConnOptions{})
		for i := range 6 {
			if i == 3 && second != first {
				c = second.ConnContinue(c)
			}
			c.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 1))
			c.Response(uint16(i), 1, tracetest.RegistersResponse(3, uint16(i)))
		}
		c.Close()
	}
	wb := mk(&whole)
	script(wb, wb)
	_ = wb.Close()
	ab, bbb := mk(&a), mk(&bb)
	script(ab, bbb)
	_ = ab.Close()
	_ = bbb.Close()
	pa, pb := filepath.Join(dir, "a.pcap"), filepath.Join(dir, "b.pcap")
	_ = os.WriteFile(pa, a.Bytes(), 0o600)
	_ = os.WriteFile(pb, bb.Bytes(), 0o600)
	f, err := trace.OpenFiles(pa, pb)
	if err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	rep, err := Export(context.Background(), f, trace.Options{}, Options{Producer: "test"}, func(h capture.Header) (capture.Writer, error) {
		return jsonl.NewWriter(&out, h)
	})
	if err != nil {
		t.Fatal(err)
	}
	split := readCapture(t, out.Bytes(), "jsonl")
	wholeOut, _ := export(t, whole.Bytes(), Options{}, "jsonl")
	one := readCapture(t, wholeOut, "jsonl")
	if len(split.Samples) != 6 || fmt.Sprint(split.Samples) != fmt.Sprint(one.Samples) || len(rep.Inputs) != 2 {
		t.Errorf("split %d samples, whole %d; inputs %+v", len(split.Samples), len(one.Samples), rep.Inputs)
	}
	if split.Header.Tags["trace.file"] != "a.pcap,b.pcap" {
		t.Errorf("tags %v", split.Header.Tags)
	}
}

// TestInvalidTime: a response without a timestamp, or stamped before 1970
// (a damaged clock), is excluded as invalid_time, and the capture starts at
// the earliest sample instead of at the impossible first packet.
func TestInvalidTime(t *testing.T) {
	sp, err := newSpool()
	if err != nil {
		t.Fatal(err)
	}
	defer sp.remove()
	x := &exporter{eo: Options{Producer: "test", TickNS: capture.DefaultTickNS, WarnReplayMemory: -1}, sp: sp, rep: newReport(),
		targets: map[targetKey]*target{}, streams: map[streamKey]*stream{}, writes: map[targetKey][]write{}}
	early, good := time.Unix(-3600, 0).UTC(), time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	txn := func(at *time.Time) *model.Event {
		return &model.Event{Kind: model.KindTxn, Txn: &model.Transaction{Conn: 1, Status: model.StatusOK, Function: 3, Class: "read",
			Client: netip.MustParseAddrPort("10.0.0.1:40000"), Server: netip.MustParseAddrPort("10.0.0.2:502"), Unit: 1,
			Request:  &model.ADU{PDU: tracetest.ReadRequest(3, 0, 1), First: at, Last: at},
			Response: &model.ADU{PDU: tracetest.RegistersResponse(3, 7), First: at, Last: at}}}
	}
	for _, at := range []*time.Time{nil, &early, &good} {
		if err := x.event(txn(at)); err != nil {
			t.Fatal(err)
		}
	}
	if err := sp.flush(); err != nil {
		t.Fatal(err)
	}
	var out bytes.Buffer
	var h capture.Header
	rep, err := x.write(&trace.FileSummary{First: &early, Last: &good}, func(hh capture.Header) (capture.Writer, error) {
		h = hh
		return jsonl.NewWriter(&out, hh)
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Excluded[string(InvalidTime)] != 2 || rep.SamplesWritten != 1 || !h.WallStart.Equal(good) {
		t.Errorf("excluded %v, written %d, wall start %v", rep.Excluded, rep.SamplesWritten, h.WallStart)
	}
	identity(t, rep)
}

// TestMoreWarnings produces the warnings and the reason TestWarnings does
// not: capture drops, a gap in the window, a role from structure only,
// time disorder, and transactions of a connection whose roles are unknown.
func TestMoreWarnings(t *testing.T) {
	data := build(t, func(b *tracetest.Builder) {
		// Structure only: no handshake, not a server port.
		c := b.Conn(tracetest.ConnOptions{Midstream: true, Server: netip.MustParseAddrPort("10.0.0.9:1502")})
		for i := range 25 {
			c.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 1))
			c.Response(uint16(i), 1, tracetest.RegistersResponse(3, uint16(i)))
		}
		// A lost response segment: the transaction after it is uncertain.
		g := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.1:40001"), Server: srv2})
		g.Request(1, 2, tracetest.ReadRequest(4, 0, 1))
		g.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: 1, Unit: 2, PDU: tracetest.RegistersResponse(4, 1)})
		g.Request(2, 2, tracetest.ReadRequest(4, 0, 1))
		g.Response(2, 2, tracetest.RegistersResponse(4, 2))
		// The clock steps back five seconds.
		b.Advance(-5 * time.Second)
		g.Request(3, 2, tracetest.ReadRequest(4, 0, 1))
		g.Response(3, 2, tracetest.RegistersResponse(4, 3))
		// Roles undecidable: two vendor frames on port 7.
		u := b.Conn(tracetest.ConnOptions{Midstream: true, Client: netip.MustParseAddrPort("10.0.0.8:41000"), Server: netip.MustParseAddrPort("10.0.0.9:7")})
		u.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{TID: 1, Unit: 1, PDU: []byte{0x41, 1}})
		u.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{TID: 2, Unit: 1, PDU: []byte{0x41, 2}})
		b.InterfaceDrops(0, 7)
	})
	_, rep := export(t, data, Options{}, "jsonl")
	codes := map[string]int{}
	for _, w := range rep.Warnings {
		codes[w.Code]++
	}
	for _, c := range []string{WarnCaptureDrops, WarnGapInWindow, WarnRoleGuessed, WarnTimeDisorder} {
		if codes[c] == 0 {
			t.Errorf("no %s warning: %+v", c, rep.Warnings)
		}
	}
	if rep.Excluded[string(RoleUnknown)] == 0 || rep.Quality.CaptureDrops != 7 || rep.Quality.Midstream == 0 || rep.Quality.RoleGuessed == 0 {
		t.Errorf("excluded %v, quality %+v", rep.Excluded, rep.Quality)
	}
	identity(t, rep)

	// A window that ends before the gap (packets are 100 µs apart) has no
	// gap warning.
	to := 5 * time.Millisecond
	_, rep = export(t, data, Options{Selection: selection.Selection{ToOffset: &to}}, "jsonl")
	for _, w := range rep.Warnings {
		if w.Code == WarnGapInWindow {
			t.Errorf("gap warning for a window without the gap: %+v", w)
		}
	}
}

// failWriter fails at one stage of writing.
type failWriter struct{ at string }

var errDisk = errors.New("disk full")

func (w failWriter) fail(s string) error {
	if w.at == s {
		return errDisk
	}
	return nil
}
func (w failWriter) WriteTarget(capture.Target) error { return w.fail("target") }
func (w failWriter) WriteStream(capture.Stream) error { return w.fail("stream") }
func (w failWriter) WriteSample(capture.Sample) error { return w.fail("sample") }
func (w failWriter) Close(capture.End) error          { return w.fail("close") }

// TestErrors: invalid options, a writer that fails at each stage (an I/O
// error, not ErrWriter), and the checker refusing a target, a stream and a
// sample (ErrWriter: a bug the exporter must never cause).
func TestErrors(t *testing.T) {
	data := build(t, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, tracetest.ReadRequest(3, 0, 1))
		c.Response(1, 1, tracetest.RegistersResponse(3, 1))
	})
	f := func() *trace.File { return trace.OpenReader(bytes.NewReader(data)) }
	open := func(w capture.Writer) Open { return func(capture.Header) (capture.Writer, error) { return w, nil } }
	for _, eo := range []Options{{}, {Producer: "x", TickNS: capture.MaxTickNS + 1}} {
		if _, err := Export(context.Background(), f(), trace.Options{}, eo, open(failWriter{})); !errors.Is(err, ErrOptions) {
			t.Errorf("%+v: %v", eo, err)
		}
	}
	for _, at := range []string{"target", "stream", "sample", "close"} {
		_, err := Export(context.Background(), f(), trace.Options{}, Options{Producer: "x"}, open(failWriter{at: at}))
		if !errors.Is(err, errDisk) || errors.Is(err, ErrWriter) {
			t.Errorf("writer failing at %s: %v", at, err)
		}
	}
	if _, err := Export(context.Background(), f(), trace.Options{}, Options{Producer: "x"},
		func(capture.Header) (capture.Writer, error) { return nil, errDisk }); !errors.Is(err, errDisk) {
		t.Errorf("open: %v", err)
	}

	// The checker's refusals, provoked inside: they are ErrWriter.
	refused := func(change func(x *exporter)) error {
		sp, err := newSpool()
		if err != nil {
			t.Fatal(err)
		}
		defer sp.remove()
		x := &exporter{eo: Options{Producer: "x", TickNS: capture.DefaultTickNS}, sp: sp, rep: newReport(),
			targets: map[targetKey]*target{}, streams: map[streamKey]*stream{}, writes: map[targetKey][]write{}}
		at := time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
		err = x.event(&model.Event{Kind: model.KindTxn, Txn: &model.Transaction{Conn: 1, Status: model.StatusOK, Function: 3, Class: "read",
			Client: netip.MustParseAddrPort("10.0.0.1:40000"), Server: srv, Unit: 1,
			Request:  &model.ADU{PDU: tracetest.ReadRequest(3, 0, 1), First: &at, Last: &at},
			Response: &model.ADU{PDU: tracetest.RegistersResponse(3, 7), First: &at, Last: &at}}})
		if err != nil {
			t.Fatal(err)
		}
		change(x)
		if err := sp.flush(); err != nil {
			t.Fatal(err)
		}
		_, err = x.write(&trace.FileSummary{First: &at, Last: &at}, open(failWriter{}))
		return err
	}
	for name, change := range map[string]func(x *exporter){
		"target": func(x *exporter) { x.tlist[0].ID = 0 },
		"stream": func(x *exporter) { x.tlist[0].streams[0].Target = 99 },
		"sample": func(x *exporter) {
			_ = x.sp.add(x.tlist[0].streams[0].ID, time.Date(2026, 10, 15, 8, 0, 1, 0, time.UTC).UnixNano(), []byte{6, 0, 0, 0, 1}, []byte{6, 0, 0, 0, 1})
		},
		"header": func(x *exporter) { x.eo.Producer = strings.Repeat("p", 70000) },
	} {
		if err := refused(change); !errors.Is(err, ErrWriter) {
			t.Errorf("checker refusing the %s: %v", name, err)
		}
	}
}

// TestQualityCounts: the flags that do not exclude are counted.
func TestQualityCounts(t *testing.T) {
	data := build(t, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, tracetest.ReadRequest(3, 0, 1))
		c.Request(1, 1, tracetest.ReadRequest(3, 0, 1)) // retried
		b.Advance(2 * time.Second)                      // slow
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{5, 4}, Reverse: true}, tracetest.Frame{TID: 1, Unit: 1, PDU: tracetest.RegistersResponse(3, 1)})
		c.Request(2, 1, tracetest.ReadRequest(3, 0, 1))
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Retransmit: []int{0}}, tracetest.Frame{TID: 2, Unit: 1, PDU: tracetest.RegistersResponse(3, 1)})
	})
	_, rep := export(t, data, Options{ChangeOnly: true}, "jsonl")
	q := rep.Quality
	if q.Retried == 0 || q.Slow == 0 || q.OutOfOrder == 0 || rep.ChangeOnlyDropped != 1 {
		t.Errorf("quality %+v, change-only dropped %d", q, rep.ChangeOnlyDropped)
	}
	identity(t, rep)
}
