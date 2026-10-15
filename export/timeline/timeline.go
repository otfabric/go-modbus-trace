// SPDX-License-Identifier: MIT

// Package timeline writes a trace's events as CSV or JSON Lines, one row or
// line per event, ordered by time (with a bounded reorder window) or in
// order of determination (ARCHITECTURE.md section 11, REQUIREMENTS.md L14).
package timeline

import (
	"bufio"
	"bytes"
	"container/heap"
	"context"
	"encoding/csv"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
)

// Format is an output encoding.
type Format int

// Formats.
const (
	CSV Format = iota + 1
	JSONL
)

// Order is the row order.
type Order int

// Orders.
const (
	ByTime Order = iota // by event time, through a reorder window
	ByFile              // in order of determination
)

// DefaultWindow is the reorder window of ByTime, in trace time.
const DefaultWindow = 60 * time.Second

// DefaultBuffer bounds the encoded rows held for reordering. When it is
// full the oldest row is written early; what then arrives older than it is
// written out of order and counted (Stats.Late).
const DefaultBuffer = 64 << 20

// Options shape the export.
type Options struct {
	Format    Format
	Order     Order
	Window    time.Duration // ByTime reorder window (DefaultWindow)
	Buffer    int           // ByTime reorder buffer in bytes (DefaultBuffer)
	Selection selection.Selection
}

// Stats report what was written.
type Stats struct {
	Rows uint64 // rows or lines written
	Late uint64 // events older than the window, written out of order
}

// Write analyses f and writes its timeline to w.
func Write(ctx context.Context, f *trace.File, o trace.Options, w io.Writer, to Options) (*trace.FileSummary, Stats, error) {
	if to.Window <= 0 {
		to.Window = DefaultWindow
	}
	if to.Buffer <= 0 {
		to.Buffer = DefaultBuffer
	}
	tw, err := newWriter(w, to.Format)
	if err != nil {
		return nil, Stats{}, err
	}
	s := &sink{to: to, w: tw}
	sel := &s.to.Selection
	prev := o.FirstPacket
	o.FirstPacket = func(t time.Time) {
		sel.Resolve(t)
		if prev != nil {
			prev(t)
		}
	}
	sum, err := trace.Analyze(ctx, f, o, s)
	if err == nil || sum != nil {
		if ferr := s.flush(); err == nil {
			err = ferr
		}
	}
	if ferr := tw.close(); err == nil {
		err = ferr
	}
	return sum, s.st, err
}

// sink filters events and orders them.
type sink struct {
	to      Options
	w       *writer
	st      Stats
	q       queue
	held    int // bytes of encoded rows in q
	newest  time.Time
	emitted time.Time
	conns   map[uint32]bool // connections whose events are selected
}

func (s *sink) Event(e *model.Event) error {
	if !s.selected(e) {
		return nil
	}
	line, err := s.w.encode(e)
	if err != nil {
		return err
	}
	if s.to.Order == ByFile {
		return s.write(line)
	}
	t := s.newest
	if e.Time != nil {
		t = *e.Time
	}
	if t.After(s.newest) {
		s.newest = t
	}
	heap.Push(&s.q, item{t: t, seq: e.Seq, line: line})
	s.held += len(line)
	for s.q.Len() > 0 && (s.q[0].t.Before(s.newest.Add(-s.to.Window)) || s.held > s.to.Buffer) {
		if err := s.pop(); err != nil {
			return err
		}
	}
	return nil
}

func (s *sink) pop() error {
	it := heap.Pop(&s.q).(item)
	s.held -= len(it.line)
	if it.t.Before(s.emitted) {
		s.st.Late++
	} else {
		s.emitted = it.t
	}
	return s.write(it.line)
}

func (s *sink) flush() error {
	for s.q.Len() > 0 {
		if err := s.pop(); err != nil {
			return err
		}
	}
	return nil
}

func (s *sink) selected(e *model.Event) bool {
	sel := &s.to.Selection
	switch {
	case e.Txn != nil:
		return sel.Match(e.Txn)
	case e.Conn != nil:
		ok := sel.MatchConn(e.Conn.ID, e.Conn.Client, e.Conn.Server)
		if s.conns == nil {
			s.conns = map[uint32]bool{}
		}
		s.conns[e.Conn.ID] = ok
		return ok
	case e.Gap != nil:
		return s.conns[e.Gap.Conn]
	case e.Resync != nil:
		return s.conns[e.Resync.Conn]
	default:
		return true
	}
}

func (s *sink) write(line []byte) error {
	s.st.Rows++
	_, err := s.w.bw.Write(line)
	return err
}

type item struct {
	t    time.Time
	seq  uint64
	line []byte
}

// queue is a min-heap by time, then determination order.
type queue []item

func (q queue) Len() int { return len(q) }
func (q queue) Less(i, j int) bool {
	if !q[i].t.Equal(q[j].t) {
		return q[i].t.Before(q[j].t)
	}
	return q[i].seq < q[j].seq
}
func (q queue) Swap(i, j int) { q[i], q[j] = q[j], q[i] }
func (q *queue) Push(x any)   { *q = append(*q, x.(item)) }
func (q *queue) Pop() any {
	old := *q
	it := old[len(old)-1]
	*q = old[:len(old)-1]
	return it
}

// ErrUnknownFormat is wrapped by the error Write returns for a Format it
// does not know.
var ErrUnknownFormat = errors.New("timeline: unknown format")

// Columns are the CSV columns, in order.
var Columns = []string{"kind", "seq", "time", "conn", "client", "server", "unit", "tid", "function", "sub", "class",
	"status", "exception", "latency_ns", "flags", "warnings", "summary", "ranges",
	"request_pdu", "response_pdu", "request_frames", "response_frames",
	"request_first", "request_last", "response_first", "response_last",
	"role_source", "open", "close", "dir", "pos", "bytes", "reason", "note"}

type writer struct {
	bw     *bufio.Writer
	csv    *csv.Writer // writes into scr
	scr    bytes.Buffer
	format Format
}

func newWriter(w io.Writer, f Format) (*writer, error) {
	tw := &writer{bw: bufio.NewWriterSize(w, 1<<20), format: f}
	switch f {
	case CSV:
		tw.csv = csv.NewWriter(&tw.scr)
		if err := tw.csv.Write(Columns); err != nil {
			return nil, err
		}
		tw.csv.Flush()
		_, err := tw.bw.Write(tw.scr.Bytes())
		tw.scr.Reset()
		return tw, err
	case JSONL:
		return tw, nil
	default:
		return nil, fmt.Errorf("%w %d", ErrUnknownFormat, f)
	}
}

func (w *writer) close() error { return w.bw.Flush() }

// encode returns the event as one encoded line.
func (w *writer) encode(e *model.Event) ([]byte, error) {
	if w.format == JSONL {
		w.scr.Reset()
		enc := json.NewEncoder(&w.scr)
		enc.SetEscapeHTML(false)
		if err := enc.Encode(e); err != nil {
			return nil, err
		}
		return append([]byte(nil), w.scr.Bytes()...), nil
	}
	w.scr.Reset()
	if err := w.csv.Write(row(e)); err != nil {
		return nil, err
	}
	w.csv.Flush()
	if err := w.csv.Error(); err != nil {
		return nil, err
	}
	return append([]byte(nil), w.scr.Bytes()...), nil
}

func ts(t *time.Time) string {
	if t == nil {
		return ""
	}
	return t.UTC().Format(time.RFC3339Nano)
}

func u(x uint64) string { return strconv.FormatUint(x, 10) }

func frames(a *model.ADU) string {
	if a == nil {
		return ""
	}
	p := make([]string, len(a.Refs))
	for i, r := range a.Refs {
		p[i] = u(r.Frame)
	}
	return strings.Join(p, ";")
}

// row flattens an event into the CSV columns.
func row(e *model.Event) []string {
	r := make(map[string]string, len(Columns))
	r["kind"], r["seq"], r["time"] = e.Kind, u(e.Seq), ts(e.Time)
	switch {
	case e.Txn != nil:
		t := e.Txn
		r["conn"], r["client"], r["server"] = u(uint64(t.Conn)), t.Client.String(), t.Server.String()
		r["unit"], r["tid"], r["function"] = u(uint64(t.Unit)), u(uint64(t.TID)), u(uint64(t.Function))
		if t.Sub != nil {
			r["sub"] = u(uint64(*t.Sub))
		}
		r["class"], r["status"], r["summary"] = t.Class, t.Status, t.Summary
		if t.Exception != 0 {
			r["exception"] = u(uint64(t.Exception))
		}
		if t.LatencyNS != 0 || t.Response != nil && t.Request != nil {
			r["latency_ns"] = strconv.FormatInt(t.LatencyNS, 10)
		}
		r["flags"], r["warnings"] = strings.Join(t.Flags, "|"), strings.Join(t.Warnings, "|")
		var rs []string
		for _, x := range t.Ranges {
			s := fmt.Sprintf("%s:%d+%d", x.Space, x.Start, x.Count)
			if x.Write {
				s += ":w"
			}
			rs = append(rs, s)
		}
		r["ranges"] = strings.Join(rs, ";")
		if t.Request != nil {
			r["request_pdu"], r["request_frames"] = fmt.Sprintf("%x", []byte(t.Request.PDU)), frames(t.Request)
			r["request_first"], r["request_last"] = ts(t.Request.First), ts(t.Request.Last)
		}
		if t.Response != nil {
			r["response_pdu"], r["response_frames"] = fmt.Sprintf("%x", []byte(t.Response.PDU)), frames(t.Response)
			r["response_first"], r["response_last"] = ts(t.Response.First), ts(t.Response.Last)
		}
	case e.Conn != nil:
		c := e.Conn
		r["conn"], r["client"], r["server"] = u(uint64(c.ID)), c.Client.String(), c.Server.String()
		r["role_source"], r["open"], r["close"] = c.RoleSource, c.Open, c.Close
	case e.Gap != nil:
		g := e.Gap
		r["conn"], r["dir"], r["pos"] = u(uint64(g.Conn)), g.Dir, u(g.Pos)
		r["bytes"], r["reason"] = strconv.FormatInt(g.Bytes, 10), g.Reason
	case e.Resync != nil:
		x := e.Resync
		r["conn"], r["dir"], r["pos"] = u(uint64(x.Conn)), x.Dir, u(x.Pos)
		r["bytes"], r["reason"] = strconv.Itoa(x.Skipped), x.Confidence
	case e.Note != nil:
		r["reason"], r["note"] = e.Note.Code, e.Note.Text
		if e.Note.Count != 0 {
			r["bytes"] = u(e.Note.Count)
		}
	}
	out := make([]string, len(Columns))
	for i, c := range Columns {
		out[i] = r[c]
	}
	return out
}
