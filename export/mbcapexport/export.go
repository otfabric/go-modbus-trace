// SPDX-License-Identifier: MIT

package mbcapexport

import (
	"bufio"
	"context"
	"encoding/binary"
	"errors"
	"fmt"
	"hash/fnv"
	"io"
	"net/netip"
	"os"
	"runtime/debug"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/edit"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
)

// DefaultWarnReplayMemory is the estimate above which the report warns
// that a replay needs much memory.
const DefaultWarnReplayMemory = 1 << 30

// Options shape an export.
type Options struct {
	// Producer names the tool for the header (required), e.g.
	// "mbtracectl 0.1.0".
	Producer string
	// Step is the provenance step (command and flags, no file names);
	// default "go-modbus-trace <version> export mbcap".
	Step string
	// TickNS is the tick size, 1 ns to 1 s (default capture.DefaultTickNS).
	TickNS uint64
	// ChangeOnly writes a change-only capture.
	ChangeOnly bool
	// NoExceptions leaves exception responses out.
	NoExceptions bool
	// Names labels targets: "ip:port/unit" -> label.
	Names map[string]string
	// Selection selects transactions; its time window also sets the
	// capture start.
	Selection selection.Selection
	// WarnReplayMemory is the replay estimate above which the report warns
	// (0: DefaultWarnReplayMemory; negative: never).
	WarnReplayMemory int64
}

// Open returns the writer for a capture with header h.
type Open func(h capture.Header) (capture.Writer, error)

// ErrWriter reports a sample the writer or the capture checker refused. It
// is a bug: the exporter only writes admissible samples.
var ErrWriter = errors.New("mbcapexport: the capture library refused a sample")

type targetKey struct {
	server netip.AddrPort
	unit   uint8
}

type streamKey struct {
	target uint32
	client netip.Addr
}

// Export analyses f and writes the admitted transactions through the
// writer open returns, then returns the report. The samples are spooled to
// a temporary file during the pass, so the header can carry what is known
// only at the end (the earliest timestamp, the hashes).
func Export(ctx context.Context, f *trace.File, o trace.Options, eo Options, open Open) (*Report, error) {
	if eo.Producer == "" {
		return nil, errors.New("mbcapexport: Options.Producer is required")
	}
	if eo.TickNS == 0 {
		eo.TickNS = capture.DefaultTickNS
	}
	if eo.TickNS > capture.MaxTickNS {
		return nil, fmt.Errorf("mbcapexport: tick of %d ns, want 1 to %d", eo.TickNS, capture.MaxTickNS)
	}
	if eo.WarnReplayMemory == 0 {
		eo.WarnReplayMemory = DefaultWarnReplayMemory
	}
	sp, err := newSpool()
	if err != nil {
		return nil, err
	}
	defer sp.remove()
	x := &exporter{eo: eo, sp: sp, rep: newReport(), targets: map[targetKey]*target{}, streams: map[streamKey]*stream{},
		writes: map[targetKey][]write{}}
	x.sel = eo.Selection
	x.noTime = eo.Selection
	x.noTime.From, x.noTime.To, x.noTime.FromOffset, x.noTime.ToOffset = nil, nil, nil, nil
	prev := o.FirstPacket
	o.FirstPacket = func(t time.Time) {
		x.sel.Resolve(t)
		if prev != nil {
			prev(t)
		}
	}
	o.OmitPDU = false
	sum, err := trace.Analyze(ctx, f, o, trace.SinkFunc(x.event))
	if err != nil {
		return nil, err
	}
	if err := sp.flush(); err != nil {
		return nil, err
	}
	return x.write(sum, open)
}

// Per-target bounds on the state the report needs (values is bounded by the
// address spaces: 4 × 65,536).
const (
	maxReadRanges = 65_536 // distinct read ranges kept for stale_after_write
	maxRequests   = 65_536 // distinct other requests whose last response is kept
)

type target struct {
	capture.Target
	key     targetKey
	role    string
	streams []*stream
	rep     *TargetReport
	reads   map[readKey]int64 // last time each exported read range was read
	values  map[uint32]uint16 // FC01-04 last value per address, for the replay estimate
	resps   map[string]uint64 // other functions: hash of the last response per request
}

type stream struct {
	capture.Stream
	rep *StreamReport
}

type readKey struct {
	space        string
	start, count uint16
}

type write struct {
	space        string
	start, count uint16
	at           int64
}

type exporter struct {
	eo      Options
	sel     selection.Selection // with the time window resolved
	noTime  selection.Selection // the same without the time window
	sp      *spool
	rep     *Report
	targets map[targetKey]*target
	tlist   []*target
	streams map[streamKey]*stream
	nstream uint32
	writes  map[targetKey][]write
	roles   map[uint32]string
}

func (x *exporter) event(e *model.Event) error {
	if e.Conn != nil && e.Kind == model.KindConnOpen {
		if x.roles == nil {
			x.roles = map[uint32]string{}
		}
		x.roles[e.Conn.ID] = e.Conn.RoleSource
	}
	t := e.Txn
	if t == nil {
		return nil
	}
	x.rep.TransactionsSeen++
	x.noteQuality(t)
	key := targetKey{t.Server, t.Unit}
	if t.Status == model.StatusOK && t.Class == "write" {
		x.recordWrite(key, t)
	}
	r := Classify(t)
	if r == Admit && t.Status == model.StatusException && x.eo.NoExceptions {
		r = ExceptionsDisabled
	}
	if r == Admit && !x.noTime.Match(t) {
		r = NotSelected
	}
	if r == Admit && !x.sel.Match(t) {
		r = OutsideWindow
	}
	if r != Admit {
		x.rep.Excluded[string(r)]++
		return nil
	}
	tg := x.targets[key]
	if tg == nil {
		tg = &target{key: key, role: x.roles[t.Conn], reads: map[readKey]int64{}, values: map[uint32]uint16{}, resps: map[string]uint64{}}
		tg.ID = uint32(len(x.tlist) + 1)
		tg.Transport = capture.TransportTCP
		tg.Host, tg.Port, tg.Unit = t.Server.Addr().String(), t.Server.Port(), t.Unit
		tg.Label = x.eo.Names[fmt.Sprintf("%s/%d", t.Server, t.Unit)]
		if tg.Label == "" {
			tg.Label = fmt.Sprintf("%s unit %d", t.Server, t.Unit)
		}
		tg.Tags = map[string]string{"trace.role_source": tg.role}
		x.targets[key] = tg
		x.tlist = append(x.tlist, tg)
	}
	sk := streamKey{tg.ID, t.Client.Addr()}
	st := x.streams[sk]
	if st == nil {
		x.nstream++
		st = &stream{Stream: capture.Stream{ID: x.nstream, Target: tg.ID, Role: "passive", Label: "client " + t.Client.Addr().String()}}
		x.streams[sk] = st
		tg.streams = append(tg.streams, st)
	}
	at := t.Response.Last
	if at == nil {
		at = t.Response.First
	}
	if at == nil {
		x.rep.Excluded[string(Malformed)]++ // no timestamp (pcapng simple packets): no sample time
		return nil
	}
	if t.Status == model.StatusOK {
		for _, rg := range t.Ranges {
			k := readKey{string(rg.Space), rg.Start, rg.Count}
			if _, ok := tg.reads[k]; !rg.Write && (ok || len(tg.reads) < maxReadRanges) {
				tg.reads[k] = at.UnixNano()
			}
		}
	}
	return x.sp.add(st.ID, at.UnixNano(), t.Request.PDU, t.Response.PDU)
}

func (x *exporter) recordWrite(key targetKey, t *model.Transaction) {
	ws := x.writes[key]
	tt := t.Time()
	if tt == nil {
		return
	}
	for _, rg := range t.Ranges {
		if rg.Write {
			ws = append(ws, write{string(rg.Space), rg.Start, rg.Count, tt.UnixNano()})
		}
	}
	if len(ws) > 4096 { // bounded: the most recent writes
		ws = append(ws[:0], ws[len(ws)-4096:]...)
	}
	x.writes[key] = ws
}

func (x *exporter) noteQuality(t *model.Transaction) {
	for _, f := range t.Flags {
		switch f {
		case model.FlagRetransmitted:
			x.rep.Quality.Retransmitted++
		case model.FlagResynced:
			x.rep.Quality.Resyncs++
		case model.FlagSnaplen:
			x.rep.Quality.SnaplenTruncated++
		}
	}
}

// write writes the capture from the spool and completes the report.
func (x *exporter) write(sum *trace.FileSummary, open Open) (*Report, error) {
	rep := x.rep
	wall := time.Unix(0, 0).UTC()
	if sum.First != nil {
		wall = *sum.First
	}
	if x.sel.From != nil {
		wall = *x.sel.From
	}
	h := capture.Header{TickNS: x.eo.TickNS, WallStart: wall, ChangeOnly: x.eo.ChangeOnly, Exceptions: !x.eo.NoExceptions,
		Producer: x.eo.Producer, Tags: x.tags(sum)}
	step := x.eo.Step
	if step == "" {
		step = "go-modbus-trace " + trace.Version + " export mbcap"
	}
	h = edit.WithProvenance(h, step)
	ticks := func(ns int64) capture.Ticks { return h.Ticks(time.Duration(ns - wall.UnixNano())) }
	end := capture.End{Known: true}
	if sum.Last != nil {
		end.At = ticks(sum.Last.UnixNano())
	}
	if x.sel.To != nil && sum.Last != nil && x.sel.To.Before(*sum.Last) {
		end.At = ticks(x.sel.To.UnixNano())
	}
	w, err := open(h)
	if err != nil {
		return nil, err
	}
	chk, err := capture.NewChecker(h)
	if err != nil {
		return nil, fmt.Errorf("%w: header: %v", ErrWriter, err)
	}
	byID := map[uint32]*stream{}
	tgOf := map[uint32]*target{}
	for _, tg := range x.tlist {
		if err := chk.Target(tg.Target); err != nil {
			return nil, fmt.Errorf("%w: target %d: %v", ErrWriter, tg.ID, err)
		}
		if err := w.WriteTarget(tg.Target); err != nil {
			return nil, err
		}
		tg.rep = &TargetReport{ID: tg.ID, Server: tg.key.server.String(), Unit: tg.Unit, Label: tg.Label, RoleSource: tg.role,
			ByFunction: map[string]uint64{}}
		for _, st := range tg.streams {
			if err := chk.Stream(st.Stream); err != nil {
				return nil, fmt.Errorf("%w: stream %d: %v", ErrWriter, st.ID, err)
			}
			if err := w.WriteStream(st.Stream); err != nil {
				return nil, err
			}
			st.rep = &StreamReport{ID: st.ID, Client: strings.TrimPrefix(st.Label, "client "), Samples: 0}
			byID[st.ID] = st
			tgOf[st.ID] = tg
		}
	}
	var lastAt capture.Ticks
	disorder := false
	err = x.sp.each(func(id uint32, ns int64, req, resp []byte) error {
		s := capture.Sample{Stream: id, At: ticks(ns), Request: req, Response: resp}
		keep, err := chk.Admit(s)
		if err != nil {
			return fmt.Errorf("%w: %v", ErrWriter, err)
		}
		if !keep {
			rep.ChangeOnlyDropped++
			return nil
		}
		if err := w.WriteSample(s); err != nil {
			return fmt.Errorf("%w: %v", ErrWriter, err)
		}
		if s.At+capture.Ticks(time.Second/time.Duration(h.TickNS)) < lastAt {
			disorder = true
		}
		lastAt = max(lastAt, s.At)
		rep.SamplesWritten++
		st, tg := byID[id], tgOf[id]
		st.rep.Samples++
		x.account(tg, ns, req, resp)
		return nil
	})
	if err != nil {
		return nil, err
	}
	if end.At < lastAt {
		end.At = lastAt
	}
	if err := chk.End(end); err != nil {
		return nil, fmt.Errorf("%w: end: %v", ErrWriter, err)
	}
	if err := w.Close(end); err != nil {
		return nil, err
	}
	x.finishReport(sum, h, disorder)
	return rep, nil
}

// account adds a written sample to its target's report and to the replay
// estimate.
func (x *exporter) account(tg *target, ns int64, req, resp []byte) {
	r := tg.rep
	r.Samples++
	t := time.Unix(0, ns).UTC()
	if r.First == nil || t.Before(*r.First) {
		r.First = &t
	}
	if r.Last == nil || t.After(*r.Last) {
		r.Last = &t
	}
	r.ByFunction[strconv.Itoa(int(req[0]))]++
	if resp[0]&0x80 != 0 {
		r.Exceptions++
		return // exceptions are not hosted by a replay
	}
	if req[0] <= 4 {
		if av, ok := capture.SplitAddresses(&capture.Sample{Request: req, Response: resp}); ok {
			for i, v := range av.Values {
				k := uint32(req[0])<<16 | uint32(av.Start+uint16(i))
				if old, seen := tg.values[k]; !seen || old != v {
					x.rep.changed++
					tg.values[k] = v
				}
			}
		}
		return
	}
	h := fnv.New64a()
	h.Write(resp)
	sum := h.Sum64()
	old, seen := tg.resps[string(req)]
	if !seen || old != sum {
		x.rep.changed += uint64(len(resp)) // past the cap every response counts: the estimate stays an upper bound
		if seen || len(tg.resps) < maxRequests {
			tg.resps[string(req)] = sum
		}
	}
}

// tags are the header tags of MBCAP-EXPORT.md section 2.
func (x *exporter) tags(sum *trace.FileSummary) map[string]string {
	t := map[string]string{
		"trace.clock":            "packet timestamps",
		"export.admission":       "reads-only/1",
		"export.library":         "go-modbus-trace " + trace.Version,
		"export.capture_library": "go-modbus-capture " + CaptureLibraryVersion(),
	}
	var files, sums, formats []string
	for _, in := range sum.Inputs {
		files = append(files, in.File)
		sums = append(sums, in.SHA256)
		formats = append(formats, in.Format)
	}
	t["trace.file"] = strings.Join(files, ",") // base names (trace.Input), never paths
	t["trace.sha256"] = strings.Join(sums, ",")
	t["trace.format"] = strings.Join(formats, ",")
	if sum.First != nil {
		t["trace.first_packet"] = sum.First.Format(time.RFC3339Nano)
		t["trace.last_packet"] = sum.Last.Format(time.RFC3339Nano)
	}
	links := map[string]bool{}
	for _, f := range sum.Interfaces {
		links[f.Link] = true
	}
	var ls []string
	for l := range links {
		ls = append(ls, l)
	}
	sort.Strings(ls)
	t["trace.link_types"] = strings.Join(ls, ",")
	var tools []string
	for _, s := range sum.Sections {
		if v := strings.TrimSpace(s.Application + " " + s.OS); v != "" {
			tools = append(tools, v)
		}
	}
	if len(tools) > 0 {
		t["trace.tool"] = strings.Join(tools, "; ")
	}
	if sel := x.eo.Selection.String(); sel != "" {
		t["export.selection"] = sel
	}
	return t
}

// CaptureLibraryVersion returns the version of go-modbus-capture linked in.
func CaptureLibraryVersion() string {
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, d := range bi.Deps {
			if d.Path == "github.com/otfabric/go-modbus-capture" {
				if d.Replace != nil {
					return d.Replace.Version
				}
				return d.Version
			}
		}
	}
	return "unknown"
}

// spool holds the admitted samples in a temporary file during the pass.
type spool struct {
	f *os.File
	w *bufio.Writer
}

func newSpool() (*spool, error) {
	f, err := os.CreateTemp("", "mbtrace-spool-*")
	if err != nil {
		return nil, err
	}
	return &spool{f: f, w: bufio.NewWriterSize(f, 1<<20)}, nil
}

func (s *spool) add(stream uint32, ns int64, req, resp []byte) error {
	if len(req) > capture.MaxPDULen || len(resp) > capture.MaxPDULen {
		return fmt.Errorf("%w: a PDU of more than %d bytes", ErrWriter, capture.MaxPDULen)
	}
	var h [14]byte
	binary.LittleEndian.PutUint32(h[0:], stream)
	binary.LittleEndian.PutUint64(h[4:], uint64(ns))
	h[12], h[13] = byte(len(req)), byte(len(resp))
	if _, err := s.w.Write(h[:]); err != nil {
		return err
	}
	if _, err := s.w.Write(req); err != nil {
		return err
	}
	_, err := s.w.Write(resp)
	return err
}

func (s *spool) flush() error { return s.w.Flush() }

func (s *spool) each(fn func(stream uint32, ns int64, req, resp []byte) error) error {
	if _, err := s.f.Seek(0, io.SeekStart); err != nil {
		return err
	}
	r := bufio.NewReaderSize(s.f, 1<<20)
	var h [14]byte
	buf := make([]byte, 2*capture.MaxPDULen)
	for {
		if _, err := io.ReadFull(r, h[:]); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
		n1, n2 := int(h[12]), int(h[13])
		b := buf[:n1+n2]
		if _, err := io.ReadFull(r, b); err != nil {
			return err
		}
		if err := fn(binary.LittleEndian.Uint32(h[0:]), int64(binary.LittleEndian.Uint64(h[4:])), b[:n1], b[n1:]); err != nil {
			return err
		}
	}
}

func (s *spool) remove() {
	_ = s.f.Close()
	_ = os.Remove(s.f.Name())
}
