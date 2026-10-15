// SPDX-License-Identifier: MIT

package trace

import (
	"context"
	"time"

	"github.com/otfabric/go-modbus-trace/internal/flow"
	"github.com/otfabric/go-modbus-trace/internal/pair"
	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
)

// Options configure Analyze.
type Options struct {
	ScanOptions
	// Flows restricts the events to these flow IDs (as Scan numbers them);
	// nil means every flow.
	Flows []uint32
	// Slow is the latency above which a transaction is flagged slow (1 s).
	Slow time.Duration
	// MaxOutstanding bounds the unanswered requests per connection (256).
	MaxOutstanding int
	// OmitPDU leaves the PDU bytes out of the events (they stay
	// recoverable through the frame references).
	OmitPDU bool
	// FirstPacket, if set, is called once with the time of the first
	// timestamped packet, before any event that follows it (for selections
	// relative to the start of the trace).
	FirstPacket func(time.Time)
}

// Sink receives events in order of determination. An error stops the pass.
type Sink interface {
	Event(e *model.Event) error
}

// SinkFunc adapts a function to a Sink.
type SinkFunc func(e *model.Event) error

// Event implements Sink.
func (f SinkFunc) Event(e *model.Event) error { return f(e) }

// maxQueued bounds the ADUs per direction held while a connection's roles
// are undecided; then the roles are decided with what there is.
const maxQueued = 64

// Analyze reads the whole trace once and sends its events to sink:
// connections, transactions (paired, decoded and validated), gaps, resyncs
// and notes, in order of determination. Consumers sort transactions by
// their request time. It returns the file summary, with the transaction
// counters.
func Analyze(ctx context.Context, f *File, o Options, sink Sink) (*FileSummary, error) {
	an := &analysis{o: o, sink: sink, status: map[string]uint64{}, flags: map[string]uint64{}}
	if o.Flows != nil {
		an.flows = map[uint32]bool{}
		for _, id := range o.Flows {
			an.flows[id] = true
		}
	}
	sum, _, err := scan(ctx, f, o.ScanOptions, nil, an)
	if an.err != nil {
		return sum, an.err
	}
	if sum != nil {
		sum.Transactions = an.status
		sum.TransactionFlags = an.flags
	}
	return sum, err
}

type analysis struct {
	o      Options
	sink   Sink
	flows  map[uint32]bool
	seq    uint64
	txnSeq uint64
	err    error
	status map[string]uint64
	flags  map[string]uint64
}

func (an *analysis) emit(e *model.Event) {
	if an.err != nil {
		return
	}
	an.seq++
	e.Seq = an.seq
	an.err = an.sink.Event(e)
}

// aconn is the analysis state of one connection.
type aconn struct {
	an      *analysis
	c       *flow.Conn
	decided bool
	server  int // direction index of the server's packets; -1: unknown
	role    mbtcp.Role
	info    *model.Connection
	pair    *pair.Pairer
	chunks  [2][]chunk
	gapNext [2]bool // the next ADU of the direction follows a gap
	queue   []queued
	queued  [2]int
	samples [2][]mbtcp.Sample
	order   uint32
}

type chunk struct {
	pos uint64
	n   int
	ch  flow.Chunk
}

type queued struct {
	dir    int
	adu    *model.ADU
	pdu    []byte
	flags  mbtcp.Flags
	gap    *model.Gap
	resync *model.Resync
}

func (an *analysis) open(c *flow.Conn) *aconn {
	if an.flows != nil && !an.flows[c.ID] {
		return nil
	}
	a := &aconn{an: an, c: c, server: -1}
	r := mbtcp.DecideRole(a.roleInput())
	if r.Source != mbtcp.RoleUnknown {
		a.start(r)
	}
	return a
}

func (a *aconn) roleInput() mbtcp.RoleInput {
	o := a.an.o.ScanOptions
	ports := o.ServerPorts
	if ports == nil {
		ports = DefaultServerPorts
	}
	return mbtcp.RoleInput{Endpoints: a.c.Endpoints, SYNFrom: a.c.SYNFrom, SYNACKFrom: a.c.SYNACKFrom,
		ServerPorts: ports, Servers: o.Servers, Clients: o.Clients, Samples: a.samples}
}

func (a *aconn) dirName(d int) string {
	if d == a.server {
		return "s2c"
	}
	return "c2s"
}

// start fixes the roles, emits conn.open and replays what was held.
func (a *aconn) start(r mbtcp.Role) {
	a.decided, a.role, a.server = true, r, r.Server
	c := a.c
	cl, sv := 0, 1
	if a.server == 0 {
		cl, sv = 1, 0
	}
	a.info = &model.Connection{ID: c.ID, Client: c.Endpoints[cl], Server: c.Endpoints[sv], RoleSource: r.Source.String(),
		RoleConfidence: r.Confidence, Open: c.Open.String(), Iface: c.Iface}
	if c.FirstNS != 0 {
		a.info.First = tm(c.FirstNS)
	}
	var flags []string
	if c.Open == flow.OpenMidstream {
		flags = append(flags, model.FlagMidstream)
	}
	sawSYN := c.SYNFrom >= 0 || c.SYNACKFrom >= 0
	switch {
	case r.Server < 0:
		flags = append(flags, model.FlagRoleUnknown)
	case r.Source.Guessed(sawSYN):
		flags = append(flags, model.FlagRoleGuessed)
	}
	a.pair = pair.New(pair.Options{MaxOutstanding: a.an.o.MaxOutstanding, Slow: a.an.o.Slow},
		pair.Conn{ID: c.ID, Client: a.info.Client, Server: a.info.Server, Flags: flags}, a.txn)
	open := *a.info
	a.an.emit(&model.Event{Kind: model.KindConnOpen, Time: a.info.First, Conn: &open})
	q := a.queue
	a.queue, a.samples = nil, [2][]mbtcp.Sample{}
	for _, x := range q {
		switch {
		case x.gap != nil:
			a.gapEvent(x.dir, x.gap)
		case x.resync != nil:
			x.resync.Dir = a.dirName(x.dir)
			a.an.emit(&model.Event{Kind: model.KindResync, Resync: x.resync})
		default:
			a.handle(x.dir, x.adu, x.pdu, x.flags)
		}
	}
}

func (a *aconn) decideNow() {
	if !a.decided {
		a.start(mbtcp.DecideRole(a.roleInput()))
	}
}

// data records where the direction's bytes came from.
func (a *aconn) data(d int, pos uint64, n int, ch flow.Chunk) {
	cs := append(a.chunks[d], chunk{pos, n, ch})
	if len(cs) > 4096 { // the framer consumes in order; this only guards odd streams
		cs = append(cs[:0], cs[len(cs)-2048:]...)
	}
	a.chunks[d] = cs
}

// consume drops the chunks that end at or before pos.
func (a *aconn) consume(d int, pos uint64) {
	cs := a.chunks[d]
	i := 0
	for i < len(cs) && cs[i].pos+uint64(cs[i].n) <= pos {
		i++
	}
	if i > 0 {
		a.chunks[d] = append(cs[:0], cs[i:]...)
	}
}

// refs returns the packets that carried [pos, pos+n).
func (a *aconn) refs(d int, pos uint64, n int) ([]model.FrameRef, bool, bool) {
	a.consume(d, pos)
	end := pos + uint64(n)
	var out []model.FrameRef
	retrans, ooo := false, false
	for _, c := range a.chunks[d] {
		if c.pos >= end {
			break
		}
		s, e := max(pos, c.pos), min(end, c.pos+uint64(c.n))
		if s >= e {
			continue
		}
		r := model.FrameRef{Frame: c.ch.Frame, Offset: c.ch.Offset, Iface: c.ch.Iface, PayOff: -1, PayLen: int32(e - s)}
		if c.ch.PayOff >= 0 {
			r.PayOff = c.ch.PayOff + int32(s-c.pos)
		}
		if c.ch.HasTime {
			r.Time = tm(c.ch.TimeNS)
		}
		retrans = retrans || c.ch.Retransmitted
		ooo = ooo || c.ch.OutOfOrder
		out = append(out, r)
	}
	a.consume(d, end)
	return out, retrans, ooo
}

// adu takes a framed ADU from the framer of direction d.
func (a *aconn) adu(d int, f *mbtcp.ADU) {
	refs, retrans, ooo := a.refs(d, f.Pos, f.Size)
	m := &model.ADU{TID: f.TID, Unit: f.Unit, Size: f.Size, Refs: refs}
	for _, r := range refs {
		if r.Time != nil {
			if m.First == nil || r.Time.Before(*m.First) {
				m.First = r.Time
			}
			if m.Last == nil || r.Time.After(*m.Last) {
				m.Last = r.Time
			}
		}
	}
	if retrans {
		m.Flags = append(m.Flags, model.FlagRetransmitted)
	}
	if ooo {
		m.Flags = append(m.Flags, model.FlagOutOfOrder)
	}
	pdu := append([]byte(nil), f.PDU...)
	if !a.decided {
		if f.Flags&(mbtcp.Foreign|mbtcp.Truncated) == 0 && len(pdu) > 0 && len(a.samples[d]) < mbtcp.MaxSamples {
			a.order++
			a.samples[d] = append(a.samples[d], mbtcp.NewSample(a.order, f.TID, f.Unit, pdu))
		}
		a.queue = append(a.queue, queued{dir: d, adu: m, pdu: pdu, flags: f.Flags})
		a.queued[d]++
		if (len(a.samples[0]) >= mbtcp.MaxSamples && len(a.samples[1]) >= mbtcp.MaxSamples) || a.queued[d] >= maxQueued {
			a.decideNow()
		}
		return
	}
	a.handle(d, m, pdu, f.Flags)
}

// handle decodes and pairs one ADU once the roles are known.
func (a *aconn) handle(d int, m *model.ADU, pdu []byte, fl mbtcp.Flags) {
	if fl&mbtcp.Resynced != 0 {
		m.Flags = append(m.Flags, model.FlagResynced)
	}
	if fl&mbtcp.Truncated != 0 {
		m.Flags = append(m.Flags, model.FlagSnaplen)
	}
	if fl&mbtcp.Foreign != 0 {
		m.Flags = append(m.Flags, model.FlagForeign)
	}
	if a.gapNext[d] {
		m.Flags = append(m.Flags, model.FlagGapAdjacent)
		a.gapNext[d] = false
	}
	if !a.an.o.OmitPDU {
		m.PDU = pdu
	}
	request := d != a.server
	as := mbtcp.AsResponse
	if request {
		as = mbtcp.AsRequest
	}
	p := pair.ADU{A: m, PDU: pdu, View: mbtcp.Decode(as, pdu)}
	switch {
	case fl&mbtcp.Foreign != 0:
		a.pair.Lone(p, request, model.StatusMalformed, model.FlagForeign)
	case fl&mbtcp.Truncated != 0 || len(pdu) == 0:
		a.pair.Lone(p, request, model.StatusMalformed)
	case a.server < 0:
		a.pair.Lone(p, d == 0, model.StatusUncertain)
	case request:
		a.pair.Request(p)
	default:
		a.pair.Response(p)
	}
}

func (a *aconn) gap(d int, pos uint64, n int64, reason string) {
	g := &model.Gap{Conn: a.c.ID, Pos: pos, Bytes: n, Reason: reason}
	if !a.decided {
		a.queue = append(a.queue, queued{dir: d, gap: g})
		return
	}
	a.gapEvent(d, g)
}

func (a *aconn) gapEvent(d int, g *model.Gap) {
	g.Dir = a.dirName(d)
	if g.Reason != flow.GapSnaplen.String() {
		a.gapNext[d] = true
		if d == a.server {
			a.pair.ResponseGap()
		}
	}
	a.an.emit(&model.Event{Kind: model.KindGap, Gap: g})
}

func (a *aconn) resync(d int, pos uint64, skipped int, c mbtcp.Confidence) {
	r := &model.Resync{Conn: a.c.ID, Pos: pos, Skipped: skipped, Confidence: c.String()}
	if !a.decided {
		a.queue = append(a.queue, queued{dir: d, resync: r})
		return
	}
	r.Dir = a.dirName(d)
	a.an.emit(&model.Event{Kind: model.KindResync, Resync: r})
}

// junk records bytes that framed as nothing.
func (a *aconn) junk(d int, pos uint64, n int, why mbtcp.JunkReason) {
	a.consume(d, pos+uint64(n))
	if why != mbtcp.Skipped {
		a.gap(d, pos, int64(n), why.String())
	}
}

func (a *aconn) txn(t *model.Transaction) {
	an := a.an
	an.txnSeq++
	t.Seq = an.txnSeq
	a.info.Transactions++
	an.status[t.Status]++
	for _, f := range t.Flags {
		an.flags[f]++
	}
	an.emit(&model.Event{Kind: model.KindTxn, Time: t.Time(), Txn: t})
}

// close ends the connection after its framers were closed.
func (a *aconn) close() {
	a.decideNow()
	a.pair.Close(a.c.Close == flow.CloseEvict)
	c := a.c
	info := *a.info
	info.Close = c.Close.String()
	if c.FirstNS != 0 {
		info.First, info.Last = tm(c.FirstNS), tm(c.LastNS)
	}
	info.MultiIface = c.MultiIface
	cl, sv := 0, 1
	if a.server == 0 {
		cl, sv = 1, 0
	}
	info.Packets = [2]uint64{c.Packets[cl], c.Packets[sv]}
	info.Bytes = [2]uint64{c.Bytes[cl], c.Bytes[sv]}
	a.an.emit(&model.Event{Kind: model.KindConnClose, Time: info.Last, Conn: &info})
}

// notes emits the trace-level facts at the end of the pass.
func (an *analysis) notes(s *FileSummary) {
	note := func(n *model.Note) { an.emit(&model.Event{Kind: model.KindNote, Note: n}) }
	for _, f := range s.Interfaces {
		if f.Drops != nil && *f.Drops > 0 {
			id := uint32(f.ID)
			note(&model.Note{Code: "capture_drops", Iface: &id, Count: *f.Drops,
				Text: "the capture host dropped packets on this interface"})
		}
	}
	if n := s.Snaplen.TruncatedPackets; n > 0 {
		note(&model.Note{Code: "snaplen", Count: n, Text: "packets were cut by the snap length"})
	}
	var unsupported uint64
	for _, n := range s.Unsupported {
		unsupported += n
	}
	if unsupported > 0 {
		note(&model.Note{Code: "unsupported", Count: unsupported, Text: "packets were not TCP or not decodable (see the file summary)"})
	}
	if s.Reader.SkippedBlocks > 0 || s.Reader.TruncatedTail || s.Error != "" {
		text := "the file is damaged"
		if s.Error != "" {
			text = s.Error
		}
		note(&model.Note{Code: "damaged_file", Count: s.Reader.SkippedBlocks, Text: text})
	}
	for _, e := range s.InternalErrors {
		note(&model.Note{Code: "internal_error", Count: e.Frame, Text: e.Message})
	}
}
