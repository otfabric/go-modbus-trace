// SPDX-License-Identifier: MIT

package trace

import (
	"context"
	"slices"
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
//
// Event is called synchronously on the goroutine that runs the pass, one
// call at a time: a sink needs no locking of its own, and a slow sink only
// slows the pass down. The event and everything it points to belong to the
// sink from the call on: the library neither reads nor changes them
// afterwards, so a sink may keep them and may change them. A sink may call
// File.Frames and start other passes on the same File.
//
// Event must return normally. A call that does not is contained like the
// decoding of a packet that does not: it is counted and listed in
// FileSummary.InternalErrors, what that packet still had to deliver may be
// lost, and the pass goes on and returns no error for it. To stop a pass,
// return an error.
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
//
// What Analyze holds does not grow with the size of the trace: it keeps
// nothing of a connection that closed, and what open connections hold is
// bounded by Limits (MaxConns, the reassembly buffers, AnalysisBudget) and
// MaxOutstanding.
//
// A damaged file ends the pass with the events and the summary so far and an
// error wrapping ErrCorrupt, as for Scan.
func Analyze(ctx context.Context, f *File, o Options, sink Sink) (*FileSummary, error) {
	an := &analysis{o: o, sink: sink, status: map[string]uint64{}, flags: map[string]uint64{},
		budget: o.Limits.withDefaults().AnalysisBudget}
	for k := range an.lists {
		l := &an.lists[k]
		l.links[k].prev, l.links[k].next = l, l
	}
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
	// What the connections hold between packets, charged against
	// Limits.AnalysisBudget (see shed).
	budget int
	held   int      // bytes charged over all connections
	lists  [2]aconn // per kind of state: the list of the connections that hold some, most recently charged first (sentinels)
	freed  uint64   // times the budget freed state
}

// Kinds of state a connection holds between packets.
const (
	heldADUs   = iota // ADUs not emitted yet, and gaps and resyncs held with them: a decision frees them
	heldChunks        // where the bytes being framed came from: freed with the connection
)

// What each item is charged, in bytes: estimates from above of the heap
// behind it, so the budget bounds the memory and not only a count.
const (
	costADU   = 512 // an ADU not emitted yet: the ADU, its place in a transaction, the fixed part of its decoded view
	costByte  = 96  // per PDU byte: the copy, and the decoded fields with their text at their densest
	costRef   = 96  // a frame reference with its time
	costChunk = 64  // a chunk
	costHeld  = 160 // a gap or a resync held while the roles are undecided
)

// charge adds n bytes of state of kind k to the connection, which becomes
// the most recently charged of its kind.
func (an *analysis) charge(a *aconn, k, n int) {
	an.held += n
	a.held[k] += n
	l := &an.lists[k]
	if l.links[k].next == a {
		return
	}
	an.unlink(a, k)
	x := &a.links[k]
	x.prev, x.next = l, l.links[k].next
	x.next.links[k].prev = a
	l.links[k].next = a
}

// release takes n bytes of state of kind k off the connection.
func (an *analysis) release(a *aconn, k, n int) {
	an.held -= n
	a.held[k] -= n
	if a.held[k] == 0 {
		an.unlink(a, k)
	}
}

func (an *analysis) unlink(a *aconn, k int) {
	if x := &a.links[k]; x.next != nil {
		x.prev.links[k].next, x.next.links[k].prev = x.next, x.prev
		x.prev, x.next = nil, nil
	}
}

// shed frees state until what the connections hold fits the budget again.
// It runs between two packets. The connection whose ADUs were added to
// least recently goes first: its roles are decided with what there is, then
// its oldest outstanding request is decided unanswered and uncertain, one at
// a time. When no connection holds an ADU any more and the chunks alone are
// over the budget, the connection whose chunks were added to least recently
// is closed as evicted: the partly framed bytes it holds cannot be given up
// without their provenance.
func (an *analysis) shed(tr *flow.Tracker) {
	for an.held > an.budget {
		if a := an.lists[heldADUs].links[heldADUs].prev; a != &an.lists[heldADUs] {
			an.freed++
			switch {
			case !a.decided:
				a.decideNow()
			case !a.pair.PushOut():
				tr.Evict(a.c) // cannot be: a decided connection's unemitted ADUs are outstanding requests
			}
			continue
		}
		a := an.lists[heldChunks].links[heldChunks].prev
		if a == &an.lists[heldChunks] {
			return
		}
		an.freed++
		tr.Evict(a.c)
	}
}

func (an *analysis) emit(e *model.Event) {
	if an.err != nil {
		return
	}
	an.seq++
	e.Seq, e.SchemaVersion = an.seq, model.SchemaVersion
	an.err = an.sink.Event(e)
}

// framerWindow is how far back from the end of the delivered bytes a framer
// can still hold unframed ones: an incomplete ADU, or one waiting for the
// header that follows it. What lies further back was framed or passed over.
const framerWindow = mbtcp.MaxADU + mbtcp.HeaderLen

// aconn is the analysis state of one connection.
type aconn struct {
	an      *analysis
	c       *flow.Conn
	held    [2]int                         // bytes charged, per kind of state
	links   [2]struct{ prev, next *aconn } // the analysis's lists of holders
	decided bool
	server  int // direction index of the server's packets; -1: unknown
	role    mbtcp.Role
	info    *model.Connection
	pair    *pair.Pairer
	chunks  [2][]chunk
	unsent  [2][]unsent // framed ADUs whose transaction is not emitted yet
	copyEnd [2]uint64   // end of the furthest stream range seen again
	gapNext [2]bool     // the next ADU of the direction follows a gap
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

// unsent is a framed ADU that a copy can still mark: it is bounded by the
// outstanding requests and the ADUs held while the roles are undecided.
type unsent struct {
	pos, end uint64
	adu      *model.ADU
	cost     int // charged while it is here
}

type queued struct {
	dir    int
	adu    *model.ADU
	pdu    []byte
	flags  mbtcp.Flags
	ahead  bool // see aconn.adu
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
		if x.adu == nil {
			a.an.release(a, heldADUs, costHeld)
		}
		switch {
		case x.gap != nil:
			a.gapEvent(x.dir, x.gap)
		case x.resync != nil:
			x.resync.Dir = a.dirName(x.dir)
			a.an.emit(&model.Event{Kind: model.KindResync, Resync: x.resync})
		default:
			a.handle(x.dir, x.adu, x.pdu, x.flags, x.ahead)
		}
	}
}

func (a *aconn) decideNow() {
	if !a.decided {
		a.start(mbtcp.DecideRole(a.roleInput()))
	}
}

// data records where the direction's bytes came from. The chunks of bytes
// the framer cannot hold any more (it passed over them without framing an
// ADU: a resync scan) are dropped first, so a direction keeps the chunks of
// at most framerWindow bytes and of the segment being written.
func (a *aconn) data(d int, pos uint64, n int, ch flow.Chunk) {
	if pos > framerWindow {
		a.consume(d, pos-framerWindow)
	}
	a.chunks[d] = append(a.chunks[d], chunk{pos, n, ch})
	a.an.charge(a, heldChunks, costChunk)
}

// repeat records that the direction's bytes [pos, end) were seen again. It
// marks the ADUs overlapping them whose transaction is not emitted yet, and
// through copyEnd the one still being framed. An emitted transaction belongs
// to the sink and stays as it is, so a later copy only counts.
func (a *aconn) repeat(d int, pos, end uint64) {
	a.copyEnd[d] = max(a.copyEnd[d], end)
	for _, u := range a.unsent[d] {
		if pos < u.end && u.pos < end && !slices.Contains(u.adu.Flags, model.FlagRetransmitted) {
			u.adu.Flags = slices.Insert(u.adu.Flags, 0, model.FlagRetransmitted)
		}
	}
}

// settled forgets the ADU once its transaction is emitted.
func (a *aconn) settled(m *model.ADU) {
	if m == nil {
		return
	}
	for d := range a.unsent {
		if i := slices.IndexFunc(a.unsent[d], func(u unsent) bool { return u.adu == m }); i >= 0 {
			a.an.release(a, heldADUs, a.unsent[d][i].cost)
			a.unsent[d] = slices.Delete(a.unsent[d], i, i+1)
			return
		}
	}
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
		a.an.release(a, heldChunks, i*costChunk)
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
		r := model.FrameRef{Part: c.ch.Part, Frame: c.ch.Frame, Offset: c.ch.Offset, Iface: c.ch.Iface, PayOff: -1, PayLen: int32(e - s)}
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
	if retrans || f.Pos < a.copyEnd[d] {
		m.Flags = append(m.Flags, model.FlagRetransmitted)
	}
	if ooo {
		m.Flags = append(m.Flags, model.FlagOutOfOrder)
	}
	cost := costADU + costByte*len(f.PDU) + costRef*len(refs)
	a.unsent[d] = append(a.unsent[d], unsent{f.Pos, f.Pos + uint64(f.Size), m, cost})
	a.an.charge(a, heldADUs, cost)
	pdu := append([]byte(nil), f.PDU...)
	// The packet that carried this ADU (or an earlier one of its sender)
	// acknowledged bytes of the other direction that the capture has not
	// delivered: for a response, the request direction has a hole now,
	// whether or not a gap is declared for it later.
	ahead := a.c.AckedAhead(1 - d)
	if !a.decided {
		if f.Flags&(mbtcp.Foreign|mbtcp.Truncated) == 0 && len(pdu) > 0 && len(a.samples[d]) < mbtcp.MaxSamples {
			a.order++
			a.samples[d] = append(a.samples[d], mbtcp.NewSample(a.order, f.TID, f.Unit, pdu))
		}
		a.queue = append(a.queue, queued{dir: d, adu: m, pdu: pdu, flags: f.Flags, ahead: ahead})
		a.queued[d]++
		if (len(a.samples[0]) >= mbtcp.MaxSamples && len(a.samples[1]) >= mbtcp.MaxSamples) || a.queued[d] >= maxQueued {
			a.decideNow()
		}
		return
	}
	a.handle(d, m, pdu, f.Flags, ahead)
}

// handle decodes and pairs one ADU once the roles are known. ahead: when
// the ADU was framed, the request direction had bytes its peer acknowledged
// and the capture did not deliver.
func (a *aconn) handle(d int, m *model.ADU, pdu []byte, fl mbtcp.Flags, ahead bool) {
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
		if ahead {
			a.pair.RequestGap()
		}
		a.pair.Response(p)
	}
}

func (a *aconn) gap(d int, pos uint64, n int64, reason string) {
	g := &model.Gap{Conn: a.c.ID, Pos: pos, Bytes: n, Reason: reason}
	if !a.decided {
		a.queue = append(a.queue, queued{dir: d, gap: g})
		a.an.charge(a, heldADUs, costHeld)
		return
	}
	a.gapEvent(d, g)
}

func (a *aconn) gapEvent(d int, g *model.Gap) {
	g.Dir = a.dirName(d)
	if g.Reason != flow.GapSnaplen.String() {
		a.gapNext[d] = true
		switch {
		case a.server < 0: // nothing is paired
		case d == a.server:
			a.pair.ResponseGap()
		default:
			a.pair.RequestGap()
		}
	}
	a.an.emit(&model.Event{Kind: model.KindGap, Gap: g})
}

func (a *aconn) resync(d int, pos uint64, skipped int, c mbtcp.Confidence) {
	r := &model.Resync{Conn: a.c.ID, Pos: pos, Skipped: skipped, Confidence: c.String()}
	if !a.decided {
		a.queue = append(a.queue, queued{dir: d, resync: r})
		a.an.charge(a, heldADUs, costHeld)
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
	a.settled(t.Request)
	a.settled(t.Response)
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
	// Everything is emitted: nothing of this connection is held any more.
	a.chunks = [2][]chunk{}
	for k := range a.held {
		a.an.release(a, k, a.held[k])
	}
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
