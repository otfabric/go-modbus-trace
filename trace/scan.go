// SPDX-License-Identifier: MIT

package trace

import (
	"context"
	"encoding/hex"
	"errors"
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"time"

	"github.com/otfabric/go-modbus-trace/internal/flow"
	"github.com/otfabric/go-modbus-trace/internal/link"
	"github.com/otfabric/go-modbus-trace/internal/pcapio"
	"github.com/otfabric/go-modbus-trace/mbtcp"
)

// maxInternalErrors bounds the list of recovered panics kept.
const maxInternalErrors = 100

// Scan reads the whole trace once and returns its summary and its TCP flows
// with their Modbus assessment, ordered by flow ID. It frames MBAP in both
// directions but does not pair or decode PDUs.
//
// A damaged file ends the scan with the results so far and an error
// wrapping ErrCorrupt. Cancelling ctx stops it between packets.
func Scan(ctx context.Context, f *File, o ScanOptions) (*FileSummary, []Flow, error) {
	return scan(ctx, f, o, nil, nil)
}

// aduHook sees every framed ADU (tests).
type aduHook func(c *flow.Conn, dir int, a *mbtcp.ADU)

func scan(ctx context.Context, f *File, o ScanOptions, hook aduHook, an *analysis) (*FileSummary, []Flow, error) {
	rc, err := f.open()
	if err != nil {
		return nil, nil, err
	}
	defer func() { _ = rc.Close() }()
	lim := o.Limits.withDefaults()
	if o.ServerPorts == nil {
		o.ServerPorts = DefaultServerPorts
	}
	rd, err := pcapio.NewReader(rc, pcapio.Options{MaxPacket: lim.MaxPacket})
	if err != nil {
		return nil, nil, err
	}
	name := f.Name()
	if name != "-" {
		name = filepath.Base(name)
	}
	sc := &scanner{o: o, lim: lim, hook: hook, an: an, sum: &FileSummary{File: name, Format: rd.Format().String(), Gzip: rd.Gzip(),
		Unsupported: map[string]uint64{}}}
	dec := link.NewDecoder(lim.FragmentBudget)
	tr := flow.NewTracker(flow.Limits{MaxConns: lim.MaxConns, BufferPerDir: lim.BufferPerDir, BufferTotal: lim.BufferTotal,
		TailKeep: flow.DefaultLimits.TailKeep}, sc)
	done := ctx.Done()
	var (
		p        pcapio.Packet
		seg      link.Segment
		readErr  error
		lastNS   int64
		nextProg int64 = 4 << 20
	)
	for {
		select {
		case <-done:
			return nil, nil, ctx.Err()
		default:
		}
		if err := rd.Next(&p); err != nil {
			if !errors.Is(err, io.EOF) {
				readErr = err
				sc.sum.Error = err.Error()
			}
			break
		}
		s := sc.sum
		s.Packets++
		s.Bytes += uint64(len(p.Data))
		if p.Truncated() {
			s.Snaplen.TruncatedPackets++
		}
		if p.HasTime {
			t := p.TimeNS
			if s.First == nil || t < s.First.UnixNano() {
				if s.First == nil && an != nil && an.o.FirstPacket != nil {
					an.o.FirstPacket(time.Unix(0, t).UTC())
				}
				s.First = tm(t)
			}
			if s.Last == nil || t > s.Last.UnixNano() {
				s.Last = tm(t)
			}
			if lastNS != 0 && t < lastNS {
				s.TimeBackwards++
			}
			lastNS = t
		}
		sc.packet(dec, tr, &p, &seg)
		if an != nil && an.err != nil {
			return sc.sum, nil, an.err
		}
		if o.Progress != nil && rd.InputBytes() >= nextProg {
			o.Progress(rd.InputBytes(), f.Size())
			nextProg = rd.InputBytes() + 4<<20
		}
	}
	tr.Finish()
	sc.finish(rd, dec, tr)
	if an != nil {
		an.notes(sc.sum)
		if an.err != nil {
			return sc.sum, nil, an.err
		}
	}
	if readErr != nil {
		return sc.sum, sc.flows, fmt.Errorf("%s: %w", f.Name(), readErr)
	}
	return sc.sum, sc.flows, nil
}

func tm(ns int64) *time.Time {
	t := time.Unix(0, ns).UTC()
	return &t
}

type scanner struct {
	an    *analysis
	hook  aduHook
	o     ScanOptions
	lim   Limits
	sum   *FileSummary
	flows []Flow
	q     Quality
	order uint32
}

// packet decodes one packet; a panic is recovered and counted.
func (sc *scanner) packet(dec *link.Decoder, tr *flow.Tracker, p *pcapio.Packet, seg *link.Segment) {
	defer func() {
		if r := recover(); r != nil {
			if len(sc.sum.InternalErrors) < maxInternalErrors {
				sc.sum.InternalErrors = append(sc.sum.InternalErrors, InternalError{Frame: p.Frame, Message: fmt.Sprint(r)})
			}
		}
	}()
	if dec.Decode(p.LinkType, p.Data, seg) != link.OK {
		return
	}
	tr.Packet(p, seg)
}

func (sc *scanner) finish(rd *pcapio.Reader, dec *link.Decoder, tr *flow.Tracker) {
	s := sc.sum
	s.SHA256 = hexSum(rd.SHA256())
	s.InputBytes = rd.InputBytes()
	var drops uint64
	anyDrops := false
	for i, f := range rd.Interfaces() {
		x := Interface{ID: i, Section: f.Section, LinkType: f.LinkType, Link: link.LinkName(f.LinkType), SnapLen: f.SnapLen,
			TSResol: f.TSResol, Name: f.Name, Description: f.Description, Packets: f.Packets}
		if f.Stats != nil && f.Stats.IfDrop != nil {
			v := *f.Stats.IfDrop
			x.Drops = &v
			drops += v
			anyDrops = true
		}
		s.Snaplen.Max = max(s.Snaplen.Max, f.SnapLen)
		s.Interfaces = append(s.Interfaces, x)
	}
	if anyDrops {
		s.CaptureDrop = &drops
	}
	for _, sec := range rd.Sections() {
		s.Sections = append(s.Sections, Section{Application: sec.Application, OS: sec.OS, Hardware: sec.Hardware, Comment: sec.Comment})
	}
	for r := link.LinkUnsupported; r < link.NumReasons; r++ {
		if n := dec.Counts[r]; n > 0 {
			s.Unsupported[r.String()] = n
		}
	}
	fr := dec.Defrag()
	s.Fragments = Fragments{Reassembled: fr.Datagrams, Dropped: fr.Dropped, Incomplete: fr.Pending}
	c := rd.Counters()
	s.Reader = ReaderCounters{SimplePackets: c.SimplePackets, SkippedBlocks: c.SkippedBlocks, UnknownBlocks: c.UnknownBlocks,
		OtherFrames: c.OtherFrames, TruncatedTail: c.TruncatedTail}
	st := tr.Stats
	s.Connections = ConnCounters{Total: st.Conns, Midstream: st.Midstream, Evicted: st.Evicted, Superseded: st.Superseded,
		MaxTracked: st.MaxTracked, AfterClose: st.AfterClose}
	q := sc.q
	q.Retransmitted, q.OutOfOrder, q.OverlapConflicts = st.Retransmits, st.OutOfOrder, st.Conflicts
	q.Keepalives, q.SYNRetransmits, q.Gaps, q.GapBytes = st.Keepalives, st.SYNRetrans, st.Gaps, st.GapBytes
	q.ReassemblyOverflow, q.ReassemblyBudget = st.Overflows, st.BudgetGaps
	s.Quality = q
	s.Snaplen.PayloadBytesCut = st.SnapBytes
	sort.Slice(sc.flows, func(i, j int) bool { return sc.flows[i].ID < sc.flows[j].ID })
}

func hexSum(b [32]byte) string { return hex.EncodeToString(b[:]) }

// connState is the scan state of one connection.
type connState struct {
	a       *aconn // analysis, when Analyze runs and the flow is selected
	c       *flow.Conn
	sc      *scanner
	fr      [2]*mbtcp.Framer
	dirs    [2]dirState
	samples [2][]mbtcp.Sample
}

type dirState struct {
	adus, run, maxRun uint64
	units             uint64 // framed units: ADUs, foreign frames, junk runs
	foreign, resyncs  uint64
	junk              uint64
	first             bool // the first payload bytes were seen
	tls               bool
}

type dirSink struct {
	cs *connState
	d  int
}

func (s dirSink) ADU(a *mbtcp.ADU) {
	cs, ds := s.cs, &s.cs.dirs[s.d]
	if cs.sc.hook != nil {
		cs.sc.hook(cs.c, s.d, a)
	}
	if cs.a != nil {
		cs.a.adu(s.d, a)
	}
	ds.units++
	if a.Flags&mbtcp.Truncated != 0 {
		cs.sc.q.SnaplenTruncated++
	}
	if a.Flags&mbtcp.Foreign != 0 || len(a.PDU) == 0 || !mbtcp.PlausibleFunction(a.PDU[0]) {
		if a.Flags&mbtcp.Foreign != 0 {
			ds.foreign++
			cs.sc.q.ForeignFrames++
		}
		ds.run = 0
		return
	}
	ds.adus++
	ds.run++
	ds.maxRun = max(ds.maxRun, ds.run)
	if len(cs.samples[s.d]) < mbtcp.MaxSamples {
		cs.sc.order++
		cs.samples[s.d] = append(cs.samples[s.d], mbtcp.NewSample(cs.sc.order, a.TID, a.Unit, a.PDU))
	}
}

func (s dirSink) Resync(pos uint64, skipped int, c mbtcp.Confidence) {
	if s.cs.a != nil {
		s.cs.a.resync(s.d, pos, skipped, c)
	}
	s.cs.dirs[s.d].resyncs++
	s.cs.sc.q.Resyncs++
}

func (s dirSink) Junk(pos uint64, n int, why mbtcp.JunkReason) {
	if s.cs.a != nil {
		s.cs.a.junk(s.d, pos, n, why)
	}
	ds := &s.cs.dirs[s.d]
	ds.units++
	ds.run = 0
	ds.junk += uint64(n)
	s.cs.sc.q.JunkBytes += uint64(n)
	if why == mbtcp.ResyncFailed {
		s.cs.sc.q.ResyncFailed++
	}
}

// Open implements flow.Handler.
func (sc *scanner) Open(c *flow.Conn) {
	cs := &connState{sc: sc, c: c}
	for d := range 2 {
		cs.fr[d] = mbtcp.NewFramer(sc.lim.ResyncScan, dirSink{cs, d})
	}
	if sc.an != nil {
		cs.a = sc.an.open(c)
	}
	c.User = cs
}

// Data implements flow.Handler.
func (sc *scanner) Data(c *flow.Conn, d int, pos uint64, b []byte, ch flow.Chunk) {
	cs := c.User.(*connState)
	ds := &cs.dirs[d]
	if !ds.first {
		ds.first = true
		ds.tls = pos == 0 && c.Open == flow.OpenSYN && len(b) >= 2 && b[0] == 0x16 && b[1] == 0x03
	}
	if ds.tls {
		return // TLS: Modbus/TCP Security is not decodable
	}
	if cs.a != nil {
		cs.a.data(d, pos, len(b), ch)
	}
	cs.fr[d].Write(pos, b)
}

// Gap implements flow.Handler.
func (sc *scanner) Gap(c *flow.Conn, d int, pos uint64, n int64, kind flow.GapKind) {
	cs := c.User.(*connState)
	cs.fr[d].Gap(pos, n, kind == flow.GapSnaplen)
	if cs.a != nil {
		cs.a.gap(d, pos, n, kind.String())
	}
}

// Close implements flow.Handler.
func (sc *scanner) Close(c *flow.Conn) {
	cs := c.User.(*connState)
	c.User = nil
	for d := range 2 {
		cs.fr[d].Close()
	}
	if cs.a != nil {
		cs.a.close()
	}
	role := mbtcp.DecideRole(mbtcp.RoleInput{Endpoints: c.Endpoints, SYNFrom: c.SYNFrom, SYNACKFrom: c.SYNACKFrom,
		ServerPorts: sc.o.ServerPorts, Servers: sc.o.Servers, Clients: sc.o.Clients, Samples: cs.samples})
	a, b := 0, 1 // direction indexes of A (client) and B (server)
	if role.Server == 0 {
		a, b = 1, 0
	}
	fl := Flow{
		ID: c.ID, A: c.Endpoints[a], B: c.Endpoints[b], Role: role.Source.String(),
		RoleGuess:  role.Server >= 0 && role.Source.Guessed(c.SYNFrom >= 0 || c.SYNACKFrom >= 0),
		Confidence: role.Confidence, Open: c.Open.String(), Close: c.Close.String(),
		Iface: c.Iface, MultiIface: c.MultiIface,
		Packets: [2]uint64{c.Packets[a], c.Packets[b]}, Bytes: [2]uint64{c.Bytes[a], c.Bytes[b]},
		ADUs: [2]uint64{cs.dirs[a].adus, cs.dirs[b].adus}, MaxRun: [2]uint64{cs.dirs[a].maxRun, cs.dirs[b].maxRun},
		Foreign: cs.dirs[0].foreign + cs.dirs[1].foreign, Resyncs: cs.dirs[0].resyncs + cs.dirs[1].resyncs,
		JunkBytes: cs.dirs[0].junk + cs.dirs[1].junk,
		Gaps:      c.Stats.Gaps, GapBytes: c.Stats.GapBytes, Retransmits: c.Stats.Retransmits,
		OutOfOrder: c.Stats.OutOfOrder, Conflicts: c.Stats.Conflicts,
	}
	if c.FirstNS != 0 {
		fl.First, fl.Last = tm(c.FirstNS), tm(c.LastNS)
	}
	if role.Server >= 0 {
		fl.ServerPort = fl.B.Port()
	}
	fl.Class, fl.Score = classify(cs)
	sc.flows = append(sc.flows, fl)
}

// classify applies the scan rule: Modbus/TCP if either direction carries
// valid ADUs in a run of at least 3, or as at least 90% of its framed units.
func classify(cs *connState) (string, float64) {
	if cs.dirs[0].tls || cs.dirs[1].tls {
		return ClassTLS, 0
	}
	score := 0.0
	modbus := false
	for _, ds := range cs.dirs {
		if ds.units == 0 {
			continue
		}
		share := float64(ds.adus) / float64(ds.units)
		score = max(score, share)
		if ds.maxRun >= 3 || (ds.adus > 0 && share >= 0.9) {
			modbus = true
		}
	}
	if modbus {
		return ClassModbus, score
	}
	return ClassOther, score
}
