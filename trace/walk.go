// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"
	"sort"

	"github.com/otfabric/go-modbus-trace/internal/flow"
	"github.com/otfabric/go-modbus-trace/internal/link"
	"github.com/otfabric/go-modbus-trace/internal/pcapio"
)

// RawPacket is one captured packet, as Walk sees it. Data is valid only
// during the callback.
type RawPacket struct {
	Part    int       // input file
	Frame   uint64    // 1-based within its file
	Iface   Interface // the capture interface (ID within its file)
	TimeNS  int64     // packet time, nanoseconds since 1970
	HasTime bool      // false for pcapng simple packets (TimeNS is then 0)
	OrigLen uint32    // length on the wire
	Data    []byte    // the captured bytes
	// Conn is the TCP connection the packet belongs to (as Scan numbers
	// them), 0 for anything else; Endpoints are its two ends.
	Conn      uint32
	Endpoints [2]netip.AddrPort
}

type nullHandler struct{}

func (nullHandler) Open(*flow.Conn)                                  {}
func (nullHandler) Data(*flow.Conn, int, uint64, []byte, flow.Chunk) {}
func (nullHandler) Repeat(*flow.Conn, int, uint64, uint64)           {}
func (nullHandler) Gap(*flow.Conn, int, uint64, int64, flow.GapKind) {}
func (nullHandler) Close(*flow.Conn)                                 {}

// Walk reads every packet of the trace once and tells fn which TCP
// connection each belongs to (connection IDs are the same as Scan's). It
// does not reassemble or frame; a sub-trace extractor uses it.
//
// Packets come in file order, with one exception: the IP fragments of a
// datagram are held until the fragment that completes it, and then given
// to fn, with the datagram's connection, just before it. Fragments of a
// datagram that never completes (or that the fragment budget dropped) come
// at the end of their file (or earlier, when the fragment budget lets
// them go) with Conn 0.
func Walk(ctx context.Context, f *File, o ScanOptions, fn func(p *RawPacket) error) error {
	lim := o.Limits.withDefaults()
	dec := link.NewDecoder(lim.FragmentBudget)
	tr := flow.NewTracker(flow.Limits{MaxConns: lim.MaxConns, BufferPerDir: lim.BufferPerDir, BufferTotal: lim.BufferTotal}, nullHandler{})
	w := &walker{ctx: ctx, lim: lim, dec: dec, tr: tr, fn: fn}
	for i, pt := range f.parts {
		rc, err := pt.open()
		if err != nil {
			return err
		}
		err = w.part(i, pt, rc)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

type walker struct {
	ctx context.Context
	lim Limits
	dec *link.Decoder
	tr  *flow.Tracker
	fn  func(*RawPacket) error
}

// part walks one input file.
func (w *walker) part(i int, pt *part, rc io.Reader) error {
	ctx, lim, dec, tr, fn := w.ctx, w.lim, w.dec, w.tr, w.fn
	done := ctx.Done()
	rd, err := pcapio.NewReader(rc, pcapio.Options{MaxPacket: lim.MaxPacket})
	if err != nil {
		return fmt.Errorf("%s: %w", pt.name(), err)
	}
	var p pcapio.Packet
	var seg link.Segment
	rp := &RawPacket{Part: i}
	h := &heldFrags{max: lim.FragmentBudget, m: map[link.FragKey]*heldDatagram{}}
	for {
		select {
		case <-done:
			return ctx.Err()
		default:
		}
		if err := rd.Next(&p); err != nil {
			if errors.Is(err, io.EOF) {
				return h.flush(fn)
			}
			return fmt.Errorf("%s: %w", pt.name(), err)
		}
		p.Part = uint16(i)
		f := rd.Interfaces()[p.Iface]
		rp.Frame, rp.TimeNS, rp.HasTime, rp.OrigLen, rp.Data = p.Frame, p.TimeNS, p.HasTime, p.OrigLen, p.Data
		rp.Iface = Interface{ID: int(p.Iface), Part: i, Section: f.Section, LinkType: f.LinkType, Link: link.LinkName(f.LinkType),
			SnapLen: f.SnapLen, TSResol: f.TSResol, Name: f.Name, Description: f.Description}
		rp.Conn, rp.Endpoints = 0, [2]netip.AddrPort{}
		r := dec.Decode(p.LinkType, p.Data, &seg)
		if r == link.FragmentHeld {
			for _, x := range h.hold(dec.Frag, rp) {
				if err := fn(x); err != nil {
					return err
				}
			}
			continue
		}
		if r == link.OK {
			if c := tr.Packet(&p, &seg); c != nil {
				rp.Conn, rp.Endpoints = c.ID, c.Endpoints
			}
		}
		if dec.Fragment {
			for _, x := range h.take(dec.Frag) {
				x.Conn, x.Endpoints = rp.Conn, rp.Endpoints
				if err := fn(x); err != nil {
					return err
				}
			}
		}
		if err := fn(rp); err != nil {
			return err
		}
	}
}

// heldFrags keeps copies of the IP fragments of incomplete datagrams,
// charging each its bytes plus heldFragOverhead against max; past that the
// oldest datagram's fragments are let go (given to fn at once with Conn 0),
// as the reassembler drops it too.
type heldFrags struct {
	max, used int
	m         map[link.FragKey]*heldDatagram
	order     []heldKey // oldest first; finished entries are skipped lazily
	gen       uint64
}

type heldDatagram struct {
	pkts []*RawPacket
	gen  uint64
}

type heldKey struct {
	k   link.FragKey
	gen uint64
}

const heldFragOverhead = 64

// hold keeps a copy of rp and returns the fragments let go to stay within
// the budget.
func (h *heldFrags) hold(k link.FragKey, rp *RawPacket) []*RawPacket {
	c := *rp
	c.Data = bytes.Clone(rp.Data)
	d := h.m[k]
	if d == nil {
		h.gen++
		d = &heldDatagram{gen: h.gen}
		h.m[k] = d
		h.order = append(h.order, heldKey{k, h.gen})
	}
	d.pkts = append(d.pkts, &c)
	h.used += len(c.Data) + heldFragOverhead
	var out []*RawPacket
	for h.used > h.max && len(h.order) > 0 {
		o := h.order[0]
		h.order = h.order[1:]
		if x := h.m[o.k]; x != nil && x.gen == o.gen {
			out = append(out, h.take(o.k)...)
		}
	}
	return out
}

// take removes and returns the fragments held for k.
func (h *heldFrags) take(k link.FragKey) []*RawPacket {
	d := h.m[k]
	if d == nil {
		return nil
	}
	delete(h.m, k)
	for _, x := range d.pkts {
		h.used -= len(x.Data) + heldFragOverhead
	}
	if len(h.order) > 2*len(h.m)+64 { // forget finished datagrams
		live := h.order[:0]
		for _, o := range h.order {
			if x := h.m[o.k]; x != nil && x.gen == o.gen {
				live = append(live, o)
			}
		}
		h.order = live
	}
	return d.pkts
}

// flush gives fn the fragments that never became a datagram, in file order.
func (h *heldFrags) flush(fn func(*RawPacket) error) error {
	var out []*RawPacket
	for _, d := range h.m {
		out = append(out, d.pkts...)
	}
	h.m = map[link.FragKey]*heldDatagram{}
	sort.Slice(out, func(a, b int) bool { return out[a].Frame < out[b].Frame })
	for _, x := range out {
		if err := fn(x); err != nil {
			return err
		}
	}
	return nil
}
