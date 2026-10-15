// SPDX-License-Identifier: MIT

package trace

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/netip"

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
	TimeNS  int64
	HasTime bool
	OrigLen uint32
	Data    []byte
	// Conn is the TCP connection the packet belongs to (as Scan numbers
	// them), 0 for anything else; Endpoints are its two ends.
	Conn      uint32
	Endpoints [2]netip.AddrPort
}

type nullHandler struct{}

func (nullHandler) Open(*flow.Conn)                                  {}
func (nullHandler) Data(*flow.Conn, int, uint64, []byte, flow.Chunk) {}
func (nullHandler) Gap(*flow.Conn, int, uint64, int64, flow.GapKind) {}
func (nullHandler) Close(*flow.Conn)                                 {}

// Walk reads every packet of the trace once, in file order, and tells fn
// which TCP connection each belongs to (connection IDs are the same as
// Scan's). It does not reassemble or frame; a sub-trace extractor uses it.
func Walk(ctx context.Context, f *File, o ScanOptions, fn func(p *RawPacket) error) error {
	lim := o.Limits.withDefaults()
	dec := link.NewDecoder(lim.FragmentBudget)
	tr := flow.NewTracker(flow.Limits{MaxConns: lim.MaxConns, BufferPerDir: lim.BufferPerDir, BufferTotal: lim.BufferTotal}, nullHandler{})
	done := ctx.Done()
	for i, pt := range f.parts {
		rc, err := pt.open()
		if err != nil {
			return err
		}
		err = walkPart(i, pt, rc, lim, dec, tr, done, fn)
		_ = rc.Close()
		if err != nil {
			return err
		}
	}
	return ctx.Err()
}

func walkPart(i int, pt *part, rc io.Reader, lim Limits, dec *link.Decoder, tr *flow.Tracker, done <-chan struct{}, fn func(*RawPacket) error) error {
	rd, err := pcapio.NewReader(rc, pcapio.Options{MaxPacket: lim.MaxPacket})
	if err != nil {
		return fmt.Errorf("%s: %w", pt.name(), err)
	}
	var p pcapio.Packet
	var seg link.Segment
	rp := &RawPacket{Part: i}
	for {
		select {
		case <-done:
			return context.Canceled
		default:
		}
		if err := rd.Next(&p); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return fmt.Errorf("%s: %w", pt.name(), err)
		}
		p.Part = uint16(i)
		f := rd.Interfaces()[p.Iface]
		rp.Frame, rp.TimeNS, rp.HasTime, rp.OrigLen, rp.Data = p.Frame, p.TimeNS, p.HasTime, p.OrigLen, p.Data
		rp.Iface = Interface{ID: int(p.Iface), Part: i, Section: f.Section, LinkType: f.LinkType, Link: link.LinkName(f.LinkType),
			SnapLen: f.SnapLen, TSResol: f.TSResol, Name: f.Name, Description: f.Description}
		rp.Conn, rp.Endpoints = 0, [2]netip.AddrPort{}
		if dec.Decode(p.LinkType, p.Data, &seg) == link.OK {
			if c := tr.Packet(&p, &seg); c != nil {
				rp.Conn, rp.Endpoints = c.ID, c.Endpoints
			}
		}
		if err := fn(rp); err != nil {
			return err
		}
	}
}
