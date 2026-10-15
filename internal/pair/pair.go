// SPDX-License-Identifier: MIT

// Package pair matches the requests and responses of one connection into
// transactions (ARCHITECTURE.md section 9).
package pair

import (
	"bytes"
	"net/netip"
	"time"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
)

// Options bound and tune pairing.
type Options struct {
	MaxOutstanding int           // outstanding requests per connection (256)
	Slow           time.Duration // latency above which a transaction is flagged slow (1 s)
}

// Conn is what pairing needs to know about the connection.
type Conn struct {
	ID             uint32
	Client, Server netip.AddrPort
	Flags          []string // connection-level flags: midstream, role_guessed, role_unknown
}

// ADU is a framed ADU with its decoded view.
type ADU struct {
	A    *model.ADU
	PDU  []byte
	View mbtcp.View
}

type pending struct {
	ADU
	retried, ambiguous, gapTouched bool
}

// Pairer pairs one connection. Emit receives every transaction.
type Pairer struct {
	o    Options
	c    Conn
	out  []*pending
	emit func(*model.Transaction)
}

// New returns a pairer.
func New(o Options, c Conn, emit func(*model.Transaction)) *Pairer {
	if o.MaxOutstanding <= 0 {
		o.MaxOutstanding = 256
	}
	if o.Slow <= 0 {
		o.Slow = time.Second
	}
	return &Pairer{o: o, c: c, emit: emit}
}

// Request takes a request ADU.
func (p *Pairer) Request(a ADU) {
	q := &pending{ADU: a}
	for _, o := range p.out {
		if o.A.Unit == a.A.Unit && o.A.TID == a.A.TID {
			if bytes.Equal(o.PDU, a.PDU) {
				o.retried, q.retried = true, true
			} else {
				o.ambiguous, q.ambiguous = true, true
			}
		}
	}
	if len(p.out) >= p.o.MaxOutstanding {
		old := p.out[0]
		p.out = p.out[1:]
		p.build(old, nil, model.StatusUnanswered, true) // pushed out: unanswered and uncertain
	}
	p.out = append(p.out, q)
}

// Response takes a response ADU: the oldest outstanding request with the
// same unit, transaction ID and function code (or its exception form).
func (p *Pairer) Response(a ADU) {
	fc := byte(0)
	if len(a.PDU) > 0 {
		fc = a.PDU[0] &^ 0x80
	}
	for i, o := range p.out {
		if o.A.Unit == a.A.Unit && o.A.TID == a.A.TID && len(o.PDU) > 0 && o.PDU[0] == fc {
			// Older requests whose responses may have been in a gap are
			// decided now: a request sent after them got its answer, so
			// theirs was lost. This keeps the outstanding list short.
			keep := p.out[:0]
			var lost []*pending
			for _, x := range p.out[:i] {
				if x.gapTouched {
					lost = append(lost, x)
				} else {
					keep = append(keep, x)
				}
			}
			keep = append(keep, p.out[i+1:]...)
			p.out = keep
			for _, x := range lost {
				p.build(x, nil, model.StatusUnanswered, false)
			}
			p.build(o, &a, "", false)
			return
		}
	}
	p.lone(nil, &a, model.StatusOrphan)
}

// Lone reports an ADU that is not paired (malformed, foreign protocol, or
// a connection whose roles are unknown).
func (p *Pairer) Lone(a ADU, request bool, status string, flags ...string) {
	if request {
		p.lone(&a, nil, status, flags...)
	} else {
		p.lone(nil, &a, status, flags...)
	}
}

// ResponseGap records a gap in the server-to-client direction: the
// responses of the outstanding requests may have been in it.
func (p *Pairer) ResponseGap() {
	for _, o := range p.out {
		o.gapTouched = true
	}
}

// Close ends the connection: what is outstanding is unanswered, and
// uncertain too when the connection was cut off (evicted) rather than seen
// to its end.
func (p *Pairer) Close(cutOff bool) {
	for _, o := range p.out {
		p.build(o, nil, model.StatusUnanswered, cutOff)
	}
	p.out = nil
}

func (p *Pairer) lone(req, resp *ADU, status string, flags ...string) {
	var q *pending
	if req != nil {
		q = &pending{ADU: *req}
	}
	p.build(q, resp, status, false, flags...)
}

// flagOrder is the order flags are written in.
var flagOrder = []string{model.FlagRetransmitted, model.FlagOutOfOrder, model.FlagGapAdjacent, model.FlagResynced,
	model.FlagSnaplen, model.FlagMidstream, model.FlagRoleGuessed, model.FlagRoleUnknown, model.FlagRetried,
	model.FlagClockOrder, model.FlagSlow, model.FlagInvalidPDU, model.FlagSerialOverTCP, model.FlagUnknownFunc,
	model.FlagBroadcast, model.FlagForeign}

func (p *Pairer) build(q *pending, resp *ADU, status string, uncertain bool, extra ...string) {
	set := map[string]bool{}
	for _, f := range p.c.Flags {
		set[f] = true
	}
	for _, f := range extra {
		set[f] = true
	}
	t := &model.Transaction{Conn: p.c.ID, Client: p.c.Client, Server: p.c.Server}
	var reqV, respV *mbtcp.View
	var warns []string
	addWarn := func(ws []string) {
		for _, w := range ws {
			dup := false
			for _, x := range warns {
				dup = dup || x == w
			}
			if !dup {
				warns = append(warns, w)
			}
		}
	}
	if q != nil {
		reqV = &q.View
		t.Request = q.A
		t.Unit, t.TID = q.A.Unit, q.A.TID
		for _, f := range q.A.Flags {
			set[f] = true
		}
		if q.retried {
			set[model.FlagRetried] = true
		}
		if q.gapTouched {
			set[model.FlagGapAdjacent] = true
		}
		if q.ambiguous && status != model.StatusUnanswered {
			status = model.StatusAmbiguous
		}
		addWarn(q.View.Warnings)
	}
	if resp != nil {
		v := resp.View
		respV = &v
		t.Response = resp.A
		if q == nil {
			t.Unit, t.TID = resp.A.Unit, resp.A.TID
		}
		for _, f := range resp.A.Flags {
			set[f] = true
		}
		if q != nil {
			addWarn(mbtcp.CheckPair(q.PDU, q.View, resp.PDU, respV))
		}
		addWarn(respV.Warnings)
		resp.A.View = respV
		if status == "" {
			status = model.StatusOK
			if v.Exception {
				status, t.Exception = model.StatusException, v.Code
			}
			if q.ambiguous {
				status = model.StatusAmbiguous
			}
		}
	}
	if q != nil {
		q.A.View = &q.View
	}
	main := reqV
	if main == nil {
		main = respV
	}
	if main != nil {
		t.Function, t.Sub, t.Class = main.Function, main.Sub, string(main.Class)
		t.Ranges = main.Ranges
		if reqV == nil && respV != nil {
			t.Ranges = respV.Ranges
		}
		if !main.Known {
			set[model.FlagUnknownFunc] = true
		}
		if mbtcp.SerialOnly(main.Function) {
			set[model.FlagSerialOverTCP] = true
		}
		if reqV != nil {
			t.Summary = mbtcp.Summary(*reqV, respV)
		} else {
			t.Summary = "Response to " + mbtcp.Summary(*respV, respV)
		}
	}
	if len(warns) > 0 {
		set[model.FlagInvalidPDU] = true
		t.Warnings = warns
	}
	if q != nil && resp != nil && q.A.Last != nil && resp.A.First != nil {
		lat := resp.A.First.Sub(*q.A.Last)
		if lat < 0 {
			lat = 0
			set[model.FlagClockOrder] = true
		}
		t.LatencyNS = int64(lat)
		if lat > p.o.Slow {
			set[model.FlagSlow] = true
		}
	}
	if status == model.StatusUnanswered && t.Unit == 0 {
		set[model.FlagBroadcast] = true
	}
	// A transaction touched by a gap or a resync is uncertain, whatever
	// else it is (malformed stays malformed: it is reported alone).
	if status != model.StatusMalformed && (uncertain || set[model.FlagResynced] || set[model.FlagGapAdjacent] || set[model.FlagRoleUnknown]) {
		status = model.StatusUncertain
	}
	t.Status = status
	for _, f := range flagOrder {
		if set[f] {
			t.Flags = append(t.Flags, f)
		}
	}
	p.emit(t)
}
