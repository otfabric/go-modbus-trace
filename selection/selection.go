// SPDX-License-Identifier: MIT

// Package selection is the one transaction predicate the CLI, the
// exporters and applications share. A selection decides what is listed or
// exported; it never changes decoding.
package selection

import (
	"fmt"
	"net/netip"
	"slices"
	"strings"
	"time"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
)

// Selection selects transactions. Empty fields select everything.
type Selection struct {
	Servers   []netip.AddrPort // a zero port matches any port
	Clients   []netip.Addr
	Units     []uint8
	Conns     []uint32
	Functions []uint8
	Statuses  []string
	Classes   []string // read, write, other
	Require   []string // quality flags a transaction must have
	Exclude   []string // quality flags it must not have
	// Time window, inclusive start, exclusive end. From and To are
	// absolute; FromOffset and ToOffset are offsets from the first packet
	// of the trace and are resolved with Resolve.
	From, To             *time.Time
	FromOffset, ToOffset *time.Duration
	// Address range: transactions touching [Start, End] in Space.
	Space      mbtcp.Space
	Start, End uint16
}

// Resolve turns the offsets into absolute times, given the time of the
// trace's first packet.
func (s *Selection) Resolve(first time.Time) {
	if s.FromOffset != nil {
		t := first.Add(*s.FromOffset)
		s.From = &t
	}
	if s.ToOffset != nil {
		t := first.Add(*s.ToOffset)
		s.To = &t
	}
}

// Empty reports a selection that selects everything.
func (s *Selection) Empty() bool { return s.String() == "" }

// MatchConn reports whether events of a connection can be selected at all
// (servers, clients, connections).
func (s *Selection) MatchConn(id uint32, client, server netip.AddrPort) bool {
	if len(s.Conns) > 0 && !slices.Contains(s.Conns, id) {
		return false
	}
	if len(s.Clients) > 0 && !slices.Contains(s.Clients, client.Addr()) {
		return false
	}
	if len(s.Servers) > 0 {
		ok := false
		for _, x := range s.Servers {
			ok = ok || (x.Addr() == server.Addr() && (x.Port() == 0 || x.Port() == server.Port()))
		}
		return ok
	}
	return true
}

// Match reports whether a transaction is selected.
func (s *Selection) Match(t *model.Transaction) bool {
	if !s.MatchConn(t.Conn, t.Client, t.Server) {
		return false
	}
	if len(s.Units) > 0 && !slices.Contains(s.Units, t.Unit) {
		return false
	}
	if len(s.Functions) > 0 && !slices.Contains(s.Functions, t.Function) {
		return false
	}
	if len(s.Statuses) > 0 && !slices.Contains(s.Statuses, t.Status) {
		return false
	}
	if len(s.Classes) > 0 && !slices.Contains(s.Classes, t.Class) {
		return false
	}
	for _, f := range s.Require {
		if !slices.Contains(t.Flags, f) {
			return false
		}
	}
	for _, f := range s.Exclude {
		if slices.Contains(t.Flags, f) {
			return false
		}
	}
	if s.From != nil || s.To != nil {
		tt := t.Time()
		if tt == nil || (s.From != nil && tt.Before(*s.From)) || (s.To != nil && !tt.Before(*s.To)) {
			return false
		}
	}
	if s.Space != "" {
		ok := false
		for _, r := range t.Ranges {
			end := uint32(r.Start) + uint32(max(r.Count, 1)) - 1
			ok = ok || (r.Space == s.Space && uint32(r.Start) <= uint32(s.End) && end >= uint32(s.Start))
		}
		if !ok {
			return false
		}
	}
	return true
}

func join[T any](xs []T) string {
	p := make([]string, len(xs))
	for i, x := range xs {
		p[i] = fmt.Sprint(x)
	}
	return strings.Join(p, ",")
}

// String returns the canonical form of the selection ("" for everything),
// used in export headers and reports.
func (s *Selection) String() string {
	var p []string
	add := func(k, v string) {
		if v != "" {
			p = append(p, k+"="+v)
		}
	}
	add("server", join(s.Servers))
	add("client", join(s.Clients))
	add("unit", join(s.Units))
	add("conn", join(s.Conns))
	add("fc", join(s.Functions))
	add("status", strings.Join(s.Statuses, ","))
	add("class", strings.Join(s.Classes, ","))
	add("flag", strings.Join(s.Require, ","))
	add("no-flag", strings.Join(s.Exclude, ","))
	if s.FromOffset != nil {
		add("from", s.FromOffset.String())
	} else if s.From != nil {
		add("from", s.From.UTC().Format(time.RFC3339Nano))
	}
	if s.ToOffset != nil {
		add("to", s.ToOffset.String())
	} else if s.To != nil {
		add("to", s.To.UTC().Format(time.RFC3339Nano))
	}
	if s.Space != "" {
		add("range", fmt.Sprintf("%s:%d-%d", s.Space, s.Start, s.End))
	}
	return strings.Join(p, "; ")
}
