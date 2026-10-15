// SPDX-License-Identifier: MIT

// Package subtrace writes the packets of selected connections as a pcapng
// file that Wireshark opens (REQUIREMENTS.md L15): original timestamps and
// link types, the source's interface descriptions, and a section header
// that names the tool and the selection. Payloads are copied verbatim,
// writes and vendor functions included.
package subtrace

import (
	"context"
	"errors"
	"io"
	"time"

	"github.com/otfabric/go-modbus-trace/internal/pcapio"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
)

// Options shape an extraction.
type Options struct {
	// Selection picks connections (Conns, Servers, Clients: either end may
	// match, since roles are not decided here) and a time window; the
	// transaction-level fields (units, functions, statuses, flags, ranges)
	// do not apply to packets and are refused.
	Selection selection.Selection
	// Tool is written as shb_userappl, e.g. "mbtracectl 0.1.0".
	Tool string
}

// Stats report what was written.
type Stats struct {
	Packets     uint64 `json:"packets"`
	Bytes       uint64 `json:"bytes"`
	Connections int    `json:"connections"`
	NoTime      uint64 `json:"packets_without_time"` // written with time 0 (pcapng simple packets)
}

// ErrTransactionSelection is returned for a selection with
// transaction-level fields (units, functions, statuses, flags, ranges): a
// packet can carry several transactions, so they do not select packets.
var ErrTransactionSelection = errors.New("subtrace: a sub-trace selects connections and a time window, not transactions")

// Extract reads f once and writes the selected packets to w.
func Extract(ctx context.Context, f *trace.File, o trace.ScanOptions, so Options, w io.Writer) (Stats, error) {
	sel := so.Selection
	if len(sel.Units)+len(sel.Functions)+len(sel.Statuses)+len(sel.Classes)+len(sel.Require)+len(sel.Exclude) > 0 || sel.Space != "" {
		return Stats{}, ErrTransactionSelection
	}
	comment := "selection: " + sel.String()
	if sel.String() == "" {
		comment = "selection: every TCP connection"
	}
	nw, err := pcapio.NewNgWriter(w, pcapio.Section{Application: so.Tool, Comment: comment}, nil)
	if err != nil {
		return Stats{}, err
	}
	type ifKey struct{ part, id int }
	ifaces := map[ifKey]uint32{}
	conns := map[uint32]bool{}
	var st Stats
	resolved := false
	err = trace.Walk(ctx, f, o, func(p *trace.RawPacket) error {
		if !resolved && p.HasTime {
			sel.Resolve(time.Unix(0, p.TimeNS).UTC())
			resolved = true
		}
		if p.Conn == 0 {
			return nil
		}
		a, b := p.Endpoints[0], p.Endpoints[1]
		if !sel.MatchConn(p.Conn, a, b) && !sel.MatchConn(p.Conn, b, a) {
			return nil
		}
		if sel.From != nil || sel.To != nil {
			t := time.Unix(0, p.TimeNS).UTC()
			if !p.HasTime || (sel.From != nil && t.Before(*sel.From)) || (sel.To != nil && !t.Before(*sel.To)) {
				return nil
			}
		}
		k := ifKey{p.Part, p.Iface.ID}
		id, ok := ifaces[k]
		if !ok {
			resol := p.Iface.TSResol
			if resol&0x80 != 0 || resol > 9 {
				resol = 9 // binary or sub-nanosecond units are written as nanoseconds
			}
			if err := nw.AddInterface(pcapio.Interface{LinkType: p.Iface.LinkType, SnapLen: p.Iface.SnapLen, TSResol: resol,
				Name: p.Iface.Name, Description: p.Iface.Description}); err != nil {
				return err
			}
			id = uint32(len(ifaces))
			ifaces[k] = id
		}
		if !p.HasTime {
			st.NoTime++
		}
		conns[p.Conn] = true
		st.Packets++
		st.Bytes += uint64(len(p.Data))
		return nw.WritePacket(id, p.TimeNS, p.OrigLen, p.Data)
	})
	st.Connections = len(conns)
	if err != nil {
		return st, err
	}
	return st, nw.Flush()
}
