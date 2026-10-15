// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/netip"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/otfabric/go-modbus-trace/trace"
)

// schemaVersion is the version of the CLI's JSON output.
const schemaVersion = 1

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

// scanFlags are the options shared by the commands that scan a trace.
type scanFlags struct {
	serverPorts []uint
	servers     []string
	clients     []string
}

func (s *scanFlags) register(cmd *cobra.Command) {
	cmd.Flags().UintSliceVar(&s.serverPorts, "server-port", []uint{502}, "TCP ports taken as Modbus servers when no handshake decides")
	cmd.Flags().StringSliceVar(&s.servers, "server", nil, "endpoints that are servers: ip or ip:port (overrides every other rule)")
	cmd.Flags().StringSliceVar(&s.clients, "client", nil, "endpoints that are clients: ip or ip:port")
}

func endpoints(flag string, xs []string) ([]netip.AddrPort, error) {
	var out []netip.AddrPort
	for _, x := range xs {
		if ap, err := netip.ParseAddrPort(x); err == nil {
			out = append(out, ap)
			continue
		}
		a, err := netip.ParseAddr(strings.Trim(x, "[]"))
		if err != nil {
			return nil, usageErr("--%s %q: not an ip or ip:port", flag, x)
		}
		out = append(out, netip.AddrPortFrom(a, 0))
	}
	return out, nil
}

func (s *scanFlags) options(e *env) (trace.ScanOptions, error) {
	var o trace.ScanOptions
	for _, p := range s.serverPorts {
		if p == 0 || p > 65535 {
			return o, usageErr("--server-port %d: not a port", p)
		}
		o.ServerPorts = append(o.ServerPorts, uint16(p))
	}
	var err error
	if o.Servers, err = endpoints("server", s.servers); err != nil {
		return o, err
	}
	if o.Clients, err = endpoints("client", s.clients); err != nil {
		return o, err
	}
	if e.progress {
		o.Progress = func(read, total int64) {
			if total > 0 {
				_, _ = fmt.Fprintf(e.stderr, "\r%d / %d MiB", read>>20, total>>20)
			} else {
				_, _ = fmt.Fprintf(e.stderr, "\r%d MiB", read>>20)
			}
		}
	}
	return o, nil
}

// open opens a trace argument: a path or "-".
func open(e *env, arg string) (*trace.File, error) {
	if arg == "-" {
		return trace.OpenReader(e.stdin), nil
	}
	return trace.Open(arg)
}

// scan runs a scan; a damaged file still returns what was read, with the
// error.
func scan(cmd *cobra.Command, e *env, arg string, o trace.ScanOptions) (*trace.FileSummary, []trace.Flow, error) {
	f, err := open(e, arg)
	if err != nil {
		return nil, nil, err
	}
	sum, flows, err := trace.Scan(cmd.Context(), f, o)
	if o.Progress != nil {
		_, _ = fmt.Fprint(e.stderr, "\r\033[K")
	}
	if err != nil && sum == nil {
		return nil, nil, err
	}
	return sum, flows, err
}

func infoCommand(e *env) *cobra.Command {
	var sf scanFlags
	cmd := &cobra.Command{
		Use:   "info TRACE...",
		Short: "Describe a trace: format, interfaces, link types, drops, snap length, connections, quality",
		Args:  args(1, -1),
		RunE: func(cmd *cobra.Command, a []string) error {
			o, err := sf.options(e)
			if err != nil {
				return err
			}
			var outs []infoJSON
			var firstErr error
			for i, arg := range a {
				sum, flows, err := scan(cmd, e, arg, o)
				if sum == nil {
					return err
				}
				if err != nil && firstErr == nil {
					firstErr = err
				}
				if e.json {
					outs = append(outs, infoJSON{Summary: sum, Flows: counts(flows)})
					continue
				}
				if i > 0 {
					_, _ = fmt.Fprintln(e.stdout)
				}
				if err := printInfo(e.stdout, sum, flows); err != nil {
					return err
				}
			}
			if e.json {
				if err := writeJSON(e.stdout, struct {
					SchemaVersion int        `json:"schema_version"`
					Traces        []infoJSON `json:"traces"`
				}{schemaVersion, outs}); err != nil {
					return err
				}
			}
			return firstErr
		},
	}
	sf.register(cmd)
	return cmd
}

type flowCounts struct {
	TCP    int `json:"tcp"`
	Modbus int `json:"modbus_tcp"`
	TLS    int `json:"tls"`
}

type infoJSON struct {
	Summary *trace.FileSummary `json:"summary"`
	Flows   flowCounts         `json:"flows"`
}

func counts(flows []trace.Flow) flowCounts {
	c := flowCounts{TCP: len(flows)}
	for _, f := range flows {
		switch f.Class {
		case trace.ClassModbus:
			c.Modbus++
		case trace.ClassTLS:
			c.TLS++
		}
	}
	return c
}

func ts(t *time.Time) string {
	if t == nil {
		return "-"
	}
	return t.Format(time.RFC3339Nano)
}

func printInfo(w io.Writer, s *trace.FileSummary, flows []trace.Flow) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	p := func(k, format string, a ...any) {
		_, _ = fmt.Fprintf(tw, "%s\t"+format+"\n", append([]any{k}, a...)...)
	}
	format := s.Format
	if s.Gzip {
		format += ", gzip"
	}
	p("file", "%s (%s, %d bytes)", s.File, format, s.InputBytes)
	p("sha256", "%s", s.SHA256)
	p("packets", "%d (%d bytes captured)", s.Packets, s.Bytes)
	if s.First != nil {
		p("time", "%s to %s (%s)", ts(s.First), ts(s.Last), s.Last.Sub(*s.First))
	}
	for _, f := range s.Interfaces {
		line := fmt.Sprintf("%d: %s (link type %d), snaplen %d, tsresol %d, %d packets", f.ID, f.Link, f.LinkType, f.SnapLen, f.TSResol, f.Packets)
		if f.Name != "" {
			line += ", " + strconv.Quote(f.Name)
		}
		if f.Drops != nil {
			line += fmt.Sprintf(", %d dropped by the capture", *f.Drops)
		}
		p("interface", "%s", line)
	}
	for _, sec := range s.Sections {
		if sec.Application != "" || sec.OS != "" {
			p("captured by", "%s %s %s", sec.Application, sec.OS, sec.Hardware)
		}
	}
	if s.Snaplen.TruncatedPackets > 0 {
		p("snaplen", "%d packets truncated, %d TCP payload bytes cut", s.Snaplen.TruncatedPackets, s.Snaplen.PayloadBytesCut)
	}
	if len(s.Unsupported) > 0 {
		p("not TCP", "%s", kv(s.Unsupported))
	}
	c := counts(flows)
	p("connections", "%d TCP, %d Modbus/TCP, %d TLS; %d midstream, %d evicted", c.TCP, c.Modbus, c.TLS,
		s.Connections.Midstream, s.Connections.Evicted)
	q := s.Quality
	p("quality", "%s", kv(map[string]uint64{"retransmitted": q.Retransmitted, "out_of_order": q.OutOfOrder,
		"overlap_conflict": q.OverlapConflicts, "gaps": q.Gaps, "gap_bytes": q.GapBytes, "resyncs": q.Resyncs,
		"resync_failed": q.ResyncFailed, "foreign_protocol": q.ForeignFrames, "snaplen_truncated": q.SnaplenTruncated,
		"reassembly_overflow": q.ReassemblyOverflow, "reassembly_budget": q.ReassemblyBudget, "keepalives": q.Keepalives,
		"time_backwards": s.TimeBackwards}))
	r := s.Reader
	if r.SimplePackets+r.SkippedBlocks > 0 || r.TruncatedTail {
		p("reader", "%d simple packets (no time), %d damaged blocks skipped, truncated tail %v", r.SimplePackets, r.SkippedBlocks, r.TruncatedTail)
	}
	if s.Error != "" {
		p("error", "%s", s.Error)
	}
	return tw.Flush()
}

// kv prints non-zero counters in key order, or "none".
func kv(m map[string]uint64) string {
	keys := make([]string, 0, len(m))
	for k, v := range m {
		if v != 0 {
			keys = append(keys, k)
		}
	}
	if len(keys) == 0 {
		return "none"
	}
	sort.Strings(keys)
	parts := make([]string, len(keys))
	for i, k := range keys {
		parts[i] = fmt.Sprintf("%s=%d", k, m[k])
	}
	return strings.Join(parts, " ")
}

func flowsCommand(e *env) *cobra.Command {
	var (
		sf       scanFlags
		minScore float64
		all      bool
	)
	cmd := &cobra.Command{
		Use:   "flows TRACE",
		Short: "List the TCP flows with their Modbus score, class and roles",
		Long: `List the TCP flows of a trace with their Modbus/TCP assessment. By default only
flows classed modbus_tcp, or scoring at least --min-score, are listed; --all
lists every TCP flow. Non-standard ports are found this way: the class comes
from the traffic, not from the port.`,
		Args: args(1, 1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if minScore < 0 || minScore > 1 {
				return usageErr("--min-score %v: between 0 and 1", minScore)
			}
			o, err := sf.options(e)
			if err != nil {
				return err
			}
			_, flows, scanErr := scan(cmd, e, a[0], o)
			if flows == nil && scanErr != nil {
				return scanErr
			}
			var shown []trace.Flow
			for _, f := range flows {
				if all || f.Class == trace.ClassModbus || f.Score >= minScore {
					shown = append(shown, f)
				}
			}
			if shown == nil {
				shown = []trace.Flow{}
			}
			if e.json {
				err = writeJSON(e.stdout, struct {
					SchemaVersion int          `json:"schema_version"`
					Flows         []trace.Flow `json:"flows"`
				}{schemaVersion, shown})
			} else {
				err = printFlows(e.stdout, shown)
			}
			if err != nil {
				return err
			}
			return scanErr
		},
	}
	sf.register(cmd)
	cmd.Flags().Float64Var(&minScore, "min-score", 0.5, "also list flows scoring at least this (0..1)")
	cmd.Flags().BoolVar(&all, "all", false, "list every TCP flow")
	return cmd
}

func printFlows(w io.Writer, flows []trace.Flow) error {
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "ID\tCLIENT\tSERVER\tCLASS\tSCORE\tROLE\tOPEN\tCLOSE\tPACKETS\tADUS\tGAPS\tFIRST")
	for _, f := range flows {
		role := f.Role
		if f.RoleGuess {
			role += "?"
		}
		a, b := f.A.String(), f.B.String()
		if f.Role == "unknown" {
			a, b = a+" ?", b+" ?"
		}
		_, _ = fmt.Fprintf(tw, "%d\t%s\t%s\t%s\t%.2f\t%s\t%s\t%s\t%d\t%d/%d\t%d\t%s\n", f.ID, a, b, f.Class, f.Score, role,
			f.Open, f.Close, f.Packets[0]+f.Packets[1], f.ADUs[0], f.ADUs[1], f.Gaps, ts(f.First))
	}
	if len(flows) == 0 {
		_, _ = fmt.Fprintln(tw, "(no Modbus/TCP flows; --all lists every TCP flow)")
	}
	return tw.Flush()
}
