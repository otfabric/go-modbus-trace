// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

	"github.com/otfabric/go-modbus-trace/analyze"
	"github.com/otfabric/go-modbus-trace/export/timeline"
	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
)

// selFlags are the selection flags (ARCHITECTURE.md section 11).
type selFlags struct {
	servers, clients, units, conns, fcs, statuses, classes, flags, noFlags []string
	from, to, fromTime, toTime, addr                                       string
}

func (s *selFlags) register(cmd *cobra.Command) {
	f := cmd.Flags()
	f.StringSliceVar(&s.servers, "server", nil, "server endpoints: ip or ip:port")
	f.StringSliceVar(&s.clients, "client", nil, "client addresses")
	f.StringSliceVar(&s.units, "unit", nil, "unit IDs")
	f.StringSliceVar(&s.conns, "conn", nil, "connection IDs (as flows lists them)")
	f.StringSliceVar(&s.fcs, "fc", nil, "function codes, decimal or 0x hex")
	f.StringSliceVar(&s.statuses, "status", nil, "statuses: ok, exception, unanswered, orphan_response, ambiguous, malformed, uncertain")
	f.StringSliceVar(&s.classes, "class", nil, "classes: read, write, other")
	f.StringSliceVar(&s.flags, "flag", nil, "quality flags a transaction must have")
	f.StringSliceVar(&s.noFlags, "no-flag", nil, "quality flags a transaction must not have")
	f.StringVar(&s.from, "from", "", "start of the time window, as an offset from the first packet (e.g. 10m)")
	f.StringVar(&s.to, "to", "", "end of the time window, as an offset from the first packet")
	f.StringVar(&s.fromTime, "from-time", "", "start of the time window, RFC 3339")
	f.StringVar(&s.toTime, "to-time", "", "end of the time window, RFC 3339")
	f.StringVar(&s.addr, "range", "", "address range touched: space:start-end (holding:4096-4200)")
}

func number(flag, x string, bits int) (uint64, error) {
	v, err := strconv.ParseUint(x, 0, bits)
	if err != nil {
		return 0, usageErr("--%s %q: not a number", flag, x)
	}
	return v, nil
}

func (s *selFlags) selection() (selection.Selection, error) {
	var sel selection.Selection
	var err error
	if sel.Servers, err = endpoints("server", s.servers); err != nil {
		return sel, err
	}
	for _, c := range s.clients {
		a, err := netip.ParseAddr(strings.Trim(c, "[]"))
		if err != nil {
			return sel, usageErr("--client %q: not an address", c)
		}
		sel.Clients = append(sel.Clients, a)
	}
	for _, x := range s.units {
		v, err := number("unit", x, 8)
		if err != nil {
			return sel, err
		}
		sel.Units = append(sel.Units, uint8(v))
	}
	for _, x := range s.conns {
		v, err := number("conn", x, 32)
		if err != nil {
			return sel, err
		}
		sel.Conns = append(sel.Conns, uint32(v))
	}
	for _, x := range s.fcs {
		v, err := number("fc", x, 8)
		if err != nil {
			return sel, err
		}
		sel.Functions = append(sel.Functions, uint8(v))
	}
	sel.Statuses, sel.Classes, sel.Require, sel.Exclude = s.statuses, s.classes, s.flags, s.noFlags
	dur := func(flag, x string) (*time.Duration, error) {
		if x == "" {
			return nil, nil
		}
		d, err := time.ParseDuration(x)
		if err != nil || d < 0 {
			return nil, usageErr("--%s %q: not a duration (10m, 1h30m)", flag, x)
		}
		return &d, nil
	}
	abs := func(flag, x string) (*time.Time, error) {
		if x == "" {
			return nil, nil
		}
		t, err := time.Parse(time.RFC3339Nano, x)
		if err != nil {
			return nil, usageErr("--%s %q: not an RFC 3339 time", flag, x)
		}
		return &t, nil
	}
	if (s.from != "" && s.fromTime != "") || (s.to != "" && s.toTime != "") {
		return sel, usageErr("--from/--to and --from-time/--to-time exclude each other")
	}
	if sel.FromOffset, err = dur("from", s.from); err != nil {
		return sel, err
	}
	if sel.ToOffset, err = dur("to", s.to); err != nil {
		return sel, err
	}
	if sel.From, err = abs("from-time", s.fromTime); err != nil {
		return sel, err
	}
	if sel.To, err = abs("to-time", s.toTime); err != nil {
		return sel, err
	}
	if s.addr != "" {
		space, rng, ok := strings.Cut(s.addr, ":")
		lo, hi, ok2 := strings.Cut(rng, "-")
		a, err1 := strconv.ParseUint(lo, 0, 16)
		b, err2 := strconv.ParseUint(hi, 0, 16)
		valid := map[string]bool{"coil": true, "discrete": true, "holding": true, "input": true, "file": true, "fifo": true}
		if !ok || !ok2 || err1 != nil || err2 != nil || a > b || !valid[space] {
			return sel, usageErr("--range %q: space:start-end, space one of coil, discrete, holding, input, file, fifo", s.addr)
		}
		sel.Space, sel.Start, sel.End = mbtcp.Space(space), uint16(a), uint16(b)
	}
	return sel, nil
}

// analyzeFlags are the options of the commands that analyse. Their
// --server and --client (selection flags) also tell the role decision who
// the server and the client are.
type analyzeFlags struct {
	ports []uint
	slow  time.Duration
}

func (a *analyzeFlags) register(cmd *cobra.Command) {
	cmd.Flags().UintSliceVar(&a.ports, "server-port", []uint{502}, "TCP ports taken as Modbus servers when no handshake decides")
	cmd.Flags().DurationVar(&a.slow, "slow", time.Second, "latency above which a transaction is flagged slow")
}

func (a *analyzeFlags) options(e *env, sel selection.Selection) (trace.Options, error) {
	sf := scanFlags{serverPorts: a.ports}
	so, err := sf.options(e)
	if err != nil {
		return trace.Options{}, err
	}
	so.Servers = sel.Servers
	for _, c := range sel.Clients {
		so.Clients = append(so.Clients, netip.AddrPortFrom(c, 0))
	}
	if a.slow <= 0 {
		return trace.Options{}, usageErr("--slow %v: must be positive", a.slow)
	}
	return trace.Options{ScanOptions: so, Slow: a.slow}, nil
}

// summaryJSON is the JSON form of summary (docs/schema/summary-1.schema.json).
type summaryJSON struct {
	SchemaVersion int                      `json:"schema_version"`
	Selection     string                   `json:"selection,omitempty"`
	Summary       *trace.FileSummary       `json:"summary"`
	Overview      *analyze.OverviewResult  `json:"overview"`
	Devices       *analyze.DevicesResult   `json:"devices"`
	Patterns      *analyze.PatternsResult  `json:"patterns"`
	Coverage      []analyze.CoverageResult `json:"coverage"`
	// CoverageOverflow counts ranges of server, unit and space keys beyond
	// analyze.MaxCoverageSpaces.
	CoverageOverflow uint64 `json:"coverage_overflow"`
}

func summaryCommand(e *env) *cobra.Command {
	var (
		af  analyzeFlags
		sf  selFlags
		top int
		sel selection.Selection
	)
	cmd := &cobra.Command{
		Use:   "summary TRACE...",
		Short: "Summarise the Modbus traffic: devices, poll patterns, address coverage, latency, quality",
		Args:  args(1, -1),
		RunE: func(cmd *cobra.Command, a []string) error {
			var err error
			if sel, err = sf.selection(); err != nil {
				return err
			}
			o, err := af.options(e, sel)
			if err != nil {
				return err
			}
			o.FirstPacket = sel.Resolve
			f, err := openInputs(e, a)
			if err != nil {
				return err
			}
			ov, dev, pat, cov := analyze.NewOverview(), analyze.NewDevices(), analyze.NewPatterns(), analyze.NewCoverage()
			all := analyze.Tee(ov, dev, pat, cov)
			sum, aerr := trace.Analyze(cmd.Context(), f, o, trace.SinkFunc(func(ev *model.Event) error {
				if ev.Txn != nil && !sel.Match(ev.Txn) {
					return nil
				}
				if ev.Conn != nil && !sel.MatchConn(ev.Conn.ID, ev.Conn.Client, ev.Conn.Server) {
					return nil
				}
				return all.Event(ev)
			}))
			if sum == nil {
				return aerr
			}
			out := summaryJSON{SchemaVersion: schemaVersion, Selection: sel.String(), Summary: sum, Overview: ov.Result(),
				Devices: dev.Result(), Patterns: pat.Result(), Coverage: cov.Result(), CoverageOverflow: cov.Overflow()}
			if e.json {
				err = writeJSON(e.stdout, out)
			} else {
				err = printSummary(e.stdout, &out, top)
			}
			if err != nil {
				return err
			}
			return aerr
		},
	}
	af.register(cmd)
	sf.register(cmd)
	cmd.Flags().IntVar(&top, "top", 10, "poll patterns to list in the text output")
	return cmd
}

func dur(ns int64) string { return time.Duration(ns).Round(time.Microsecond).String() }

func printSummary(out io.Writer, s *summaryJSON, top int) error {
	w := &stickyWriter{w: out}
	f := s.Summary
	_, _ = fmt.Fprintf(w, "%s: %d packets, %s to %s\n", f.File, f.Packets, ts(f.First), ts(f.Last))
	_, _ = fmt.Fprintf(w, "transactions: %s\n", kv(s.Overview.ByStatus))
	if len(s.Overview.Flags) > 0 {
		_, _ = fmt.Fprintf(w, "flags:        %s\n", kv(s.Overview.Flags))
	}
	_, _ = fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tUNIT\tTXNS\tSTATUSES\tFUNCTIONS\tCLIENTS\tLATENCY P50/P99/MAX\tLAST")
	for _, d := range s.Devices.Devices {
		lat := "-"
		if l := d.Latency; l != nil {
			lat = dur(l.P50NS) + "/" + dur(l.P99NS) + "/" + dur(l.MaxNS)
		}
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n", d.Server, d.Unit, d.Transactions, kv(d.ByStatus),
			kv(d.ByFunction), strings.Join(d.Clients, ","), lat, ts(d.Last))
	}
	if len(s.Devices.Devices) == 0 {
		_, _ = fmt.Fprintln(tw, "(no transactions)")
	}
	_ = tw.Flush()
	if n := min(top, len(s.Patterns.Patterns)); n > 0 {
		_, _ = fmt.Fprintf(w, "\npoll patterns (%d of %d):\n", n, len(s.Patterns.Patterns))
		tw = tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
		_, _ = fmt.Fprintln(tw, "CLIENT\tSERVER\tUNIT\tREQUEST\tCOUNT\tINTERVAL P50\tJITTER\tVOLATILITY")
		for _, p := range s.Patterns.Patterns[:n] {
			iv := "-"
			if p.Interval != nil {
				iv = dur(p.Interval.P50NS)
			}
			_, _ = fmt.Fprintf(tw, "%s\t%s\t%d\t%s\t%d\t%s\t%s\t%.2f\n", p.Client, p.Server, p.Unit, p.Summary, p.Count, iv, dur(p.JitterNS), p.Volatility)
		}
		_ = tw.Flush()
	}
	if len(s.Coverage) > 0 {
		_, _ = fmt.Fprintln(w, "\naddresses read (written):")
		for _, c := range s.Coverage {
			_, _ = fmt.Fprintf(w, "  %s unit %d %s: %s", c.Server, c.Unit, c.Space, ranges(c.Read))
			if len(c.Written) > 0 {
				_, _ = fmt.Fprintf(w, " (%s)", ranges(c.Written))
			}
			_, _ = fmt.Fprintln(w)
		}
	}
	return w.err
}

func ranges(ivs []analyze.Interval) string {
	if len(ivs) == 0 {
		return "-"
	}
	var p []string
	for _, iv := range ivs {
		if iv.Start == iv.End {
			p = append(p, strconv.Itoa(int(iv.Start)))
		} else {
			p = append(p, fmt.Sprintf("%d-%d", iv.Start, iv.End))
		}
	}
	return strings.Join(p, ",")
}

// timelineCommand writes the timeline to stdout.
func timelineCommand(e *env) *cobra.Command {
	var (
		af            analyzeFlags
		sf            selFlags
		format, order string
		window        time.Duration
	)
	cmd := &cobra.Command{
		Use:   "timeline TRACE...",
		Short: "Write the timeline of events: text, CSV or JSON Lines on stdout",
		Args:  args(1, -1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if e.json {
				format = "jsonl"
			}
			return runTimeline(cmd, e, &af, &sf, a, e.stdout, format, order, window)
		},
	}
	af.register(cmd)
	sf.register(cmd)
	cmd.Flags().StringVar(&format, "format", "text", "text, csv or jsonl")
	cmd.Flags().StringVar(&order, "order", "time", "time (bounded reorder window) or file (order of determination)")
	cmd.Flags().DurationVar(&window, "window", timeline.DefaultWindow, "reorder window of --order time, in trace time")
	return cmd
}

func runTimeline(cmd *cobra.Command, e *env, af *analyzeFlags, sf *selFlags, ins []string, w io.Writer, format, order string, window time.Duration) error {
	sel, err := sf.selection()
	if err != nil {
		return err
	}
	o, err := af.options(e, sel)
	if err != nil {
		return err
	}
	to := timeline.Options{Selection: sel, Window: window}
	switch order {
	case "time":
		to.Order = timeline.ByTime
	case "file":
		to.Order = timeline.ByFile
	default:
		return usageErr("--order %q: time or file", order)
	}
	if window <= 0 {
		return usageErr("--window %v: must be positive", window)
	}
	f, err := openInputs(e, ins)
	if err != nil {
		return err
	}
	switch format {
	case "csv":
		to.Format = timeline.CSV
	case "jsonl":
		to.Format = timeline.JSONL
	case "text":
		return textTimeline(cmd, e, f, o, sel, w)
	default:
		return usageErr("--format %q: text, csv or jsonl", format)
	}
	_, st, err := timeline.Write(cmd.Context(), f, o, w, to)
	if err == nil && st.Late > 0 { // a warning, on stderr whether or not it is a terminal
		_, _ = fmt.Fprintf(e.stderr, "%d events came later than the reorder window and were written out of order\n", st.Late)
	}
	return err
}

// textTimeline writes one line per transaction, in order of determination.
func textTimeline(cmd *cobra.Command, e *env, f *trace.File, o trace.Options, sel selection.Selection, w io.Writer) error {
	o.FirstPacket = sel.Resolve
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "TIME\tCONN\tCLIENT\tSERVER\tUNIT\tTID\tSTATUS\tLATENCY\tSUMMARY\tFLAGS")
	sum, err := trace.Analyze(cmd.Context(), f, o, trace.SinkFunc(func(ev *model.Event) error {
		t := ev.Txn
		if t == nil || !sel.Match(t) {
			return nil
		}
		lat := ""
		if t.Request != nil && t.Response != nil {
			lat = time.Duration(t.LatencyNS).String()
		}
		_, err := fmt.Fprintf(tw, "%s\t%d\t%s\t%s\t%d\t%d\t%s\t%s\t%s\t%s\n", ts(t.Time()), t.Conn, t.Client, t.Server, t.Unit, t.TID,
			t.Status, lat, t.Summary, strings.Join(t.Flags, ","))
		return err
	}))
	if ferr := tw.Flush(); err == nil {
		err = ferr
	}
	_ = sum
	return err
}

func exportCommand(e *env) *cobra.Command {
	cmd := &cobra.Command{Use: "export", Short: "Export a trace: MBCAP for replay, or the timeline"}
	var (
		af          analyzeFlags
		sf          selFlags
		out, format string
		order       string
		window      time.Duration
	)
	tl := &cobra.Command{
		Use:   "timeline TRACE... -o OUT",
		Short: "Write the timeline as CSV or JSON Lines to a file (format from the extension or --format)",
		Args:  args(1, -1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if out == "" {
				return usageErr("export timeline: -o OUT is required")
			}
			if format == "" {
				switch {
				case strings.HasSuffix(out, ".csv"):
					format = "csv"
				case strings.HasSuffix(out, ".jsonl"), strings.HasSuffix(out, ".ndjson"):
					format = "jsonl"
				default:
					return usageErr("export timeline: cannot tell the format of %q: use .csv or .jsonl, or --format", out)
				}
			}
			if format == "text" {
				return usageErr("export timeline: --format csv or jsonl")
			}
			return safeWriteAll(e, a, out, func(w io.Writer) error {
				return runTimeline(cmd, e, &af, &sf, a, w, format, order, window)
			})
		},
	}
	af.register(tl)
	sf.register(tl)
	tl.Flags().StringVarP(&out, "output", "o", "", "output file, or - for stdout")
	tl.Flags().StringVar(&format, "format", "", "csv or jsonl (default: from the extension)")
	tl.Flags().StringVar(&order, "order", "time", "time or file")
	tl.Flags().DurationVar(&window, "window", timeline.DefaultWindow, "reorder window of --order time")
	cmd.AddCommand(mbcapCommand(e), tl)
	return cmd
}

// safeWriteAll writes out through a temporary file next to it, renamed
// into place only on success; an output that is also an input is refused.
func safeWriteAll(e *env, ins []string, out string, write func(io.Writer) error) error {
	if out == "-" {
		return write(e.stdout)
	}
	for _, in := range ins {
		if in == "-" {
			continue
		}
		if a, err := os.Stat(in); err == nil {
			if b, err := os.Stat(out); err == nil && os.SameFile(a, b) {
				return usageErr("the output %s is an input", out)
			}
		}
	}
	tmp, err := os.CreateTemp(filepath.Dir(out), "."+filepath.Base(out)+".*.tmp")
	if err != nil {
		return err
	}
	defer func() { _ = os.Remove(tmp.Name()) }()
	if err := write(tmp); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	return os.Rename(tmp.Name(), out)
}
