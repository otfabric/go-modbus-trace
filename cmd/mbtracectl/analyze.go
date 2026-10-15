// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"
	"net/netip"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"text/tabwriter"
	"time"

	"github.com/spf13/cobra"

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

// device aggregates the transactions of one server endpoint and unit.
type device struct {
	Server       string            `json:"server"`
	Unit         uint8             `json:"unit"`
	Transactions uint64            `json:"transactions"`
	Statuses     map[string]uint64 `json:"statuses"`
	Functions    map[string]uint64 `json:"functions"`
	Clients      []string          `json:"clients"`
	First        *time.Time        `json:"first,omitempty"`
	Last         *time.Time        `json:"last,omitempty"`
	MaxLatencyNS int64             `json:"max_latency_ns"`
	clients      map[string]bool
}

func summaryCommand(e *env) *cobra.Command {
	var (
		af  analyzeFlags
		sf  selFlags
		sel selection.Selection
	)
	cmd := &cobra.Command{
		Use:   "summary TRACE",
		Short: "Summarise the Modbus traffic per server and unit: transactions by status and function, clients, latency",
		Args:  args(1, 1),
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
			f, err := open(e, a[0])
			if err != nil {
				return err
			}
			devs := map[string]*device{}
			sum, aerr := trace.Analyze(cmd.Context(), f, o, trace.SinkFunc(func(ev *model.Event) error {
				t := ev.Txn
				if t == nil || !sel.Match(t) {
					return nil
				}
				k := fmt.Sprintf("%s/%d", t.Server, t.Unit)
				d := devs[k]
				if d == nil {
					d = &device{Server: t.Server.String(), Unit: t.Unit, Statuses: map[string]uint64{}, Functions: map[string]uint64{}, clients: map[string]bool{}}
					devs[k] = d
				}
				d.Transactions++
				d.Statuses[t.Status]++
				d.Functions[strconv.Itoa(int(t.Function))]++
				d.clients[t.Client.Addr().String()] = true
				if tt := t.Time(); tt != nil {
					if d.First == nil || tt.Before(*d.First) {
						d.First = tt
					}
					if d.Last == nil || tt.After(*d.Last) {
						d.Last = tt
					}
				}
				d.MaxLatencyNS = max(d.MaxLatencyNS, t.LatencyNS)
				return nil
			}))
			if sum == nil {
				return aerr
			}
			list := make([]*device, 0, len(devs))
			for _, d := range devs {
				for c := range d.clients {
					d.Clients = append(d.Clients, c)
				}
				sort.Strings(d.Clients)
				list = append(list, d)
			}
			sort.Slice(list, func(i, j int) bool {
				if list[i].Server != list[j].Server {
					return list[i].Server < list[j].Server
				}
				return list[i].Unit < list[j].Unit
			})
			if e.json {
				err = writeJSON(e.stdout, struct {
					SchemaVersion int                `json:"schema_version"`
					Selection     string             `json:"selection,omitempty"`
					Summary       *trace.FileSummary `json:"summary"`
					Devices       []*device          `json:"devices"`
				}{schemaVersion, sel.String(), sum, list})
			} else {
				err = printSummary(e.stdout, sum, list)
			}
			if err != nil {
				return err
			}
			return aerr
		},
	}
	af.register(cmd)
	sf.register(cmd)
	return cmd
}

func printSummary(w io.Writer, s *trace.FileSummary, devs []*device) error {
	_, _ = fmt.Fprintf(w, "%s: %d packets, %s to %s\n", s.File, s.Packets, ts(s.First), ts(s.Last))
	_, _ = fmt.Fprintf(w, "transactions: %s\n", kv(s.Transactions))
	if len(s.TransactionFlags) > 0 {
		_, _ = fmt.Fprintf(w, "flags:        %s\n", kv(s.TransactionFlags))
	}
	_, _ = fmt.Fprintln(w)
	tw := tabwriter.NewWriter(w, 0, 4, 2, ' ', 0)
	_, _ = fmt.Fprintln(tw, "SERVER\tUNIT\tTXNS\tSTATUSES\tFUNCTIONS\tCLIENTS\tMAX LATENCY\tLAST")
	for _, d := range devs {
		_, _ = fmt.Fprintf(tw, "%s\t%d\t%d\t%s\t%s\t%s\t%s\t%s\n", d.Server, d.Unit, d.Transactions, kv(d.Statuses),
			kv(d.Functions), strings.Join(d.Clients, ","), time.Duration(d.MaxLatencyNS), ts(d.Last))
	}
	if len(devs) == 0 {
		_, _ = fmt.Fprintln(tw, "(no transactions)")
	}
	return tw.Flush()
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
		Use:   "timeline TRACE",
		Short: "Write the timeline of events: text, CSV or JSON Lines on stdout",
		Args:  args(1, 1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if e.json {
				format = "jsonl"
			}
			return runTimeline(cmd, e, &af, &sf, a[0], e.stdout, format, order, window)
		},
	}
	af.register(cmd)
	sf.register(cmd)
	cmd.Flags().StringVar(&format, "format", "text", "text, csv or jsonl")
	cmd.Flags().StringVar(&order, "order", "time", "time (bounded reorder window) or file (order of determination)")
	cmd.Flags().DurationVar(&window, "window", timeline.DefaultWindow, "reorder window of --order time, in trace time")
	return cmd
}

func runTimeline(cmd *cobra.Command, e *env, af *analyzeFlags, sf *selFlags, arg string, w io.Writer, format, order string, window time.Duration) error {
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
	f, err := open(e, arg)
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
	if err == nil && st.Late > 0 && e.progress {
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
	cmd := &cobra.Command{Use: "export", Short: "Export a trace: timeline (MBCAP follows)"}
	var (
		af          analyzeFlags
		sf          selFlags
		out, format string
		order       string
		window      time.Duration
	)
	tl := &cobra.Command{
		Use:   "timeline TRACE -o OUT",
		Short: "Write the timeline as CSV or JSON Lines to a file (format from the extension or --format)",
		Args:  args(1, 1),
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
			return safeWrite(e, a[0], out, func(w io.Writer) error {
				return runTimeline(cmd, e, &af, &sf, a[0], w, format, order, window)
			})
		},
	}
	af.register(tl)
	sf.register(tl)
	tl.Flags().StringVarP(&out, "output", "o", "", "output file, or - for stdout")
	tl.Flags().StringVar(&format, "format", "", "csv or jsonl (default: from the extension)")
	tl.Flags().StringVar(&order, "order", "time", "time or file")
	tl.Flags().DurationVar(&window, "window", timeline.DefaultWindow, "reorder window of --order time")
	cmd.AddCommand(tl)
	return cmd
}

// safeWrite writes out through a temporary file next to it, renamed into
// place only on success; an output that is also the input is refused.
func safeWrite(e *env, in, out string, write func(io.Writer) error) error {
	if out == "-" {
		return write(e.stdout)
	}
	if in != "-" {
		if a, err := os.Stat(in); err == nil {
			if b, err := os.Stat(out); err == nil && os.SameFile(a, b) {
				return usageErr("the output %s is the input", out)
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
