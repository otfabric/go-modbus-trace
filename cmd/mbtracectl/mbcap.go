// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"regexp"
	"strconv"
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/jsonl"
	"github.com/otfabric/go-modbus-capture/mbcap"
	"github.com/otfabric/go-modbus-capture/mbcsv"

	"github.com/otfabric/go-modbus-trace/export/mbcapexport"
	"github.com/otfabric/go-modbus-trace/trace"
)

// openInputs opens the trace arguments: one stream ("-") or files that are
// one trace, in the order given.
func openInputs(e *env, args []string) (*trace.File, error) {
	if len(args) == 1 {
		return open(e, args[0])
	}
	for _, a := range args {
		if a == "-" {
			return nil, usageErr("standard input (-) cannot be combined with other inputs")
		}
	}
	return trace.OpenFiles(args...)
}

var sizeRE = regexp.MustCompile(`^(\d+)\s*(B|KiB|MiB|GiB|TiB|KB|MB|GB|TB)?$`)

// parseSize reads 1GiB, 512MiB, 1000000 (bytes).
func parseSize(flag, s string) (int64, error) {
	m := sizeRE.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return 0, usageErr("--%s %q: a size such as 512MiB or 1GiB", flag, s)
	}
	n, err := strconv.ParseInt(m[1], 10, 64)
	if err != nil {
		return 0, usageErr("--%s %q: %v", flag, s, err)
	}
	mult := map[string]int64{"": 1, "B": 1, "KiB": 1 << 10, "MiB": 1 << 20, "GiB": 1 << 30, "TiB": 1 << 40,
		"KB": 1e3, "MB": 1e6, "GB": 1e9, "TB": 1e12}[m[2]]
	return n * mult, nil
}

func mbcapCommand(e *env) *cobra.Command {
	var (
		af                        analyzeFlags
		sf                        selFlags
		out, report, format, comp string
		changeOnly, noExceptions  bool
		tick                      uint64
		names                     []string
		warnMem                   string
		blockSamples              int
	)
	cmd := &cobra.Command{
		Use:   "mbcap TRACE... -o OUT",
		Short: "Export the trace's reads as an MBCAP capture that modbusctl can replay as a virtual device",
		Long: `Export the matched, valid reads of a trace as an MBCAP capture (docs/MBCAP-EXPORT.md):
one target per server endpoint and unit, one stream per client. Writes, FC23,
vendor functions and anything uncertain are left out and counted in the report.
Several traces given in time order are one trace. The encoding follows the
output name (.mbcap, .mbcap.jsonl or .jsonl, .mbcap.csv or .csv) or --format.`,
		Args: args(1, -1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if out == "" {
				return usageErr("export mbcap: -o OUT is required")
			}
			if format == "" {
				switch {
				case out == "-", strings.HasSuffix(out, ".jsonl"):
					format = "jsonl"
				case strings.HasSuffix(out, ".csv"):
					format = "csv"
				case strings.HasSuffix(out, ".mbcap"):
					format = "mbcap"
				default:
					return usageErr("export mbcap: cannot tell the encoding of %q: use .mbcap, .mbcap.jsonl or .mbcap.csv, or --format", out)
				}
			}
			var opts *mbcap.Options
			switch format {
			case "mbcap":
				opts = &mbcap.Options{BlockSamples: blockSamples}
				switch comp {
				case "deflate":
					opts.Compression = mbcap.Deflate
				case "none":
					opts.Compression = mbcap.NoCompression
				default:
					return usageErr("--compression %q: deflate or none", comp)
				}
			case "jsonl", "csv":
			default:
				return usageErr("--format %q: mbcap, jsonl or csv", format)
			}
			if tick == 0 || tick > capture.MaxTickNS {
				return usageErr("--tick-ns %d: 1 to %d", tick, capture.MaxTickNS)
			}
			sel, err := sf.selection()
			if err != nil {
				return err
			}
			o, err := af.options(e, sel)
			if err != nil {
				return err
			}
			eo := mbcapexport.Options{Producer: "mbtracectl " + version, Step: step(cmd), TickNS: tick, ChangeOnly: changeOnly,
				NoExceptions: noExceptions, Selection: sel, Names: map[string]string{}}
			for _, n := range names {
				k, label, ok := strings.Cut(n, "=")
				if !ok || label == "" || !strings.Contains(k, "/") {
					return usageErr("--name %q: ip:port/unit=Label", n)
				}
				eo.Names[k] = label
			}
			lim, err := parseSize("warn-replay-memory", warnMem)
			if err != nil {
				return err
			}
			eo.WarnReplayMemory = lim
			if lim == 0 {
				eo.WarnReplayMemory = -1 // 0 turns the warning off
			}
			f, err := openInputs(e, a)
			if err != nil {
				return err
			}
			if report != "" && report == out {
				return usageErr("the report and the capture are the same file")
			}
			var rep *mbcapexport.Report
			err = safeWriteAll(e, a, out, func(w io.Writer) error {
				var err error
				rep, err = mbcapexport.Export(cmd.Context(), f, o, eo, func(h capture.Header) (capture.Writer, error) {
					switch format {
					case "mbcap":
						return mbcap.NewWriter(w, h, opts)
					case "csv":
						return mbcsv.NewWriter(w, h)
					default:
						return jsonl.NewWriter(w, h)
					}
				})
				return err
			})
			if err != nil {
				return err
			}
			if report != "" {
				if err := safeWriteAll(e, a, report, func(w io.Writer) error {
					enc := json.NewEncoder(w)
					enc.SetIndent("", "  ")
					return enc.Encode(rep)
				}); err != nil {
					return err
				}
			}
			if out != "-" {
				return printReport(e, rep)
			}
			return nil
		},
	}
	af.register(cmd)
	sf.register(cmd)
	fl := cmd.Flags()
	fl.StringVarP(&out, "output", "o", "", "output capture, or - for JSON Lines on stdout")
	fl.StringVar(&report, "report", "", "write the export report (JSON) to this file")
	fl.StringVar(&format, "format", "", "mbcap, jsonl or csv (default: from the output name)")
	fl.BoolVar(&changeOnly, "change-only", false, "write a change-only capture (repeated identical responses are dropped)")
	fl.BoolVar(&noExceptions, "no-exceptions", false, "leave exception responses out")
	fl.Uint64Var(&tick, "tick-ns", capture.DefaultTickNS, "tick size in nanoseconds (1 to 1e9)")
	fl.StringArrayVar(&names, "name", nil, "label a target: ip:port/unit=Label (repeatable)")
	fl.StringVar(&warnMem, "warn-replay-memory", "1GiB", "warn when a replay would need more memory than this (0: never)")
	fl.StringVar(&comp, "compression", "deflate", "binary data block compression: deflate or none")
	fl.IntVar(&blockSamples, "block-samples", 256, "binary: samples per data block")
	return cmd
}

// step is the provenance step: the command and its flags, no file names.
func step(cmd *cobra.Command) string {
	parts := []string{"mbtracectl " + version, "export mbcap"}
	cmd.Flags().Visit(func(f *pflag.Flag) {
		switch f.Name {
		case "output", "report":
			return
		}
		parts = append(parts, "--"+f.Name+"="+f.Value.String())
	})
	return strings.Join(parts, " ")
}

func printReport(e *env, r *mbcapexport.Report) error {
	if e.json {
		return writeJSON(e.stdout, r)
	}
	w := e.stdout
	_, _ = fmt.Fprintf(w, "%d transactions, %d samples written", r.TransactionsSeen, r.SamplesWritten)
	if r.ChangeOnlyDropped > 0 {
		_, _ = fmt.Fprintf(w, ", %d unchanged dropped", r.ChangeOnlyDropped)
	}
	_, _ = fmt.Fprintln(w)
	_, _ = fmt.Fprintf(w, "excluded: %s\n", kv(r.Excluded))
	for _, t := range r.Targets {
		_, _ = fmt.Fprintf(w, "target %d: %s (%d samples, %d clients)\n", t.ID, t.Label, t.Samples, len(t.Streams))
	}
	for _, x := range r.Warnings {
		if x.Code == "format_draft" {
			continue
		}
		if x.Target != 0 {
			_, _ = fmt.Fprintf(w, "warning: target %d: %s: %s\n", x.Target, x.Code, x.Text)
			continue
		}
		_, _ = fmt.Fprintf(w, "warning: %s: %s\n", x.Code, x.Text)
	}
	_, _ = fmt.Fprintf(w, "replay: about %d MiB in memory\n", r.Replay.EstimatedInMemoryBytes>>20)
	return nil
}
