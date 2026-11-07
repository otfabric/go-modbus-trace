// SPDX-License-Identifier: MIT

// Command mbtracectl reads packet traces (pcap or pcapng, from tcpdump,
// Wireshark, dumpcap or tshark) and reports the Modbus/TCP traffic in them.
// It never captures live and never sends anything: the trace is its only
// input.
package main

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"os/signal"
	"strings"
	"syscall"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/otfabric/go-modbus-trace/cmd/mbtracectl/internal/buildinfo"
)

// Set by the linker (see Makefile and .github/workflows/release.yml); empty
// when not injected, and then resolved by buildinfo.
var (
	version   = ""
	tag       = ""
	commit    = ""
	buildDate = ""
)

// build is the resolved build information of this binary.
func build() buildinfo.Info {
	return buildinfo.Resolve("mbtracectl", version, tag, commit, buildDate, "github.com/otfabric/go-modbus-trace")
}

// toolVersion is the version written into the provenance of output files.
func toolVersion() string { return build().Version }

// Exit codes (docs/exitcodes.md): the organisation table. No command
// completes with a result that reports problems, so 1 (findings) is not
// used; a damaged trace is invalid input even when what was read before the
// damage is printed.
const (
	exitOK           = 0
	exitUsage        = 2
	exitInvalidInput = 3
	exitInternal     = 10 // output that cannot be written, or an internal error
	exitInterrupted  = 130
)

// errUsage marks an error in the command line.
var errUsage = errors.New("usage")

func usageErr(format string, args ...any) error {
	return fmt.Errorf("%w: %s", errUsage, fmt.Sprintf(format, args...))
}

// env is what a command reads and writes besides files.
type env struct {
	stdin    io.Reader
	stdout   io.Writer
	stderr   io.Writer
	json     bool
	progress bool // stderr is a terminal
}

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, isTerminal(os.Stderr)))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) int {
	e := &env{stdin: stdin, stdout: outWriter{stdout}, stderr: stderr, progress: tty}
	root := rootCommand(e)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(e.stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	if err == nil {
		return exitOK
	}
	code := exitCode(ctx, err)
	if code == exitUsage {
		_, _ = fmt.Fprintf(stderr, "mbtracectl: %s\n", strings.TrimPrefix(err.Error(), errUsage.Error()+": "))
		_, _ = fmt.Fprintln(stderr, "Run 'mbtracectl --help' for usage.")
		return code
	}
	if code == exitInterrupted {
		_, _ = fmt.Fprintln(stderr, "mbtracectl: interrupted")
		return code
	}
	_, _ = fmt.Fprintf(stderr, "mbtracectl: %v\n", err)
	return code
}

func rootCommand(e *env) *cobra.Command {
	root := &cobra.Command{
		Use:   "mbtracectl",
		Short: "Find and analyse Modbus/TCP traffic in pcap and pcapng traces",
		Long: `mbtracectl reads packet traces (pcap or pcapng, plain or gzip, from tcpdump,
Wireshark, dumpcap or tshark) and reports the Modbus/TCP traffic in them.
It never captures live and never sends anything: the trace is its only input.

A trace argument is a path, or - for standard input.

Every flag can also be set by an environment variable: MBTRACECTL_ and the flag
name in capitals with dashes as underscores (MBTRACECTL_JSON=1,
MBTRACECTL_SERVER_PORT=502,1502). A flag on the command line wins.`,
		SilenceUsage:  true,
		SilenceErrors: true,
		PersistentPreRunE: func(cmd *cobra.Command, _ []string) error {
			return applyEnv(cmd)
		},
	}
	root.PersistentFlags().BoolVar(&e.json, "json", false, "write JSON (docs/json-output.md) instead of text")
	root.SetFlagErrorFunc(func(_ *cobra.Command, err error) error { return usageErr("%v", err) })
	root.AddCommand(infoCommand(e), flowsCommand(e), summaryCommand(e), timelineCommand(e), exportCommand(e), extractCommand(e), versionCommand(e))
	registerCompletions(root)
	return root
}

// applyEnv sets every flag not given on the command line from its
// MBTRACECTL_ environment variable.
func applyEnv(cmd *cobra.Command) error {
	var err error
	set := func(f *pflag.Flag) {
		if err != nil || f.Changed {
			return
		}
		name := "MBTRACECTL_" + strings.ToUpper(strings.ReplaceAll(f.Name, "-", "_"))
		if v, ok := os.LookupEnv(name); ok {
			if e := cmd.Flags().Set(f.Name, v); e != nil {
				err = usageErr("%s: %v", name, e)
			}
		}
	}
	cmd.Flags().VisitAll(set)
	cmd.InheritedFlags().VisitAll(set)
	return err
}

// args checks the number of positional arguments as a usage error.
func args(lo, hi int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, a []string) error {
		if len(a) < lo || (hi >= 0 && len(a) > hi) {
			return usageErr("%s: %s", cmd.Name(), cmd.Use)
		}
		return nil
	}
}

func versionCommand(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Long: `Print the version, tag, commit, build date, Go version and platform on one line,
or with --json as one line of JSON (docs/schema/version-2.schema.json).`,
		Args: args(0, 0),
		RunE: func(*cobra.Command, []string) error {
			b := build()
			line := b.String()
			if e.json {
				line = b.JSON()
			}
			_, err := fmt.Fprintln(e.stdout, line)
			return err
		},
	}
}

// stickyWriter keeps the first write error, so a report printed line by
// line still fails the command on a closed pipe or a full disk.
type stickyWriter struct {
	w   io.Writer
	err error
}

func (s *stickyWriter) Write(b []byte) (int, error) {
	if s.err != nil {
		return 0, s.err
	}
	n, err := s.w.Write(b)
	s.err = err
	return n, err
}

// plural writes n with its noun: "1 client", "2 clients".
func plural(n uint64, noun string) string {
	if n == 1 {
		return "1 " + noun
	}
	return fmt.Sprintf("%d %ss", n, noun)
}
