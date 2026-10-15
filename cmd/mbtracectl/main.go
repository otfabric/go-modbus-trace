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

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// Set by the linker (see Makefile).
var (
	version   = "0.0.0-dev"
	tag       = ""
	commit    = "unknown"
	buildDate = "unknown"
)

// Exit codes (docs/exitcodes.md).
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
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
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	defer stop()
	os.Exit(run(ctx, os.Args[1:], os.Stdin, os.Stdout, os.Stderr, isTerminal(os.Stderr)))
}

func isTerminal(f *os.File) bool {
	fi, err := f.Stat()
	return err == nil && fi.Mode()&os.ModeCharDevice != 0
}

func run(ctx context.Context, args []string, stdin io.Reader, stdout, stderr io.Writer, tty bool) int {
	e := &env{stdin: stdin, stdout: stdout, stderr: stderr, progress: tty}
	root := rootCommand(e)
	root.SetArgs(args)
	root.SetIn(stdin)
	root.SetOut(stdout)
	root.SetErr(stderr)
	err := root.ExecuteContext(ctx)
	switch {
	case err == nil:
		return exitOK
	case errors.Is(err, errUsage):
		_, _ = fmt.Fprintf(stderr, "mbtracectl: %s\n", strings.TrimPrefix(err.Error(), errUsage.Error()+": "))
		_, _ = fmt.Fprintln(stderr, "Run 'mbtracectl --help' for usage.")
		return exitUsage
	default:
		_, _ = fmt.Fprintf(stderr, "mbtracectl: %v\n", err)
		return exitError
	}
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
	root.AddCommand(infoCommand(e), flowsCommand(e), summaryCommand(e), timelineCommand(e), exportCommand(e), versionCommand(e))
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
func args(min, max int) cobra.PositionalArgs {
	return func(cmd *cobra.Command, a []string) error {
		if len(a) < min || (max >= 0 && len(a) > max) {
			return usageErr("%s: %s", cmd.Name(), cmd.Use)
		}
		return nil
	}
}

func versionCommand(e *env) *cobra.Command {
	return &cobra.Command{
		Use:   "version",
		Short: "Print the version",
		Args:  args(0, 0),
		RunE: func(*cobra.Command, []string) error {
			if e.json {
				return writeJSON(e.stdout, map[string]string{"version": version, "tag": tag, "commit": commit, "build_date": buildDate})
			}
			_, err := fmt.Fprintf(e.stdout, "mbtracectl %s (commit %s, built %s)\n", version, commit, buildDate)
			return err
		},
	}
}
