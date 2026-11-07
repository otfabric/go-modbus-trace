// SPDX-License-Identifier: MIT

package main

import (
	"strings"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"

	"github.com/otfabric/go-modbus-trace/model"
)

// traceExts are the file extensions offered for a trace argument.
var traceExts = []string{"pcap", "pcapng", "cap", "gz"}

// flagValues are the value sets of the flags that take one, by flag name, for
// every command that has the flag.
var flagValues = map[string][]string{
	"status": {model.StatusOK, model.StatusException, model.StatusUnanswered, model.StatusOrphan,
		model.StatusAmbiguous, model.StatusMalformed, model.StatusUncertain},
	"class":       {"read", "write", "other"},
	"flag":        qualityFlags,
	"no-flag":     qualityFlags,
	"order":       {"time", "file"},
	"compression": {"deflate", "none"},
}

var qualityFlags = []string{model.FlagRetransmitted, model.FlagOutOfOrder, model.FlagGapAdjacent, model.FlagResynced,
	model.FlagSnaplen, model.FlagMidstream, model.FlagRoleGuessed, model.FlagRoleUnknown, model.FlagRetried,
	model.FlagClockOrder, model.FlagSlow, model.FlagInvalidPDU, model.FlagSerialOverTCP, model.FlagUnknownFunc,
	model.FlagBroadcast, model.FlagForeign}

// commandFlagValues are value sets and file extensions that depend on the
// command: the command path, then the flag.
var commandFlagValues = map[string]map[string][]string{
	"mbtracectl timeline":        {"format": {"text", "csv", "jsonl"}},
	"mbtracectl export timeline": {"format": {"csv", "jsonl"}},
	"mbtracectl export mbcap":    {"format": {"mbcap", "jsonl", "csv"}},
}

var commandFlagFiles = map[string]map[string][]string{
	"mbtracectl extract":         {"output": {"pcapng"}},
	"mbtracectl export timeline": {"output": {"csv", "jsonl"}},
	"mbtracectl export mbcap":    {"output": {"mbcap", "jsonl", "csv"}, "report": {"json"}},
}

// registerCompletions gives every flag of every command a completion: its
// value set, files of its type, or no file names for a free value; and the
// trace arguments complete trace files.
func registerCompletions(root *cobra.Command) {
	walk(root, func(c *cobra.Command) {
		path := c.CommandPath()
		if c.ValidArgsFunction == nil && len(c.ValidArgs) == 0 && hasTraceArgs(c) {
			c.ValidArgsFunction = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
				return traceExts, cobra.ShellCompDirectiveFilterFileExt
			}
		}
		each := func(f *pflag.Flag) {
			if _, ok := c.GetFlagCompletionFunc(f.Name); ok || f.Value.Type() == "bool" {
				return
			}
			var fn cobra.CompletionFunc
			switch {
			case commandFlagValues[path][f.Name] != nil:
				fn = cobra.FixedCompletions(commandFlagValues[path][f.Name], cobra.ShellCompDirectiveNoFileComp)
			case commandFlagFiles[path][f.Name] != nil:
				exts := commandFlagFiles[path][f.Name]
				fn = func(*cobra.Command, []string, string) ([]string, cobra.ShellCompDirective) {
					return exts, cobra.ShellCompDirectiveFilterFileExt
				}
			case flagValues[f.Name] != nil:
				fn = cobra.FixedCompletions(flagValues[f.Name], cobra.ShellCompDirectiveNoFileComp)
			default:
				fn = cobra.NoFileCompletions
			}
			_ = c.RegisterFlagCompletionFunc(f.Name, fn)
		}
		c.LocalFlags().VisitAll(each)
		c.PersistentFlags().VisitAll(each)
	})
}

// hasTraceArgs reports whether the positional arguments of c are traces.
func hasTraceArgs(c *cobra.Command) bool {
	return strings.Contains(c.Use, "TRACE")
}

func walk(c *cobra.Command, fn func(*cobra.Command)) {
	fn(c)
	for _, s := range c.Commands() {
		walk(s, fn)
	}
}
