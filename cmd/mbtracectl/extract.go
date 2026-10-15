// SPDX-License-Identifier: MIT

package main

import (
	"fmt"
	"io"

	"github.com/spf13/cobra"

	"github.com/otfabric/go-modbus-trace/export/subtrace"
)

// extractDoc is the JSON form of extract (docs/schema/extract-1.schema.json).
type extractDoc struct {
	SchemaVersion int `json:"schema_version"`
	subtrace.Stats
}

func extractCommand(e *env) *cobra.Command {
	var (
		af  analyzeFlags
		sf  selFlags
		out string
	)
	cmd := &cobra.Command{
		Use:   "extract TRACE... -o OUT.pcapng",
		Short: "Write the packets of selected connections, optionally in a time window, as a pcapng file",
		Long: `Write the packets of the selected connections as a pcapng file that Wireshark
opens: original timestamps, link types and interface descriptions, and a section
comment naming the selection. Select with --conn (IDs as flows lists them),
--server, --client (either end of a connection may match) and the time window.`,
		Args: args(1, -1),
		RunE: func(cmd *cobra.Command, a []string) error {
			if out == "" {
				return usageErr("extract: -o OUT is required")
			}
			sel, err := sf.selection()
			if err != nil {
				return err
			}
			o, err := af.options(e, sel)
			if err != nil {
				return err
			}
			f, err := openInputs(e, a)
			if err != nil {
				return err
			}
			var st subtrace.Stats
			err = safeWriteAll(e, a, out, func(w io.Writer) error {
				var err error
				st, err = subtrace.Extract(cmd.Context(), f, o.ScanOptions, subtrace.Options{Selection: sel, Tool: "mbtracectl " + version}, w)
				return err
			})
			if err != nil {
				return err
			}
			if out == "-" {
				return nil
			}
			if e.json {
				return writeJSON(e.stdout, extractDoc{schemaVersion, st})
			}
			_, err = fmt.Fprintf(e.stdout, "%d packets of %d connections written\n", st.Packets, st.Connections)
			return err
		},
	}
	af.register(cmd)
	f := cmd.Flags()
	f.StringVarP(&out, "output", "o", "", "output pcapng file, or - for stdout")
	f.StringSliceVar(&sf.servers, "server", nil, "server endpoints: ip or ip:port")
	f.StringSliceVar(&sf.clients, "client", nil, "client addresses")
	f.StringSliceVar(&sf.conns, "conn", nil, "connection IDs (as flows lists them)")
	f.StringVar(&sf.from, "from", "", "start of the time window, as an offset from the first packet")
	f.StringVar(&sf.to, "to", "", "end of the time window, as an offset from the first packet")
	f.StringVar(&sf.fromTime, "from-time", "", "start of the time window, RFC 3339")
	f.StringVar(&sf.toTime, "to-time", "", "end of the time window, RFC 3339")
	return cmd
}
