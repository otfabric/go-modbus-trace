// SPDX-License-Identifier: MIT

package subtrace_test

import (
	"context"
	"fmt"
	"log"
	"net/netip"
	"os"
	"path/filepath"

	"github.com/otfabric/go-modbus-trace/export/subtrace"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
)

// The packets of one device's connections, as a pcapng file for Wireshark.
func ExampleExtract() {
	f, err := trace.Open("../../testdata/plant.pcapng")
	if err != nil {
		log.Fatal(err)
	}
	dir, err := os.MkdirTemp("", "example")
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = os.RemoveAll(dir) }()
	out, err := os.Create(filepath.Join(dir, "inverter.pcapng"))
	if err != nil {
		log.Fatal(err)
	}
	defer func() { _ = out.Close() }()
	sel := selection.Selection{Servers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.2:502")}}
	st, err := subtrace.Extract(context.Background(), f, trace.ScanOptions{}, subtrace.Options{Selection: sel, Tool: "example 1.0"}, out)
	if err != nil {
		log.Fatal(err)
	}
	fmt.Println(st.Packets, "packets of", st.Connections, "connection")
	// Output:
	// 130 packets of 1 connection
}
