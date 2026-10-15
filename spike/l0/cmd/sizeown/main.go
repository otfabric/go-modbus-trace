// SPDX-License-Identifier: MIT

// Command sizeown links only the own candidate, to compare binary sizes.
package main

import (
	"os"

	"github.com/otfabric/go-modbus-trace/spike/l0/own"
)

func main() {
	r, err := own.NewReader(os.Stdin)
	if err != nil {
		os.Exit(1)
	}
	p := own.NewPipeline(own.DefaultLimits)
	var pk own.Packet
	for r.Next(&pk) == nil {
		p.Packet(&pk)
	}
	p.Finish()
	os.Exit(int(p.S.ADUs & 1))
}
