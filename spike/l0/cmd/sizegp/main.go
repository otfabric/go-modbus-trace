// SPDX-License-Identifier: MIT

// Command sizegp links only the gopacket candidate, to compare binary sizes.
package main

import (
	"os"

	"github.com/otfabric/go-modbus-trace/spike/l0/gp"
)

func main() {
	st, err := gp.Run(os.Stdin, 1100)
	if err != nil {
		os.Exit(1)
	}
	os.Exit(int(st.ADUs & 1))
}
