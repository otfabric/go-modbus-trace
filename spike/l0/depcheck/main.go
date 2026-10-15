// SPDX-License-Identifier: MIT

// Command depcheck imports the gopacket packages a trace reader would use, so
// that `go list -deps` and cross-builds show what they pull in.
package main

import (
	_ "github.com/gopacket/gopacket"
	_ "github.com/gopacket/gopacket/ip4defrag"
	_ "github.com/gopacket/gopacket/ip6defrag"
	_ "github.com/gopacket/gopacket/layers"
	_ "github.com/gopacket/gopacket/pcapgo"
	_ "github.com/gopacket/gopacket/reassembly"
)

func main() {}
