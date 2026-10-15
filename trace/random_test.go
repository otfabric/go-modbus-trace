// SPDX-License-Identifier: MIT

package trace

import (
	"fmt"
	"math/rand/v2"
	"net/netip"
	"os"
	"strconv"
	"testing"

	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// TestRandomScripts runs seeded random scripts: interleaved connections,
// random segmentation and one fault per write, compared with the truth.
func TestRandomScripts(t *testing.T) {
	seeds := 200
	if testing.Short() {
		seeds = 20
	}
	if n, err := strconv.Atoi(os.Getenv("MBTRACE_RANDOM_SEEDS")); err == nil {
		seeds = n // a longer run on demand
	}
	for seed := range seeds {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			data, tr, servers := randomScript(t, seed)
			r := run(t, data, ScanOptions{}, servers...)
			checkADUs(t, r, tr)
			checkCounters(t, r, tr)
		})
	}
}

// randomScript builds the trace of one seed.
func randomScript(t *testing.T, seed int) ([]byte, *tracetest.Truth, []netip.AddrPort) {
	{
		{
			rng := rand.New(rand.NewPCG(uint64(seed), 7))
			ng := rng.IntN(2) == 0
			o := tracetest.Options{Interfaces: []tracetest.Iface{{Link: tracetest.Ethernet}}}
			if ng {
				o.Format = tracetest.PcapNG
				o.Interfaces = append(o.Interfaces, tracetest.Iface{Link: tracetest.SLL2, TSResol: 9})
			}
			var servers []netip.AddrPort
			data, tr := build(t, o, func(b *tracetest.Builder) {
				var conns []*tracetest.Conn
				for i := range 1 + rng.IntN(4) {
					sv := netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 1, byte(i + 1)}), 502)
					servers = append(servers, sv)
					conns = append(conns, b.Conn(tracetest.ConnOptions{
						Client:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), uint16(40000+i)),
						Server:    sv,
						Midstream: rng.IntN(4) == 0,
						ServerISN: rng.Uint32(), ClientISN: rng.Uint32(), MSS: 16 + rng.IntN(300),
					}))
				}
				for i := range 30 + rng.IntN(60) {
					c := conns[rng.IntN(len(conns))]
					tid := uint16(0x0101 + i)
					n := 1 + rng.IntN(3)
					var frames []tracetest.Frame
					d := tracetest.Dir(rng.IntN(2))
					for k := range n {
						if d == tracetest.ToServer {
							frames = append(frames, tracetest.Frame{TID: tid + uint16(k), Unit: 1, PDU: tracetest.ReadRequest(3, 0x1111, 0x7d)})
						} else {
							vals := make([]uint16, 1+rng.IntN(20))
							for j := range vals {
								vals[j] = 0x0101 + uint16(rng.IntN(0xFE00))
							}
							frames = append(frames, tracetest.Frame{TID: tid + uint16(k), Unit: 1, PDU: tracetest.RegistersResponse(3, vals...)})
						}
					}
					var wo tracetest.WriteOpts
					for range 4 {
						wo.Seg = append(wo.Seg, 1+rng.IntN(40))
					}
					switch rng.IntN(9) {
					case 0:
						wo.Lose = []int{rng.IntN(5)}
					case 1:
						wo.Retransmit = []int{rng.IntN(5)}
					case 2:
						wo.Conflict = []int{rng.IntN(5)}
					case 3:
						wo.Reverse = true
					case 4:
						wo.OneByte = true
					case 5:
						if ng {
							wo.Duplicate, wo.DupIface = []int{rng.IntN(5)}, 1
						}
					case 6:
						c.Keepalive(d)
					}
					c.Write(d, wo, frames...)
				}
				for _, c := range conns {
					c.Close()
				}
			})
			return data, tr, servers
		}
	}
}
