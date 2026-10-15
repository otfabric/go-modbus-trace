// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"testing"

	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// FuzzPipeline drives raw IPv4/TCP packets of three connections from the
// fuzz input (flags, sequence offsets, payloads), so the fuzzer gets past
// the readers into reassembly and framing. Scan must never panic.
func FuzzPipeline(f *testing.F) {
	seed, _ := build(&testing.T{}, tracetest.Options{Format: tracetest.Pcap, Interfaces: []tracetest.Iface{{Link: tracetest.Raw}}},
		func(b *tracetest.Builder) {
			c := b.Conn(tracetest.ConnOptions{})
			poll(c, 1, 2)
			c.Close()
		})
	f.Add(seed[24:]) // records only
	f.Add([]byte{0x02, 0, 0, 0, 0x18, 0, 7, 0, 1, 0, 0, 0, 0, 6, 1, 3, 0, 0, 0, 1})
	f.Fuzz(func(t *testing.T, in []byte) {
		var buf bytes.Buffer
		b, _ := tracetest.New(&buf, tracetest.Options{Format: tracetest.Pcap, Interfaces: []tracetest.Iface{{Link: tracetest.Raw}}})
		ends := [3][2]netip.AddrPort{}
		for i := range ends {
			ends[i] = [2]netip.AddrPort{netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(i + 1)}), 40000),
				netip.MustParseAddrPort("10.0.0.9:502")}
		}
		var seq [3][2]uint32
		for len(in) >= 4 {
			ctl, flags, delta, n := in[0], in[1], int16(binary.BigEndian.Uint16(in[2:])), 0
			in = in[4:]
			if len(in) > 0 {
				n = min(int(in[0]), len(in)-1)
				in = in[1:]
			}
			payload := in[:n]
			in = in[n:]
			c, d := int(ctl%3), int(ctl>>7)
			src, dst := ends[c][d], ends[c][1-d]
			s := seq[c][d] + uint32(int32(delta))
			tcp := binary.BigEndian.AppendUint16(nil, src.Port())
			tcp = binary.BigEndian.AppendUint16(tcp, dst.Port())
			tcp = binary.BigEndian.AppendUint32(tcp, s)
			tcp = binary.BigEndian.AppendUint32(tcp, seq[c][1-d])
			tcp = append(tcp, 5<<4, flags, 0xff, 0xff, 0, 0, 0, 0)
			b.IPProto(0, src.Addr(), dst.Addr(), 6, append(tcp, payload...))
			seq[c][d] = s + uint32(n)
		}
		_ = b.Close()
		sum, flows, err := Scan(context.Background(), OpenReader(&buf), ScanOptions{Limits: Limits{MaxConns: 2, BufferPerDir: 512, BufferTotal: 1024, ResyncScan: 128}})
		if err != nil {
			t.Fatal(err)
		}
		if len(sum.InternalErrors) > 0 {
			t.Fatalf("recovered panic: %+v", sum.InternalErrors[0])
		}
		if uint64(len(flows)) != sum.Connections.Total {
			t.Fatalf("%d flows, %d connections", len(flows), sum.Connections.Total)
		}
	})
}
