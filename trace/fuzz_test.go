// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"encoding/binary"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
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
		raw := buf.Bytes()
		sum, flows, err := Scan(context.Background(), OpenReader(bytes.NewReader(raw)), ScanOptions{Limits: Limits{MaxConns: 2, BufferPerDir: 512, BufferTotal: 1024, ResyncScan: 128}})
		if err != nil {
			t.Fatal(err)
		}
		if len(sum.InternalErrors) > 0 {
			t.Fatalf("recovered panic: %+v", sum.InternalErrors[0])
		}
		if uint64(len(flows)) != sum.Connections.Total {
			t.Fatalf("%d flows, %d connections", len(flows), sum.Connections.Total)
		}
		// The full analysis of the same bytes: no panic, consistent events,
		// and provenance that points at packets carrying the ADU (TESTING.md
		// section 3).
		path := filepath.Join(t.TempDir(), "f.pcap")
		if err := os.WriteFile(path, raw, 0o600); err != nil {
			t.Fatal(err)
		}
		file, _ := Open(path)
		var opens, closes int
		var adus []*model.ADU
		asum, err := Analyze(context.Background(), file, Options{ScanOptions: ScanOptions{Limits: Limits{MaxConns: 2,
			BufferPerDir: 512, BufferTotal: 1024, ResyncScan: 128}}, MaxOutstanding: 4}, SinkFunc(func(e *model.Event) error {
			switch e.Kind {
			case model.KindConnOpen:
				opens++
			case model.KindConnClose:
				closes++
			case model.KindTxn:
				if e.Txn.Request == nil && e.Txn.Response == nil {
					t.Fatal("a transaction without ADUs")
				}
				for _, a := range []*model.ADU{e.Txn.Request, e.Txn.Response} {
					if a != nil {
						adus = append(adus, a)
					}
				}
			}
			return nil
		}))
		if err != nil || opens != closes || uint64(opens) != sum.Connections.Total || asum.InternalErrorCount > 0 {
			t.Fatalf("err %v, %d opens, %d closes, %d connections, internal errors %+v", err, opens, closes, sum.Connections.Total, asum.InternalErrors)
		}
		for _, a := range adus {
			for _, r := range a.Refs {
				if r.Frame == 0 || r.Frame > asum.Packets {
					t.Fatalf("frame %d of %d", r.Frame, asum.Packets)
				}
			}
			if a.Size != 7+len(a.PDU) {
				continue // cut short: the frames hold less
			}
			frs, err := file.Frames(a.Refs)
			if err != nil {
				t.Fatal(err)
			}
			var got []byte
			for _, fr := range frs {
				got = append(got, fr.Payload...)
			}
			want := tracetest.MBAP(a.TID, a.Unit, a.PDU)
			if len(got) == len(want) {
				copy(want[2:4], got[2:4]) // a foreign frame keeps its protocol ID
			}
			if !bytes.Equal(got, want) {
				t.Fatalf("ADU %x, frames carry %x", want, got)
			}
		}
	})
}
