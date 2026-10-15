// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"net/netip"
	"os"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-trace/internal/pcapio"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// plant builds testdata/plant.pcapng, the fixture the README uses: a
// SCADA host polls an inverter (holding registers every second, its
// identity once, a setpoint write at 30 s) and a gateway with two meters
// (input registers every two seconds; one read of a missing register).
func plant() []byte {
	var buf bytes.Buffer
	b, _ := tracetest.New(&buf, tracetest.Options{Format: tracetest.PcapNG,
		Section:    pcapio.Section{Application: "tracetest (go-modbus-trace testdata/plant.pcapng)"},
		Interfaces: []tracetest.Iface{{Link: tracetest.Ethernet, TSResol: 6, Name: "eth0"}}})
	scada := netip.MustParseAddr("10.0.0.10")
	inv := b.Conn(tracetest.ConnOptions{Client: netip.AddrPortFrom(scada, 40100), Server: netip.MustParseAddrPort("10.0.0.2:502")})
	gw := b.Conn(tracetest.ConnOptions{Client: netip.AddrPortFrom(scada, 40200), Server: netip.MustParseAddrPort("10.0.0.3:502")})
	id := []byte{0x2B, 0x0E, 0x01, 0x01, 0x00, 0x00, 0x03}
	for i, v := range []string{"OT Fabric", "INV-5000", "2.1.0"} {
		id = append(id, byte(i), byte(len(v)))
		id = append(id, v...)
	}
	inv.Request(1, 1, []byte{0x2B, 0x0E, 0x01, 0x00})
	inv.Response(1, 1, id)
	setpoint := uint16(100)
	for s := 0; s < 60; s++ {
		tid := uint16(10 + s)
		if s == 30 {
			setpoint = 80
			inv.Request(9000, 1, []byte{6, 0, 5, 0, 80})
			inv.Response(9000, 1, []byte{6, 0, 5, 0, 80})
		}
		vals := []uint16{uint16(230 + s%3), 50, uint16(1000 + 10*s), 0, 1, setpoint, 0, 0, 0, 0}
		inv.Request(tid, 1, tracetest.ReadRequest(3, 0, 10))
		inv.Response(tid, 1, tracetest.RegistersResponse(3, vals...))
		if s%2 == 0 {
			for unit := uint8(1); unit <= 2; unit++ {
				t := uint16(1000*int(unit) + s)
				gw.Request(t, unit, tracetest.ReadRequest(4, 0, 4))
				gw.Response(t, unit, tracetest.RegistersResponse(4, uint16(s), uint16(100*unit), 0, 1))
			}
		}
		if s == 10 {
			gw.Request(5000, 2, tracetest.ReadRequest(4, 100, 1))
			gw.Response(5000, 2, tracetest.Exception(4, 2))
		}
		b.Advance(time.Second)
	}
	inv.Close()
	gw.Close()
	_ = b.Close()
	return buf.Bytes()
}

// TestFixture keeps testdata/plant.pcapng the builder's output
// (MBTRACE_UPDATE=1 rewrites it; make golden).
func TestFixture(t *testing.T) {
	const path = "../testdata/plant.pcapng"
	want := plant()
	if os.Getenv("MBTRACE_UPDATE") != "" {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(path)
	if err != nil || !bytes.Equal(have, want) {
		t.Fatalf("testdata/plant.pcapng is not the builder's output: run make golden (%v)", err)
	}
}
