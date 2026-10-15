// SPDX-License-Identifier: MIT

package subtrace

import (
	"bytes"
	"context"
	"encoding/hex"
	"fmt"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/selection"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

func fixture(t *testing.T) []byte {
	var buf bytes.Buffer
	b, _ := tracetest.New(&buf, tracetest.Options{Format: tracetest.PcapNano, Interfaces: []tracetest.Iface{{Link: tracetest.SLL2}}})
	c := b.Conn(tracetest.ConnOptions{})
	d := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.5:41000"), Server: netip.MustParseAddrPort("10.0.0.3:502")})
	for i := range 6 {
		c.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 2))
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Seg: []int{5}}, tracetest.Frame{TID: uint16(i), Unit: 1, PDU: tracetest.RegistersResponse(3, uint16(i), 9)})
		d.Request(uint16(i), 1, []byte{6, 0, 1, 0, byte(i)})
		d.Response(uint16(i), 1, []byte{6, 0, 1, 0, byte(i)})
		b.Advance(time.Second)
	}
	c.Close()
	d.Close()
	b.UDP(0, netip.MustParseAddrPort("10.0.0.1:5000"), netip.MustParseAddrPort("10.0.0.2:5000"), []byte("x"))
	_ = b.Close()
	return buf.Bytes()
}

func lines(t *testing.T, data []byte, conn uint32) []string {
	t.Helper()
	var out []string
	_, err := trace.Analyze(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
		if x := e.Txn; x != nil && (conn == 0 || x.Conn == conn) {
			out = append(out, fmt.Sprintf("%s %s %s %s %s", x.Client, x.Server, x.Status, hex.EncodeToString(x.Request.PDU), hex.EncodeToString(x.Response.PDU)))
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// TestExtract is LA12.
func TestExtract(t *testing.T) {
	data := fixture(t)
	var out bytes.Buffer
	st, err := Extract(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.ScanOptions{},
		Options{Selection: selection.Selection{Conns: []uint32{1}}, Tool: "test"}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if st.Connections != 1 || st.Packets == 0 {
		t.Fatalf("%+v", st)
	}
	want, got := lines(t, data, 1), lines(t, out.Bytes(), 0)
	if strings.Join(got, "\n") != strings.Join(want, "\n") || len(got) != 6 {
		t.Errorf("re-analysis:\n%s\nwant:\n%s", strings.Join(got, "\n"), strings.Join(want, "\n"))
	}
	// A time window and a server (either end matches).
	from, to := 2*time.Second, 4*time.Second
	out.Reset()
	_, err = Extract(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.ScanOptions{},
		Options{Selection: selection.Selection{Servers: []netip.AddrPort{netip.MustParseAddrPort("10.0.0.3:502")}, FromOffset: &from, ToOffset: &to}}, &out)
	if err != nil {
		t.Fatal(err)
	}
	if got := lines(t, out.Bytes(), 0); len(got) != 2 || !strings.Contains(got[0], "10.0.0.3:502") {
		t.Errorf("window: %v", got)
	}
	if _, err := Extract(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.ScanOptions{},
		Options{Selection: selection.Selection{Units: []uint8{1}}}, &out); err == nil {
		t.Error("a transaction-level selection must be refused")
	}
	// Wireshark reads it, with the original timestamps.
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		return
	}
	out.Reset()
	_, _ = Extract(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.ScanOptions{}, Options{Tool: "test"}, &out)
	dir := t.TempDir()
	in, sub := filepath.Join(dir, "in.pcap"), filepath.Join(dir, "sub.pcapng")
	_ = os.WriteFile(in, data, 0o600)
	_ = os.WriteFile(sub, out.Bytes(), 0o600)
	fields := func(p string) string {
		b, err := exec.Command(tshark, "-r", p, "-Y", "tcp", "-T", "fields", "-e", "frame.time_epoch", "-e", "frame.len", "-e", "tcp.seq_raw").Output()
		if err != nil {
			t.Fatalf("tshark %s: %v", p, err)
		}
		return string(b)
	}
	if a, b := fields(in), fields(sub); a != b || a == "" {
		t.Errorf("tshark differs:\n%s\n%s", a, b)
	}
}
