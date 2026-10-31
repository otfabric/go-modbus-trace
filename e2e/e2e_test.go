// SPDX-License-Identifier: MIT

// Package e2e records a real go-modbus client and server talking over
// loopback TCP, writes the conversation as a trace file and takes that file
// through the public API, the way an application does: analysis, MBCAP
// export, timeline and sub-trace, then the error paths of a damaged file.
package e2e

import (
	"bytes"
	"context"
	"encoding/hex"
	"errors"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	modbus "github.com/otfabric/go-modbus"
	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/mbcap"

	"github.com/otfabric/go-modbus-trace/export/mbcapexport"
	"github.com/otfabric/go-modbus-trace/export/subtrace"
	"github.com/otfabric/go-modbus-trace/export/timeline"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

const (
	unit  = 5
	polls = 20
)

// device answers holding registers with their address and refuses address
// 9000, so the trace holds an exception too.
type device struct{}

func (device) HandleCoils(_ context.Context, r *modbus.CoilsRequest) ([]bool, error) {
	return make([]bool, r.Quantity), nil
}

func (device) HandleDiscreteInputs(_ context.Context, r *modbus.DiscreteInputsRequest) ([]bool, error) {
	return make([]bool, r.Quantity), nil
}

func (device) HandleInputRegisters(_ context.Context, r *modbus.InputRegistersRequest) ([]uint16, error) {
	return make([]uint16, r.Quantity), nil
}

func (device) HandleDeviceIdentification(context.Context, *modbus.DeviceIdentificationRequest) (*modbus.DeviceIdentificationResponse, error) {
	return nil, modbus.ErrIllegalFunction
}

func (device) HandleHoldingRegisters(_ context.Context, r *modbus.HoldingRegistersRequest) ([]uint16, error) {
	if r.Addr >= 9000 {
		return nil, modbus.ErrIllegalDataAddress
	}
	out := make([]uint16, r.Quantity)
	for i := range out {
		out[i] = r.Addr + uint16(i)
	}
	return out, nil
}

// chunk is one read on one side of the proxy.
type chunk struct {
	toServer bool
	b        []byte
}

// recorder is a TCP proxy between client and server that keeps every chunk
// in wire order.
type recorder struct {
	mu     sync.Mutex
	chunks []chunk
	wg     sync.WaitGroup
}

func (r *recorder) pipe(dst, src net.Conn, toServer bool) {
	defer r.wg.Done()
	buf := make([]byte, 4096)
	for {
		n, err := src.Read(buf)
		if n > 0 {
			r.mu.Lock()
			r.chunks = append(r.chunks, chunk{toServer, append([]byte(nil), buf[:n]...)})
			_, werr := dst.Write(buf[:n])
			r.mu.Unlock()
			if werr != nil {
				return
			}
		}
		if err != nil {
			if c, ok := dst.(*net.TCPConn); ok {
				_ = c.CloseWrite()
			}
			return
		}
	}
}

func freeAddr(t *testing.T) string {
	t.Helper()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().String()
}

// record runs the conversation and returns it as a pcapng file on disk, with
// the registers the client got, in order.
func record(t *testing.T) (string, [][]uint16) {
	t.Helper()
	ctx := context.Background()
	saddr := freeAddr(t)
	srv, err := modbus.NewServer(&modbus.ServerConfig{URL: "tcp://" + saddr, Timeout: 5 * time.Second}, device{})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { _ = srv.Stop() }()
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = l.Close() }()
	rec := &recorder{}
	rec.wg.Add(1)
	go func() {
		defer rec.wg.Done()
		cc, err := l.Accept()
		if err != nil {
			return
		}
		sc, err := net.Dial("tcp", saddr)
		if err != nil {
			_ = cc.Close()
			return
		}
		rec.wg.Add(2)
		go rec.pipe(sc, cc, true)
		go rec.pipe(cc, sc, false)
	}()

	client, err := modbus.New(modbus.Config{URL: "tcp://" + l.Addr().String(), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Open(); err != nil {
		t.Fatal(err)
	}
	var got [][]uint16
	for i := range polls {
		regs, err := client.ReadHoldingRegisters(ctx, unit, uint16(100+i), 4)
		if err != nil {
			t.Fatal(err)
		}
		got = append(got, regs)
	}
	if _, err := client.ReadHoldingRegisters(ctx, unit, 9000, 1); !errors.Is(err, modbus.ErrIllegalDataAddress) {
		t.Fatalf("read of the refused address: %v", err)
	}
	if err := client.Close(); err != nil {
		t.Fatal(err)
	}
	rec.wg.Wait()

	var buf bytes.Buffer
	b, err := tracetest.New(&buf, tracetest.Options{Format: tracetest.PcapNG})
	if err != nil {
		t.Fatal(err)
	}
	c := b.Conn(tracetest.ConnOptions{
		Client: netip.MustParseAddrPort("10.0.0.1:50000"),
		Server: netip.MustParseAddrPort("10.0.0.2:502"),
	})
	for _, ch := range rec.chunks {
		d := tracetest.ToClient
		if ch.toServer {
			d = tracetest.ToServer
		}
		c.Write(d, tracetest.WriteOpts{}, tracetest.Frame{Raw: ch.b})
		b.Advance(10 * time.Millisecond)
	}
	c.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "live.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, got
}

func analyze(t *testing.T, f *trace.File) []*model.Transaction {
	t.Helper()
	var txns []*model.Transaction
	_, err := trace.Analyze(context.Background(), f, trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
		if e.Txn != nil {
			txns = append(txns, e.Txn)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	return txns
}

func open(t *testing.T, path string) *trace.File {
	t.Helper()
	f, err := trace.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// registerHex is the PDU the server sent for a read that returned regs.
func registerHex(regs []uint16) string {
	b := []byte{3, byte(2 * len(regs))}
	for _, r := range regs {
		b = append(b, byte(r>>8), byte(r))
	}
	return hex.EncodeToString(b)
}

// TestAnalysisAgreesWithTheClient compares what the library decodes from the
// file with what the client really received.
func TestAnalysisAgreesWithTheClient(t *testing.T) {
	path, got := record(t)
	txns := analyze(t, open(t, path))
	if len(txns) != polls+1 {
		t.Fatalf("%d transactions, want %d", len(txns), polls+1)
	}
	for i, regs := range got {
		x := txns[i]
		if x.Status != model.StatusOK || x.Unit != unit || x.Function != 3 {
			t.Fatalf("transaction %d: %+v", i, x)
		}
		if h := hex.EncodeToString(x.Response.PDU); h != registerHex(regs) {
			t.Errorf("transaction %d: response %s, the client read %s", i, h, registerHex(regs))
		}
	}
	if last := txns[polls]; last.Status != model.StatusException || last.Exception != 2 {
		t.Errorf("last transaction: %+v", last)
	}
}

// TestExportToMBCAP writes a capture and reads it back with go-modbus-capture.
func TestExportToMBCAP(t *testing.T) {
	path, got := record(t)
	var out bytes.Buffer
	report, err := mbcapexport.Export(context.Background(), open(t, path), trace.Options{},
		mbcapexport.Options{Producer: "go-modbus-trace e2e"}, func(h capture.Header) (capture.Writer, error) {
			return mbcap.NewWriter(&out, h, nil)
		})
	if err != nil {
		t.Fatal(err)
	}
	if report.TransactionsSeen != polls+1 || report.SamplesWritten == 0 {
		t.Fatalf("report: %d seen, %d written", report.TransactionsSeen, report.SamplesWritten)
	}
	r, err := mbcap.NewReader(&out)
	if err != nil {
		t.Fatal(err)
	}
	c, err := capture.ReadAll(r)
	if err != nil {
		t.Fatal(err)
	}
	if err := c.Validate(); err != nil {
		t.Fatal(err)
	}
	if uint64(len(c.Samples)) != report.SamplesWritten {
		t.Fatalf("%d samples in the file, %d in the report", len(c.Samples), report.SamplesWritten)
	}
	if h := hex.EncodeToString(c.Samples[0].Response); h != registerHex(got[0]) {
		t.Errorf("first sample %s, the client read %s", h, registerHex(got[0]))
	}
}

// TestTimelineAndSubtrace checks the two other outputs: one timeline line per
// transaction, and a sub-trace that analyses to the same transactions.
func TestTimelineAndSubtrace(t *testing.T) {
	path, _ := record(t)
	var lines bytes.Buffer
	if _, _, err := timeline.Write(context.Background(), open(t, path), trace.Options{}, &lines, timeline.Options{Format: timeline.JSONL}); err != nil {
		t.Fatal(err)
	}
	if n := strings.Count(lines.String(), "\n"); n < polls+1 {
		t.Errorf("timeline has %d lines for %d transactions", n, polls+1)
	}

	var sub bytes.Buffer
	stats, err := subtrace.Extract(context.Background(), open(t, path), trace.ScanOptions{}, subtrace.Options{Tool: "e2e"}, &sub)
	if err != nil {
		t.Fatal(err)
	}
	if stats.Connections != 1 || stats.Packets == 0 {
		t.Fatalf("sub-trace stats %+v", stats)
	}
	want, again := analyze(t, open(t, path)), analyze(t, trace.OpenReader(bytes.NewReader(sub.Bytes())))
	if len(want) != len(again) {
		t.Fatalf("the sub-trace holds %d transactions of %d", len(again), len(want))
	}
	for i := range want {
		if !bytes.Equal(want[i].Response.PDU, again[i].Response.PDU) {
			t.Errorf("transaction %d differs in the sub-trace", i)
		}
	}
}

// TestDamagedFiles are the failures a user meets: results up to the end of a
// cut file, an error for something that is no trace at all.
func TestDamagedFiles(t *testing.T) {
	path, _ := record(t)
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var seen int
	// A trace may legally end anywhere, as one from a killed tcpdump does.
	if _, err = trace.Analyze(context.Background(), trace.OpenReader(bytes.NewReader(data[:len(data)/2])), trace.Options{},
		trace.SinkFunc(func(e *model.Event) error {
			if e.Txn != nil && e.Txn.Response != nil {
				seen++
			}
			return nil
		})); err != nil {
		t.Logf("cut file: %v", err)
	}
	if seen == 0 || seen >= polls+1 {
		t.Errorf("%d transactions from half a file of %d", seen, polls+1)
	}

	bad := filepath.Join(t.TempDir(), "notes.pcap")
	if err := os.WriteFile(bad, []byte("this is not a capture file at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := trace.Analyze(context.Background(), open(t, bad), trace.Options{}, trace.SinkFunc(func(*model.Event) error { return nil })); err == nil {
		t.Error("a text file analysed without an error")
	}
	if _, err := trace.Open(filepath.Join(t.TempDir(), "missing.pcap")); err == nil {
		t.Error("a missing file opened without an error")
	}
}
