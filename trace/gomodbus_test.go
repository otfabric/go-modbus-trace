// SPDX-License-Identifier: MIT

package trace_test

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/hex"
	"fmt"
	"net"
	"net/netip"
	"strings"
	"sync"
	"testing"
	"time"

	modbus "github.com/otfabric/go-modbus"

	"github.com/otfabric/go-modbus-trace/mbtcp"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// This is LA6's bridge: a real go-modbus client talks to a real go-modbus
// server (v1.7.1 serves every function) on loopback, through a proxy that
// records both byte streams as they were read. The recording becomes a
// synthetic trace; its decode must equal what the client API returned.

// device answers every function with fixed values.
type device struct{}

func (device) HandleCoils(_ context.Context, r *modbus.CoilsRequest) ([]bool, error) {
	out := make([]bool, r.Quantity)
	for i := range out {
		out[i] = (int(r.Addr)+i)%3 == 0
	}
	return out, nil
}

func (device) HandleDiscreteInputs(_ context.Context, r *modbus.DiscreteInputsRequest) ([]bool, error) {
	out := make([]bool, r.Quantity)
	for i := range out {
		out[i] = (int(r.Addr)+i)%2 == 0
	}
	return out, nil
}

func (device) HandleHoldingRegisters(_ context.Context, r *modbus.HoldingRegistersRequest) ([]uint16, error) {
	if r.Addr == 9999 {
		return nil, modbus.ErrIllegalDataAddress
	}
	out := make([]uint16, r.Quantity)
	for i := range out {
		out[i] = 0x1000 + r.Addr + uint16(i)
	}
	return out, nil
}

func (device) HandleInputRegisters(_ context.Context, r *modbus.InputRegistersRequest) ([]uint16, error) {
	out := make([]uint16, r.Quantity)
	for i := range out {
		out[i] = 0x2000 + r.Addr + uint16(i)
	}
	return out, nil
}

func (device) HandleMaskWrite(context.Context, *modbus.MaskWriteRequest) error { return nil }
func (device) HandleReadWriteRegisters(_ context.Context, r *modbus.ReadWriteRegistersRequest) ([]uint16, error) {
	out := make([]uint16, r.ReadQty)
	for i := range out {
		out[i] = 0x3000 + uint16(i)
	}
	return out, nil
}
func (device) HandleExceptionStatus(context.Context, *modbus.ExceptionStatusRequest) (uint8, error) {
	return 0x6D, nil
}
func (device) HandleCommEventCounter(context.Context, *modbus.CommEventCounterRequest) (*modbus.CommEventCounterResponse, error) {
	return &modbus.CommEventCounterResponse{Status: 0, EventCount: 264}, nil
}
func (device) HandleCommEventLog(context.Context, *modbus.CommEventLogRequest) (*modbus.CommEventLogResponse, error) {
	return &modbus.CommEventLogResponse{Status: 0, EventCount: 264, MessageCount: 289, Events: []byte{0x20, 0x00}}, nil
}
func (device) HandleDiagnostics(_ context.Context, r *modbus.DiagnosticsRequest) ([]byte, error) {
	switch r.SubFunction {
	case modbus.DiagReturnQueryData:
		return r.Data, nil
	case modbus.DiagClearCountersAndDiagnosticReg:
		return []byte{0, 0}, nil
	case 0x02:
		return []byte{0xA5, 0x5A}, nil
	default:
		return []byte{0, 11}, nil
	}
}
func (device) HandleReportServerID(context.Context, *modbus.ReportServerIDRequest) ([]byte, error) {
	return []byte{0x42, 0xFF}, nil
}
func (device) HandleReadFileRecords(_ context.Context, r *modbus.ReadFileRecordsRequest) ([][]uint16, error) {
	var out [][]uint16
	for _, q := range r.Requests {
		rec := make([]uint16, q.RecordLength)
		for i := range rec {
			rec[i] = q.FileNumber<<8 | q.RecordNumber + uint16(i)
		}
		out = append(out, rec)
	}
	return out, nil
}
func (device) HandleWriteFileRecords(context.Context, *modbus.WriteFileRecordsRequest) error {
	return nil
}
func (device) HandleReadFIFOQueue(context.Context, *modbus.FIFOQueueRequest) ([]uint16, error) {
	return []uint16{0x01B8, 0x1284}, nil
}
func (device) HandleDeviceIdentification(context.Context, *modbus.DeviceIdentificationRequest) (*modbus.DeviceIdentificationResponse, error) {
	long := strings.Repeat("x", 120) // several objects of this size force paged (more follows) responses
	return &modbus.DeviceIdentificationResponse{Objects: []modbus.DeviceIdentificationObject{
		{ID: 0, Value: "OT Fabric"}, {ID: 1, Value: "TRACE-1"}, {ID: 2, Value: "1.7.1"},
		{ID: 3, Value: "https://otfabric.example"}, {ID: 4, Value: long}, {ID: 5, Value: long}, {ID: 6, Value: long},
	}}, nil
}

// chunk is one read on one side of the proxy.
type chunk struct {
	toServer bool
	b        []byte
}

// recorder forwards one client connection to the server and records the
// chunks in the order they were read.
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
			_, werr := dst.Write(buf[:n]) // under the lock: chunk order is wire order
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

func freePort(t *testing.T) int {
	l, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Skipf("no loopback: %v", err)
	}
	defer func() { _ = l.Close() }()
	return l.Addr().(*net.TCPAddr).Port
}

type op struct {
	name string
	call func(ctx context.Context, c *modbus.Client) (any, error)
	// check verifies the decoded transactions of the call against the value
	// the client returned.
	check func(t *testing.T, got any, txns []*model.Transaction)
}

func regsOf(v *mbtcp.View, name string) []uint16 {
	for _, f := range v.Fields {
		if f.Name == name {
			b, _ := hex.DecodeString(f.Hex)
			out := make([]uint16, len(b)/2)
			for i := range out {
				out[i] = binary.BigEndian.Uint16(b[2*i:])
			}
			return out
		}
	}
	return nil
}

func field(v *mbtcp.View, name string) uint64 {
	for _, f := range v.Fields {
		if f.Name == name && f.Value != nil {
			return *f.Value
		}
	}
	return 1 << 63
}

func ok(t *testing.T, txns []*model.Transaction, fc uint8) *model.Transaction {
	t.Helper()
	if len(txns) == 0 {
		t.Fatal("no transaction")
	}
	x := txns[0]
	if x.Status != model.StatusOK || x.Function != fc || len(x.Warnings) > 0 || x.Response == nil {
		t.Fatalf("transaction %+v (warnings %v)", x, x.Warnings)
	}
	return x
}

func TestGoModbusFrames(t *testing.T) {
	sport, pport := freePort(t), freePort(t)
	srv, err := modbus.NewServer(&modbus.ServerConfig{URL: fmt.Sprintf("tcp://127.0.0.1:%d", sport), Timeout: 5 * time.Second}, device{})
	if err != nil {
		t.Fatal(err)
	}
	if err := srv.Start(); err != nil {
		t.Skipf("server: %v", err)
	}
	defer func() { _ = srv.Stop() }()
	l, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", pport))
	if err != nil {
		t.Skipf("proxy: %v", err)
	}
	defer func() { _ = l.Close() }()
	rec := &recorder{}
	go func() {
		cc, err := l.Accept()
		if err != nil {
			return
		}
		sc, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", sport))
		if err != nil {
			_ = cc.Close()
			return
		}
		rec.wg.Add(2)
		go rec.pipe(sc, cc, true)
		go rec.pipe(cc, sc, false)
	}()
	client, err := modbus.New(modbus.Config{URL: fmt.Sprintf("tcp://127.0.0.1:%d", pport), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Open(); err != nil {
		t.Fatal(err)
	}
	const unit = 7
	ops := []op{
		{"FC01", func(ctx context.Context, c *modbus.Client) (any, error) { return c.ReadCoils(ctx, unit, 10, 12) },
			func(t *testing.T, got any, x []*model.Transaction) {
				tx := ok(t, x, 1)
				for i, b := range got.([]bool) {
					if v, ok := mbtcp.ValueAt(tx.Request.PDU, tx.Response.PDU, 10+uint16(i)); !ok || (v == 1) != b {
						t.Errorf("coil %d: %d, client %v", 10+i, v, b)
					}
				}
			}},
		{"FC02", func(ctx context.Context, c *modbus.Client) (any, error) { return c.ReadDiscreteInputs(ctx, unit, 3, 9) },
			func(t *testing.T, got any, x []*model.Transaction) {
				tx := ok(t, x, 2)
				for i, b := range got.([]bool) {
					if v, _ := mbtcp.ValueAt(tx.Request.PDU, tx.Response.PDU, 3+uint16(i)); (v == 1) != b {
						t.Errorf("input %d", i)
					}
				}
			}},
		{"FC03", func(ctx context.Context, c *modbus.Client) (any, error) {
			return c.ReadHoldingRegisters(ctx, unit, 100, 5)
		},
			func(t *testing.T, got any, x []*model.Transaction) {
				tx := ok(t, x, 3)
				if fmt.Sprint(regsOf(tx.Response.View, "registers")) != fmt.Sprint(got) || tx.Summary != "Read 5 holding registers @ 100" {
					t.Errorf("%v vs %v, %q", regsOf(tx.Response.View, "registers"), got, tx.Summary)
				}
			}},
		{"FC04", func(ctx context.Context, c *modbus.Client) (any, error) { return c.ReadInputRegisters(ctx, unit, 5, 3) },
			func(t *testing.T, got any, x []*model.Transaction) {
				if tx := ok(t, x, 4); fmt.Sprint(regsOf(tx.Response.View, "registers")) != fmt.Sprint(got) {
					t.Error("registers differ")
				}
			}},
		{"FC03 exception", func(ctx context.Context, c *modbus.Client) (any, error) {
			return c.ReadHoldingRegisters(ctx, unit, 9999, 1)
		},
			func(t *testing.T, _ any, x []*model.Transaction) {
				if x[0].Status != model.StatusException || x[0].Exception != 2 {
					t.Errorf("%+v", x[0])
				}
			}},
		{"FC05", func(ctx context.Context, c *modbus.Client) (any, error) { return nil, c.WriteCoil(ctx, unit, 3, true) },
			func(t *testing.T, _ any, x []*model.Transaction) {
				if tx := ok(t, x, 5); field(tx.Request.View, "value") != 0xFF00 || tx.Class != "write" {
					t.Errorf("%+v", tx.Request.View)
				}
			}},
		{"FC06", func(ctx context.Context, c *modbus.Client) (any, error) {
			return nil, c.WriteRegister(ctx, unit, 7, 0x1234)
		},
			func(t *testing.T, _ any, x []*model.Transaction) {
				if tx := ok(t, x, 6); field(tx.Request.View, "value") != 0x1234 || field(tx.Request.View, "address") != 7 {
					t.Error("FC06 fields")
				}
			}},
		{"FC07", func(ctx context.Context, c *modbus.Client) (any, error) { return c.ReadExceptionStatus(ctx, unit) },
			func(t *testing.T, got any, x []*model.Transaction) {
				if tx := ok(t, x, 7); field(tx.Response.View, "status") != uint64(got.(uint8)) || !hasFlag(tx, model.FlagSerialOverTCP) {
					t.Error("FC07")
				}
			}},
		{"FC08/0", func(ctx context.Context, c *modbus.Client) (any, error) {
			return c.DiagnosticLoopback(ctx, unit, 0x1234)
		},
			func(t *testing.T, _ any, x []*model.Transaction) {
				if tx := ok(t, x, 8); *tx.Sub != 0 || tx.Class != "read" {
					t.Errorf("%+v", tx)
				}
			}},
		{"FC08/2", func(ctx context.Context, c *modbus.Client) (any, error) { return c.DiagnosticRegister(ctx, unit) },
			func(t *testing.T, got any, x []*model.Transaction) {
				if tx := ok(t, x, 8); *tx.Sub != 2 || !strings.HasSuffix(regsHex(tx.Response.View), fmt.Sprintf("%04x", got.(uint16))) {
					t.Errorf("%+v", tx.Response.View)
				}
			}},
		{"FC08/11", func(ctx context.Context, c *modbus.Client) (any, error) { return c.BusMessageCount(ctx, unit) },
			func(t *testing.T, _ any, x []*model.Transaction) {
				if tx := ok(t, x, 8); *tx.Sub != 11 || tx.Class != "read" {
					t.Error("FC08/11")
				}
			}},
		{"FC08/10", func(ctx context.Context, c *modbus.Client) (any, error) {
			return nil, c.DiagnosticClearCounters(ctx, unit)
		},
			func(t *testing.T, _ any, x []*model.Transaction) {
				if tx := ok(t, x, 8); *tx.Sub != 10 || tx.Class != "other" {
					t.Error("FC08/10 changes state")
				}
			}},
		{"FC11", func(ctx context.Context, c *modbus.Client) (any, error) { return c.GetCommEventCounter(ctx, unit) },
			func(t *testing.T, got any, x []*model.Transaction) {
				if tx := ok(t, x, 11); field(tx.Response.View, "event_count") != uint64(got.(*modbus.CommEventCounterResponse).EventCount) {
					t.Error("FC11")
				}
			}},
		{"FC12", func(ctx context.Context, c *modbus.Client) (any, error) { return c.GetCommEventLog(ctx, unit) },
			func(t *testing.T, got any, x []*model.Transaction) {
				g := got.(*modbus.CommEventLogResponse)
				if tx := ok(t, x, 12); field(tx.Response.View, "message_count") != uint64(g.MessageCount) {
					t.Error("FC12")
				}
			}},
		{"FC15", func(ctx context.Context, c *modbus.Client) (any, error) {
			return nil, c.WriteCoils(ctx, unit, 20, []bool{true, false, true, true, false, false, true, false, true})
		}, func(t *testing.T, _ any, x []*model.Transaction) {
			if tx := ok(t, x, 15); field(tx.Request.View, "quantity") != 9 || field(tx.Request.View, "byte_count") != 2 {
				t.Error("FC15")
			}
		}},
		{"FC16", func(ctx context.Context, c *modbus.Client) (any, error) {
			return nil, c.WriteRegisters(ctx, unit, 30, []uint16{1, 2, 3})
		}, func(t *testing.T, _ any, x []*model.Transaction) {
			if tx := ok(t, x, 16); fmt.Sprint(regsOf(tx.Request.View, "values")) != "[1 2 3]" {
				t.Error("FC16")
			}
		}},
		{"FC17", func(ctx context.Context, c *modbus.Client) (any, error) { return c.ReportServerID(ctx, unit) },
			func(t *testing.T, _ any, x []*model.Transaction) {
				if tx := ok(t, x, 17); !hasFlag(tx, model.FlagSerialOverTCP) {
					t.Error("FC17")
				}
			}},
		{"FC20", func(ctx context.Context, c *modbus.Client) (any, error) {
			return c.ReadFileRecords(ctx, unit, []modbus.FileRecordRequest{{FileNumber: 4, RecordNumber: 1, RecordLength: 2}, {FileNumber: 3, RecordNumber: 9, RecordLength: 1}})
		}, func(t *testing.T, got any, x []*model.Transaction) {
			tx := ok(t, x, 20)
			g := got.([][]uint16)
			want := fmt.Sprintf("%04x%04x", g[0][0], g[0][1])
			if len(tx.Ranges) != 2 || tx.Ranges[1].File != 3 || !strings.Contains(regsHex(tx.Response.View), want) {
				t.Errorf("%+v %s", tx.Ranges, regsHex(tx.Response.View))
			}
		}},
		{"FC21", func(ctx context.Context, c *modbus.Client) (any, error) {
			return nil, c.WriteFileRecords(ctx, unit, []modbus.FileRecord{{FileNumber: 4, RecordNumber: 7, Data: []uint16{1, 2}}})
		}, func(t *testing.T, _ any, x []*model.Transaction) {
			if tx := ok(t, x, 21); len(tx.Ranges) != 1 || !tx.Ranges[0].Write {
				t.Error("FC21")
			}
		}},
		{"FC22", func(ctx context.Context, c *modbus.Client) (any, error) {
			return nil, c.MaskWriteRegister(ctx, unit, 4, 0x00F2, 0x0025)
		}, func(t *testing.T, _ any, x []*model.Transaction) {
			if tx := ok(t, x, 22); field(tx.Request.View, "or_mask") != 0x25 {
				t.Error("FC22")
			}
		}},
		{"FC23", func(ctx context.Context, c *modbus.Client) (any, error) {
			return c.ReadWriteMultipleRegisters(ctx, unit, 3, 4, 14, []uint16{0xFF, 0xFE})
		}, func(t *testing.T, got any, x []*model.Transaction) {
			tx := ok(t, x, 23)
			if fmt.Sprint(regsOf(tx.Response.View, "registers")) != fmt.Sprint(got) || len(tx.Ranges) != 2 || !tx.Ranges[1].Write {
				t.Error("FC23")
			}
		}},
		{"FC24", func(ctx context.Context, c *modbus.Client) (any, error) { return c.ReadFIFOQueue(ctx, unit, 0x04DE) },
			func(t *testing.T, got any, x []*model.Transaction) {
				tx := ok(t, x, 24)
				if fmt.Sprint(regsOf(tx.Response.View, "values")) != fmt.Sprint(got) || tx.Response.View.Ranges[0].Count != 2 {
					t.Errorf("FC24 %+v", tx.Response.View)
				}
			}},
		{"FC43/14 paged", func(ctx context.Context, c *modbus.Client) (any, error) {
			return c.ReadAllDeviceIdentification(ctx, unit)
		},
			func(t *testing.T, got any, x []*model.Transaction) {
				di := got.(*modbus.DeviceIdentification)
				if len(x) < 2 {
					t.Fatalf("%d pages: the device should page", len(x))
				}
				var values []string
				for _, tx := range x {
					ok(t, []*model.Transaction{tx}, 43)
					for _, f := range tx.Response.View.Fields {
						if strings.HasSuffix(f.Name, "_value") {
							b, _ := hex.DecodeString(f.Hex)
							values = append(values, string(b))
						}
					}
				}
				var want []string
				for _, o := range di.Objects {
					want = append(want, o.Value)
				}
				if strings.Join(values, "|") != strings.Join(want, "|") {
					t.Errorf("objects %q, client %q", values, want)
				}
			}},
	}
	ctx := context.Background()
	results := make([]any, len(ops))
	errs := make([]error, len(ops))
	for i, o := range ops {
		results[i], errs[i] = o.call(ctx, client)
	}
	_ = client.Close()
	_ = l.Close()
	rec.wg.Wait()

	// The recorded byte streams as a trace.
	var buf bytes.Buffer
	b, _ := tracetest.New(&buf, tracetest.Options{Format: tracetest.PcapNG})
	c := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("127.0.0.1:50000"), Server: netip.MustParseAddrPort(fmt.Sprintf("127.0.0.1:%d", sport))})
	for _, ch := range rec.chunks {
		d := tracetest.ToClient
		if ch.toServer {
			d = tracetest.ToServer
		}
		c.Write(d, tracetest.WriteOpts{}, tracetest.Frame{Raw: ch.b})
	}
	c.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	var all []*model.Transaction
	_, err = trace.Analyze(ctx, trace.OpenReader(&buf), trace.Options{}, trace.SinkFunc(func(e *model.Event) error {
		if e.Txn != nil {
			all = append(all, e.Txn)
		}
		return nil
	}))
	if err != nil {
		t.Fatal(err)
	}
	// The transactions in call order: one per call, except the paged FC43,
	// which is last and takes the rest.
	i := 0
	for k, o := range ops {
		t.Run(o.name, func(t *testing.T) {
			if errs[k] != nil && !strings.Contains(o.name, "exception") {
				t.Fatalf("client: %v", errs[k])
			}
			n := 1
			if strings.HasPrefix(o.name, "FC43") {
				n = len(all) - i
			}
			if i+n > len(all) {
				t.Fatalf("%d transactions, need %d", len(all), i+n)
			}
			o.check(t, results[k], all[i:i+n])
		})
		if strings.HasPrefix(o.name, "FC43") {
			i = len(all)
		} else {
			i++
		}
	}
	if i != len(all) {
		t.Errorf("%d transactions, %d checked", len(all), i)
	}
}

func hasFlag(t *model.Transaction, f string) bool {
	for _, x := range t.Flags {
		if x == f {
			return true
		}
	}
	return false
}

// regsHex returns the hex of every raw-data field of a view.
func regsHex(v *mbtcp.View) string {
	var s string
	for _, f := range v.Fields {
		s += f.Hex
	}
	return s
}
