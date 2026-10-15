// SPDX-License-Identifier: MIT

package mbcapexport_test

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"

	modbus "github.com/otfabric/go-modbus"
	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/jsonl"
	"github.com/otfabric/go-modbus-capture/mbcap"
	"github.com/otfabric/go-modbus-capture/mbcsv"

	"github.com/otfabric/go-modbus-trace/export/mbcapexport"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// tool finds a pinned tool: $MBCAPCTL / $MODBUSCTL, or the PATH. Without it
// the test skips, unless MBTRACE_REQUIRE_TOOLS is set (CI), where it fails.
func tool(t *testing.T, name string) string {
	t.Helper()
	if p := os.Getenv(strings.ToUpper(name)); p != "" {
		return p
	}
	if p, err := exec.LookPath(name); err == nil {
		return p
	}
	msg := name + " is not installed: install the pinned version (Makefile: tools) or set $" + strings.ToUpper(name)
	if os.Getenv("MBTRACE_REQUIRE_TOOLS") != "" {
		t.Fatal(msg)
	}
	t.Skip(msg)
	return ""
}

// value is the script: register a at poll k.
func value(k int, a uint16) uint16 { return uint16(1000*k) + a }

const (
	unit  = 7
	polls = 10
	base  = 100
	regs  = 4
)

var identity = []string{"OT Fabric", "TRACE-1", "0.1.0", "https://otfabric.example"}

// scripted builds the trace: polls of holding registers 100..103, one per
// second, and a device identification read in two pages.
func scripted(t *testing.T) []byte {
	var buf bytes.Buffer
	b, _ := tracetest.New(&buf, tracetest.Options{Format: tracetest.PcapNG})
	c := b.Conn(tracetest.ConnOptions{Server: tracetest.MustEndpoint("10.0.0.2:502")})
	page := func(objs []int, more byte, next byte) []byte {
		p := []byte{0x2B, 0x0E, 0x02, 0x82, more, next, byte(len(objs))}
		for _, id := range objs {
			p = append(p, byte(id), byte(len(identity[id])))
			p = append(p, identity[id]...)
		}
		return p
	}
	c.Request(1, unit, []byte{0x2B, 0x0E, 0x02, 0x00})
	c.Response(1, unit, page([]int{0, 1}, 0xFF, 2))
	c.Request(2, unit, []byte{0x2B, 0x0E, 0x02, 0x02})
	c.Response(2, unit, page([]int{2, 3}, 0x00, 0))
	for k := range polls {
		vals := make([]uint16, regs)
		for i := range vals {
			vals[i] = value(k, base+uint16(i))
		}
		c.Request(uint16(10+k), unit, tracetest.ReadRequest(3, base, regs))
		c.Response(uint16(10+k), unit, tracetest.RegistersResponse(3, vals...))
		b.Advance(time.Second)
	}
	c.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func exportTo(t *testing.T, data []byte, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer func() { _ = f.Close() }()
	_, err = mbcapexport.Export(context.Background(), trace.OpenReader(bytes.NewReader(data)), trace.Options{},
		mbcapexport.Options{Producer: "go-modbus-trace test"}, func(h capture.Header) (capture.Writer, error) {
			switch {
			case strings.HasSuffix(path, ".jsonl"):
				return jsonl.NewWriter(f, h)
			case strings.HasSuffix(path, ".csv"):
				return mbcsv.NewWriter(f, h)
			default:
				return mbcap.NewWriter(f, h, nil)
			}
		})
	if err != nil {
		t.Fatal(err)
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

// serve starts modbusctl and returns a connected client.
func serve(t *testing.T, modbusctl string, args ...string) *modbus.Client {
	t.Helper()
	port := freePort(t)
	args = append(args, "--listen", "127.0.0.1", "--port", fmt.Sprint(port))
	cmd := exec.Command(modbusctl, args...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		_ = cmd.Process.Kill()
		_ = cmd.Wait()
	})
	deadline := time.Now().Add(10 * time.Second)
	for {
		c, err := net.Dial("tcp", fmt.Sprintf("127.0.0.1:%d", port))
		if err == nil {
			_ = c.Close()
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("modbusctl %v did not listen: %s", args, stderr.String())
		}
		time.Sleep(50 * time.Millisecond)
	}
	client, err := modbus.New(modbus.Config{URL: fmt.Sprintf("tcp://127.0.0.1:%d", port), Timeout: 5 * time.Second})
	if err != nil {
		t.Fatal(err)
	}
	if err := client.Open(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = client.Close() })
	return client
}

// TestReplayEndToEnd is LA10: trace -> export -> mbcapctl verify ->
// modbusctl static and replay -> a go-modbus client reads the scripted
// values, an exception where nothing was read, and the identity objects.
func TestReplayEndToEnd(t *testing.T) {
	mbcapctl, modbusctl := tool(t, "mbcapctl"), tool(t, "modbusctl")
	dir := t.TempDir()
	data := scripted(t)
	site := filepath.Join(dir, "site.mbcap")
	for _, p := range []string{site, filepath.Join(dir, "site.mbcap.jsonl"), filepath.Join(dir, "site.mbcap.csv")} {
		exportTo(t, data, p)
		if out, err := exec.Command(mbcapctl, "verify", p).CombinedOutput(); err != nil {
			t.Fatalf("mbcapctl verify %s: %v\n%s", filepath.Base(p), err, out)
		}
	}
	ctx := context.Background()
	for _, at := range []int{0, 3, 9} {
		t.Run(fmt.Sprintf("static at %ds", at), func(t *testing.T) {
			c := serve(t, modbusctl, "server", "static", "--input", site, "--at", fmt.Sprintf("%ds", at))
			got, err := c.ReadHoldingRegisters(ctx, unit, base, regs)
			if err != nil {
				t.Fatal(err)
			}
			// The poll of second k lands a fraction after k s: within one
			// sample interval of the scripted time.
			for i, v := range got {
				a := base + uint16(i)
				if v != value(at, a) && (at == 0 || v != value(at-1, a)) {
					t.Errorf("register %d at %ds: %d, want %d", a, at, v, value(at, a))
				}
			}
			if _, err := c.ReadHoldingRegisters(ctx, unit, 500, 1); !errors.Is(err, modbus.ErrIllegalDataAddress) {
				t.Errorf("a register never read: %v, want illegal data address", err)
			}
			di, err := c.ReadAllDeviceIdentification(ctx, unit)
			if err != nil {
				t.Fatal(err)
			}
			var vals []string
			for _, o := range di.Objects {
				vals = append(vals, o.Value)
			}
			if strings.Join(vals, "|") != strings.Join(identity, "|") {
				t.Errorf("identity %q", vals)
			}
		})
	}
	t.Run("replay", func(t *testing.T) {
		c := serve(t, modbusctl, "server", "replay", "--input", site, "--before-first", "absent", "--missing", "exception",
			"--speed", "1000", "--loops", "1")
		time.Sleep(300 * time.Millisecond) // the 10 s capture plays in 10 ms; then the last values stay
		got, err := c.ReadHoldingRegisters(ctx, unit, base, regs)
		if err != nil {
			t.Fatal(err)
		}
		for i, v := range got {
			if a := base + uint16(i); v != value(polls-1, a) {
				t.Errorf("register %d after the replay: %d, want %d", a, v, value(polls-1, a))
			}
		}
	})
}
