// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"errors"
	"net/netip"
	"os"
	"path/filepath"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// twoFiles writes one script cut into two files after the third poll, plus
// a UDP packet that belongs to no connection, and returns their paths.
func twoFiles(t *testing.T) (string, string) {
	t.Helper()
	var a, b bytes.Buffer
	ab, err := tracetest.New(&a, tracetest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	bb, err := tracetest.New(&b, tracetest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	c := ab.Conn(tracetest.ConnOptions{})
	ab.UDP(0, netip.MustParseAddrPort("10.0.0.9:5353"), netip.MustParseAddrPort("10.0.0.10:5353"), []byte("x"))
	for i := range 6 {
		if i == 3 {
			c = bb.ConnContinue(c)
		}
		c.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 1))
		c.Response(uint16(i), 1, tracetest.RegistersResponse(3, uint16(i)))
	}
	c.Close()
	if err := ab.Close(); err != nil {
		t.Fatal(err)
	}
	if err := bb.Close(); err != nil {
		t.Fatal(err)
	}
	dir := t.TempDir()
	pa, pb := filepath.Join(dir, "a.pcap"), filepath.Join(dir, "b.pcap")
	if err := os.WriteFile(pa, a.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(pb, b.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return pa, pb
}

func TestWalk(t *testing.T) {
	pa, pb := twoFiles(t)
	f, err := OpenFiles(pa, pb)
	if err != nil {
		t.Fatal(err)
	}
	if f.Name() != pa+","+pb || len(f.Names()) != 2 || f.Size() <= 0 {
		t.Errorf("name %q, names %v, size %d", f.Name(), f.Names(), f.Size())
	}
	sum, flows, err := Scan(context.Background(), f, ScanOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if len(flows) != 1 || len(sum.Inputs) != 2 {
		t.Fatalf("%d flows, inputs %+v", len(flows), sum.Inputs)
	}
	perConn := map[uint32]uint64{}
	perPart := map[int]uint64{}
	var other, frames uint64
	err = Walk(context.Background(), f, ScanOptions{}, func(p *RawPacket) error {
		perPart[p.Part]++
		if p.Frame != perPart[p.Part] || !p.HasTime || len(p.Data) == 0 || p.Iface.Part != p.Part {
			t.Errorf("packet %+v", p)
		}
		if p.Conn == 0 {
			other++
			return nil
		}
		if p.Endpoints[0] != flows[0].A && p.Endpoints[0] != flows[0].B {
			t.Errorf("endpoints %v, flow %v-%v", p.Endpoints, flows[0].A, flows[0].B)
		}
		perConn[p.Conn]++
		frames++
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	// Walk also gives the packets after the close (the last ACK) to their
	// connection; Scan counts them apart.
	if other != 1 || perConn[flows[0].ID] != flows[0].Packets[0]+flows[0].Packets[1]+sum.Connections.AfterClose || len(perPart) != 2 {
		t.Errorf("other %d, per connection %v, flow %+v, per file %v", other, perConn, flows[0], perPart)
	}
	if perPart[0]+perPart[1] != sum.Packets {
		t.Errorf("walked %v, scanned %d packets", perPart, sum.Packets)
	}

	// The frames of a transaction in the second file are found there.
	var refs []model.FrameRef
	_, err = Analyze(context.Background(), f, Options{}, SinkFunc(func(e *model.Event) error {
		if e.Txn != nil && e.Txn.Response != nil && e.Txn.Response.Refs[0].Part == 1 && refs == nil {
			refs = e.Txn.Response.Refs
		}
		return nil
	}))
	if err != nil || refs == nil {
		t.Fatalf("no transaction in the second file: %v", err)
	}
	fr, err := f.Frames(refs)
	if err != nil || len(fr) != len(refs) || fr[0].Ref.Part != 1 {
		t.Errorf("frames %+v, %v", fr, err)
	}
}

func TestWalkStops(t *testing.T) {
	pa, pb := twoFiles(t)
	f, err := OpenFiles(pa, pb)
	if err != nil {
		t.Fatal(err)
	}
	stop := errors.New("stop")
	n := 0
	err = Walk(context.Background(), f, ScanOptions{}, func(*RawPacket) error {
		n++
		return stop
	})
	if !errors.Is(err, stop) || n != 1 {
		t.Errorf("callback error: %v after %d packets", err, n)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := Walk(ctx, f, ScanOptions{}, func(*RawPacket) error { return nil }); !errors.Is(err, context.Canceled) {
		t.Errorf("cancelled: %v", err)
	}

	bad := filepath.Join(t.TempDir(), "bad.pcap")
	if err := os.WriteFile(bad, []byte("not a trace at all"), 0o600); err != nil {
		t.Fatal(err)
	}
	g, err := OpenFiles(pa, bad)
	if err != nil {
		t.Fatal(err)
	}
	if err := Walk(context.Background(), g, ScanOptions{}, func(*RawPacket) error { return nil }); err == nil {
		t.Error("a file that is no trace walked without an error")
	}
	if _, err := OpenFiles(filepath.Join(t.TempDir(), "missing.pcap")); err == nil {
		t.Error("a missing file opened")
	}
	if _, err := OpenFiles(t.TempDir()); err == nil {
		t.Error("a directory opened")
	}
	if s := OpenReader(bytes.NewReader(nil)); s.Size() != -1 || s.Name() != "-" {
		t.Errorf("stream size %d name %q", s.Size(), s.Name())
	}
}
