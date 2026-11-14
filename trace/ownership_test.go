// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"context"
	"encoding/json"
	"math"
	"os"
	"path/filepath"
	"reflect"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// scribble overwrites everything reachable from v in place: numbers,
// strings, times, the elements of slices and what pointers point at.
func scribble(t testing.TB, v reflect.Value) {
	switch v.Kind() {
	case reflect.Pointer:
		if !v.IsNil() {
			scribble(t, v.Elem())
		}
	case reflect.Slice, reflect.Array:
		for i := range v.Len() {
			scribble(t, v.Index(i))
		}
	case reflect.Struct:
		opaque := false
		for i := range v.NumField() {
			opaque = opaque || !v.Type().Field(i).IsExported()
		}
		if opaque { // time.Time, netip.AddrPort
			if v.CanSet() {
				v.Set(reflect.Zero(v.Type()))
			}
			return
		}
		for i := range v.NumField() {
			scribble(t, v.Field(i))
		}
	case reflect.String:
		v.SetString("scribbled")
	case reflect.Bool:
		v.SetBool(!v.Bool())
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		v.SetInt(math.MaxInt8)
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		v.SetUint(math.MaxUint8)
	case reflect.Float32, reflect.Float64:
		v.SetFloat(-1)
	default:
		t.Fatalf("the events hold a %s, which scribble does not change yet", v.Kind())
	}
}

// TestEventsBelongToTheSink: an event and everything it points to belong to
// the sink once Event is called. A sink that overwrites every field of every
// event it receives gets the same later events, and the pass returns the
// same summary, as a sink that only reads them: the library neither reads
// nor changes an event after handing it over.
func TestEventsBelongToTheSink(t *testing.T) {
	traces := map[string][]byte{}
	traces["random"], _, _ = randomScript(t, 11)
	traces["faults"], _ = build(t, tracetest.Options{Format: tracetest.PcapNG}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, rd3)
		c.Request(1, 1, rd3) // retried
		c.Response(1, 1, resp3(1))
		c.Request(2, 1, rd3)
		c.Write(tracetest.ToClient, tracetest.WriteOpts{Lose: []int{0}}, tracetest.Frame{TID: 2, Unit: 1, PDU: resp3(2)})
		c.Write(tracetest.ToServer, tracetest.WriteOpts{OneByte: true, Retransmit: []int{3}}, tracetest.Frame{TID: 3, Unit: 1, PDU: rd3b})
		c.Response(3, 1, tracetest.Exception(3, 2))
		c.Request(4, 1, []byte{43, 14, 1, 0})
		c.Response(4, 1, []byte{43, 14, 1, 1, 0, 0, 1, 0, 2, 'O', 'K'})
		m := b.Conn(tracetest.ConnOptions{Midstream: true, Server: server6, Client: client6})
		m.Response(7, 1, resp3(7))
		m.Request(8, 1, rd3)
		c.Close()
	})
	for name, data := range traces {
		pass := func(change bool) ([]string, string) {
			var seen []string
			sum, err := Analyze(context.Background(), OpenReader(bytes.NewReader(data)), Options{}, SinkFunc(func(e *model.Event) error {
				b, err := json.Marshal(e)
				seen = append(seen, string(b))
				if change {
					scribble(t, reflect.ValueOf(e))
				}
				return err
			}))
			if err != nil {
				t.Fatal(err)
			}
			s, _ := json.Marshal(sum)
			return seen, string(s)
		}
		want, wantSum := pass(false)
		got, gotSum := pass(true)
		if len(got) != len(want) || len(want) < 10 {
			t.Fatalf("%s: %d events with a sink that changes them, %d with one that reads them", name, len(got), len(want))
		}
		for i := range want {
			if got[i] != want[i] {
				t.Fatalf("%s: event %d differs after the sink changed the events before it:\n %s\n %s", name, i+1, got[i], want[i])
			}
		}
		if gotSum != wantSum {
			t.Errorf("%s: the summary differs:\n %s\n %s", name, gotSum, wantSum)
		}
	}
}

func traceFile(t *testing.T, data []byte) *File {
	t.Helper()
	path := filepath.Join(t.TempDir(), "t.pcap")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	return f
}

// TestFramesBelongToTheCaller: every Frames call returns newly read packets
// that belong to the caller: changing one result changes no other, and
// Payload is the part of Data the reference names, not a copy.
func TestFramesBelongToTheCaller(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		poll(c, 1, 2)
		c.Close()
	})
	f := traceFile(t, data)
	_, evs := analyze(t, data, Options{})
	refs := txns(evs)[0].Request.Refs
	one, err := f.Frames(refs)
	if err != nil || len(one) != 1 || len(one[0].Payload) != 12 {
		t.Fatalf("frames %+v, %v", one, err)
	}
	fr := one[0]
	if &fr.Payload[0] != &fr.Data[fr.Ref.PayOff] || len(fr.Payload) != int(fr.Ref.PayLen) {
		t.Errorf("Payload is not Data[%d:%d]", fr.Ref.PayOff, fr.Ref.PayOff+fr.Ref.PayLen)
	}
	want := bytes.Clone(fr.Data)
	two, _ := f.Frames(refs)
	for i := range fr.Data {
		fr.Data[i] = 0xEE // also changes Payload
	}
	if fr.Payload[0] != 0xEE {
		t.Error("Payload does not share Data's bytes")
	}
	three, _ := f.Frames(refs)
	if !bytes.Equal(two[0].Data, want) || !bytes.Equal(three[0].Data, want) || !bytes.Equal(three[0].Payload, want[fr.Ref.PayOff:fr.Ref.PayOff+fr.Ref.PayLen]) {
		t.Error("a change to one result reached another")
	}
}

// TestFramesPayloadRange: the payload range of a reference is the caller's.
// A range inside the packet gives that part of it; any other range, also a
// negative or an overflowing one, gives no payload and no failure.
func TestFramesPayloadRange(t *testing.T) {
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		poll(c, 1, 1)
		c.Close()
	})
	f := traceFile(t, data)
	_, evs := analyze(t, data, Options{})
	ref := txns(evs)[0].Request.Refs[0]
	frs, err := f.Frames([]model.FrameRef{ref})
	if err != nil {
		t.Fatal(err)
	}
	n := int32(len(frs[0].Data))
	const none = -1
	for _, c := range []struct {
		off, length int32
		want        int32 // length of the payload, none for nil
	}{
		{ref.PayOff, ref.PayLen, ref.PayLen},
		{0, 0, 0}, {0, 1, 1}, {0, n - 1, n - 1}, {0, n, n}, {0, n + 1, none},
		{1, n - 1, n - 1}, {1, n, none},
		{n - 1, 1, 1}, {n - 1, 2, none}, {n, 0, 0}, {n, 1, none}, {n + 1, 0, none},
		{-1, 1, none}, {-1, 0, none}, {-1, n, none}, {math.MinInt32, 1, none},
		{0, -1, none}, {n, -1, none}, {n - 1, -1, none}, {1, math.MinInt32, none}, {math.MinInt32, math.MinInt32, none},
		{0, math.MaxInt32, none}, {1, math.MaxInt32, none}, {math.MaxInt32, 1, none}, {math.MaxInt32, math.MaxInt32, none},
		{math.MaxInt32, 0, none}, {math.MaxInt32, math.MinInt32, none}, {math.MaxInt32 - 1, 2, none},
	} {
		r := ref
		r.PayOff, r.PayLen = c.off, c.length
		frs, err := f.Frames([]model.FrameRef{r})
		if err != nil || len(frs) != 1 || int32(len(frs[0].Data)) != n {
			t.Fatalf("offset %d, length %d: %v, %d frames", c.off, c.length, err, len(frs))
		}
		got := int32(none)
		if frs[0].Payload != nil {
			got = int32(len(frs[0].Payload))
		}
		if got != c.want {
			t.Errorf("offset %d, length %d: payload of %d bytes, want %d (-1: none)", c.off, c.length, got, c.want)
		}
		if c.want > 0 && &frs[0].Payload[0] != &frs[0].Data[c.off] {
			t.Errorf("offset %d, length %d: the payload is not at its offset", c.off, c.length)
		}
	}
}

// TestCallbacksUseTheFile: a sink, and a Walk callback, may read frames back
// and run another pass on the same File while their own pass is running:
// the passes share nothing but the File, which is safe for concurrent use.
func TestCallbacksUseTheFile(t *testing.T) {
	data, _, _ := randomScript(t, 5)
	f := traceFile(t, data)
	ctx := context.Background()
	plain, err := Analyze(ctx, f, Options{}, SinkFunc(func(*model.Event) error { return nil }))
	if err != nil {
		t.Fatal(err)
	}
	frames, scans := 0, 0
	sum, err := Analyze(ctx, f, Options{}, SinkFunc(func(e *model.Event) error {
		if e.Txn == nil || e.Txn.Request == nil {
			return nil
		}
		frs, err := f.Frames(e.Txn.Request.Refs)
		if err != nil {
			return err
		}
		frames += len(frs)
		if scans < 3 { // a pass inside the pass
			inner, _, err := Scan(ctx, f, ScanOptions{})
			if err != nil || inner.Packets != plain.Packets {
				t.Errorf("the scan inside the sink: %v", err)
			}
			scans++
		}
		return nil
	}))
	a, _ := json.Marshal(plain)
	b, _ := json.Marshal(sum)
	if err != nil || frames == 0 || scans != 3 || !bytes.Equal(a, b) {
		t.Errorf("err %v, %d frames read, %d scans, summaries equal %v", err, frames, scans, bytes.Equal(a, b))
	}
	walked := 0
	if err := Walk(ctx, f, ScanOptions{}, func(p *RawPacket) error {
		if walked++; walked == 2 {
			n := 0
			if err := Walk(ctx, f, ScanOptions{}, func(*RawPacket) error { n++; return nil }); err != nil || uint64(n) != plain.Packets {
				t.Errorf("the walk inside the walk: %d packets, %v", n, err)
			}
		}
		return nil
	}); err != nil || uint64(walked) != plain.Packets {
		t.Errorf("walk: %d packets, %v", walked, err)
	}
}
