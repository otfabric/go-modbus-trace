// SPDX-License-Identifier: MIT

package trace_test

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/rand/v2"
	"net/netip"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"sync"
	"testing"
	"time"

	"github.com/otfabric/go-modbus-capture/capture"
	"github.com/otfabric/go-modbus-capture/mbcap"

	"github.com/otfabric/go-modbus-trace/analyze"
	"github.com/otfabric/go-modbus-trace/export/mbcapexport"
	"github.com/otfabric/go-modbus-trace/export/subtrace"
	"github.com/otfabric/go-modbus-trace/export/timeline"
	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// The chaos tests throw seeded random traffic at every consumer of the
// pipeline: many clients, servers and units, every class of function,
// malformed and vendor PDUs, pipelining, reused and unanswered transaction
// IDs, orphan responses, TCP faults, clock jumps, tiny limits, corrupted
// bytes and cancellation. There is no ground truth here; instead every run
// must keep the invariants that hold for any input (chaosCheck). A failing
// seed is reproduced with MBTRACE_CHAOS_SEED=<n>.

func chaosSeeds(t *testing.T) []int {
	if s, err := strconv.Atoi(os.Getenv("MBTRACE_CHAOS_SEED")); err == nil {
		return []int{s}
	}
	n := 150
	if testing.Short() {
		n = 15
	}
	if v, err := strconv.Atoi(os.Getenv("MBTRACE_CHAOS_SEEDS")); err == nil {
		n = v
	}
	out := make([]int, n)
	for i := range out {
		out[i] = i
	}
	return out
}

// chaosPDU returns a request and a response of a random kind.
func chaosPDU(rng *rand.Rand) (req, resp []byte) {
	addr, qty := uint16(rng.IntN(200)), uint16(1+rng.IntN(20))
	switch rng.IntN(12) {
	case 0, 1, 2: // holding or input registers
		fc := uint8(3 + rng.IntN(2))
		vals := make([]uint16, qty)
		for i := range vals {
			vals[i] = uint16(rng.IntN(4)) // few values: some responses repeat
		}
		return tracetest.ReadRequest(fc, addr, qty), tracetest.RegistersResponse(fc, vals...)
	case 3: // coils or discrete inputs
		fc := uint8(1 + rng.IntN(2))
		bits := make([]byte, 1+(int(qty)-1)/8)
		for i := range bits {
			bits[i] = byte(rng.IntN(256))
		}
		bits[len(bits)-1] &= byte(0xFF >> (8 - ((int(qty)-1)%8 + 1)))
		return tracetest.ReadRequest(fc, addr, qty), append([]byte{fc, byte(len(bits))}, bits...)
	case 4: // write single register
		r := []byte{6, byte(addr >> 8), byte(addr), 0, byte(rng.IntN(256))}
		return r, r
	case 5: // write multiple registers
		return []byte{16, byte(addr >> 8), byte(addr), 0, 1, 2, 0, 7}, []byte{16, byte(addr >> 8), byte(addr), 0, 1}
	case 6: // diagnostics echo, or a state-changing sub-function
		sub := []byte{0, 0}
		if rng.IntN(2) == 0 {
			sub = []byte{0, 1}
		}
		r := append([]byte{8}, append(sub, 0x12, 0x34)...)
		return r, r
	case 7: // device identification, basic stream
		return []byte{0x2B, 0x0E, 1, 0}, []byte{0x2B, 0x0E, 1, 1, 0, 0, 1, 0, 3, 'A', 'B', 'C'}
	case 8: // exception
		fc := uint8(1 + rng.IntN(4))
		return tracetest.ReadRequest(fc, addr, qty), tracetest.Exception(fc, uint8(1+rng.IntN(4)))
	case 9: // vendor function
		return []byte{0x41, 1, 2}, []byte{0x41, 3}
	case 10: // garbage after a valid function code
		g := make([]byte, 1+rng.IntN(8))
		for i := range g {
			g[i] = byte(rng.IntN(256))
		}
		return append([]byte{3}, g...), append([]byte{3}, g...)
	default: // FC23
		return []byte{23, 0, 0, 0, 1, 0, 9, 0, 1, 2, 0, 5}, []byte{23, 2, 0, 4}
	}
}

// chaosTrace builds the trace of one seed.
func chaosTrace(t *testing.T, rng *rand.Rand) []byte {
	t.Helper()
	o := tracetest.Options{Interfaces: []tracetest.Iface{{Link: tracetest.Ethernet}, {Link: tracetest.Ethernet}}}
	if rng.IntN(2) == 0 {
		o.Format = tracetest.PcapNG
		o.Interfaces[1] = tracetest.Iface{Link: tracetest.SLL2, TSResol: 9}
	}
	if rng.IntN(5) == 0 {
		o.SnapLen = uint32(60 + rng.IntN(40))
	}
	var buf bytes.Buffer
	b, err := tracetest.New(&buf, o)
	if err != nil {
		t.Fatal(err)
	}
	var conns []*tracetest.Conn
	for i := range 1 + rng.IntN(6) {
		port := uint16(502)
		if rng.IntN(4) == 0 {
			port = 1502 // found by structure, not by port
		}
		conns = append(conns, b.Conn(tracetest.ConnOptions{
			Client:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 0, byte(1 + rng.IntN(3))}), uint16(40000+i)),
			Server:    netip.AddrPortFrom(netip.AddrFrom4([4]byte{10, 0, 1, byte(1 + rng.IntN(3))}), port),
			Iface:     rng.IntN(2),
			Midstream: rng.IntN(4) == 0,
			ClientISN: rng.Uint32(), ServerISN: rng.Uint32(),
			MSS: 8 + rng.IntN(400),
		}))
	}
	tid := uint16(rng.IntN(65536))
	for range 20 + rng.IntN(120) {
		c := conns[rng.IntN(len(conns))]
		unit := uint8(rng.IntN(3))
		var wo tracetest.WriteOpts
		switch rng.IntN(14) {
		case 0:
			wo.Lose = []int{rng.IntN(3)}
		case 1:
			wo.Retransmit = []int{rng.IntN(3)}
		case 2:
			wo.Conflict = []int{rng.IntN(3)}
		case 3:
			wo.Reverse, wo.Seg = true, []int{1 + rng.IntN(5), 1 + rng.IntN(5)}
		case 4:
			wo.OneByte = true
		case 5:
			wo.Duplicate, wo.DupIface = []int{0}, 1
		case 6:
			wo.Fragment = 8 * (1 + rng.IntN(3))
		}
		if rng.IntN(20) == 0 {
			b.Advance(-time.Duration(rng.IntN(5)) * time.Millisecond) // clock jumps back
		} else {
			b.Advance(time.Duration(rng.IntN(3)) * time.Millisecond)
		}
		req, resp := chaosPDU(rng)
		if rng.IntN(15) != 0 {
			tid++ // otherwise reuse the previous transaction ID
		}
		switch rng.IntN(16) {
		case 0: // unanswered
			c.Write(tracetest.ToServer, wo, tracetest.Frame{TID: tid, Unit: unit, PDU: req})
		case 1: // orphan
			c.Write(tracetest.ToClient, wo, tracetest.Frame{TID: tid, Unit: unit, PDU: resp})
		case 2: // pipelined, answered out of order
			req2, resp2 := chaosPDU(rng)
			c.Write(tracetest.ToServer, wo, tracetest.Frame{TID: tid, Unit: unit, PDU: req}, tracetest.Frame{TID: tid + 1, Unit: unit, PDU: req2})
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{TID: tid + 1, Unit: unit, PDU: resp2}, tracetest.Frame{TID: tid, Unit: unit, PDU: resp})
			tid++
		case 3:
			c.Keepalive(tracetest.Dir(rng.IntN(2)))
		case 4: // junk between ADUs
			junk := make([]byte, 1+rng.IntN(30))
			for i := range junk {
				junk[i] = byte(rng.IntN(256))
			}
			c.Write(tracetest.ToServer, wo, tracetest.Frame{Raw: junk})
		default:
			c.Write(tracetest.ToServer, wo, tracetest.Frame{TID: tid, Unit: unit, PDU: req})
			c.Write(tracetest.ToClient, tracetest.WriteOpts{}, tracetest.Frame{TID: tid, Unit: unit, PDU: resp})
		}
		if rng.IntN(60) == 0 {
			b.UDP(0, netip.MustParseAddrPort("10.0.9.1:5353"), netip.MustParseAddrPort("10.0.9.2:5353"), []byte{1, 2, 3})
		}
	}
	for _, c := range conns {
		switch rng.IntN(3) {
		case 0:
			c.Close()
		case 1:
			c.Reset(tracetest.Dir(rng.IntN(2)))
		} // else: open at the end of the trace
	}
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// corrupt damages a trace in a random way, or leaves it intact.
func corrupt(rng *rand.Rand, data []byte) ([]byte, bool) {
	d := bytes.Clone(data)
	switch rng.IntN(6) {
	case 0: // flip bytes
		for range 1 + rng.IntN(20) {
			d[rng.IntN(len(d))] ^= byte(1 + rng.IntN(255))
		}
	case 1: // cut
		d = d[:rng.IntN(len(d))]
	case 2: // repeat a slice
		i := rng.IntN(len(d))
		j := i + rng.IntN(len(d)-i)
		d = append(d[:j:j], append(bytes.Clone(d[i:j]), d[j:]...)...)
	default:
		return d, false
	}
	return d, true
}

func chaosLimits(rng *rand.Rand) trace.Options {
	var o trace.Options
	if rng.IntN(3) == 0 {
		o.Limits = trace.Limits{MaxConns: 1 + rng.IntN(3), BufferPerDir: 16 + rng.IntN(512),
			BufferTotal: 32 + rng.IntN(1024), ResyncScan: 8 + rng.IntN(256), FragmentBudget: 64 + rng.IntN(1024)}
		o.MaxOutstanding = 1 + rng.IntN(4)
	}
	if rng.IntN(4) == 0 {
		o.ServerPorts = []uint16{502, 1502}
	}
	o.Slow = time.Duration(rng.IntN(3)) * time.Millisecond
	return o
}

// events runs Analyze and returns the events as JSON lines.
func events(ctx context.Context, f *trace.File, o trace.Options) (*trace.FileSummary, []*model.Event, []byte, error) {
	var evs []*model.Event
	var js bytes.Buffer
	enc := json.NewEncoder(&js)
	sum, err := trace.Analyze(ctx, f, o, trace.SinkFunc(func(e *model.Event) error {
		c := *e
		evs = append(evs, &c)
		return enc.Encode(e)
	}))
	return sum, evs, js.Bytes(), err
}

// chaosCheck holds for any input: no internal error, consistent counts,
// valid statuses, provenance inside the trace, and frames that carry the
// ADU bytes when the trace was not damaged.
func chaosCheck(t *testing.T, f *trace.File, sum *trace.FileSummary, evs []*model.Event, damaged bool) {
	t.Helper()
	if len(sum.InternalErrors) > 0 {
		t.Fatalf("recovered panics: %+v", sum.InternalErrors)
	}
	statuses := map[string]uint64{}
	for _, e := range evs {
		x := e.Txn
		if x == nil {
			continue
		}
		statuses[string(x.Status)]++
		switch x.Status {
		case model.StatusOK, model.StatusException, model.StatusUnanswered, model.StatusOrphan,
			model.StatusAmbiguous, model.StatusMalformed, model.StatusUncertain:
		default:
			t.Errorf("status %q", x.Status)
		}
		if x.Request == nil && x.Response == nil {
			t.Errorf("transaction without ADUs: %+v", x)
		}
		if x.Status == model.StatusOK && (x.Request == nil || x.Response == nil) {
			t.Errorf("ok without a pair: %+v", x)
		}
		for _, a := range []*model.ADU{x.Request, x.Response} {
			if a == nil {
				continue
			}
			if len(a.Refs) == 0 {
				t.Errorf("ADU without provenance: %+v", a)
				continue
			}
			for _, r := range a.Refs {
				if r.Frame == 0 || r.Frame > sum.Packets {
					t.Errorf("frame %d outside 1..%d", r.Frame, sum.Packets)
				}
			}
			if damaged || len(a.PDU) == 0 || a.Size != 7+len(a.PDU) { // cut by the snap length
				continue
			}
			frs, err := f.Frames(a.Refs)
			if err != nil {
				t.Errorf("frames %+v: %v", a.Refs, err)
				continue
			}
			var got []byte
			for _, fr := range frs {
				if fr.Payload == nil {
					got = nil // reassembled from IP fragments: no payload slice
					break
				}
				got = append(got, fr.Payload...)
			}
			want := tracetest.MBAP(a.TID, a.Unit, a.PDU)
			if len(got) >= 4 && slices.Contains(x.Flags, model.FlagForeign) {
				copy(want[2:4], got[2:4]) // a foreign frame keeps its protocol ID
			}
			if got != nil && !bytes.Equal(got, want) {
				t.Errorf("ADU %x, frames carry %x", want, got)
			}
		}
	}
	for k, n := range sum.Transactions {
		if statuses[k] != n {
			t.Errorf("summary counts %s=%d, events %d", k, n, statuses[k])
		}
	}
	for k, n := range statuses {
		if sum.Transactions[k] != n {
			t.Errorf("events count %s=%d, summary %d", k, n, sum.Transactions[k])
		}
	}
}

func TestChaos(t *testing.T) {
	for _, seed := range chaosSeeds(t) {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(uint64(seed), 0xC4A05))
			clean := chaosTrace(t, rng)
			data, damaged := corrupt(rng, clean)
			path := filepath.Join(t.TempDir(), "chaos.pcap")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			f, err := trace.Open(path)
			if err != nil {
				t.Fatal(err)
			}
			o := chaosLimits(rng)
			ctx := context.Background()

			sum, evs, js, err := events(ctx, f, o)
			if err != nil {
				if !damaged {
					t.Fatalf("an intact trace failed: %v", err)
				}
				return // a damaged header may end the read; it must not panic
			}
			chaosCheck(t, f, sum, evs, damaged)

			// Determinism, and a stream gives the same events as the file.
			_, _, again, err := events(ctx, trace.OpenReader(bytes.NewReader(data)), o)
			if err != nil || !bytes.Equal(js, again) {
				t.Errorf("the stream differs from the file (%v)", err)
			}

			// The scan agrees with the analysis on the packets.
			ssum, _, err := trace.Scan(ctx, f, o.ScanOptions)
			if err != nil || ssum.Packets != sum.Packets {
				t.Errorf("scan: %v, %d packets, analysis %d", err, ssum.Packets, sum.Packets)
			}

			// The analyzers see every transaction once.
			ov, dev := analyze.NewOverview(), analyze.NewDevices()
			pat, cov := analyze.NewPatterns(), analyze.NewCoverage()
			if _, err := trace.Analyze(ctx, f, o, analyze.Tee(ov, dev, pat, cov)); err != nil {
				t.Fatal(err)
			}
			var txns uint64
			for _, n := range sum.Transactions {
				txns += n
			}
			if ov.Result().Transactions != txns {
				t.Errorf("overview %d transactions, summary %d", ov.Result().Transactions, txns)
			}
			var perDevice uint64
			for _, d := range dev.Result().Devices {
				perDevice += d.Transactions
			}
			if perDevice+dev.Result().Overflow > txns {
				t.Errorf("devices count %d of %d transactions", perDevice, txns)
			}
			_ = pat.Result()
			_ = cov.Result()

			// The export accounts for every transaction and writes only what
			// the library accepts.
			var capBuf bytes.Buffer
			rep, err := mbcapexport.Export(ctx, f, o, mbcapexport.Options{Producer: "chaos"}, func(h capture.Header) (capture.Writer, error) {
				return mbcap.NewWriter(&capBuf, h, nil)
			})
			if err != nil {
				t.Fatalf("export: %v", err)
			}
			var excluded uint64
			for _, n := range rep.Excluded {
				excluded += n
			}
			if rep.TransactionsSeen != rep.SamplesWritten+rep.ChangeOnlyDropped+excluded || rep.TransactionsSeen != txns {
				t.Errorf("report: seen %d, written %d, dropped %d, excluded %d; summary %d",
					rep.TransactionsSeen, rep.SamplesWritten, rep.ChangeOnlyDropped, excluded, txns)
			}
			rd, err := mbcap.NewReader(bytes.NewReader(capBuf.Bytes()))
			if err != nil {
				t.Fatalf("the export does not read back: %v", err)
			}
			n := uint64(0)
			for {
				rec, err := rd.Next()
				if errors.Is(err, io.EOF) {
					break
				}
				if err != nil {
					t.Fatalf("after %d samples: %v", n, err)
				}
				if _, ok := rec.(capture.Sample); ok {
					n++
				}
			}
			if n != rep.SamplesWritten {
				t.Errorf("read back %d samples, report %d", n, rep.SamplesWritten)
			}

			// The timeline writes every event in both orders.
			for _, ord := range []timeline.Order{timeline.ByFile, timeline.ByTime} {
				if _, st, err := timeline.Write(ctx, f, o, io.Discard, timeline.Options{Format: timeline.JSONL, Order: ord}); err != nil || st.Rows != uint64(len(evs)) {
					t.Errorf("timeline order %v: %d rows of %d events, %v", ord, st.Rows, len(evs), err)
				}
			}

			// A sub-trace of everything re-analyses to the same transactions
			// (at default limits: tight ones evict differently when the
			// other traffic is gone).
			do := trace.Options{ScanOptions: trace.ScanOptions{ServerPorts: o.ServerPorts}, Slow: o.Slow}
			var sub bytes.Buffer
			if _, err := subtrace.Extract(ctx, f, do.ScanOptions, subtrace.Options{Tool: "chaos"}, &sub); err != nil {
				t.Fatalf("extract: %v", err)
			}
			if _, err := subtrace.Extract(ctx, f, o.ScanOptions, subtrace.Options{Tool: "chaos"}, io.Discard); err != nil {
				t.Fatalf("extract at tight limits: %v", err)
			}
			subSum, _, _, err := events(ctx, trace.OpenReader(&sub), do)
			if err != nil {
				t.Fatalf("the sub-trace does not read: %v", err)
			}
			full, _, _, err := events(ctx, f, do)
			if err != nil {
				t.Fatal(err)
			}
			if !damaged && fmt.Sprint(subSum.Transactions) != fmt.Sprint(full.Transactions) {
				t.Errorf("sub-trace transactions %v, trace %v", subSum.Transactions, full.Transactions)
			}
		})
	}
}

// TestChaosCancel cancels passes at random points: each ends with the
// context's error, never a panic or a partial success.
func TestChaosCancel(t *testing.T) {
	for _, seed := range chaosSeeds(t)[:min(30, len(chaosSeeds(t)))] {
		t.Run(fmt.Sprint(seed), func(t *testing.T) {
			t.Parallel()
			rng := rand.New(rand.NewPCG(uint64(seed), 0xCA9C))
			data := chaosTrace(t, rng)
			stopAt := 1 + rng.IntN(20)
			ctx, cancel := context.WithCancel(context.Background())
			defer cancel()
			n := 0
			_, err := trace.Analyze(ctx, trace.OpenReader(bytes.NewReader(data)), trace.Options{}, trace.SinkFunc(func(*model.Event) error {
				if n++; n == stopAt {
					cancel()
				}
				return nil
			}))
			if n >= stopAt && !errors.Is(err, context.Canceled) {
				t.Errorf("cancelled after %d events: %v", n, err)
			}
			if n < stopAt && err != nil {
				t.Errorf("%d events: %v", n, err)
			}
		})
	}
}

// TestConcurrentUse runs every kind of pass on one File from many
// goroutines at once (run it with -race): a File, Frames and the passes are
// safe for concurrent use and give the same results as one at a time.
func TestConcurrentUse(t *testing.T) {
	rng := rand.New(rand.NewPCG(42, 1))
	data := chaosTrace(t, rng)
	path := filepath.Join(t.TempDir(), "c.pcap")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	f, err := trace.Open(path)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	_, evs, want, err := events(ctx, f, trace.Options{})
	if err != nil {
		t.Fatal(err)
	}
	var refs []model.FrameRef
	for _, e := range evs {
		if e.Txn != nil && e.Txn.Request != nil {
			refs = append(refs, e.Txn.Request.Refs...)
		}
	}
	var wg sync.WaitGroup
	for g := range 16 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			switch g % 4 {
			case 0:
				if _, _, got, err := events(ctx, f, trace.Options{}); err != nil || !bytes.Equal(got, want) {
					t.Errorf("goroutine %d: analysis differs (%v)", g, err)
				}
			case 1:
				if frs, err := f.Frames(refs); err != nil || len(frs) != len(refs) {
					t.Errorf("goroutine %d: %d frames of %d, %v", g, len(frs), len(refs), err)
				}
			case 2:
				var b bytes.Buffer
				if _, err := mbcapexport.Export(ctx, f, trace.Options{}, mbcapexport.Options{Producer: "c"}, func(h capture.Header) (capture.Writer, error) {
					return mbcap.NewWriter(&b, h, nil)
				}); err != nil {
					t.Errorf("goroutine %d: %v", g, err)
				}
			case 3:
				if _, _, err := trace.Scan(ctx, f, trace.ScanOptions{}); err != nil {
					t.Errorf("goroutine %d: %v", g, err)
				}
			}
		}()
	}
	wg.Wait()

	// A stream is read by exactly one of the passes that race for it.
	s := trace.OpenReader(bytes.NewReader(data))
	var ok, consumed int
	var mu sync.Mutex
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			_, _, err := trace.Scan(ctx, s, trace.ScanOptions{})
			mu.Lock()
			defer mu.Unlock()
			switch {
			case err == nil:
				ok++
			case errors.Is(err, trace.ErrConsumed):
				consumed++
			default:
				t.Error(err)
			}
		}()
	}
	wg.Wait()
	if ok != 1 || consumed != 7 {
		t.Errorf("%d passes read the stream, %d were refused", ok, consumed)
	}
}
