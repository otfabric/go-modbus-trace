// SPDX-License-Identifier: MIT

package link

import (
	"bytes"
	"fmt"
	"math/rand/v2"
	"net/netip"
	"runtime"
	"testing"
)

// model is the reassembly rule written out byte by byte, to compare Defrag
// with: every byte comes from the fragment with the lowest offset that
// covers it, of two with the same offset from the first; the datagram is
// complete when its last fragment is known and no byte is missing.
type model struct {
	val   [65536]byte
	own   [65536]int32 // offset of the fragment that gave the byte; -1: none
	end   int          // end of the furthest byte held
	total int          // -1 until the last fragment is seen
	done  bool
}

func newModel() *model {
	m := &model{total: -1}
	for i := range m.own {
		m.own[i] = -1
	}
	return m
}

func (m *model) add(off int, more bool, data []byte) ([]byte, Reason) {
	end := off + len(data)
	switch {
	case len(data) == 0 || off%8 != 0 || end > 65535 || (more && len(data)%8 != 0):
		return nil, FragmentBad
	case !more && m.total >= 0 && m.total != end, !more && end < m.end, m.total >= 0 && end > m.total:
		return nil, FragmentBad
	case !more:
		m.total = end
	}
	for i, b := range data {
		if x := off + i; m.own[x] < 0 || int32(off) < m.own[x] {
			m.val[x], m.own[x] = b, int32(off)
		}
	}
	m.end = max(m.end, end)
	if m.total < 0 {
		return nil, FragmentHeld
	}
	for x := range m.total {
		if m.own[x] < 0 {
			return nil, FragmentHeld
		}
	}
	m.done = true
	return bytes.Clone(m.val[:m.total]), OK
}

type frag struct {
	off  int
	more bool
	data []byte
}

// randomFragments cuts a datagram of random bytes into fragments in a random
// order, with copies, overlaps of other lengths, overlaps with other bytes,
// and, unless consistent, fragments that contradict the datagram's length.
func randomFragments(rng *rand.Rand, consistent bool) []frag {
	total := 1 + rng.IntN(600)
	if rng.IntN(20) == 0 {
		total = 60000 + rng.IntN(5535)
	}
	body := make([]byte, total)
	for i := range body {
		body[i] = byte(rng.IntN(256))
	}
	piece := func(off, n int, alter bool) frag {
		end := min(off+n, total)
		d := bytes.Clone(body[off:end])
		if alter {
			d[rng.IntN(len(d))] ^= byte(1 + rng.IntN(255))
		}
		return frag{off, end < total, d}
	}
	var fs []frag
	step := 8 * (1 + rng.IntN(6))
	if total > 10000 {
		step = 8 * (40 + rng.IntN(150))
	}
	for off := 0; off < total; off += step {
		if rng.IntN(12) != 0 { // sometimes a fragment is missing
			fs = append(fs, piece(off, step, false))
		}
	}
	for range rng.IntN(1 + len(fs)) { // copies and overlaps
		off := 8 * rng.IntN(1+(total-1)/8)
		fs = append(fs, piece(off, 8*(1+rng.IntN(2*step/8)), rng.IntN(3) == 0))
	}
	if !consistent {
		for range rng.IntN(3) {
			off := 8 * rng.IntN(1+total/8+4)
			more := rng.IntN(2) == 0
			d := make([]byte, 1+rng.IntN(40))
			if more {
				d = make([]byte, 8*(1+rng.IntN(5)))
			}
			fs = append(fs, frag{off, more, d})
		}
	}
	rng.Shuffle(len(fs), func(i, j int) { fs[i], fs[j] = fs[j], fs[i] })
	return fs
}

// TestDefragAgainstModel: for seeded random fragment sequences Defrag gives,
// fragment by fragment, the result of the rule written out byte by byte.
func TestDefragAgainstModel(t *testing.T) {
	k := FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), ID: 7, Proto: 6}
	completed := 0
	for seed := range 1000 {
		rng := rand.New(rand.NewPCG(uint64(seed), 0xF4A6))
		f, m := NewDefrag(1<<20), newModel()
		for i, x := range randomFragments(rng, seed%2 == 0) {
			want, wr := m.add(x.off, x.more, x.data)
			got, gr := f.Add(k, x.off, x.more, x.data)
			if gr != wr || !bytes.Equal(got, want) {
				t.Fatalf("seed %d, fragment %d (offset %d, %d bytes, more %v): %v with %d bytes, the model says %v with %d bytes",
					seed, i, x.off, len(x.data), x.more, gr, len(got), wr, len(want))
			}
			if gr == OK {
				completed++
				break // the datagram is delivered: what follows would start another
			}
		}
		if f.used != f.Pending*datagramOverhead+used(f) {
			t.Fatalf("seed %d: %d bytes charged, the datagrams hold %d", seed, f.used, f.Pending*datagramOverhead+used(f))
		}
	}
	if completed < 150 {
		t.Errorf("only %d datagrams completed: the sequences test little", completed)
	}
}

// used adds up what the pending datagrams' buffers take.
func used(f *Defrag) int {
	n := 0
	for _, d := range f.m {
		n += cap(d.data) + 2*cap(d.owner)
	}
	return n
}

// TestDefragInvalid: fragments that cannot belong to a valid datagram are
// refused, at the boundaries of each rule.
func TestDefragInvalid(t *testing.T) {
	k := FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), ID: 1, Proto: 6}
	b := make([]byte, 65536)
	for _, c := range []struct {
		name  string
		prior []frag
		frag  frag
		want  Reason
	}{
		{"no bytes", nil, frag{0, true, nil}, FragmentBad},
		{"an offset that is not a multiple of 8", nil, frag{4, true, b[:8]}, FragmentBad},
		{"a negative offset", nil, frag{-8, true, b[:8]}, FragmentBad},
		{"not the last fragment, and not a multiple of 8 long", nil, frag{0, true, b[:7]}, FragmentBad},
		{"the last fragment may be any length", nil, frag{8, false, b[:7]}, FragmentHeld},
		{"ends at 65535", nil, frag{65528, false, b[:7]}, FragmentHeld},
		{"ends at 65536", nil, frag{65528, true, b[:8]}, FragmentBad},
		{"a second last fragment with another end", []frag{{16, false, b[:16]}}, frag{8, false, b[:16]}, FragmentBad},
		{"a second last fragment with the same end", []frag{{16, false, b[:16]}}, frag{8, false, b[:24]}, FragmentHeld},
		{"beyond the last fragment", []frag{{16, false, b[:16]}}, frag{32, true, b[:8]}, FragmentBad},
		{"up to the last fragment's end", []frag{{16, false, b[:16]}}, frag{24, true, b[:8]}, FragmentHeld},
		{"a last fragment that ends before bytes already held", []frag{{24, true, b[:8]}}, frag{16, false, b[:8]}, FragmentBad},
		{"a last fragment that ends where the bytes held end", []frag{{24, true, b[:8]}}, frag{16, false, b[:16]}, FragmentHeld},
		{"larger than the budget", nil, frag{0, true, b[:4096]}, FragmentBad},
		{"as large as the budget allows a fragment", nil, frag{0, true, b[:2048]}, FragmentHeld},
	} {
		f := NewDefrag(4095)
		for _, p := range c.prior {
			f.Add(k, p.off, p.more, p.data)
		}
		if _, r := f.Add(k, c.frag.off, c.frag.more, c.frag.data); r != c.want {
			t.Errorf("%s: %v, want %v", c.name, r, c.want)
		}
	}
}

// TestDefragWork: the work of reassembly is proportional to the bytes of the
// fragments, whatever their number, order and overlap, and a datagram never
// holds more than its own length. Each case is a worst one for a reassembler
// that keeps every fragment: its fragments arrive last first (so the length
// is known from the start), in descending order, many times over.
func TestDefragWork(t *testing.T) {
	k := FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), ID: 9, Proto: 6}
	body := make([]byte, 65528)
	for i := range body {
		body[i] = byte(i * 7)
	}
	const (
		budget = 16 << 20
		// One datagram's buffers at their largest: its bytes, two bytes per
		// block, and the overhead.
		perDatagram = 65535 + 2*8192 + datagramOverhead
	)
	for _, c := range []struct {
		name   string
		size   int // bytes per fragment
		copies int // times every fragment but the first arrives
	}{
		{"8-byte fragments, each 30 times", 8, 30},
		{"8-byte fragments, once", 8, 1},
		{"1024-byte fragments, each 300 times", 1024, 300},
		{"every 64th byte to the end of the datagram", 0, 1}, // each fragment reaches the end: all overlap
	} {
		t.Run(c.name, func(t *testing.T) {
			f := NewDefrag(budget)
			var fragments, blocks uint64
			add := func(off, n int) ([]byte, Reason) {
				end := min(off+n, len(body))
				fragments++
				blocks += uint64((end - off + 7) / 8)
				return f.Add(k, off, end < len(body), body[off:end])
			}
			size := c.size
			step := size
			if size == 0 {
				size, step = len(body), 64
			}
			for range c.copies {
				for off := (len(body) - 1) / step * step; off > 0; off -= step {
					if _, r := add(off, size); r != FragmentHeld {
						t.Fatalf("offset %d: %v", off, r)
					}
					if d := f.m[k]; d.size > perDatagram || f.used != d.size {
						t.Fatalf("offset %d: the datagram is charged %d bytes (%d in all), more than a datagram can take (%d)", off, d.size, f.used, perDatagram)
					}
				}
			}
			if out, r := add(0, size); r != OK || !bytes.Equal(out, body) {
				t.Fatalf("the first fragment: %v, %d bytes", r, len(out))
			}
			// Each fragment costs its blocks, once.
			if f.work != blocks {
				t.Errorf("%d fragments of %d blocks in all took %d steps", fragments, blocks, f.work)
			}
			if f.used != 0 || f.Pending != 0 || f.Datagrams != 1 {
				t.Errorf("after the datagram: %d bytes charged, %d pending, %d reassembled", f.used, f.Pending, f.Datagrams)
			}
			t.Logf("%d fragments, %d blocks, %d steps", fragments, blocks, f.work)
		})
	}
}

// liveHeap returns the bytes of live heap objects after a collection.
func liveHeap() uint64 {
	runtime.GC()
	runtime.GC()
	var m runtime.MemStats
	runtime.ReadMemStats(&m)
	return m.HeapAlloc
}

// TestFragmentBudgetHeap: what the reassembler holds is bounded by its
// budget in heap bytes, not only in the bytes it counts. Fragments of
// datagrams that never complete, small ones and ones at the highest offset,
// are fed until many times the budget went through; the live heap stays
// within the budget and a quarter (the map's and the order list's spare
// capacity vary).
func TestFragmentBudgetHeap(t *testing.T) {
	for _, c := range []struct {
		name string
		off  int
		n    int // datagrams
	}{
		{"first fragments of 8 bytes", 0, 400_000},
		{"8 bytes at the highest offset", 65520, 4_000},
	} {
		t.Run(c.name, func(t *testing.T) {
			const budget = 4 << 20
			k := FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), Proto: 6}
			data := make([]byte, 8)
			before := liveHeap()
			f := NewDefrag(budget)
			charged := 0
			for i := range c.n {
				k.ID = uint32(i)
				if _, r := f.Add(k, c.off, true, data); r != FragmentHeld {
					t.Fatalf("datagram %d: %v", i, r)
				}
				if f.used > budget {
					t.Fatalf("datagram %d: %d bytes charged, budget %d", i, f.used, budget)
				}
				if f.Dropped == 0 {
					charged = f.used
				}
			}
			after := liveHeap()
			held := after - min(after, before)
			t.Logf("%d datagrams, %d dropped, %d pending: %d KiB charged, %d KiB live (budget %d KiB)",
				c.n, f.Dropped, f.Pending, f.used>>10, held>>10, budget>>10)
			if f.Dropped == 0 || charged < budget*3/4 {
				t.Errorf("the budget was not reached: %d dropped, %d bytes charged", f.Dropped, charged)
			}
			if held > budget*5/4 {
				t.Errorf("%d bytes live, more than the budget of %d and a quarter", held, budget)
			}
			runtime.KeepAlive(f)
		})
	}
}

func ExampleDefrag() {
	f := NewDefrag(1 << 16)
	k := FragKey{Src: netip.MustParseAddr("10.0.0.1"), Dst: netip.MustParseAddr("10.0.0.2"), ID: 1, Proto: 6}
	_, r := f.Add(k, 8, false, []byte("world"))
	fmt.Println(r)
	out, r := f.Add(k, 0, true, []byte("hello, w"))
	fmt.Println(r, string(out))
	// Output:
	// fragment_held
	// ok hello, wworld
}
