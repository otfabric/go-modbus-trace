// SPDX-License-Identifier: MIT

package link

import (
	"net/netip"
)

// FragKey identifies one IP datagram being reassembled.
type FragKey struct {
	Src, Dst netip.Addr
	ID       uint32 // IPv4: 16-bit identification; IPv6: Fragment header ID
	Proto    uint8  // IPv4 protocol; IPv6: next header of the fragment header
	V6       bool
}

// A datagram being reassembled is kept as its bytes so far and, for every
// 8-byte block of it (fragments start on multiples of 8), which fragment
// gave the block. A fragment is copied into the blocks it wins and nothing
// else is kept of it, so a datagram holds at most its own length however
// many fragments, copies and overlaps arrive, and the work of adding a
// fragment is proportional to the fragment's length.
type datagram struct {
	data  []byte   // the bytes so far, up to the furthest one held
	owner []uint16 // per block: the block at which the fragment that gave it starts; free if not held
	held  int      // blocks held
	total int      // -1 until the last fragment is seen
	size  int      // bytes charged: the capacity of data and owner, and datagramOverhead
	gen   uint64
}

const (
	block = 8      // IP fragment offsets count units of 8 bytes
	free  = 0xFFFF // owner of a block that is not held (no fragment starts there: the last block is 8191)
	// datagramOverhead is charged per datagram besides its buffers: what its
	// entry in the map, its entries in the order list (which keeps those of
	// finished datagrams for a while) and the datagram itself take on the
	// heap, measured with first fragments of 8 bytes (TestFragmentBudgetHeap).
	// So tiny fragments cannot hold more memory than the budget says.
	datagramOverhead = 448
)

type orderKey struct {
	k   FragKey
	gen uint64
}

// Defrag reassembles IPv4 and IPv6 fragments within a total byte budget.
// When the budget is exceeded the oldest incomplete datagram is dropped and
// counted. Overlapping fragments: the bytes of the lower offset win, and of
// two fragments with the same offset those of the first one.
type Defrag struct {
	max   int
	used  int
	m     map[FragKey]*datagram
	order []orderKey // oldest first; entries of finished datagrams are skipped lazily
	gen   uint64
	work  uint64 // blocks looked at so far: the work of Add, for the budget tests
	// Counters.
	Datagrams uint64 // datagrams reassembled
	Dropped   uint64 // incomplete datagrams dropped by the budget
	Pending   int    // incomplete datagrams held now
}

// NewDefrag returns a reassembler that holds at most budget bytes.
func NewDefrag(budget int) *Defrag { return &Defrag{max: budget, m: map[FragKey]*datagram{}} }

// Add stores one fragment and returns the reassembled transport payload
// with OK once every byte is there; FragmentHeld while incomplete. The
// returned payload is the caller's.
func (f *Defrag) Add(k FragKey, off int, more bool, data []byte) ([]byte, Reason) {
	end := off + len(data)
	if len(data) == 0 || off < 0 || off%block != 0 || end > 65535 || (more && len(data)%block != 0) || len(data) > f.max {
		return nil, FragmentBad
	}
	d := f.m[k]
	if d == nil {
		f.gen++
		d = &datagram{total: -1, gen: f.gen, size: datagramOverhead}
		f.m[k] = d
		f.order = append(f.order, orderKey{k, f.gen})
		f.used += datagramOverhead
		f.Pending++
	}
	switch {
	case !more && d.total >= 0 && d.total != end:
		return nil, FragmentBad // two different last fragments
	case !more && end < len(d.data):
		return nil, FragmentBad // a last fragment that ends before bytes already held
	case d.total >= 0 && end > d.total:
		return nil, FragmentBad // beyond the last fragment
	case !more:
		d.total = end
	}
	first, last := off/block, (end+block-1)/block // the fragment's blocks; only the datagram's last one can be short
	f.work += uint64(last - first)
	f.grow(d, end, last)
	for b := first; b < last; b++ {
		switch o := d.owner[b]; {
		case o == free:
			d.held++
		case int(o) <= first:
			continue // held from a fragment that starts at or before this one: its bytes stay
		}
		d.owner[b] = uint16(first)
		s := b * block
		copy(d.data[s:min(s+block, end)], data[s-off:])
	}
	for f.used > f.max && len(f.order) > 0 {
		o := f.order[0]
		f.order = f.order[1:]
		if x := f.m[o.k]; x != nil && x.gen == o.gen {
			f.drop(o.k)
			f.Dropped++
		}
	}
	if f.m[k] != d || d.total < 0 || d.held < (d.total+block-1)/block {
		return nil, FragmentHeld // dropped by the budget, no last fragment yet, or a hole
	}
	out := d.data[:d.total]
	f.drop(k)
	f.Datagrams++
	return out, OK
}

// grow makes room in d for bytes up to end and blocks up to blocks, and
// charges the budget what the buffers grow by. Capacity doubles, so growing
// a datagram fragment by fragment copies each byte a bounded number of
// times.
func (f *Defrag) grow(d *datagram, end, blocks int) {
	before := cap(d.data) + 2*cap(d.owner)
	if end > len(d.data) {
		if end > cap(d.data) {
			nd := make([]byte, len(d.data), min(max(end, 2*cap(d.data)), 65535))
			copy(nd, d.data)
			d.data = nd
		}
		d.data = d.data[:end]
	}
	if n := len(d.owner); blocks > n {
		if blocks > cap(d.owner) {
			no := make([]uint16, n, min(max(blocks, 2*cap(d.owner)), 65536/block))
			copy(no, d.owner)
			d.owner = no
		}
		d.owner = d.owner[:blocks]
		for i := n; i < blocks; i++ {
			d.owner[i] = free
		}
	}
	grown := cap(d.data) + 2*cap(d.owner) - before
	d.size += grown
	f.used += grown
}

func (f *Defrag) drop(k FragKey) {
	if d := f.m[k]; d != nil {
		f.used -= d.size
		delete(f.m, k)
		f.Pending--
	}
	if len(f.order) > 2*len(f.m)+64 { // forget finished datagrams
		live := f.order[:0]
		for _, o := range f.order {
			if x := f.m[o.k]; x != nil && x.gen == o.gen {
				live = append(live, o)
			}
		}
		f.order = live
	}
}
