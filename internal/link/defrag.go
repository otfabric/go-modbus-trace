// SPDX-License-Identifier: MIT

package link

import (
	"net/netip"
	"sort"
)

// FragKey identifies one IP datagram being reassembled.
type FragKey struct {
	Src, Dst netip.Addr
	ID       uint32 // IPv4: 16-bit identification; IPv6: Fragment header ID
	Proto    uint8  // IPv4 protocol; IPv6: next header of the fragment header
	V6       bool
}

type part struct {
	off  int
	data []byte
}

type datagram struct {
	parts []part // sorted by offset
	total int    // -1 until the last fragment is seen
	size  int    // bytes charged: data plus overheads
	gen   uint64
}

// Overheads charged against the budget besides the fragment bytes, so tiny
// fragments cannot hold millions of entries within it.
const (
	fragOverhead     = 64
	datagramOverhead = 128
)

type orderKey struct {
	k   FragKey
	gen uint64
}

// Defrag reassembles IPv4 and IPv6 fragments within a total byte budget.
// When the budget is exceeded the oldest incomplete datagram is dropped and
// counted. Overlapping fragments: the bytes of the lower offset win.
type Defrag struct {
	max   int
	used  int
	m     map[FragKey]*datagram
	order []orderKey // oldest first; entries of finished datagrams are skipped lazily
	gen   uint64
	// Counters.
	Datagrams uint64 // datagrams reassembled
	Dropped   uint64 // incomplete datagrams dropped by the budget
	Pending   int    // incomplete datagrams held now
}

// NewDefrag returns a reassembler that holds at most budget bytes.
func NewDefrag(budget int) *Defrag { return &Defrag{max: budget, m: map[FragKey]*datagram{}} }

// Add stores one fragment and returns the reassembled transport payload
// with OK once every byte is there; FragmentHeld while incomplete.
func (f *Defrag) Add(k FragKey, off int, more bool, data []byte) ([]byte, Reason) {
	end := off + len(data)
	if len(data) == 0 || end > 65535 || (more && len(data)%8 != 0) || len(data) > f.max {
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
	case !more:
		d.total = end
	}
	if d.total >= 0 && end > d.total {
		return nil, FragmentBad
	}
	// After the parts with the same offset: the earlier fragment wins.
	i := sort.Search(len(d.parts), func(i int) bool { return d.parts[i].off > off })
	d.parts = append(d.parts, part{})
	copy(d.parts[i+1:], d.parts[i:])
	d.parts[i] = part{off, append([]byte(nil), data...)}
	d.size += len(data) + fragOverhead
	f.used += len(data) + fragOverhead
	for f.used > f.max && len(f.order) > 0 {
		o := f.order[0]
		f.order = f.order[1:]
		if x := f.m[o.k]; x != nil && x.gen == o.gen {
			f.drop(o.k)
			f.Dropped++
		}
	}
	if f.m[k] != d || d.total < 0 {
		return nil, FragmentHeld
	}
	have := 0
	for _, p := range d.parts {
		if p.off > have {
			return nil, FragmentHeld // a hole
		}
		have = max(have, p.off+len(p.data))
	}
	if have < d.total {
		return nil, FragmentHeld
	}
	out := make([]byte, d.total)
	have = 0
	for _, p := range d.parts {
		if e := p.off + len(p.data); e > have {
			copy(out[have:], p.data[have-p.off:])
			have = e
		}
	}
	f.drop(k)
	f.Datagrams++
	return out, OK
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
