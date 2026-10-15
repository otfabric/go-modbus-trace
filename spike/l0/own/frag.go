// SPDX-License-Identifier: MIT

package own

import (
	"encoding/binary"
	"net/netip"
	"sort"
)

// FragKey identifies one IP datagram being reassembled (IPv4: 16-bit ID and
// protocol; IPv6: 32-bit ID from the Fragment header).
type FragKey struct {
	Src, Dst netip.Addr
	ID       uint32
	Proto    uint8
}

type part struct {
	off  int
	data []byte
}

type datagram struct {
	parts []part
	total int // -1 until the last fragment is seen
	size  int // bytes buffered
}

// Defrag reassembles IP fragments within a total byte budget. When the
// budget is exceeded the oldest datagram is dropped and counted.
type Defrag struct {
	Max     int
	used    int
	m       map[FragKey]*datagram
	order   []FragKey
	Dropped int64
}

// NewDefrag returns a reassembler with a total budget of max bytes.
func NewDefrag(max int) *Defrag { return &Defrag{Max: max, m: map[FragKey]*datagram{}} }

// Add stores one fragment (offset in bytes) and returns the whole payload
// once every byte is present. Overlaps: the first data wins.
func (f *Defrag) Add(k FragKey, off int, more bool, data []byte) ([]byte, bool) {
	if off+len(data) > 65535 {
		f.Dropped++
		return nil, false
	}
	d := f.m[k]
	if d == nil {
		d = &datagram{total: -1}
		f.m[k] = d
		f.order = append(f.order, k)
	}
	if !more {
		d.total = off + len(data)
	}
	d.parts = append(d.parts, part{off, append([]byte(nil), data...)})
	d.size += len(data)
	f.used += len(data)
	for f.used > f.Max && len(f.order) > 0 {
		f.drop(f.order[0])
		f.Dropped++
	}
	if f.m[k] == nil || d.total < 0 {
		return nil, false
	}
	sort.SliceStable(d.parts, func(i, j int) bool { return d.parts[i].off < d.parts[j].off })
	out := make([]byte, d.total)
	have := 0
	for _, p := range d.parts {
		if p.off > have {
			return nil, false // hole
		}
		if end := p.off + len(p.data); end > have {
			copy(out[have:], p.data[have-p.off:])
			have = min(end, d.total)
		}
	}
	if have < d.total {
		return nil, false
	}
	f.drop(k)
	return out, true
}

func (f *Defrag) drop(k FragKey) {
	if d := f.m[k]; d != nil {
		f.used -= d.size
		delete(f.m, k)
	}
	for i, o := range f.order {
		if o == k {
			f.order = append(f.order[:i], f.order[i+1:]...)
			break
		}
	}
}

// IPv4Frag returns the key, offset and more-fragments flag of an IPv4 header.
func IPv4Frag(ip []byte) (FragKey, int, bool) {
	fo := binary.BigEndian.Uint16(ip[6:])
	return FragKey{Src: netip.AddrFrom4([4]byte(ip[12:16])), Dst: netip.AddrFrom4([4]byte(ip[16:20])),
		ID: uint32(binary.BigEndian.Uint16(ip[4:])), Proto: ip[9]}, int(fo&0x1FFF) * 8, fo&0x2000 != 0
}

// IPv6Frag parses an IPv6 Fragment extension header (8 bytes).
func IPv6Frag(src, dst netip.Addr, h []byte) (FragKey, uint8, int, bool) {
	fo := binary.BigEndian.Uint16(h[2:])
	return FragKey{Src: src, Dst: dst, ID: binary.BigEndian.Uint32(h[4:])}, h[0], int(fo>>3) * 8, fo&1 != 0
}
