// SPDX-License-Identifier: MIT

// Package tracetest builds synthetic packet traces with a known ground
// truth, for the tests of this module and of the applications built on it.
//
// A Builder writes a classic pcap or pcapng stream (optionally gzip) as it
// goes, so a trace of any size can be produced without being held in
// memory. Connections are scripted: each Write sends Modbus ADUs (or raw
// bytes) in one direction, segmented by a policy and with optional faults
// (loss, retransmission, conflicting overlap, reordering, duplicates on a
// second interface, snap-length truncation, IP fragmentation). Every ADU
// written is recorded in the Truth with its fate, and the TCP conditions a
// correct reassembler must report are counted there too.
package tracetest

import (
	"compress/gzip"
	"encoding/binary"
	"fmt"
	"io"
	"net/netip"
	"time"

	"github.com/otfabric/go-modbus-trace/internal/pcapio"
)

// Format is the file format to write.
type Format int

// Formats.
const (
	Pcap     Format = iota // classic pcap, microseconds, little endian
	PcapNano               // classic pcap, nanoseconds
	PcapBE                 // classic pcap, microseconds, big endian
	PcapNG                 // pcapng, little endian
	PcapNGBE               // pcapng, big endian
)

// Link is the link-layer framing of an interface.
type Link int

// Links.
const (
	Ethernet     Link = iota // Ethernet II
	EthernetVLAN             // Ethernet with one 802.1Q tag
	EthernetQinQ             // Ethernet with an 802.1ad and an 802.1Q tag
	Null                     // BSD loopback (link type 0, family in little endian)
	Loop                     // OpenBSD loopback (link type 108, family in big endian)
	Raw                      // raw IP (link type 101)
	IPv4Link                 // link type 228
	IPv6Link                 // link type 229
	SLL                      // Linux cooked v1 (113)
	SLL2                     // Linux cooked v2 (276)
)

// LinkType returns the LINKTYPE_ value of l.
func (l Link) LinkType() uint16 {
	switch l {
	case Null:
		return 0
	case Loop:
		return 108
	case Raw:
		return 101
	case IPv4Link:
		return 228
	case IPv6Link:
		return 229
	case SLL:
		return 113
	case SLL2:
		return 276
	default:
		return 1
	}
}

// Iface is one capture interface (pcapng; classic pcap uses the first).
type Iface struct {
	Link    Link
	TSResol byte // pcapng if_tsresol, decimal 0..9; 0 means 6
	Name    string
}

// Options configure a Builder.
type Options struct {
	Format     Format
	Gzip       bool
	Interfaces []Iface        // default: one Ethernet interface
	Start      time.Time      // time of the first packet; default 2026-10-15T08:00:00Z
	Step       time.Duration  // time between packets; default 100µs
	SnapLen    uint32         // cut every packet to this length (0: none)
	CountOnly  bool           // keep the truth's counters but not its list of ADUs (for long streams)
	Section    pcapio.Section // pcapng section header options
}

// Builder writes a synthetic trace.
type Builder struct {
	o      Options
	gz     *gzip.Writer
	pcap   *pcapio.PcapWriter
	ng     *pcapio.NgWriter
	now    int64
	err    error
	truth  Truth
	frames uint64
	ipID   uint16
	conns  int
}

// New starts a trace written to w.
func New(w io.Writer, o Options) (*Builder, error) {
	if len(o.Interfaces) == 0 {
		o.Interfaces = []Iface{{Link: Ethernet}}
	}
	if o.Start.IsZero() {
		o.Start = time.Date(2026, 10, 15, 8, 0, 0, 0, time.UTC)
	}
	if o.Step == 0 {
		o.Step = 100 * time.Microsecond
	}
	b := &Builder{o: o, now: o.Start.UnixNano()}
	if o.Gzip {
		b.gz = gzip.NewWriter(w)
		w = b.gz
	}
	var err error
	switch o.Format {
	case Pcap, PcapNano, PcapBE:
		b.pcap, err = pcapio.NewPcapWriter(w, pcapio.PcapOptions{LinkType: o.Interfaces[0].Link.LinkType(),
			SnapLen: o.SnapLen, Nanos: o.Format == PcapNano, BigEndian: o.Format == PcapBE})
	case PcapNG, PcapNGBE:
		s := o.Section
		s.BigEndian = o.Format == PcapNGBE
		var ifs []pcapio.Interface
		for _, f := range o.Interfaces {
			ifs = append(ifs, pcapio.Interface{LinkType: f.Link.LinkType(), TSResol: f.TSResol, Name: f.Name, SnapLen: o.SnapLen})
		}
		b.ng, err = pcapio.NewNgWriter(w, s, ifs)
	default:
		err = fmt.Errorf("tracetest: unknown format %d", o.Format)
	}
	if err != nil {
		return nil, err
	}
	return b, nil
}

// Close flushes the trace. It returns the first error of any write.
func (b *Builder) Close() error {
	if b.err == nil {
		if b.pcap != nil {
			b.err = b.pcap.Flush()
		} else {
			b.err = b.ng.Flush()
		}
	}
	if b.gz != nil {
		if err := b.gz.Close(); b.err == nil {
			b.err = err
		}
	}
	return b.err
}

// Err returns the first write error, if any.
func (b *Builder) Err() error { return b.err }

// Truth returns the ground truth so far.
func (b *Builder) Truth() *Truth { return &b.truth }

// Now returns the time the next packet gets.
func (b *Builder) Now() time.Time { return time.Unix(0, b.now).UTC() }

// Advance moves the clock; a negative duration makes a clock jump back.
func (b *Builder) Advance(d time.Duration) { b.now += int64(d) }

// Frames returns the number of packet records written.
func (b *Builder) Frames() uint64 { return b.frames }

// Packet writes one raw packet (link-layer bytes) on an interface.
func (b *Builder) Packet(iface int, data []byte) {
	b.packet(iface, data)
}

func (b *Builder) packet(iface int, data []byte) {
	if b.err != nil {
		return
	}
	orig := uint32(len(data))
	if b.o.SnapLen != 0 && uint32(len(data)) > b.o.SnapLen {
		data = data[:b.o.SnapLen]
	}
	b.write(iface, orig, data)
}

func (b *Builder) write(iface int, orig uint32, data []byte) {
	if b.err != nil {
		return
	}
	b.frames++
	b.truth.Packets++
	if b.pcap != nil {
		b.err = b.pcap.WritePacket(b.now, orig, data)
	} else {
		b.err = b.ng.WritePacket(uint32(iface), b.now, orig, data)
	}
	b.now += int64(b.o.Step)
}

// SimplePacket writes a pcapng Simple Packet Block (interface 0, no time).
func (b *Builder) SimplePacket(data []byte) {
	if b.err != nil || b.ng == nil {
		return
	}
	b.frames++
	b.truth.Packets++
	b.err = b.ng.WriteSimplePacket(0, data)
}

// InterfaceDrops writes a pcapng Interface Statistics Block reporting drops.
func (b *Builder) InterfaceDrops(iface int, drops uint64) {
	if b.err != nil || b.ng == nil {
		return
	}
	b.err = b.ng.WriteInterfaceStats(uint32(iface), pcapio.InterfaceStats{TimeNS: b.now, IfDrop: &drops})
}

// Block writes an arbitrary pcapng block (for unknown-block tests).
func (b *Builder) Block(typ uint32, body []byte) {
	if b.err != nil || b.ng == nil {
		return
	}
	b.err = b.ng.WriteBlock(typ, body)
}

// wrap puts an IP datagram into the link framing of an interface.
func (b *Builder) wrap(iface int, ip []byte, v6 bool) []byte {
	l := b.o.Interfaces[iface].Link
	ether := uint16(0x0800)
	if v6 {
		ether = 0x86DD
	}
	var h []byte
	switch l {
	case Ethernet, EthernetVLAN, EthernetQinQ:
		h = []byte{0x02, 0, 0, 0, 0, 2, 0x02, 0, 0, 0, 0, 1}
		if l == EthernetQinQ {
			h = append(h, 0x88, 0xa8, 0x00, 0x64)
		}
		if l != Ethernet {
			h = append(h, 0x81, 0x00, 0x00, 0x0a)
		}
		h = binary.BigEndian.AppendUint16(h, ether)
	case Null:
		fam := uint32(2)
		if v6 {
			fam = 30
		}
		h = binary.LittleEndian.AppendUint32(nil, fam)
	case Loop:
		fam := uint32(2)
		if v6 {
			fam = 24
		}
		h = binary.BigEndian.AppendUint32(nil, fam)
	case SLL:
		h = []byte{0, 0, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0}
		h = binary.BigEndian.AppendUint16(h, ether)
	case SLL2:
		h = binary.BigEndian.AppendUint16(nil, ether)
		h = append(h, 0, 0)
		h = binary.BigEndian.AppendUint32(h, 3) // interface index
		h = append(h, 0, 1, 0, 6, 2, 0, 0, 0, 0, 1, 0, 0)
	case Raw, IPv4Link, IPv6Link:
	}
	out := append(h, ip...)
	if l == Ethernet || l == EthernetVLAN || l == EthernetQinQ {
		for len(out) < 60 {
			out = append(out, 0) // Ethernet padding must not become data
		}
	}
	return out
}

// ipPacket builds an IPv4 or IPv6 header around a transport payload.
func (b *Builder) ipPacket(src, dst netip.Addr, proto uint8, payload []byte) []byte {
	b.ipID++
	if src.Is4() {
		ip := make([]byte, 20, 20+len(payload))
		ip[0], ip[8], ip[9] = 0x45, 64, proto
		binary.BigEndian.PutUint16(ip[2:], uint16(20+len(payload)))
		binary.BigEndian.PutUint16(ip[4:], b.ipID)
		ip[6] = 0x40 // don't fragment
		s, d := src.As4(), dst.As4()
		copy(ip[12:], s[:])
		copy(ip[16:], d[:])
		return append(ip, payload...)
	}
	ip := make([]byte, 40, 40+len(payload))
	ip[0], ip[6], ip[7] = 0x60, proto, 64
	binary.BigEndian.PutUint16(ip[4:], uint16(len(payload)))
	s, d := src.As16(), dst.As16()
	copy(ip[8:], s[:])
	copy(ip[24:], d[:])
	return append(ip, payload...)
}

// fragments splits a transport payload into IP fragments of at most size
// payload bytes (a multiple of 8), as complete IP packets.
func (b *Builder) fragments(src, dst netip.Addr, proto uint8, payload []byte, size int) [][]byte {
	b.ipID++
	size &^= 7
	var out [][]byte
	for off := 0; off < len(payload); off += size {
		end := min(off+size, len(payload))
		more := end < len(payload)
		if src.Is4() {
			ip := make([]byte, 20)
			ip[0], ip[8], ip[9] = 0x45, 64, proto
			binary.BigEndian.PutUint16(ip[2:], uint16(20+end-off))
			binary.BigEndian.PutUint16(ip[4:], b.ipID)
			fo := uint16(off / 8)
			if more {
				fo |= 0x2000
			}
			binary.BigEndian.PutUint16(ip[6:], fo)
			s, d := src.As4(), dst.As4()
			copy(ip[12:], s[:])
			copy(ip[16:], d[:])
			out = append(out, append(ip, payload[off:end]...))
			continue
		}
		ip := make([]byte, 48)
		ip[0], ip[6], ip[7] = 0x60, 44, 64
		binary.BigEndian.PutUint16(ip[4:], uint16(8+end-off))
		s, d := src.As16(), dst.As16()
		copy(ip[8:], s[:])
		copy(ip[24:], d[:])
		ip[40] = proto
		fo := uint16(off/8) << 3
		if more {
			fo |= 1
		}
		binary.BigEndian.PutUint16(ip[42:], fo)
		binary.BigEndian.PutUint32(ip[44:], 0x10000+uint32(b.ipID))
		out = append(out, append(ip, payload[off:end]...))
	}
	return out
}

// UDP writes one UDP datagram (for "not TCP" counters).
func (b *Builder) UDP(iface int, src, dst netip.AddrPort, payload []byte) {
	u := binary.BigEndian.AppendUint16(nil, src.Port())
	u = binary.BigEndian.AppendUint16(u, dst.Port())
	u = binary.BigEndian.AppendUint16(u, uint16(8+len(payload)))
	u = append(u, 0, 0)
	u = append(u, payload...)
	b.packet(iface, b.wrap(iface, b.ipPacket(src.Addr(), dst.Addr(), 17, u), src.Addr().Is6()))
}

// IPProto writes an IP packet of any protocol (tunnels, IPsec, ICMP).
func (b *Builder) IPProto(iface int, src, dst netip.Addr, proto uint8, payload []byte) {
	b.packet(iface, b.wrap(iface, b.ipPacket(src, dst, proto, payload), src.Is6()))
}

// ARP writes an Ethernet ARP frame on an Ethernet interface.
func (b *Builder) ARP(iface int) {
	f := []byte{0xff, 0xff, 0xff, 0xff, 0xff, 0xff, 0x02, 0, 0, 0, 0, 1, 0x08, 0x06}
	b.packet(iface, append(f, make([]byte, 46)...))
}
