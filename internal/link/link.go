// SPDX-License-Identifier: MIT

// Package link decodes the link, IP and TCP headers of a captured packet
// into a TCP segment. It is headers only and bounds-checked, never checks a
// checksum (captures taken on the sending host show unverified checksums),
// reassembles IPv4 and IPv6 fragments within a byte budget, and counts every
// packet it cannot use by reason.
package link

import (
	"encoding/binary"
	"net/netip"
)

// Link types (LINKTYPE_ values).
const (
	LinkNull     = 0   // BSD loopback, family in host byte order
	LinkEthernet = 1   //
	LinkRaw      = 101 // raw IP, version from the first nibble
	LinkLoop     = 108 // OpenBSD loopback, family in network byte order
	LinkSLL      = 113 // Linux cooked capture v1
	LinkIPv4     = 228
	LinkIPv6     = 229
	LinkSLL2     = 276 // Linux cooked capture v2
)

// LinkName returns a short name for a link type.
func LinkName(lt uint16) string {
	switch lt {
	case LinkNull:
		return "null"
	case LinkEthernet:
		return "ethernet"
	case LinkRaw:
		return "raw"
	case LinkLoop:
		return "loop"
	case LinkSLL:
		return "linux_sll"
	case LinkIPv4:
		return "ipv4"
	case LinkIPv6:
		return "ipv6"
	case LinkSLL2:
		return "linux_sll2"
	default:
		return "other"
	}
}

// Reason says why a packet did not yield a segment.
type Reason uint8

// Reasons. OK and FragmentHeld are not drops.
const (
	OK              Reason = iota
	FragmentHeld           // an IP fragment, kept until its datagram is complete
	LinkUnsupported        // a link type this package does not decode
	NotIP                  // ARP, LLDP, other EtherTypes and address families
	NotTCP                 // UDP, ICMP and other IP protocols
	Tunnel                 // IP-in-IP, GRE, VXLAN: counted, never opened
	IPsec                  // AH, ESP
	Short                  // headers cut short by the snap length or damaged
	BadHeader              // an impossible header length or version
	ExtHeaders             // too many IPv6 extension headers
	FragmentBad            // a fragment that cannot belong to a valid datagram
	NumReasons
)

var reasonNames = [NumReasons]string{"ok", "fragment_held", "link_unsupported", "not_ip", "not_tcp", "tunnel", "ipsec",
	"short", "bad_header", "ipv6_ext_headers", "fragment_bad"}

func (r Reason) String() string {
	if r < NumReasons {
		return reasonNames[r]
	}
	return "unknown"
}

// TCP flags.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// Segment is the TCP part of a packet. Payload points into the packet's
// data, or into the reassembled datagram for IP fragments.
type Segment struct {
	Src, Dst netip.AddrPort
	Seq, Ack uint32
	Flags    uint8
	Window   uint16
	Payload  []byte
	PayOff   int    // offset of Payload in the packet's data; -1 after IP reassembly
	Missing  uint32 // payload bytes the snap length cut off (the IP length says more)
	IfIndex  int32  // interface index from a Linux cooked header, -1 if none
	IPv6     bool
}

// MaxExtHeaders bounds the IPv6 extension header walk.
const MaxExtHeaders = 8

// Decoder decodes packets. It is not safe for concurrent use.
type Decoder struct {
	frag   *Defrag
	Counts [NumReasons]uint64
}

// NewDecoder returns a decoder whose fragment reassembly holds at most
// fragBudget bytes.
func NewDecoder(fragBudget int) *Decoder {
	return &Decoder{frag: NewDefrag(fragBudget)}
}

// Defrag returns the decoder's fragment reassembler (for its counters).
func (d *Decoder) Defrag() *Defrag { return d.frag }

// Decode decodes one packet of the given link type into s.
func (d *Decoder) Decode(linkType uint16, data []byte, s *Segment) Reason {
	r := d.decode(linkType, data, s)
	d.Counts[r]++
	return r
}

func (d *Decoder) decode(linkType uint16, b []byte, s *Segment) Reason {
	orig := b
	ether := uint16(0)
	ifIndex := int32(-1)
	switch linkType {
	case LinkEthernet:
		if len(b) < 14 {
			return Short
		}
		ether, b = binary.BigEndian.Uint16(b[12:]), b[14:]
		for ether == 0x8100 || ether == 0x88a8 || ether == 0x9100 {
			if len(b) < 4 {
				return Short
			}
			ether, b = binary.BigEndian.Uint16(b[2:]), b[4:]
		}
	case LinkNull, LinkLoop:
		if len(b) < 4 {
			return Short
		}
		fam := binary.BigEndian.Uint32(b)
		if linkType == LinkNull && fam > 0xFFFF {
			fam = binary.LittleEndian.Uint32(b)
		}
		b = b[4:]
		switch fam {
		case 2:
			ether = 0x0800
		case 10, 24, 28, 30: // AF_INET6 on Linux, NetBSD/OpenBSD, FreeBSD, macOS
			ether = 0x86DD
		default:
			return NotIP
		}
	case LinkRaw:
	case LinkIPv4:
		ether = 0x0800
	case LinkIPv6:
		ether = 0x86DD
	case LinkSLL:
		if len(b) < 16 {
			return Short
		}
		ether, b = binary.BigEndian.Uint16(b[14:]), b[16:]
	case LinkSLL2:
		if len(b) < 20 {
			return Short
		}
		ether, ifIndex = binary.BigEndian.Uint16(b[0:]), int32(binary.BigEndian.Uint32(b[4:]))
		b = b[20:]
	default:
		return LinkUnsupported
	}
	if ether == 0 {
		if len(b) == 0 {
			return Short
		}
		switch b[0] >> 4 {
		case 4:
			ether = 0x0800
		case 6:
			ether = 0x86DD
		default:
			return NotIP
		}
	}
	var (
		src, dst netip.Addr
		proto    uint8
		missing  int
		payOff   = -1
	)
	switch ether {
	case 0x0800:
		if len(b) < 20 {
			return Short
		}
		if b[0]>>4 != 4 {
			return BadHeader
		}
		ihl := int(b[0]&0x0F) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if ihl < 20 || total < ihl {
			return BadHeader
		}
		if len(b) < ihl {
			return Short
		}
		src, dst, proto = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20])), b[9]
		fo := binary.BigEndian.Uint16(b[6:])
		if fo&0x3FFF != 0 { // more fragments, or a non-zero offset
			if len(b) < total {
				return Short // a cut fragment cannot be reassembled
			}
			k := FragKey{Src: src, Dst: dst, ID: uint32(binary.BigEndian.Uint16(b[4:])), Proto: proto}
			whole, r := d.frag.Add(k, int(fo&0x1FFF)*8, fo&0x2000 != 0, b[ihl:total])
			if r != OK {
				return r
			}
			b = whole
		} else {
			missing = max(0, total-len(b))
			b = b[ihl:min(total, len(b))] // trims Ethernet padding
			payOff = 0
		}
	case 0x86DD:
		if len(b) < 40 {
			return Short
		}
		if b[0]>>4 != 6 {
			return BadHeader
		}
		plen := int(binary.BigEndian.Uint16(b[4:]))
		next := b[6]
		src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		if plen == 0 { // jumbogram or unknown: use what was captured
			plen = len(b) - 40
		}
		missing = max(0, 40+plen-len(b))
		b = b[40:min(40+plen, len(b))]
		payOff = 0
		for i := 0; ; i++ {
			if next == 44 { // Fragment header
				if len(b) < 8 {
					return Short
				}
				if missing > 0 {
					return Short
				}
				fo := binary.BigEndian.Uint16(b[2:])
				k := FragKey{Src: src, Dst: dst, ID: binary.BigEndian.Uint32(b[4:]), Proto: b[0], V6: true}
				whole, r := d.frag.Add(k, int(fo>>3)*8, fo&1 != 0, b[8:])
				if r != OK {
					return r
				}
				next, b, payOff = b[0], whole, -1
				continue
			}
			if !isExtHeader(next) {
				break
			}
			if i == MaxExtHeaders {
				return ExtHeaders
			}
			if len(b) < 8 {
				return Short
			}
			n := 8 + int(b[1])*8
			if next == 51 { // AH: length in 4-byte units
				return IPsec
			}
			if len(b) < n {
				return Short
			}
			next, b = b[0], b[n:]
		}
		proto = next
	default:
		return NotIP
	}
	switch proto {
	case 6:
	case 4, 41, 47:
		return Tunnel
	case 50, 51:
		return IPsec
	case 17:
		if len(b) >= 4 && binary.BigEndian.Uint16(b[2:]) == 4789 {
			return Tunnel // VXLAN
		}
		return NotTCP
	default:
		return NotTCP
	}
	if len(b) < 20 {
		return Short
	}
	off := int(b[12]>>4) * 4
	if off < 20 {
		return BadHeader
	}
	if len(b) < off {
		return Short
	}
	*s = Segment{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(b[0:])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(b[2:])),
		Seq:     binary.BigEndian.Uint32(b[4:]),
		Ack:     binary.BigEndian.Uint32(b[8:]),
		Flags:   b[13],
		Window:  binary.BigEndian.Uint16(b[14:]),
		Payload: b[off:],
		PayOff:  -1,
		Missing: uint32(missing),
		IfIndex: ifIndex,
		IPv6:    ether == 0x86DD,
	}
	if payOff == 0 {
		s.PayOff = cap(orig) - cap(s.Payload) // every slice above cut from the front
	}
	return OK
}

func isExtHeader(n uint8) bool {
	switch n {
	case 0, 43, 51, 60, 135, 139, 140: // hop-by-hop, routing, AH, destination, mobility, HIP, shim6
		return true
	}
	return false
}
