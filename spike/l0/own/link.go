// SPDX-License-Identifier: MIT

package own

import (
	"encoding/binary"
	"net/netip"
)

// Segment is the TCP part of a packet.
type Segment struct {
	Src, Dst netip.AddrPort
	Seq, Ack uint32
	Flags    byte
	Payload  []byte
	PayOff   int // payload offset within the packet's Data
}

// TCP flags.
const (
	FIN = 0x01
	SYN = 0x02
	RST = 0x04
	PSH = 0x08
	ACK = 0x10
)

// Drop reasons (counted, never silent).
const (
	OK = iota
	Short
	LinkUnsupported
	NotIP
	NotTCP
	Fragment
	ExtHeaders
	numReasons
)

// ParseTCP decodes link, IP and TCP headers. No checksum is checked.
func ParseTCP(link uint16, b []byte, s *Segment) int {
	orig := b
	ether := uint16(0)
	switch link {
	case 1: // Ethernet
		if len(b) < 14 {
			return Short
		}
		ether, b = binary.BigEndian.Uint16(b[12:]), b[14:]
		for ether == 0x8100 || ether == 0x88a8 {
			if len(b) < 4 {
				return Short
			}
			ether, b = binary.BigEndian.Uint16(b[2:]), b[4:]
		}
	case 0, 108: // BSD loopback: 4-byte family in host or network order
		if len(b) < 4 {
			return Short
		}
		fam := binary.LittleEndian.Uint32(b)
		if fam > 0xFFFF {
			fam = binary.BigEndian.Uint32(b)
		}
		b = b[4:]
		switch fam {
		case 2:
			ether = 0x0800
		case 24, 28, 30:
			ether = 0x86DD
		default:
			return NotIP
		}
	case 101, 228, 229: // raw IP
	case 113: // SLL
		if len(b) < 16 {
			return Short
		}
		ether, b = binary.BigEndian.Uint16(b[14:]), b[16:]
	case 276: // SLL2
		if len(b) < 20 {
			return Short
		}
		ether, b = binary.BigEndian.Uint16(b[0:]), b[20:]
	default:
		return LinkUnsupported
	}
	if ether == 0 && len(b) > 0 {
		switch b[0] >> 4 {
		case 4:
			ether = 0x0800
		case 6:
			ether = 0x86DD
		}
	}
	var src, dst netip.Addr
	switch ether {
	case 0x0800:
		if len(b) < 20 {
			return Short
		}
		ihl := int(b[0]&0x0F) * 4
		total := int(binary.BigEndian.Uint16(b[2:]))
		if ihl < 20 || total < ihl || len(b) < ihl {
			return Short
		}
		if binary.BigEndian.Uint16(b[6:])&0x3FFF != 0 {
			return Fragment
		}
		if b[9] != 6 {
			return NotTCP
		}
		src, dst = netip.AddrFrom4([4]byte(b[12:16])), netip.AddrFrom4([4]byte(b[16:20]))
		b = b[ihl:min(total, len(b))] // trims Ethernet padding
	case 0x86DD:
		if len(b) < 40 {
			return Short
		}
		plen := int(binary.BigEndian.Uint16(b[4:]))
		next := b[6]
		src, dst = netip.AddrFrom16([16]byte(b[8:24])), netip.AddrFrom16([16]byte(b[24:40]))
		b = b[40:min(40+plen, len(b))]
		for i := 0; next != 6; i++ {
			switch next {
			case 0, 43, 60:
				if i == 8 || len(b) < 8 {
					return ExtHeaders
				}
				n := 8 + int(b[1])*8
				if len(b) < n {
					return Short
				}
				next, b = b[0], b[n:]
			case 44:
				return Fragment
			default:
				return NotTCP
			}
		}
	default:
		return NotIP
	}
	if len(b) < 20 {
		return Short
	}
	off := int(b[12]>>4) * 4
	if off < 20 || len(b) < off {
		return Short
	}
	*s = Segment{
		Src:     netip.AddrPortFrom(src, binary.BigEndian.Uint16(b[0:])),
		Dst:     netip.AddrPortFrom(dst, binary.BigEndian.Uint16(b[2:])),
		Seq:     binary.BigEndian.Uint32(b[4:]),
		Ack:     binary.BigEndian.Uint32(b[8:]),
		Flags:   b[13],
		Payload: b[off:],
	}
	s.PayOff = cap(orig) - cap(s.Payload) // every slice above cuts from the front
	return OK
}
