// SPDX-License-Identifier: MIT

// Command framecases writes a pcap (raw IPv4) with one TCP connection per
// MBAP framing case, so that a second implementation (tshark's mbtcp
// dissector) can be asked how it frames each one.
package main

import (
	"bufio"
	"encoding/binary"
	"fmt"
	"os"
)

type step struct {
	toServer bool
	data     []byte
}

func mbap(tid, pid, length uint16, unit byte, pdu ...byte) []byte {
	b := binary.BigEndian.AppendUint16(nil, tid)
	b = binary.BigEndian.AppendUint16(b, pid)
	b = binary.BigEndian.AppendUint16(b, length)
	b = append(b, unit)
	return append(b, pdu...)
}

var read = []byte{0x03, 0x00, 0x00, 0x00, 0x01}
var resp = []byte{0x03, 0x02, 0x12, 0x34}

func cat(bs ...[]byte) []byte {
	var out []byte
	for _, b := range bs {
		out = append(out, b...)
	}
	return out
}

func main() {
	big := make([]byte, 253)
	big[0], big[1] = 0x03, 252 // FC03 response with 252 data bytes: PDU 253 bytes
	over := make([]byte, 254)
	over[0], over[1] = 0x03, 253
	cases := []struct {
		name  string
		steps []step
	}{
		{"01 valid request/response", []step{{true, mbap(1, 0, 6, 1, read...)}, {false, mbap(1, 0, 5, 1, resp...)}}},
		{"02 protocol id 1", []step{{true, mbap(2, 1, 6, 1, read...)}}},
		{"03 length 0", []step{{true, mbap(3, 0, 0, 1)}}},
		{"04 length 1 (unit only)", []step{{true, mbap(4, 0, 1, 1)}}},
		{"05 length 2 (unit + fc)", []step{{true, mbap(5, 0, 2, 1, 0x07)}}},
		{"06 length 254 (PDU 253)", []step{{true, mbap(6, 0, 6, 1, read...)}, {false, mbap(6, 0, 254, 1, big...)}}},
		{"07 length 255 (PDU 254)", []step{{true, mbap(7, 0, 6, 1, read...)}, {false, mbap(7, 0, 255, 1, over...)}}},
		{"08 two ADUs in one segment", []step{{true, cat(mbap(8, 0, 6, 1, read...), mbap(9, 0, 6, 1, read...))}}},
		{"09 header split 3+rest", []step{{true, mbap(10, 0, 6, 1, read...)[:3]}, {true, mbap(10, 0, 6, 1, read...)[3:]}}},
		{"10 length says more than sent", []step{{true, mbap(11, 0, 9, 1, read...)}}},
		{"11 unit 0xFF and unit 0", []step{{true, mbap(12, 0, 6, 0xFF, read...)}, {true, mbap(13, 0, 6, 0, read...)}}},
		{"12 junk then valid", []step{{true, cat([]byte{0xde, 0xad, 0xbe, 0xef, 0x00}, mbap(14, 0, 6, 1, read...))}}},
	}
	w := bufio.NewWriter(os.Stdout)
	defer w.Flush()
	h := binary.LittleEndian.AppendUint32(nil, 0xa1b2c3d4)
	h = binary.LittleEndian.AppendUint16(h, 2)
	h = binary.LittleEndian.AppendUint16(h, 4)
	h = append(h, make([]byte, 8)...)
	h = binary.LittleEndian.AppendUint32(h, 65535)
	h = binary.LittleEndian.AppendUint32(h, 101)
	w.Write(h)
	ts := uint32(0)
	pkt := func(src, dst byte, sp, dp uint16, seq, ack uint32, flags byte, data []byte) {
		b := []byte{0x45, 0, 0, 0, 0, 0, 0x40, 0, 64, 6, 0, 0, 10, 0, 0, src, 10, 0, 0, dst}
		binary.BigEndian.PutUint16(b[2:], uint16(40+len(data)))
		b = binary.BigEndian.AppendUint16(b, sp)
		b = binary.BigEndian.AppendUint16(b, dp)
		b = binary.BigEndian.AppendUint32(b, seq)
		b = binary.BigEndian.AppendUint32(b, ack)
		b = append(b, 0x50, flags, 0xff, 0xff, 0, 0, 0, 0)
		b = append(b, data...)
		ts++
		r := binary.LittleEndian.AppendUint32(nil, 1760515200+ts)
		r = binary.LittleEndian.AppendUint32(r, 0)
		r = binary.LittleEndian.AppendUint32(r, uint32(len(b)))
		r = binary.LittleEndian.AppendUint32(r, uint32(len(b)))
		w.Write(r)
		w.Write(b)
	}
	for i, c := range cases {
		cp := uint16(41000 + i)
		cs, ss := uint32(1000), uint32(5000)
		pkt(1, 2, cp, 502, cs-1, 0, 0x02, nil)
		pkt(2, 1, 502, cp, ss-1, cs, 0x12, nil)
		pkt(1, 2, cp, 502, cs, ss, 0x10, nil)
		for _, s := range c.steps {
			if s.toServer {
				pkt(1, 2, cp, 502, cs, ss, 0x18, s.data)
				cs += uint32(len(s.data))
			} else {
				pkt(2, 1, 502, cp, ss, cs, 0x18, s.data)
				ss += uint32(len(s.data))
			}
		}
		pkt(1, 2, cp, 502, cs, ss, 0x11, nil)
		pkt(2, 1, 502, cp, ss, cs+1, 0x11, nil)
		fmt.Fprintf(os.Stderr, "port %d: %s\n", cp, c.name)
	}
}
