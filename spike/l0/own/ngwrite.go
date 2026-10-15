// SPDX-License-Identifier: MIT

package own

import (
	"bufio"
	"encoding/binary"
	"io"
)

// Iface describes an output interface.
type Iface struct {
	Link    uint16
	Snap    uint32
	TSResol byte // pcapng if_tsresol; 6 = µs, 9 = ns
	Name    string
}

// NgWriter writes pcapng: one section, interfaces, Enhanced Packet Blocks.
type NgWriter struct {
	w      *bufio.Writer
	units  []uint64
	hdr    [28]byte
	scrach []byte
}

func opt(b []byte, code uint16, v []byte) []byte {
	b = binary.LittleEndian.AppendUint16(b, code)
	b = binary.LittleEndian.AppendUint16(b, uint16(len(v)))
	b = append(b, v...)
	return append(b, make([]byte, (4-len(v)%4)%4)...)
}

func block(b []byte, typ uint32, body []byte) []byte {
	n := uint32(12 + len(body))
	b = binary.LittleEndian.AppendUint32(b, typ)
	b = binary.LittleEndian.AppendUint32(b, n)
	b = append(b, body...)
	return binary.LittleEndian.AppendUint32(b, n)
}

// NewNgWriter writes the section header (application and comment) and the
// interfaces.
func NewNgWriter(w io.Writer, app, comment string, ifaces []Iface) (*NgWriter, error) {
	nw := &NgWriter{w: bufio.NewWriterSize(w, 1<<20)}
	body := binary.LittleEndian.AppendUint32(nil, 0x1A2B3C4D)
	body = binary.LittleEndian.AppendUint16(body, 1)
	body = binary.LittleEndian.AppendUint16(body, 0)
	body = binary.LittleEndian.AppendUint64(body, 0xFFFFFFFFFFFFFFFF)
	body = opt(body, 1, []byte(comment)) // opt_comment
	body = opt(body, 4, []byte(app))     // shb_userappl
	body = opt(body, 0, nil)
	b := block(nil, 0x0A0D0D0A, body)
	for _, f := range ifaces {
		body = binary.LittleEndian.AppendUint16(body[:0], f.Link)
		body = binary.LittleEndian.AppendUint16(body, 0)
		body = binary.LittleEndian.AppendUint32(body, f.Snap)
		if f.Name != "" {
			body = opt(body, 2, []byte(f.Name))
		}
		body = opt(body, 9, []byte{f.TSResol})
		body = opt(body, 0, nil)
		b = block(b, 1, body)
		nw.units = append(nw.units, pow10(f.TSResol))
	}
	_, err := nw.w.Write(b)
	return nw, err
}

// WritePacket writes one packet with a UTC nanosecond timestamp.
func (nw *NgWriter) WritePacket(iface uint32, timeNS int64, origLen uint32, data []byte) error {
	u := nw.units[iface]
	ts := uint64(timeNS) / (1e9 / u) // resolutions up to ns, decimal
	pad := (4 - len(data)%4) % 4
	n := uint32(32 + len(data) + pad)
	h := nw.hdr[:]
	binary.LittleEndian.PutUint32(h[0:], 6)
	binary.LittleEndian.PutUint32(h[4:], n)
	binary.LittleEndian.PutUint32(h[8:], iface)
	binary.LittleEndian.PutUint32(h[12:], uint32(ts>>32))
	binary.LittleEndian.PutUint32(h[16:], uint32(ts))
	binary.LittleEndian.PutUint32(h[20:], uint32(len(data)))
	binary.LittleEndian.PutUint32(h[24:], origLen)
	nw.w.Write(h)
	nw.w.Write(data)
	var tail [8]byte
	binary.LittleEndian.PutUint32(tail[pad:], n)
	_, err := nw.w.Write(tail[:pad+4])
	return err
}

// Flush flushes buffered output.
func (nw *NgWriter) Flush() error { return nw.w.Flush() }
