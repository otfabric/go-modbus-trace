// SPDX-License-Identifier: MIT

package pcapio

import (
	"bufio"
	"encoding/binary"
	"errors"
	"fmt"
	"io"
)

// order is a byte order that can also append.
type order interface {
	binary.ByteOrder
	binary.AppendByteOrder
}

// PcapOptions configure a classic pcap writer.
type PcapOptions struct {
	LinkType  uint16
	SnapLen   uint32 // 0: 262144
	Nanos     bool   // nanosecond magic a1b23c4d
	BigEndian bool
}

// PcapWriter writes classic pcap.
type PcapWriter struct {
	w     *bufio.Writer
	bo    order
	nanos bool
	h     [16]byte
}

// NewPcapWriter writes the file header.
func NewPcapWriter(w io.Writer, o PcapOptions) (*PcapWriter, error) {
	pw := &PcapWriter{w: bufio.NewWriterSize(w, 1<<20), bo: binary.LittleEndian, nanos: o.Nanos}
	if o.BigEndian {
		pw.bo = binary.BigEndian
	}
	magic := uint32(0xa1b2c3d4)
	if o.Nanos {
		magic = 0xa1b23c4d
	}
	snap := o.SnapLen
	if snap == 0 {
		snap = 262144
	}
	h := make([]byte, 0, 24)
	h = pw.bo.AppendUint32(h, magic)
	h = pw.bo.AppendUint16(h, 2)
	h = pw.bo.AppendUint16(h, 4)
	h = pw.bo.AppendUint32(h, 0)
	h = pw.bo.AppendUint32(h, 0)
	h = pw.bo.AppendUint32(h, snap)
	h = pw.bo.AppendUint32(h, uint32(o.LinkType))
	_, err := pw.w.Write(h)
	return pw, err
}

// WritePacket writes one record. origLen 0 means len(data).
func (pw *PcapWriter) WritePacket(timeNS int64, origLen uint32, data []byte) error {
	if origLen == 0 {
		origLen = uint32(len(data))
	}
	sub := timeNS % 1e9
	if !pw.nanos {
		sub /= 1000
	}
	pw.bo.PutUint32(pw.h[0:], uint32(timeNS/1e9))
	pw.bo.PutUint32(pw.h[4:], uint32(sub))
	pw.bo.PutUint32(pw.h[8:], uint32(len(data)))
	pw.bo.PutUint32(pw.h[12:], origLen)
	if _, err := pw.w.Write(pw.h[:]); err != nil {
		return err
	}
	_, err := pw.w.Write(data)
	return err
}

// Flush flushes buffered output.
func (pw *PcapWriter) Flush() error { return pw.w.Flush() }

// NgWriter writes pcapng: sections, interfaces, Enhanced and Simple Packet
// Blocks, Interface Statistics Blocks and, for tests, arbitrary blocks.
type NgWriter struct {
	w      *bufio.Writer
	bo     order
	units  []uint64
	scr    []byte
	nIface int
}

// ErrInterface reports a packet for an interface that was not added.
var ErrInterface = errors.New("pcapng: unknown interface")

// NewNgWriter writes a section header and the interfaces.
func NewNgWriter(w io.Writer, s Section, ifaces []Interface) (*NgWriter, error) {
	nw := &NgWriter{w: bufio.NewWriterSize(w, 1<<20)}
	if err := nw.NewSection(s, ifaces); err != nil {
		return nil, err
	}
	return nw, nil
}

func (nw *NgWriter) opt(b []byte, code uint16, v []byte) []byte {
	if len(v) > 0xFFFF {
		v = v[:0xFFFF]
	}
	b = nw.bo.AppendUint16(b, code)
	b = nw.bo.AppendUint16(b, uint16(len(v)))
	b = append(b, v...)
	return append(b, make([]byte, (4-len(v)%4)%4)...)
}

func (nw *NgWriter) strOpt(b []byte, code uint16, v string) []byte {
	if v == "" {
		return b
	}
	return nw.opt(b, code, []byte(v))
}

// WriteBlock writes one block of any type with the given body (padded to 4).
func (nw *NgWriter) WriteBlock(typ uint32, body []byte) error {
	pad := (4 - len(body)%4) % 4
	n := uint32(12 + len(body) + pad)
	b := nw.scr[:0]
	b = nw.bo.AppendUint32(b, typ)
	b = nw.bo.AppendUint32(b, n)
	b = append(b, body...)
	b = append(b, make([]byte, pad)...)
	b = nw.bo.AppendUint32(b, n)
	nw.scr = b
	_, err := nw.w.Write(b)
	return err
}

// NewSection starts a new section; interface IDs start again at 0.
func (nw *NgWriter) NewSection(s Section, ifaces []Interface) error {
	nw.bo = binary.LittleEndian
	if s.BigEndian {
		nw.bo = binary.BigEndian
	}
	body := nw.bo.AppendUint32(nil, 0x1A2B3C4D)
	body = nw.bo.AppendUint16(body, 1)
	body = nw.bo.AppendUint16(body, 0)
	body = nw.bo.AppendUint64(body, 0xFFFFFFFFFFFFFFFF)
	body = nw.strOpt(body, 1, s.Comment)
	body = nw.strOpt(body, 2, s.Hardware)
	body = nw.strOpt(body, 3, s.OS)
	body = nw.strOpt(body, 4, s.Application)
	body = nw.opt(body, 0, nil)
	if err := nw.WriteBlock(blockSHB, body); err != nil {
		return err
	}
	nw.units, nw.nIface = nw.units[:0], 0
	for _, f := range ifaces {
		if err := nw.AddInterface(f); err != nil {
			return err
		}
	}
	return nil
}

// AddInterface writes an Interface Description Block. TSResol 0 means 6.
func (nw *NgWriter) AddInterface(f Interface) error {
	if f.TSResol == 0 {
		f.TSResol = 6
	}
	u, ok := unitsPerSecond(f.TSResol)
	if !ok || f.TSResol&0x80 != 0 || f.TSResol > 9 {
		return fmt.Errorf("pcapng: unsupported if_tsresol %d (decimal 0..9)", f.TSResol)
	}
	body := nw.bo.AppendUint16(nil, f.LinkType)
	body = nw.bo.AppendUint16(body, 0)
	body = nw.bo.AppendUint32(body, f.SnapLen)
	body = nw.strOpt(body, 2, f.Name)
	body = nw.strOpt(body, 3, f.Description)
	body = nw.opt(body, 9, []byte{f.TSResol})
	if f.TSOffset != 0 {
		body = nw.opt(body, 14, nw.bo.AppendUint64(nil, uint64(f.TSOffset)))
	}
	body = nw.strOpt(body, 12, f.OS)
	body = nw.opt(body, 0, nil)
	nw.units = append(nw.units, u)
	nw.nIface++
	return nw.WriteBlock(blockIDB, body)
}

func (nw *NgWriter) ts(iface uint32, timeNS int64) (uint64, error) {
	if int(iface) >= nw.nIface {
		return 0, fmt.Errorf("%w %d", ErrInterface, iface)
	}
	return uint64(timeNS) / (1e9 / nw.units[iface]), nil
}

// WritePacket writes an Enhanced Packet Block. origLen 0 means len(data).
// timeNS is absolute; an interface's if_tsoffset is not subtracted.
func (nw *NgWriter) WritePacket(iface uint32, timeNS int64, origLen uint32, data []byte) error {
	ts, err := nw.ts(iface, timeNS)
	if err != nil {
		return err
	}
	if origLen == 0 {
		origLen = uint32(len(data))
	}
	body := nw.bo.AppendUint32(nw.scr[:0], iface)
	body = nw.bo.AppendUint32(body, uint32(ts>>32))
	body = nw.bo.AppendUint32(body, uint32(ts))
	body = nw.bo.AppendUint32(body, uint32(len(data)))
	body = nw.bo.AppendUint32(body, origLen)
	body = append(body, data...)
	b := append([]byte(nil), body...)
	return nw.WriteBlock(blockEPB, b)
}

// WriteSimplePacket writes a Simple Packet Block (interface 0, no time).
func (nw *NgWriter) WriteSimplePacket(origLen uint32, data []byte) error {
	if origLen == 0 {
		origLen = uint32(len(data))
	}
	body := nw.bo.AppendUint32(nil, origLen)
	return nw.WriteBlock(blockSPB, append(body, data...))
}

// WriteInterfaceStats writes an Interface Statistics Block with the
// counters that are set.
func (nw *NgWriter) WriteInterfaceStats(iface uint32, s InterfaceStats) error {
	ts, err := nw.ts(iface, s.TimeNS)
	if err != nil {
		return err
	}
	body := nw.bo.AppendUint32(nil, iface)
	body = nw.bo.AppendUint32(body, uint32(ts>>32))
	body = nw.bo.AppendUint32(body, uint32(ts))
	for _, o := range []struct {
		code uint16
		v    *uint64
	}{{4, s.IfRecv}, {5, s.IfDrop}, {6, s.FilterAccept}, {7, s.OSDrop}, {8, s.UsrDeliv}} {
		if o.v != nil {
			body = nw.opt(body, o.code, nw.bo.AppendUint64(nil, *o.v))
		}
	}
	body = nw.opt(body, 0, nil)
	return nw.WriteBlock(blockISB, body)
}

// Flush flushes buffered output.
func (nw *NgWriter) Flush() error { return nw.w.Flush() }
