// SPDX-License-Identifier: MIT

package mbtcp

import (
	"encoding/binary"
	"encoding/hex"
	"fmt"
)

// As says how a PDU is decoded: as a request or as a response.
type As uint8

// Decoding roles.
const (
	AsRequest As = iota + 1
	AsResponse
)

// Space is a Modbus data space.
type Space string

// Data spaces.
const (
	Coil     Space = "coil"
	Discrete Space = "discrete"
	Holding  Space = "holding"
	Input    Space = "input"
	FileRec  Space = "file"
	FIFO     Space = "fifo"
)

// Class says what a function does to the device.
type Class string

// Classes.
const (
	ClassRead  Class = "read"  // reads data and changes nothing
	ClassWrite Class = "write" // writes data (also FC23, which reads too)
	ClassOther Class = "other" // diagnostics that change state, CANopen, unknown and vendor functions
)

// Range is the part of a data space a PDU touches. Addresses are the raw
// zero-based PDU addresses.
type Range struct {
	Space Space  `json:"space"`
	File  uint16 `json:"file,omitempty"` // FC20/21: file number
	Start uint16 `json:"start"`
	Count uint16 `json:"count"` // FC24 request: 0 (the response gives it)
	Write bool   `json:"write,omitempty"`
}

// Field is one decoded field with its byte range in the ADU (the MBAP
// header is bytes 0..6, the function code byte 7).
type Field struct {
	Name   string  `json:"name"`
	Offset int     `json:"offset"`
	Length int     `json:"length"`
	Value  *uint64 `json:"value,omitempty"` // numbers
	Hex    string  `json:"hex,omitempty"`   // raw data
}

// View is a decoded PDU. Values stay raw: words, bits and bytes.
type View struct {
	Function  uint8    `json:"function"` // without the exception bit
	Name      string   `json:"name"`
	Known     bool     `json:"known"` // in the coverage table
	Exception bool     `json:"exception,omitempty"`
	Code      uint8    `json:"exception_code,omitempty"`
	Sub       *uint16  `json:"sub,omitempty"` // FC08 sub-function, FC43 MEI type
	Class     Class    `json:"class"`
	Ranges    []Range  `json:"ranges,omitempty"`
	Fields    []Field  `json:"fields,omitempty"`
	Warnings  []string `json:"warnings,omitempty"`
}

// Validation warnings (stable codes).
const (
	WarnEmpty          = "empty_pdu"
	WarnTruncated      = "truncated"       // shorter than the function's fixed part
	WarnLength         = "length_mismatch" // longer or shorter than its fields say
	WarnQuantity       = "quantity_out_of_range"
	WarnByteCount      = "byte_count_mismatch"
	WarnCoilValue      = "coil_value" // FC05 value not 0xFF00 or 0x0000
	WarnExceptionCode  = "unknown_exception_code"
	WarnReferenceType  = "reference_type" // FC20/21 sub-request reference type not 6
	WarnRecord         = "record_structure"
	WarnMEIStructure   = "mei_structure"
	WarnMismatch       = "response_mismatch" // the response does not fit its request
	WarnNotRequest     = "exception_as_request"
	WarnReadDeviceCode = "read_device_id_code"
)

// Exception codes and their names.
var exceptionNames = map[uint8]string{
	0x01: "illegal function", 0x02: "illegal data address", 0x03: "illegal data value",
	0x04: "server device failure", 0x05: "acknowledge", 0x06: "server device busy",
	0x07: "negative acknowledge", 0x08: "memory parity error",
	0x0A: "gateway path unavailable", 0x0B: "gateway target device failed to respond",
}

// ExceptionName returns the name of an exception code ("" if unknown).
func ExceptionName(code uint8) string { return exceptionNames[code] }

// dec builds a View.
type dec struct {
	p []byte
	v *View
}

func (d *dec) warn(w string) {
	for _, x := range d.v.Warnings {
		if x == w {
			return
		}
	}
	d.v.Warnings = append(d.v.Warnings, w)
}

func (d *dec) need(n int) bool {
	if len(d.p) < n {
		d.warn(WarnTruncated)
		return false
	}
	return true
}

// exact warns when the PDU is not n bytes.
func (d *dec) exact(n int) {
	if len(d.p) != n {
		d.warn(WarnLength)
	}
}

func num(v uint64) *uint64 { return &v }

func (d *dec) u8(name string, off int) uint8 {
	x := d.p[off]
	d.v.Fields = append(d.v.Fields, Field{Name: name, Offset: HeaderLen + off, Length: 1, Value: num(uint64(x))})
	return x
}

func (d *dec) u16(name string, off int) uint16 {
	x := binary.BigEndian.Uint16(d.p[off:])
	d.v.Fields = append(d.v.Fields, Field{Name: name, Offset: HeaderLen + off, Length: 2, Value: num(uint64(x))})
	return x
}

// raw records n bytes at off (clipped to the PDU).
func (d *dec) raw(name string, off, n int) {
	if off >= len(d.p) || n <= 0 {
		return
	}
	n = min(n, len(d.p)-off)
	d.v.Fields = append(d.v.Fields, Field{Name: name, Offset: HeaderLen + off, Length: n, Hex: hex.EncodeToString(d.p[off : off+n])})
}

func (d *dec) rng(s Space, start, count uint16, write bool) {
	d.v.Ranges = append(d.v.Ranges, Range{Space: s, Start: start, Count: count, Write: write})
}

// Decode decodes a PDU (function code first) as a request or a response.
// It never fails: a violated rule is a warning, an unknown function an
// opaque view.
func Decode(as As, pdu []byte) View {
	v := View{Class: ClassOther}
	d := &dec{p: pdu, v: &v}
	if len(pdu) == 0 {
		d.warn(WarnEmpty)
		return v
	}
	fc := pdu[0]
	v.Function = fc & 0x7F
	d.v.Fields = append(d.v.Fields, Field{Name: "function", Offset: HeaderLen, Length: 1, Value: num(uint64(fc))})
	f := functions[v.Function]
	if f != nil {
		v.Name, v.Known, v.Class = f.Name, true, f.Class
	} else {
		v.Name = fmt.Sprintf("function %d", v.Function)
	}
	if fc&0x80 != 0 {
		v.Exception = true
		if as == AsRequest {
			d.warn(WarnNotRequest)
		}
		if d.need(2) {
			v.Code = d.u8("exception_code", 1)
			if exceptionNames[v.Code] == "" {
				d.warn(WarnExceptionCode)
			}
			d.exact(2)
		}
		return v
	}
	if f == nil {
		d.raw("data", 1, len(pdu)-1)
		return v
	}
	if as == AsRequest {
		f.req(d)
	} else {
		f.resp(d)
	}
	return v
}

// function is one row of the coverage table.
type function struct {
	Name       string
	Class      Class
	SerialOnly bool   // normally limited to serial lines
	MBCAP      string // admission to MBCAP: yes, no, sub (depends on the sub-function or MEI type)
	req, resp  func(d *dec)
}

// functions is the coverage table.
var functions = map[uint8]*function{
	1:  {Name: "Read Coils", Class: ClassRead, MBCAP: "yes", req: readReq(Coil, 2000), resp: bitsResp},
	2:  {Name: "Read Discrete Inputs", Class: ClassRead, MBCAP: "yes", req: readReq(Discrete, 2000), resp: bitsResp},
	3:  {Name: "Read Holding Registers", Class: ClassRead, MBCAP: "yes", req: readReq(Holding, 125), resp: regsResp},
	4:  {Name: "Read Input Registers", Class: ClassRead, MBCAP: "yes", req: readReq(Input, 125), resp: regsResp},
	5:  {Name: "Write Single Coil", Class: ClassWrite, MBCAP: "no", req: fc05, resp: fc05},
	6:  {Name: "Write Single Register", Class: ClassWrite, MBCAP: "no", req: fc06, resp: fc06},
	7:  {Name: "Read Exception Status", Class: ClassRead, SerialOnly: true, MBCAP: "yes", req: only(1), resp: fc07Resp},
	8:  {Name: "Diagnostics", Class: ClassOther, SerialOnly: true, MBCAP: "sub", req: fc08, resp: fc08},
	11: {Name: "Get Comm Event Counter", Class: ClassRead, SerialOnly: true, MBCAP: "yes", req: only(1), resp: fc11Resp},
	12: {Name: "Get Comm Event Log", Class: ClassRead, SerialOnly: true, MBCAP: "yes", req: only(1), resp: fc12Resp},
	15: {Name: "Write Multiple Coils", Class: ClassWrite, MBCAP: "no", req: fc15Req, resp: writeMultiResp(Coil)},
	16: {Name: "Write Multiple Registers", Class: ClassWrite, MBCAP: "no", req: fc16Req, resp: writeMultiResp(Holding)},
	17: {Name: "Report Server ID", Class: ClassRead, SerialOnly: true, MBCAP: "yes", req: only(1), resp: countedResp("server_id")},
	20: {Name: "Read File Record", Class: ClassRead, MBCAP: "yes", req: fc20Req, resp: fc20Resp},
	21: {Name: "Write File Record", Class: ClassWrite, MBCAP: "no", req: fc21, resp: fc21},
	22: {Name: "Mask Write Register", Class: ClassWrite, MBCAP: "no", req: fc22, resp: fc22},
	23: {Name: "Read/Write Multiple Registers", Class: ClassWrite, MBCAP: "no", req: fc23Req, resp: regsResp},
	24: {Name: "Read FIFO Queue", Class: ClassRead, MBCAP: "yes", req: fc24Req, resp: fc24Resp},
	43: {Name: "Encapsulated Interface Transport", Class: ClassOther, MBCAP: "sub", req: fc43Req, resp: fc43Resp},
}

func only(n int) func(d *dec) {
	return func(d *dec) { d.exact(n) }
}

func readReq(s Space, maxQ uint16) func(d *dec) {
	return func(d *dec) {
		if !d.need(5) {
			return
		}
		a, q := d.u16("address", 1), d.u16("quantity", 3)
		if q < 1 || q > maxQ {
			d.warn(WarnQuantity)
		}
		d.rng(s, a, q, false)
		d.exact(5)
	}
}

func bitsResp(d *dec) {
	if !d.need(2) {
		return
	}
	bc := d.u8("byte_count", 1)
	if bc == 0 {
		d.warn(WarnByteCount)
	}
	name := "coil_status"
	if d.v.Function == 2 {
		name = "input_status"
	}
	d.raw(name, 2, int(bc))
	if len(d.p) != 2+int(bc) {
		d.warn(WarnByteCount)
	}
}

func regsResp(d *dec) {
	if !d.need(2) {
		return
	}
	bc := d.u8("byte_count", 1)
	if bc == 0 || bc%2 != 0 {
		d.warn(WarnByteCount)
	}
	d.raw("registers", 2, int(bc))
	if len(d.p) != 2+int(bc) {
		d.warn(WarnByteCount)
	}
}

func fc05(d *dec) {
	if !d.need(5) {
		return
	}
	a, val := d.u16("address", 1), d.u16("value", 3)
	if val != 0xFF00 && val != 0 {
		d.warn(WarnCoilValue)
	}
	d.rng(Coil, a, 1, true)
	d.exact(5)
}

func fc06(d *dec) {
	if !d.need(5) {
		return
	}
	a := d.u16("address", 1)
	d.u16("value", 3)
	d.rng(Holding, a, 1, true)
	d.exact(5)
}

func fc07Resp(d *dec) {
	if d.need(2) {
		d.u8("status", 1)
		d.exact(2)
	}
}

// Diagnostics sub-functions; read: returns data and changes nothing.
var diagSubs = map[uint16]struct {
	name string
	read bool
}{
	0x00: {"Return Query Data", true}, 0x01: {"Restart Communications Option", false},
	0x02: {"Return Diagnostic Register", true}, 0x03: {"Change ASCII Input Delimiter", false},
	0x04: {"Force Listen Only Mode", false}, 0x0A: {"Clear Counters and Diagnostic Register", false},
	0x0B: {"Return Bus Message Count", true}, 0x0C: {"Return Bus Communication Error Count", true},
	0x0D: {"Return Bus Exception Error Count", true}, 0x0E: {"Return Server Message Count", true},
	0x0F: {"Return Server No Response Count", true}, 0x10: {"Return Server NAK Count", true},
	0x11: {"Return Server Busy Count", true}, 0x12: {"Return Bus Character Overrun Count", true},
	0x14: {"Clear Overrun Counter and Flag", false},
}

// DiagnosticsAdmissible reports an FC08 sub-function that reads without
// changing device state (MBCAP-EXPORT.md section 3).
func DiagnosticsAdmissible(sub uint16) bool {
	return sub == 0x00 || sub == 0x02 || (sub >= 0x0B && sub <= 0x12)
}

func fc08(d *dec) {
	if !d.need(3) {
		return
	}
	sub := d.u16("sub_function", 1)
	d.v.Sub = &sub
	if s, ok := diagSubs[sub]; ok {
		d.v.Name = "Diagnostics: " + s.name
		if s.read {
			d.v.Class = ClassRead
		}
	}
	d.raw("data", 3, len(d.p)-3)
}

func fc11Resp(d *dec) {
	if d.need(5) {
		d.u16("status", 1)
		d.u16("event_count", 3)
		d.exact(5)
	}
}

func fc12Resp(d *dec) {
	if !d.need(8) {
		return
	}
	bc := d.u8("byte_count", 1)
	d.u16("status", 2)
	d.u16("event_count", 4)
	d.u16("message_count", 6)
	d.raw("events", 8, int(bc)-6)
	if bc < 6 || len(d.p) != 2+int(bc) {
		d.warn(WarnByteCount)
	}
}

func countedResp(name string) func(d *dec) {
	return func(d *dec) {
		if !d.need(2) {
			return
		}
		bc := d.u8("byte_count", 1)
		d.raw(name, 2, int(bc))
		if len(d.p) != 2+int(bc) {
			d.warn(WarnByteCount)
		}
	}
}

func fc15Req(d *dec) {
	if !d.need(6) {
		return
	}
	a, q, bc := d.u16("address", 1), d.u16("quantity", 3), d.u8("byte_count", 5)
	if q < 1 || q > 1968 {
		d.warn(WarnQuantity)
	}
	if int(bc) != (int(q)+7)/8 || len(d.p) != 6+int(bc) {
		d.warn(WarnByteCount)
	}
	d.raw("values", 6, int(bc))
	d.rng(Coil, a, q, true)
}

func fc16Req(d *dec) {
	if !d.need(6) {
		return
	}
	a, q, bc := d.u16("address", 1), d.u16("quantity", 3), d.u8("byte_count", 5)
	if q < 1 || q > 123 {
		d.warn(WarnQuantity)
	}
	if int(bc) != 2*int(q) || len(d.p) != 6+int(bc) {
		d.warn(WarnByteCount)
	}
	d.raw("values", 6, int(bc))
	d.rng(Holding, a, q, true)
}

func writeMultiResp(s Space) func(d *dec) {
	return func(d *dec) {
		if !d.need(5) {
			return
		}
		a, q := d.u16("address", 1), d.u16("quantity", 3)
		d.rng(s, a, q, true)
		d.exact(5)
	}
}

// fileRecords decodes FC20/21 sub-requests (7 bytes, plus data for FC21).
func fileRecords(d *dec, write bool) {
	if !d.need(2) {
		return
	}
	bc := int(d.u8("byte_count", 1))
	if len(d.p) != 2+bc {
		d.warn(WarnByteCount)
	}
	if bc < 7 || bc > 0xF5 {
		d.warn(WarnByteCount)
	}
	end := min(len(d.p), 2+bc)
	for off, i := 2, 0; off < end; i++ {
		if off+7 > end {
			d.warn(WarnRecord)
			return
		}
		p := fmt.Sprintf("record%d_", i)
		if d.u8(p+"reference_type", off) != 6 {
			d.warn(WarnReferenceType)
		}
		file, rec, n := d.u16(p+"file", off+1), d.u16(p+"record", off+3), d.u16(p+"length", off+5)
		if rec > 0x270F {
			d.warn(WarnRecord)
		}
		d.v.Ranges = append(d.v.Ranges, Range{Space: FileRec, File: file, Start: rec, Count: n, Write: write})
		off += 7
		if write {
			if off+2*int(n) > end {
				d.warn(WarnRecord)
				return
			}
			d.raw(p+"data", off, 2*int(n))
			off += 2 * int(n)
		}
	}
}

func fc20Req(d *dec) { fileRecords(d, false) }
func fc21(d *dec)    { fileRecords(d, true) }

func fc20Resp(d *dec) {
	if !d.need(2) {
		return
	}
	bc := int(d.u8("byte_count", 1))
	if len(d.p) != 2+bc || bc < 3 || bc > 0xF5 {
		d.warn(WarnByteCount)
	}
	end := min(len(d.p), 2+bc)
	for off, i := 2, 0; off < end; i++ {
		if off+2 > end {
			d.warn(WarnRecord)
			return
		}
		p := fmt.Sprintf("record%d_", i)
		n := int(d.u8(p+"length", off))
		if d.u8(p+"reference_type", off+1) != 6 {
			d.warn(WarnReferenceType)
		}
		if n < 1 || n%2 != 1 || off+1+n > end {
			d.warn(WarnRecord)
			return
		}
		d.raw(p+"data", off+2, n-1)
		off += 1 + n
	}
}

func fc22(d *dec) {
	if !d.need(7) {
		return
	}
	a := d.u16("address", 1)
	d.u16("and_mask", 3)
	d.u16("or_mask", 5)
	d.rng(Holding, a, 1, true)
	d.exact(7)
}

func fc23Req(d *dec) {
	if !d.need(10) {
		return
	}
	ra, rq := d.u16("read_address", 1), d.u16("read_quantity", 3)
	wa, wq := d.u16("write_address", 5), d.u16("write_quantity", 7)
	bc := d.u8("byte_count", 9)
	if rq < 1 || rq > 125 || wq < 1 || wq > 121 {
		d.warn(WarnQuantity)
	}
	if int(bc) != 2*int(wq) || len(d.p) != 10+int(bc) {
		d.warn(WarnByteCount)
	}
	d.raw("write_values", 10, int(bc))
	d.rng(Holding, ra, rq, false)
	d.rng(Holding, wa, wq, true)
}

func fc24Req(d *dec) {
	if d.need(3) {
		a := d.u16("fifo_address", 1)
		d.rng(FIFO, a, 0, false)
		d.exact(3)
	}
}

func fc24Resp(d *dec) {
	if !d.need(5) {
		return
	}
	bc, n := d.u16("byte_count", 1), d.u16("fifo_count", 3)
	if n > 31 {
		d.warn(WarnQuantity)
	}
	if int(bc) != 2+2*int(n) || len(d.p) != 3+int(bc) {
		d.warn(WarnByteCount)
	}
	d.raw("values", 5, 2*int(n))
}

// MEI types.
const (
	MEICANopen  = 13
	MEIDeviceID = 14
)

func fc43Req(d *dec) {
	if !d.need(2) {
		return
	}
	mei := uint16(d.u8("mei_type", 1))
	d.v.Sub = &mei
	if mei != MEIDeviceID {
		if mei == MEICANopen {
			d.v.Name = "CANopen General Reference"
		}
		d.raw("data", 2, len(d.p)-2)
		return
	}
	d.v.Name, d.v.Class = "Read Device Identification", ClassRead
	if !d.need(4) {
		return
	}
	if c := d.u8("read_device_id_code", 2); c < 1 || c > 4 {
		d.warn(WarnReadDeviceCode)
	}
	d.u8("object_id", 3)
	d.exact(4)
}

func fc43Resp(d *dec) {
	if !d.need(2) {
		return
	}
	mei := uint16(d.u8("mei_type", 1))
	d.v.Sub = &mei
	if mei != MEIDeviceID {
		if mei == MEICANopen {
			d.v.Name = "CANopen General Reference"
		}
		d.raw("data", 2, len(d.p)-2)
		return
	}
	d.v.Name, d.v.Class = "Read Device Identification", ClassRead
	if !d.need(7) {
		return
	}
	if c := d.u8("read_device_id_code", 2); c < 1 || c > 4 {
		d.warn(WarnReadDeviceCode)
	}
	d.u8("conformity_level", 3)
	if m := d.u8("more_follows", 4); m != 0 && m != 0xFF {
		d.warn(WarnMEIStructure)
	}
	d.u8("next_object_id", 5)
	n := int(d.u8("number_of_objects", 6))
	off := 7
	for i := 0; i < n; i++ {
		if off+2 > len(d.p) {
			d.warn(WarnMEIStructure)
			return
		}
		p := fmt.Sprintf("object%d_", i)
		d.u8(p+"id", off)
		l := int(d.u8(p+"length", off+1))
		if off+2+l > len(d.p) {
			d.warn(WarnMEIStructure)
			return
		}
		d.raw(p+"value", off+2, l)
		off += 2 + l
	}
	if off != len(d.p) {
		d.warn(WarnMEIStructure)
	}
}
