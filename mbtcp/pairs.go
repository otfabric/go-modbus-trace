// SPDX-License-Identifier: MIT

package mbtcp

import (
	"bytes"
	"encoding/binary"
	"fmt"
	"sort"
	"strings"
)

// CheckPair returns the warnings of a response that does not fit its
// request (WarnMismatch), and completes the response view's ranges from the
// request: an FC01-04 response carries no address, FC24's count comes from
// the response.
func CheckPair(req []byte, reqV View, resp []byte, respV *View) []string {
	if len(req) == 0 || len(resp) == 0 || respV.Exception {
		return nil
	}
	ok := true
	switch fc := req[0]; fc {
	case 1, 2:
		if len(req) >= 5 && len(resp) >= 2 {
			q := int(binary.BigEndian.Uint16(req[3:]))
			ok = int(resp[1]) == (q+7)/8
		}
	case 3, 4:
		if len(req) >= 5 && len(resp) >= 2 {
			ok = int(resp[1]) == 2*int(binary.BigEndian.Uint16(req[3:]))
		}
	case 23:
		if len(req) >= 5 && len(resp) >= 2 {
			ok = int(resp[1]) == 2*int(binary.BigEndian.Uint16(req[3:]))
		}
	case 5, 6, 22:
		ok = bytes.Equal(req, resp)
	case 15, 16:
		ok = len(req) >= 5 && len(resp) >= 5 && bytes.Equal(req[:5], resp[:5])
	case 21:
		ok = bytes.Equal(req, resp)
	case 8:
		ok = len(req) >= 3 && len(resp) >= 3 && bytes.Equal(req[:3], resp[:3])
		if ok && binary.BigEndian.Uint16(req[1:]) == 0 {
			ok = bytes.Equal(req, resp) // Return Query Data echoes
		}
	case 20:
		ok = fileResponseFits(reqV, resp)
	case 43:
		ok = len(req) >= 3 && len(resp) >= 3 && req[1] == resp[1] && (req[1] != MEIDeviceID || req[2] == resp[2])
	}
	if reqV.Function == 1 || reqV.Function == 2 || reqV.Function == 3 || reqV.Function == 4 || reqV.Function == 23 {
		for _, r := range reqV.Ranges {
			if !r.Write {
				respV.Ranges = append(respV.Ranges, r)
			}
		}
	}
	if reqV.Function == 24 && len(reqV.Ranges) == 1 && len(resp) >= 5 {
		r := reqV.Ranges[0]
		r.Count = binary.BigEndian.Uint16(resp[3:])
		respV.Ranges = append(respV.Ranges, r)
	}
	if !ok {
		respV.Warnings = append(respV.Warnings, WarnMismatch)
		return []string{WarnMismatch}
	}
	return nil
}

// fileResponseFits checks that an FC20 response has one sub-response of the
// requested length for every sub-request.
func fileResponseFits(req View, resp []byte) bool {
	if len(resp) < 2 {
		return false
	}
	off, end := 2, min(len(resp), 2+int(resp[1]))
	for _, r := range req.Ranges {
		if off >= end || int(resp[off]) != 1+2*int(r.Count) {
			return false
		}
		off += 1 + int(resp[off])
	}
	return off == end
}

// ValueAt returns the raw value at a zero-based address from a read
// response and its request: a register word (FC03/04/23) or a bit as 0/1
// (FC01/02). ok is false when the response does not hold the address.
func ValueAt(req, resp []byte, addr uint16) (v uint16, ok bool) {
	if len(req) < 5 || len(resp) < 2 || resp[0] != req[0] {
		return 0, false
	}
	start, q := binary.BigEndian.Uint16(req[1:]), binary.BigEndian.Uint16(req[3:])
	if addr < start || uint32(addr) >= uint32(start)+uint32(q) {
		return 0, false
	}
	i := int(addr - start)
	data := resp[2:min(len(resp), 2+int(resp[1]))]
	switch req[0] {
	case 1, 2:
		if i/8 >= len(data) {
			return 0, false
		}
		return uint16(data[i/8]>>(i%8)) & 1, true
	case 3, 4, 23:
		if 2*i+2 > len(data) {
			return 0, false
		}
		return binary.BigEndian.Uint16(data[2*i:]), true
	}
	return 0, false
}

var spaceNouns = map[Space][2]string{
	Coil: {"coil", "coils"}, Discrete: {"discrete input", "discrete inputs"},
	Holding: {"holding register", "holding registers"}, Input: {"input register", "input registers"},
}

func noun(s Space, n uint16) string {
	if n == 1 {
		return spaceNouns[s][0]
	}
	return spaceNouns[s][1]
}

// Summary returns a one-line English description of a request, with the
// outcome of its response when given, for display ("Read 62 holding
// registers @ 4096").
func Summary(req View, resp *View) string {
	var s string
	r := func(i int) Range {
		if i < len(req.Ranges) {
			return req.Ranges[i]
		}
		return Range{}
	}
	switch req.Function {
	case 1, 2, 3, 4:
		x := r(0)
		s = fmt.Sprintf("Read %d %s @ %d", x.Count, noun(x.Space, x.Count), x.Start)
	case 5:
		state := "OFF"
		for _, f := range req.Fields {
			if f.Name == "value" && f.Value != nil && *f.Value == 0xFF00 {
				state = "ON"
			}
		}
		s = fmt.Sprintf("Write coil @ %d = %s", r(0).Start, state)
	case 6:
		val := uint64(0)
		for _, f := range req.Fields {
			if f.Name == "value" && f.Value != nil {
				val = *f.Value
			}
		}
		s = fmt.Sprintf("Write holding register @ %d = %d", r(0).Start, val)
	case 15, 16:
		x := r(0)
		s = fmt.Sprintf("Write %d %s @ %d", x.Count, noun(x.Space, x.Count), x.Start)
	case 22:
		s = fmt.Sprintf("Mask write holding register @ %d", r(0).Start)
	case 23:
		s = fmt.Sprintf("Read %d holding registers @ %d, write %d @ %d", r(0).Count, r(0).Start, r(1).Count, r(1).Start)
	case 20, 21:
		verb := "Read"
		if req.Function == 21 {
			verb = "Write"
		}
		s = fmt.Sprintf("%s %d file record(s)", verb, len(req.Ranges))
	case 24:
		s = fmt.Sprintf("Read FIFO queue @ %d", r(0).Start)
	default:
		s = req.Name
		if !req.Known {
			s = fmt.Sprintf("Function %d", req.Function)
		}
	}
	if resp != nil && resp.Exception {
		name := ExceptionName(resp.Code)
		if name == "" {
			name = "unknown"
		}
		s += fmt.Sprintf(": exception %d (%s)", resp.Code, name)
	}
	return s
}

// FunctionInfo is a row of the coverage table, for documentation.
type FunctionInfo struct {
	Code       uint8
	Name       string
	Class      Class
	SerialOnly bool
	MBCAP      string // yes, no, sub
	Request    []string
	Response   []string
}

// Coverage returns the coverage table in function-code order, with the
// field names its decoders produce for a typical PDU.
func Coverage() []FunctionInfo {
	var out []FunctionInfo
	for code, f := range functions {
		out = append(out, FunctionInfo{Code: code, Name: f.Name, Class: f.Class, SerialOnly: f.SerialOnly, MBCAP: f.MBCAP,
			Request: fieldNames(Decode(AsRequest, samplePDU(code, AsRequest))), Response: fieldNames(Decode(AsResponse, samplePDU(code, AsResponse)))})
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Code < out[j].Code })
	return out
}

func fieldNames(v View) []string {
	seen := map[string]bool{}
	var out []string
	for _, f := range v.Fields[1:] {
		n := f.Name
		if i := strings.Index(n, "_"); i > 0 && strings.HasPrefix(n, "record") || strings.HasPrefix(n, "object") {
			n = "…" + n[i:]
		}
		if !seen[n] {
			seen[n] = true
			out = append(out, n)
		}
	}
	return out
}

// samplePDU returns a valid PDU of each function, for the coverage table
// and the tests.
func samplePDU(code uint8, as As) []byte {
	req := map[uint8][]byte{
		1: {1, 0, 0, 0, 10}, 2: {2, 0, 0, 0, 10}, 3: {3, 0, 0, 0, 2}, 4: {4, 0, 0, 0, 2},
		5: {5, 0, 1, 0xFF, 0}, 6: {6, 0, 1, 0, 7}, 7: {7}, 8: {8, 0, 0, 0xA5, 0x37}, 11: {11}, 12: {12},
		15: {15, 0, 0, 0, 10, 2, 0xFF, 3}, 16: {16, 0, 0, 0, 2, 4, 0, 1, 0, 2}, 17: {17},
		20: {20, 7, 6, 0, 4, 0, 1, 0, 2}, 21: {21, 11, 6, 0, 4, 0, 7, 0, 2, 0, 1, 0, 2},
		22: {22, 0, 4, 0, 0xF2, 0, 0x25}, 23: {23, 0, 3, 0, 2, 0, 14, 0, 1, 2, 0, 0xFF},
		24: {24, 0x04, 0xDE}, 43: {43, 14, 1, 0},
	}
	resp := map[uint8][]byte{
		1: {1, 2, 0xCD, 0x01}, 2: {2, 2, 0xAC, 0x03}, 3: {3, 4, 0, 1, 0, 2}, 4: {4, 4, 0, 1, 0, 2},
		5: {5, 0, 1, 0xFF, 0}, 6: {6, 0, 1, 0, 7}, 7: {7, 0x6D}, 8: {8, 0, 0, 0xA5, 0x37}, 11: {11, 0, 0, 1, 8},
		12: {12, 8, 0, 0, 1, 8, 1, 0x21, 0x20, 0x00}, 15: {15, 0, 0, 0, 10}, 16: {16, 0, 0, 0, 2}, 17: {17, 2, 0x42, 0xFF},
		20: {20, 6, 5, 6, 0x0D, 0xFE, 0x00, 0x20}, 21: {21, 11, 6, 0, 4, 0, 7, 0, 2, 0, 1, 0, 2},
		22: {22, 0, 4, 0, 0xF2, 0, 0x25}, 23: {23, 4, 0, 1, 0, 2}, 24: {24, 0, 6, 0, 2, 0x01, 0xB8, 0x12, 0x84},
		43: {43, 14, 1, 1, 0, 0, 1, 0, 3, 'A', 'C', 'M'},
	}
	if as == AsRequest {
		return req[code]
	}
	return resp[code]
}

// SerialOnly reports a function normally limited to serial lines (FC07,
// 08, 11, 12, 17), which is flagged when seen over TCP.
func SerialOnly(fc uint8) bool {
	f := functions[fc&0x7F]
	return f != nil && f.SerialOnly
}
