// SPDX-License-Identifier: MIT

package mbtcp

import (
	"bytes"
	"fmt"
	"os"
	"strings"
	"testing"
)

// fields renders a view's fields compactly: name=value or name=hex.
func fields(v View) string {
	var p []string
	for _, f := range v.Fields[1:] {
		switch {
		case f.Value != nil:
			p = append(p, fmt.Sprintf("%s=%d", f.Name, *f.Value))
		default:
			p = append(p, fmt.Sprintf("%s=%s", f.Name, f.Hex))
		}
	}
	return strings.Join(p, " ")
}

func ranges(v View) string {
	var p []string
	for _, r := range v.Ranges {
		s := fmt.Sprintf("%s:%d+%d", r.Space, r.Start, r.Count)
		if r.File != 0 {
			s = fmt.Sprintf("%s#%d:%d+%d", r.Space, r.File, r.Start, r.Count)
		}
		if r.Write {
			s += "w"
		}
		p = append(p, s)
	}
	return strings.Join(p, " ")
}

// TestGoldenDecodes is the golden part of LA6: a request and a response of
// every function in the coverage table.
func TestGoldenDecodes(t *testing.T) {
	cases := []struct {
		fc                uint8
		reqFields, reqRng string
		respFields, class string
		summary           string
	}{
		{1, "address=0 quantity=10", "coil:0+10", "byte_count=2 coil_status=cd01", "read", "Read 10 coils @ 0"},
		{2, "address=0 quantity=10", "discrete:0+10", "byte_count=2 input_status=ac03", "read", "Read 10 discrete inputs @ 0"},
		{3, "address=0 quantity=2", "holding:0+2", "byte_count=4 registers=00010002", "read", "Read 2 holding registers @ 0"},
		{4, "address=0 quantity=2", "input:0+2", "byte_count=4 registers=00010002", "read", "Read 2 input registers @ 0"},
		{5, "address=1 value=65280", "coil:1+1w", "address=1 value=65280", "write", "Write coil @ 1 = ON"},
		{6, "address=1 value=7", "holding:1+1w", "address=1 value=7", "write", "Write holding register @ 1 = 7"},
		{7, "", "", "status=109", "read", "Read Exception Status"},
		{8, "sub_function=0 data=a537", "", "sub_function=0 data=a537", "read", "Diagnostics: Return Query Data"},
		{11, "", "", "status=0 event_count=264", "read", "Get Comm Event Counter"},
		{12, "", "", "byte_count=8 status=0 event_count=264 message_count=289 events=2000", "read", "Get Comm Event Log"},
		{15, "address=0 quantity=10 byte_count=2 values=ff03", "coil:0+10w", "address=0 quantity=10", "write", "Write 10 coils @ 0"},
		{16, "address=0 quantity=2 byte_count=4 values=00010002", "holding:0+2w", "address=0 quantity=2", "write", "Write 2 holding registers @ 0"},
		{17, "", "", "byte_count=2 server_id=42ff", "read", "Report Server ID"},
		{20, "byte_count=7 record0_reference_type=6 record0_file=4 record0_record=1 record0_length=2", "file#4:1+2", "byte_count=6 record0_length=5 record0_reference_type=6 record0_data=0dfe0020", "read", "Read 1 file record(s)"},
		{21, "byte_count=11 record0_reference_type=6 record0_file=4 record0_record=7 record0_length=2 record0_data=00010002", "file#4:7+2w", "byte_count=11 record0_reference_type=6 record0_file=4 record0_record=7 record0_length=2 record0_data=00010002", "write", "Write 1 file record(s)"},
		{22, "address=4 and_mask=242 or_mask=37", "holding:4+1w", "address=4 and_mask=242 or_mask=37", "write", "Mask write holding register @ 4"},
		{23, "read_address=3 read_quantity=2 write_address=14 write_quantity=1 byte_count=2 write_values=00ff", "holding:3+2 holding:14+1w", "byte_count=4 registers=00010002", "write", "Read 2 holding registers @ 3, write 1 @ 14"},
		{24, "fifo_address=1246", "fifo:1246+0", "byte_count=6 fifo_count=2 values=01b81284", "read", "Read FIFO queue @ 1246"},
		{43, "mei_type=14 read_device_id_code=1 object_id=0", "", "mei_type=14 read_device_id_code=1 conformity_level=1 more_follows=0 next_object_id=0 number_of_objects=1 object0_id=0 object0_length=3 object0_value=41434d", "read", "Read Device Identification"},
	}
	for _, c := range cases {
		t.Run(fmt.Sprint(c.fc), func(t *testing.T) {
			req, resp := samplePDU(c.fc, AsRequest), samplePDU(c.fc, AsResponse)
			rq, rs := Decode(AsRequest, req), Decode(AsResponse, resp)
			if w := CheckPair(req, rq, resp, &rs); len(w)+len(rq.Warnings)+len(rs.Warnings) > 0 {
				t.Errorf("warnings %v %v %v", w, rq.Warnings, rs.Warnings)
			}
			if got := fields(rq); got != c.reqFields {
				t.Errorf("request fields\n got  %s\n want %s", got, c.reqFields)
			}
			if got := ranges(rq); got != c.reqRng {
				t.Errorf("request ranges %q, want %q", got, c.reqRng)
			}
			if got := fields(rs); got != c.respFields {
				t.Errorf("response fields\n got  %s\n want %s", got, c.respFields)
			}
			if string(rq.Class) != c.class || !rq.Known {
				t.Errorf("class %s known %v", rq.Class, rq.Known)
			}
			if got := Summary(rq, &rs); got != c.summary {
				t.Errorf("summary %q, want %q", got, c.summary)
			}
			// Every field's byte range points at its bytes in the ADU.
			adu := append(make([]byte, HeaderLen), resp...)
			for _, f := range rs.Fields {
				if f.Offset < HeaderLen || f.Offset+f.Length > len(adu) {
					t.Errorf("field %s out of the ADU", f.Name)
				}
			}
		})
	}
}

// TestValidation: each documented violation gives its warning.
func TestValidation(t *testing.T) {
	cases := []struct {
		name string
		as   As
		pdu  []byte
		warn string
	}{
		{"empty", AsRequest, nil, WarnEmpty},
		{"FC03 quantity 0", AsRequest, []byte{3, 0, 0, 0, 0}, WarnQuantity},
		{"FC03 quantity 126", AsRequest, []byte{3, 0, 0, 0, 126}, WarnQuantity},
		{"FC01 quantity 2001", AsRequest, []byte{1, 0, 0, 0x07, 0xD1}, WarnQuantity},
		{"FC03 request too long", AsRequest, []byte{3, 0, 0, 0, 1, 9}, WarnLength},
		{"FC03 request too short", AsRequest, []byte{3, 0, 0}, WarnTruncated},
		{"FC03 odd byte count", AsResponse, []byte{3, 3, 0, 0, 0}, WarnByteCount},
		{"FC03 byte count beyond the data", AsResponse, []byte{3, 4, 0, 1}, WarnByteCount},
		{"FC05 value", AsRequest, []byte{5, 0, 1, 0x12, 0x34}, WarnCoilValue},
		{"FC15 byte count", AsRequest, []byte{15, 0, 0, 0, 10, 1, 0xFF}, WarnByteCount},
		{"FC15 quantity", AsRequest, []byte{15, 0, 0, 0x07, 0xB1, 0}, WarnQuantity},
		{"FC16 byte count", AsRequest, []byte{16, 0, 0, 0, 2, 2, 0, 1}, WarnByteCount},
		{"FC16 quantity", AsRequest, []byte{16, 0, 0, 0, 124, 248}, WarnQuantity},
		{"FC07 request length", AsRequest, []byte{7, 0}, WarnLength},
		{"FC11 response length", AsResponse, []byte{11, 0, 0, 1}, WarnTruncated},
		{"FC22 length", AsRequest, []byte{22, 0, 4, 0, 0xF2, 0}, WarnTruncated},
		{"FC24 request length", AsRequest, []byte{24, 0, 1, 0}, WarnLength},
		{"FC23 write quantity", AsRequest, []byte{23, 0, 0, 0, 1, 0, 0, 0, 122, 244}, WarnQuantity},
		{"FC20 reference type", AsRequest, []byte{20, 7, 5, 0, 4, 0, 1, 0, 2}, WarnReferenceType},
		{"FC20 sub-request cut", AsRequest, []byte{20, 9, 6, 0, 4, 0, 1, 0, 2, 6, 0}, WarnRecord},
		{"FC24 count above 31", AsResponse, []byte{24, 0, 66, 0, 32}, WarnQuantity},
		{"FC43/14 object cut", AsResponse, []byte{43, 14, 1, 1, 0, 0, 1, 0, 9, 'A'}, WarnMEIStructure},
		{"FC43/14 code", AsRequest, []byte{43, 14, 9, 0}, WarnReadDeviceCode},
		{"exception code unknown", AsResponse, []byte{0x83, 0x42}, WarnExceptionCode},
		{"exception length", AsResponse, []byte{0x83, 2, 0}, WarnLength},
		{"exception as a request", AsRequest, []byte{0x83, 2}, WarnNotRequest},
		{"FC01 byte count 0", AsResponse, []byte{1, 0}, WarnByteCount},
		{"FC01 response cut", AsResponse, []byte{1}, WarnTruncated},
		{"FC17 byte count", AsResponse, []byte{17, 3, 1}, WarnByteCount},
		{"FC12 byte count", AsResponse, []byte{12, 5, 0, 0, 0, 0, 0, 0}, WarnByteCount},
		{"FC20 response byte count", AsResponse, []byte{20, 2, 1, 6}, WarnByteCount},
		{"FC20 response reference type", AsResponse, []byte{20, 4, 3, 5, 0, 1}, WarnReferenceType},
		{"FC20 response record length", AsResponse, []byte{20, 4, 2, 6, 0, 1}, WarnRecord},
		{"FC20 response record cut", AsResponse, []byte{20, 3, 9}, WarnRecord},
		{"FC21 data cut", AsRequest, []byte{21, 9, 6, 0, 4, 0, 7, 0, 9, 0, 1}, WarnRecord},
		{"FC20 record number", AsRequest, []byte{20, 7, 6, 0, 4, 0x27, 0x10, 0, 2}, WarnRecord},
		{"FC24 response byte count", AsResponse, []byte{24, 0, 9, 0, 2, 1, 2, 3, 4}, WarnByteCount},
		{"FC43/14 more follows", AsResponse, []byte{43, 14, 1, 1, 7, 0, 0}, WarnMEIStructure},
		{"FC43/14 trailing bytes", AsResponse, []byte{43, 14, 1, 1, 0, 0, 0, 9}, WarnMEIStructure},
		{"FC43/14 object header cut", AsResponse, []byte{43, 14, 1, 1, 0, 0, 1, 0}, WarnMEIStructure},
		{"FC43/14 response code", AsResponse, []byte{43, 14, 0, 1, 0, 0, 0}, WarnReadDeviceCode},
		{"FC43/14 response cut", AsResponse, []byte{43, 14, 1}, WarnTruncated},
		{"FC43 request cut", AsRequest, []byte{43}, WarnTruncated},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			v := Decode(c.as, c.pdu)
			found := false
			for _, w := range v.Warnings {
				found = found || w == c.warn
			}
			if !found {
				t.Errorf("warnings %v, want %s", v.Warnings, c.warn)
			}
		})
	}
}

func TestOpaqueAndExceptions(t *testing.T) {
	v := Decode(AsRequest, []byte{0x41, 1, 2, 3})
	if v.Known || v.Class != ClassOther || fields(v) != "data=010203" || Summary(v, nil) != "Function 65" {
		t.Errorf("vendor: %+v", v)
	}
	v = Decode(AsRequest, []byte{43, 13, 0xAA})
	if v.Name != "CANopen General Reference" || v.Class != ClassOther || *v.Sub != 13 {
		t.Errorf("MEI 13: %+v", v)
	}
	if v = Decode(AsResponse, []byte{43, 13, 0xBB}); v.Name != "CANopen General Reference" || fields(v) != "mei_type=13 data=bb" {
		t.Errorf("MEI 13 response: %+v", v)
	}
	if v = Decode(AsResponse, []byte{43, 99}); v.Name != "Encapsulated Interface Transport" || v.Class != ClassOther {
		t.Errorf("MEI 99: %+v", v)
	}
	for _, sub := range []uint16{1, 3, 4, 10, 20, 99} {
		if DiagnosticsAdmissible(sub) {
			t.Errorf("FC08/%d is not a read", sub)
		}
	}
	if ExceptionName(0x0B) == "" || ExceptionName(0x09) != "" || !SerialOnly(0x88) || SerialOnly(3) {
		t.Error("tables")
	}
	v = Decode(AsRequest, []byte{8, 0, 1, 0, 0})
	if v.Class != ClassOther || DiagnosticsAdmissible(*v.Sub) {
		t.Errorf("FC08 restart: %+v", v)
	}
	e := Decode(AsResponse, []byte{0x83, 0x02})
	if !e.Exception || e.Code != 2 || e.Function != 3 || len(e.Warnings) != 0 {
		t.Errorf("exception: %+v", e)
	}
	if s := Summary(Decode(AsRequest, []byte{3, 0, 7, 0, 1}), &e); s != "Read 1 holding register @ 7: exception 2 (illegal data address)" {
		t.Errorf("summary %q", s)
	}
}

func TestCheckPair(t *testing.T) {
	mismatch := []struct {
		name      string
		req, resp []byte
	}{
		{"FC03 fewer registers", []byte{3, 0, 0, 0, 3}, []byte{3, 4, 0, 1, 0, 2}},
		{"FC01 byte count", []byte{1, 0, 0, 0, 9}, []byte{1, 1, 0xFF}},
		{"FC06 echo", []byte{6, 0, 1, 0, 7}, []byte{6, 0, 1, 0, 8}},
		{"FC16 echo", []byte{16, 0, 0, 0, 2, 4, 0, 1, 0, 2}, []byte{16, 0, 0, 0, 3}},
		{"FC08 echo", []byte{8, 0, 0, 1, 2}, []byte{8, 0, 0, 1, 3}},
		{"FC20 record length", []byte{20, 7, 6, 0, 4, 0, 1, 0, 2}, []byte{20, 4, 3, 6, 0, 1}},
		{"FC43 code", []byte{43, 14, 1, 0}, []byte{43, 14, 2, 1, 0, 0, 0}},
	}
	for _, c := range mismatch {
		rq, rs := Decode(AsRequest, c.req), Decode(AsResponse, c.resp)
		if w := CheckPair(c.req, rq, c.resp, &rs); len(w) != 1 || w[0] != WarnMismatch {
			t.Errorf("%s: %v", c.name, w)
		}
	}
	req := []byte{3, 0x10, 0, 0, 2}
	rq, rs := Decode(AsRequest, req), Decode(AsResponse, []byte{3, 4, 0, 1, 0, 2})
	CheckPair(req, rq, []byte{3, 4, 0, 1, 0, 2}, &rs)
	if ranges(rs) != "holding:4096+2" {
		t.Errorf("response ranges %q", ranges(rs))
	}
}

func TestValueAt(t *testing.T) {
	regs := []byte{3, 0x10, 0, 0, 3}
	cases := []struct {
		req, resp []byte
		addr      uint16
		v         uint16
		ok        bool
	}{
		{regs, []byte{3, 6, 0, 1, 0xAB, 0xCD, 0, 3}, 4097, 0xABCD, true},
		{regs, []byte{3, 6, 0, 1, 0xAB, 0xCD, 0, 3}, 4099, 0, false},
		{regs, []byte{3, 6, 0, 1, 0xAB, 0xCD, 0, 3}, 4095, 0, false},
		{regs, []byte{3, 2, 0, 1}, 4098, 0, false},
		{[]byte{1, 0, 20, 0, 10}, []byte{1, 2, 0b0000_0100, 0b10}, 22, 1, true},
		{[]byte{1, 0, 20, 0, 10}, []byte{1, 2, 0b0000_0100, 0b10}, 29, 1, true},
		{[]byte{1, 0, 20, 0, 10}, []byte{1, 2, 0b0000_0100, 0b10}, 21, 0, true},
		{regs, []byte{0x83, 2}, 4096, 0, false},
	}
	for i, c := range cases {
		if v, ok := ValueAt(c.req, c.resp, c.addr); v != c.v || ok != c.ok {
			t.Errorf("%d: %d %v", i, v, ok)
		}
	}
}

// TestCoverageDoc keeps docs/COVERAGE.md generated from the table. Run
// with MBTRACE_UPDATE=1 to rewrite it.
func TestCoverageDoc(t *testing.T) {
	var b bytes.Buffer
	b.WriteString("# Function coverage\n\nGenerated from `mbtcp`'s table by `TestCoverageDoc` (`make golden`); do not edit.\n\n")
	b.WriteString("Every function below is decoded and validated as a request and as a response; exception responses are decoded for every function code. Any other code (the user-defined ranges 65-72 and 100-110, vendor and unknown codes) is kept opaque: its function code and data bytes. `Class` is what the function does to the device; `MBCAP` is its admission (`MBCAP-EXPORT.md` section 3; `sub`: it depends on the FC08 sub-function or the FC43 MEI type); `Serial` marks a function normally limited to serial lines, flagged `serial_function_over_tcp` when seen over TCP.\n\n")
	b.WriteString("| FC | Name | Class | Serial | MBCAP | Request fields | Response fields |\n|---|---|---|---|---|---|---|\n")
	for _, f := range Coverage() {
		serial := ""
		if f.SerialOnly {
			serial = "yes"
		}
		fmt.Fprintf(&b, "| %d | %s | %s | %s | %s | %s | %s |\n", f.Code, f.Name, f.Class, serial, f.MBCAP,
			strings.Join(f.Request, ", "), strings.Join(f.Response, ", "))
	}
	b.WriteString("\nFC08 sub-functions decoded by name: ")
	var subs []string
	for code := uint16(0); code <= 0x14; code++ {
		if s, ok := diagSubs[code]; ok {
			adm := ""
			if DiagnosticsAdmissible(code) {
				adm = ", read"
			}
			subs = append(subs, fmt.Sprintf("%d %s%s", code, s.name, adm))
		}
	}
	b.WriteString(strings.Join(subs, "; ") + ". FC43: MEI type 14 (Read Device Identification) is decoded; type 13 (CANopen) is opaque.\n")
	const path = "../docs/COVERAGE.md"
	if os.Getenv("MBTRACE_UPDATE") != "" {
		if err := os.WriteFile(path, b.Bytes(), 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	have, err := os.ReadFile(path)
	have = bytes.ReplaceAll(have, []byte("\r\n"), []byte("\n")) // a Windows checkout may convert line endings
	if err != nil || !bytes.Equal(have, b.Bytes()) {
		t.Fatalf("docs/COVERAGE.md is not up to date: run make golden (%v)", err)
	}
}

func FuzzDecodeRequest(f *testing.F) {
	for code := range functions {
		f.Add(samplePDU(code, AsRequest))
	}
	f.Fuzz(func(t *testing.T, pdu []byte) {
		v := Decode(AsRequest, pdu)
		for _, x := range v.Fields {
			if x.Offset < HeaderLen || x.Offset+x.Length > HeaderLen+len(pdu) {
				t.Fatalf("field %s out of the PDU", x.Name)
			}
		}
		_ = Summary(v, nil)
	})
}

func FuzzDecodeResponse(f *testing.F) {
	for code := range functions {
		f.Add(samplePDU(code, AsRequest), samplePDU(code, AsResponse))
	}
	f.Fuzz(func(t *testing.T, req, resp []byte) {
		rq, rs := Decode(AsRequest, req), Decode(AsResponse, resp)
		CheckPair(req, rq, resp, &rs)
		for _, x := range rs.Fields {
			if x.Offset < HeaderLen || x.Offset+x.Length > HeaderLen+len(resp) {
				t.Fatalf("field %s out of the PDU", x.Name)
			}
		}
		_ = Summary(rq, &rs)
		for a := range uint16(8) {
			ValueAt(req, resp, a)
		}
	})
}
