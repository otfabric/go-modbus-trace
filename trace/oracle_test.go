// SPDX-License-Identifier: MIT

package trace

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"github.com/otfabric/go-modbus-trace/model"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// TestTsharkOracle is LA13, advisory: on the same trace, Wireshark's
// dissector agrees with our transactions on transaction ID, unit, function,
// reference number, count, exception code and request/response linking.
// It runs with MBTRACE_ORACLE=1 where tshark is installed (an advisory CI
// job); a disagreement is triaged by hand, not fixed automatically.
func TestTsharkOracle(t *testing.T) {
	if os.Getenv("MBTRACE_ORACLE") == "" {
		t.Skip("set MBTRACE_ORACLE=1 to compare with tshark")
	}
	tshark, err := exec.LookPath("tshark")
	if err != nil {
		t.Skip("tshark not installed")
	}
	fields := []string{"frame.number", "mbtcp.trans_id", "mbtcp.unit_id", "modbus.func_code", "modbus.reference_num",
		"modbus.word_cnt", "modbus.bit_cnt", "modbus.request_frame", "modbus.exception_code"}
	known, err := exec.Command(tshark, "-G", "fields").Output()
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range fields {
		if !bytes.Contains(known, []byte("\t"+f+"\t")) {
			t.Fatalf("this tshark has no field %s: update the mapping", f)
		}
	}
	data, _ := build(t, tracetest.Options{}, func(b *tracetest.Builder) {
		c := b.Conn(tracetest.ConnOptions{})
		c.Request(1, 1, tracetest.ReadRequest(3, 100, 4))
		c.Response(1, 1, tracetest.RegistersResponse(3, 1, 2, 3, 4))
		c.Request(2, 2, tracetest.ReadRequest(1, 20, 10))
		c.Response(2, 2, []byte{1, 2, 0xFF, 0x03})
		c.Request(3, 1, tracetest.ReadRequest(4, 7, 1))
		c.Response(3, 1, tracetest.Exception(4, 2))
		c.Request(4, 1, []byte{16, 0, 30, 0, 2, 4, 0, 1, 0, 2})
		c.Response(4, 1, []byte{16, 0, 30, 0, 2})
		c.Request(5, 1, tracetest.ReadRequest(2, 0, 8))
		c.Request(6, 1, tracetest.ReadRequest(3, 0, 1))
		c.Response(6, 1, tracetest.RegistersResponse(3, 9))
		c.Response(5, 1, []byte{2, 1, 0x5A})
		c.Close()
	})
	path := filepath.Join(t.TempDir(), "o.pcap")
	if err := os.WriteFile(path, data, 0o600); err != nil {
		t.Fatal(err)
	}
	args := []string{"-r", path, "-Y", "mbtcp", "-T", "fields", "-E", "separator=/t"}
	for _, f := range fields {
		args = append(args, "-e", f)
	}
	out, err := exec.Command(tshark, args...).Output()
	if err != nil {
		t.Fatal(err)
	}
	rows := map[uint64][]string{}
	for _, l := range strings.Split(strings.TrimSpace(string(out)), "\n") {
		r := strings.Split(l, "\t")
		n, _ := strconv.ParseUint(r[0], 10, 64)
		rows[n] = r
	}
	_, evs := analyze(t, data, Options{})
	n := 0
	for _, tx := range txns(evs) {
		if tx.Request == nil || tx.Response == nil {
			continue
		}
		n++
		qf, rf := tx.Request.Refs[0].Frame, tx.Response.Refs[0].Frame
		q, r := rows[qf], rows[rf]
		if q == nil || r == nil {
			t.Errorf("tid %d: tshark has no Modbus/TCP rows for frames %d and %d", tx.TID, qf, rf)
			continue
		}
		u := strconv.Itoa
		check := func(what, theirs, ours string) {
			if theirs != ours {
				t.Errorf("tid %d %s: tshark %q, ours %q", tx.TID, what, theirs, ours)
			}
		}
		check("transaction ID", q[1], u(int(tx.TID)))
		check("unit", q[2], u(int(tx.Unit)))
		check("function", q[3], u(int(tx.Function)))
		if len(tx.Ranges) > 0 && tx.Function != 16 {
			check("reference", q[4], u(int(tx.Ranges[0].Start)))
			cnt := q[5]
			if tx.Function <= 2 {
				cnt = q[6]
			}
			check("count", cnt, u(int(tx.Ranges[0].Count)))
		}
		if tx.Status == model.StatusException {
			// Triaged (L4): tshark 4.6 does not link an exception response to
			// its request (modbus.request_frame is empty); only the code is
			// compared.
			check("exception", r[8], u(int(tx.Exception)))
		} else {
			check("request frame", r[7], strconv.FormatUint(qf, 10))
		}
	}
	if n != 6 {
		t.Errorf("%d paired transactions compared", n)
	}
}
