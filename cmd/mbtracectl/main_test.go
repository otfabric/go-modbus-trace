// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"encoding/binary"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

// fixture writes a small trace: one Modbus connection on port 1502 (found
// by its traffic), one HTTP connection.
func fixture(t *testing.T) (string, []byte) {
	t.Helper()
	var buf bytes.Buffer
	b, err := tracetest.New(&buf, tracetest.Options{Format: tracetest.PcapNG})
	if err != nil {
		t.Fatal(err)
	}
	c := b.Conn(tracetest.ConnOptions{Server: netip.MustParseAddrPort("10.0.0.2:1502")})
	for i := range 4 {
		c.Request(uint16(i), 1, tracetest.ReadRequest(3, 100, 2))
		c.Response(uint16(i), 1, tracetest.RegistersResponse(3, 1, 2))
	}
	c.Close()
	h := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.1:40001"), Server: netip.MustParseAddrPort("10.0.0.3:80")})
	h.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: []byte("GET / HTTP/1.1\r\n\r\n")})
	h.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(t.TempDir(), "site.pcapng")
	if err := os.WriteFile(path, buf.Bytes(), 0o600); err != nil {
		t.Fatal(err)
	}
	return path, buf.Bytes()
}

func cli(t *testing.T, stdin []byte, args ...string) (int, string, string) {
	t.Helper()
	var out, errw bytes.Buffer
	code := run(context.Background(), args, bytes.NewReader(stdin), &out, &errw, false)
	return code, out.String(), errw.String()
}

func TestInfo(t *testing.T) {
	path, _ := fixture(t)
	code, out, errs := cli(t, nil, "info", path)
	if code != exitOK || errs != "" {
		t.Fatalf("exit %d, stderr %q", code, errs)
	}
	for _, want := range []string{"site.pcapng (pcapng", "2 TCP, 1 Modbus/TCP", "interface    0: ethernet"} {
		if !strings.Contains(out, want) {
			t.Errorf("output lacks %q:\n%s", want, out)
		}
	}
}

func TestFlowsJSONAndStdin(t *testing.T) {
	path, data := fixture(t)
	code, fromFile, _ := cli(t, nil, "flows", "--json", path)
	if code != exitOK {
		t.Fatalf("exit %d", code)
	}
	var doc struct {
		SchemaVersion int `json:"schema_version"`
		Flows         []struct {
			B     string  `json:"b"`
			Class string  `json:"class"`
			Role  string  `json:"role_source"`
			Score float64 `json:"score"`
		} `json:"flows"`
	}
	if err := json.Unmarshal([]byte(fromFile), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SchemaVersion != 1 || len(doc.Flows) != 1 || doc.Flows[0].B != "10.0.0.2:1502" || doc.Flows[0].Class != "modbus_tcp" {
		t.Errorf("flows %+v", doc)
	}
	_, fromStdin, _ := cli(t, data, "flows", "--json", "-")
	if fromStdin != fromFile {
		t.Errorf("stdin and file differ:\n%s\n%s", fromStdin, fromFile)
	}
	if _, all, _ := cli(t, nil, "flows", "--all", path); !strings.Contains(all, "other_tcp") {
		t.Errorf("--all lacks the HTTP flow:\n%s", all)
	}
}

func TestExitCodes(t *testing.T) {
	path, data := fixture(t)
	cases := []struct {
		name string
		args []string
		in   []byte
		code int
	}{
		{"no command", nil, nil, exitOK}, // help
		{"unknown flag", []string{"info", "--nope", path}, nil, exitUsage},
		{"missing argument", []string{"flows"}, nil, exitUsage},
		{"too many arguments", []string{"flows", path, path}, nil, exitUsage},
		{"bad endpoint", []string{"flows", "--server", "not-an-ip", path}, nil, exitUsage},
		{"bad score", []string{"flows", "--min-score", "2", path}, nil, exitUsage},
		{"missing file", []string{"info", "/nonexistent/x.pcap"}, nil, exitError},
		{"not a trace", []string{"info", "-"}, []byte("hello, world"), exitError},
		{"damaged trace: results and an error", []string{"info", "-"}, damage(data), exitError},
		{"version", []string{"version"}, nil, exitOK},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if code, _, errs := cli(t, tc.in, tc.args...); code != tc.code {
				t.Errorf("exit %d, want %d (stderr %q)", code, tc.code, errs)
			}
		})
	}
}

// damage gives the first block past the middle an impossible length.
func damage(b []byte) []byte {
	b = append([]byte(nil), b...)
	for off := 0; off+8 <= len(b); {
		n := int(binary.LittleEndian.Uint32(b[off+4:]))
		if off > len(b)/2 {
			binary.LittleEndian.PutUint32(b[off+4:], 0xFFFFFFF0)
			return b
		}
		off += n
	}
	panic("no block past the middle")
}

func TestEnvironment(t *testing.T) {
	path, _ := fixture(t)
	t.Setenv("MBTRACECTL_JSON", "true")
	t.Setenv("MBTRACECTL_SERVER_PORT", "1502")
	code, out, _ := cli(t, nil, "flows", path)
	if code != exitOK || !strings.HasPrefix(out, "{") {
		t.Fatalf("exit %d, output %q", code, out)
	}
	t.Setenv("MBTRACECTL_MIN_SCORE", "x")
	if code, _, _ := cli(t, nil, "flows", path); code != exitUsage {
		t.Errorf("a bad environment value: exit %d", code)
	}
}

func TestSummary(t *testing.T) {
	path, _ := fixture(t)
	code, out, errs := cli(t, nil, "summary", path)
	if code != exitOK || !strings.Contains(out, "transactions: ok=4") || !strings.Contains(out, "10.0.0.2:1502  1") {
		t.Fatalf("exit %d, stderr %q, output:\n%s", code, errs, out)
	}
	code, out, _ = cli(t, nil, "summary", "--json", "--fc", "3", path)
	var doc struct {
		Selection string `json:"selection"`
		Devices   []struct {
			Server       string `json:"server"`
			Transactions int    `json:"transactions"`
		} `json:"devices"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != exitOK {
		t.Fatalf("%v %d", err, code)
	}
	if doc.Selection != "fc=3" || len(doc.Devices) != 1 || doc.Devices[0].Transactions != 4 {
		t.Errorf("%+v", doc)
	}
}

func TestTimeline(t *testing.T) {
	path, data := fixture(t)
	code, out, _ := cli(t, nil, "timeline", path)
	if code != exitOK || strings.Count(out, "Read 2 holding registers @ 100") != 4 {
		t.Fatalf("exit %d:\n%s", code, out)
	}
	_, csvOut, _ := cli(t, nil, "timeline", "--format", "csv", "--tid-not-a-flag", path)
	if csvOut != "" {
		t.Error("an unknown flag must not write output")
	}
	_, fromFile, _ := cli(t, nil, "timeline", "--format", "jsonl", path)
	_, fromStdin, _ := cli(t, data, "timeline", "--format", "jsonl", "-")
	if fromFile == "" || fromFile != fromStdin {
		t.Error("stdin and file differ")
	}
	if code, _, _ := cli(t, nil, "timeline", "--order", "sideways", path); code != exitUsage {
		t.Errorf("bad --order: exit %d", code)
	}
	if code, _, _ := cli(t, nil, "timeline", "--range", "holding:9-1", path); code != exitUsage {
		t.Errorf("bad --range: exit %d", code)
	}
}

func TestExportTimeline(t *testing.T) {
	path, _ := fixture(t)
	dir := filepath.Dir(path)
	out := filepath.Join(dir, "tl.csv")
	if code, _, errs := cli(t, nil, "export", "timeline", path, "-o", out, "--status", "ok"); code != exitOK {
		t.Fatalf("exit %d: %s", code, errs)
	}
	b, _ := os.ReadFile(out)
	if !strings.HasPrefix(string(b), "kind,seq,time,") || strings.Count(string(b), "\ntxn,") != 4 {
		t.Errorf("csv:\n%s", b)
	}
	if code, _, _ := cli(t, nil, "export", "timeline", path, "-o", path, "--format", "jsonl"); code != exitUsage {
		t.Errorf("output = input: exit %d", code)
	}
	if code, _, _ := cli(t, nil, "export", "timeline", path, "-o", filepath.Join(dir, "x.txt")); code != exitUsage {
		t.Errorf("unknown extension: exit %d", code)
	}
	// A failure leaves no partial output, and no temporary file.
	bad := filepath.Join(dir, "bad.jsonl")
	if code, _, _ := cli(t, []byte("not a trace at all"), "export", "timeline", "-", "-o", bad); code != exitError {
		t.Errorf("bad input: exit %d", code)
	}
	entries, _ := os.ReadDir(dir)
	for _, e := range entries {
		if e.Name() == "bad.jsonl" || strings.HasSuffix(e.Name(), ".tmp") {
			t.Errorf("left behind: %s", e.Name())
		}
	}
}

func TestSelectionFlags(t *testing.T) {
	path, _ := fixture(t)
	good := [][]string{
		{"--client", "10.0.0.1", "--unit", "1", "--conn", "1", "--fc", "0x03", "--status", "ok", "--class", "read", "--no-flag", "slow"},
		{"--from-time", "2026-10-15T08:00:00Z", "--to-time", "2027-01-01T00:00:00Z", "--range", "holding:100-101"},
		{"--from", "0s", "--to", "1h", "--server", "10.0.0.2:1502", "--slow", "2s"},
	}
	for _, g := range good {
		code, out, errs := cli(t, nil, append([]string{"timeline", path}, g...)...)
		if code != exitOK || strings.Count(out, "Read 2 holding registers") != 4 {
			t.Errorf("%v: exit %d, %s\n%s", g, code, errs, out)
		}
	}
	bad := [][]string{
		{"--client", "nope"}, {"--unit", "300"}, {"--conn", "x"}, {"--fc", "256"}, {"--from", "-1s"}, {"--to-time", "yesterday"},
		{"--from", "1s", "--from-time", "2026-10-15T08:00:00Z"}, {"--range", "registers:1-2"}, {"--slow", "0s"}, {"--window", "0s"},
		{"--server-port", "0"},
	}
	for _, b := range bad {
		if code, _, _ := cli(t, nil, append([]string{"timeline", path}, b...)...); code != exitUsage {
			t.Errorf("%v: exit %d", b, code)
		}
	}
}
