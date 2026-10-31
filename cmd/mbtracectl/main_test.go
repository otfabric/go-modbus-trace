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
		{"too many arguments", []string{"version", "extra"}, nil, exitUsage},
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
	if code != exitOK || !strings.Contains(out, "transactions: ok=4") || !strings.Contains(out, "10.0.0.2:1502  1") ||
		!strings.Contains(out, "Read 2 holding registers @ 100") || !strings.Contains(out, "holding: 100-101") {
		t.Fatalf("exit %d, stderr %q, output:\n%s", code, errs, out)
	}
	code, out, _ = cli(t, nil, "summary", "--json", "--fc", "3", path)
	var doc struct {
		Selection string `json:"selection"`
		Devices   struct {
			Devices []struct {
				Server       string `json:"server"`
				Transactions int    `json:"transactions"`
			} `json:"devices"`
		} `json:"devices"`
		Patterns struct {
			Patterns []struct {
				Count int `json:"count"`
			} `json:"patterns"`
		} `json:"patterns"`
	}
	if err := json.Unmarshal([]byte(out), &doc); err != nil || code != exitOK {
		t.Fatalf("%v %d", err, code)
	}
	if doc.Selection != "fc=3" || len(doc.Devices.Devices) != 1 || doc.Devices.Devices[0].Transactions != 4 || doc.Patterns.Patterns[0].Count != 4 {
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

func TestExportMBCAP(t *testing.T) {
	path, data := fixture(t)
	dir := filepath.Dir(path)
	out, rep := filepath.Join(dir, "site.mbcap"), filepath.Join(dir, "site.report.json")
	code, stdout, errs := cli(t, nil, "export", "mbcap", path, "-o", out, "--report", rep, "--name", "10.0.0.2:1502/1=Pump")
	if code != exitOK || !strings.Contains(stdout, "4 samples written") || !strings.Contains(stdout, "Pump") {
		t.Fatalf("exit %d, %s\n%s", code, errs, stdout)
	}
	var r struct {
		SamplesWritten int `json:"samples_written"`
	}
	b, _ := os.ReadFile(rep)
	if err := json.Unmarshal(b, &r); err != nil || r.SamplesWritten != 4 {
		t.Errorf("report %s", b)
	}
	if b, _ := os.ReadFile(out); !bytes.HasPrefix(b, []byte("\x89MBCAP")) {
		t.Errorf("not a binary capture: % x", b[:min(8, len(b))])
	}
	// stdin streaming to JSON Lines on stdout.
	code, stdout, _ = cli(t, data, "export", "mbcap", "-", "-o", "-")
	if code != exitOK || !strings.HasPrefix(stdout, "{") || strings.Count(stdout, "\n") < 7 {
		t.Errorf("stdin: exit %d\n%s", code, stdout)
	}
	// Several inputs are one trace; - cannot join them.
	if code, _, errs := cli(t, nil, "export", "mbcap", path, path, "-o", filepath.Join(dir, "two.mbcap.jsonl")); code != exitOK {
		t.Errorf("two inputs: exit %d %s", code, errs)
	}
	for _, bad := range [][]string{
		{path, "-", "-o", filepath.Join(dir, "x.mbcap")},
		{path, "-o", path, "--format", "jsonl"},
		{path, "-o", filepath.Join(dir, "x.txt")},
		{path, "-o", filepath.Join(dir, "x.mbcap"), "--tick-ns", "0"},
		{path, "-o", filepath.Join(dir, "x.mbcap"), "--name", "Pump"},
		{path, "-o", filepath.Join(dir, "x.mbcap"), "--warn-replay-memory", "lots"},
		{path, "-o", filepath.Join(dir, "x.mbcap"), "--compression", "zip"},
		{path},
	} {
		if code, _, _ := cli(t, nil, append([]string{"export", "mbcap"}, bad...)...); code != exitUsage {
			t.Errorf("%v: exit %d", bad, code)
		}
	}
	// A failure leaves no output behind.
	if code, _, _ := cli(t, []byte("garbage"), "export", "mbcap", "-", "-o", filepath.Join(dir, "bad.mbcap")); code != exitError {
		t.Errorf("garbage: exit %d", code)
	}
	if _, err := os.Stat(filepath.Join(dir, "bad.mbcap")); err == nil {
		t.Error("partial output left behind")
	}
}

func TestExtract(t *testing.T) {
	path, _ := fixture(t)
	out := filepath.Join(filepath.Dir(path), "sub.pcapng")
	code, stdout, errs := cli(t, nil, "extract", path, "-o", out, "--conn", "1")
	if code != exitOK || !strings.Contains(stdout, "of 1 connection written") {
		t.Fatalf("exit %d %s %s", code, errs, stdout)
	}
	code, stdout, _ = cli(t, nil, "flows", "--json", out)
	if code != exitOK || !strings.Contains(stdout, `"modbus_tcp"`) || strings.Contains(stdout, `"10.0.0.3:80"`) {
		t.Errorf("the sub-trace: %s", stdout)
	}
	if code, _, _ := cli(t, nil, "extract", path, "-o", path); code != exitUsage {
		t.Errorf("output = input: exit %d", code)
	}
	if code, _, _ := cli(t, nil, "extract", path); code != exitUsage {
		t.Errorf("no output: exit %d", code)
	}
}

// The flag checks of every command, before any file is read.
func TestBadFlags(t *testing.T) {
	path, _ := fixture(t)
	out := filepath.Join(t.TempDir(), "o.pcapng")
	for _, args := range [][]string{
		{"info", "--server-port", "0", path},
		{"info", "--server-port", "70000", path},
		{"info", "--client", "not-an-ip", path},
		{"flows", "--client", "not-an-ip", path},
		{"summary", "--server", "not-an-ip", path},
		{"summary", "--from", "soon", path},
		{"timeline", "--server", "not-an-ip", path},
		{"timeline", "--from", "soon", path},
		{"extract", path},
		{"extract", "-o", out, "--from", "soon", path},
		{"extract", "-o", out, "--server", "not-an-ip", path},
	} {
		t.Run(strings.Join(args[:2], " "), func(t *testing.T) {
			if code, _, errs := cli(t, nil, args...); code != exitUsage {
				t.Errorf("%v: exit %d, want %d (stderr %q)", args, code, exitUsage, errs)
			}
		})
	}
}

// Missing inputs are failures of the run in every command, not usage errors.
func TestMissingInput(t *testing.T) {
	missing := "/nonexistent/x.pcap"
	out := filepath.Join(t.TempDir(), "o.pcapng")
	for _, args := range [][]string{
		{"flows", missing},
		{"summary", missing},
		{"timeline", missing},
		{"extract", "-o", out, missing},
	} {
		if code, _, _ := cli(t, nil, args...); code != exitError {
			t.Errorf("%v: exit %d, want %d", args, code, exitError)
		}
	}
	if _, err := os.Stat(out); err == nil {
		t.Error("extract left an output behind")
	}
}

// A trace without Modbus says so and says how to see the rest.
func TestNoModbusFlows(t *testing.T) {
	var buf bytes.Buffer
	b, err := tracetest.New(&buf, tracetest.Options{})
	if err != nil {
		t.Fatal(err)
	}
	h := b.Conn(tracetest.ConnOptions{Client: netip.MustParseAddrPort("10.0.0.1:40001"), Server: netip.MustParseAddrPort("10.0.0.3:80")})
	h.Write(tracetest.ToServer, tracetest.WriteOpts{}, tracetest.Frame{Raw: []byte("GET / HTTP/1.1\r\n\r\n")})
	h.Close()
	if err := b.Close(); err != nil {
		t.Fatal(err)
	}
	code, out, _ := cli(t, buf.Bytes(), "flows", "-")
	if code != exitOK || !strings.Contains(out, "no Modbus/TCP flows") {
		t.Errorf("exit %d:\n%s", code, out)
	}
}

// Progress mode leaves stdout as it is.
func TestProgress(t *testing.T) {
	path, _ := fixture(t)
	_, want, _ := cli(t, nil, "flows", path)
	var stdout, stderr bytes.Buffer
	code := run(context.Background(), []string{"flows", path}, strings.NewReader(""), &stdout, &stderr, true)
	if code != exitOK || stdout.String() != want {
		t.Fatalf("exit %d, stdout:\n%s", code, stdout.String())
	}
}
