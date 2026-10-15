// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/netip"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/otfabric/go-modbus-trace/export/timeline"
	"github.com/otfabric/go-modbus-trace/trace"
	"github.com/otfabric/go-modbus-trace/trace/tracetest"
)

const plant = "../../testdata/plant.pcapng"

// goldenFile holds the SHA-256 of every output of the plant fixture. CI runs
// this test on every target's own runner, so the same bytes on all of them
// is L21's cross-platform determinism. MBTRACE_UPDATE=1 (make golden)
// rewrites it.
const goldenFile = "../../testdata/plant.outputs.json"

func TestGoldenOutputs(t *testing.T) {
	dir := t.TempDir()
	outputs := map[string][]string{
		// Uncompressed: deflate output may change between Go releases.
		"export.mbcap":             {"export", "mbcap", plant, "-o", "OUT.mbcap", "--report", "REPORT", "--compression", "none"},
		"export.mbcap.jsonl":       {"export", "mbcap", plant, "-o", "OUT.mbcap.jsonl"},
		"export.mbcap.csv":         {"export", "mbcap", plant, "-o", "OUT.mbcap.csv"},
		"export.timeline.csv":      {"export", "timeline", plant, "-o", "OUT.csv"},
		"export.timeline.jsonl":    {"export", "timeline", plant, "-o", "OUT.jsonl"},
		"extract.pcapng":           {"extract", plant, "-o", "OUT.pcapng", "--server", "10.0.0.2:502"},
		"summary.json":             {"summary", "--json", plant},
		"flows.json":               {"flows", "--json", plant},
		"export.mbcap.report.json": nil, // written by the first command
	}
	got := map[string]string{}
	for name, args := range outputs {
		if args == nil {
			continue
		}
		var out string
		for i, a := range args {
			switch {
			case strings.HasPrefix(a, "OUT"):
				out = filepath.Join(dir, name)
				args[i] = out
			case a == "REPORT":
				args[i] = filepath.Join(dir, "export.mbcap.report.json")
			}
		}
		code, stdout, errs := cli(t, nil, args...)
		if code != exitOK {
			t.Fatalf("%v: exit %d %s", args, code, errs)
		}
		b := []byte(stdout)
		if out != "" {
			var err error
			if b, err = os.ReadFile(out); err != nil {
				t.Fatal(err)
			}
		}
		got[name] = hash(b)
	}
	b, err := os.ReadFile(filepath.Join(dir, "export.mbcap.report.json"))
	if err != nil {
		t.Fatal(err)
	}
	got["export.mbcap.report.json"] = hash(b)

	enc, _ := json.MarshalIndent(got, "", "  ")
	enc = append(enc, '\n')
	if os.Getenv("MBTRACE_UPDATE") != "" {
		if err := os.WriteFile(goldenFile, enc, 0o644); err != nil {
			t.Fatal(err)
		}
		return
	}
	want := map[string]string{}
	wb, err := os.ReadFile(goldenFile)
	if err != nil {
		t.Fatalf("%v: run make golden", err)
	}
	if err := json.Unmarshal(wb, &want); err != nil {
		t.Fatal(err)
	}
	for name, h := range got {
		if want[name] != h {
			t.Errorf("%s differs from %s (a platform difference, or run make golden after a reviewed change)", name, goldenFile)
		}
	}
}

func hash(b []byte) string {
	s := sha256.Sum256(b)
	return hex.EncodeToString(s[:])
}

// TestCLIEqualsLibrary: the CLI writes what the library writes (LA11).
func TestCLIEqualsLibrary(t *testing.T) {
	f, err := trace.Open(plant)
	if err != nil {
		t.Fatal(err)
	}
	var lib bytes.Buffer
	if _, _, err := timeline.Write(context.Background(), f, trace.Options{}, &lib, timeline.Options{Format: timeline.JSONL, Order: timeline.ByTime}); err != nil {
		t.Fatal(err)
	}
	code, out, errs := cli(t, nil, "timeline", "--format", "jsonl", plant)
	if code != exitOK || out != lib.String() {
		t.Errorf("exit %d %s: the CLI's timeline differs from the library's", code, errs)
	}
}

// TestInputsCLI: several files are one trace, stdin exports to a file, and
// an output that would overwrite an input is refused.
func TestInputsCLI(t *testing.T) {
	dir := t.TempDir()
	var whole, a, b bytes.Buffer
	wb, _ := tracetest.New(&whole, tracetest.Options{})
	ab, _ := tracetest.New(&a, tracetest.Options{})
	bb, _ := tracetest.New(&b, tracetest.Options{})
	for _, pair := range [][2]*tracetest.Builder{{wb, wb}, {ab, bb}} {
		c := pair[0].Conn(tracetest.ConnOptions{Server: netip.MustParseAddrPort("10.0.0.2:502")})
		for i := range 6 {
			if i == 3 && pair[1] != pair[0] {
				c = pair[1].ConnContinue(c)
			}
			c.Request(uint16(i), 1, tracetest.ReadRequest(3, 0, 1))
			c.Response(uint16(i), 1, tracetest.RegistersResponse(3, uint16(i)))
		}
		c.Close()
	}
	for _, x := range []*tracetest.Builder{wb, ab, bb} {
		if err := x.Close(); err != nil {
			t.Fatal(err)
		}
	}
	pw, pa, pb := filepath.Join(dir, "whole.pcap"), filepath.Join(dir, "a.pcap"), filepath.Join(dir, "b.pcap")
	for p, d := range map[string][]byte{pw: whole.Bytes(), pa: a.Bytes(), pb: b.Bytes()} {
		if err := os.WriteFile(p, d, 0o600); err != nil {
			t.Fatal(err)
		}
	}
	_, one, _ := cli(t, nil, "timeline", "--format", "jsonl", pw)
	code, two, errs := cli(t, nil, "timeline", "--format", "jsonl", pa, pb)
	strip := func(s string) string { // frame references name their file; nothing else may differ
		var out []string
		for _, l := range strings.Split(s, "\n") {
			var e map[string]any
			if json.Unmarshal([]byte(l), &e) != nil {
				continue
			}
			if x, ok := e["txn"].(map[string]any); ok {
				out = append(out, x["status"].(string)+" "+x["summary"].(string))
			}
		}
		return strings.Join(out, "\n")
	}
	if code != exitOK || strip(one) != strip(two) || strings.Count(strip(two), "ok ") != 6 {
		t.Errorf("exit %d %s\nwhole:\n%s\nsplit:\n%s", code, errs, strip(one), strip(two))
	}

	// stdin to a file.
	out := filepath.Join(dir, "in.mbcap")
	if code, _, errs := cli(t, whole.Bytes(), "export", "mbcap", "-", "-o", out); code != exitOK {
		t.Fatalf("stdin: exit %d %s", code, errs)
	}
	if b, _ := os.ReadFile(out); !bytes.HasPrefix(b, []byte("\x89MBCAP")) {
		t.Error("stdin export is not a capture")
	}
	// A report over an input is refused, and the input survives.
	if code, _, _ := cli(t, nil, "export", "mbcap", pw, "-o", filepath.Join(dir, "x.mbcap"), "--report", pw); code != exitUsage {
		t.Errorf("report over the input: exit %d", code)
	}
	if b, _ := os.ReadFile(pw); !bytes.Equal(b, whole.Bytes()) {
		t.Error("the input was changed")
	}
}

type brokenPipe struct{ n int }

func (b *brokenPipe) Write(p []byte) (int, error) {
	if b.n <= 0 {
		return 0, os.ErrClosed
	}
	b.n--
	return len(p), nil
}

// TestWriteErrors: a report printed line by line fails the command when
// its output goes away (a closed pipe), instead of exiting 0.
func TestWriteErrors(t *testing.T) {
	for _, args := range [][]string{{"summary", plant}, {"export", "mbcap", plant, "-o", filepath.Join(t.TempDir(), "x.mbcap")}} {
		var errw bytes.Buffer
		if code := run(context.Background(), args, bytes.NewReader(nil), &brokenPipe{n: 1}, &errw, false); code != exitError {
			t.Errorf("%v: exit %d with a broken stdout", args[0], code)
		}
	}
}
