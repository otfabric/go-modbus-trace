// SPDX-License-Identifier: MIT

package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/santhosh-tekuri/jsonschema/v6"

	"github.com/otfabric/go-modbus-trace/export/mbcapexport"
	"github.com/otfabric/go-modbus-trace/internal/schemagen"
	"github.com/otfabric/go-modbus-trace/trace"
)

// schemas are generated from the types (L22); `make golden` rewrites them.
var schemas = []struct {
	name, title, desc string
	v                 any
}{
	{"file-summary-1", "go-modbus-trace file summary", "trace.FileSummary: what Scan and Analyze report about the input.", trace.FileSummary{}},
	{"info-1", "mbtracectl info --json", "The file summary and flow counts of each input.", infoDoc{}},
	{"flows-1", "mbtracectl flows --json", "The TCP flows with their Modbus assessment.", flowsDoc{}},
	{"summary-1", "mbtracectl summary --json", "The file summary and the analyzers: overview, devices, patterns, coverage.", summaryJSON{}},
	{"export-report-1", "MBCAP export report", "mbcapexport.Report (MBCAP-EXPORT.md section 5); mbtracectl export mbcap --report and --json.", mbcapexport.Report{}},
	{"extract-1", "mbtracectl extract --json", "What a sub-trace extraction wrote.", extractDoc{}},
	{"version-1", "mbtracectl version --json", "The build of mbtracectl.", versionDoc{}},
}

func schemaPath(name string) string {
	return filepath.Join("..", "..", "docs", "schema", name+".schema.json")
}

// TestSchemasUpToDate: the published schemas are the generated ones.
func TestSchemasUpToDate(t *testing.T) {
	for _, s := range schemas {
		b, err := schemagen.Generate("https://github.com/otfabric/go-modbus-trace/docs/schema/"+s.name+".schema.json", s.title, s.desc, s.v)
		if err != nil {
			t.Fatal(err)
		}
		if os.Getenv("MBTRACE_UPDATE") != "" {
			if err := os.WriteFile(schemaPath(s.name), b, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		have, err := os.ReadFile(schemaPath(s.name))
		have = bytes.ReplaceAll(have, []byte("\r\n"), []byte("\n"))
		if err != nil || !bytes.Equal(have, b) {
			t.Errorf("docs/schema/%s.schema.json is not up to date: run make golden (%v)", s.name, err)
		}
	}
}

func compile(t *testing.T, name string) *jsonschema.Schema {
	t.Helper()
	raw, err := os.ReadFile(schemaPath(name))
	if err != nil {
		t.Fatal(err)
	}
	doc, err := jsonschema.UnmarshalJSON(bytes.NewReader(raw))
	if err != nil {
		t.Fatal(err)
	}
	c := jsonschema.NewCompiler()
	c.AssertFormat()
	if err := c.AddResource(name, doc); err != nil {
		t.Fatal(err)
	}
	s, err := c.Compile(name)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func validate(t *testing.T, name, out string) {
	t.Helper()
	v, err := jsonschema.UnmarshalJSON(strings.NewReader(out))
	if err != nil {
		t.Fatalf("%s: not JSON: %v\n%s", name, err, out)
	}
	if err := compile(t, name).Validate(v); err != nil {
		t.Errorf("%s does not validate: %v\n%s", name, err, out)
	}
}

// TestJSONOutputValidates is LA17's schema part: every --json output
// validates against its schema.
func TestJSONOutputValidates(t *testing.T) {
	path, _ := fixture(t)
	dir := filepath.Dir(path)
	run := func(args ...string) string {
		code, out, errs := cli(t, nil, args...)
		if code != exitOK {
			t.Fatalf("%v: exit %d %s", args, code, errs)
		}
		return out
	}
	validate(t, "info-1", run("info", "--json", path))
	validate(t, "flows-1", run("flows", "--json", "--all", path))
	validate(t, "summary-1", run("summary", "--json", path))
	validate(t, "version-1", run("version", "--json"))
	validate(t, "extract-1", run("extract", "--json", path, "-o", filepath.Join(dir, "s.pcapng")))
	rep := filepath.Join(dir, "r.json")
	validate(t, "export-report-1", run("export", "mbcap", "--json", path, "-o", filepath.Join(dir, "x.mbcap"), "--report", rep))
	b, _ := os.ReadFile(rep)
	validate(t, "export-report-1", string(b))
	// The file summary on its own (as the library returns it).
	sum := run("summary", "--json", path)
	start := strings.Index(sum, `"summary": {`) + len(`"summary": `)
	depth, end := 0, start
	for k := start; k < len(sum); k++ {
		switch sum[k] {
		case '{':
			depth++
		case '}':
			depth--
		}
		if depth == 0 {
			end = k + 1
			break
		}
	}
	validate(t, "file-summary-1", sum[start:end])
}
