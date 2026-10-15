// SPDX-License-Identifier: MIT

package policy

import (
	"bytes"
	"encoding/json"
	"io"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// forbidden lists import paths that no non-test package of the module may
// depend on, directly or indirectly, with the reason.
var forbidden = map[string]string{
	"net/http":                      "offline only (L20)",
	"os/exec":                       "the library runs no programs (AGENTS.md)",
	"plugin":                        "pure Go (L19)",
	"golang.org/x/sys/unix":         "no raw sockets or live capture (AGENTS.md)",
	"golang.org/x/net/bpf":          "no live capture (AGENTS.md)",
	"github.com/gopacket/gopacket":  "not a dependency (docs/DECISIONS.md)",
	"github.com/google/gopacket":    "not a dependency (docs/DECISIONS.md)",
	"github.com/otfabric/go-modbus": "test-only dependency (ARCHITECTURE.md section 3)",
}

// cliOnly may appear in the dependencies of cmd/ only.
var cliOnly = map[string]bool{"os/exec": true}

type pkg struct {
	ImportPath string
	Standard   bool
	CgoFiles   []string
	Deps       []string
}

// list runs `go list -deps -json` for the module's non-test packages with
// CGO_ENABLED=1, so that a package with cgo files would show them.
func list(t *testing.T, patterns ...string) []pkg {
	t.Helper()
	root, err := filepath.Abs(filepath.Join("..", ".."))
	if err != nil {
		t.Fatal(err)
	}
	args := append([]string{"list", "-deps", "-json"}, patterns...)
	cmd := exec.Command("go", args...)
	cmd.Dir = root
	cmd.Env = append(cmd.Environ(), "CGO_ENABLED=1", "GOWORK=off", "GOFLAGS=-mod=mod")
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, stderr.String())
	}
	var pkgs []pkg
	dec := json.NewDecoder(bytes.NewReader(out))
	for {
		var p pkg
		if err := dec.Decode(&p); err == io.EOF {
			break
		} else if err != nil {
			t.Fatal(err)
		}
		pkgs = append(pkgs, p)
	}
	return pkgs
}

func forbiddenFor(path string) (string, bool) {
	for f, why := range forbidden {
		if path == f || strings.HasPrefix(path, f+"/") {
			return why, true
		}
	}
	return "", false
}

func TestNoForbiddenDependencies(t *testing.T) {
	const module = "github.com/otfabric/go-modbus-trace"
	for _, p := range list(t, "./...") {
		if p.Standard || !strings.HasPrefix(p.ImportPath, module) {
			continue
		}
		cli := strings.HasPrefix(p.ImportPath, module+"/cmd/")
		for _, d := range append([]string{p.ImportPath}, p.Deps...) {
			why, bad := forbiddenFor(d)
			if bad && (!cli || !cliOnly[d]) {
				t.Errorf("%s depends on %s: %s", p.ImportPath, d, why)
			}
		}
	}
}

func TestNoCgo(t *testing.T) {
	for _, p := range list(t, "./...") {
		// runtime/cgo and the standard library's optional cgo files are not
		// linked with CGO_ENABLED=0; anything else with cgo files is.
		if p.Standard {
			continue
		}
		if len(p.CgoFiles) > 0 {
			t.Errorf("%s has cgo files %v: the module must build with CGO_ENABLED=0 (L19)", p.ImportPath, p.CgoFiles)
		}
	}
}
