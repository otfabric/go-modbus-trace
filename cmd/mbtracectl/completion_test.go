// SPDX-License-Identifier: MIT

package main

import (
	"encoding/json"
	"runtime"
	"slices"
	"strings"
	"testing"

	"github.com/spf13/cobra"
	"github.com/spf13/pflag"
)

// complete runs the hidden __complete command and returns the candidates
// (without descriptions) and the directive line.
func complete(t *testing.T, args ...string) ([]string, string) {
	t.Helper()
	code, out, errs := cli(t, nil, append([]string{"__complete"}, args...)...)
	if code != exitOK {
		t.Fatalf("__complete %v: exit %d %s", args, code, errs)
	}
	var got []string
	directive := ""
	for _, l := range strings.Split(strings.TrimSpace(out), "\n") {
		if strings.HasPrefix(l, ":") {
			directive = l
			continue
		}
		got = append(got, strings.SplitN(l, "\t", 2)[0])
	}
	return got, directive
}

func TestCompletionShells(t *testing.T) {
	got, _ := complete(t, "completion", "")
	for _, sh := range []string{"bash", "zsh", "fish", "powershell"} {
		if !slices.Contains(got, sh) {
			t.Errorf("completion lacks %s: %v", sh, got)
		}
		if code, out, errs := cli(t, nil, "completion", sh); code != exitOK || out == "" {
			t.Errorf("completion %s: exit %d, %d bytes, %s", sh, code, len(out), errs)
		}
	}
}

func TestCompletionFlagValues(t *testing.T) {
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"timeline", "--format", ""}, []string{"text", "csv", "jsonl"}},
		{[]string{"timeline", "--order", ""}, []string{"time", "file"}},
		{[]string{"summary", "--status", ""}, []string{"ok", "exception", "unanswered", "orphan_response", "ambiguous", "malformed", "uncertain"}},
		{[]string{"summary", "--class", ""}, []string{"read", "write", "other"}},
		{[]string{"summary", "--flag", ""}, qualityFlags},
		{[]string{"export", "timeline", "--format", ""}, []string{"csv", "jsonl"}},
		{[]string{"export", "mbcap", "--format", ""}, []string{"mbcap", "jsonl", "csv"}},
		{[]string{"export", "mbcap", "--compression", ""}, []string{"deflate", "none"}},
		{[]string{"export", "timeline", "--no-flag", ""}, qualityFlags},
	}
	for _, tc := range cases {
		got, dir := complete(t, tc.args...)
		if !slices.Equal(got, tc.want) {
			t.Errorf("%v: got %v, want %v", tc.args, got, tc.want)
		}
		if dir != ":4" { // ShellCompDirectiveNoFileComp
			t.Errorf("%v: directive %s", tc.args, dir)
		}
	}
}

func TestCompletionFiles(t *testing.T) {
	cases := []struct {
		args []string
		want []string
	}{
		{[]string{"info", ""}, traceExts},
		{[]string{"extract", "-o", ""}, []string{"pcapng"}},
		{[]string{"export", "mbcap", "--report", ""}, []string{"json"}},
	}
	for _, tc := range cases {
		got, dir := complete(t, tc.args...)
		if !slices.Equal(got, tc.want) || dir != ":8" { // ShellCompDirectiveFilterFileExt
			t.Errorf("%v: got %v %s, want %v :8", tc.args, got, dir, tc.want)
		}
	}
	if got, dir := complete(t, "flows", "--min-score", ""); len(got) != 0 || dir != ":4" {
		t.Errorf("free value: got %v %s, want no candidates :4", got, dir)
	}
}

// TestEveryFlagCompletes: every flag that takes a value has a completion
// function (its value set, files of its type, or no file names).
func TestEveryFlagCompletes(t *testing.T) {
	root := rootCommand(&env{})
	var check func(c *cobra.Command)
	check = func(c *cobra.Command) {
		visit := func(f *pflag.Flag) {
			if f.Value.Type() == "bool" {
				return
			}
			if _, ok := c.GetFlagCompletionFunc(f.Name); !ok {
				t.Errorf("%s --%s (%s) has no completion", c.CommandPath(), f.Name, f.Usage)
			}
		}
		c.LocalFlags().VisitAll(visit)
		for _, s := range c.Commands() {
			check(s)
		}
	}
	check(root)
}

func TestVersionOutput(t *testing.T) {
	code, out, _ := cli(t, nil, "version")
	want := "mbtracectl dev (commit unknown, built unknown, " + libsText() + runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")\n"
	if code != exitOK || out != want {
		t.Errorf("version: exit %d %q, want %q", code, out, want)
	}
	code, out, _ = cli(t, nil, "version", "--json")
	want = `{"name":"mbtracectl","version":"dev","tag":"","commit":"unknown","built":"unknown",` + libsJSON() + `"go":"` + runtime.Version() + `","platform":"` + runtime.GOOS + "/" + runtime.GOARCH + "\"}\n"
	if code != exitOK || out != want {
		t.Errorf("version --json: exit %d %q, want %q", code, out, want)
	}
	t.Setenv("MBTRACECTL_JSON", "1")
	if _, env, _ := cli(t, nil, "version"); env != want {
		t.Errorf("MBTRACECTL_JSON=1 version: %q", env)
	}
}

func TestVersionInjected(t *testing.T) {
	old := [4]string{version, tag, commit, buildDate}
	t.Cleanup(func() { version, tag, commit, buildDate = old[0], old[1], old[2], old[3] })
	version, tag, commit, buildDate = "0.7.0", "v0.7.0", "1802d0f9afe8642d1e278120b76fcdfac967cb9e", "2026-11-05T15:41:49Z"
	_, out, _ := cli(t, nil, "version")
	want := "mbtracectl 0.7.0 (tag v0.7.0, commit 1802d0f9afe8642d1e278120b76fcdfac967cb9e, built 2026-11-05T15:41:49Z, " + libsText() +
		runtime.Version() + ", " + runtime.GOOS + "/" + runtime.GOARCH + ")\n"
	if out != want {
		t.Errorf("got %q, want %q", out, want)
	}
}

// libsText and libsJSON are the libraries part of the version output of
// this test binary (whatever OT Fabric modules it links).
func libsText() string {
	s := ""
	for _, l := range build().Libraries {
		s += l.Name + " " + l.Version + ", "
	}
	return s
}

func libsJSON() string {
	b, _ := json.Marshal(build().Libraries)
	return `"libraries":` + string(b) + `,`
}
