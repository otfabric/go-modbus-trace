// SPDX-License-Identifier: MIT

package mbcapexport

import (
	"runtime/debug"
	"testing"

	"github.com/otfabric/go-modbus-trace/trace"
)

func TestLibraryVersions(t *testing.T) {
	want := trace.Version
	if bi, ok := debug.ReadBuildInfo(); ok && bi.Main.Version != "" {
		want = bi.Main.Version
	}
	if got := LibraryVersion(); got != want {
		t.Errorf("LibraryVersion() = %q, want %q", got, want)
	}
	// Test binaries do not always record their dependencies (CI builds them
	// without), so only the fallback is certain here.
	if got := CaptureLibraryVersion(); got == "" {
		t.Errorf("CaptureLibraryVersion() is empty, want a version or %q", "unknown")
	}
	if got := moduleVersion("example.com/not-linked"); got != "" {
		t.Errorf("moduleVersion of a module that is not linked = %q, want empty", got)
	}
}

func TestBuildModuleVersion(t *testing.T) {
	const lib = "github.com/otfabric/go-modbus-trace"
	bi := &debug.BuildInfo{
		Main: debug.Module{Path: "example.com/app", Version: "v1.0.0"},
		Deps: []*debug.Module{
			{Path: lib, Version: "v0.5.1"},
			{Path: "example.com/forked", Version: "v1.2.3", Replace: &debug.Module{Path: "example.com/fork", Version: "v1.2.4"}},
		},
	}
	for _, tc := range []struct {
		bi         *debug.BuildInfo
		path, want string
	}{
		{nil, lib, ""},
		{bi, "example.com/app", "v1.0.0"},
		{bi, lib, "v0.5.1"},
		{bi, "example.com/forked", "v1.2.4"},
		{bi, "example.com/absent", ""},
	} {
		if got := buildModuleVersion(tc.bi, tc.path); got != tc.want {
			t.Errorf("buildModuleVersion(%s) = %q, want %q", tc.path, got, tc.want)
		}
	}
}

func TestVersionOr(t *testing.T) {
	if got := versionOr("v1.2.3", "unknown"); got != "v1.2.3" {
		t.Errorf("versionOr with a version = %q", got)
	}
	if got := versionOr("", "unknown"); got != "unknown" {
		t.Errorf("versionOr without a version = %q", got)
	}
}
