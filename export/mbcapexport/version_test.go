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
