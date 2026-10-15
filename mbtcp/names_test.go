// SPDX-License-Identifier: MIT

package mbtcp

import (
	"fmt"
	"testing"
)

// TestNamesOutOfRange: a value outside the enumeration names itself
// "unknown" instead of panicking.
func TestNamesOutOfRange(t *testing.T) {
	for _, s := range []fmt.Stringer{RoleSource(200), Confidence(200), JunkReason(200)} {
		if s.String() != "unknown" {
			t.Errorf("%T: %q", s, s.String())
		}
	}
	if RoleStructure.String() != "structure" || Confidence(1).String() != "next_header" || JunkReason(2).String() != "resync_failed" {
		t.Error("in-range names changed")
	}
}
