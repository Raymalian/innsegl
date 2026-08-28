// SPDX-License-Identifier: Apache-2.0

package version

import (
	"runtime"
	"strings"
	"testing"
)

func TestStringIdentifiesTheBinaryAndItsBuild(t *testing.T) {
	got := String()

	for _, want := range []string{"innsegl", Version(), runtime.GOOS, runtime.GOARCH} {
		if !strings.Contains(got, want) {
			t.Errorf("String() = %q, want it to contain %q", got, want)
		}
	}
	if strings.Contains(got, "\n") {
		t.Errorf("String() = %q, want a single line", got)
	}
}

func TestVersionDefaultsToDevInAnUnstampedBuild(t *testing.T) {
	if Version() != "dev" {
		t.Errorf("Version() = %q, want %q when no -ldflags stamp is applied", Version(), "dev")
	}
}
