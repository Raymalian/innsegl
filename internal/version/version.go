// SPDX-License-Identifier: Apache-2.0

// Package version reports the build identity of the innsegl binary.
//
// The values are stamped at link time by the Makefile:
//
//	go build -ldflags "-X innsegl.dev/innsegl/internal/version.version=v0.1.0 ..."
//
// An unstamped build (go build ./..., go test ./...) reports "dev", which is
// deliberately not a plausible release version.
package version

import (
	"fmt"
	"runtime"
)

// Stamped at link time; never assign to these at run time.
var (
	version = "dev"
	commit  = "unknown"
	date    = "unknown"
)

// Version returns the release version, or "dev" for an unstamped build.
func Version() string { return version }

// String returns a single-line build identity suitable for `innsegl version`.
func String() string {
	return fmt.Sprintf("innsegl %s (commit %s, built %s, %s %s/%s)",
		version, commit, date, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}
