// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"testing"

	"innsegl.dev/innsegl/internal/dockertest"
)

func RequireDocker(t *testing.T, id string) {
	t.Helper()
	if err := dockertest.Usable(t.Context()); err != nil {
		skip, failure := dockertest.StartupOutcome(err)
		if failure != "" {
			t.Fatal(failure)
		}
		t.Skipf("skipping %s: %s", id, skip)
	}
}
