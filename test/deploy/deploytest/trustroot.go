// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"fmt"
	"os"
	"testing"
)

func WriteFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.WriteFile(path, []byte(body), 0o600); err != nil {
		t.Fatalf("writing %s: %v", path, err)
	}
}

// UniqueName keeps concurrent runs and leftovers from colliding.
func UniqueName(t *testing.T, prefix string) string {
	t.Helper()
	return fmt.Sprintf("%s-%d", prefix, os.Getpid())
}
