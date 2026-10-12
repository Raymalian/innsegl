// SPDX-License-Identifier: Apache-2.0

package deploytest

import (
	"regexp"
	"testing"
)

// MakeRecipe is the recipe of one Makefile target: every line after its rule
// line up to the first blank line.
func MakeRecipe(t *testing.T, mk, target string) string {
	t.Helper()
	m := regexp.MustCompile(`(?ms)^` + regexp.QuoteMeta(target) + `:[^\n]*\n(.*?)\n\n`).FindStringSubmatch(mk)
	if m == nil {
		t.Fatalf("the Makefile has no %s target", target)
	}
	return m[1]
}
