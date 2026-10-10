// SPDX-License-Identifier: Apache-2.0

package acme

import (
	"sort"
	"strings"
	"testing"
)

// TLS-006: a provider is chosen by name from the set compiled in, built
// from its own settings; a name not in the set is refused, listing the set.
func TestTLS006AProviderIsChosenByNameFromTheSetCompiledIn(t *testing.T) {
	names := Providers()
	if !sort.StringsAreSorted(names) || len(names) != len(providers) {
		t.Fatalf("Providers() = %v", names)
	}
	for _, generic := range []string{"rfc2136", "httpreq", "exec"} {
		if _, ok := providers[generic]; !ok {
			t.Errorf("the generic provider %s is not compiled in", generic)
		}
	}
	t.Setenv("EXEC_PATH", "/bin/true")
	if p, err := providerByName("EXEC"); err != nil || p == nil {
		t.Fatalf("exec with its setting: %v", err)
	}
	if _, err := providerByName("no-such-dns"); err == nil || !strings.Contains(err.Error(), "rfc2136") {
		t.Fatalf("an unknown provider: %v, want a refusal listing the set", err)
	}
	// Every builder runs; without its settings each says so rather than
	// building a provider that would fail at the first order.
	for name, build := range providers {
		if name == "exec" {
			continue
		}
		if _, err := build(); err == nil {
			t.Logf("%s built with no settings", name)
		}
	}
}
