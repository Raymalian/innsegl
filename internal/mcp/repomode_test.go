// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"encoding/json"
	"testing"
)

// OPS-175 (ADR-0080 decision 5): readiness reports the repository mode the
// running process writes, always, and never gates on it. An empty mode is a
// deployment that never set one, which is literal.
func TestOPS175ReadinessReportsTheRepositoryMode(t *testing.T) {
	for _, tc := range []struct{ set, want string }{
		{"", "literal"}, {"literal", "literal"}, {"pseudonymous", "pseudonymous"},
	} {
		h := healthWithFakes(t, HealthConfig{RepoMode: tc.set})
		ready := h.Ready(t.Context())
		if !ready.Ready {
			t.Fatalf("three succeeding probes did not produce ready")
		}
		body, err := json.Marshal(ready)
		if err != nil {
			t.Fatal(err)
		}
		var wire map[string]any
		if err := json.Unmarshal(body, &wire); err != nil {
			t.Fatal(err)
		}
		if wire["repo_mode"] != tc.want {
			t.Errorf("RepoMode %q: repo_mode = %v, want %q", tc.set, wire["repo_mode"], tc.want)
		}
	}
}
