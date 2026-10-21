// SPDX-License-Identifier: Apache-2.0

package client

import (
	"strings"
	"testing"
)

// OAI-020/025: launch configuration routes the selected auth mode and
// disables unobserved transport without editing the user's configuration.
func TestOAI025CodexLaunchRoutesAndHooks(t *testing.T) {
	for _, api := range []bool{false, true} {
		args, err := CodexLaunchArgs("http://127.0.0.1:28195", "/opt/innsegl/bin/innsegl", api)
		if err != nil {
			t.Fatal(err)
		}
		config := strings.Join(args, "\n")
		path := "/backend-api/codex"
		if api {
			path = "/v1"
		}
		for _, required := range []string{"http://127.0.0.1:28195" + path, "supports_websockets=false", "requires_openai_auth=true", "hook session", "--capture-only", "hooks.SessionStart=", "hooks.UserPromptSubmit=", "hooks.SessionEnd="} {
			if !strings.Contains(config, required) {
				t.Errorf("missing %q in launch configuration", required)
			}
		}
	}
	for _, bad := range []string{"https://example.test", "http://127.0.0.1:28195/evil", "http://user:pass@127.0.0.1:28195", "http://127.0.0.1:28195?token=x"} {
		if _, err := CodexLaunchArgs(bad, "/opt/innsegl/bin/innsegl", false); err == nil {
			t.Fatalf("accepted nonlocal or ambiguous endpoint %s", bad)
		}
	}
}
