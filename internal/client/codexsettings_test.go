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
		for _, required := range []string{"http://127.0.0.1:28195" + path, "supports_websockets=false", "agents.enabled=false", "requires_openai_auth=true", "hook session", "--capture-only", "hooks.SessionStart=", "hooks.UserPromptSubmit=", "hooks.SessionEnd="} {
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

// OAI-014/025: signing is explicit and exposes shell calls as structured
// wire evidence, without changing ordinary capture launches.
func TestOAI014SigningLaunchConfiguration(t *testing.T) {
	args, err := CodexSigningLaunchArgs("http://127.0.0.1:28195", "/opt/innsegl/bin/innsegl", false)
	if err != nil {
		t.Fatal(err)
	}
	s := strings.Join(args, "\n")
	for _, want := range []string{`agents.enabled=false`, `features.code_mode.enabled=true`, `direct_only_tool_namespaces=["functions"]`, `hook pre-tool-use`, `hook post-tool-use`, `hook session`} {
		if !strings.Contains(s, want) {
			t.Errorf("missing %q", want)
		}
	}
	if strings.Contains(s, "--capture-only") {
		t.Fatal("signing uses capture-only lifecycle")
	}
	ordinary, err := CodexLaunchArgs("http://127.0.0.1:28195", "/opt/innsegl/bin/innsegl", false)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.Join(ordinary, "\n"), "code_mode") {
		t.Fatal("changed default capture")
	}
}

// OAI-006/025: child support adds lifecycle hooks only after negotiation.
func TestOAI006CodexThreadLaunchHooks(t *testing.T) {
	for _, signing := range []bool{false, true} {
		args, err := CodexThreadLaunchArgs("http://127.0.0.1:28495", "/opt/innsegl/bin/innsegl", false, signing)
		if err != nil {
			t.Fatal(err)
		}
		config := strings.Join(args, "\n")
		for _, want := range []string{"agents.enabled=true", "hooks.SubagentStart=", "hooks.SubagentStop="} {
			if !strings.Contains(config, want) {
				t.Errorf("missing %s", want)
			}
		}
		if strings.Contains(config, "agents.enabled=false") {
			t.Fatal("conflicting agent settings")
		}
		if strings.Contains(config, "--capture-only") == signing {
			t.Fatal("lifecycle signing mode mismatch")
		}
	}
}
