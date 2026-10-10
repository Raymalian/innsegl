// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

// ACC-014 at the command line (RM-307, #486): the operator's organisation
// sees runs no machine is mapped to unless the deployment hides them. Shown
// by default, so a core whose runs all predate enrolled machines keeps
// showing them to its operator after an update.
func TestACC014TheOperatorSeesUnownedRunsUnlessTheDeploymentHidesThem(t *testing.T) {
	t.Setenv(envAPIHideUnownedRuns, "")
	var seen apiOptions
	if code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), &seen)); code != exitOK {
		t.Fatalf("exit = %d. stderr: %s", code, stderr)
	}
	if seen.hideUnownedRuns {
		t.Error("unowned runs are hidden by default")
	}

	t.Setenv(envAPIHideUnownedRuns, "true")
	if code, _, stderr := runAPIUntilStopped(t, minimalAPIArgs(), stubAPIDeps(healthyStub(), &seen)); code != exitOK {
		t.Fatalf("exit = %d. stderr: %s", code, stderr)
	}
	if !seen.hideUnownedRuns {
		t.Errorf("$%s=true did not hide unowned runs", envAPIHideUnownedRuns)
	}
}
