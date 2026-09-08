// SPDX-License-Identifier: Apache-2.0

package smoke

import (
	"encoding/json"
	"os/exec"
	"strings"
	"testing"
)

// OPS-017 (proposed for doc 07; doc 07 is not modified here).
//
// #168 (RM-103): this harness runs deploy/compose/README.md's boot and
// teardown blocks verbatim, which is what makes OPS-005 mean anything. The
// teardown block ends in `down -v`.
//
// deploy/compose/sigstore.yml and spire.yml pin their own project names —
// `name: innsegl-sigstore`, `name: innsegl-spire` — so those commands always
// acted on the projects `make innsegl-up` brings up. Running `go test ./...`
// on a machine with the stack up therefore deleted the developer's Rekor,
// Fulcio PKI and SPIRE data.
//
// It happened twice on 2026-09-07. The second time it destroyed the Rekor
// entry for an agent-signed commit, and that is not recoverable: the entry is
// gone, Fulcio was re-rooted, and the commit can never verify again.
//
// # What is under test, and why it is this and not the destruction itself
//
// The fix is one environment variable. `stack.sh` exports
// COMPOSE_PROJECT_NAME, which overrides the pinned `name:` — so the commands
// stay verbatim, OPS-005 still finds every one of them in the README, and only
// the namespace they act in changes.
//
// **The whole fix rests on that override actually happening.** If compose ever
// preferred the file's `name:` over the environment, the harness would go back
// to deleting the developer's stack and nothing would say so until someone
// lost data again. So the override is what this asserts, against the real
// `docker compose` and the real shipped files, rather than the deletion — a
// test that destroyed a stack to prove it could would need a stack to destroy,
// and would be indistinguishable from the bug.
// requireCompose fails rather than skips when docker compose is absent.
// test/smoke's own rule, stated in smokestack_test.go: on a machine that HAS
// Docker, a stack that will not start is an infrastructure fault, and
// reporting it as a skip turns it into a pass.
func requireCompose(t *testing.T) {
	t.Helper()
	if _, err := exec.LookPath("docker"); err != nil {
		t.Skipf("docker is not installed: %v", err)
	}
	if err := exec.CommandContext(t.Context(), "docker", "compose", "version").Run(); err != nil {
		t.Fatalf("docker is installed but `docker compose` does not run: %v", err)
	}
}

func TestOPS017TheHarnessDoesNotActOnTheShippedComposeProjects(t *testing.T) {
	requireCompose(t)

	// The two shipped files, and the project each pins. A file added here
	// later without its name in this table is a file this test does not cover.
	for _, tc := range []struct {
		file   string
		pinned string
	}{
		{"../../deploy/compose/sigstore.yml", "innsegl-sigstore"},
		{"../../deploy/compose/spire.yml", "innsegl-spire"},
	} {
		t.Run(tc.pinned, func(t *testing.T) {
			// Without the override: the pinned name. Establishes that the
			// danger is real and that this test would notice if it stopped
			// being — an assertion that only checked the override would pass
			// just as well against a file that pinned nothing.
			if got := composeProjectName(t, tc.file, ""); got != tc.pinned {
				t.Fatalf("%s resolves to project %q with no override, want the pinned %q; "+
					"this test's premise no longer holds", tc.file, got, tc.pinned)
			}

			// With it: the harness's own namespace.
			got := composeProjectName(t, tc.file, smokeComposeProject)
			if got != smokeComposeProject {
				t.Errorf("COMPOSE_PROJECT_NAME=%s did not override %s's pinned name: got %q.\n"+
					"stack.sh relies on this override, and without it the documented "+
					"`down -v` deletes the developer's own stack (#168).",
					smokeComposeProject, tc.file, got)
			}
			if got == tc.pinned {
				t.Errorf("the harness would act on %q — the project `make innsegl-up` brings up", tc.pinned)
			}
		})
	}
}

// OPS-018 (proposed). The constant itself must not name a shipped project.
// Cheap, and it is the one way this fix could be undone by a careless edit
// that every other check here would still pass.
func TestOPS018TheHarnessProjectIsNotAShippedOne(t *testing.T) {
	for _, shipped := range []string{"innsegl-sigstore", "innsegl-spire", "innsegl-core"} {
		if smokeComposeProject == shipped {
			t.Fatalf("smokeComposeProject is %q, which is a shipped compose project; "+
				"this harness tears its projects down with -v (#168)", shipped)
		}
	}
	if !strings.HasPrefix(smokeComposeProject, "innsegl-smoke") {
		t.Errorf("smokeComposeProject = %q; keep it under this harness's own "+
			"innsegl-smoke prefix so its containers are recognisable as the test's",
			smokeComposeProject)
	}
}

// composeProjectName asks docker compose what project a file resolves to,
// optionally with COMPOSE_PROJECT_NAME set. It reads compose's own answer
// rather than reimplementing the precedence rules, which are the thing in
// doubt.
func composeProjectName(t *testing.T, file, override string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "docker", "compose", "-f", file, "config", "--format", "json")
	// sigstore.yml requires the issuer rather than defaulting it (ADR-0029
	// decision 3), so `config` fails without it — this value is never used to
	// start anything here.
	cmd.Env = append(cmd.Environ(), "INNSEGL_SPIRE_JWT_ISSUER=http://spire-oidc:8080")
	if override != "" {
		cmd.Env = append(cmd.Env, "COMPOSE_PROJECT_NAME="+override)
	}
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("docker compose -f %s config: %v", file, err)
	}
	// The name is a top-level string field; a substring search over the JSON
	// would match a service or a volume that happens to contain it.
	var doc struct {
		Name string `json:"name"`
	}
	if err := json.Unmarshal(out, &doc); err != nil {
		t.Fatalf("decoding compose config for %s: %v", file, err)
	}
	return doc.Name
}
