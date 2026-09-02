// SPDX-License-Identifier: Apache-2.0

package deploy

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// OPS-007 (PROPOSED for doc 07's TC-OPS) — the reference deployment is doc 05
// §1's twelve rows, and a row that is not a service is not a row.
//
// #109: seven of the twelve were not compose services at all. The consequence
// was not untidiness. `test/smoke`, `internal/segment`, `cmd/innsegl` and
// `test/chaos` each stood up their own Postgres, their own MinIO and their own
// `innsegl serve` with plain `docker run`, so "the reference deployment" named
// no artifact anyone could point at — and E8 is scheduled to raise
// verify.innsegl.dev and dashboard.innsegl.dev *from* it.
//
// This test needs no Docker and takes microseconds, so the twelve rows are
// checked on every CI run rather than only on the ones that reach containers.
// A row deleted from a compose file fails here, next to the sentence in doc 05
// §1 that requires it.
// ---------------------------------------------------------------------------

// composeFiles are the shipped compose projects, in boot order.
var composeFiles = []string{
	"deploy/compose/spire.yml",
	"deploy/compose/sigstore.yml",
	"deploy/compose/innsegl.yml",
}

// doc05Rows is doc 05 §1's table, by the service name each row must carry.
// Spelled out rather than derived: the table is the specification, and a test
// that read the compose files for its expectations would agree with them by
// construction.
var doc05Rows = []struct {
	service string
	role    string
}{
	{"spire-server", "trust domain innsegl.dev root"},
	{"spire-agent", "node and workload attestation"},
	{"spire-oidc", "JWT-SVID to OIDC bridge for Fulcio"},
	{"fulcio", "local CA"},
	{"rekor", "local transparency log"},
	{"postgres", "ledger hot tier"},
	{"minio", "object storage with object lock enabled"},
	{"innsegl-mcp", "the MCP server"},
	{"innsegl-reconciler", "intent expiry, Rekor cross-check, drift detection"},
	{"innsegl-sealer", "segment sealing and anchoring"},
	{"innsegl-dashboard", "read-only UI and BFF proof checks"},
	{"demo-agent", "scripted agent that registers, commits and retires"},
}

func TestOPS007TheComposeStackShipsEveryDoc05Row(t *testing.T) {
	root := repoRoot(t)

	declared := map[string]string{}
	for _, rel := range composeFiles {
		for _, name := range composeServices(t, filepath.Join(root, rel)) {
			declared[name] = rel
		}
	}

	var missing []string
	for _, row := range doc05Rows {
		if where, ok := declared[row.service]; ok {
			t.Logf("doc 05 §1 %-19s -> %s (%s)", row.service, where, row.role)
			continue
		}
		missing = append(missing, row.service+" ("+row.role+")")
	}
	if len(missing) > 0 {
		t.Errorf("doc 05 §1 names twelve services; %d of them are not compose "+
			"services in %v:\n  %s\n\nA reference deployment missing its own "+
			"components is one nobody can point at, and every suite that needs "+
			"one builds it ad hoc instead (#109).",
			len(missing), composeFiles, strings.Join(missing, "\n  "))
	}
}

// ---------------------------------------------------------------------------
// OPS-008 (PROPOSED for doc 07's TC-OPS) — the shipped stack runs the MCP
// under the append-only role, and refuses to start if it is not.
//
// doc 05 §1 requires a database role that can append and cannot delete.
// Before #109 nothing created one, so the reference stack ran the MCP as the
// database owner and `innsegl serve` printed DATABASE ROLE IS OVER-PRIVILEGED
// on an adopter's first contact with the project.
//
// Two things are asserted, and the second is the one that matters. Creating
// the role is provisioning; making the server REFUSE TO START without it is
// the control. `-require-append-only-role` already exists in cmd/innsegl and
// was defaulted off precisely because the compose stack did not create the
// role. The stack now does, so the stack now sets the flag.
// ---------------------------------------------------------------------------

func TestOPS008TheStackRunsTheMCPUnderTheAppendOnlyRole(t *testing.T) {
	root := repoRoot(t)
	stack := readFile(t, filepath.Join(root, "deploy", "compose", "innsegl.yml"))

	for _, want := range []struct{ needle, why string }{
		{"INNSEGL_REQUIRE_APPEND_ONLY_ROLE",
			"the MCP must refuse to start on an over-privileged role rather than warn: " +
				"a warning is what #109 is about"},
		{"innsegl_appender",
			"doc 05 §1's append-only role has to be named somewhere the MCP's DSN reads"},
	} {
		if !strings.Contains(stack, want.needle) {
			t.Errorf("deploy/compose/innsegl.yml never mentions %q: %s", want.needle, want.why)
		}
	}

	// The provisioning and its proof must both ship. A role that is granted
	// and never probed is a role somebody's later GRANT silently widens.
	for _, rel := range []string{
		filepath.Join("deploy", "compose", "innsegl", "appendonly.sql"),
		filepath.Join("deploy", "compose", "innsegl", "verify-role.sh"),
	} {
		if _, err := os.Stat(filepath.Join(root, rel)); err != nil {
			t.Errorf("%s must ship: internal/api/readonly.sql is the model, and its "+
				"lesson is that the provisioning and the assertion are two files, "+
				"not one: %v", rel, err)
		}
	}
}

// ---------------------------------------------------------------------------
// Helpers.
// ---------------------------------------------------------------------------

// serviceLine matches a top-level service key in a compose file: exactly two
// spaces of indent, a name, a colon, end of line. The shipped files are hand
// written with that convention and every comment in them is a `#` line, so a
// regexp is enough and buys the package no YAML dependency.
var serviceLine = regexp.MustCompile(`^ {2}([a-z][a-z0-9_-]*):\s*$`)

// composeServices returns the service names a compose file declares.
func composeServices(t *testing.T, path string) []string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s is part of the reference deployment and must exist: %v", path, err)
	}

	var out []string
	inServices := false
	for _, line := range strings.Split(string(body), "\n") {
		switch {
		case strings.HasPrefix(line, "services:"):
			inServices = true
			continue
		case line != "" && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "#"):
			inServices = false
		}
		if !inServices {
			continue
		}
		if m := serviceLine.FindStringSubmatch(line); m != nil {
			out = append(out, m[1])
		}
	}
	return out
}

func readFile(t *testing.T, path string) string {
	t.Helper()
	body, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("%s must exist: %v", path, err)
	}
	return string(body)
}

// repoRoot finds the module root from the test's working directory.
func repoRoot(t *testing.T) string {
	t.Helper()
	out, err := exec.Command("git", "rev-parse", "--show-toplevel").Output()
	if err != nil {
		t.Fatalf("locating the repository root: %v", err)
	}
	return strings.TrimSpace(string(out))
}
