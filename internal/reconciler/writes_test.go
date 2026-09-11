// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"innsegl.dev/innsegl/internal/reconciler"
)

// BlobID must equal what git itself prints, or the whole check compares two
// different things and reports every honest write as missing.
//
// Measured against the real binary rather than a second implementation of the
// same formula: a test that recomputed `blob %d\x00` here would agree with the
// code for the same wrong reason.
func TestBlobIDEqualsGitHashObject(t *testing.T) {
	for _, content := range []string{
		"",
		"one line\n",
		"no trailing newline",
		"unicode: ✓ é 日本\n",
		strings.Repeat("long\n", 5000),
		"nul-ish \x01\x02 bytes\n",
	} {
		dir := t.TempDir()
		file := filepath.Join(dir, "f")
		if err := os.WriteFile(file, []byte(content), 0o644); err != nil {
			t.Fatalf("writing the fixture: %v", err)
		}
		out, err := exec.CommandContext(t.Context(), "git", "hash-object", file).Output()
		if err != nil {
			t.Fatalf("git hash-object: %v", err)
		}
		want := strings.TrimSpace(string(out))
		if got := reconciler.BlobID(content); got != want {
			t.Errorf("BlobID(%d bytes) = %s, git says %s", len(content), got, want)
		}
	}
}

func writeBody(t *testing.T, path, content string) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"tool_name":  "Write",
		"tool_input": map[string]any{"file_path": path, "content": content},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

func editBody(t *testing.T, path, original, oldText, newText string, all bool) []byte {
	t.Helper()
	raw, err := json.Marshal(map[string]any{
		"tool_name": "Edit",
		"tool_input": map[string]any{
			"file_path": path, "old_string": oldText, "new_string": newText, "replace_all": all,
		},
		"tool_response": map[string]any{"originalFile": original},
	})
	if err != nil {
		t.Fatalf("marshal: %v", err)
	}
	return raw
}

// A Write states the content outright.
func TestClaimFromBodyReadsAWrite(t *testing.T) {
	claim, ok := reconciler.ClaimFromBody(writeBody(t, "/repo/a.go", "package a\n"), "e1", "run-1")
	if !ok {
		t.Fatal("a Write body produced no claim")
	}
	if claim.Path != "/repo/a.go" {
		t.Errorf("path %q", claim.Path)
	}
	if want := reconciler.BlobID("package a\n"); claim.BlobID != want {
		t.Errorf("blob %s, want %s", claim.BlobID, want)
	}
}

// An Edit is DERIVED from its own before-and-after rather than taken on trust.
func TestClaimFromBodyDerivesAnEdit(t *testing.T) {
	original := "alpha\nbeta\ngamma\n"
	claim, ok := reconciler.ClaimFromBody(
		editBody(t, "/repo/b.go", original, "beta", "BETA", false), "e2", "run-1")
	if !ok {
		t.Fatal("an Edit body produced no claim")
	}
	if want := reconciler.BlobID("alpha\nBETA\ngamma\n"); claim.BlobID != want {
		t.Errorf("blob %s, want the id of the edited content %s", claim.BlobID, want)
	}
}

func TestClaimFromBodyHonoursReplaceAll(t *testing.T) {
	original := "x\nx\nx\n"
	one, _ := reconciler.ClaimFromBody(editBody(t, "/f", original, "x", "y", false), "e", "r")
	all, _ := reconciler.ClaimFromBody(editBody(t, "/f", original, "x", "y", true), "e", "r")

	if want := reconciler.BlobID("y\nx\nx\n"); one.BlobID != want {
		t.Errorf("single replace produced %s, want %s", one.BlobID, want)
	}
	if want := reconciler.BlobID("y\ny\ny\n"); all.BlobID != want {
		t.Errorf("replace_all produced %s, want %s", all.BlobID, want)
	}
}

// An Edit whose old_string is not in the original contradicts itself. There is
// nothing to check it against, and reporting a missing blob would name the
// wrong fault.
func TestClaimFromBodyRefusesAnEditThatDoesNotApply(t *testing.T) {
	if _, ok := reconciler.ClaimFromBody(
		editBody(t, "/f", "alpha\n", "not-present", "z", false), "e", "r"); ok {
		t.Fatal("an Edit whose old_string is absent produced a claim")
	}
}

// Everything that claims no file content yields no claim. These are the bulk of
// the log — Bash alone is 6689 of 8904 events on this deployment — and a check
// that reported them would be noise, not evidence.
func TestClaimFromBodyIgnoresWhatItCannotCheck(t *testing.T) {
	cases := map[string][]byte{
		"a Bash call": []byte(`{"tool_name":"Bash","tool_input":{"command":"ls"}}`),
		"a Read call": []byte(`{"tool_name":"Read","tool_input":{"file_path":"/f"}}`),
		"an MCP call": []byte(`{"tool_name":"mcp__x__y","tool_input":{"a":1}}`),
		"a Write with no content": []byte(
			`{"tool_name":"Write","tool_input":{"file_path":"/f"}}`),
		"an Edit with no original": []byte(
			`{"tool_name":"Edit","tool_input":{"file_path":"/f","old_string":"a","new_string":"b"}}`),
		"not JSON at all": []byte("{"),
	}
	for name, raw := range cases {
		if _, ok := reconciler.ClaimFromBody(raw, "e", "r"); ok {
			t.Errorf("%s produced a claim", name)
		}
	}
}

// End to end against a real repository: a claimed write that IS in the tree the
// run signed is supported, one that is not is the finding, and a run that
// signed nothing is uncheckable rather than accused.
func TestJudgeWriteAgainstARealTree(t *testing.T) {
	repo := t.TempDir()
	run := func(args ...string) string {
		t.Helper()
		cmd := exec.CommandContext(t.Context(), "git", args...)
		cmd.Dir = repo
		cmd.Env = append(os.Environ(),
			"GIT_AUTHOR_NAME=t", "GIT_AUTHOR_EMAIL=t@example.invalid",
			"GIT_COMMITTER_NAME=t", "GIT_COMMITTER_EMAIL=t@example.invalid")
		out, err := cmd.Output()
		if err != nil {
			t.Fatalf("git %s: %v", strings.Join(args, " "), err)
		}
		return strings.TrimSpace(string(out))
	}
	run("init", "-q", "-b", "main")
	const committed = "package a\n\nfunc A() {}\n"
	if err := os.WriteFile(filepath.Join(repo, "a.go"), []byte(committed), 0o644); err != nil {
		t.Fatalf("seeding: %v", err)
	}
	run("add", "a.go")
	run("commit", "-q", "-m", "seed", "--no-gpg-sign")
	tree := run("rev-parse", "HEAD^{tree}")

	blobs, err := reconciler.TreeBlobs(t.Context(), "", repo, tree)
	if err != nil {
		t.Fatalf("TreeBlobs: %v", err)
	}
	signed := []map[string]struct{}{blobs}

	// The write that really happened.
	honest, ok := reconciler.ClaimFromBody(writeBody(t, "a.go", committed), "e1", "run-1")
	if !ok {
		t.Fatal("no claim from the honest body")
	}
	if v := reconciler.JudgeWrite(honest, signed); v != reconciler.WriteSupported {
		t.Errorf("an honest write judged %v, want supported — git holds this exact blob", v)
	}

	// A write nobody made.
	forged, ok := reconciler.ClaimFromBody(
		writeBody(t, "a.go", "package a\n\nfunc Backdoor() {}\n"), "e2", "run-1")
	if !ok {
		t.Fatal("no claim from the forged body")
	}
	if v := reconciler.JudgeWrite(forged, signed); v != reconciler.WriteUnsupported {
		t.Errorf("a claimed write that is in no signed tree judged %v, want unsupported — "+
			"this is the whole finding", v)
	}

	// A run that signed nothing is not accused of anything.
	if v := reconciler.JudgeWrite(honest, nil); v != reconciler.WriteUncheckable {
		t.Errorf("a run that signed no tree judged %v, want uncheckable — an absence of "+
			"evidence reported as evidence is the failure this project exists to avoid", v)
	}
}

// A tree the repository does not hold is an error, not an empty set. "This
// repository does not have that object" and "that content was never written"
// are different findings and only one is about the agent.
func TestTreeBlobsRefusesATreeItCannotRead(t *testing.T) {
	repo := t.TempDir()
	cmd := exec.CommandContext(t.Context(), "git", "init", "-q", "-b", "main")
	cmd.Dir = repo
	if err := cmd.Run(); err != nil {
		t.Fatalf("git init: %v", err)
	}
	if _, err := reconciler.TreeBlobs(t.Context(), "", repo,
		"0000000000000000000000000000000000000000"); err == nil {
		t.Fatal("an unreadable tree returned no error; it would read as an empty tree " +
			"and accuse every claim against it")
	}
}
