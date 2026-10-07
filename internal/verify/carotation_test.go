// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/trusthistory"
)

// ---------------------------------------------------------------------------
// OPS-133 (PROPOSED for doc 07's TC-OPS) — a Fulcio CA rotation, on a real
// chain (#533, ADR-0075).
//
// The stack is this package's own: real SPIRE, real Fulcio from
// deploy/compose/sigstore.yml (so the bootstrap's per-host password and
// Fulcio's serve.yaml are real too), real Rekor. The rotation is the SHIPPED
// scripts/ca-rotate.sh, against this stack's Fulcio container and CA volume,
// writing a trust history through the real `innsegl trust-history`.
//
// What is not real here, and why:
//   - the script's proof step is `true`. Its default runs
//     deploy/compose/sigstore/verify.sh, which reaches SPIRE through the
//     shipped project names; commit B below is a stronger proof of the same
//     thing: a commit signed after the rotation verifies under root 2.
//   - there is no core container: the history command is the binary on the
//     host, given the history's path, and the core-running check is off.
//
// The sequence is the issue's:
//   commit A under root 1 -> rotate with MODE=revoke
//   -> A still verifies, logged before revoked_at
//   -> commit B signs under root 2 and verifies
//   -> a commit signed with root 1's key after revoked_at is refused.
// For the last, root 1 is put back with `ca-rotate.sh rollback`, which is how
// someone holding the old key would run a Fulcio on it; then root 2 again.
// ---------------------------------------------------------------------------

func TestOPS133ARotatedRootStillVerifiesWhatItSignedAndNothingAfter(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 15*time.Minute)
	defer cancel()

	root := filepath.Dir(filepath.Dir(mustGetwd(t)))
	bin := filepath.Join(t.TempDir(), "innsegl")
	build := exec.CommandContext(ctx, "go", "build", "-o", bin, "innsegl.dev/innsegl/cmd/innsegl")
	build.Dir = root
	if out, err := build.CombinedOutput(); err != nil {
		t.Fatalf("building innsegl: %v: %s", err, out)
	}
	historyFile := filepath.Join(t.TempDir(), trusthistory.FileName)

	// The history, seeded with root 1 the way the core's trust pass seeds it.
	root1, err := harnessGET(ctx, s.fulcioURL+"/api/v1/rootCert")
	if err != nil {
		t.Fatal(err)
	}
	runIn(ctx, t, root, root1, nil, bin, "trust-history", "record", "--kind", "fulcio_root", "--file", historyFile)
	root1ID, err := trusthistory.KeyIDOf(root1)
	if err != nil {
		t.Fatal(err)
	}

	repo := sharedRepo(t)
	a := signOne(t, s, repo, "OPS-133: signed under root 1", "rm-533")

	env := []string{
		"INNSEGL_ROTATE_FULCIO_CONTAINER=" + s.project + "-fulcio",
		"INNSEGL_ROTATE_CORE_CONTAINER=",
		"INNSEGL_ROTATE_FULCIO_URL=" + s.fulcioURL,
		"INNSEGL_ROTATE_HISTORY_CMD=" + bin + " trust-history",
		"INNSEGL_TRUST_HISTORY=" + historyFile,
		"INNSEGL_ROTATE_PROOF_CMD=true",
	}
	out := runIn(ctx, t, root, nil, append(env, "CONFIRM=rotate", "MODE=revoke",
		"REASON=OPS-133: the key may have been exposed"), filepath.Join(root, "scripts", "ca-rotate.sh"), "rotate")
	t.Logf("the rotation:\n%s", out)
	stamp := regexp.MustCompile(`archive/([0-9TZ]+)\.`).FindStringSubmatch(out)
	if stamp == nil {
		t.Fatalf("the rotation names no archive:\n%s", out)
	}

	root2, err := harnessGET(ctx, s.fulcioURL+"/api/v1/rootCert")
	if err != nil {
		t.Fatal(err)
	}
	root2ID, err := trusthistory.KeyIDOf(root2)
	if err != nil {
		t.Fatal(err)
	}
	if root2ID == root1ID {
		t.Fatal("Fulcio serves the same root after the rotation")
	}
	h := loadHistory(t, historyFile)
	old, _ := h.Lookup(trusthistory.KindFulcioRoot, root1ID)
	if old.RevokedAt == nil {
		t.Fatalf("root 1 is not revoked in the history: %+v", old)
	}
	if _, ok := h.Lookup(trusthistory.KindFulcioRoot, root2ID); !ok {
		t.Fatal("root 2 is not recorded in the history")
	}

	t.Run("commit A, logged before revoked_at, still verifies", func(t *testing.T) {
		rep := verifyWith(ctx, t, s, historyFile, repo, a.sha)
		if rep.Verdict != VerdictVerified {
			t.Fatalf("A: %s\n%s", rep.Verdict, Render(rep))
		}
		if got := rootFact(rep); got != root1ID {
			t.Fatalf("A chained to %q, want root 1 %s", got, root1ID)
		}
	})

	stageMore(t, repo, "b.txt", "after the rotation\n")
	b := signOne(t, s, repo, "OPS-133: signed under root 2", "rm-533")
	t.Run("commit B signs under root 2 and verifies", func(t *testing.T) {
		rep := verifyWith(ctx, t, s, historyFile, repo, b.sha)
		if rep.Verdict != VerdictVerified {
			t.Fatalf("B: %s\n%s", rep.Verdict, Render(rep))
		}
		if got := rootFact(rep); got != root2ID {
			t.Fatalf("B chained to %q, want root 2 %s", got, root2ID)
		}
	})

	// Root 1's key, after its revocation: put it back in a Fulcio, sign, and
	// put root 2 back before verifying, so the only way to trust root 1 is
	// the history that revoked it.
	scriptPath := filepath.Join(root, "scripts", "ca-rotate.sh")
	back := runIn(ctx, t, root, nil, append(env, "CONFIRM=rollback"), scriptPath, "rollback", stamp[1])
	t.Logf("root 1 back in Fulcio:\n%s", back)
	keep := regexp.MustCompile(`kept as archive/(\S+-before-rollback)`).FindStringSubmatch(back)
	if keep == nil {
		t.Fatalf("the rollback names no archive for root 2:\n%s", back)
	}
	stageMore(t, repo, "c.txt", "root 1's key, after its revocation\n")
	c := signOne(t, s, repo, "OPS-133: signed with root 1's key after its revocation", "rm-533")
	t.Logf("root 2 back in Fulcio:\n%s",
		runIn(ctx, t, root, nil, append(env, "CONFIRM=rollback"), scriptPath, "rollback", keep[1]))
	now, err := harnessGET(ctx, s.fulcioURL+"/api/v1/rootCert")
	if err != nil {
		t.Fatal(err)
	}
	if id, err := trusthistory.KeyIDOf(now); err != nil || id != root2ID {
		t.Fatalf("Fulcio serves %s after putting root 2 back, want %s", id, root2ID)
	}

	t.Run("a signature with root 1's key after revoked_at is refused", func(t *testing.T) {
		rep := verifyWith(ctx, t, s, historyFile, repo, c.sha)
		if rep.Verdict == VerdictVerified || rep.Verdict == VerdictContentVerified {
			t.Fatalf("C verified (%s) under a revoked root\n%s", rep.Verdict, Render(rep))
		}
		chain := findCheck(rep, CheckCertificateChain)
		if chain.Result != Failed || !strings.Contains(chain.Detail, "revoked") {
			t.Fatalf("the chain check is %s (%q); want failed, naming the revocation\n%s",
				chain.Result, chain.Detail, Render(rep))
		}
	})
}

func mustGetwd(t *testing.T) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	return wd
}

// runIn runs a command in dir with stdin and extra environment, and fails the
// test on a non-zero exit. It returns stdout and stderr together.
func runIn(ctx context.Context, t *testing.T, dir string, stdin []byte, env []string, name string, args ...string) string {
	t.Helper()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), env...)
	if stdin != nil {
		cmd.Stdin = strings.NewReader(string(stdin))
	}
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("%s %s: %v\n%s", name, strings.Join(args, " "), err, out)
	}
	return string(out)
}

func loadHistory(t *testing.T, path string) *trusthistory.History {
	t.Helper()
	h, err := trusthistory.Load(path)
	if err != nil {
		t.Fatalf("loading the trust history: %v", err)
	}
	return h
}

func verifyWith(ctx context.Context, t *testing.T, s *stack, historyFile, repo, sha string) Report {
	t.Helper()
	rep, err := stackVerifier(t, s).WithHistory(loadHistory(t, historyFile)).Verify(ctx, repo, sha)
	if err != nil {
		t.Fatalf("Verify %s: %v", sha, err)
	}
	return rep
}

func rootFact(rep Report) string {
	for _, c := range rep.Checks {
		for _, f := range c.Facts {
			if f.Name == FactTrustRootKeyID {
				return f.Value
			}
		}
	}
	return ""
}

func findCheck(rep Report, name string) Check {
	for _, c := range rep.Checks {
		if c.Name == name {
			return c
		}
	}
	return Check{}
}
