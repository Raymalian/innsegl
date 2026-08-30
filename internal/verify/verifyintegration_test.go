// SPDX-License-Identifier: Apache-2.0

package verify

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TC-VER's integration cases: real SPIRE, real Fulcio, real Rekor, the
// released gitsign binary, and — for VER-001 — a real container with no route
// to a real Postgres.

// ---------------------------------------------------------------------------
// VER-001 — `innsegl verify <sha>` on a good commit, WITH DATABASE ACCESS
// REMOVED. doc 07: "All three checks pass using only git + Fulcio + Rekor."
// This is I5, and it is the point of the whole project.
//
// TWO PROOFS, and neither is sufficient alone.
//
// The first is structural and runs everywhere: the package's transitive import
// graph contains no ledger and no database driver, so there is no code path to
// a database to disable. A test that merely avoided calling the ledger would
// prove nothing; this proves the call does not exist.
//
// The second is empirical and needs Docker: a Postgres container is started on
// a network of its own and shown to be REACHABLE from that network, then the
// verifier runs inside a container attached only to the Sigstore stack's
// published network, where the same address is shown to be UNREACHABLE — from
// the same container, in the same invocation, seconds before the verification
// runs. Not "the verifier did not connect": there is no route.
// ---------------------------------------------------------------------------

func TestVER001TheVerifierHasNoDatabaseToReach(t *testing.T) {
	out, err := exec.CommandContext(t.Context(), "go", "list", "-deps",
		"innsegl.dev/innsegl/internal/verify").Output()
	if err != nil {
		t.Fatalf("go list -deps: %v", err)
	}
	// Exact packages, and one documented allowance.
	//
	// `database/sql` is the package that opens connections; it is absent, and
	// that is the assertion. `database/sql/driver` IS present, and naming it
	// here rather than hiding it behind a prefix match is the honest form:
	// github.com/google/uuid imports it so that uuid.UUID can implement
	// driver.Valuer and sql.Scanner. It is a package of interface types. It
	// cannot open a socket, and nothing reachable from here can.
	forbidden := map[string]string{
		"database/sql":                        "the standard library's connection manager",
		"github.com/jackc/pgx/v5":             "this project's Postgres driver",
		"github.com/jackc/pgx/v5/pgxpool":     "this project's Postgres pool",
		"innsegl.dev/innsegl/internal/ledger": "the ledger",
		"innsegl.dev/innsegl/internal/mcp":    "the MCP server, which holds the ledger",
	}
	for _, line := range strings.Split(string(out), "\n") {
		if what, bad := forbidden[strings.TrimSpace(line)]; bad {
			t.Errorf("internal/verify transitively imports %q (%s). I5 says verification "+
				"must be checkable \"by a third party with no access to our database\"; "+
				"a verifier that CAN reach one is one configuration change away from "+
				"depending on it.", line, what)
		}
	}
	if !strings.Contains(string(out), "database/sql/driver") {
		t.Log("note: database/sql/driver is no longer in the graph; the allowance " +
			"documented above can be removed")
	}
}

func TestVER001VerifiesWithTheDatabaseUnreachable(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	repo := sharedRepo(t)
	good := signOne(t, s, repo, "VER-001: a commit a stranger will check", "rm-037")

	// A real Postgres, on a network of its own, proved reachable from that
	// network. Without this half, "unreachable" would be satisfied by a
	// database that is simply not running.
	pg := startPostgres(ctx, t, s)
	if err := probeFrom(ctx, pg.network, pg.ip, "5432"); err != nil {
		t.Fatalf("the control probe could not reach postgres on its own network, so "+
			"the negative probe below would prove nothing: %v", err)
	}
	t.Logf("control: postgres at %s:5432 IS reachable from %s", pg.ip, pg.network)

	binDir := buildLinuxBinary(ctx, t)

	// One container, one invocation: prove there is no route, then verify.
	script := fmt.Sprintf(`set -e
if nc -z -w 5 %s 5432 2>/dev/null; then echo "FAIL: postgres is reachable by address"; exit 90; fi
echo "postgres %s:5432 -- no route from this container"
if nc -z -w 5 %s 5432 2>/dev/null; then echo "FAIL: postgres is reachable by name"; exit 91; fi
echo "postgres %s:5432 -- name does not resolve"
exec /innsegl/innsegl verify %s --repo /repo --fulcio-url http://fulcio:5555 --rekor-url http://rekor:3000
`, pg.ip, pg.ip, pg.name, pg.name, good.sha)

	args := []string{
		"run", "--rm",
		"--network", s.publishedNetwork,
		"-v", repo + ":/repo:ro",
		"-v", binDir + ":/innsegl:ro",
		"-e", "GIT_CONFIG_COUNT=1",
		"-e", "GIT_CONFIG_KEY_0=safe.directory",
		"-e", "GIT_CONFIG_VALUE_0=*",
		// A DSN is deliberately present in the environment. If the verifier
		// had any database code path at all, this is what it would use.
		"-e", "INNSEGL_DATABASE_URL=postgres://innsegl:innsegl-test@" + pg.ip + ":5432/innsegl",
		// alpine/git's ENTRYPOINT is `git`, so a shell needs saying.
		"--entrypoint", "sh", verifyRunnerImage, "-c", script,
	}
	cmd := exec.CommandContext(ctx, "docker", args...)
	combined, err := cmd.CombinedOutput()
	t.Logf("VER-001, inside a container with no route to the database:\n%s", combined)
	if err != nil {
		t.Fatalf("`innsegl verify` failed with the database unreachable: %v", err)
	}

	text := string(combined)
	for _, want := range []string{
		CheckCertificateChain, CheckRekorInclusion, CheckTrailerIdentity,
		"no route from this container", good.claim.Identity,
	} {
		if !strings.Contains(text, want) {
			t.Errorf("the output does not carry %q:\n%s", want, text)
		}
	}
	if strings.Count(text, string(Verified)) < 3 {
		t.Errorf("fewer than three checks reported %s:\n%s", Verified, text)
	}
	if strings.Contains(text, string(Unavailable)) {
		t.Errorf("a check reported %s; all three must be settled from git, Fulcio "+
			"and Rekor alone:\n%s", Unavailable, text)
	}
}

// ---------------------------------------------------------------------------
// VER-003 — squash/rebase. doc 07: "Rewritten commit verifies FAILED; original
// attribution still resolvable via Rekor + tree hash where possible."
// ---------------------------------------------------------------------------

func TestVER003ASquashedCommitFailsAndTheOriginalIsStillResolvable(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	repo := sharedRepo(t)
	// A base commit, so the two signed ones are not the root and the squash
	// has a parent to reset to.
	harnessGit(t, repo, "-c", "user.name="+harnessAuthorName,
		"-c", "user.email="+harnessAuthorEmail,
		"commit", "--no-gpg-sign", "-m", "base")
	stageMore(t, repo, "first.txt", "first\n")
	first := signOne(t, s, repo, "VER-003: the first signed commit", "rm-037")
	stageMore(t, repo, "second.txt", "second\n")
	second := signOne(t, s, repo, "VER-003: the second signed commit", "rm-037")

	// The squash: git rewrites the two commits into one, carrying the first
	// commit's message — trailers and all — onto an object nothing signed.
	message := harnessGit(t, repo, "log", "-1", "--format=%B", first.sha)
	// NOT .git/SQUASH_MSG: `git reset` deletes that file, and the reset comes
	// between writing the message and using it.
	msgFile := filepath.Join(t.TempDir(), "squash-msg")
	if err := os.WriteFile(msgFile, []byte(message), 0o600); err != nil {
		t.Fatal(err)
	}
	harnessGit(t, repo, "reset", "--soft", first.sha+"^")
	harnessGit(t, repo,
		"-c", "user.name="+harnessAuthorName, "-c", "user.email="+harnessAuthorEmail,
		"commit", "--no-gpg-sign", "--cleanup=verbatim", "--file", msgFile)
	squashed := harnessGit(t, repo, "rev-parse", "HEAD")

	if squashed == second.sha || squashed == first.sha {
		t.Fatalf("the squash produced the same object as an original (%s)", squashed)
	}

	v := stackVerifier(t, s)
	rep, err := v.Verify(ctx, repo, squashed)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	t.Logf("VER-003, the rewritten commit:\n%s", Render(rep))

	if rep.Verdict != VerdictFailed {
		t.Fatalf("the rewritten commit verified as %s, want %s: the signature does "+
			"not cover the new object\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}

	// "where possible": the rewrite kept the tree, and the original commit
	// object is still in this repository, so the original attribution is
	// recoverable — commit SHA -> Rekor entry -> certificate identity.
	if len(rep.Recovered) == 0 {
		t.Fatalf("the original attribution was not recovered from the tree hash, "+
			"although %s still holds the same tree in this repository\n%s",
			second.sha, Render(rep))
	}
	found := false
	for _, r := range rep.Recovered {
		if r.CommitSHA == second.sha && r.Identity == second.claim.Identity {
			found = true
			if r.LogIndex < 0 {
				t.Errorf("the recovered attribution carries no Rekor log index: %+v", r)
			}
		}
	}
	if !found {
		t.Errorf("the recovered attributions %+v do not include %s as %s",
			rep.Recovered, second.sha, second.claim.Identity)
	}

	// AND THE ORIGINAL STILL VERIFIES. A rewrite does not retract what was
	// signed; it only fails to carry it.
	orig, err := v.Verify(ctx, repo, second.sha)
	if err != nil {
		t.Fatalf("Verify of the original: %v", err)
	}
	if orig.Verdict != VerdictVerified {
		t.Errorf("the original commit %s now verifies as %s\n%s",
			second.sha, orig.Verdict, Render(orig))
	}
}

// Where "where possible" stops: with the original objects gone, a tree hash
// alone resolves nothing. Rekor is indexed by the hash of a COMMIT SHA, and a
// tree hash is not one — there is no query to make.
func TestTheTreeHashRecoveryStopsWhenTheOriginalObjectIsGone(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	repo := sharedRepo(t)
	signed := signOne(t, s, repo, "VER-003: a commit that will be forgotten", "rm-037")

	// A second repository holding the same tree and message, and none of the
	// history — a fresh clone of a rewritten branch, in effect.
	fresh := sharedRepo(t)
	harnessGit(t, fresh, "-c", "user.name="+harnessAuthorName,
		"-c", "user.email="+harnessAuthorEmail,
		"commit", "--no-gpg-sign", "-m",
		harnessGit(t, repo, "log", "-1", "--format=%B", signed.sha))
	rewritten := harnessGit(t, fresh, "rev-parse", "HEAD")

	rep, err := stackVerifier(t, s).Verify(ctx, fresh, rewritten)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictFailed {
		t.Errorf("verdict = %s, want %s\n%s", rep.Verdict, VerdictFailed, Render(rep))
	}
	if len(rep.Recovered) != 0 {
		t.Errorf("attribution was recovered from a repository that holds no signed "+
			"commit: %+v", rep.Recovered)
	}
	if !strings.Contains(Render(rep), "no other commit in this repository") {
		t.Errorf("the report does not say why recovery found nothing:\n%s", Render(rep))
	}
}

// ---------------------------------------------------------------------------
// VER-002, on the real stack. The unit case constructs the pure form — a
// certificate that is genuinely this commit's, with a trailer that is not.
// Here the forgery is what an attacker can actually do to a real signed
// commit: edit the trailer and rewrite the object.
// ---------------------------------------------------------------------------

func TestVER002AForgedTrailerOnARealSignedCommitFailsLoudly(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
	defer cancel()

	repo := sharedRepo(t)
	good := signOne(t, s, repo, "VER-002: a commit whose trailer will be forged", "rm-037")

	raw := harnessGit(t, repo, "cat-file", "commit", good.sha)
	forgedID := good.claim.Identity[:strings.LastIndex(good.claim.Identity, "/")] + "/run-forged"
	forged := strings.Replace(raw, good.claim.Identity, forgedID, 1)
	if forged == raw {
		t.Fatalf("the identity %q does not appear in the commit object", good.claim.Identity)
	}
	sha := writeRawCommit(t, repo, forged)

	rep, err := stackVerifier(t, s).Verify(ctx, repo, sha)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	out := Render(rep)
	t.Logf("VER-002, a forged trailer on a real signed commit:\n%s", out)

	if rep.Verdict != VerdictFailed {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictFailed, out)
	}
	if c := rep.check(t, CheckTrailerIdentity); c.Result != Failed {
		t.Errorf("check 3 = %s (%s), want %s", c.Result, c.Detail, Failed)
	}
	if !strings.Contains(out, "run-id") || !strings.Contains(out, "run-forged") {
		t.Errorf("the output does not name the differing segment and its two values:\n%s", out)
	}
}

// ---------------------------------------------------------------------------
// VER-006 — an unsigned commit in a monitored repo, end to end.
// ---------------------------------------------------------------------------

func TestVER006AnUnsignedCommitInAMonitoredRepoIsUnattributed(t *testing.T) {
	s := requireStack(t)
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	repo := sharedRepo(t)
	harnessGit(t, repo, "-c", "user.name=A Human", "-c", "user.email=human@example.com",
		"commit", "--no-gpg-sign", "-m", "an ordinary commit by a person")
	sha := harnessGit(t, repo, "rev-parse", "HEAD")

	rep, err := stackVerifier(t, s).Verify(ctx, repo, sha)
	if err != nil {
		t.Fatalf("Verify: %v", err)
	}
	if rep.Verdict != VerdictUnattributed {
		t.Fatalf("verdict = %s, want %s\n%s", rep.Verdict, VerdictUnattributed, Render(rep))
	}
}

// ---------------------------------------------------------------------------
// Container plumbing for VER-001.
// ---------------------------------------------------------------------------

// verifyRunnerImage carries git and busybox's `nc`, and nothing of ours.
const verifyRunnerImage = "alpine/git:latest"

type pgContainer struct {
	name    string
	ip      string
	network string
}

func startPostgres(ctx context.Context, t *testing.T, s *stack) pgContainer {
	t.Helper()
	network := s.project + "-ledger"
	name := s.project + "-postgres"
	if _, err := docker(ctx, "network", "create", network); err != nil {
		t.Fatalf("creating the ledger network: %v", err)
	}
	t.Cleanup(func() {
		c, cancel := context.WithTimeout(context.Background(), 60*time.Second)
		defer cancel()
		dockerIgnore(docker(c, "rm", "-f", name))
		dockerIgnore(docker(c, "network", "rm", network))
	})
	if _, err := docker(ctx, "run", "-d", "--name", name, "--network", network,
		"--env", "POSTGRES_USER=innsegl",
		"--env", "POSTGRES_PASSWORD=innsegl-test",
		"--env", "POSTGRES_DB=innsegl",
		"postgres:16"); err != nil {
		t.Fatalf("starting postgres: %v", err)
	}
	ip, err := docker(ctx, "inspect", "-f",
		"{{(index .NetworkSettings.Networks \""+network+"\").IPAddress}}", name)
	if err != nil {
		t.Fatalf("reading the postgres address: %v", err)
	}
	deadline := time.Now().Add(2 * time.Minute)
	var last error
	for time.Now().Before(deadline) {
		if last = probeFrom(ctx, network, ip, "5432"); last == nil {
			return pgContainer{name: name, ip: ip, network: network}
		}
		time.Sleep(2 * time.Second)
	}
	t.Fatalf("postgres never accepted a connection on its own network: %v", last)
	return pgContainer{}
}

// probeFrom opens a TCP connection from a throwaway container on `network`.
func probeFrom(ctx context.Context, network, host, port string) error {
	_, err := docker(ctx, "run", "--rm", "--network", network,
		"--entrypoint", "sh", verifyRunnerImage,
		"-c", "nc -z -w 5 "+host+" "+port)
	return err
}

// buildLinuxBinary cross-compiles the shipped `innsegl` binary for the
// container's platform. It is the SHIPPED binary, not a test harness: VER-001
// is about what a stranger runs.
func buildLinuxBinary(ctx context.Context, t *testing.T) string {
	t.Helper()
	arch, err := docker(ctx, "version", "--format", "{{.Server.Arch}}")
	if err != nil {
		t.Fatalf("reading the docker server architecture: %v", err)
	}
	dir, err := os.MkdirTemp("/tmp", "innsegl-bin-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(dir) })

	wd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	cmd := exec.CommandContext(ctx, "go", "build", "-o", filepath.Join(dir, "innsegl"),
		"innsegl.dev/innsegl/cmd/innsegl")
	cmd.Dir = filepath.Dir(filepath.Dir(wd))
	cmd.Env = append(os.Environ(), "GOOS=linux", "GOARCH="+arch, "CGO_ENABLED=0")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("cross-compiling innsegl for linux/%s: %v: %s", arch, err, out)
	}
	return dir
}

// writeRawCommit writes a hand-edited commit object and returns its SHA.
func writeRawCommit(t *testing.T, repo, object string) string {
	t.Helper()
	cmd := exec.CommandContext(t.Context(), "git", "-C", repo,
		"hash-object", "-t", "commit", "-w", "--stdin")
	cmd.Stdin = strings.NewReader(object)
	cmd.Env = append(os.Environ(), "GIT_CONFIG_NOSYSTEM=1")
	out, err := cmd.Output()
	if err != nil {
		t.Fatalf("git hash-object: %v", err)
	}
	return strings.TrimSpace(string(out))
}

// dockerIgnore discards the result of a best-effort cleanup command. A
// container that is already gone is the outcome this asked for.
func dockerIgnore(string, error) {}
