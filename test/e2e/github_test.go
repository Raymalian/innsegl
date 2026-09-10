// SPDX-License-Identifier: Apache-2.0

package e2e

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/jackc/pgx/v5/pgxpool"

	"innsegl.dev/innsegl/internal/ledger"
	"innsegl.dev/innsegl/internal/signing"
)

// ---------------------------------------------------------------------------
// The policy, loaded from one committed file.
// ---------------------------------------------------------------------------

// authorPolicyPath is the one place this repository states who its commits may
// be authored by. The gate names it in every refusal, because "add the address
// here" is the whole remediation.
const authorPolicyPath = "testdata/author-policy.json"

// noreplyOperator is the address these fixtures author as. It is the operator's
// GitHub noreply address — the one GitHub issues precisely so a commit need not
// carry a personal mailbox — and it is what the policy lists.
//
// Fixtures used to hardcode a personal address instead. Every one of them was
// printed by the case log below on every run of a public repository's CI, which
// is republishing what the policy is arranged not to publish.
const noreplyOperator = "66436734+KodyMike@users.noreply.github.com"

// authorPolicyFile is the on-disk form of signing.AuthorPolicy. It is decoded
// strictly: an unknown key is a failure rather than a silently ignored one,
// for the same reason ADR-0028 refuses an unparseable Operators entry — a typo
// in a policy with no cryptographic backstop must be loud.
type authorPolicyFile struct {
	PolicyFor    string   `json:"policy_for"`
	DocumentedIn string   `json:"documented_in"`
	Operators    []string `json:"operators"`

	AllowUnlinked bool `json:"allow_unlinked"`

	// InstalledBots are third-party bots the operator installed, admitted by
	// exact address. A CODING AGENT is never listed here — see the field's
	// documentation in internal/signing.
	InstalledBots []string `json:"installed_bots"`

	// InstalledBotsNote carries the rule in the file itself. Whoever adds an
	// entry is editing JSON, not reading Go, and the one thing they must know
	// is which actors may never be listed.
	InstalledBotsNote string `json:"installed_bots_note"`
}

func loadAuthorPolicy(t *testing.T) signing.AuthorPolicy {
	t.Helper()
	raw, err := os.ReadFile(authorPolicyPath)
	if err != nil {
		t.Fatalf("read %s: %v", authorPolicyPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var f authorPolicyFile
	if err := dec.Decode(&f); err != nil {
		t.Fatalf("decode %s: %v", authorPolicyPath, err)
	}
	if len(f.Operators) == 0 && !f.AllowUnlinked {
		// The zero value admits nothing (ADR-0028 §7), so an empty file would
		// turn the gate into an unconditional failure rather than a check.
		t.Fatalf("%s admits nothing: no operators and allow_unlinked false", authorPolicyPath)
	}
	return signing.AuthorPolicy{
		Operators: f.Operators, AllowUnlinked: f.AllowUnlinked, InstalledBots: f.InstalledBots,
	}
}

// ---------------------------------------------------------------------------
// Reading commits.
// ---------------------------------------------------------------------------

// commitRecord is one commit as the gate sees it: who it says wrote it, and
// what it says.
type commitRecord struct {
	SHA     string
	Author  string
	Message string
}

// errEmptyRange is the anti-vacuity guard. A gate that resolves the wrong
// revision range inspects nothing and passes forever; every range this gate is
// asked about contains at least one commit, so zero is a bug in the gate and
// not a clean bill of health.
var errEmptyRange = errors.New("the commit range resolved to no commits at all")

// gitEnv is a git environment that reads no ambient configuration. ADR-0028
// uses the same neutering for its differential oracle and for the same reason:
// a developer's `format.pretty` or `log.showSignature` must not be able to
// change what the gate reads back.
func gitEnv(home string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + home,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(home, "no-such-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
		"LC_ALL=C",
		"TZ=UTC",
	}
}

func runGit(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = env
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s (in %s): %w\n%s",
			strings.Join(args, " "), dir, err, stderr.String())
	}
	return stdout.String(), nil
}

// runGitStdin is runGit with something on the child's stdin, which `git
// patch-id` needs: it reads a diff and prints an identity for it.
func runGitStdin(ctx context.Context, dir string, env []string, stdin string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = env
	cmd.Stdin = strings.NewReader(stdin)
	var stdout, stderr bytes.Buffer
	cmd.Stdout, cmd.Stderr = &stdout, &stderr
	if err := cmd.Run(); err != nil {
		return "", fmt.Errorf("git %s (in %s): %w\n%s",
			strings.Join(args, " "), dir, err, stderr.String())
	}
	return stdout.String(), nil
}

// Unit separator between fields, record separator between commits. Neither can
// occur in a commit message: internal/signing refuses every C0 control but tab
// and newline, and git itself would have to be fed one deliberately.
const (
	fieldSep  = "\x1f"
	recordSep = "\x1e"
)

// collect reads the commits selected by revs. It returns errEmptyRange rather
// than an empty slice, so a caller cannot mistake "nothing selected" for
// "nothing wrong".
func collect(ctx context.Context, dir string, env []string, revs ...string) ([]commitRecord, error) {
	args := append([]string{"log", "--format=%H" + fieldSep + "%ae" + fieldSep + "%B" + recordSep}, revs...)
	out, err := runGit(ctx, dir, env, args...)
	if err != nil {
		return nil, err
	}
	var commits []commitRecord
	for _, chunk := range strings.Split(out, recordSep) {
		chunk = strings.Trim(chunk, "\n")
		if chunk == "" {
			continue
		}
		parts := strings.SplitN(chunk, fieldSep, 3)
		if len(parts) != 3 {
			return nil, fmt.Errorf("git log emitted a record with %d fields, want 3: %q", len(parts), chunk)
		}
		commits = append(commits, commitRecord{SHA: parts[0], Author: parts[1], Message: parts[2]})
	}
	if len(commits) == 0 {
		return nil, fmt.Errorf("%w: git log %s", errEmptyRange, strings.Join(revs, " "))
	}
	return commits, nil
}

// ---------------------------------------------------------------------------
// The gate itself.
// ---------------------------------------------------------------------------

// finding is one commit the gate refuses, and why.
type finding struct {
	SHA    string
	Author string
	Why    string
}

func (f finding) String() string { return f.SHA[:min(12, len(f.SHA))] + " <" + f.Author + "> " + f.Why }

// probe* are a fixed, admitted commit used to ask internal/signing whether a
// single line is a co-authorship trailer. The question is asked of that
// package rather than answered here: signing.hasTrailerToken is the matcher
// ADR-0028 §5 specifies (case-insensitive, whitespace before the separator
// allowed, start of line only), it is unexported, and a second copy of it here
// would be a second rule that can drift from the one sign_commit enforces.
var (
	probePolicy = signing.AuthorPolicy{AllowUnlinked: true}
	probeClaim  = signing.Claim{
		Identity: "spiffe://innsegl.dev/agent/gate/probe/probe",
		Run:      "probe",
		Task:     "probe",
	}
)

const probeAuthor = "gate@innsegl.invalid"

// isCoAuthorshipTrailer reports whether line is a `Co-authored-by:` trailer,
// as internal/signing judges one.
//
// Each line is asked about on its own, in a synthetic two-paragraph message,
// rather than handing the whole commit message over at once. CommitMessage
// returns on the FIRST problem it meets, so a message containing a `---`
// divider above a co-authorship trailer would come back as ErrMessage and the
// trailer would go unseen. Per line, nothing can mask anything else.
//
// A trailing CR is stripped first: git stores a CRLF message verbatim, and
// internal/signing refuses a carriage return before it looks for the trailer.
func isCoAuthorshipTrailer(line string) bool {
	line = strings.TrimSuffix(line, "\r")
	_, err := signing.CommitMessage(probePolicy, signing.Commit{
		Message:     "probe\n\n" + line,
		AuthorEmail: probeAuthor,
		Claim:       probeClaim,
	})
	return errors.Is(err, signing.ErrCoAuthorship)
}

// scanCommits applies I6 to each commit and returns every refusal.
//
// Both halves of I6 are asked, and neither is asked twice: the author gate is
// signing.AuthorPolicy.CheckAuthor — the same call CommitMessage makes before
// it will render a message — and the co-authorship gate is CommitMessage
// itself.
func scanCommits(p signing.AuthorPolicy, commits []commitRecord) []finding {
	var out []finding
	for _, c := range commits {
		if err := p.CheckAuthor(c.Author); err != nil {
			out = append(out, finding{SHA: c.SHA, Author: c.Author, Why: err.Error()})
		}
		for i, line := range strings.Split(c.Message, "\n") {
			if isCoAuthorshipTrailer(line) {
				out = append(out, finding{SHA: c.SHA, Author: c.Author, Why: fmt.Sprintf(
					"message line %d is a co-authorship trailer (%q); I6 admits one from no source, "+
						"resolvable or not (ADR-0028 §5)", i+1, strings.TrimSpace(line))})
			}
		}
	}
	return out
}

// ---------------------------------------------------------------------------
// GH-002 — the CI gate.
// ---------------------------------------------------------------------------

// TestGH002TheAuthorGateRejectsAForbiddenAuthor is doc 07 GH-002's teeth.
//
// A gate that inspects the wrong range passes on every pull request forever,
// so the gate is first driven over a repository built to contain exactly the
// commits it must refuse and exactly the commits it must admit. The same
// scanCommits the pull-request gate calls is the one under test here.
func TestGH002TheAuthorGateRejectsAForbiddenAuthor(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	home := t.TempDir()
	env := gitEnv(home)
	dir := t.TempDir()

	if _, err := runGit(ctx, dir, env, "init", "-q", "-b", "main"); err != nil {
		t.Fatalf("git init: %v", err)
	}

	cases := []struct {
		label   string
		email   string
		message string
		refused bool
	}{{
		label:   "the operator, listed by address",
		email:   noreplyOperator,
		message: "feat: a commit by the operator\n",
	}, {
		label:   "the same operator on a squash merge",
		email:   noreplyOperator,
		message: "chore: a squash merge performed by the operator\n",
	}, {
		label:   "an unlinked address in a reserved TLD (RFC 2606)",
		email:   "agent@innsegl.invalid",
		message: "feat: a commit by an agent\n",
	}, {
		label:   "an unlinked address in a reserved second-level name",
		email:   "agent@example.com",
		message: "feat: another commit by an agent\n",
	}, {
		label:   "a GitHub noreply address that is NOT the operator's",
		email:   "9999+agent-bot@users.noreply.github.com",
		message: "feat: the commit that makes agent-bot a contributor\n",
		refused: true,
	}, {
		label:   "a resolvable address in a real domain, not listed as an operator",
		email:   "agent@innsegl.dev",
		message: "feat: a commit by an address that can hold a verified email\n",
		refused: true,
	}, {
		label:   "GitHub's own merge identity",
		email:   "noreply@github.com",
		message: "feat: a commit authored by GitHub itself\n",
		refused: true,
	}, {
		label:   "an admitted author, but the message co-authors a resolvable account",
		email:   noreplyOperator,
		message: "feat: a commit with a co-author\n\nCo-authored-by: A Bot <bot@gmail.com>\n",
		refused: true,
	}, {
		label: "an admitted author whose PROSE mentions the trailer key mid-line",
		email: noreplyOperator,
		message: "docs: explain the rule\n\nSIG-006 asserts no Co-authored-by is ever emitted, and\n" +
			"Agent-Task exactly as ADR-0028 §5 describes.\n",
	}}

	refused := map[string]string{} // sha -> label
	admitted := map[string]string{}
	for i, c := range cases {
		sha := commitAs(ctx, t, dir, env, c.email, c.message)
		if c.refused {
			refused[sha] = c.label
		} else {
			admitted[sha] = c.label
		}
		t.Logf("case %d  %s  <%s>  %s", i, sha[:12], c.email, c.label)
	}

	commits, err := collect(ctx, dir, env, "--no-merges", "HEAD")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	if got, want := len(commits), len(cases); got != want {
		t.Fatalf("the fixture repository yielded %d commits, want %d", got, want)
	}

	got := map[string]finding{}
	for _, f := range scanCommits(loadAuthorPolicy(t), commits) {
		if prev, dup := got[f.SHA]; dup {
			t.Logf("note: %s produced a second finding: %s (first: %s)", f.SHA[:12], f.Why, prev.Why)
			continue
		}
		got[f.SHA] = f
	}

	for sha, label := range refused {
		f, ok := got[sha]
		if !ok {
			t.Errorf("GATE DID NOT BITE: %s (%s) was admitted; I6 requires it to be refused",
				sha[:12], label)
			continue
		}
		t.Logf("refused as required: %s — %s", label, f)
	}
	for sha, label := range admitted {
		if f, ok := got[sha]; ok {
			t.Errorf("GATE OVER-BITES: %s (%s) was refused: %s", sha[:12], label, f.Why)
		}
	}
}

// commitAs writes one empty commit with the given author and message and
// returns its SHA. --cleanup=verbatim keeps the message byte-exact, so a
// trailer in a fixture is the trailer the gate reads back.
func commitAs(ctx context.Context, t *testing.T, dir string, env []string, email, message string) string {
	t.Helper()
	msg := filepath.Join(t.TempDir(), "msg")
	if err := os.WriteFile(msg, []byte(message), 0o600); err != nil {
		t.Fatalf("write message: %v", err)
	}
	withAuthor := append([]string{}, env...)
	withAuthor = append(withAuthor,
		"GIT_AUTHOR_NAME=Fixture", "GIT_AUTHOR_EMAIL="+email,
		"GIT_COMMITTER_NAME=Fixture", "GIT_COMMITTER_EMAIL=committer@innsegl.invalid",
		"GIT_AUTHOR_DATE=2026-01-01T00:00:00Z", "GIT_COMMITTER_DATE=2026-01-01T00:00:00Z",
	)
	if _, err := runGit(ctx, dir, withAuthor, "commit", "-q", "--allow-empty",
		"--cleanup=verbatim", "--no-gpg-sign", "-F", msg); err != nil {
		t.Fatalf("git commit: %v", err)
	}
	sha, err := runGit(ctx, dir, env, "rev-parse", "HEAD")
	if err != nil {
		t.Fatalf("git rev-parse: %v", err)
	}
	return strings.TrimSpace(sha)
}

// TestGH002ARangeThatSelectsNothingIsAFailure pins the anti-vacuity guard.
// This is the shape a broken gate takes: it resolves a range, the range is
// empty, every commit in it satisfies I6 trivially, and the pull request
// passes. collect refuses to return that answer.
func TestGH002ARangeThatSelectsNothingIsAFailure(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	home := t.TempDir()
	env := gitEnv(home)
	dir := t.TempDir()
	if _, err := runGit(ctx, dir, env, "init", "-q", "-b", "main"); err != nil {
		t.Fatalf("git init: %v", err)
	}
	commitAs(ctx, t, dir, env, noreplyOperator, "feat: something\n")

	if _, err := collect(ctx, dir, env, "HEAD..HEAD"); !errors.Is(err, errEmptyRange) {
		t.Fatalf("an empty range returned %v, want %v", err, errEmptyRange)
	}
}

// TestGH002ThisRepositorysCommitHistorySatisfiesI6 is the gate as CI runs it:
// every non-merge commit reachable from HEAD, against the committed policy.
//
// Merge commits are excluded because GitHub's own contributor calculation
// excludes them, and because a merge commit's author is whoever performed the
// merge rather than the author of any content. GitHub synthesises one such
// commit per pull-request run at refs/pull/N/merge, authored by
// `GitHub <noreply@github.com>`; it is never pushed anywhere and inspecting it
// would fail every pull request for a commit that does not exist.
func TestGH002ThisRepositorysCommitHistorySatisfiesI6(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	home := t.TempDir()
	env := gitEnv(home)
	root := repoRoot(ctx, t, env)

	shallow, err := runGit(ctx, root, env, "rev-parse", "--is-shallow-repository")
	if err != nil {
		t.Fatalf("rev-parse --is-shallow-repository: %v", err)
	}
	if strings.TrimSpace(shallow) == "true" {
		// Not a skip. A shallow clone hides most of the history from the gate,
		// and a gate that silently inspects three commits out of twenty-five is
		// the false green this whole file exists to refuse.
		t.Fatalf("this is a shallow clone, so most of the history is invisible to the I6 gate. " +
			"Check out with `fetch-depth: 0` (see .github/workflows/author-gate.yml)")
	}

	commits, err := collect(ctx, root, env, "--no-merges", "HEAD")
	if err != nil {
		t.Fatalf("collect: %v", err)
	}

	// Cross-check the walk against git's own count. A parsing bug that dropped
	// records would otherwise shrink the inspected set without saying so.
	countOut, err := runGit(ctx, root, env, "rev-list", "--no-merges", "--count", "HEAD")
	if err != nil {
		t.Fatalf("rev-list --count: %v", err)
	}
	want, err := strconv.Atoi(strings.TrimSpace(countOut))
	if err != nil {
		t.Fatalf("parse rev-list count %q: %v", countOut, err)
	}
	if len(commits) != want {
		t.Fatalf("inspected %d commits but git reports %d reachable non-merge commits; "+
			"the gate is reading the wrong range", len(commits), want)
	}

	// This test asserts an ABSENCE, which is the shape that passes when it is
	// reading nothing. So prove the scan is reading THIS history: under the
	// zero-value policy, which ADR-0028 §7 says admits nothing, every one of
	// these commits must come back refused.
	if n := len(scanCommits(signing.AuthorPolicy{}, commits)); n < len(commits) {
		t.Fatalf("the zero-value policy admits nothing, so it must refuse all %d commits; "+
			"it refused %d — the scan is not reading this history", len(commits), n)
	}

	policy := loadAuthorPolicy(t)
	t.Logf("I6 gate: %d non-merge commits reachable from HEAD, policy %s", len(commits), authorPolicyPath)
	seen := map[string]int{}
	for _, c := range commits {
		seen[c.Author]++
	}
	// The census prints an address in full only when the policy admits it, and
	// an admitted address is a listed operator or a reserved domain — neither
	// of which is anybody's personal mail. Every other address is a commit
	// author this repository is not claiming as its own, and printing it here
	// would republish it in the log of every run on a public repository. The
	// domain and the count are what the census is read for.
	for _, a := range sortedKeys(seen) {
		t.Logf("  %4d  %s", seen[a], censusLabel(policy, a))
	}

	// The SAME baseline GH-003 reads, and deliberately one file rather than
	// two: a reader asking "what does this repository knowingly excuse, and
	// why" should have one place to look, not one per gate. An entry is dated
	// and carries a reason, and the loader refuses one without both.
	excused := loadAttributionBaseline(t)
	for _, f := range scanCommits(policy, commits) {
		if reason, ok := excused[f.SHA]; ok {
			t.Logf("  baseline  %s  %s", f.SHA[:12], reason)
			continue
		}
		t.Errorf("I6 VIOLATION: %s\n"+
			"      If this address is a human operator of this deployment, add it to %s.\n"+
			"      It is never correct to add an agent address there (ADR-0028 §6).\n"+
			"      It is never correct to add a NEW commit to %s either: that file records\n"+
			"      history that cannot be fixed, not changes that have not landed yet.",
			f, authorPolicyPath, attributionBaselinePath)
	}
}

// censusLabel renders one author for the census above: in full when the policy
// admits it, and as its domain alone when it does not.
//
// An admitted address is a listed operator or an address in a reserved domain,
// and neither is personal. An address the policy does not admit is one this
// repository is not claiming, and the census is a distribution rather than a
// contact list — the domain and the count carry what it is read for.
func censusLabel(p signing.AuthorPolicy, addr string) string {
	if p.CheckAuthor(addr) == nil {
		return addr
	}
	at := strings.LastIndex(addr, "@")
	if at < 0 {
		return "(not an address)"
	}
	return "(withheld)@" + addr[at+1:]
}

func repoRoot(ctx context.Context, t *testing.T, env []string) string {
	t.Helper()
	wd, err := os.Getwd()
	if err != nil {
		t.Fatalf("getwd: %v", err)
	}
	out, err := runGit(ctx, wd, env, "rev-parse", "--show-toplevel")
	if err != nil {
		t.Fatalf("rev-parse --show-toplevel: %v", err)
	}
	return strings.TrimSpace(out)
}

func sortedKeys(m map[string]int) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// ---------------------------------------------------------------------------
// GH-001 — the empirical half, and the dated record it writes.
// ---------------------------------------------------------------------------

const (
	// gh001RecordPath is the dated snapshot threat model §5, residual risk 3
	// requires. It is a tracked file, rewritten by a successful real run.
	gh001RecordPath = "testdata/gh-001-run.json"

	gh001RepoEnv = "INNSEGL_GH001_REPO"
	// gh001TokenEnv names the variable; it is not a credential itself.
	gh001TokenEnv = "INNSEGL_GH001_TOKEN"
	gh001WaitEnv  = "INNSEGL_GH001_WAIT"

	// gh001AuthorEmail is the unlinked author under test: a mailbox in a
	// top-level name RFC 2606 §2 guarantees will never be delegated, so no
	// GitHub account can ever hold it as a verified address (ADR-0028 §6).
	gh001AuthorEmail = "agent@innsegl.invalid"

	// gh001DefaultWait is the propagation window. GitHub computes the
	// contributor list asynchronously and caches it; the endpoint answers 202
	// while it is recomputing. The wait is generous on purpose — a short wait
	// that observes "no contributor" only because the list had not refreshed
	// yet would be the false green this test exists to avoid.
	gh001DefaultWait = 15 * time.Minute

	gh001StatusNeverRun = "never-run"
	gh001StatusRan      = "ran"
)

// gh001Record is testdata/gh-001-run.json. Every observation the assertion
// rests on is a field, so a reader can tell what was measured and when without
// re-running anything.
type gh001Record struct {
	TestID                     string   `json:"test_id"`
	Invariant                  string   `json:"invariant"`
	Status                     string   `json:"status"`
	LastRun                    *string  `json:"last_run"`
	RerunAfterDays             int      `json:"rerun_after_days"`
	ScratchRepo                string   `json:"scratch_repo"`
	AuthorEmail                string   `json:"author_email"`
	PushedCommits              []string `json:"pushed_commits"`
	PropagationWait            string   `json:"propagation_wait"`
	ContributorsBefore         []string `json:"contributors_before"`
	ContributorsAfter          []string `json:"contributors_after"`
	AnonymousContributorsAfter []string `json:"anonymous_contributors_after"`
	CommitAuthorField          string   `json:"commit_author_field"`
	GitHubVerifiedBadge        string   `json:"github_verified_badge"`
	Note                       string   `json:"note"`
}

func readGH001Record(t *testing.T) gh001Record {
	t.Helper()
	raw, err := os.ReadFile(gh001RecordPath)
	if err != nil {
		t.Fatalf("read %s: %v", gh001RecordPath, err)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	var r gh001Record
	if err := dec.Decode(&r); err != nil {
		t.Fatalf("decode %s: %v", gh001RecordPath, err)
	}
	return r
}

// TestGH001TheRecordedRunDateIsHonest is the half of GH-001 that runs on every
// CI run, on every machine, with no credential and no network. It never skips.
//
// It enforces threat model §5, residual risk 3 — "the test is dated and re-run
// on a schedule" — by making the schedule a failing assertion rather than an
// intention: once a real run has been recorded, this fails when that record
// ages past rerun_after_days.
//
// It also refuses a record that claims a pass it did not observe. A record
// with status "ran" must carry the repository, the author address, the pushed
// SHAs, and contributor lists that are actually equal. A hand-edited "ran" with
// no observations behind it does not get to stand in for the measurement.
func TestGH001TheRecordedRunDateIsHonest(t *testing.T) {
	t.Parallel()
	r := readGH001Record(t)

	if r.TestID != "GH-001" || r.Invariant != "I6" {
		t.Errorf("%s identifies itself as %q/%q, want GH-001/I6", gh001RecordPath, r.TestID, r.Invariant)
	}
	if r.RerunAfterDays <= 0 {
		t.Fatalf("%s sets rerun_after_days to %d; a snapshot with no expiry is not dated",
			gh001RecordPath, r.RerunAfterDays)
	}

	switch r.Status {
	case gh001StatusNeverRun:
		if r.LastRun != nil {
			t.Errorf("status is %q but last_run is %q", r.Status, *r.LastRun)
		}
		if len(r.PushedCommits) != 0 || r.ScratchRepo != "" {
			t.Errorf("status is %q but the record carries observations (%q, %v)",
				r.Status, r.ScratchRepo, r.PushedCommits)
		}
		// Loud, on every run, so the debt is visible in the log rather than
		// only in this file.
		t.Logf("I6 EMPIRICAL HALF UNPROVEN: GH-001 has never been run. Nothing in this\n"+
			"      repository has observed GitHub's contributor behaviour for a commit\n"+
			"      authored by an unlinked address; GH-002 proves only that we followed\n"+
			"      our own rule. See %s and the skip message of\n"+
			"      TestGH001NoContributorAppearsForAnUnlinkedAuthor.", gh001RecordPath)

	case gh001StatusRan:
		if r.LastRun == nil {
			t.Fatalf("status is %q with no last_run", r.Status)
		}
		at, err := time.Parse(time.RFC3339, *r.LastRun)
		if err != nil {
			t.Fatalf("last_run %q is not RFC 3339: %v", *r.LastRun, err)
		}
		age := time.Since(at)
		if age < 0 {
			t.Fatalf("last_run %s is in the future", *r.LastRun)
		}
		if r.ScratchRepo == "" || r.AuthorEmail == "" || len(r.PushedCommits) == 0 {
			t.Errorf("status is %q but the record names no repository, author or commits", r.Status)
		}
		if !equalStrings(r.ContributorsBefore, r.ContributorsAfter) {
			t.Errorf("the recorded run is not a pass: contributors before %v, after %v",
				r.ContributorsBefore, r.ContributorsAfter)
		}
		limit := time.Duration(r.RerunAfterDays) * 24 * time.Hour
		t.Logf("GH-001 last observed GitHub on %s (%d days ago), re-run interval %d days",
			at.UTC().Format(time.RFC3339), int(age.Hours()/24), r.RerunAfterDays)
		if age > limit {
			t.Errorf("GH-001's snapshot of GitHub's contributor behaviour is %d days old, past the\n"+
				"      %d-day re-run interval. Threat model §5 residual risk 3 requires a re-run:\n"+
				"      GitHub's attribution logic is external and may have changed. Re-run\n"+
				"      TestGH001NoContributorAppearsForAnUnlinkedAuthor and commit the updated %s.",
				int(age.Hours()/24), r.RerunAfterDays, gh001RecordPath)
		}

	default:
		t.Fatalf("%s has status %q, want %q or %q",
			gh001RecordPath, r.Status, gh001StatusNeverRun, gh001StatusRan)
	}
}

func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	x, y := append([]string(nil), a...), append([]string(nil), b...)
	sort.Strings(x)
	sort.Strings(y)
	for i := range x {
		if x[i] != y[i] {
			return false
		}
	}
	return true
}

// TestGH001NoContributorAppearsForAnUnlinkedAuthor is doc 07 GH-001.
//
// It pushes commits authored by an address in a reserved domain to a scratch
// GitHub repository, waits out the contributor-list propagation window, and
// asks GitHub whether a contributor appeared. There is no way to answer that
// question without a real repository, a real credential and a real wait, and
// no way to weaken it into something that runs offline: a local check would
// only re-assert what GH-002 already asserts, and the thing under test is
// GitHub's behaviour, not ours.
//
// So it refuses to run rather than pretending. The skip is allowlisted in
// scripts/test-no-skips.sh, and TestGH001TheRecordedRunDateIsHonest keeps the
// debt visible on every CI run.
func TestGH001NoContributorAppearsForAnUnlinkedAuthor(t *testing.T) {
	repo := os.Getenv(gh001RepoEnv)
	token := os.Getenv(gh001TokenEnv)
	if repo == "" || token == "" {
		t.Skipf(`skipping: GH-001 measures GITHUB's behaviour and needs a human to provision it.

  What it does
      Clones a scratch GitHub repository, adds two commits authored by
      %s carrying the three Agent-* trailers, pushes them to
      the default branch, waits %s for GitHub's contributor list to
      recompute, and asserts the set of account contributors is unchanged and
      that GET /repos/{repo}/commits/{sha} reports author: null.

  What it needs from you
      %s   owner/name of a THROWAWAY repository with at least one
                             commit on its default branch. Its history is
                             modified by this test; never point it at a real
                             repository. It must not be a fork, and it must be
                             one whose contributor graph you do not care about.
      %s   a token that can push to that repository
                             (fine-grained: Contents read+write on that repo
                             only). It is never logged; git is fed it through
                             GIT_ASKPASS.
      %s    optional, default %s. GitHub recomputes the
                             contributor list asynchronously and caches it; a
                             short wait can observe "no contributor" merely
                             because the list had not refreshed.

  How to run it
      INNSEGL_GH001_REPO=you/innsegl-gh001-scratch \
      INNSEGL_GH001_TOKEN=... \
        go test ./test/e2e -run TestGH001NoContributorAppearsForAnUnlinkedAuthor -v -timeout 60m

      On success it rewrites %s with the run date and every
      observation. Commit that file: it is the dated snapshot threat model §5
      residual risk 3 requires, and TestGH001TheRecordedRunDateIsHonest fails
      once it ages past its re-run interval.

  Until then
      I6's empirical half is UNPROVEN. GH-002 proves this repository follows
      its own author policy; only this test proves the policy achieves what I6
      claims.`,
			gh001AuthorEmail, gh001DefaultWait,
			gh001RepoEnv, gh001TokenEnv, gh001WaitEnv, gh001DefaultWait,
			gh001RecordPath)
	}

	wait := gh001DefaultWait
	if v := os.Getenv(gh001WaitEnv); v != "" {
		d, err := time.ParseDuration(v)
		if err != nil {
			t.Fatalf("%s=%q is not a duration: %v", gh001WaitEnv, v, err)
		}
		wait = d
	}

	ctx, cancel := context.WithTimeout(context.Background(), wait+30*time.Minute)
	defer cancel()

	meta := struct {
		DefaultBranch string `json:"default_branch"`
		Fork          bool   `json:"fork"`
	}{}
	mustGetGitHub(ctx, t, token, "/repos/"+repo, &meta)
	if meta.Fork {
		t.Fatalf("%s is a fork; GitHub attributes a fork's commits to the upstream contributor "+
			"graph, so the measurement would not be about this repository", repo)
	}
	t.Logf("scratch repository %s, default branch %s", repo, meta.DefaultBranch)

	before := contributorLogins(ctx, t, token, repo, false)
	t.Logf("contributors before: %v", before)

	shas := pushUnlinkedCommits(ctx, t, token, repo, meta.DefaultBranch)
	t.Logf("pushed: %v", shas)

	// The sharp signal, available immediately: GitHub reports the account it
	// resolved the author email to, and null when it resolved none. A
	// contributor is exactly an account that resolved, so a non-null author
	// here is I6 already broken, before any propagation delay.
	authorField := "null"
	for _, sha := range shas {
		var c struct {
			Author *struct {
				Login string `json:"login"`
			} `json:"author"`
			Commit struct {
				Author struct {
					Email string `json:"email"`
				} `json:"author"`
			} `json:"commit"`
		}
		mustGetGitHub(ctx, t, token, "/repos/"+repo+"/commits/"+sha, &c)
		if c.Commit.Author.Email != gh001AuthorEmail {
			t.Fatalf("commit %s reads back with author email %q, want %q — the fixture did not push what it meant to",
				sha, c.Commit.Author.Email, gh001AuthorEmail)
		}
		if c.Author != nil {
			authorField = c.Author.Login
			t.Errorf("I6 VIOLATION: GitHub resolved %s to the account %q for commit %s",
				gh001AuthorEmail, c.Author.Login, sha)
		}
	}

	t.Logf("waiting %s for GitHub's contributor list to recompute", wait)
	select {
	case <-time.After(wait):
	case <-ctx.Done():
		t.Fatalf("context expired during the propagation wait: %v", ctx.Err())
	}

	after := contributorLogins(ctx, t, token, repo, false)
	anon := contributorLogins(ctx, t, token, repo, true)
	t.Logf("contributors after:  %v", after)
	t.Logf("including anonymous: %v", anon)

	if !equalStrings(before, after) {
		t.Errorf("I6 VIOLATION: the contributor list changed after pushing commits authored by %s\n"+
			"      before: %v\n      after:  %v", gh001AuthorEmail, before, after)
	}
	if t.Failed() {
		t.Fatalf("GH-001 observed a contributor appearing; the record is NOT updated. " +
			"GitHub's attribution behaviour has changed and I6's author policy needs revisiting " +
			"(threat model §5, residual risk 3).")
	}

	writeGH001Record(t, gh001Record{
		TestID:                     "GH-001",
		Invariant:                  "I6",
		Status:                     gh001StatusRan,
		LastRun:                    ptr(time.Now().UTC().Format(time.RFC3339)),
		RerunAfterDays:             readGH001Record(t).RerunAfterDays,
		ScratchRepo:                repo,
		AuthorEmail:                gh001AuthorEmail,
		PushedCommits:              shas,
		PropagationWait:            wait.String(),
		ContributorsBefore:         before,
		ContributorsAfter:          after,
		AnonymousContributorsAfter: anon,
		CommitAuthorField:          authorField,
		GitHubVerifiedBadge: "not applicable (IP §3 E3): GitHub does not render gitsign signatures " +
			"as Verified, because it checks a signature against keys an account has uploaded and " +
			"gitsign's key is ephemeral. Expected, permanent, not chased.",
		Note: "Observed by TestGH001NoContributorAppearsForAnUnlinkedAuthor. This is a snapshot " +
			"of EXTERNAL behaviour (threat model §5, residual risk 3) and expires: " +
			"TestGH001TheRecordedRunDateIsHonest fails once it is older than rerun_after_days.",
	})
	t.Logf("recorded the run in %s — commit it", gh001RecordPath)
}

func ptr[T any](v T) *T { return &v }

func writeGH001Record(t *testing.T, r gh001Record) {
	t.Helper()
	raw, err := json.MarshalIndent(r, "", "  ")
	if err != nil {
		t.Fatalf("marshal record: %v", err)
	}
	if err := os.WriteFile(gh001RecordPath, append(raw, '\n'), 0o600); err != nil {
		t.Fatalf("write %s: %v", gh001RecordPath, err)
	}
}

// mustGetGitHub performs one authenticated GET against the REST API. The token
// is never placed anywhere it could be logged.
func mustGetGitHub(ctx context.Context, t *testing.T, token, path string, into any) {
	t.Helper()
	status, body := getGitHub(ctx, t, token, path)
	if status != http.StatusOK {
		t.Fatalf("GET %s: HTTP %d: %s", path, status, truncate(body))
	}
	if into != nil {
		if err := json.Unmarshal(body, into); err != nil {
			t.Fatalf("GET %s: decode: %v: %s", path, err, truncate(body))
		}
	}
}

func getGitHub(ctx context.Context, t *testing.T, token, path string) (int, []byte) {
	t.Helper()
	u := "https://api.github.com" + path
	if _, err := url.Parse(u); err != nil {
		t.Fatalf("bad url %q: %v", u, err)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		t.Fatalf("build request for %s: %v", path, err)
	}
	req.Header.Set("Authorization", "Bearer "+token)
	req.Header.Set("Accept", "application/vnd.github+json")
	req.Header.Set("X-GitHub-Api-Version", "2022-11-28")
	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		t.Fatalf("GET %s: %v", path, err)
	}
	defer func() { _ = resp.Body.Close() }()
	body, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		t.Fatalf("GET %s: read body: %v", path, err)
	}
	return resp.StatusCode, body
}

func truncate(b []byte) string {
	const limit = 400
	if len(b) > limit {
		return string(b[:limit]) + "…"
	}
	return string(b)
}

// contributorLogins reads the contributor list, polling through the 202 that
// GitHub returns while it recomputes the statistic.
//
// With anon=false the list is accounts only, which is exactly what I6 forbids
// gaining a member. With anon=true it also contains "anonymous" entries keyed
// by the raw author identity in the commits; those are not accounts and are
// recorded as an observation rather than asserted on.
func contributorLogins(ctx context.Context, t *testing.T, token, repo string, anon bool) []string {
	t.Helper()
	path := "/repos/" + repo + "/contributors?per_page=100"
	if anon {
		path += "&anon=1"
	}
	deadline := time.Now().Add(5 * time.Minute)
	for {
		status, body := getGitHub(ctx, t, token, path)
		switch status {
		case http.StatusOK:
			var list []struct {
				Login string `json:"login"`
				Type  string `json:"type"`
				Name  string `json:"name"`
				Email string `json:"email"`
			}
			if err := json.Unmarshal(body, &list); err != nil {
				t.Fatalf("decode contributors: %v: %s", err, truncate(body))
			}
			out := make([]string, 0, len(list))
			for _, c := range list {
				switch {
				case c.Login != "":
					out = append(out, c.Login)
				case anon:
					out = append(out, "anonymous:"+c.Name+" <"+c.Email+">")
				default:
					t.Fatalf("a non-anonymous contributor came back with no login: %+v", c)
				}
			}
			sort.Strings(out)
			return out
		case http.StatusNoContent:
			// An empty repository has no contributors at all.
			return []string{}
		case http.StatusAccepted:
			if time.Now().After(deadline) {
				t.Fatalf("GitHub kept answering 202 (statistic still computing) for 5 minutes")
			}
			select {
			case <-time.After(15 * time.Second):
			case <-ctx.Done():
				t.Fatalf("context expired waiting for the contributor statistic: %v", ctx.Err())
			}
		default:
			t.Fatalf("GET %s: HTTP %d: %s", path, status, truncate(body))
		}
	}
}

// pushUnlinkedCommits clones the scratch repository, adds two commits authored
// by the unlinked address and carrying the three Agent-* trailers, and pushes
// them to the default branch. The messages are rendered by
// signing.CommitMessage, so what GitHub sees is what sign_commit produces.
func pushUnlinkedCommits(ctx context.Context, t *testing.T, token, repo, branch string) []string {
	t.Helper()
	home := t.TempDir()
	dir := t.TempDir()

	// The token reaches git through GIT_ASKPASS, never through a command line
	// or a URL, so nothing that gets logged can carry it.
	askpass := filepath.Join(home, "askpass.sh")
	if err := os.WriteFile(askpass, []byte("#!/bin/sh\nprintf '%s' \"$INNSEGL_GH001_TOKEN\"\n"), 0o700); err != nil {
		t.Fatalf("write askpass: %v", err)
	}
	env := append(gitEnv(home),
		"GIT_ASKPASS="+askpass,
		gh001TokenEnv+"="+token,
		"GIT_AUTHOR_NAME=Innsegl Agent",
		"GIT_AUTHOR_EMAIL="+gh001AuthorEmail,
		"GIT_COMMITTER_NAME=Innsegl Agent",
		"GIT_COMMITTER_EMAIL="+gh001AuthorEmail,
	)
	remote := "https://x-access-token@github.com/" + repo + ".git"

	if _, err := runGit(ctx, dir, env, "clone", "--depth", "1", "--branch", branch, remote, "."); err != nil {
		t.Fatalf("clone: %v", err)
	}

	policy := signing.AuthorPolicy{AllowUnlinked: true}
	var shas []string
	for i := 1; i <= 2; i++ {
		run := "run-gh001-" + strconv.Itoa(i)
		claim := signing.Claim{
			Identity: "spiffe://innsegl.dev/agent/e2e/gh-001/" + run,
			Run:      run,
			Task:     "gh-001",
		}
		msg, msgErr := signing.CommitMessage(policy, signing.Commit{
			Message:     fmt.Sprintf("test(gh-001): empirical contributor probe %d\n", i),
			AuthorEmail: gh001AuthorEmail,
			Claim:       claim,
		})
		if msgErr != nil {
			t.Fatalf("render commit message: %v", msgErr)
		}
		name := filepath.Join(dir, fmt.Sprintf("gh-001-%d-%d.txt", time.Now().UTC().Unix(), i))
		if writeErr := os.WriteFile(name, []byte(msg), 0o600); writeErr != nil {
			t.Fatalf("write probe file: %v", writeErr)
		}
		if _, addErr := runGit(ctx, dir, env, "add", "-A"); addErr != nil {
			t.Fatalf("git add: %v", addErr)
		}
		msgFile := filepath.Join(home, "msg")
		if writeErr := os.WriteFile(msgFile, []byte(msg), 0o600); writeErr != nil {
			t.Fatalf("write message: %v", writeErr)
		}
		if _, commitErr := runGit(ctx, dir, env, "commit", "-q", "--cleanup=verbatim", "--no-gpg-sign", "-F", msgFile); commitErr != nil {
			t.Fatalf("git commit: %v", commitErr)
		}
		sha, shaErr := runGit(ctx, dir, env, "rev-parse", "HEAD")
		if shaErr != nil {
			t.Fatalf("git rev-parse: %v", shaErr)
		}
		shas = append(shas, strings.TrimSpace(sha))
	}

	if _, err := runGit(ctx, dir, env, "push", "origin", "HEAD:"+branch); err != nil {
		t.Fatalf("push: %v", err)
	}
	return shas
}

// GH-003 (proposed for doc 07; doc 07 is not modified here).
//
// A commit that CLAIMS an agent identity must carry the signature that backs
// the claim.
//
// # What this catches, measured rather than imagined
//
// On 2026-09-08 a correctly signed agent commit was merged with GitHub's squash
// button. Squashing does not move a commit; it writes a NEW one. The trailers
// survived, because they are message text. The gitsign signature did not,
// because it covers the commit object that no longer exists. What landed on
// `main` was `4ab53d0`, which says:
//
//	Agent-Identity: spiffe://innsegl.dev/agent/cb590b02/c1c85725/run-ed343721...
//
// and carries a PGP signature made by GitHub's own web-flow key. GitHub renders
// it as "Verified". The shipped verifier answers `failed` on all three checks,
// with "the commit's signature is not PEM".
//
// That is worse than an unsigned commit. An unsigned commit claims nothing; this
// one claims an agent did the work and offers a signature by somebody else.
//
// # Why the check is the signature's TYPE and not a full verification
//
// gitsign writes a PKCS#7/x509 signature, which begins `BEGIN SIGNED MESSAGE`.
// PGP begins `BEGIN PGP SIGNATURE`. Telling them apart needs no network, no
// Fulcio and no Rekor, so this gate is cheap enough to run on every build --
// and it is exactly the distinction the failure mode turns on. Whether a
// well-formed x509 signature actually verifies is the verifier's question, and
// it is asked where the answers can be trusted: against a live log.
//
// ADR-0046 disabled squash merging for this reason. This is the half that does
// not depend on which button somebody clicks.
func TestGH003ACommitClaimingAnAgentIdentityCarriesAnAgentSignature(t *testing.T) {
	t.Parallel()
	ctx := t.Context()
	env := gitEnv(t.TempDir())
	root := repoRoot(ctx, t, env)

	// THE RANGE IS THE PULL REQUEST, not the whole history.
	//
	// Written to walk everything reachable from HEAD, this gate turned main red
	// the moment the first pull request merged: nine ATTRIBUTION VIOLATIONs,
	// every one of them a commit it had passed a day earlier. Nothing had gone
	// wrong. GitHub's rebase button rewrites each commit, so the signature that
	// covered the old object is gone -- measured against the button itself --
	// while the trailers survive because they are message text.
	//
	// So the question has to be asked while the evidence still exists. In a
	// pull request the commits are the ones that were signed; after a merge
	// they are not, and no amount of scanning brings the signature back.
	//
	// This is a narrowing and not a weakening: every commit still passes
	// through it exactly once, before it can reach main, and a commit that
	// claims an identity it cannot prove is still refused there. What it stops
	// doing is re-asking a question whose answer was destroyed in between.
	// Checking main again becomes possible under ADR-0047, which anchors
	// attribution to the change rather than to the commit object; #195 rebuilds
	// this gate on it.
	// TWO MODES, AND THE REPORT SAYS WHICH ONE RAN (#195).
	//
	// With a ledger, the question is ADR-0047's and it can be asked anywhere:
	// does a signed run's record carry the change this commit makes? That
	// survives a rebase, so `main` becomes checkable again.
	//
	// Without one, the question is the old one — is the signature on the
	// object — and it is only answerable inside a pull request, because the
	// merge destroys the object it was asked about. That is a real limit of
	// the environment rather than of the gate, and the skip below now says so
	// by name instead of describing it as unanswerable in principle.
	if dsn := os.Getenv("INNSEGL_LEDGER_DSN"); dsn != "" {
		gh003ByContent(t, root, env, dsn)
		return
	}

	rangeSpec, err := pullRequestRange(os.Getenv("GITHUB_EVENT_NAME"), os.Getenv("GITHUB_BASE_REF"))
	if err != nil {
		t.Fatalf("GH-003 did not run: %v", err)
	}
	if rangeSpec == "" {
		t.Skipf("GH-003 ran in OBJECT mode, which can only ask about a pull request: " +
			"after a merge every commit object is new and the merge dropped the " +
			"signature that covered the old one (ADR-0047). This run is not a pull " +
			"request, so there is no such range.\n" +
			"      Set INNSEGL_LEDGER_DSN and it runs in CONTENT mode instead, which " +
			"asks whether a signed run recorded the CHANGE each commit makes — a " +
			"question a rebase does not destroy, and one `main` can answer. " +
			"scripts/test-no-skips.sh allows this skip and states the reason.")
	}
	// Counted before collecting, because collect treats an empty range as an
	// error -- reasonable when the range is all of history, wrong when it is a
	// pull request that has not added a commit yet.
	countOut, err := runGit(ctx, root, env, "rev-list", "--no-merges", "--count", rangeSpec)
	if err != nil {
		t.Fatalf("rev-list --count %s: %v", rangeSpec, err)
	}
	if strings.TrimSpace(countOut) == "0" {
		t.Logf("GH-003: %s adds no commits; nothing to check", rangeSpec)
		return
	}
	commits, err := collect(ctx, root, env, "--no-merges", rangeSpec)
	if err != nil {
		t.Fatalf("collect %s: %v", rangeSpec, err)
	}

	baseline := loadAttributionBaseline(t)
	claimed, checked := 0, 0
	for _, c := range commits {
		if !strings.Contains(c.Message, "Agent-Identity:") {
			continue
		}
		claimed++
		if reason, excused := baseline[c.SHA]; excused {
			t.Logf("  baseline  %s  %s", c.SHA[:12], reason)
			continue
		}
		checked++

		raw, err := runGit(ctx, root, env, "cat-file", "commit", c.SHA)
		if err != nil {
			t.Fatalf("cat-file commit %s: %v", c.SHA, err)
		}
		header, _, _ := strings.Cut(raw, "\n\n")
		switch {
		case !strings.Contains(header, "gpgsig"):
			t.Errorf("ATTRIBUTION VIOLATION: %s claims an agent identity and carries no "+
				"signature at all. The trailers are message text and survive a rewrite; "+
				"the signature does not.", c.SHA[:12])
		case !strings.Contains(header, "BEGIN SIGNED MESSAGE"):
			t.Errorf("ATTRIBUTION VIOLATION: %s claims an agent identity and is signed by "+
				"something that is not gitsign — its signature is not x509/PEM. A rewritten "+
				"commit keeps the claim and loses the evidence; use a merge commit, which "+
				"preserves the commit object the signature covers (ADR-0046).", c.SHA[:12])
		}
	}

	t.Logf("GH-003: %d of %d commits claim an agent identity, %d checked, %d on the baseline",
		claimed, len(commits), checked, claimed-checked)

	// A pull request with no agent-authored commits is normal -- a dependency
	// bump is exactly that -- so an empty count is not a fault.
	//
	// It WAS a fault while this gate scanned all of history: a repository whose
	// whole point is agent-signed commits, showing none, meant the scan was
	// looking in the wrong place. Narrowing to the pull request took that
	// meaning away, and keeping the check would have failed every dependency
	// bump for the crime of containing no agent work.
	if claimed == 0 {
		t.Logf("GH-003: no commit in %s claims an agent identity; nothing to check", rangeSpec)
	}
}

// pullRequestRange is the commit range GH-003 can honestly ask about, decided
// from the two variables GitHub Actions sets: GITHUB_EVENT_NAME and
// GITHUB_BASE_REF.
//
// An empty spec and no error means this run is not a pull request, and the
// caller skips: the merge button rewrote every commit on the way to main, so
// there is no range left whose signatures mean anything (ADR-0047).
//
// A pull-request event with no base ref returns an ERROR instead, because that
// combination is the one way this gate can go quiet where it matters. Nothing
// reaches main except through a pull request, so the pull-request run is the
// only place GH-003 ever runs; a skip there is the gate not running rather than
// the gate having nothing to ask, and ADR-0037 §2 already draws that line for
// GH-002's shallow clone and empty range. It is also what bounds the entry
// scripts/test-no-skips.sh carries for this test: the skip is allowed exactly
// where the question is unanswerable, and refused where it is not.
//
// The range is never returned alongside an error, for the reason ADR-0028 §7
// gives for the author guard: a caller that ignores the error still has nothing
// to scan.
func pullRequestRange(event, base string) (string, error) {
	if base = strings.TrimSpace(base); base != "" {
		return "origin/" + base + "..HEAD", nil
	}
	if strings.HasPrefix(strings.TrimSpace(event), "pull_request") {
		return "", fmt.Errorf("GITHUB_EVENT_NAME is %q and GITHUB_BASE_REF is empty, so "+
			"there is no pull-request range to check. Every commit reaches main through a "+
			"pull request, so this run is where GH-003 has to answer; skipping it would "+
			"retire the gate silently. Check out with fetch-depth: 0 and leave "+
			"GITHUB_BASE_REF to the event (see .github/workflows/author-gate.yml)", event)
	}
	return "", nil
}

// TestGH003TheRangeIsAPullRequestsOrTheGateSaysItDidNotRun pins the one
// decision that keeps GH-003's skip honest.
//
// GH-003 asks its question only where the answer still exists: inside a pull
// request, before the merge button rewrites each commit and drops the signature
// that covered it (ADR-0047). Everywhere else it skips, and
// scripts/test-no-skips.sh allows that skip by name.
//
// An allowlisted skip is the shape this project has been bitten by, so the
// allowance is bounded by an assertion rather than by a comment: on a
// pull-request event the range MUST resolve, and a missing GITHUB_BASE_REF
// there is a failure, not a skip. Every commit reaches main through a pull
// request, so that run is the only place GH-003 ever runs; a skip there would
// be the gate not running rather than the gate having nothing to ask. ADR-0037
// §2 draws the same line for GH-002's shallow clone and empty range.
func TestGH003TheRangeIsAPullRequestsOrTheGateSaysItDidNotRun(t *testing.T) {
	t.Parallel()
	for _, tc := range []struct {
		name    string
		event   string
		base    string
		want    string
		wantErr bool
	}{
		{"a pull request names its base", "pull_request", "main", "origin/main..HEAD", false},
		{"a pull request onto a release branch", "pull_request", "release/v0.2", "origin/release/v0.2..HEAD", false},
		{"whitespace around the base ref is not a base ref", "pull_request", "  main  ", "origin/main..HEAD", false},
		{"a pull request with no base ref is a gate that did not run", "pull_request", "", "", true},
		{"and so is pull_request_target", "pull_request_target", "", "", true},
		{"a push to main has no range, and skips", "push", "", "", false},
		{"neither does a developer's laptop", "", "", "", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()
			got, err := pullRequestRange(tc.event, tc.base)
			if tc.wantErr {
				if err == nil {
					t.Fatalf("event %q with base %q returned %q and no error; a "+
						"pull-request run with no base ref means GH-003 did not run, "+
						"which is a failure and not a skip", tc.event, tc.base, got)
				}
				if got != "" {
					t.Errorf("returned range %q alongside the error; a caller that "+
						"ignores the error must still have nothing to scan", got)
				}
				return
			}
			if err != nil {
				t.Fatalf("event %q with base %q: unexpected error %v", tc.event, tc.base, err)
			}
			if got != tc.want {
				t.Errorf("event %q with base %q gave %q, want %q", tc.event, tc.base, got, tc.want)
			}
		})
	}
}

// loadAttributionBaseline reads the commits GH-003 knowingly excuses.
//
// A gate with an undocumented exception is a gate nobody trusts, so the file is
// a map from full SHA to the REASON, and a commit with no reason is not on the
// baseline. Nothing is added to it to make a build green: an entry is a
// statement that a specific historical commit cannot be fixed, and why.
func loadAttributionBaseline(t *testing.T) map[string]string {
	t.Helper()
	raw, err := os.ReadFile(attributionBaselinePath)
	if errors.Is(err, os.ErrNotExist) {
		return map[string]string{}
	}
	if err != nil {
		t.Fatalf("reading %s: %v", attributionBaselinePath, err)
	}
	var file struct {
		Excused []struct {
			Commit string `json:"commit"`
			Date   string `json:"date"`
			Reason string `json:"reason"`
		} `json:"excused"`
	}
	if err := json.Unmarshal(raw, &file); err != nil {
		t.Fatalf("parsing %s: %v", attributionBaselinePath, err)
	}
	out := map[string]string{}
	for _, e := range file.Excused {
		if e.Reason == "" || e.Date == "" {
			t.Fatalf("%s: %s has no date or no reason. An exception without either is "+
				"an exception nobody can review", attributionBaselinePath, e.Commit)
		}
		out[e.Commit] = e.Date + ": " + e.Reason
	}
	return out
}

const attributionBaselinePath = "testdata/attribution-baseline.json"

// gh003ByContent is GH-003 asked the way ADR-0047 makes it answerable
// anywhere: not "is the signature on this object" but "did a signed run record
// the change this commit makes" (#195, RM-123).
//
// # Why this can check `main` where the object check cannot
//
// A gitsign signature covers the commit object, and every merge strategy
// GitHub offers rewrites it. The object check therefore has exactly one moment
// where it is answerable — inside the pull request, before the button — and
// after that the evidence is gone. The change is not: `git patch-id --verbatim`
// names it, it survives a rebase, and the ledger records it against the run
// that made it (#192, #193).
//
// # Both halves, for the third time and the same reason
//
// The patch id says WHAT and cannot say who; the trailer says WHO and is text
// anybody can type. A commit passes only when a record carries this change AND
// names the run this commit claims. gh003MutantContentCheck below removes one
// half at a time and asserts a forgery gets through, which is the mutation the
// issue asks for.
func gh003ByContent(t *testing.T, root string, env []string, dsn string) {
	t.Helper()
	ctx := t.Context()

	pool, err := pgxpool.New(ctx, dsn)
	if err != nil {
		t.Fatalf("GH-003 content mode: opening the ledger: %v", err)
	}
	defer pool.Close()

	// BEFORE ANYTHING ELSE: has this deployment ever recorded a change?
	//
	// `patch_id` arrives with schema 2. A chain written by an older server
	// holds none, and every commit it signed is outside the content scheme —
	// not because the content changed, but because nothing recorded what the
	// content was. Measured on 2026-09-10 against this project's own
	// deployment: 126 `commit_recorded` events, zero patch ids. Without this
	// question, content mode would accuse all 126 genuine signatures.
	anyPatchID, err := ledger.HoldsAnyPatchID(ctx, pool)
	if err != nil {
		t.Fatalf("GH-003 content mode: asking the ledger about patch ids: %v", err)
	}
	if !anyPatchID {
		t.Skipf("GH-003 CONTENT mode: this ledger holds no patch_id on any commit " +
			"event, so it was written by a deployment older than schema 2 and there " +
			"is nothing to check a change against (ADR-0047).\n" +
			"      Upgrade the deployment and run `innsegl migrate-schema`; commits " +
			"signed after the cutover are checkable, and commits signed before it stay " +
			"exactly as valid as they were — I4 does not let them change.")
	}

	commits, err := collect(ctx, root, env, "--no-merges", "HEAD")
	if err != nil {
		t.Fatalf("collect HEAD: %v", err)
	}

	baseline := loadAttributionBaseline(t)
	claimed, checked, confirmed := 0, 0, 0
	for _, c := range commits {
		if !strings.Contains(c.Message, "Agent-Identity:") {
			continue
		}
		claimed++
		if reason, excused := baseline[c.SHA]; excused {
			t.Logf("  baseline  %s  %s", c.SHA[:12], reason)
			continue
		}
		checked++

		run := gh003RunOf(c.Message)
		if run == "" {
			t.Errorf("ATTRIBUTION VIOLATION: %s claims an agent identity and carries no "+
				"Agent-Run trailer, so there is no run to check the change against. "+
				"ADR-0028 §5 requires all three trailers together.", c.SHA[:12])
			continue
		}
		patchID, perr := gh003PatchID(ctx, root, env, c.SHA)
		if perr != nil {
			t.Fatalf("computing the change made by %s: %v", c.SHA[:12], perr)
		}
		if patchID == "" {
			t.Logf("  empty     %s  changes nothing, so it is outside the scheme", c.SHA[:12])
			continue
		}

		records, rerr := ledger.RunsForPatchID(ctx, pool, patchID)
		if rerr != nil {
			// A ledger that cannot answer is not a commit that failed. Fatal
			// rather than an error on this commit: every commit after it would
			// report the same thing, and a hundred identical failures hide the
			// one fact that matters.
			t.Fatalf("GH-003 content mode: the ledger could not be asked about %s: %v",
				c.SHA[:12], rerr)
		}
		if gh003Confirms(records, run, patchID) {
			confirmed++
			continue
		}
		t.Errorf("ATTRIBUTION VIOLATION: %s claims run %s, and no record in the ledger "+
			"carries that run against this change (patch id %s).\n"+
			"      Either the content changed after it was signed, or the claim is not "+
			"this run's to make. ADR-0047: a conflicted rebase reads as the content "+
			"changing; an edit reads the same way, and both are the commit's problem "+
			"rather than the gate's.", c.SHA[:12], run, patchID[:12])
	}

	t.Logf("GH-003 CONTENT mode: %d of %d commits claim an agent identity, %d checked, "+
		"%d confirmed by content, %d on the baseline",
		claimed, len(commits), checked, confirmed, claimed-checked)
	if claimed == 0 {
		t.Log("GH-003: no commit reachable from HEAD claims an agent identity")
	}
}

// gh003Confirms is the rule, alone in a function so a mutation test can remove
// half of it.
func gh003Confirms(records []ledger.ContentRecord, run, patchID string) bool {
	for _, r := range records {
		if r.RunID == run && r.PatchID == patchID {
			return true
		}
	}
	return false
}

// gh003RunOf reads the Agent-Run trailer.
func gh003RunOf(message string) string {
	for _, line := range strings.Split(message, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimSpace(line), "Agent-Run:"); ok {
			return strings.TrimSpace(rest)
		}
	}
	return ""
}

// gh003PatchID computes a commit's change identity with the same two commands
// and the same flags sign_commit and the reconciler use. An empty string means
// the commit changes nothing.
func gh003PatchID(ctx context.Context, root string, env []string, sha string) (string, error) {
	patch, err := runGit(ctx, root, env,
		"diff-tree", "-p", "--root", "--no-color", "--no-ext-diff", sha)
	if err != nil {
		return "", err
	}
	if strings.TrimSpace(patch) == "" {
		return "", nil
	}
	out, err := runGitStdin(ctx, root, env, patch, "patch-id", "--verbatim")
	if err != nil {
		return "", err
	}
	fields := strings.Fields(out)
	if len(fields) == 0 {
		return "", nil
	}
	return fields[0], nil
}

// TestGH003BothHalvesOfTheContentCheckAreLoadBearing is the mutation the issue
// asks for, run as a test rather than by hand: "removing the content check
// admits an unattributable commit".
//
// gh003Confirms is the whole rule, in one function, so each half can be removed
// in isolation and the forgery it was holding back can be named. A gate whose
// mutation coverage is a note in a pull request is a gate nobody re-checks.
func TestGH003BothHalvesOfTheContentCheckAreLoadBearing(t *testing.T) {
	const (
		theRun   = "run-42"
		thePatch = "5e4c6c1f0a2d9b3e8f7a1c4d6b0e9f2a3c5d7e81"
		other    = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	)
	records := []ledger.ContentRecord{{RunID: theRun, PatchID: thePatch}}

	if !gh003Confirms(records, theRun, thePatch) {
		t.Fatal("the genuine case is refused, so nothing below means anything")
	}

	// MUTANT 1: match on the change alone. An impostor attaches their own
	// Agent-Run to somebody else's change and the gate confirms it.
	matchesChangeOnly := func(records []ledger.ContentRecord, _, patchID string) bool {
		for _, r := range records {
			if r.PatchID == patchID {
				return true
			}
		}
		return false
	}
	if !matchesChangeOnly(records, "run-impostor", thePatch) {
		t.Error("the change-only mutant did not admit the forgery it exists to " +
			"demonstrate; the mutation proves nothing")
	}
	if gh003Confirms(records, "run-impostor", thePatch) {
		t.Error("GH-003 confirmed a commit claiming a run that recorded no such change")
	}

	// MUTANT 2: match on the run alone. Any commit carrying a genuine
	// Agent-Run passes, whatever it actually changed — which is the edited
	// commit keeping the attribution of the one it was edited from.
	matchesRunOnly := func(records []ledger.ContentRecord, run, _ string) bool {
		for _, r := range records {
			if r.RunID == run {
				return true
			}
		}
		return false
	}
	if !matchesRunOnly(records, theRun, other) {
		t.Error("the run-only mutant did not admit the forgery it exists to demonstrate")
	}
	if gh003Confirms(records, theRun, other) {
		t.Error("GH-003 confirmed a commit whose change no run recorded")
	}
}
