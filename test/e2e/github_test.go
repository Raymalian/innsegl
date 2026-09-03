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

	// GrandfatheredNote and GrandfatheredCommits admit, one hash at a time,
	// the commits that predate this policy and were authored with an address
	// that is not listed above and must not be.
	//
	// Listing the address instead would put it in this file, in every refusal
	// message, and in the author census below — on a public repository, on
	// every CI run, forever. Naming the commits keeps the gate honest about
	// them without republishing what it is trying not to republish.
	//
	// The list is CLOSED, and TestGH002ThisRepositorysCommitHistorySatisfiesI6
	// enforces that: an entry matching no commit in the history is a failure,
	// so the list cannot quietly grow into a general exemption.
	GrandfatheredNote    string   `json:"grandfathered_note"`
	GrandfatheredCommits []string `json:"grandfathered_commits"`

	AllowUnlinked bool `json:"allow_unlinked"`
}

func loadAuthorPolicyFile(t *testing.T) authorPolicyFile {
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
	return f
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
	return signing.AuthorPolicy{Operators: f.Operators, AllowUnlinked: f.AllowUnlinked}
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
	file := loadAuthorPolicyFile(t)
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

	// A grandfathered commit is admitted by hash, so the address that authored
	// it never appears. The entries are checked against the history first: one
	// that matches nothing is a stale exemption, and a list of those is how a
	// closed exception becomes an open one.
	grandfathered := map[string]bool{}
	for _, sha := range file.GrandfatheredCommits {
		grandfathered[sha] = true
	}
	present := map[string]bool{}
	for _, c := range commits {
		if grandfathered[c.SHA] {
			present[c.SHA] = true
		}
	}
	for _, sha := range file.GrandfatheredCommits {
		if !present[sha] {
			t.Errorf("%s grandfathers %s, which is not a non-merge commit reachable from "+
				"HEAD. An entry that matches nothing exempts nothing and hides that it is "+
				"doing so; remove it.", authorPolicyPath, sha)
		}
	}
	if n := len(file.GrandfatheredCommits); n > 0 {
		t.Logf("%d commit(s) admitted by hash: they predate the policy and their author is "+
			"deliberately not listed in it", n)
	}

	for _, f := range scanCommits(policy, commits) {
		if grandfathered[f.SHA] {
			continue
		}
		t.Errorf("I6 VIOLATION: %s\n"+
			"      If this address is a human operator of this deployment, add it to %s.\n"+
			"      It is never correct to add an agent address there (ADR-0028 §6).",
			f, authorPolicyPath)
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
