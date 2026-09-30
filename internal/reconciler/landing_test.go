// SPDX-License-Identifier: Apache-2.0

package reconciler_test

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/reconciler"
)

// RM-243 (#388), test CMT-015 and its own unit-level proofs.
//
// ADR-0059 decision 6 is binding: "signed is recorded; landed is observed;
// the two are never conflated." So this file proves two things about a
// commit that lost git's own ref race — signed, and never landed:
//
//  1. It NEVER produces `ledger_drift_detected` or any other alert
//     (TestALostRefRaceNeverProducesDriftOrAnyOtherAlert) — a lost race is
//     git's own concurrency control, not a discrepancy between the chain and
//     the transparency log, and the drift cross-check (drift.go) has no
//     reachability check to trip in the first place.
//  2. The reconciler's own report — never the chain — names it
//     "signed_not_landed" (the rest of this file), counted and listed, with
//     NOTHING appended to the ledger for it, ever.
//
// The real git race — N byte-identical `git commit`s, one landing — is
// landing_integration_test.go's TestCMT015NConcurrentIdenticalCommitsOneLands,
// against real Postgres, real git and a real Rekor. This file is the decision
// logic: reachable, unreachable, unreadable, and corroborated by a run's own
// tool-call result — exercised over states a real stack cannot be driven into
// on demand, the same division drift_test.go and driftintegration_test.go
// already draw.

// ---------------------------------------------------------------------------
// A Repos fake that also answers CommitReachable — landing.go's own
// interface, which *GitWorkspace satisfies for real (see
// TestCommitReachableAgainstARealRepository below).
// ---------------------------------------------------------------------------

type landingRepos struct {
	fakeRepos
	// reachable and errs are keyed on repo+"\x00"+sha.
	reachable map[string]bool
	errs      map[string]error
	calls     int
}

func newLandingRepos() *landingRepos {
	return &landingRepos{
		fakeRepos: fakeRepos{commits: map[string]map[string][]string{}},
		reachable: map[string]bool{},
		errs:      map[string]error{},
	}
}

func landingReposKey(repo, sha string) string { return repo + "\x00" + sha }

func (f *landingRepos) setReachable(repo, sha string, ok bool) {
	f.reachable[landingReposKey(repo, sha)] = ok
}

func (f *landingRepos) setErr(repo, sha string, err error) {
	f.errs[landingReposKey(repo, sha)] = err
}

func (f *landingRepos) CommitReachable(_ context.Context, repo, sha string) (bool, error) {
	f.calls++
	key := landingReposKey(repo, sha)
	if err, has := f.errs[key]; has {
		return false, err
	}
	return f.reachable[key], nil
}

var _ interface {
	CommitReachable(context.Context, string, string) (bool, error)
} = (*landingRepos)(nil)

// ---------------------------------------------------------------------------
// Seeding a commit_recorded directly — the state this pass reads, whichever
// call site wrote it (sign_commit, the commit-sign path, or a repair).
// ---------------------------------------------------------------------------

const (
	landingRunID      = "run-landing"
	landingRepo       = "github.com/innsegl/landing-demo"
	landingTree       = "5dda8fd290f4d08d527bbe82c310a27fc0cddadb"
	landingCommit     = "709483c5a911bd74809f728c23d67da0bebbf72a"
	landingPatchID    = "ffffffffffffffffffffffffffffffffffffffff"
	landingRekorUUID1 = "aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111aaaa1111"
)

// seedCommitRecorded appends a run_registered, a commit_intent and its
// commit_recorded — a fully resolved intent, exactly the state landing.go
// reads and REC-001/002 have nothing left to do about.
func seedCommitRecorded(t *testing.T, m *memLedger, runID, repo, tree, commitSHA, rekorUUID string) event.Fields {
	t.Helper()
	seedRun(t, m, runID)
	intent := seedIntent(t, m, runID, tree)
	record, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "sign_commit/recorded/" + runID,
		event.FieldRepo:           repo,
		event.FieldTreeHash:       tree,
		event.FieldPatchID:        landingPatchID,
		event.FieldCommitSHA:      commitSHA,
		event.FieldRekorEntryUUID: rekorUUID,
		event.FieldRekorLogIndex:  int64(1),
		event.FieldIntentEventID:  str(intent, event.FieldEventID),
	})
	if err != nil {
		t.Fatalf("seed commit_recorded: %v", err)
	}
	return record
}

// seedToolCall appends a tool_call event and writes its retained body under
// dir, in the layout readRunBody (writes.go) expects, returning the digest.
func seedToolCall(t *testing.T, m *memLedger, dir, runID string, body []byte) event.Fields {
	t.Helper()
	sum := sha256.Sum256(body)
	digest := "sha256:" + hex.EncodeToString(sum[:])

	runDir := filepath.Join(dir, runID)
	if err := os.MkdirAll(runDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(runDir, hex.EncodeToString(sum[:])+".json"), body, 0o600); err != nil {
		t.Fatal(err)
	}

	record, err := m.Append(context.Background(), event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeToolCall,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       spiffeIDFor(runID),
		event.FieldIdempotencyKey: "toolcall/" + runID + "/1",
		event.FieldToolName:       "Bash",
		event.FieldPayloadDigest:  digest,
	})
	if err != nil {
		t.Fatalf("seed tool_call: %v", err)
	}
	return record
}

// gitCommitToolCallBody is the shape internal/gateway/record.go's
// gatewayToolCallBody assembles — reproduced narrowly here, matching
// landing.go's own landingToolCallBody, rather than importing a package
// this one must not depend on.
type gitCommitToolCallBody struct {
	Tool    string `json:"tool"`
	Input   any    `json:"input"`
	Result  any    `json:"result"`
	IsError bool   `json:"is_error"`
}

func mustJSON(t *testing.T, v any) []byte {
	t.Helper()
	out, err := json.Marshal(v)
	if err != nil {
		t.Fatalf("json.Marshal: %v", err)
	}
	return out
}

// ---------------------------------------------------------------------------
// A reconciler builder, landing-specific: drift and landing both on, over a
// fresh chain and a landingRepos this test controls directly.
// ---------------------------------------------------------------------------

type landingFixture struct {
	clock  *clock
	ledger *memLedger
	repos  *landingRepos
	sweep  *fakeSweep
	alerts []reconciler.DriftFinding
}

func newLandingFixture(t *testing.T) *landingFixture {
	t.Helper()
	c := &clock{at: time.Date(2026, 9, 30, 9, 0, 0, 0, time.UTC)}
	return &landingFixture{
		clock:  c,
		ledger: newMemLedger(c.now),
		repos:  newLandingRepos(),
		sweep:  &fakeSweep{},
	}
}

// build assembles a reconciler over the fixture. cfg is applied to the
// reconciler.Config before New is called, so a test sets exactly the
// Landing (and, where it wants task 1's proof, Drift) it needs.
func (f *landingFixture) build(t *testing.T, edit func(*reconciler.Config)) *reconciler.Reconciler {
	t.Helper()
	cfg := reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       f.repos,
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		ExpireAfter: 24 * time.Hour,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
	}
	if edit != nil {
		edit(&cfg)
	}
	r, err := reconciler.New(cfg)
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	return r
}

// ---------------------------------------------------------------------------
// Task 1: a lost ref race never produces drift or any other alert.
// ---------------------------------------------------------------------------

// TestALostRefRaceNeverProducesDriftOrAnyOtherAlert measures what today's
// drift cross-check (drift.go, REC-004) does with a commit_recorded whose
// SHA is unreachable in its repository — exactly the state a lost git ref
// race leaves, and exactly commit_recorded's own claim: it states that this
// content was signed, under this run's identity, with this Rekor entry
// (ADR-0059 decision 6). Reachability from a branch is not one of the four
// things checkRecords (drift.go) asks the log to confirm, so this passes
// against TODAY'S code with no change to drift.go — proving the claim in
// task 1 rather than assuming it. Deleting drift.go's reachability
// indifference is not possible without inventing a check the chain has no
// field for; what IS possible, and what would make this fail, is landing.go
// itself accidentally wiring reachability into the drift path instead of its
// own separate, non-appending report.
func TestALostRefRaceNeverProducesDriftOrAnyOtherAlert(t *testing.T) {
	f := newLandingFixture(t)

	// A commit_recorded whose Rekor entry is real and agrees on every one of
	// the four things checkRecords verifies (artifact hash, certificate
	// identity, log index) — the ONLY thing distinguishing it from an
	// ordinary, fully-landed signature is that the repository says its SHA is
	// not reachable from any ref.
	rec := seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	f.sweep.entries = []reconciler.SweptEntry{{
		UUID:                landingRekorUUID1,
		LogIndex:            1,
		ArtifactHash:        artifactOf(landingCommit),
		CertificateIdentity: spiffeIDFor(landingRunID),
	}}
	f.repos.setReachable(landingRepo, landingCommit, false)

	r := f.build(t, func(cfg *reconciler.Config) {
		cfg.Drift = &reconciler.DriftConfig{
			Sweep: f.sweep,
			Alert: func(_ context.Context, d reconciler.DriftFinding) { f.alerts = append(f.alerts, d) },
		}
		cfg.Landing = &reconciler.LandingConfig{}
	})

	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if !result.Drift.Enabled {
		t.Fatal("drift detection reported itself disabled")
	}
	if result.Drift.Fabricated != 0 || result.Drift.Unattributed != 0 || result.Drift.Unresolved != 0 {
		t.Fatalf("a lost-race commit_recorded raised drift: %+v", result.Drift)
	}
	if len(f.alerts) != 0 {
		t.Fatalf("the operator sink saw %d drift alerts for a lost-race commit: %+v", len(f.alerts), f.alerts)
	}
	if got := str(rec, event.FieldEventType); got != event.EventTypeCommitRecorded {
		t.Fatalf("sanity: seeded record is a %s, want commit_recorded", got)
	}

	// The SAME cycle's own landing pass sees exactly this as signed, not
	// landed — the two reports diverge on purpose (drift: silent; landing:
	// one finding), and that divergence is the whole point of this file.
	if result.Landing.NotLanded != 1 {
		t.Fatalf("Landing.NotLanded = %d, want 1: %+v", result.Landing.NotLanded, result.Landing)
	}
}

// ---------------------------------------------------------------------------
// The derived report itself.
// ---------------------------------------------------------------------------

func TestLandingReportsDisabledWithNoConfig(t *testing.T) {
	f := newLandingFixture(t)
	seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	f.repos.setReachable(landingRepo, landingCommit, true)

	r := f.build(t, nil) // no Landing config at all
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.Enabled {
		t.Fatal("Landing.Enabled is true with no Config.Landing")
	}
	if result.Landing.Checked != 0 || len(result.Landing.Findings) != 0 {
		t.Fatalf("a disabled pass reported something: %+v", result.Landing)
	}
}

func TestLandingReportsLandedAndAppendsNoFindingForIt(t *testing.T) {
	f := newLandingFixture(t)
	seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	f.repos.setReachable(landingRepo, landingCommit, true)

	r := f.build(t, func(cfg *reconciler.Config) { cfg.Landing = &reconciler.LandingConfig{} })
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.Checked != 1 || result.Landing.Landed != 1 || result.Landing.NotLanded != 0 {
		t.Fatalf("Landing = %+v, want 1 checked, 1 landed, 0 not landed", result.Landing)
	}
	if len(result.Landing.Findings) != 0 {
		t.Fatalf("a landed commit produced %d findings, want 0 (the quiet case): %+v",
			len(result.Landing.Findings), result.Landing.Findings)
	}
}

func TestLandingReportsSignedNotLandedWhenTheRepositorySaysUnreachable(t *testing.T) {
	f := newLandingFixture(t)
	rec := seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	f.repos.setReachable(landingRepo, landingCommit, false)

	countBefore, err := f.ledger.Count(t.Context())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}

	r := f.build(t, func(cfg *reconciler.Config) { cfg.Landing = &reconciler.LandingConfig{} })
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}

	if result.Landing.Checked != 1 || result.Landing.NotLanded != 1 || result.Landing.Landed != 0 {
		t.Fatalf("Landing = %+v, want 1 checked, 1 not landed, 0 landed", result.Landing)
	}
	if len(result.Landing.Findings) != 1 {
		t.Fatalf("got %d findings, want 1: %+v", len(result.Landing.Findings), result.Landing.Findings)
	}
	got := result.Landing.Findings[0]
	if got.Outcome != reconciler.LandingNotLanded {
		t.Fatalf("Outcome = %q, want %q", got.Outcome, reconciler.LandingNotLanded)
	}
	if got.SubjectEventID != str(rec, event.FieldEventID) {
		t.Fatalf("SubjectEventID = %q, want the commit_recorded's own %q",
			got.SubjectEventID, str(rec, event.FieldEventID))
	}
	if got.RunID != landingRunID || got.Repo != landingRepo || got.CommitSHA != landingCommit {
		t.Fatalf("finding names the wrong subject: %+v", got)
	}
	if got.Detail == "" {
		t.Fatal("a not-landed finding carries no Detail an operator could read")
	}

	// I3 read backwards, and ADR-0059 decision 6 in as many words: NOTHING is
	// appended to the chain for a derived finding.
	countAfter, err := f.ledger.Count(t.Context())
	if err != nil {
		t.Fatalf("Count: %v", err)
	}
	if countAfter != countBefore {
		t.Fatalf("the chain grew from %d to %d events; landing must append nothing",
			countBefore, countAfter)
	}
	if len(result.Appended) != 0 {
		t.Fatalf("Result.Appended = %v, want empty: landing writes nothing", result.Appended)
	}
}

// TestLandingIsReDerivedEveryCycleNotRecorded proves the other half of
// "derived, never recorded": unlike a repair or an expiry, a landing finding
// does not disappear after the cycle that first reports it, because nothing
// was written that a second cycle could read back as "already handled". A
// fresh reconciler over the SAME chain reports the SAME finding — the answer
// changes only when the underlying evidence does.
func TestLandingIsReDerivedEveryCycleNotRecorded(t *testing.T) {
	f := newLandingFixture(t)
	seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	f.repos.setReachable(landingRepo, landingCommit, false)

	build := func() *reconciler.Reconciler {
		return f.build(t, func(cfg *reconciler.Config) { cfg.Landing = &reconciler.LandingConfig{} })
	}

	first, err := build().Reconcile(t.Context())
	if err != nil {
		t.Fatalf("first Reconcile: %v", err)
	}
	second, err := build().Reconcile(t.Context())
	if err != nil {
		t.Fatalf("second Reconcile: %v", err)
	}
	if first.Landing.NotLanded != 1 || second.Landing.NotLanded != 1 {
		t.Fatalf("NotLanded = %d then %d, want 1 then 1 -- a derived finding must not vanish "+
			"after one cycle", first.Landing.NotLanded, second.Landing.NotLanded)
	}

	// Now the evidence changes -- the commit lands, e.g. a retry succeeded on
	// a later branch state this test does not otherwise model -- and the very
	// next cycle agrees with the new evidence rather than the old finding.
	f.repos.setReachable(landingRepo, landingCommit, true)
	third, err := build().Reconcile(t.Context())
	if err != nil {
		t.Fatalf("third Reconcile: %v", err)
	}
	if third.Landing.NotLanded != 0 || third.Landing.Landed != 1 {
		t.Fatalf("after the repository reports it reachable, Landing = %+v, want 0 not-landed, "+
			"1 landed", third.Landing)
	}
}

func TestLandingReportsNotCheckedWhenTheRepositoryCannotBeRead(t *testing.T) {
	f := newLandingFixture(t)
	rec := seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	f.repos.setErr(landingRepo, landingCommit, os.ErrNotExist)

	r := f.build(t, func(cfg *reconciler.Config) { cfg.Landing = &reconciler.LandingConfig{} })
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.NotChecked != 1 || result.Landing.NotLanded != 0 || result.Landing.Landed != 0 {
		t.Fatalf("Landing = %+v, want 1 not checked and nothing else", result.Landing)
	}
	if len(result.Landing.Findings) != 1 || result.Landing.Findings[0].Outcome != reconciler.LandingNotChecked {
		t.Fatalf("Findings = %+v, want one LandingNotChecked", result.Landing.Findings)
	}
	if result.Landing.Findings[0].SubjectEventID != str(rec, event.FieldEventID) {
		t.Fatalf("the not-checked finding names the wrong subject: %+v", result.Landing.Findings[0])
	}
}

func TestLandingReportsNotCheckedWhenTheReposDoesNotSupportReachability(t *testing.T) {
	f := newLandingFixture(t)
	seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)

	cfg := reconciler.Config{
		Ledger:      f.ledger,
		Appender:    f.ledger,
		Repos:       &fakeRepos{commits: map[string]map[string][]string{}}, // no CommitReachable
		Log:         &fakeLog{entries: map[string]reconciler.LogEntry{}},
		TrustDomain: testTrustDomain,
		ExpireAfter: 24 * time.Hour,
		Now:         f.clock.now,
		Alert:       func(context.Context, reconciler.Finding) {},
		Observe:     func(reconciler.Result, error) {},
		Landing:     &reconciler.LandingConfig{},
	}
	r, err := reconciler.New(cfg)
	if err != nil {
		t.Fatalf("reconciler.New: %v", err)
	}
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.NotChecked != 1 {
		t.Fatalf("Landing = %+v, want 1 not checked", result.Landing)
	}
}

// ---------------------------------------------------------------------------
// The corroborating signal: a run's own git commit tool call.
// ---------------------------------------------------------------------------

func TestLandingCorroboratesFromARefLockFailureInTheToolCallResult(t *testing.T) {
	f := newLandingFixture(t)
	bodyDir := t.TempDir()
	rec := seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	seedToolCall(t, f.ledger, bodyDir, landingRunID, mustJSON(t, gitCommitToolCallBody{
		Tool:    "Bash",
		Input:   map[string]string{"command": "git commit -m x"},
		Result:  "error: cannot lock ref 'refs/heads/main': is at 1111111111111111111111111111111111111111 but expected 2222222222222222222222222222222222222222",
		IsError: true,
	}))
	// The repository cannot be read at all -- the case this corroboration
	// exists for: a deployment where this reconciler has no checkout of the
	// repository, so the only evidence is the run's own tool-call result.
	f.repos.setErr(landingRepo, landingCommit, os.ErrNotExist)

	r := f.build(t, func(cfg *reconciler.Config) {
		cfg.Landing = &reconciler.LandingConfig{LogDir: bodyDir}
	})
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.NotLanded != 1 || result.Landing.NotChecked != 0 {
		t.Fatalf("Landing = %+v, want 1 not landed (corroborated), 0 not checked", result.Landing)
	}
	got := result.Landing.Findings[0]
	if got.SubjectEventID != str(rec, event.FieldEventID) {
		t.Fatalf("the corroborated finding names the wrong subject: %+v", got)
	}
	if got.Detail == "" {
		t.Fatal("a corroborated finding carries no Detail")
	}
}

// TestLandingCorroborationReadsAContentBlockResult covers the OTHER shape a
// retained tool-call result carries — an Anthropic content-block array
// rather than a bare string — proving resultText (landing.go) is not only
// exercised by the bare-string case above.
func TestLandingCorroborationReadsAContentBlockResult(t *testing.T) {
	f := newLandingFixture(t)
	bodyDir := t.TempDir()
	seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	seedToolCall(t, f.ledger, bodyDir, landingRunID, mustJSON(t, gitCommitToolCallBody{
		Tool:  "Bash",
		Input: map[string]string{"command": "git commit -m x"},
		Result: []map[string]string{
			{"type": "text", "text": "error: failed to lock ref 'refs/heads/main' for update"},
		},
		IsError: true,
	}))
	f.repos.setErr(landingRepo, landingCommit, os.ErrNotExist)

	r := f.build(t, func(cfg *reconciler.Config) {
		cfg.Landing = &reconciler.LandingConfig{LogDir: bodyDir}
	})
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.NotLanded != 1 {
		t.Fatalf("Landing = %+v, want 1 not landed", result.Landing)
	}
}

// TestLandingIgnoresAToolCallResultThatIsNotARefLockFailure proves the
// corroboration is not a rubber stamp: an ordinary Bash failure with no
// ref-lock text in it must never manufacture a not-landed finding when the
// repository itself could not be read -- that would be a guess, which this
// pass refuses to make (see landing.go's own header).
func TestLandingIgnoresAToolCallResultThatIsNotARefLockFailure(t *testing.T) {
	f := newLandingFixture(t)
	bodyDir := t.TempDir()
	rec := seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	seedToolCall(t, f.ledger, bodyDir, landingRunID, mustJSON(t, gitCommitToolCallBody{
		Tool:    "Bash",
		Input:   map[string]string{"command": "git commit -m x"},
		Result:  "error: pathspec 'x' did not match any files",
		IsError: true,
	}))
	f.repos.setErr(landingRepo, landingCommit, os.ErrNotExist)

	r := f.build(t, func(cfg *reconciler.Config) {
		cfg.Landing = &reconciler.LandingConfig{LogDir: bodyDir}
	})
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.NotChecked != 1 || result.Landing.NotLanded != 0 {
		t.Fatalf("Landing = %+v, want 1 not checked (no guess) and 0 not landed", result.Landing)
	}
	if result.Landing.Findings[0].SubjectEventID != str(rec, event.FieldEventID) {
		t.Fatalf("wrong subject: %+v", result.Landing.Findings[0])
	}
}

// TestLandingIgnoresAnUnrelatedToolCall proves the corroboration only ever
// reads a run's OWN git commit call: a successful, unrelated Bash call in the
// same run's own body directory must never be mistaken for corroboration.
func TestLandingIgnoresAnUnrelatedToolCall(t *testing.T) {
	f := newLandingFixture(t)
	bodyDir := t.TempDir()
	seedCommitRecorded(t, f.ledger, landingRunID, landingRepo, landingTree, landingCommit, landingRekorUUID1)
	seedToolCall(t, f.ledger, bodyDir, landingRunID, mustJSON(t, gitCommitToolCallBody{
		Tool:    "Bash",
		Input:   map[string]string{"command": "ls -la"},
		Result:  "total 0",
		IsError: false,
	}))
	f.repos.setReachable(landingRepo, landingCommit, true)

	r := f.build(t, func(cfg *reconciler.Config) {
		cfg.Landing = &reconciler.LandingConfig{LogDir: bodyDir}
	})
	result, err := r.Reconcile(t.Context())
	if err != nil {
		t.Fatalf("Reconcile: %v", err)
	}
	if result.Landing.Landed != 1 || result.Landing.NotLanded != 0 {
		t.Fatalf("Landing = %+v, want 1 landed and 0 not landed", result.Landing)
	}
}

// ---------------------------------------------------------------------------
// CommitReachable against a real repository — no Docker, no network: what is
// under test is which ref (if any) reaches a commit object, and git answers
// that itself, on the same repos_test.go fixtures the rest of this package
// uses for exactly this reason.
// ---------------------------------------------------------------------------

func TestCommitReachableAgainstARealRepository(t *testing.T) {
	const repo = "github.com/innsegl/landing-reachability"
	root, worktree := newRepo(t, repo)

	landed, _ := commitInto(t, worktree, "a.txt", "one\n", "landed")
	dangling, _ := commitInto(t, worktree, "b.txt", "two\n", "will be orphaned by the reset below")
	// Exactly the state a lost ref race leaves: the object exists (git wrote
	// it), and after this reset no ref reaches it any more.
	git(t, worktree, "reset", "--hard", landed)

	ws, err := reconciler.NewGitWorkspace(root)
	if err != nil {
		t.Fatalf("NewGitWorkspace: %v", err)
	}
	ctx := t.Context()

	if ok, err := ws.CommitReachable(ctx, repo, landed); err != nil || !ok {
		t.Fatalf("CommitReachable(landed) = (%v, %v), want (true, nil)", ok, err)
	}
	if ok, err := ws.CommitReachable(ctx, repo, dangling); err != nil || ok {
		t.Fatalf("CommitReachable(dangling) = (%v, %v), want (false, nil): the object exists "+
			"but no ref reaches it, exactly a lost ref race", ok, err)
	}
	const neverExisted = "abbaabbaabbaabbaabbaabbaabbaabbaabbaabba"
	if ok, err := ws.CommitReachable(ctx, repo, neverExisted); err != nil || ok {
		t.Fatalf("CommitReachable(never-existed) = (%v, %v), want (false, nil)", ok, err)
	}
	if _, err := ws.CommitReachable(ctx, "github.com/innsegl/no-such-repo", landed); err == nil {
		t.Fatal("CommitReachable against a repository this workspace does not hold returned no error")
	}
	if _, err := ws.CommitReachable(ctx, repo, "not-a-git-object-id"); err == nil {
		t.Fatal("CommitReachable accepted a malformed commit sha")
	}
}
