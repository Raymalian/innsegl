// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"encoding/json"
	"fmt"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
)

// Landing: RM-243 (#388), test CMT-015. ADR-0059 decision 6 is binding here
// and this file does exactly what it says and nothing more:
//
//	"Signed is recorded; landed is observed; the two are never conflated
//	 ... whether a signed commit landed is derived, never assumed ... Both are
//	 read-only checks against evidence that already exists; neither writes a
//	 new ledger event, and a caller that wants to know 'did this land' asks
//	 the question rather than reading it off commit_recorded's presence."
//
// So this pass APPENDS NOTHING, ever. There is no new ledger event, no
// schema change, no new field or enum value (doc 02 is untouched). A commit
// that lost git's own ref race is not drift and not a fault: it is git's
// single-writer serialization on a repository this system does not
// serialize and must not try to (ADR-0059 decision 6, measurement 4). What
// this pass adds is purely a DERIVED line in the reconciler's own report —
// "signed, not landed" — counted and listed for an operator, the same way
// writes.go's corroboration is a number and never an accusation.
//
// # The two signals, and which one is load-bearing
//
// The load-bearing signal is the repository itself: a commit_recorded names
// a commit_sha, and CommitReachable asks the repository whether that object
// is reachable from any ref. That is read-only evidence that already
// exists — the exact evidence ADR-0059 decision 6 names — and it needs
// nothing beyond the Repos this package already requires for REC-001/002.
//
// The second signal — a run's own `git commit` tool-call result carrying
// git's own ref-lock failure text ("cannot lock ref", "is at X but expected
// Y") — is corroborating, read from the same retained tool-call bodies
// writes.go already reads (LandingConfig.LogDir, optional exactly as
// WritesConfig.LogDir is). It is consulted when the repository could not be
// read at all, so a deployment with no retained bodies still gets the
// primary signal, and a deployment with no readable repository for this
// commit still gets a corroborated finding instead of a guess.
//
// # What "not checked" means, and why it is never a guess
//
// A repository this pass cannot read is not evidence of anything about the
// commit — the same rule Reconcile already holds for an intent's own
// repository read (resolve, reconcile.go): "we could not tell" is never
// promoted to an answer. Absent a readable repository AND absent a
// corroborating tool-call result, the finding is `LandingNotChecked`, said
// plainly rather than defaulted to either landed or not.

// LandingOutcome is what this pass derived about one commit_recorded.
type LandingOutcome string

const (
	// LandingLanded: the commit is reachable from a ref in its repository.
	// Never given its own Finding entry — a landed commit is the quiet case,
	// the same reasoning REC-005 gives for an already-resolved intent.
	LandingLanded LandingOutcome = "landed"
	// LandingNotLanded: signed, not landed. The commit was signed under this
	// run's identity (commit_recorded exists) and either the repository
	// answered that the object is not reachable from any ref, or the run's
	// own git commit tool call recorded a ref-lock failure. Git's own
	// concurrency control, not drift (ADR-0059 decision 6).
	LandingNotLanded LandingOutcome = "signed_not_landed"
	// LandingNotChecked: neither signal was available. The repository could
	// not be read (or this deployment's Repos does not support the
	// reachability check at all) and no corroborating tool-call result was
	// found. Never promoted to landed or not-landed.
	LandingNotChecked LandingOutcome = "not_checked"
)

// LandingFinding is one commit_recorded's derived landing verdict.
type LandingFinding struct {
	SubjectEventID string
	RunID          string
	SPIFFEID       string
	Repo           string
	CommitSHA      string
	Outcome        LandingOutcome
	// Detail is why, in words an operator reads. It is never written to the
	// chain — nothing in this file is.
	Detail string
}

// LandingReport is what one cycle's landing pass found.
type LandingReport struct {
	// Enabled is false when no Config.Landing was given, so a reader never
	// mistakes "not run" for "every commit landed".
	Enabled bool
	// Checked is how many commit_recorded events this cycle considered.
	Checked int
	// Landed, NotLanded and NotChecked partition Checked.
	Landed    int
	NotLanded int
	// Rewritten counts commits a merge or rebase rewrote: superseded by a
	// later commit_recorded for the same patch_id, so they landed as a new
	// SHA (ADR-0047).
	Rewritten  int
	NotChecked int
	// Findings is one entry per NotLanded or NotChecked commit — a landed
	// commit gets no entry, the quiet-cycle convention every other pass in
	// this package already follows.
	Findings []LandingFinding
}

// LandingConfig turns the pass on. Nil in Config leaves it OFF, and
// Result.Landing.Enabled says so on every cycle.
type LandingConfig struct {
	// LogDir optionally reads each subject run's own retained tool-call
	// bodies (the same store WritesConfig.LogDir reads, writes.go) for its
	// git commit tool call's own ref-lock failure text — corroborating a
	// repository read this pass could not do, or one that could be done but
	// whose own detail is worth adding. Empty relies on repository
	// reachability alone; nothing about correctness depends on it being set.
	LogDir string
}

// ---------------------------------------------------------------------------
// The ledger side, folded out of the same chain walk every other pass uses.
// ---------------------------------------------------------------------------

// landingRecord is one commit_recorded, reduced to what this pass checks.
type landingRecord struct {
	eventID   string
	runID     string
	spiffeID  string
	repo      string
	commitSHA string
}

// landingClaim is one tool_call, reduced to what this pass needs to find its
// retained body — the identical shape writesView's claimRef holds, kept
// separate because this pass reads a different verdict out of the same body.
type landingClaim struct {
	eventID string
	runID   string
	digest  string
}

// landingView is this pass's fold of the same chain walk ledgerView.observe
// already performs for drift.go, writes.go and rebase.go.
type landingView struct {
	records []landingRecord
	claims  []landingClaim
	// superseded holds every commit_recorded event id a later record's
	// `supersedes` names.
	superseded map[string]bool
}

func newLandingView() *landingView { return &landingView{superseded: map[string]bool{}} }

// observe folds one event in. Called for every event, like the other three
// readers of the same walk.
func (v *landingView) observe(record event.Fields) {
	runID := recordString(record, event.FieldRunID)
	switch recordString(record, event.FieldEventType) {
	case event.EventTypeCommitRecorded:
		if from := recordString(record, event.FieldSupersedes); from != "" {
			v.superseded[from] = true
		}
		eventID := recordString(record, event.FieldEventID)
		sha := recordString(record, event.FieldCommitSHA)
		repo := recordString(record, event.FieldRepo)
		if eventID == "" || sha == "" || repo == "" {
			return
		}
		v.records = append(v.records, landingRecord{
			eventID:   eventID,
			runID:     runID,
			spiffeID:  recordString(record, event.FieldSpiffeID),
			repo:      repo,
			commitSHA: sha,
		})
	case event.EventTypeToolCall:
		digest := recordString(record, event.FieldPayloadDigest)
		eventID := recordString(record, event.FieldEventID)
		if runID == "" || digest == "" || eventID == "" {
			return
		}
		v.claims = append(v.claims, landingClaim{eventID: eventID, runID: runID, digest: digest})
	}
}

// ---------------------------------------------------------------------------
// The repository side.
// ---------------------------------------------------------------------------

// landingReachabilityChecker is implemented by a Repos that can also answer
// whether one commit SHA is reachable from any ref in a repository.
// *GitWorkspace implements it (CommitReachable, below). A Repos that does
// not is never asked to guess: every finding it could have produced comes
// back LandingNotChecked instead (see checkLanding).
type landingReachabilityChecker interface {
	CommitReachable(ctx context.Context, repo, sha string) (bool, error)
}

// CommitReachable reports whether commit sha is reachable from any ref in
// repo — landing.go's own git read, built on repos.go's own worktree
// resolution and invocation discipline (w.worktree, w.run) rather than a
// second one, for ADR-0033 decision 3's reason: `repo` is already held to
// doc 02 §5's grammar and mapped once, and a second mapping is a second
// thing that could disagree about which directory it names.
//
// Two questions, in order. First, does the object exist in the object
// database at all — `git cat-file -e`, exactly the check repos.go's own
// SignedCommitsWithTree filters commits with, read here for existence
// alone. A commit_recorded's object not existing at all is folded into "not
// reachable" rather than treated as a repository fault: worktree() above has
// already proven the directory is a readable repository, so past that point
// "no such object" is a fact about the commit, not about whether this
// process could read the repository. Second, for an object that does exist,
// is it reachable from any ref — `git for-each-ref --contains`, the same
// question ReachableBlobs answers for blobs, asked here of one commit
// directly rather than by materialising every reachable object.
func (w *GitWorkspace) CommitReachable(ctx context.Context, repo, sha string) (bool, error) {
	if err := event.ValidateGitObjectID(sha); err != nil {
		return false, fmt.Errorf("reconciler: %q is not a git object id: %w", sha, err)
	}
	dir, err := w.worktree(repo)
	if err != nil {
		return false, err
	}
	if _, cerr := w.run(ctx, dir, nil, "cat-file", "-e", sha); cerr != nil {
		// `git cat-file -e` fails both for "no such object" and for a
		// repository fault, but worktree() above has already proven dir is a
		// readable repository, so a failure past that point is the object
		// simply not existing — not reachable, and not an error this pass
		// need alert on (see the function doc above).
		return false, nil //nolint:nilerr // deliberate: "no such object" is folded into "not reachable", not treated as a read failure
	}
	out, rerr := w.run(ctx, dir, nil, "for-each-ref", "--contains="+sha, "--format=%(refname)")
	if rerr != nil {
		return false, fmt.Errorf(
			"reconciler: checking whether %s is reachable from any ref in %s: %w", sha, repo, rerr)
	}
	return strings.TrimSpace(out) != "", nil
}

// ---------------------------------------------------------------------------
// The corroborating signal: a run's own git commit tool call.
// ---------------------------------------------------------------------------

// landingToolCallBody is the part of a retained tool-call body this check
// reads — the shape internal/gateway/record.go's gatewayToolCallBody
// assembles and internal/mcp's observe_tool_call stores unchanged. A narrow
// struct rather than a map, on writes.go's own hookBody reasoning: the rest
// of the body is the operator's own commands and output.
type landingToolCallBody struct {
	Tool  string `json:"tool"`
	Input struct {
		Command string `json:"command"`
	} `json:"input"`
	Result  json.RawMessage `json:"result"`
	IsError bool            `json:"is_error"`
}

// refLockFailureDetail scans runID's own tool_call claims for a git commit
// whose recorded result shows a ref-lock failure, and returns the first
// one's own detail text. Empty means none was found — never itself a
// finding, only ever a corroborating detail for one.
func refLockFailureDetail(logDir string, view *landingView, runID string) string {
	for _, c := range view.claims {
		if c.runID != runID {
			continue
		}
		raw, ok := readRunBody(logDir, c.runID, c.digest)
		if !ok {
			continue
		}
		var body landingToolCallBody
		if err := json.Unmarshal(raw, &body); err != nil {
			continue
		}
		if body.Tool != "Bash" || !commitpath.IsGitCommitCommand(body.Input.Command) {
			continue
		}
		if !body.IsError {
			continue
		}
		text, ok := resultText(body.Result)
		if !ok {
			text = string(body.Result)
		}
		if !looksLikeRefLockFailure(text) {
			continue
		}
		return fmt.Sprintf("tool call %s's git commit result shows a ref-lock failure: %s",
			c.eventID, strings.TrimSpace(text))
	}
	return ""
}

// looksLikeRefLockFailure recognises git's own error text for the ONE
// outcome ADR-0059 decision 6 names: another commit won the race to move
// the branch. It matches git's own words, not a status code — measured
// against real git in CMT-015 (landing_integration_test.go) rather than
// assumed.
func looksLikeRefLockFailure(text string) bool {
	lower := strings.ToLower(text)
	switch {
	case strings.Contains(lower, "cannot lock ref"):
		return true
	case strings.Contains(lower, "failed to lock ref"):
		return true
	case strings.Contains(lower, "unable to create") && strings.Contains(lower, ".lock"):
		return true
	case strings.Contains(lower, "but expected"):
		return true
	default:
		return false
	}
}

// ---------------------------------------------------------------------------
// The pass.
// ---------------------------------------------------------------------------

// checkLanding derives a landing verdict for every commit_recorded this
// cycle's chain walk observed. It appends nothing — see this file's own
// header — and an error from a single repository read is never fatal to the
// cycle: it is folded into that one commit's own LandingNotChecked finding,
// exactly as an unreadable repository is folded into OutcomeUnresolved for
// an open intent (resolve, reconcile.go), never into a cycle-wide failure.
func (r *Reconciler) checkLanding(ctx context.Context, view *landingView, cfg *LandingConfig) LandingReport {
	report := LandingReport{Enabled: true}
	if view == nil {
		return report
	}
	checker, canCheckRepo := r.cfg.Repos.(landingReachabilityChecker)

	// A record a rebase pass superseded (doc 02 §2 `supersedes`, ADR-0047)
	// was rewritten by a merge and landed as the superseding record's SHA:
	// not lost. Only the superseding record's own naming counts; identical
	// commits sharing a patch_id are not rewrites of each other.
	for _, rec := range view.records {
		report.Checked++
		finding := LandingFinding{
			SubjectEventID: rec.eventID,
			RunID:          rec.runID,
			SPIFFEID:       rec.spiffeID,
			Repo:           rec.repo,
			CommitSHA:      rec.commitSHA,
		}

		var (
			reachable   bool
			repoChecked bool
			repoErr     error
		)
		if canCheckRepo {
			reachable, repoErr = checker.CommitReachable(ctx, rec.repo, rec.commitSHA)
			repoChecked = repoErr == nil
		}

		var refLockDetail string
		if cfg.LogDir != "" {
			refLockDetail = refLockFailureDetail(cfg.LogDir, view, rec.runID)
		}

		switch {
		case repoChecked && reachable:
			finding.Outcome = LandingLanded
			report.Landed++
			continue // the quiet case: no Finding entry, matching every other pass here.

		case repoChecked && !reachable && view.superseded[rec.eventID]:
			report.Rewritten++
			continue // landed as the SHA that superseded it: nothing to report.

		case repoChecked && !reachable:
			finding.Outcome = LandingNotLanded
			finding.Detail = fmt.Sprintf(
				"commit %s is signed (run %s, %s) but is not reachable from any ref in %s: "+
					"git's own ref lock let a different commit land (ADR-0059 decision 6)",
				rec.commitSHA, rec.runID, rec.eventID, rec.repo)
			if refLockDetail != "" {
				finding.Detail += "; " + refLockDetail
			}
			report.NotLanded++

		case !repoChecked && refLockDetail != "":
			finding.Outcome = LandingNotLanded
			finding.Detail = refLockDetail
			if repoErr != nil {
				finding.Detail += fmt.Sprintf(
					" (the repository %s could not itself be read to confirm reachability "+
						"directly: %v)", rec.repo, repoErr)
			}
			report.NotLanded++

		default:
			finding.Outcome = LandingNotChecked
			switch {
			case repoErr != nil:
				finding.Detail = fmt.Sprintf(
					"%s could not be read, so whether commit %s landed is unknown: %v",
					rec.repo, rec.commitSHA, repoErr)
			case !canCheckRepo:
				finding.Detail = "the configured repository reader does not support a " +
					"reachability check, and no corroborating tool-call result was found"
			default:
				finding.Detail = "no corroborating tool-call result was found"
			}
			report.NotChecked++
		}
		report.Findings = append(report.Findings, finding)
	}
	return report
}
