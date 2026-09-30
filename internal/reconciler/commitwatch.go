// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"log/slog"
	"regexp"
	"strings"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
)

// commitwatch.go — RM-244 (#389), E17 (the commit path, ADR-0059).
//
// ADR-0059 attributes a commit through the tool call that asked for it: the
// harness's own `git commit` carries that tool call's own identifier into
// `prepare-commit-msg` and `gpg.x509.program`, and the core signs and records
// it there, in the SAME call, on the SAME run. Nothing in git itself stops an
// agent from asking for a commit a different way — `git -c
// commit.gpgsign=false -c core.hooksPath=/dev/null commit ...`, or plain
// `--no-gpg-sign` — git still makes the commit object, and nothing is signed
// or recorded. This pass is the detection control for exactly that: a commit
// an agent made, that this deployment never signed.
//
// # What it reads, and why no new evidence is needed
//
// Every tool call is already a `tool_call` event (source mcp), and the
// gateway already retains its body (internal/gateway/record.go's own
// gatewayToolCallBody), read the SAME way writes.go's RM-104 check already
// reads one: readRunBody, by (run, digest), never trusted past its own
// digest. The body's `input.command` says whether the call asked git for a
// commit — commitpath.IsGitCommitCommand, the SAME reading the harness's own
// hook and the core's own gate use, so this pass and ADR-0059's gate can
// never disagree about what counts. The body's `result` says whether git
// actually made one: git's own `print_summary` (builtin/commit.c) prints
// exactly one line shaped `[<branch> <sha>] <subject>`, or
// `[<branch> (root-commit) <sha>] <subject>` for a repository's first
// commit, and nothing else a harness ever puts in a tool result is shaped
// like it — see commitSummaryLine, anchored to the START of a line so an
// agent's own commit message, or a Bash command's unrelated output, can
// never be mistaken for git's own line. "Parse it strictly" — match the
// fixed grammar, never merely search for the substring.
//
// # What "signed" means here
//
// The SAME run's `commit_recorded` events, folded from the SAME chain walk
// every other pass in this package folds (drift.go, writes.go, rebase.go —
// "one walk, N readers": ledgerView.observe calls this file's observe
// exactly as it calls theirs). ADR-0059 decision 4 appends `commit_recorded`
// from INSIDE the blocking `git commit` invocation, before that invocation
// returns and therefore before the harness can ever observe its result — so
// in the ordinary case the record is already on the chain by the time a
// tool_call for the same command is. But chain position is never assumed:
// both sides are folded from the WHOLE walk before either is judged, so a
// commit_recorded appended a position or two later, in the SAME cycle, is
// still found. See commitWatchView.
//
// # Never a finding on what cannot be read
//
// A body that is missing, unreadable, truncated (input or result), or was
// never observed at all — a tool_use record.go's own bounded pending table
// evicted before its result arrived — says NOTHING about whether a commit
// happened. It is counted Unchecked, exactly as RM-104 counts an unreadable
// claim Uncheckable/Unreadable rather than treating an absence of evidence
// as evidence of anything (doc 06 P2).
//
// # Idempotency
//
// This pass writes doc 02 §3's EXISTING `ledger_drift_detected` — "a ledger
// claim with no external proof" fits exactly: the claim a matching
// commit_recorded would make is that this run's signature exists for this
// commit, and it does not. No new event type, field or enum value (doc 08 §3
// protected surface 2). It reuses drift.go's own dedupe key,
// LedgerDriftKey(subjectEventID) — here the tool_call's own event id — and
// reads "already reported" back out of view.drift.subjects, the SAME set
// every ledger_drift_detected on the chain populates regardless of which
// pass or which reason wrote it (drift.go's driftView.observe). A second
// cycle over unchanged chain state finds every subject already there and
// appends nothing (CMT-016).

// reasonCommitNotSigned is this pass's one `reason` constant.
//
// PROTECTED-ADJACENT, exactly as drift.go records for its own: `reason` is
// part of the canonical preimage (doc 02 §4) of an event in an append-only
// chain. A constant, carrying no sha, uuid or timestamp — what varies goes in
// the event's run scope, and in the finding's Detail, which is never written
// to the chain.
const reasonCommitNotSigned = "a git commit was made with no signature recorded for it"

// commitSummaryLine is git's own commit-summary format (builtin/commit.c's
// print_summary): the branch name (or "(root-commit)" ahead of the sha for a
// repository's very first commit) and the abbreviated object id, inside
// brackets, at the very start of a line. Anchored with `(?m)^` rather than
// searched for anywhere, so a subject line or an unrelated Bash command's own
// output that happens to contain a bracketed substring can never be mistaken
// for it.
var commitSummaryLine = regexp.MustCompile(`(?m)^\[\S+ (?:\(root-commit\) )?([0-9a-f]{4,40})\]`)

// commitShortSHA reports the abbreviated commit id git's own summary line
// names in text, and whether text holds one at all.
func commitShortSHA(text string) (string, bool) {
	m := commitSummaryLine.FindStringSubmatch(text)
	if m == nil {
		return "", false
	}
	return m[1], true
}

// ---------------------------------------------------------------------------
// The retained body, as this pass reads it.
// ---------------------------------------------------------------------------

// commitWatchBody is the part of a gateway-recorded tool_call body this pass
// reads: internal/gateway/record.go's own gatewayToolCallBody, restated here
// rather than imported — that type is unexported to its own package, the same
// reason writes.go restates the harness hook's own body shape as its own
// unexported hookBody rather than importing one.
type commitWatchBody struct {
	Tool            string          `json:"tool"`
	Input           json.RawMessage `json:"input"`
	InputTruncated  bool            `json:"input_truncated"`
	ResultObserved  bool            `json:"result_observed"`
	Result          json.RawMessage `json:"result"`
	ResultTruncated bool            `json:"result_truncated"`
}

// resultText reads a tool_result's own `content` field: a plain string (the
// ordinary shape for a Bash result) or an array of content blocks, of which
// only `{"type":"text",...}` ones contribute. ok is false when raw is neither
// shape — a body this pass cannot read a verdict from, counted Unchecked
// rather than treated as "no commit shown".
func resultText(raw json.RawMessage) (string, bool) {
	if len(raw) == 0 {
		return "", true
	}
	var s string
	if err := json.Unmarshal(raw, &s); err == nil {
		return s, true
	}
	var blocks []struct {
		Type string `json:"type"`
		Text string `json:"text"`
	}
	if err := json.Unmarshal(raw, &blocks); err == nil {
		var b strings.Builder
		for _, blk := range blocks {
			if blk.Type == "text" {
				b.WriteString(blk.Text)
			}
		}
		return b.String(), true
	}
	return "", false
}

// ---------------------------------------------------------------------------
// Findings.
// ---------------------------------------------------------------------------

// CommitWatchFinding is one tool call's verdict, and the operator-visible
// half of this pass.
type CommitWatchFinding struct {
	ToolCallEventID string
	RunID           string
	SPIFFEID        string
	// ShortSHA is the abbreviated commit id git's own summary line named.
	ShortSHA string
	// Reason is the constant that goes into the ledger_drift_detected this
	// finding produced.
	Reason string
	// Detail is why, in words an operator reads, with the identifiers Reason
	// deliberately leaves out.
	Detail string
	// AppendedEventID is the alert this finding produced, empty when it was
	// already reported (idempotent) or when nothing could be appended.
	AppendedEventID string
}

// CommitWatchReport is what one pass did.
type CommitWatchReport struct {
	// Enabled is false when no Config.CommitWatch was given, so a reader
	// never mistakes "not run" for "nothing to find".
	Enabled bool
	// Checked is how many git-commit tool calls this pass could read a
	// verdict for: a readable, untruncated body whose result was observed.
	Checked int
	// Signed is how many of those needed no alert: no commit shown at all
	// (nothing to commit, a refusal, a lost ref race), or a commit shown and
	// a matching commit_recorded exists on the same run.
	Signed int
	// Unsigned is how many NEW findings this cycle produced: a commit shown
	// with no matching commit_recorded on the run, not already carrying a
	// ledger_drift_detected from an earlier cycle. Exactly drift.go's own
	// convention for Fabricated: a call already reported is skipped before
	// it is even judged again, so a standing finding is not recounted cycle
	// after cycle — it is read back off the chain instead (REC-005).
	Unsigned int
	// Unchecked is how many tool calls this pass could not read a verdict
	// for: an unreadable or truncated body, or one whose result was never
	// observed at all. Never a finding.
	Unchecked int
	// Findings is one entry per Unsigned tool call, in no particular order.
	Findings []CommitWatchFinding
	// Appended is the event_id of each alert this cycle wrote. Empty on a
	// cycle over already-reported state.
	Appended []string
}

// ---------------------------------------------------------------------------
// Configuration.
// ---------------------------------------------------------------------------

// CommitWatchConfig turns the pass on. Nil leaves it OFF, and
// Result.CommitWatch.Enabled says so on every cycle rather than letting a
// deployment believe a reconciler without it is watching for a bypassed hook.
type CommitWatchConfig struct {
	// LogDir is where the gateway retains tool-call bodies, one directory per
	// run — the SAME store WritesConfig.LogDir reads (writes.go); a
	// deployment running both passes points them at one directory. Required:
	// a detector that cannot read a tool call's result reports agreement it
	// never checked.
	LogDir string
	// Alert receives every finding, including the ones already reported.
	// Defaults to an error-level slog line, the same default drift.go gives
	// its own Alert.
	Alert func(context.Context, CommitWatchFinding)
}

// validate refuses a half-configured detector, the same discipline
// DriftConfig.validate holds its own to.
func (c *CommitWatchConfig) validate() error {
	if c == nil {
		return nil
	}
	if c.LogDir == "" {
		return errors.New("reconciler: commit watch is configured with no body directory; " +
			"a detector that cannot read a tool call's own result reports agreement it " +
			"never checked")
	}
	return nil
}

func (c *CommitWatchConfig) alert(ctx context.Context, finding CommitWatchFinding) {
	if c.Alert != nil {
		c.Alert(ctx, finding)
		return
	}
	defaultCommitWatchAlert(ctx, finding)
}

// ---------------------------------------------------------------------------
// The ledger side of the check, folded out of the same chain walk.
// ---------------------------------------------------------------------------

// commitWatchCall is one Bash tool_call this pass has to judge: cheap to
// collect during the walk (event fields only), expensive to judge (a body
// read), so judging happens once, after the whole chain has been folded —
// exactly writesView's own split between claims collected during observe and
// claims judged afterward.
type commitWatchCall struct {
	eventID  string
	runID    string
	spiffeID string
	digest   string
}

// commitWatchView is this pass's fold of the chain: which commit shas each
// run's own commit_recorded events name, and which Bash tool calls might be
// an unsigned commit. One walk, folded alongside drift.go's, writes.go's and
// rebase.go's own readers.
type commitWatchView struct {
	// commitsByRun is every commit_sha a commit_recorded on that run holds —
	// originals and any superseding record (ADR-0047) alike: a rebase keeps
	// the same signature and only moves which object it is over, so the
	// run's own recorded set only ever grows.
	commitsByRun map[string]map[string]struct{}
	calls        []commitWatchCall
}

func newCommitWatchView() *commitWatchView {
	return &commitWatchView{commitsByRun: map[string]map[string]struct{}{}}
}

// observe folds one event in. Called for EVERY event, like drift's and
// writes's own.
func (v *commitWatchView) observe(record event.Fields) {
	switch recordString(record, event.FieldEventType) {
	case event.EventTypeCommitRecorded:
		runID := recordString(record, event.FieldRunID)
		sha := recordString(record, event.FieldCommitSHA)
		if runID == "" || sha == "" {
			return
		}
		if v.commitsByRun[runID] == nil {
			v.commitsByRun[runID] = map[string]struct{}{}
		}
		v.commitsByRun[runID][sha] = struct{}{}
	case event.EventTypeToolCall:
		// Cheap filter before the expensive one: only a Bash call could ever
		// have run `git commit`, and reading every tool call's body would be
		// a git-commit check that costs like a check of everything.
		if recordString(record, event.FieldToolName) != "Bash" {
			return
		}
		runID := recordString(record, event.FieldRunID)
		eventID := recordString(record, event.FieldEventID)
		digest := recordString(record, event.FieldPayloadDigest)
		if runID == "" || eventID == "" || digest == "" {
			return
		}
		v.calls = append(v.calls, commitWatchCall{
			eventID:  eventID,
			runID:    runID,
			spiffeID: recordString(record, event.FieldSpiffeID),
			digest:   digest,
		})
	}
}

// signedFor reports whether some commit this run signed has shortSHA as a
// prefix of its full object id — the join git's own abbreviation makes
// unambiguous inside one repository.
func signedFor(recorded map[string]struct{}, shortSHA string) bool {
	for sha := range recorded {
		if strings.HasPrefix(sha, shortSHA) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// The cycle.
// ---------------------------------------------------------------------------

// checkCommits judges every Bash tool call this cycle can read a verdict for.
func (r *Reconciler) checkCommits(ctx context.Context, view *ledgerView) CommitWatchReport {
	report := CommitWatchReport{Enabled: true}
	cfg := r.cfg.CommitWatch

	for _, call := range view.commitWatch.calls {
		// Dedupe FIRST, before any body I/O: the key is the tool call's own
		// event id, known from the chain alone, exactly as drift.go checks
		// view.drift.subjects before calling judge. A call already reported
		// is not re-read, re-parsed or re-counted every cycle for the rest
		// of the chain's life — the standing alert is read back off the
		// chain (REC-005), not recomputed.
		if _, already := view.drift.subjects[call.eventID]; already {
			continue
		}
		raw, ok := readRunBody(cfg.LogDir, call.runID, call.digest)
		if !ok {
			report.Unchecked++
			continue
		}
		var body commitWatchBody
		if err := json.Unmarshal(raw, &body); err != nil || body.Tool != "Bash" {
			report.Unchecked++
			continue
		}
		if body.InputTruncated {
			report.Unchecked++
			continue
		}
		var input struct {
			Command string `json:"command"`
		}
		if err := json.Unmarshal(body.Input, &input); err != nil {
			report.Unchecked++
			continue
		}
		if !commitpath.IsGitCommitCommand(input.Command) {
			continue // not a git commit call: nothing this pass has an opinion about
		}
		if !body.ResultObserved {
			// The tool_use was evicted before its result arrived (record.go's
			// own bounded pending table), or a result has simply not reached
			// the gateway yet. Either way, whether git made a commit is
			// unknown, never "no".
			report.Unchecked++
			continue
		}
		if body.ResultTruncated {
			report.Unchecked++
			continue
		}
		text, ok := resultText(body.Result)
		if !ok {
			report.Unchecked++
			continue
		}

		report.Checked++
		shortSHA, madeCommit := commitShortSHA(text)
		if !madeCommit {
			// Nothing to commit, refused by the hook, lost the ref lock, or
			// any other non-zero exit that never reached print_summary.
			report.Signed++
			continue
		}
		if signedFor(view.commitWatch.commitsByRun[call.runID], shortSHA) {
			report.Signed++
			continue
		}

		report.Unsigned++
		finding := CommitWatchFinding{
			ToolCallEventID: call.eventID,
			RunID:           call.runID,
			SPIFFEID:        call.spiffeID,
			ShortSHA:        shortSHA,
			Reason:          reasonCommitNotSigned,
			Detail: fmt.Sprintf(
				"tool_call %s ran a git commit and its result names commit %s, and no "+
					"commit_recorded on run %s names a commit whose sha starts with it: "+
					"the commit was made without going through the signing path (ADR-0059)",
				call.eventID, shortSHA, call.runID),
		}
		r.appendCommitWatchAlert(ctx, &report, finding)
	}
	return report
}

// appendCommitWatchAlert writes one alert and records what happened.
//
// An append whose idempotency_key is already spent returns the earlier event
// and writes nothing (LED-008) — two concurrent reconcilers cannot double
// alert — and is reported as an empty AppendedEventID rather than counted as
// a write. A ledger that REFUSED the append is not allowed to silence the
// finding: I3 admits no action without a record, and an alert nobody can
// record is still an alert somebody must see, so the operator sink is told
// either way.
func (r *Reconciler) appendCommitWatchAlert(
	ctx context.Context, report *CommitWatchReport, finding CommitWatchFinding,
) {
	body := event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeLedgerDriftDetected,
		event.FieldSource:         event.SourceReconciler,
		event.FieldIdempotencyKey: LedgerDriftKey(finding.ToolCallEventID),
		event.FieldSubjectEventID: finding.ToolCallEventID,
		event.FieldReason:         finding.Reason,
	}
	// doc 02 §2: run_id and spiffe_id are omitted TOGETHER. The subject is a
	// run's own tool_call, so both are present unless the tool_call itself
	// carried no spiffe_id — in which case inventing one would be a second
	// falsehood on top of the one being reported.
	if finding.RunID != "" && finding.SPIFFEID != "" {
		body[event.FieldRunID] = finding.RunID
		body[event.FieldSpiffeID] = finding.SPIFFEID
	}
	record, err := r.cfg.Appender.Append(ctx, body)
	switch {
	case err != nil:
		finding.Detail += fmt.Sprintf("; and this alert could not be appended to the chain: %v", err)
	case recordString(record, event.FieldEventType) != event.EventTypeLedgerDriftDetected:
		finding.Detail += fmt.Sprintf("; and the idempotency key %q names a %s rather than this alert",
			recordString(body, event.FieldIdempotencyKey), recordString(record, event.FieldEventType))
	default:
		finding.AppendedEventID = recordString(record, event.FieldEventID)
	}
	report.Findings = append(report.Findings, finding)
	if finding.AppendedEventID != "" {
		report.Appended = append(report.Appended, finding.AppendedEventID)
	}
	r.cfg.CommitWatch.alert(ctx, finding)
}

// defaultCommitWatchAlert is the sink a deployment gets if it names none.
// Error level, unconditionally — the same standing drift.go's own default
// gives an alert that "must be loud".
func defaultCommitWatchAlert(ctx context.Context, finding CommitWatchFinding) {
	slog.ErrorContext(ctx, "commit watch: a git commit was made with no signature recorded for it",
		"tool_call_event_id", finding.ToolCallEventID,
		"run_id", finding.RunID,
		"short_sha", finding.ShortSHA,
		"appended_event_id", finding.AppendedEventID,
		"detail", finding.Detail)
}
