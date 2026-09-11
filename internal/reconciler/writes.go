// SPDX-License-Identifier: Apache-2.0

package reconciler

import (
	"context"
	"crypto/sha1" //nolint:gosec // G505: git's object id is SHA-1; this computes git's id, not a security digest
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"innsegl.dev/innsegl/internal/event"
)

// Making a reported write falsifiable — RM-104 (#169).
//
// # What was unfalsifiable
//
// `record_event` validates `payload_digest` for SHAPE and compares it to
// nothing: any 64 hex digits are accepted. The ledger therefore recorded what a
// caller SAID it did. `staged_ref` is the opposite and the contrast is the
// point — `sign_commit` requires it to equal the repository's own index, so git
// is the authority and the caller cannot lie about it.
//
// # Why the digest is not the handle, though the issue proposed it
//
// #169 asks whether a claimed write's `payload_digest` appears as a blob in a
// tree the run signed. It cannot: the hook computes that digest over the whole
// event JSON — session id, cwd, tool name, inputs, responses — and a git blob id
// is taken over `blob <len>\x00<content>`. The two can never be equal, so the
// check would report nothing for an honest write and nothing for a forged one,
// which is worse than no check because it looks like one.
//
// What IS checkable is the retained BODY. A `Write` body carries the whole new
// file; an `Edit` body carries the file as it was plus the substitution made to
// it. Either reconstructs the content the agent claims to have produced, and
// that content has a git object id that either appears in a tree the run signed
// or does not.
//
// # What this buys, and what it does not
//
//   - A reported write becomes FALSIFIABLE. That is strictly more than today
//     and strictly less than proof.
//   - OMISSION stays invisible. A write never reported leaves a blob nobody
//     claimed, which is indistinguishable from a build artifact.
//   - `Read` and `Bash` produce no blob and stay uncheckable. A model that
//     writes a file through `Bash` is outside this, exactly as it is outside
//     every hook.
//   - The bodies are local and expire by age (90 days by default), so this can
//     never be re-run over history the way a chain walk can. The ledger keeps
//     the digest forever and the content not at all.

// WriteClaim is one reported file write, reduced to what can be checked.
type WriteClaim struct {
	// EventID is the `tool_call` that claimed it.
	EventID string
	// RunID is the run that claimed it.
	RunID string
	// SPIFFEID is that run's identity. doc 02 §2 omits run_id and spiffe_id
	// TOGETHER, so a finding that names one must carry the other.
	SPIFFEID string
	// Path is the file the body names, as the body names it.
	Path string
	// BlobID is the git object id of the content the claim implies.
	BlobID string
}

// hookBody is the part of a retained tool-call body this check reads.
//
// Deliberately a narrow struct rather than a map: everything else in these
// bodies is the operator's own file contents and commands, and a reader that
// decoded the whole thing would be one refactor away from putting it somewhere.
type hookBody struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		FilePath   string `json:"file_path"`
		Content    string `json:"content"`
		OldString  string `json:"old_string"`
		NewString  string `json:"new_string"`
		ReplaceAll bool   `json:"replace_all"`
	} `json:"tool_input"`
	ToolResponse struct {
		OriginalFile string `json:"originalFile"`
	} `json:"tool_response"`
}

// ClaimFromBody reads one retained body and returns the write it claims.
//
// ok is false for every body that claims no file content — `Read`, `Bash`, an
// MCP call, a `Write` with no path. Those are not findings and must never be
// reported as ones: this check can only speak about writes whose content it can
// reconstruct.
func ClaimFromBody(raw []byte, eventID, runID string) (WriteClaim, bool) {
	var body hookBody
	if err := json.Unmarshal(raw, &body); err != nil {
		return WriteClaim{}, false
	}
	if body.ToolInput.FilePath == "" {
		return WriteClaim{}, false
	}
	content, ok := contentAfter(body)
	if !ok {
		return WriteClaim{}, false
	}
	return WriteClaim{
		EventID: eventID,
		RunID:   runID,
		Path:    body.ToolInput.FilePath,
		BlobID:  BlobID(content),
	}, true
}

// contentAfter reconstructs the file as the claim leaves it.
//
// `Write` states it outright. `Edit` states the file as it was and the one
// substitution made to it, so the result is derived rather than taken on trust —
// which is the point: a body that claims an edit its own before-and-after do not
// produce is already contradicting itself.
//
// An `Edit` whose `old_string` does not occur in the original is exactly that
// case and yields no claim: there is nothing to check it against, and reporting
// it as a missing blob would name the wrong fault.
func contentAfter(body hookBody) (string, bool) {
	switch body.ToolName {
	case "Write":
		if body.ToolInput.Content == "" {
			return "", false
		}
		return body.ToolInput.Content, true
	case "Edit":
		original := body.ToolResponse.OriginalFile
		if original == "" || body.ToolInput.OldString == "" {
			return "", false
		}
		if !strings.Contains(original, body.ToolInput.OldString) {
			return "", false
		}
		n := 1
		if body.ToolInput.ReplaceAll {
			n = -1
		}
		return strings.Replace(original, body.ToolInput.OldString, body.ToolInput.NewString, n), true
	default:
		return "", false
	}
}

// BlobID is git's object id for content stored as a blob.
//
// `blob <len>\x00<content>`, SHA-1 — git's own construction, not a security
// digest, which is why the weak-hash lint is silenced at the import. This must
// equal what `git hash-object` prints or the whole check compares two different
// things and reports every honest write as missing.
func BlobID(content string) string {
	h := sha1.New() //nolint:gosec // G401: git's object id is SHA-1 by definition
	fmt.Fprintf(h, "blob %d\x00", len(content))
	h.Write([]byte(content))
	return hex.EncodeToString(h.Sum(nil))
}

// TreeBlobs is every blob object id reachable from one tree.
//
// One `ls-tree -r` per tree rather than one `cat-file` per claim: a run with a
// thousand Edits against a handful of trees would otherwise be a thousand git
// invocations, and the answer is the same set either way.
//
// A tree git cannot read is not an empty tree. It returns an error, because
// "this repository does not have that object" and "that content was never
// written" are different findings and only one of them is about the agent.
func TreeBlobs(ctx context.Context, gitPath, repo, tree string) (map[string]struct{}, error) {
	git := gitPath
	if git == "" {
		git = "git"
	}
	out, err := exec.CommandContext(ctx, git, "-C", repo,
		"ls-tree", "-r", "--format=%(objectname) %(objecttype)", "--end-of-options", tree).Output()
	if err != nil {
		return nil, fmt.Errorf("listing tree %s in %s: %w", tree, repo, err)
	}
	blobs := map[string]struct{}{}
	for _, line := range strings.Split(string(out), "\n") {
		id, kind, ok := strings.Cut(line, " ")
		if !ok || kind != "blob" {
			continue
		}
		blobs[id] = struct{}{}
	}
	return blobs, nil
}

// WriteVerdict is what the check concluded about one claim.
type WriteVerdict int

const (
	// WriteSupported: the content the claim implies is in a tree the run
	// signed. The claim is corroborated by git, which the caller does not
	// control.
	WriteSupported WriteVerdict = iota
	// WriteUnsupported: the content is in none of them. This is the finding.
	WriteUnsupported
	// WriteUncheckable: the run signed no tree this check could read, so
	// there was nothing to check against. Never a finding — an absence of
	// evidence reported as evidence is the failure mode this whole project
	// exists to avoid (doc 06 P2).
	WriteUncheckable
)

// JudgeWrite decides one claim against the blobs of every tree the run signed.
func JudgeWrite(claim WriteClaim, signed []map[string]struct{}) WriteVerdict {
	if len(signed) == 0 {
		return WriteUncheckable
	}
	for _, blobs := range signed {
		if _, found := blobs[claim.BlobID]; found {
			return WriteSupported
		}
	}
	return WriteUnsupported
}

// ---------------------------------------------------------------------------
// The pass — RM-104 (#169)
// ---------------------------------------------------------------------------

// WritesConfig turns the check on. Nil leaves it OFF.
type WritesConfig struct {
	// LogDir is where the harness writes tool-call bodies, one directory per
	// run. Required: the digest in the chain is over the event envelope and
	// says nothing about content, so the body is the only thing to check.
	//
	// READ-ONLY, and it holds the operator's own file contents. This pass opens
	// what a run's own events name and nothing else.
	LogDir string
	// Repos are the repository identifiers whose trees may be read. Required
	// for RebaseConfig.Repos' reason: a pass that discovered its own
	// repositories would read trees nobody asked it to.
	Repos []string
}

// WritesReport is what one pass did.
type WritesReport struct {
	// Enabled is false when no WritesConfig was given, so a reader never
	// mistakes "not run" for "nothing to find".
	Enabled bool
	// Checked is how many claims this pass could reconstruct and judge.
	Checked int
	// Supported is how many were corroborated by a tree the run signed.
	Supported int
	// Unsupported is how many were not. This is the finding.
	Unsupported int
	// Uncheckable is how many belonged to a run that signed no readable tree.
	// Never a finding, and counted so that a deployment can see how much of
	// its activity this check is silent about.
	Uncheckable int
	// Unreadable is how many bodies could not be opened or parsed — expired
	// past the retention window, or never written. Also never a finding: the
	// body's absence is a fact about this machine, not about the agent.
	Unreadable int
}

// reasonUnsupportedWrite is a `ledger_drift_detected` reason.
//
// PROTECTED-ADJACENT, exactly as the reasons in drift.go are: `reason` is part
// of the canonical preimage of an event in an append-only chain, and it is
// operator-facing text. A CONSTANT, carrying no path, digest or run id — what
// varies goes in the event's run scope and in the finding's Detail.
//
// It reuses `ledger_drift_detected` rather than introducing a twelfth event
// type. doc 02 §3's type list is a protected surface and a new value is a major
// schema version; this is already the vocabulary for a ledger claim that
// external evidence contradicts, which is exactly what this is.
const reasonUnsupportedWrite = "the content this tool_call reports writing is in no tree the run signed"

// unsupportedWriteKeyPrefix namespaces this pass's idempotency keys, so a
// second pass over the same claim appends nothing.
const unsupportedWriteKeyPrefix = "reconciler:unsupported_write:"

// UnsupportedWriteKey is the `idempotency_key` such a finding carries: the
// subject event's id, which is unique on the chain by construction.
func UnsupportedWriteKey(eventID string) string {
	return unsupportedWriteKeyPrefix + eventID
}

// readRunBody opens one retained tool-call body.
//
// The same layout internal/api/runlog.go reads: one directory per run, one file
// per digest. The digest is validated before it is used as a path element and
// the run id is taken by base — these two strings arrive from the ledger, and
// the guard belongs on the line that opens the file rather than forty lines
// away where a later caller can miss it.
//
// The body is NOT checked against its digest here. That check is the run log's
// job and its answer is already on the dashboard; a body that has been altered
// on disk produces a claim that will not match any tree, which this pass would
// then report as an unsupported write — the wrong finding. So a mismatch is
// treated as unreadable instead.
func readRunBody(dir, runID, digest string) ([]byte, bool) {
	hexPart, ok := strings.CutPrefix(digest, "sha256:")
	if !ok || len(hexPart) != 64 {
		return nil, false
	}
	if _, err := hex.DecodeString(hexPart); err != nil {
		return nil, false
	}
	raw, err := os.ReadFile(filepath.Join(dir, filepath.Base(runID), hexPart+".json"))
	if err != nil {
		return nil, false
	}
	sum := sha256.Sum256(raw)
	if "sha256:"+hex.EncodeToString(sum[:]) != digest {
		return nil, false
	}
	return raw, true
}

// writesView is this pass's fold of the same chain walk: which run signed which
// trees, and which tool calls claimed to write something.
//
// One walk, three readers — drift.go and rebase.go fold the same records for
// their own questions. A second pass over the chain would be a second thing
// that can disagree about what the chain says.
type writesView struct {
	// trees is the set of tree hashes each run signed, in no order: the
	// question is membership, never sequence.
	trees map[string]map[string]struct{}
	// repoOf is the repository a run signed in. A run that signed in two is
	// unusual and the first wins, because the trees are looked up by tree
	// hash and a tree is in whichever repository holds it.
	repoOf map[string]string
	// claims are the tool calls that might have written something. Whether
	// they did is decided from the body, which the chain does not hold.
	claims []claimRef
	// reported is the set of subject event ids a finding already names, read
	// back off the chain rather than remembered between cycles.
	reported map[string]struct{}
}

// claimRef is a tool call as the chain holds it: enough to find its body.
type claimRef struct {
	eventID  string
	runID    string
	spiffeID string
	digest   string
}

func newWritesView() *writesView {
	return &writesView{
		trees:    map[string]map[string]struct{}{},
		repoOf:   map[string]string{},
		claims:   nil,
		reported: map[string]struct{}{},
	}
}

// observe folds one event in. Called for EVERY event, like drift's.
func (v *writesView) observe(record event.Fields) {
	runID := recordString(record, event.FieldRunID)
	switch recordString(record, event.FieldEventType) {
	case event.EventTypeCommitRecorded:
		// The trees a run signed are the evidence every claim of that run is
		// judged against. A superseding record names the same tree as the
		// original, so a rewrite adds nothing here and costs nothing either.
		tree := recordString(record, event.FieldTreeHash)
		if runID == "" || tree == "" {
			return
		}
		if v.trees[runID] == nil {
			v.trees[runID] = map[string]struct{}{}
		}
		v.trees[runID][tree] = struct{}{}
		if _, known := v.repoOf[runID]; !known {
			v.repoOf[runID] = recordString(record, event.FieldRepo)
		}

	case event.EventTypeToolCall:
		digest := recordString(record, event.FieldPayloadDigest)
		eventID := recordString(record, event.FieldEventID)
		if runID == "" || digest == "" || eventID == "" {
			return
		}
		v.claims = append(v.claims, claimRef{
			eventID:  eventID,
			runID:    runID,
			spiffeID: recordString(record, event.FieldSpiffeID),
			digest:   digest,
		})

	case event.EventTypeLedgerDriftDetected:
		// Dedupe read back off the chain, never remembered: a fresh process
		// must behave identically to one that has been running for a week,
		// which is the property REC-005 rests on.
		if subject := recordString(record, event.FieldSubjectEventID); subject != "" {
			v.reported[subject] = struct{}{}
		}
	}
}

// checkWrites judges every claim this cycle can reconstruct.
//
// Ordered so the expensive thing happens once: trees are listed per run, not
// per claim, because a run with a thousand Edits against three trees is three
// git invocations and not a thousand.
//
// Nothing here is enforcement. record_event cannot know at write time which
// tree a later sign_commit will carry, and blocking on a digest that has not
// been committed yet would break the normal order of work. This is detection,
// after the fact, which is what #169 asked for.
func (r *Reconciler) checkWrites(
	ctx context.Context, view *writesView, cfg *WritesConfig,
) WritesReport {
	report := WritesReport{Enabled: true}
	served := map[string]struct{}{}
	for _, repo := range cfg.Repos {
		served[repo] = struct{}{}
	}
	// Per-run tree blobs, computed at most once each.
	blobsFor := map[string][]map[string]struct{}{}

	for _, claim := range view.claims {
		if _, already := view.reported[claim.eventID]; already {
			continue
		}
		raw, ok := readRunBody(cfg.LogDir, claim.runID, claim.digest)
		if !ok {
			report.Unreadable++
			continue
		}
		write, ok := ClaimFromBody(raw, claim.eventID, claim.runID)
		if !ok {
			// Not a file write, or a body whose own before-and-after do not
			// produce its claim. Neither is a finding.
			continue
		}

		signed, known := blobsFor[claim.runID]
		if !known {
			signed = r.signedBlobs(ctx, view, claim.runID, served)
			blobsFor[claim.runID] = signed
		}

		report.Checked++
		switch JudgeWrite(write, signed) {
		case WriteSupported:
			report.Supported++
		case WriteUncheckable:
			report.Uncheckable++
		case WriteUnsupported:
			report.Unsupported++
			write.SPIFFEID = claim.spiffeID
			r.reportUnsupportedWrite(ctx, write)
		}
	}
	return report
}

// signedBlobs is every blob in every tree a run signed, in a repository this
// pass was asked to read.
//
// A tree that cannot be read contributes nothing and is NOT an error for the
// run: the repository may simply not be on this machine. What that produces is
// an "uncheckable" verdict, which is the honest answer — not an accusation.
func (r *Reconciler) signedBlobs(
	ctx context.Context, view *writesView, runID string, served map[string]struct{},
) []map[string]struct{} {
	repo := view.repoOf[runID]
	if _, ok := served[repo]; !ok {
		return nil
	}
	var out []map[string]struct{}
	for tree := range view.trees[runID] {
		blobs, err := r.cfg.Repos.TreeBlobs(ctx, repo, tree)
		if err != nil {
			continue
		}
		out = append(out, blobs)
	}
	return out
}

// reportUnsupportedWrite appends the finding, once per subject.
func (r *Reconciler) reportUnsupportedWrite(ctx context.Context, write WriteClaim) {
	body := event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeLedgerDriftDetected,
		event.FieldSource:         event.SourceReconciler,
		event.FieldSubjectEventID: write.EventID,
		event.FieldReason:         reasonUnsupportedWrite,
		event.FieldIdempotencyKey: UnsupportedWriteKey(write.EventID),
	}
	// doc 02 §2: run_id and spiffe_id are omitted TOGETHER. The subject is a
	// run's own tool call, so both are present and the feed names the agent
	// whose claim this is — unless the subject was unreadable, where inventing
	// a run scope would be a second falsehood on top of the one reported.
	if write.RunID != "" && write.SPIFFEID != "" {
		body[event.FieldRunID] = write.RunID
		body[event.FieldSpiffeID] = write.SPIFFEID
	}
	_, err := r.cfg.Appender.Append(ctx, body)
	if err != nil {
		if r.cfg.Alert != nil {
			r.cfg.Alert(ctx, Finding{
				Outcome: OutcomeUnresolved,
				RunID:   write.RunID,
				Detail: fmt.Sprintf("recording an unsupported write for tool_call %s: %v",
					write.EventID, err),
			})
		}
	}
}
