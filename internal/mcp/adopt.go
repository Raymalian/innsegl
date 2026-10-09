// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/ledger"
)

// ADOPTION'S PROOF — ADR-0051 decision 2, #298 (RM-187).
//
// A live run may commit work a dead run left, and the commit names both. What
// makes that a record rather than a claim is this file: for every path handed
// over, the bytes are rebuilt from the dead run's OWN tool-call bodies, each
// read back and checked against the digest the chain holds for it. The caller
// supplies nothing that enters the proof except the list of paths.
//
// WHAT COUNTS AS WRITING A PATH. A `Write` body carries the whole content. An
// `Edit` body carries, in its response, the file as it was before the edit and
// the replacement made, so replaying the one edit gives the whole file after
// it. Either way the LAST such call on a path is the bytes the run left there.
// A path written through a shell has no body that names its bytes, and is
// refused rather than adopted on trust.
//
// STRICT ON A BAD BODY. One `Write` or `Edit` body that is missing or does not
// match its digest refuses the whole adoption, not just its path. The body
// cannot be read, so which path it touched cannot be known either — and an
// adoption that silently fell back to an earlier call for that path would be
// proving the wrong bytes.

// adoptedPath is one path's proof: the bytes the dead run left, their SHA-256,
// and the event_hash of the tool call that produced them.
type adoptedPath struct {
	Path     string
	Bytes    []byte
	SHA256   string
	ToolCall string
}

// adoptBody is the part of a stored tool-call body the proof reads, in either
// of the two shapes a body has been recorded in. The hook shape (ADR-0051)
// carries tool_name, tool_input and tool_response; the gateway shape
// (ADR-0058, internal/gateway's buildToolCallBody) carries tool, input,
// whether the result was observed and whether it was an error (ADR-0079
// decision 4).
type adoptBody struct {
	ToolName  string `json:"tool_name"`
	ToolInput struct {
		FilePath string `json:"file_path"`
		Content  string `json:"content"`
	} `json:"tool_input"`
	ToolResponse struct {
		OriginalFile string `json:"originalFile"`
		OldString    string `json:"oldString"`
		NewString    string `json:"newString"`
		ReplaceAll   bool   `json:"replaceAll"`
	} `json:"tool_response"`

	Tool  string `json:"tool"`
	Input struct {
		FilePath   string `json:"file_path"`
		Content    string `json:"content"`
		OldString  string `json:"old_string"`
		NewString  string `json:"new_string"`
		ReplaceAll bool   `json:"replace_all"`
	} `json:"input"`
	InputTruncated bool `json:"input_truncated"`
	ResultObserved bool `json:"result_observed"`
	IsError        bool `json:"is_error"`
}

// adoptOp is what one Write or Edit did to one file: left exactly `set`,
// replayed `edit` on the bytes before it, or left bytes nothing can know
// (`unknown`, saying why).
type adoptOp struct {
	file    string
	hash    string
	set     []byte
	edit    *adoptEdit
	unknown string
}

// adoptEdit is a gateway-recorded Edit: its input, and nothing of the file.
type adoptEdit struct {
	oldS, newS string
	all        bool
}

// adoptOpOf reads one verified body into what the call did. A body that is
// not a tool call, or names no file, is an error: which path it touched
// cannot be known. A gateway call whose result was an error changed nothing,
// and is (nil, nil).
func adoptOpOf(tool, hash string, raw []byte) (*adoptOp, error) {
	var b adoptBody
	if err := json.Unmarshal(raw, &b); err != nil || (b.ToolName == "" && b.Tool == "") {
		return nil, fmt.Errorf("the body of %s %s is not a tool call", tool, hash)
	}
	if b.Tool == "" {
		// The hook shape: the call's own bytes, whole.
		left, err := leftBy(tool, b)
		if err != nil {
			return nil, fmt.Errorf("%s %s on %s cannot be replayed: %w", tool, hash, b.ToolInput.FilePath, err)
		}
		return &adoptOp{file: b.ToolInput.FilePath, hash: hash, set: left}, nil
	}
	in := b.Input
	if in.FilePath == "" {
		return nil, fmt.Errorf("the body of %s %s names no file", tool, hash)
	}
	op := &adoptOp{file: in.FilePath, hash: hash}
	switch {
	case b.InputTruncated:
		op.unknown = fmt.Sprintf("%s %s was recorded with its input cut short", tool, hash)
	case !b.ResultObserved:
		op.unknown = fmt.Sprintf("the result of %s %s was never observed, so whether it ran cannot be known",
			tool, hash)
	case b.IsError:
		return nil, nil
	case tool == "Write":
		op.set = []byte(in.Content)
	default:
		op.edit = &adoptEdit{oldS: in.OldString, newS: in.NewString, all: in.ReplaceAll}
	}
	return op, nil
}

// rebuildLeftBytes returns, for every staged path, the bytes runID's Write and
// Edit calls left there, or an error naming what could not be proved.
//
// A path's calls are replayed in chain order (ADR-0079 decision 4). A Write,
// and a hook-shaped Edit, leave whole bytes of their own. A gateway Edit is
// replayed on the bytes before it: the run's own earlier calls, or the path's
// blob in the parent commit, which base answers (nil: there is none). The
// tool call that proves a path is the last one that changed it.
func rebuildLeftBytes(
	events []event.Fields, bodyDir, runID string, staged []string, base func(string) ([]byte, bool),
) (map[string]adoptedPath, error) {
	var ops []adoptOp
	var bad []string
	for _, ev := range events {
		if ev[event.FieldEventType] != event.EventTypeToolCall || ev[event.FieldRunID] != runID {
			continue
		}
		tool := fieldString(ev, event.FieldToolName)
		if tool != "Write" && tool != "Edit" {
			continue
		}
		hash := fieldString(ev, event.EventHashField)
		digest := fieldString(ev, event.FieldPayloadDigest)
		raw, err := os.ReadFile(filepath.Join(bodyDir, filepath.Base(runID),
			strings.TrimPrefix(digest, event.HashPrefix)+observeBodyExt))
		if err != nil {
			bad = append(bad, fmt.Sprintf("the body of %s %s cannot be read", tool, hash))
			continue
		}
		if event.Digest(raw) != digest {
			bad = append(bad, fmt.Sprintf("the body of %s %s does not match its digest", tool, hash))
			continue
		}
		op, err := adoptOpOf(tool, hash, raw)
		if err != nil {
			bad = append(bad, err.Error())
			continue
		}
		if op != nil {
			ops = append(ops, *op)
		}
	}

	out := make(map[string]adoptedPath, len(staged))
	top := ""
	var unproved, why []string
	for _, path := range staged {
		var mine []adoptOp
		for i := len(ops) - 1; i >= 0; i-- {
			if !strings.HasSuffix(ops[i].file, "/"+path) {
				continue
			}
			here := strings.TrimSuffix(ops[i].file, "/"+path)
			if top == "" {
				top = here
			}
			if here == top {
				mine = append([]adoptOp{ops[i]}, mine...)
			}
		}
		if len(mine) == 0 {
			unproved = append(unproved, path)
			continue
		}
		p, reason := replayPath(path, mine, base)
		if reason != "" {
			why = append(why, path+": "+reason)
			continue
		}
		out[path] = p
	}
	if len(unproved) == 0 && len(bad) == 0 && len(why) == 0 {
		return out, nil
	}
	sort.Strings(unproved)
	var parts []string
	if len(unproved) > 0 {
		parts = append(parts, fmt.Sprintf("no Write or Edit by %s in %s proves %s", runID, orUnknown(top),
			strings.Join(unproved, ", ")))
	}
	parts = append(parts, why...)
	parts = append(parts, bad...)
	return nil, fmt.Errorf("%s", strings.Join(parts, "; and "))
}

// replayPath replays one path's calls in chain order, and answers the bytes
// they left and the call that left them, or why those bytes cannot be known.
func replayPath(path string, ops []adoptOp, base func(string) ([]byte, bool)) (adoptedPath, string) {
	var cur []byte
	have := false
	if base != nil {
		cur, have = base(path)
	}
	reason, proof := "", ""
	for _, op := range ops {
		switch {
		case op.unknown != "":
			have, reason = false, op.unknown
		case op.edit == nil:
			cur, have, reason, proof = op.set, true, "", op.hash
		case !have:
			if reason == "" {
				reason = fmt.Sprintf("Edit %s edits bytes that neither an earlier call of the run "+
					"nor the parent commit holds", op.hash)
			}
		default:
			next, err := replayEdit(string(cur), op.edit.oldS, op.edit.newS, op.edit.all)
			if err != nil {
				have, reason = false, fmt.Sprintf("Edit %s cannot be replayed: %v", op.hash, err)
				continue
			}
			cur, proof = next, op.hash
		}
	}
	if !have {
		return adoptedPath{}, reason
	}
	return adoptedPath{Path: path, Bytes: cur,
		SHA256: strings.TrimPrefix(event.Digest(cur), event.HashPrefix), ToolCall: proof}, ""
}

// leftBy is the whole file one hook-shaped call left behind.
func leftBy(tool string, b adoptBody) ([]byte, error) {
	if tool == "Write" {
		return []byte(b.ToolInput.Content), nil
	}
	r := b.ToolResponse
	return replayEdit(r.OriginalFile, r.OldString, r.NewString, r.ReplaceAll)
}

// replayEdit is one Edit on the file it edited: its old string must occur,
// and exactly once unless it replaced all.
func replayEdit(original, oldS, newS string, all bool) ([]byte, error) {
	n := strings.Count(original, oldS)
	switch {
	case oldS == "" || n == 0:
		return nil, fmt.Errorf("its old string is not in the file it edited")
	case all:
		return []byte(strings.ReplaceAll(original, oldS, newS)), nil
	case n > 1:
		return nil, fmt.Errorf("its old string occurs %d times and it did not replace all", n)
	}
	return []byte(strings.Replace(original, oldS, newS, 1)), nil
}

// fieldString is one string member of an event, or "" when it is absent or
// not a string. Every member read here is a string in doc 02.
func fieldString(ev event.Fields, key string) string {
	v, ok := ev[key].(string)
	if !ok {
		return ""
	}
	return v
}

func orUnknown(top string) string {
	if top == "" {
		return "any checkout"
	}
	return top
}

// adoptionClaim is the claim a run_adopted's payload_digest names: what was
// handed over, path by path, and which tool call proved each part. It is
// stored as a body under the signing run, as a tool call's body is, because
// E4 keeps payloads out of events (ADR-0051 decision 3).
type adoptionClaim struct {
	AdoptedRunID string              `json:"adopted_run_id"`
	Paths        []adoptionClaimPath `json:"paths"`
}

type adoptionClaimPath struct {
	Path     string `json:"path"`
	SHA256   string `json:"sha256"`
	ToolCall string `json:"tool_call"`
}

// adoptionMarshal encodes the claim. A variable so the refusal for a claim
// that cannot be encoded is reachable from a test; for a struct of strings
// json.Marshal does not fail.
var adoptionMarshal = json.Marshal

// adoptionPlan is a proved adoption, ready to record.
type adoptionPlan struct {
	adoptedRun string
	state      string
	claim      []byte
	digest     string
}

// planAdoption is ADR-0051 decision 2: every check, before anything is
// recorded. A refusal here has appended nothing and written nothing.
func (c *signCommitService) planAdoption(ctx context.Context, runID, adopted, worktree string) (*adoptionPlan, error) {
	if c.adoption == nil {
		return nil, Errorf(ClassInvariantViolation, runID,
			"adopt_run is not configured on this deployment: it has no body volume to prove "+
				"a dead run's work against (ADR-0051)")
	}
	staged, err := c.adoption.StagedFiles(ctx, worktree)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, runID, "the staged files cannot be read: %v", err)
	}
	// An Edit the gateway recorded is replayed on HEAD's blob (ADR-0079
	// decision 4), when the evidence can read one.
	var base func(string) ([]byte, bool)
	if a := c.commitAdoption(); a != nil {
		base = func(path string) ([]byte, bool) {
			b, ok, berr := a.ParentFile(ctx, worktree, "HEAD", path)
			return b, ok && berr == nil
		}
	}
	return c.proveAdoption(ctx, runID, adopted, "", staged, base)
}

// refuseSpent is ADR-0051 decision 6: bytes of a path already adopted from
// this run and committed are spent. Only a COMMITTED adoption spends anything:
// one whose commit never landed failed, and the work is still there to adopt.
// A committed claim that cannot be read refuses, because what it spent cannot
// be known.
func (c *signCommitService) refuseSpent(ctx context.Context, runID, adopted string, claim adoptionClaim) error {
	prior, err := c.adoption.Adoptions(ctx, adopted)
	if err != nil {
		return Errorf(ClassLedgerUnavailable, runID,
			"the ledger could not say whether run %q's work was adopted before: %v", adopted, err)
	}
	for _, p := range prior {
		if !p.Committed {
			continue
		}
		raw, rerr := os.ReadFile(filepath.Join(c.adoption.BodyDir(), filepath.Base(p.RunID),
			strings.TrimPrefix(p.PayloadDigest, event.HashPrefix)+observeBodyExt))
		var spent adoptionClaim
		if rerr != nil || event.Digest(raw) != p.PayloadDigest || json.Unmarshal(raw, &spent) != nil {
			return Errorf(ClassInvariantViolation, runID,
				"run %q's work was adopted and committed by run %s (%s), and that claim cannot "+
					"be read, so what it spent cannot be known", adopted, p.RunID, p.EventID)
		}
		for _, was := range spent.Paths {
			for _, now := range claim.Paths {
				if was.Path == now.Path && was.SHA256 == now.SHA256 {
					return Errorf(ClassInvariantViolation, runID,
						"%s with these bytes was already adopted from run %q and committed by run "+
							"%s (%s); an adoption is spent by its commit (ADR-0051)",
						now.Path, adopted, p.RunID, p.EventID)
				}
			}
		}
	}
	return nil
}

// recordAdoption stores the claim and appends run_adopted under
// idempotencyKey, and returns its event id for the intent to carry.
func (c *signCommitService) recordAdoption(
	ctx context.Context, runID, spiffeID, idempotencyKey string, plan *adoptionPlan,
) (string, error) {
	if err := observeWriteBody(c.adoption.BodyDir(), runID, plan.digest, plan.claim); err != nil {
		return "", err
	}
	record, err := c.append(ctx, runID, event.EventTypeRunAdopted, event.Fields{
		event.FieldSchemaVersion:   event.SchemaVersion,
		event.FieldEventType:       event.EventTypeRunAdopted,
		event.FieldSource:          event.SourceMCP,
		event.FieldRunID:           runID,
		event.FieldSpiffeID:        spiffeID,
		event.FieldIdempotencyKey:  idempotencyKey,
		event.FieldAdoptedRunID:    plan.adoptedRun,
		event.FieldAdoptedRunState: plan.state,
		event.FieldPayloadDigest:   plan.digest,
	})
	if err != nil {
		return "", err
	}
	return signCommitEventID(runID, record)
}

// RunEvents is the ledger reads adoption needs: every event carrying a
// run_id, in chain order, and every earlier adoption of a run. *ledger.Store
// satisfies it.
type RunEvents interface {
	EventsForRun(ctx context.Context, runID string) ([]event.Fields, error)
	AdoptionsOf(ctx context.Context, adoptedRun string) ([]ledger.Adoption, error)
}

// LedgerAdoption is the shipped SignCommitAdoption: the run's state as every
// other tool reads it, its events from the ledger, and the staged bytes from
// the git index.
type LedgerAdoption struct {
	Runs         CredentialRuns
	Events       RunEvents
	Bodies       string
	AbandonAfter time.Duration
	// Candidates lists the ended runs a commit may adopt from (ADR-0079);
	// nil searches nothing, and the commit path then proposes no adoption.
	Candidates DeadRunLister
	// GitPath is the git binary; "" means `git` on PATH.
	GitPath string
	// Now is the clock the state is read at; nil is time.Now.
	Now func() time.Time
}

// AdoptionEvidence returns "" and nothing for a run the directory does not
// know, so planAdoption can answer RUN_NOT_FOUND by name.
func (a LedgerAdoption) AdoptionEvidence(ctx context.Context, runID string) (string, []event.Fields, error) {
	run, found, err := a.Runs.CredentialRun(ctx, runID)
	if err != nil {
		return "", nil, err
	}
	if !found {
		return "", nil, nil
	}
	events, err := a.Events.EventsForRun(ctx, runID)
	if err != nil {
		return "", nil, err
	}
	now := time.Now
	if a.Now != nil {
		now = a.Now
	}
	return run.State(now(), a.AbandonAfter), events, nil
}

// StagedFiles reads every staged path's bytes out of the index, byte for byte.
// A staged deletion or rename is refused: a dead run's bodies can prove bytes
// it left, never a path it removed.
func (a LedgerAdoption) StagedFiles(ctx context.Context, worktree string) (map[string][]byte, error) {
	g := GitRepos{GitPath: a.GitPath}
	removed, err := g.git(ctx, worktree, "diff", "--cached", "--name-only", "--diff-filter=DR")
	if err != nil {
		return nil, err
	}
	if removed != "" {
		return nil, fmt.Errorf("the index removes or renames %s; adoption proves bytes a run "+
			"left, never a path it took away", strings.ReplaceAll(removed, "\n", ", "))
	}
	names, err := g.StagedPaths(ctx, worktree)
	if err != nil {
		return nil, err
	}
	out := make(map[string][]byte, len(names))
	for _, name := range names {
		// The path is one git itself listed from this index, and `:<path>` is a
		// revision, never a flag.
		//nolint:gosec // G204: gitPath is configuration and the path came from git
		cmd := exec.CommandContext(ctx, gitOr(a.GitPath), "-C", worktree, "cat-file", "blob", ":"+name)
		cmd.Env = signCommitGitEnv(worktree)
		b, cerr := cmd.Output()
		if cerr != nil {
			return nil, fmt.Errorf("the staged bytes of %s cannot be read: %w", name, cerr)
		}
		out[name] = b
	}
	return out, nil
}

// Adoptions is the ledger's AdoptionsOf.
func (a LedgerAdoption) Adoptions(ctx context.Context, adoptedRun string) ([]ledger.Adoption, error) {
	return a.Events.AdoptionsOf(ctx, adoptedRun)
}

// BodyDir is the body volume.
func (a LedgerAdoption) BodyDir() string { return a.Bodies }

func gitOr(path string) string {
	if path == "" {
		return "git"
	}
	return path
}
