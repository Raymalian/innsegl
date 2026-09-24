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

// adoptBody is the part of a stored tool-call body the proof reads.
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
}

// rebuildLeftBytes returns, for every staged path, the bytes runID's last
// Write or Edit left there, or an error naming what could not be proved.
func rebuildLeftBytes(events []event.Fields, bodyDir, runID string, staged []string) (map[string]adoptedPath, error) {
	type call struct {
		file  string
		bytes []byte
		hash  string
	}
	var calls []call
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
		var b adoptBody
		if err = json.Unmarshal(raw, &b); err != nil {
			bad = append(bad, fmt.Sprintf("the body of %s %s is not a tool call", tool, hash))
			continue
		}
		left, err := leftBy(tool, b)
		if err != nil {
			bad = append(bad, fmt.Sprintf("%s %s on %s cannot be replayed: %v", tool, hash, b.ToolInput.FilePath, err))
			continue
		}
		calls = append(calls, call{file: b.ToolInput.FilePath, bytes: left, hash: hash})
	}

	out := make(map[string]adoptedPath, len(staged))
	top := ""
	var unproved []string
	for _, path := range staged {
		found := false
		for i := len(calls) - 1; i >= 0; i-- {
			c := calls[i]
			if !strings.HasSuffix(c.file, "/"+path) {
				continue
			}
			here := strings.TrimSuffix(c.file, "/"+path)
			if top == "" {
				top = here
			}
			if here != top {
				continue
			}
			out[path] = adoptedPath{Path: path, Bytes: c.bytes,
				SHA256: strings.TrimPrefix(event.Digest(c.bytes), event.HashPrefix), ToolCall: c.hash}
			found = true
			break
		}
		if !found {
			unproved = append(unproved, path)
		}
	}
	if len(unproved) == 0 && len(bad) == 0 {
		return out, nil
	}
	sort.Strings(unproved)
	msg := ""
	if len(unproved) > 0 {
		msg = fmt.Sprintf("no Write or Edit by %s in %s proves %s", runID, orUnknown(top),
			strings.Join(unproved, ", "))
	}
	if len(bad) > 0 {
		if msg != "" {
			msg += "; and "
		}
		msg += strings.Join(bad, "; ")
	}
	return nil, fmt.Errorf("%s", msg)
}

// leftBy is the whole file one call left behind.
func leftBy(tool string, b adoptBody) ([]byte, error) {
	if tool == "Write" {
		return []byte(b.ToolInput.Content), nil
	}
	r := b.ToolResponse
	n := strings.Count(r.OriginalFile, r.OldString)
	switch {
	case r.OldString == "" || n == 0:
		return nil, fmt.Errorf("its old string is not in the file it edited")
	case r.ReplaceAll:
		return []byte(strings.ReplaceAll(r.OriginalFile, r.OldString, r.NewString)), nil
	case n > 1:
		return nil, fmt.Errorf("its old string occurs %d times and it did not replace all", n)
	}
	return []byte(strings.Replace(r.OriginalFile, r.OldString, r.NewString, 1)), nil
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
	state, events, err := c.adoption.AdoptionEvidence(ctx, adopted)
	if err != nil {
		return nil, Errorf(ClassLedgerUnavailable, runID,
			"the ledger could not say how run %q ended or what it wrote: %v", adopted, err)
	}
	switch state {
	case "":
		return nil, Errorf(ClassRunNotFound, runID, "no run %q to adopt", adopted)
	case "retired", "lapsed", "abandoned":
	default:
		return nil, Errorf(ClassInvariantViolation, runID,
			"run %q is %s in the ledger; a run that may still be working is not dead, and its "+
				"work is not this run's to adopt (ADR-0051)", adopted, state)
	}

	staged, err := c.adoption.StagedFiles(ctx, worktree)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, runID, "the staged files cannot be read: %v", err)
	}
	if len(staged) == 0 {
		return nil, Errorf(ClassInvariantViolation, runID, "nothing is staged, so there is nothing to adopt")
	}
	names := make([]string, 0, len(staged))
	for name := range staged {
		names = append(names, name)
	}
	sort.Strings(names)

	proofs, err := rebuildLeftBytes(events, c.adoption.BodyDir(), adopted, names)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, runID, "run %q's work cannot be adopted: %v", adopted, err)
	}
	claim := adoptionClaim{AdoptedRunID: adopted}
	for _, name := range names {
		p := proofs[name]
		if got := strings.TrimPrefix(event.Digest(staged[name]), event.HashPrefix); got != p.SHA256 {
			return nil, Errorf(ClassInvariantViolation, runID,
				"%s is staged with bytes run %q did not leave: its last Write or Edit (%s) left "+
					"sha256 %s, and the index holds %s. Commit that change as this run's own work",
				name, adopted, p.ToolCall, p.SHA256, got)
		}
		claim.Paths = append(claim.Paths, adoptionClaimPath{Path: name, SHA256: p.SHA256, ToolCall: p.ToolCall})
	}
	body, err := adoptionMarshal(claim)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, runID, "the adoption claim cannot be encoded: %v", err)
	}
	return &adoptionPlan{adoptedRun: adopted, state: state, claim: body, digest: event.Digest(body)}, nil
}

// recordAdoption stores the claim and appends run_adopted, and returns its
// event id for the intent to carry.
func (c *signCommitService) recordAdoption(
	ctx context.Context, runID, spiffeID, key string, plan *adoptionPlan,
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
		event.FieldIdempotencyKey:  signCommitPhaseKey(signCommitAdoptedKeyPrefix, key),
		event.FieldAdoptedRunID:    plan.adoptedRun,
		event.FieldAdoptedRunState: plan.state,
		event.FieldPayloadDigest:   plan.digest,
	})
	if err != nil {
		return "", err
	}
	return signCommitEventID(runID, record)
}

// RunEvents is the one ledger read adoption needs: every event carrying a
// run_id, in chain order. *ledger.Store satisfies it.
type RunEvents interface {
	EventsForRun(ctx context.Context, runID string) ([]event.Fields, error)
}

// LedgerAdoption is the shipped SignCommitAdoption: the run's state as every
// other tool reads it, its events from the ledger, and the staged bytes from
// the git index.
type LedgerAdoption struct {
	Runs         CredentialRuns
	Events       RunEvents
	Bodies       string
	AbandonAfter time.Duration
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

// BodyDir is the body volume.
func (a LedgerAdoption) BodyDir() string { return a.Bodies }

func gitOr(path string) string {
	if path == "" {
		return "git"
	}
	return path
}
