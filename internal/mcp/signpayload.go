// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"errors"
	"fmt"
	"strconv"
	"strings"
	"sync"
	"time"

	"innsegl.dev/innsegl/internal/commitpath"
	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/signing"
)

// signpayload.go — RM-241 (#386), ADR-0059 decision 4: the gates and phases
// of the commit-sign path, as ONE in-process call.
//
// # This is not a sixth MCP tool
//
// ADR-0059 decision 8 is explicit: `gpg.x509.program` is git's own contract,
// answered by the core; it is not a new or renamed MCP tool, and it defines
// no new error-class vocabulary. So this file registers nothing with
// RegisterTool/Bind (tools.go) — it follows gateway.go's exported-wrapper
// pattern instead: SignPayloadForGateway is a thin, in-process seam that
// cmd/innsegl's HTTP handler (commitsign.go, not this package) calls
// directly, the same way RegisterRunForGateway reaches register_agent's own
// configured path without a second implementation of any of its rules.
//
// # What is reused, and what is new
//
// Everything decision 4 shares with `sign_commit` — the ledger, the run
// directory, the credential path (get_credential, through
// SignCommitThroughGetCredential), the I6 author policy, the signer's own
// Fulcio/Rekor/issuer configuration — is `sign_commit`'s OWN configured
// service (ConfigureSignCommit, sign_commit.go), read directly from package
// state below rather than duplicated. This file adds exactly the two
// dependencies decision 4 needs that `sign_commit` has no use for: the
// resolver gate 1 checks a tool call id against (commitpath.Resolve's own
// dependency), and the function that says what a run may CLAIM its commit's
// trailers say (ClaimFor — built by the gateway's own wiring, not here).
//
// # The gates, in order, and why nothing runs before gate 1
//
// commitpath.Resolve (gate 1) is ADR-0059's whole reason to exist: it proves
// the payload now arriving is for a `git commit` this deployment's traffic
// relay actually saw, bound to a run, inside a bounded window — the
// authorisation precondition decision 1's environment injection exists to
// satisfy. Everything after it — parsing the payload, checking its trailers,
// checking its author and committer, fetching a credential — is worthless to
// do first, because none of it says WHO is asking.
type signPayloadState struct {
	resolver commitpath.Resolver
	claimFor func(ctx context.Context, runID string) (signing.Claim, error)
	now      func() time.Time
	// sign is Phase B's signing step: the signer's own SignPayload. Only a
	// test replaces it, so Phases B and C are reachable without Sigstore.
	sign func(ctx context.Context, s *signing.Signer, req signing.PayloadRequest) (signing.PayloadResult, error)
}

func signWithSigner(ctx context.Context, s *signing.Signer, req signing.PayloadRequest) (signing.PayloadResult, error) {
	return s.SignPayload(ctx, req)
}

// SignPayloadConfig carries the two dependencies ADR-0059 decision 4 needs
// beyond sign_commit's own configured service (ConfigureSignCommit).
type SignPayloadConfig struct {
	// Resolver finds a relayed, still-pending `git commit` tool call by its
	// id — commitpath.Resolve's own dependency (gate 1).
	Resolver commitpath.Resolver
	// ClaimFor returns what a run may claim its commit's trailers say: the
	// identical construction sign_commit's own phases() makes
	// (signing.Claim{Identity: spiffeID, Run: run.RunID, Task: claimedTask}),
	// built by the gateway's own wiring and taken here as a dependency rather
	// than re-derived, so there is exactly one place that decides what a run
	// may claim.
	ClaimFor func(ctx context.Context, runID string) (signing.Claim, error)
	// Now defaults to time.Now. Substitutable so a test can put a relayed
	// call outside commitpath.Window without a real wait.
	Now func() time.Time
}

var (
	signPayloadMu  sync.RWMutex
	signPayloadCfg *signPayloadState
)

// ConfigureSignPayload installs SignPayloadConfig and returns a function
// restoring whatever was installed before.
//
// Every dependency is required, on newSignCommitService's own reasoning: a
// missing one is a gate left silently unchecked rather than a degraded mode.
func ConfigureSignPayload(cfg SignPayloadConfig) (func(), error) {
	refuse := func(detail string) (func(), error) {
		return nil, Errorf(ClassInvariantViolation, "", "commit-sign path configuration: %s", detail)
	}
	switch {
	case cfg.Resolver == nil:
		return refuse("no resolver: gate 1 (ADR-0059 decision 4) has nothing to check a tool call id against")
	case cfg.ClaimFor == nil:
		return refuse("no claim function: gate 2 has nothing to compare a payload's trailers against")
	}
	now := cfg.Now
	if now == nil {
		now = time.Now
	}
	st := &signPayloadState{resolver: cfg.Resolver, claimFor: cfg.ClaimFor, now: now, sign: signWithSigner}

	signPayloadMu.Lock()
	defer signPayloadMu.Unlock()
	previous := signPayloadCfg
	signPayloadCfg = st
	return func() {
		signPayloadMu.Lock()
		defer signPayloadMu.Unlock()
		signPayloadCfg = previous
	}, nil
}

// SignPayloadForGateway is ADR-0059 decision 4's one call: the gates, then
// Phase A, Phase B, Phase C, in IP §6.5's order. cmd/innsegl/commitsign.go's
// HTTP handler calls this directly; nothing else in this package does.
//
// shape sign_commit.go's own phases carries and the same reason: splitting it
// would hide the order, which is the one thing this function exists to get
// right (IP §6.5, ADR-0059 decision 4).
//
//nolint:gocyclo // One gate per step, each with its own refusal — the same
func SignPayloadForGateway(
	ctx context.Context, req commitpath.SignRequest,
) (commitpath.SignResponse, error) {
	signPayloadMu.RLock()
	cfg := signPayloadCfg
	signPayloadMu.RUnlock()
	if cfg == nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, "",
			"the commit-sign path is not configured; no payload is signed rather than "+
				"one signed with a gate silently unchecked")
	}

	signCommitMu.RLock()
	svc := signCommitActive
	signCommitMu.RUnlock()
	if svc == nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, "",
			"sign_commit is not configured; the commit-sign path shares its ledger, "+
				"credential and signer dependencies and has none of its own")
	}

	// ---- gate 1: the tool call this payload claims to be for --------------
	//
	// commitpath.Resolve is the shared contract both the trailers endpoint
	// and this one call — a stale, forged or missing id is refused here,
	// before anything else about the payload is even read.
	relayed, err := commitpath.Resolve(cfg.resolver, req.ToolUseID, cfg.now())
	if err != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, "", "%w", err)
	}
	runID := relayed.RunID

	// ---- gate 2: the payload's own trailers, against what this run may claim
	parsed, err := signing.ParseCommitPayload(req.Payload)
	if err != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID, "%w", err)
	}
	claim, err := cfg.claimFor(ctx, runID)
	if err != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"no claim for run %s: %v", runID, err)
	}
	wantTrailers, err := claim.Trailers()
	if err != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID, "%w", err)
	}
	if !messageCarriesTrailers(parsed.Message, wantTrailers) {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"the payload's message does not carry the trailers rendered for this tool "+
				"call's run; a payload whose claim disagrees with step 2's render is "+
				"refused before Phase A (ADR-0028 decision 4's agreement rule, checked "+
				"against a payload instead of built by hand)")
	}

	// ---- gate 3: I6, on the payload's own author and committer ------------
	//
	// AuthorPolicy.CheckAuthor, unchanged in what it checks: sign_commit's
	// own configured signer factory is asked, exactly as sign_commit asks it
	// at configuration time (Admits) — one statement of who may author a
	// commit in this deployment.
	if aerr := svc.signers.Admits(parsed.AuthorEmail); aerr != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"author %q is not admitted (I6): %w", parsed.AuthorEmail, aerr)
	}
	if aerr := svc.signers.Admits(parsed.CommitterEmail); aerr != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"committer %q is not admitted (I6): %w", parsed.CommitterEmail, aerr)
	}

	// ---- gate 4: the run, its working tree, and its credential ------------
	//
	// `repo` is not an argument on this wire at all (unlike sign_commit's
	// own). It is the one fact ADR-0046 mechanism 1 already establishes once
	// per session, carried on the run's own registration and reused here
	// rather than asked again — ADR-0059's Consequences, in as many words.
	run, _, err := svc.resolveRun(ctx, runID)
	if err != nil {
		return commitpath.SignResponse{}, err
	}
	if run.Repo == "" {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"run %s carries no repository; the commit-sign path resolves one only from "+
				"the run's own registration and has no argument of its own to fall back to",
			runID)
	}
	// The agent's own checkout when its request stated one: a commit made
	// by the harness's git has its objects there, not in the core's
	// workspace (ADR-0059: the harness runs git commit). A caller with no
	// stated directory falls back to the workspace sign_commit uses.
	var worktree string
	if relayed.WorkingDirectory != "" {
		worktree, err = commitPathWorktree(ctx, relayed.WorkingDirectory, run.Repo)
	} else {
		worktree, err = svc.workspace.Worktree(ctx, run.Repo)
	}
	if err != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"no working tree for %s: %v", run.Repo, err)
	}

	// The credential comes through the identical path sign_commit uses
	// (get_credential, ADR-0019/0033), primed before Phase A exactly as
	// sign_commit primes it — IP §6.1: any in-flight signing aborts before
	// Phase A when the credential cannot be had.
	// The run's own token (RM-212), derived here: no caller holds it on this
	// path, and the relayed tool call already authorised the commit (gate 1).
	runToken := RunToken(svc.runSecret, runID)
	src := &signCommitSource{run: run, issue: func(ctx context.Context, r CredentialRun) (signing.Credential, error) {
		return svc.credentials.IssueForSigning(ctx, r, runToken)
	}}
	if perr := src.prime(ctx); perr != nil {
		return commitpath.SignResponse{}, perr
	}

	// ---- Phase A ------------------------------------------------------------
	//
	// The tree hash is read directly out of the payload's own `tree` line
	// (ADR-0059 decision 4): the payload IS the unsigned commit object the
	// harness's own git already built, so there is nothing to derive
	// independently and nothing for it to disagree with. The patch id is the
	// one fact the payload alone cannot supply — see commitPathPatchID.
	patchID, perr := commitPathPatchID(ctx, worktree, parsed.Tree, parsed.Parents)
	if perr != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"the change %s claims cannot be identified: %v", parsed.Tree, perr)
	}
	intent, err := svc.append(ctx, runID, event.EventTypeCommitIntent, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       claim.Identity,
		event.FieldIdempotencyKey: commitPathPhaseKey(commitPathIntentKeyPrefix, req.ToolUseID, req.Payload),
		event.FieldRepo:           run.Repo,
		event.FieldTreeHash:       parsed.Tree,
		event.FieldPatchID:        patchID,
	})
	if err != nil {
		return commitpath.SignResponse{}, err
	}
	intentID, err := signCommitEventID(runID, intent)
	if err != nil {
		return commitpath.SignResponse{}, err
	}

	// ---- Phase B ------------------------------------------------------------
	//
	// gitsign runs INSIDE the core, with ADR-0031's discipline unchanged —
	// signing.SignPayload holds it. The signer factory here has to be the
	// shipped one: only it carries the Fulcio/Rekor/issuer configuration
	// Phase B needs, and sign_commit's own SignCommitSigner interface has no
	// SignPayload method to widen for this one caller (a fake bound to that
	// interface elsewhere in this package would need to grow one it has no
	// use for). NewGitsignSigners is the only production value of this type,
	// so this is additive to what is already wired, not a second wiring.
	gs, ok := svc.signers.(gitsignSigners)
	if !ok {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"the configured signer factory does not support the commit-sign path "+
				"(ADR-0059 decision 4 Phase B); only the shipped gitsign wrapper does")
	}
	signer, err := signing.NewSigner(gs.cfg, src)
	if err != nil {
		return commitpath.SignResponse{}, Errorf(ClassInvariantViolation, runID,
			"no signer for run %s: %v", runID, err)
	}
	defer func() { _ = signer.Close() }()

	result, err := cfg.sign(ctx, signer, signing.PayloadRequest{
		Args: req.Args, Payload: req.Payload, Claim: claim,
	})
	if err != nil {
		return commitpath.SignResponse{}, svc.signingError(ctx, runID, err)
	}

	// ---- Phase C ------------------------------------------------------------
	//
	// Signed is recorded; landed is observed; the two are never conflated
	// (ADR-0059 decision 6) — this append states only that Phase B's content
	// was signed under this run's identity, with this Rekor entry.
	if _, err := svc.append(ctx, runID, event.EventTypeCommitRecorded, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          runID,
		event.FieldSpiffeID:       claim.Identity,
		event.FieldIdempotencyKey: commitPathPhaseKey(commitPathRecordedKeyPrefix, req.ToolUseID, req.Payload),
		event.FieldRepo:           run.Repo,
		event.FieldCommitSHA:      result.CommitSHA,
		event.FieldTreeHash:       parsed.Tree,
		event.FieldPatchID:        patchID,
		event.FieldRekorLogIndex:  result.Rekor.LogIndex,
		event.FieldRekorEntryUUID: result.Rekor.UUID,
		event.FieldIntentEventID:  intentID,
	}); err != nil {
		return commitpath.SignResponse{}, err
	}

	return commitpath.SignResponse{Signature: result.Signature, Status: result.Status}, nil
}

// messageCarriesTrailers reports whether message's tail is exactly want,
// rendered — the "trailers read back out of the payload's own message"
// ADR-0059 decision 4 gate 2 asks for.
//
// ADR-0028's own placement rule (decision 2) makes this simple rather than a
// second trailer parser: the three (or four, with an adoption) trailers this
// deployment renders are ALWAYS the tail of the message — either they open
// their own final paragraph, or they join an existing one with no blank
// line — so "the last len(want) lines equal want, verbatim" is the
// placement rule read backwards, not a second implementation of it.
// want is never empty in practice — signing.Claim.Trailers() returns at
// least Agent-Identity/-Run/-Task on every success, and its error is
// checked before this is ever called — so no separate zero-length case is
// carried here: ADR-0033 decision 3's rule, "a check that can never fire is
// a check nobody can test," applied to this file. An empty want falls
// through the ordinary path and reports true (the message's tail vacuously
// carries zero required trailers), which no caller can reach either way.
func messageCarriesTrailers(message string, want []signing.Trailer) bool {
	lines := strings.Split(strings.TrimSuffix(message, "\n"), "\n")
	if len(lines) < len(want) {
		return false
	}
	tail := lines[len(lines)-len(want):]
	for i, t := range want {
		if tail[i] != t.String() {
			return false
		}
	}
	return true
}

// emptyTreeHash is git's own well-known SHA-1 for an empty tree — sha1 of a
// zero-length tree object. Diffing against it is exactly what `git commit
// --root` does internally for a root commit; used here because Phase A/C
// have no commit object to diff-tree with `--root` against (see
// commitPathPatchID).
const emptyTreeHash = "4b825dc642cb6eb9a060e54bf8d69288fbee4904"

// commitPathPatchID is ADR-0047's change identity, computed the one way
// available here: the payload's own tree against its first parent's — or
// against the empty tree for a root commit — never against an already
// existing commit object, because none exists yet at either phase in this
// flow (ADR-0059 decision 4 Phase A/C both run before git has written one).
//
// A merge's later parents are dropped for GitRepos.CommitPatchID's own
// reason (patchid.go): `diff-tree -p` of a merge against every parent but
// the first prints nothing for an ordinary merge, and Phase A already asks
// about the first-parent change only.
//
// `patchIDOf` is GitRepos's own (patchid.go) — reused rather than
// reimplemented, on the same reasoning ADR-0059's Consequences give for
// reusing `repo`: a second patch-id pipeline is a second thing that could
// disagree with sign_commit's about what a change's identity is.
func commitPathPatchID(ctx context.Context, worktree, tree string, parents []string) (string, error) {
	against := emptyTreeHash
	if len(parents) > 0 {
		against = parents[0]
	}
	return GitRepos{}.patchIDOf(ctx, worktree,
		[]string{"diff-tree", "-p", "--no-color", "--no-ext-diff", against, tree})
}

// The commit-sign path's two derived ledger keys, namespaced exactly as
// sign_commit's own (sign_commit.go) — a caller's key spent verbatim would
// collide with another tool's use of the same string (force 4, ADR-0033
// decision 5) — but keyed on the TOOL CALL ID and the PAYLOAD rather than a
// caller-supplied idempotency_key, because commitpath.SignRequest carries no
// such argument. The tool call id alone is not enough: one Bash call can
// make more than one commit (an amend, a retry after losing git's ref lock),
// each its own signature needing its own events. The same payload under the
// same tool call replays onto the same events.
const (
	commitPathIntentKeyPrefix   = "commit_sign_payload/intent/"
	commitPathRecordedKeyPrefix = "commit_sign_payload/recorded/"
)

func commitPathPhaseKey(prefix, toolUseID string, payload []byte) string {
	payloadDigest := event.Digest(payload)
	digest := strings.TrimPrefix(event.Digest([]byte(strconv.Quote(toolUseID)+"\n"+payloadDigest)), event.HashPrefix)
	return prefix + digest[:signCommitKeyHexDigits]
}

// commitPathWorktree returns workingDirectory once it is proven to be the
// run's own repository: the harness states the directory, so it is a claim,
// and the objects a patch-id is computed from are read only from a checkout
// whose origin names the repository the run was registered in.
func commitPathWorktree(ctx context.Context, workingDirectory, repo string) (string, error) {
	if workingDirectory == "" {
		return "", errors.New("the relayed tool call stated no working directory")
	}
	id, err := repoIDFromWorktree(ctx, workingDirectory)
	if err != nil {
		return "", fmt.Errorf("%s is not a repository the core can read: %w", workingDirectory, err)
	}
	if id != repo {
		return "", fmt.Errorf("%s is %s, not the run's repository %s", workingDirectory, id, repo)
	}
	return workingDirectory, nil
}
