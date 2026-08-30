// SPDX-License-Identifier: Apache-2.0

package mcp

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"sync"
	"time"

	sdk "github.com/modelcontextprotocol/go-sdk/mcp"

	"innsegl.dev/innsegl/internal/event"
	"innsegl.dev/innsegl/internal/signing"
)

// sign_commit — RM-033 (#41), IP §4:
//
//	sign_commit(run_id, repo, staged_ref, message, task_ref, idempotency_key) →
//	    {commit_sha, rekor_entry, trailers}. Implements the two-phase protocol
//	    in 6.5.
//
// # The single most dangerous window, and the shape of the protocol that bounds it
//
// IP §6.5 names it: a commit signed but not recorded, or recorded but not
// signed. Nothing in this system can make that window disappear — a signature
// lives in Rekor and a record lives in Postgres, and there is no transaction
// across them. What a protocol can do is choose WHICH side the window falls
// on, make it narrow, and make what is left behind recoverable. That protocol
// is three phases and they never reorder:
//
//	Phase A   append `commit_intent` (run, repo, tree hash) — BEFORE any signing
//	Phase B   sign via gitsign — Fulcio and Rekor happen here, as one operation
//	Phase C   append `commit_recorded` (commit SHA, Rekor entry) referencing A
//
// An intent with no signature is RECOVERABLE: RM-035's reconciler expires it
// and appends `commit_intent_expired`. A signature with no intent is DRIFT:
// RM-036 raises `unattributed_signature_detected`, which is either a bug or a
// compromise. The whole asymmetry is why Phase A comes first, and it is the
// same rule ADR-0018 chose for register_agent — the ledger is written before
// the world changes state, in every direction.
//
// # The two windows, named exactly
//
// BETWEEN A AND B a `commit_intent` exists and no signature does. It is
// reached by: a crash after the append; Fulcio or Rekor dying between the
// reachability probe and `git commit`; gitsign or git refusing; the author
// gate refusing inside the wrapper. Nothing here is repaired by this tool —
// REC-001 is the reconciler expiring the intent after a bounded window.
//
// BETWEEN B AND C a commit object exists, Rekor holds its entry, and no
// `commit_recorded` does. It is reached by: a crash after `git commit`
// returns; the ledger being unreachable at Phase C; the read-back checks
// refusing the result. REC-002 is the reconciler matching the Rekor entry to
// the intent and appending the missing `commit_recorded` with
// `source: reconciler`.
//
// Both are narrow BY ORDERING and not by cleanup. Everything that can fail
// cheaply — the request, the run, the working tree, the staged tree, Sigstore's
// reachability, the credential, the signer itself — happens before Phase A. The
// only thing after Phase B is one append.
//
// A REPLAY THAT LANDS IN THE SECOND WINDOW IS REFUSED, LOUDLY, AND DOES NOT
// SIGN AGAIN. ADR-0017 takes over a claim whose lease ran out and runs the tool
// a second time; if the first execution had already committed, the index is now
// identical to HEAD, `StagedTree` refuses before Phase A, and the caller is told
// that the repair belongs to the reconciler. That is deliberate: this tool
// cannot repair the window itself, because recovering the Rekor entry for an
// existing commit is a Rekor SEARCH, and internal/signing keeps that unexported
// (ADR-0031 decision 6). Making it exported is RM-035's to do, and RM-035 is the
// component IP §6.5 assigns the repair to.
//
// # Where the credential comes from, and why not from SPIRE directly
//
// IP §6.1: "spire-agent socket lost mid-run at `get_credential` →
// IDENTITY_UNAVAILABLE; any in-flight `sign_commit` aborts BEFORE Phase A."
// So the credential is obtained before the intent is appended, and it is
// obtained THROUGH get_credential — the shipped tool, with its four gates and
// its `credential_issued` append — rather than through a second path to SPIRE.
// A second path would be a second thing that could disagree about retirement,
// a second place I3's record of an issuance could be skipped, and a second
// audience allowlist. See SignCommitThroughGetCredential.
//
// # What this file does not contain
//
// No signing. internal/signing (RM-032, ADR-0031) holds the whole of it: the
// credential goes in as SIGSTORE_ID_TOKEN, a released `gitsign` produces the
// certificate, the commit and the Rekor entry, and the ephemeral private key
// never crosses the boundary (E8). This file orchestrates and records.

func init() { RegisterTool(ToolSignCommit, bindSignCommit) }

// ---------------------------------------------------------------------------
// The wire contract (MCP-004).
// ---------------------------------------------------------------------------

// signCommitIn is IP §4's argument list, verbatim.
type signCommitIn struct {
	// RunID is the run the commit is attributed to.
	RunID string `json:"run_id"`
	// Repo is doc 02 §5's `host/org/name`, which is what the event carries. It
	// is NOT a filesystem path: the working tree is resolved from it by the
	// configured workspace, so a caller cannot name a directory the deployment
	// did not publish.
	Repo string `json:"repo"`
	// StagedRef names the tree the caller staged, as a git revision. It is
	// resolved to a tree and required to equal the repository's own index, so
	// the tree Phase A records is the tree Phase B signs.
	StagedRef string `json:"staged_ref"`
	// Message is the commit message before trailers. It never reaches the
	// ledger: doc 02 §3's `commit_intent` and `commit_recorded` have no member
	// for it, which is IP E4 made mechanical.
	Message string `json:"message"`
	// TaskRef is the caller's task reference. It becomes the `Agent-Task`
	// trailer and must lowercase to the task segment of the run's SPIFFE ID.
	TaskRef string `json:"task_ref"`
	// IdempotencyKey makes the call repeatable (IP §6.6, ADR-0004).
	IdempotencyKey string `json:"idempotency_key"`
}

// SignCommitTrailer is one rendered commit trailer.
//
// A key/value pair rather than the rendered `Key: value` line: the three keys
// are protected strings and a consumer switches on them, which it cannot do
// without splitting a string on a separator this schema would then have to
// promise never to change.
type SignCommitTrailer struct {
	Key   string `json:"key"`
	Value string `json:"value"`
}

// SignCommitRekorEntry is IP §4's `rekor_entry`.
//
// `uuid` and `log_index` are the two members doc 02 §3 requires of
// `commit_recorded`, so the reply and the record name the entry the same way.
// `log_id` and `integrated_at` are the log's own answer, carried so a caller
// can fetch the inclusion proof without first asking this server again.
type SignCommitRekorEntry struct {
	UUID     string `json:"uuid"`
	LogIndex int64  `json:"log_index"`
	LogID    string `json:"log_id"`
	// IntegratedAt is doc 02 §1's timestamp form, the same spelling every
	// other instant on this wire uses.
	IntegratedAt string `json:"integrated_at"`
}

// signCommitOut is IP §4's result shape, verbatim.
type signCommitOut struct {
	CommitSHA  string               `json:"commit_sha"`
	RekorEntry SignCommitRekorEntry `json:"rekor_entry"`
	Trailers   []SignCommitTrailer  `json:"trailers"`
}

// ---------------------------------------------------------------------------
// Dependencies.
// ---------------------------------------------------------------------------

// SignCommitLedger is the ledger surface this tool needs. *ledger.Store
// satisfies it.
type SignCommitLedger interface {
	// Append writes one event; an append whose idempotency_key has already
	// been used returns the original event and writes nothing (LED-008).
	Append(ctx context.Context, body event.Fields) (event.Fields, error)
}

// SignCommitWorkspace resolves doc 02 §5's `host/org/name` to the working tree
// this deployment holds for it. *Workspace is the shipped implementation.
//
// The indirection is the security boundary: `repo` is an identifier in an
// append-only record, and a tool that took a filesystem path would let a
// caller name any directory the server process can read.
type SignCommitWorkspace interface {
	Worktree(ctx context.Context, repo string) (string, error)
}

// SignCommitRepos reads git plumbing. GitRepos is the shipped implementation.
type SignCommitRepos interface {
	// StagedTree returns the tree that will be committed, having checked that
	// stagedRef names it and that it is not already the tree at HEAD.
	StagedTree(ctx context.Context, worktree, stagedRef string) (string, error)
	// CommitTree returns the tree of one commit.
	CommitTree(ctx context.Context, worktree, commit string) (string, error)
}

// SignCommitCredentials issues the audience-bound credential one signature is
// spent on. SignCommitThroughGetCredential is the shipped implementation.
type SignCommitCredentials interface {
	IssueForSigning(ctx context.Context, run CredentialRun) (signing.Credential, error)
}

// SignCommitSigner is one run's gitsign wrapper. *signing.Signer satisfies it.
type SignCommitSigner interface {
	Sign(ctx context.Context, req signing.Request) (signing.Result, error)
	Close() error
}

// SignCommitSigners opens a signer bound to one run's credential source.
type SignCommitSigners interface {
	// Admits reports whether the I6 author policy behind this factory admits
	// email as a commit author. It is asked at CONFIGURATION time so that a
	// deployment whose policy does not admit its own author refuses to start,
	// rather than leaving a dangling `commit_intent` on its first signature.
	Admits(email string) error
	// Open returns a signer for one run. The caller closes it.
	Open(src signing.CredentialSource) (SignCommitSigner, error)
}

// The production implementations must satisfy the interfaces above, or the
// fakes the contract tests use would be free to drift from what this tool will
// actually be handed.
var (
	_ SignCommitWorkspace   = (*Workspace)(nil)
	_ SignCommitRepos       = GitRepos{}
	_ SignCommitCredentials = SignCommitThroughGetCredential{}
	_ SignCommitSigner      = (*signing.Signer)(nil)
)

// SignCommitConfig is what sign_commit runs on. Install it with
// ConfigureSignCommit before serving.
type SignCommitConfig struct {
	// Runs resolves run_id. Required, and get_credential's interface rather
	// than a second one: a second definition of "what is a run" is a second
	// thing that can disagree about retirement.
	Runs CredentialRuns
	// Ledger is the append-only event store. Required — I3 admits no action
	// without a record, and this tool's action is the most consequential one
	// the system performs.
	Ledger SignCommitLedger
	// Idempotency records the reply of each keyed call (ADR-0017). Required: a
	// replay that re-executed would sign a second commit (IP §6.6).
	Idempotency *IdempotencyStore
	// Workspace resolves `repo` to a working tree. Required.
	Workspace SignCommitWorkspace
	// Repos reads git plumbing. Nil means GitRepos.
	Repos SignCommitRepos
	// Sigstore is ADR-0024's reachability probe, asked before Phase A so that
	// an outage already visible does not leave a dangling intent. Required.
	Sigstore HealthSigstore
	// Credentials issues the credential. Required.
	Credentials SignCommitCredentials
	// Signers opens the gitsign wrapper. Required.
	Signers SignCommitSigners
	// AuthorName and AuthorEmail are the commit's author AND committer. I6
	// constrains them and Signers.Admits gates them at start-up.
	AuthorName  string
	AuthorEmail string
}

// signCommitService is the configured tool.
type signCommitService struct {
	runs        CredentialRuns
	ledger      SignCommitLedger
	idem        *IdempotencyStore
	workspace   SignCommitWorkspace
	repos       SignCommitRepos
	sigstore    HealthSigstore
	credentials SignCommitCredentials
	signers     SignCommitSigners
	authorName  string
	authorEmail string
}

// newSignCommitService checks the configuration and returns the tool.
//
// Every dependency is required because every one of them is a gate, and a
// missing gate is an open door rather than a degraded mode. The author check
// is here rather than per-call for the reason above: an I6 refusal must not be
// something a deployment discovers by leaving an intent behind.
func newSignCommitService(cfg SignCommitConfig) (*signCommitService, error) {
	refuse := func(detail string) (*signCommitService, error) {
		return nil, Errorf(ClassInvariantViolation, "", "sign_commit configuration: %s", detail)
	}
	switch {
	case cfg.Runs == nil:
		return refuse("no run directory: sign_commit cannot say which identity a commit is attributed to (I2)")
	case cfg.Ledger == nil:
		return refuse("no ledger: I3 admits no action without a record, and there would be nowhere to put the intent (IP §6.5)")
	case cfg.Idempotency == nil:
		return refuse("no idempotency store: a replay could sign a second commit (IP §6.6, ADR-0017)")
	case cfg.Workspace == nil:
		return refuse("no workspace: there is no working tree to sign in, and `repo` is an identifier rather than a path")
	case cfg.Sigstore == nil:
		return refuse("no Sigstore probe: an outage would be discovered only after the intent was appended (IP §6.3)")
	case cfg.Credentials == nil:
		return refuse("no credential source: I2 admits no signing without a credential for this run")
	case cfg.Signers == nil:
		return refuse("no signer factory: there is nothing to sign with")
	case cfg.AuthorName == "":
		return refuse("no author name: a commit's author line is part of the bytes that get signed")
	case cfg.AuthorEmail == "":
		return refuse("no author email: I6 constrains it and an empty one is not a value the policy can admit")
	}
	if err := cfg.Signers.Admits(cfg.AuthorEmail); err != nil {
		return refuse(fmt.Sprintf(
			"the configured author %q is not admitted by the signer's author policy: %v "+
				"(I6 — the one invariant with no cryptographic backstop)", cfg.AuthorEmail, err))
	}

	repos := cfg.Repos
	if repos == nil {
		repos = GitRepos{}
	}
	return &signCommitService{
		runs:        cfg.Runs,
		ledger:      cfg.Ledger,
		idem:        cfg.Idempotency,
		workspace:   cfg.Workspace,
		repos:       repos,
		sigstore:    cfg.Sigstore,
		credentials: cfg.Credentials,
		signers:     cfg.Signers,
		authorName:  cfg.AuthorName,
		authorEmail: cfg.AuthorEmail,
	}, nil
}

// signCommitState holds the installed configuration.
//
// It is package state because ADR-0016 §5 fixes the seam: a tool file
// registers its own binder from its own init and the binder receives only the
// *Server.
var (
	signCommitMu     sync.RWMutex
	signCommitActive *signCommitService
)

// ConfigureSignCommit installs the dependencies sign_commit runs on and
// returns a function restoring whatever was installed before.
func ConfigureSignCommit(cfg SignCommitConfig) (func(), error) {
	svc, err := newSignCommitService(cfg)
	if err != nil {
		return nil, err
	}
	signCommitMu.Lock()
	defer signCommitMu.Unlock()
	previous := signCommitActive
	signCommitActive = svc
	return func() {
		signCommitMu.Lock()
		defer signCommitMu.Unlock()
		signCommitActive = previous
	}, nil
}

func bindSignCommit(s *Server) error {
	return Bind(s, &sdk.Tool{
		Name: string(ToolSignCommit),
		Description: "Sign one staged commit under this run's identity, recording the intent " +
			"before signing and the result after it. The commit is created only if Fulcio " +
			"issues a certificate and Rekor records the signature; there is no unsigned " +
			"fallback. The same idempotency_key always names the same commit.",
	}, signCommit)
}

func signCommit(ctx context.Context, _ *sdk.CallToolRequest, in signCommitIn) (signCommitOut, error) {
	signCommitMu.RLock()
	svc := signCommitActive
	signCommitMu.RUnlock()
	if svc == nil {
		// Alert-level: a bound tool with no dependencies behind it is a defect
		// in the wiring, and IP §4 has no "internal error" class (ADR-0016).
		return signCommitOut{}, Errorf(ClassInvariantViolation, in.RunID,
			"sign_commit is bound but not configured; no commit is signed rather than one signed unrecorded")
	}
	return svc.sign(ctx, in)
}

// ---------------------------------------------------------------------------
// The tool.
// ---------------------------------------------------------------------------

// sign checks the request, claims the key, and runs the three phases inside
// the claim.
//
// Argument validation stays OUTSIDE the claim: it is a property of the request
// alone, so a malformed call costs nothing and reserves no key. Everything
// else is inside, because IP §6.6 requires a replay to return the original
// result and a run retired since the first call must not turn a completed
// call's replay into a refusal.
func (c *signCommitService) sign(ctx context.Context, in signCommitIn) (signCommitOut, error) {
	if err := signCommitCheckRequest(in); err != nil {
		return signCommitOut{}, err
	}

	outcome, err := c.idem.Do(ctx, Call{
		Tool: string(ToolSignCommit),
		Key:  in.IdempotencyKey,
		// The arguments that make this request this request. The key itself is
		// not among them: it is what the fingerprint is looked up by. The
		// message IS among them — two different messages under one key are two
		// different commits — and the store fingerprints its params rather
		// than storing them, so nothing here becomes a second copy of it.
		Params: map[string]any{
			"run_id":     in.RunID,
			"repo":       in.Repo,
			"staged_ref": in.StagedRef,
			"message":    in.Message,
			"task_ref":   in.TaskRef,
		},
	}, func(ctx context.Context) (any, error) {
		return c.phases(ctx, in)
	})
	if err != nil {
		return signCommitOut{}, err
	}

	var out signCommitOut
	if err := json.Unmarshal(outcome.Response, &out); err != nil {
		return signCommitOut{}, Errorf(ClassInvariantViolation, in.RunID,
			"the recorded reply for idempotency_key %q is not a sign_commit result: %w",
			in.IdempotencyKey, err)
	}
	return out, nil
}

// phases is IP §6.5, in the one order that is load bearing.
//
// would hide the order, which is the one thing this function exists to get
// right (IP §6.5).
//
//nolint:gocyclo // One gate per step, each with its own refusal. Splitting it
func (c *signCommitService) phases(ctx context.Context, in signCommitIn) (any, error) {
	// ---- before Phase A: everything that can fail cheaply ------------------

	run, spiffeID, err := c.resolveRun(ctx, in.RunID)
	if err != nil {
		return nil, err
	}

	// What the trailers will claim, checked here rather than inside the
	// wrapper so a claim this run cannot make is refused before an intent
	// exists (IP §6.9's spoofing, seen from our own side).
	claim := signing.Claim{Identity: spiffeID, Run: run.RunID, Task: in.TaskRef}
	trailers, err := claim.Trailers()
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, run.RunID,
			"the commit cannot be claimed for this run: %w", err)
	}

	worktree, err := c.workspace.Worktree(ctx, in.Repo)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, run.RunID,
			"no working tree for %s: %w", in.Repo, err)
	}

	tree, err := c.repos.StagedTree(ctx, worktree, in.StagedRef)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, run.RunID,
			"the staged tree of %s cannot be signed: %w", in.Repo, err)
	}
	if verr := event.ValidateGitObjectID(tree); verr != nil {
		return nil, Errorf(ClassInvariantViolation, run.RunID,
			"the staged tree is not a git object id: %v", verr)
	}

	// ADR-0024's definition of "Sigstore is reachable", asked BEFORE the
	// intent so that IP §6.3's two outages — which are the commonest cause of
	// a failed signature — do not each leave an intent for the reconciler.
	// It is not a guarantee: Fulcio can die between here and `git commit`, and
	// that residue is the A → B window named at the top of this file.
	if perr := probeSigstore(ctx, c.sigstore); perr != nil {
		return nil, perr
	}

	// IP §6.1: any in-flight sign_commit aborts BEFORE Phase A when the
	// credential cannot be had.
	src := &signCommitSource{run: run, issue: c.credentials.IssueForSigning}
	if perr := src.prime(ctx); perr != nil {
		return nil, perr
	}

	signer, err := c.signers.Open(src)
	if err != nil {
		return nil, Errorf(ClassInvariantViolation, run.RunID,
			"no signer for run %s: %w", run.RunID, err)
	}
	defer func() { _ = signer.Close() }()

	// ---- PHASE A ----------------------------------------------------------
	//
	// The tree hash is here and the commit SHA is not, because the commit does
	// not exist yet. That is the whole point: the intent names what is about
	// to be signed, so a signature found later can be matched back to it.
	intent, err := c.append(ctx, run.RunID, event.EventTypeCommitIntent, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitIntent,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: signCommitPhaseKey(signCommitIntentKeyPrefix, in.IdempotencyKey),
		event.FieldRepo:           in.Repo,
		event.FieldTreeHash:       tree,
	})
	if err != nil {
		return nil, err
	}
	intentID, err := signCommitEventID(run.RunID, intent)
	if err != nil {
		return nil, err
	}

	// ---- PHASE B ----------------------------------------------------------
	//
	// Fulcio and Rekor happen inside this one call (ADR-0031). Nothing is
	// retried here: internal/signing bounds the child process, and a retry
	// loop around a `git commit` is a loop that can create two commits.
	result, err := signer.Sign(ctx, signing.Request{
		Repo:        worktree,
		Message:     in.Message,
		AuthorName:  c.authorName,
		AuthorEmail: c.authorEmail,
		Claim:       claim,
	})
	if err != nil {
		return nil, c.signingError(ctx, run.RunID, err)
	}
	if err := c.checkResult(ctx, run.RunID, worktree, tree, result, trailers); err != nil {
		return nil, err
	}

	// ---- PHASE C ----------------------------------------------------------
	if _, err := c.append(ctx, run.RunID, event.EventTypeCommitRecorded, event.Fields{
		event.FieldSchemaVersion:  event.SchemaVersion,
		event.FieldEventType:      event.EventTypeCommitRecorded,
		event.FieldSource:         event.SourceMCP,
		event.FieldRunID:          run.RunID,
		event.FieldSpiffeID:       spiffeID,
		event.FieldIdempotencyKey: signCommitPhaseKey(signCommitRecordedKeyPrefix, in.IdempotencyKey),
		event.FieldRepo:           in.Repo,
		event.FieldCommitSHA:      result.CommitSHA,
		event.FieldTreeHash:       tree,
		event.FieldRekorLogIndex:  result.Rekor.LogIndex,
		event.FieldRekorEntryUUID: result.Rekor.UUID,
		// The link. Without it a `commit_recorded` is a claim about a commit;
		// with it, it is the completion of a protocol somebody can audit.
		event.FieldIntentEventID: intentID,
	}); err != nil {
		return nil, err
	}

	return signCommitOut{
		CommitSHA: result.CommitSHA,
		RekorEntry: SignCommitRekorEntry{
			UUID:         result.Rekor.UUID,
			LogIndex:     result.Rekor.LogIndex,
			LogID:        result.Rekor.LogID,
			IntegratedAt: event.NewTimestamp(result.Rekor.IntegratedAt).String(),
		},
		Trailers: signCommitTrailers(result.Trailers),
	}, nil
}

// resolveRun is the run gate: the run exists, it has not been retired, and the
// identity the directory named is that run's own.
//
// It is the same three checks record_event and retire_agent make, through the
// same two functions, so no tool can disagree with another about what a run is.
func (c *signCommitService) resolveRun(ctx context.Context, runID string) (CredentialRun, string, error) {
	run, found, err := c.runs.CredentialRun(ctx, runID)
	if err != nil {
		return CredentialRun{}, "", credentialLedgerError(runID, err)
	}
	if !found {
		return CredentialRun{}, "", Errorf(ClassRunNotFound, runID, "no run %q", runID)
	}
	if run.Retired() {
		// I4: retirement removes the identity, never the record.
		return CredentialRun{}, "", Errorf(ClassRunAlreadyRetired, runID,
			"run %q was retired at %s; retirement is effective immediately (IP §6.2)",
			runID, event.NewTimestamp(run.RetiredAt))
	}
	spiffeID, err := credentialRunIdentity(runID, run)
	if err != nil {
		return CredentialRun{}, "", err
	}
	return run, spiffeID, nil
}

// checkResult reads the signature back and refuses anything it cannot record.
//
// Every refusal here is INVARIANT_VIOLATION and never retryable, because the
// commit object already exists: a repeat of the request cannot unmake it, and
// a caller told to retry would create a second one. ADR-0031 reaches the same
// conclusion for the wrapper's own read-back checks, and for the same reason.
func (c *signCommitService) checkResult(
	ctx context.Context, runID, worktree, tree string,
	result signing.Result, claimed []signing.Trailer,
) error {
	if err := event.ValidateGitObjectID(result.CommitSHA); err != nil {
		return Errorf(ClassInvariantViolation, runID,
			"the wrapper reported %q as the commit it created: %v", result.CommitSHA, err)
	}

	// The signed commit's tree is compared with the tree Phase A recorded.
	// Without this the intent would be a claim about the request rather than
	// about the artifact, and a reconciler matching a Rekor entry to an intent
	// by tree hash would be matching on a value nothing ever checked.
	committed, err := c.repos.CommitTree(ctx, worktree, result.CommitSHA)
	if err != nil {
		return Errorf(ClassInvariantViolation, runID,
			"commit %s cannot be read back: %w", result.CommitSHA, err)
	}
	if committed != tree {
		return Errorf(ClassInvariantViolation, runID,
			"commit %s is of tree %s and the intent recorded %s; the signature does not "+
				"cover what was intended", result.CommitSHA, committed, tree)
	}

	// doc 02 §3 requires both members on `commit_recorded`. A signature with
	// no transparency entry is not non-repudiable and must not be recorded as
	// though it were (IP §6.3).
	if result.Rekor.UUID == "" {
		return Errorf(ClassInvariantViolation, runID,
			"commit %s was signed with no Rekor entry", result.CommitSHA)
	}
	if result.Rekor.LogIndex < 0 {
		return Errorf(ClassInvariantViolation, runID,
			"commit %s reports transparency-log index %d", result.CommitSHA, result.Rekor.LogIndex)
	}

	// The trailers the wrapper reports must be the ones this run claimed. A
	// disagreement here is IP §6.9's trailer spoofing arriving from our own
	// side of the boundary.
	if !slices.Equal(result.Trailers, claimed) {
		return Errorf(ClassInvariantViolation, runID,
			"commit %s carries trailers %v, and this run claimed %v",
			result.CommitSHA, result.Trailers, claimed)
	}
	return nil
}

// append writes one event and checks that what came back is what was written.
//
// The ledger returns the ORIGINAL event when an idempotency_key has already
// been used (LED-008). That is exactly the behaviour a replay depends on, and
// it is also the one way this tool could be handed another record's
// identifiers — so the returned event's type and run are compared with the
// append's before anything is read out of it.
func (c *signCommitService) append(
	ctx context.Context, runID, eventType string, body event.Fields,
) (event.Fields, error) {
	record, err := c.ledger.Append(ctx, body)
	if err != nil {
		return nil, credentialLedgerError(runID, err)
	}
	got, ok := record[event.FieldEventType].(string)
	if !ok || got != eventType {
		return nil, Errorf(ClassInvariantViolation, runID,
			"appending a %s returned a %v event; the idempotency_key names another record",
			eventType, record[event.FieldEventType])
	}
	scoped, ok := record[event.FieldRunID].(string)
	if !ok || scoped != runID {
		return nil, Errorf(ClassInvariantViolation, runID,
			"appending a %s for run %q returned an event of run %v",
			eventType, runID, record[event.FieldRunID])
	}
	return record, nil
}

// signCommitEventID reads the ledger-assigned event_id off an appended record.
func signCommitEventID(runID string, record event.Fields) (string, error) {
	raw, present := record[event.FieldEventID]
	if !present {
		return "", Errorf(ClassInvariantViolation, runID,
			"the appended intent carries no %s; nothing could reference it", event.FieldEventID)
	}
	id, ok := raw.(string)
	if !ok {
		return "", Errorf(ClassInvariantViolation, runID,
			"the appended intent's %s is %T, want a string", event.FieldEventID, raw)
	}
	if err := event.ValidateEventID(id); err != nil {
		return "", Errorf(ClassInvariantViolation, runID,
			"the appended intent's %s is not one: %v", event.FieldEventID, err)
	}
	return id, nil
}

// signCommitTrailers renders the wrapper's trailers as the wire carries them.
func signCommitTrailers(in []signing.Trailer) []SignCommitTrailer {
	out := make([]SignCommitTrailer, len(in))
	for i, t := range in {
		out[i] = SignCommitTrailer{Key: t.Key, Value: t.Value}
	}
	return out
}

// ---------------------------------------------------------------------------
// The two derived ledger keys.
// ---------------------------------------------------------------------------

// One tool call appends TWO events, and internal/ledger's idempotency_key is
// UNIQUE across the chain — so the caller's one key cannot be written twice.
// Both phases therefore carry a key DERIVED from the caller's, namespaced by
// the tool and the phase.
//
// Deriving both rather than spending the caller's key on the intent is
// deliberate. A key used verbatim would collide with the same key used by
// record_event or register_agent, and a colliding append does not fail: LED-008
// hands back the ORIGINAL event, of the wrong type, whose event_id this tool
// would then treat as an intent's. ADR-0017's store refuses that reuse one
// layer up — a key naming a different request is DUPLICATE_REQUEST — so the
// namespacing is the second of two independent refusals rather than the only
// one, and `signCommitService.append` checks the returned event's type as the
// third.
//
// The caller's key is not lost: it is the primary key of the idempotency
// store's own row, which is where an operator looks up what a call returned.
const (
	signCommitIntentKeyPrefix   = "sign_commit/intent/"
	signCommitRecordedKeyPrefix = "sign_commit/recorded/"
	// 128 bits of the digest, which keeps both keys far inside doc 02 §2's
	// 128-byte bound whatever the caller's key is — the reason a derivation is
	// used at all rather than a suffix, which would overflow for a key at the
	// limit.
	signCommitKeyHexDigits = 32
)

func signCommitPhaseKey(prefix, key string) string {
	// Quoted, so no run of concatenations can spell another key.
	digest := strings.TrimPrefix(event.Digest([]byte(strconv.Quote(key))), event.HashPrefix)
	return prefix + digest[:signCommitKeyHexDigits]
}

// ---------------------------------------------------------------------------
// Request validation.
// ---------------------------------------------------------------------------

// MaxSignCommitMessageBytes bounds the commit message.
//
// The message never reaches the ledger — doc 02 §3 gives `commit_intent` and
// `commit_recorded` no member for it — so this is not an E4 bound. It is a
// bound on an unbounded argument: a message is written to a file and becomes
// the preimage of a signature, and an argument with no limit is one an
// exhausted disk turns into an outage.
const MaxSignCommitMessageBytes = 64 << 10

// signCommitCheckRequest holds IP §4's arguments to their grammars.
//
// No refusal quotes an unbounded value back: an error message is a second
// place a payload could come to rest (the same rule record_event follows).
func signCommitCheckRequest(in signCommitIn) error {
	if err := event.ValidateIdentifier(in.RunID); err != nil {
		return Errorf(ClassRunNotFound, "", "%q is not a run id: %v", in.RunID, err)
	}
	reject := func(format string, args ...any) error {
		return Errorf(ClassInvariantViolation, in.RunID, format, args...)
	}
	if err := event.ValidateRepo(in.Repo); err != nil {
		return reject("repo: %v", err)
	}
	if err := signCommitCheckRef(in.StagedRef); err != nil {
		return reject("staged_ref: %v", err)
	}
	switch {
	case strings.TrimSpace(in.Message) == "":
		return reject("message is required: a commit message is part of the bytes that get signed")
	case len(in.Message) > MaxSignCommitMessageBytes:
		return reject("message is %d bytes, limit %d", len(in.Message), MaxSignCommitMessageBytes)
	case in.TaskRef == "":
		return reject("task_ref is required: it becomes the %s trailer (I6)", signing.TrailerAgentTask)
	case len(in.TaskRef) > event.MaxReferenceBytes:
		return reject("task_ref is %d bytes, limit %d", len(in.TaskRef), event.MaxReferenceBytes)
	}
	return nil
}

// signCommitCheckRef holds `staged_ref` to something git will read as a
// revision and never as an option.
//
// A leading `-` is refused rather than escaped: git's own argument parsing is
// what would interpret it, and a value that has to be defended against by
// quoting is one a later refactor forgets to quote.
func signCommitCheckRef(ref string) error {
	switch {
	case ref == "":
		return errors.New("required: it names the tree that is about to be signed")
	case len(ref) > event.MaxReferenceBytes:
		return fmt.Errorf("%d bytes, limit %d", len(ref), event.MaxReferenceBytes)
	case strings.HasPrefix(ref, "-"):
		return errors.New("starts with '-', which git reads as an option and not a revision")
	}
	for i := 0; i < len(ref); i++ {
		if b := ref[i]; b <= ' ' || b == 0x7f {
			return fmt.Errorf("contains a control byte or a space at offset %d", i)
		}
	}
	return nil
}

// ---------------------------------------------------------------------------
// Errors from the signing wrapper.
// ---------------------------------------------------------------------------

// signingError renders internal/signing's sentinels as IP §4's vocabulary
// (ADR-0028 decision 8: the mapping lives here, not there).
//
// Everything the wrapper can raise that is not one of the named outages is
// INVARIANT_VIOLATION and not retryable, and that is the honest reading:
// a signature that cannot be read back and a certificate that does not attest
// this run are both conditions in which a commit object may already exist, so
// telling a caller to retry would invite a second one.
//
// # Why gitsign's own refusal is re-probed
//
// ErrSigning is `gitsign` or `git` exiting non-zero, and its text is a
// subprocess's prose. It is what a Fulcio or Rekor outage that began AFTER the
// pre-Phase-A probe looks like from here — RM-034 measured the same thing from
// the other side and recorded it in ADR-0032: a Rekor outage can reach this
// layer as ErrSigning, and rendering that as INVARIANT_VIOLATION would tell an
// operator their system has a defect when a dependency is down. So the
// dependency is asked directly, once, and its answer decides the class. No
// prose is pattern-matched, which is the property ADR-0031 decision 2 was
// after when it made the trust-material fetch the discriminator.
//
// The probe runs on a context detached from the caller's cancellation: a
// caller who gave up is still owed the right class, and a cancelled context
// would otherwise make every late failure look like an outage.
func (c *signCommitService) signingError(ctx context.Context, runID string, err error) error {
	// An error that already carries a class keeps it. The credential source is
	// this package's own and classifies its failures itself; re-deriving them
	// from a sentinel would lose IDENTITY_UNAVAILABLE's retryability.
	var classified *Error
	if errors.As(err, &classified) {
		return err
	}
	switch {
	case errors.Is(err, signing.ErrSigningUnavailable):
		return Errorf(ClassSigningUnavailable, runID, "%w", err)
	case errors.Is(err, signing.ErrTransparencyUnavailable):
		return Errorf(ClassTransparencyUnavailable, runID, "%w", err)
	case errors.Is(err, signing.ErrCredentialUnavailable):
		return Errorf(ClassCredentialExpired, runID, "%w", err)
	}
	if errors.Is(err, signing.ErrSigning) {
		probe, cancel := context.WithTimeout(context.WithoutCancel(ctx), signCommitDiagnosisTimeout)
		defer cancel()
		if perr := probeSigstore(probe, c.sigstore); perr != nil {
			return Errorf(Classify(perr).Class, runID,
				"gitsign refused and Sigstore is unavailable: %v; the refusal was: %w", perr, err)
		}
	}
	return Errorf(ClassInvariantViolation, runID, "%w", err)
}

// signCommitDiagnosisTimeout bounds the one probe made on the error path. It is
// short: it exists to name a class, not to wait for a recovery.
const signCommitDiagnosisTimeout = 10 * time.Second

// ---------------------------------------------------------------------------
// The credential source.
// ---------------------------------------------------------------------------

// signCommitSource hands the wrapper this run's credential.
//
// It is primed before Phase A (IP §6.1) and hands the primed credential over
// on the wrapper's FIRST request, so the pre-fetch is not a second issuance. A
// SECOND request means the wrapper judged the credential unusable, which is
// IP §6.2's transparent re-fetch — deliberately not suppressed, because each
// issuance is its own auditable fact (ADR-0004).
type signCommitSource struct {
	run   CredentialRun
	issue func(context.Context, CredentialRun) (signing.Credential, error)

	mu     sync.Mutex
	primed *signing.Credential
}

func (s *signCommitSource) prime(ctx context.Context) error {
	cred, err := s.issue(ctx, s.run)
	if err != nil {
		return err
	}
	s.mu.Lock()
	defer s.mu.Unlock()
	s.primed = &cred
	return nil
}

func (s *signCommitSource) Credential(ctx context.Context) (signing.Credential, error) {
	s.mu.Lock()
	primed := s.primed
	s.primed = nil
	s.mu.Unlock()
	if primed != nil {
		return *primed, nil
	}
	return s.issue(ctx, s.run)
}

// SignCommitThroughGetCredential is the shipped SignCommitCredentials: the
// MCP's own get_credential tool, called in process.
//
// It is the shipped tool and not a second route to SPIRE on purpose. Going
// through get_credential means one audience allowlist, one retirement check,
// one SPIRE entry check and one `credential_issued` append (I3) — and it means
// a run retired a moment ago cannot sign, because the gate that refuses is the
// same gate an agent would have hit.
type SignCommitThroughGetCredential struct{}

// IssueForSigning mints one Sigstore-audience credential for the run.
func (SignCommitThroughGetCredential) IssueForSigning(
	ctx context.Context, run CredentialRun,
) (signing.Credential, error) {
	out, err := getCredential(ctx, nil, getCredentialIn{
		RunID:    run.RunID,
		Audience: AudienceSigstore,
	})
	if err != nil {
		return signing.Credential{}, err
	}
	expiry, err := event.ParseTimestamp(out.ExpiresAt)
	if err != nil {
		return signing.Credential{}, Errorf(ClassInvariantViolation, run.RunID,
			"get_credential returned an expiry that is not a timestamp: %v", err)
	}
	return signing.Credential{
		Token: out.JWTSVID,
		// The identity comes from the run directory, which is what the ledger
		// recorded, and not from the token: a credential is checked against
		// what this run IS, so reading the identity out of the credential
		// would make that check compare a value with itself.
		SPIFFEID:  run.SPIFFEID,
		Audience:  AudienceSigstore,
		ExpiresAt: expiry.Time(),
	}, nil
}

// ---------------------------------------------------------------------------
// The shipped workspace.
// ---------------------------------------------------------------------------

// Workspace maps doc 02 §5's `host/org/name` onto `<root>/host/org/name`.
//
// The mapping is total and it is the only one: a caller names a repository,
// never a path, so there is no argument through which a directory outside the
// root can be reached. `ValidateRepo` is what makes that true rather than
// likely — it admits exactly three segments, each matching
// `[A-Za-z0-9][A-Za-z0-9._-]*`, so no segment can be `..` and no segment can
// contain a separator.
type Workspace struct{ root string }

// NewWorkspace roots a workspace at an absolute directory.
func NewWorkspace(root string) (*Workspace, error) {
	if root == "" {
		return nil, errors.New("a workspace needs a root directory to resolve repositories against")
	}
	if !filepath.IsAbs(root) {
		return nil, fmt.Errorf("workspace root %q is relative; it would resolve against "+
			"whatever directory this process happens to be in", root)
	}
	return &Workspace{root: filepath.Clean(root)}, nil
}

// Worktree returns the working tree for a repository.
func (w *Workspace) Worktree(_ context.Context, repo string) (string, error) {
	if err := event.ValidateRepo(repo); err != nil {
		return "", err
	}
	dir := filepath.Join(w.root, filepath.FromSlash(repo))
	// A working tree, not merely a directory: `.git` is a directory in an
	// ordinary clone and a file in a linked worktree or a submodule, so its
	// existence is the check and its kind is not.
	if _, err := os.Stat(filepath.Join(dir, ".git")); err != nil {
		return "", fmt.Errorf("%s is not a git working tree: %w", dir, err)
	}
	return dir, nil
}

// ---------------------------------------------------------------------------
// The shipped git reader.
// ---------------------------------------------------------------------------

// GitRepos reads git plumbing with a built environment.
//
// It reads and never writes to a ref: `rev-parse` resolves, and `write-tree`
// writes tree objects to the object database and touches nothing reachable.
// That distinction is what keeps IP §6.3's "the repo has no new commit object
// at all" true — a tree written for a signature that never happened is
// unreferenced and is collected, and it is not a commit.
type GitRepos struct {
	// GitPath is the git binary. Empty means a PATH lookup.
	GitPath string
}

// signCommitGitEnv is ADR-0031 decision 3's argument applied to a read: the
// child's environment is built rather than inherited, so no `~/.gitconfig`,
// alias or credential helper can change what a plumbing command answers.
func signCommitGitEnv(worktree string) []string {
	return []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + worktree,
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_CONFIG_GLOBAL=" + filepath.Join(worktree, ".innsegl-no-global-gitconfig"),
		"GIT_TERMINAL_PROMPT=0",
		// A read must never be answered by a pager or an editor.
		"GIT_PAGER=cat",
	}
}

func (g GitRepos) git(ctx context.Context, worktree string, args ...string) (string, error) {
	path := g.GitPath
	if path == "" {
		path = "git"
	}
	cmd := exec.CommandContext(ctx, path, append([]string{"-C", worktree}, args...)...)
	cmd.Env = signCommitGitEnv(worktree)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return "", fmt.Errorf("git %s: %w: %s",
			strings.Join(args, " "), err, strings.TrimSpace(string(out)))
	}
	return strings.TrimSpace(string(out)), nil
}

// StagedTree resolves the tree that `git commit` would create, and refuses
// every state in which that tree is not what the caller asked for.
//
// Three refusals, and each is a failure that would otherwise appear after the
// intent was appended, or worse, after the commit existed:
//
//   - `staged_ref` names no tree. The caller's own reference is wrong.
//   - `staged_ref` names a tree the INDEX does not hold. `git commit` commits
//     the index, so signing would cover something other than what was named.
//   - the index is already the tree at HEAD. `git commit` refuses an empty
//     commit, so no commit object can exist — and this is exactly the state a
//     crash between Phase B and Phase C leaves behind, which is why the
//     message names the reconciler.
func (g GitRepos) StagedTree(ctx context.Context, worktree, stagedRef string) (string, error) {
	named, err := g.git(ctx, worktree, "rev-parse", "--verify", "--quiet", stagedRef+"^{tree}")
	if err != nil {
		return "", fmt.Errorf("staged_ref names no tree in %s: %w", worktree, err)
	}
	index, err := g.git(ctx, worktree, "write-tree")
	if err != nil {
		return "", fmt.Errorf("the index of %s cannot be resolved to a tree: %w", worktree, err)
	}
	if named != index {
		return "", fmt.Errorf(
			"staged_ref names tree %s and the index of %s holds %s; `git commit` commits "+
				"the index, so these must be the same tree", named, worktree, index)
	}
	// A repository with no HEAD has no tree to compare against, which is the
	// ordinary first-commit case and not a refusal.
	head, herr := g.git(ctx, worktree, "rev-parse", "--verify", "--quiet", "HEAD^{tree}")
	if herr == nil && head == index {
		return "", fmt.Errorf(
			"nothing is staged: the index of %s is already the tree at HEAD (%s), so git "+
				"would refuse to create a commit. If a signature for this tree already "+
				"exists, the missing commit_recorded is the reconciler's to append from "+
				"Rekor (IP §6.5)", worktree, index)
	}
	return index, nil
}

// CommitTree returns the tree of one commit.
func (g GitRepos) CommitTree(ctx context.Context, worktree, commit string) (string, error) {
	tree, err := g.git(ctx, worktree, "rev-parse", "--verify", "--quiet", commit+"^{tree}")
	if err != nil {
		return "", fmt.Errorf("no tree for %s in %s: %w", commit, worktree, err)
	}
	return tree, nil
}

// ---------------------------------------------------------------------------
// The shipped signer factory.
// ---------------------------------------------------------------------------

// NewGitsignSigners returns the shipped SignCommitSigners: RM-032's wrapper,
// one Signer per call.
//
// One per call, not one per run. ADR-0031 notes the cost — the credential
// cache degrades into a fetch per commit — and it is the right trade here:
// a Signer holds a work directory and a cached credential, and a map of them
// keyed by run would be state to expire on retirement, which is the shape of
// the cached-credential grace path IP §6.2 forbids. The fetch is the same
// get_credential call an agent would make, and it is recorded (I3).
func NewGitsignSigners(cfg signing.Config) SignCommitSigners { return gitsignSigners{cfg: cfg} }

type gitsignSigners struct{ cfg signing.Config }

// Admits asks the wrapper's own author policy, so there is exactly one
// statement of who may author a commit in this deployment (I6).
func (g gitsignSigners) Admits(email string) error { return g.cfg.Author.CheckAuthor(email) }

func (g gitsignSigners) Open(src signing.CredentialSource) (SignCommitSigner, error) {
	signer, err := signing.NewSigner(g.cfg, src)
	if err != nil {
		// Returned as a nil interface rather than a typed nil pointer: a
		// caller's `if signer != nil` must mean what it says.
		return nil, err
	}
	return signer, nil
}
